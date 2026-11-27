//! Untrusted byte-stream provider traits, outer frame bounds, and stream adapters.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tendril_core::MAX_FRAME_LEN;
use tendril_core::policy::ProviderId;
use tendril_core::wire::{ResumableFrameReader, encode_frame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;

use crate::error::RuntimeError;

/// Default per-write backpressure timeout enforced across all path providers (`1 s`).
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum outer Tendril wire frame length (`2 B` length prefix + `MAX_FRAME_LEN` body).
pub const MAX_OUTER_FRAME_LEN: usize = 2 + MAX_FRAME_LEN;

/// Read half of a split full-duplex [`PathStream`].
#[async_trait]
pub trait PathReader: Send + Sync {
    /// Reads the next chunk of raw wire bytes into `buf`, returning byte count (`0` means EOF).
    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError>;
}

/// Write half of a split full-duplex [`PathStream`].
#[async_trait]
pub trait PathWriter: Send + Sync {
    /// Sends one raw wire chunk (`<= MAX_OUTER_FRAME_LEN`) within write backpressure bounds.
    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError>;

    /// Gracefully shuts down or closes the underlying transport stream.
    async fn close(&mut self) -> Result<(), RuntimeError>;
}

/// Bidirectional byte-stream abstraction exposed by every untrusted path provider.
#[async_trait]
pub trait PathStream: Send + Sync {
    /// Returns the provider class owning this transport stream.
    fn provider_id(&self) -> ProviderId;

    /// Returns the remote peer IP address when backed by an IP socket.
    fn peer_ip(&self) -> Option<IpAddr>;

    /// Returns a cryptographic transport peer identifier when available (for pre-auth rate limiting only).
    fn peer_transport_id(&self) -> Option<String> {
        None
    }

    /// Sends one raw wire chunk (`<= MAX_OUTER_FRAME_LEN`) within write backpressure bounds.
    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError>;

    /// Reads the next chunk of raw wire bytes into `buf`, returning byte count (`0` means EOF).
    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError>;

    /// Gracefully shuts down or closes the underlying transport stream.
    async fn close(&mut self) -> Result<(), RuntimeError>;

    /// Half-closes the stream: the peer sees EOF after the bytes already sent, while
    /// [`Self::recv_chunk`] keeps working. A host that writes a final frame and then drops a
    /// stream with unread inbound data would otherwise reset the connection and discard that frame.
    ///
    /// Errors are returned, so a caller that only drains a refusal can ignore them. The default
    /// does nothing and never closes the stream. Message-framed providers (WebSocket relay) keep
    /// it, so a half-close there is a no-op, and rely on [`Self::close`].
    async fn shutdown_write(&mut self) -> Result<(), RuntimeError> {
        Ok(())
    }

    /// Splits this stream into independent read and write halves for full-duplex operation.
    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>);
}

struct FallbackReadHalf(Arc<AsyncMutex<Box<dyn PathStream>>>);
struct FallbackWriteHalf(Arc<AsyncMutex<Box<dyn PathStream>>>);

#[async_trait]
impl PathReader for FallbackReadHalf {
    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.0.lock().await.recv_chunk(buf).await
    }
}

#[async_trait]
impl PathWriter for FallbackWriteHalf {
    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.0.lock().await.send_chunk(bytes).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.0.lock().await.close().await
    }
}

/// Wraps an unsplit [`PathStream`] in mutex-backed reader and writer handles (for test mocks).
#[must_use]
pub fn split_path_stream_fallback(
    stream: Box<dyn PathStream>,
) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
    let shared = Arc::new(AsyncMutex::new(stream));
    (
        Box::new(FallbackReadHalf(Arc::clone(&shared))),
        Box::new(FallbackWriteHalf(shared)),
    )
}

/// Listener accepting incoming [`PathStream`] connections on one path provider.
#[async_trait]
pub trait PathListener: Send + Sync {
    /// Accepts the next inbound connection stream.
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError>;

    /// Returns a human-usable endpoint string identifying this listener.
    fn local_endpoint(&self) -> String;
}

/// Dialer connecting outbound [`PathStream`] instances over one path provider.
#[async_trait]
pub trait PathDialer: Send + Sync {
    /// Returns the provider class implemented by this dialer.
    fn provider_id(&self) -> ProviderId;

    /// Returns `true` when this dialer can carry `init_frame` inside its 0-RTT control setup.
    fn supports_fast_open(&self) -> bool {
        false
    }

    /// Opens an outbound stream to `endpoint`.
    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError>;

    /// Opens an outbound stream to `endpoint`, optionally attaching `init_frame` in 0-RTT setup.
    ///
    /// Returns `(stream, true)` when `init_frame` was actually sent inside the dial handshake, or
    /// `(stream, false)` when the caller must transmit initial bytes after connect.
    async fn dial_with_init(
        &self,
        endpoint: &str,
        _init_frame: Option<&[u8]>,
    ) -> Result<(Box<dyn PathStream>, bool), RuntimeError> {
        Ok((self.dial(endpoint).await?, false))
    }
}

/// Shared Tokio `AsyncRead + AsyncWrite` wrapper used by `local` and `direct` providers.
pub(crate) struct IoPathStream<S> {
    provider: ProviderId,
    peer_ip: Option<IpAddr>,
    write_timeout: Duration,
    stream: S,
}

impl<S> IoPathStream<S> {
    pub(crate) fn new(
        provider: ProviderId,
        peer_ip: Option<IpAddr>,
        write_timeout: Duration,
        stream: S,
    ) -> Self {
        Self {
            provider,
            peer_ip,
            write_timeout,
            stream,
        }
    }
}

async fn write_chunk_timed<W: AsyncWrite + Unpin>(
    writer: &mut W,
    write_timeout: Duration,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    if bytes.len() > MAX_OUTER_FRAME_LEN {
        return Err(RuntimeError::FrameTooLarge {
            size: bytes.len(),
            max: MAX_OUTER_FRAME_LEN,
        });
    }
    let write_fut = async {
        writer.write_all(bytes).await?;
        writer.flush().await
    };
    match timeout(write_timeout, write_fut).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(RuntimeError::Io(err)),
        Err(_) => Err(RuntimeError::Timeout("stream write timed out")),
    }
}

struct IoReadHalf<S> {
    read: ReadHalf<S>,
}

struct IoWriteHalf<S> {
    write: WriteHalf<S>,
    write_timeout: Duration,
}

#[async_trait]
impl<S> PathReader for IoReadHalf<S>
where
    S: AsyncRead + Unpin + Send + Sync,
{
    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        if buf.is_empty() {
            return Ok(0);
        }
        Ok(self.read.read(buf).await?)
    }
}

#[async_trait]
impl<S> PathWriter for IoWriteHalf<S>
where
    S: AsyncWrite + Unpin + Send + Sync,
{
    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        write_chunk_timed(&mut self.write, self.write_timeout, bytes).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        let _ = timeout(self.write_timeout, self.write.shutdown()).await;
        Ok(())
    }
}

#[async_trait]
impl<S> PathStream for IoPathStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    fn provider_id(&self) -> ProviderId {
        self.provider
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_ip
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        write_chunk_timed(&mut self.stream, self.write_timeout, bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.stream.read(buf).await?;
        Ok(n)
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        let _ = timeout(self.write_timeout, self.stream.shutdown()).await;
        Ok(())
    }

    async fn shutdown_write(&mut self) -> Result<(), RuntimeError> {
        match timeout(self.write_timeout, self.stream.shutdown()).await {
            Ok(res) => Ok(res?),
            Err(_) => Err(RuntimeError::Timeout("stream shutdown timed out")),
        }
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        let (read, write) = tokio::io::split(self.stream);
        (
            Box::new(IoReadHalf { read }),
            Box::new(IoWriteHalf {
                write,
                write_timeout: self.write_timeout,
            }),
        )
    }
}

fn take_prefix_chunk(prefix: &[u8], offset: &mut usize, buf: &mut [u8]) -> Option<usize> {
    if *offset < prefix.len() {
        let avail = prefix.len() - *offset;
        let take = avail.min(buf.len());
        buf[..take].copy_from_slice(&prefix[*offset..*offset + take]);
        *offset += take;
        Some(take)
    } else {
        None
    }
}

struct PrefixedPathReader {
    inner: Box<dyn PathReader>,
    prefix: Vec<u8>,
    offset: usize,
}

#[async_trait]
impl PathReader for PrefixedPathReader {
    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        if let Some(take) = take_prefix_chunk(&self.prefix, &mut self.offset, buf) {
            return Ok(take);
        }
        self.inner.recv_chunk(buf).await
    }
}

/// Replays initially peeked bytes ahead of reading remaining chunks from `inner`.
pub struct PrefixedPathStream {
    inner: Box<dyn PathStream>,
    prefix: Vec<u8>,
    offset: usize,
}

impl PrefixedPathStream {
    /// Wraps `inner` so `prefix` is yielded before subsequent `recv_chunk` calls.
    #[must_use]
    pub fn new(inner: Box<dyn PathStream>, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            offset: 0,
        }
    }
}

#[async_trait]
impl PathStream for PrefixedPathStream {
    fn provider_id(&self) -> ProviderId {
        self.inner.provider_id()
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.inner.peer_ip()
    }

    fn peer_transport_id(&self) -> Option<String> {
        self.inner.peer_transport_id()
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.inner.send_chunk(bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        if let Some(take) = take_prefix_chunk(&self.prefix, &mut self.offset, buf) {
            return Ok(take);
        }
        self.inner.recv_chunk(buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.close().await
    }

    async fn shutdown_write(&mut self) -> Result<(), RuntimeError> {
        self.inner.shutdown_write().await
    }

    fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        let (inner, w) = self.inner.into_split();
        (
            Box::new(PrefixedPathReader {
                inner,
                prefix: self.prefix,
                offset: self.offset,
            }),
            w,
        )
    }
}

/// Reads at least `min_bytes` from `stream` (preserving any extra read bytes in the returned buffer).
pub async fn peek_exact(
    stream: &mut dyn PathStream,
    min_bytes: usize,
) -> Result<Vec<u8>, RuntimeError> {
    let mut acc = Vec::with_capacity(min_bytes.max(64));
    let mut scratch = vec![0u8; MAX_OUTER_FRAME_LEN];
    while acc.len() < min_bytes {
        let n = stream.recv_chunk(&mut scratch).await?;
        if n == 0 {
            return Err(RuntimeError::Closed);
        }
        acc.extend_from_slice(&scratch[..n]);
    }
    Ok(acc)
}

/// Encodes `body` as one outer Tendril length-prefixed frame (`<= 65519` B body) and sends it.
pub async fn send_tendril_frame(
    stream: &mut dyn PathStream,
    body: &[u8],
) -> Result<(), RuntimeError> {
    let outer = encode_frame(body)?;
    stream.send_chunk(&outer).await
}

/// Reads bytes into `reader` until one complete outer Tendril frame body is decoded.
pub async fn recv_tendril_frame(
    stream: &mut dyn PathStream,
    reader: &mut ResumableFrameReader,
) -> Result<Vec<u8>, RuntimeError> {
    let mut buf = vec![0u8; MAX_OUTER_FRAME_LEN];
    loop {
        if let Some(body) = reader.next_frame()? {
            return Ok(body);
        }
        let n = stream.recv_chunk(&mut buf).await?;
        if n == 0 {
            return Err(RuntimeError::Closed);
        }
        reader.push(&buf[..n])?;
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    async fn tcp_pair() -> (Box<dyn PathStream>, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let (server, peer) = accepted.unwrap();
        let stream = IoPathStream::new(
            ProviderId::Direct,
            Some(peer.ip()),
            DEFAULT_WRITE_TIMEOUT,
            server,
        );
        (Box::new(stream), client.unwrap())
    }

    #[tokio::test]
    async fn shutdown_write_half_closes_tcp_and_keeps_reading() {
        let (mut server, mut client) = tcp_pair().await;
        server.send_chunk(b"bye").await.unwrap();
        server.shutdown_write().await.unwrap();

        let mut got = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut got))
            .await
            .expect("the client sees EOF after the half-close")
            .unwrap();
        assert_eq!(got, b"bye");

        client.write_all(b"late").await.unwrap();
        let mut buf = [0_u8; 16];
        let n = timeout(Duration::from_secs(2), server.recv_chunk(&mut buf))
            .await
            .expect("the read half stays open")
            .unwrap();
        assert_eq!(&buf[..n], b"late");
    }

    #[tokio::test]
    async fn shutdown_write_delivers_the_frame_over_unread_inbound_data() {
        let (mut server, mut client) = tcp_pair().await;
        client.write_all(&[0xAB; 4096]).await.unwrap();
        server.send_chunk(b"refusal").await.unwrap();
        server.shutdown_write().await.unwrap();

        // Like the host's refusal drain: keep the stream open and discard inbound bytes until
        // EOF or a short bound, so closing never resets over unread data.
        let drain = tokio::spawn(async move {
            let mut buf = [0_u8; 1024];
            let _ = timeout(Duration::from_millis(500), async {
                while matches!(server.recv_chunk(&mut buf).await, Ok(n) if n > 0) {}
            })
            .await;
            drop(server);
        });

        let mut got = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut got))
            .await
            .expect("EOF")
            .expect("no reset after the half-close");
        assert_eq!(got, b"refusal");
        client.shutdown().await.unwrap();
        timeout(Duration::from_secs(2), drain)
            .await
            .expect("the drain ends on the client's EOF")
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_write_passes_through_a_prefixed_stream() {
        let (server, mut client) = tcp_pair().await;
        let mut wrapped: Box<dyn PathStream> = Box::new(PrefixedPathStream::new(server, vec![1]));
        wrapped.shutdown_write().await.unwrap();
        let mut got = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut got))
            .await
            .expect("EOF through the wrapper")
            .unwrap();
        assert!(got.is_empty());
    }

    struct Bare;

    #[async_trait]
    impl PathStream for Bare {
        fn provider_id(&self) -> ProviderId {
            ProviderId::Direct
        }

        fn peer_ip(&self) -> Option<IpAddr> {
            None
        }

        async fn send_chunk(&mut self, _bytes: &[u8]) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn recv_chunk(&mut self, _buf: &mut [u8]) -> Result<usize, RuntimeError> {
            Ok(0)
        }

        async fn close(&mut self) -> Result<(), RuntimeError> {
            panic!("the default shutdown_write must not close the stream");
        }

        fn into_split(self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
            split_path_stream_fallback(self)
        }
    }

    #[tokio::test]
    async fn default_shutdown_write_is_a_safe_no_op() {
        let mut bare = Bare;
        bare.shutdown_write().await.unwrap();
    }

    struct FailingShutdown {
        stuck: bool,
    }

    impl AsyncRead for FailingShutdown {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FailingShutdown {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.stuck {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
            }
        }
    }

    #[tokio::test]
    async fn shutdown_write_returns_io_and_timeout_errors() {
        let mut failing = IoPathStream::new(
            ProviderId::Direct,
            None,
            DEFAULT_WRITE_TIMEOUT,
            FailingShutdown { stuck: false },
        );
        assert!(matches!(
            failing.shutdown_write().await,
            Err(RuntimeError::Io(e)) if e.kind() == std::io::ErrorKind::BrokenPipe
        ));
        let mut stuck = IoPathStream::new(
            ProviderId::Direct,
            None,
            Duration::from_millis(20),
            FailingShutdown { stuck: true },
        );
        assert!(matches!(
            stuck.shutdown_write().await,
            Err(RuntimeError::Timeout(_))
        ));
    }
}
