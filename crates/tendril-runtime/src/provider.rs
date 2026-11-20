//! Untrusted byte-stream provider traits, outer frame bounds, and stream adapters.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use tendril_core::MAX_FRAME_LEN;
use tendril_core::policy::ProviderId;
use tendril_core::wire::{ResumableFrameReader, encode_frame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::error::RuntimeError;

/// Default per-write backpressure timeout enforced across all path providers (`1 s`).
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum outer Tendril wire frame length (`2 B` length prefix + `MAX_FRAME_LEN` body).
pub const MAX_OUTER_FRAME_LEN: usize = 2 + MAX_FRAME_LEN;

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

    /// Opens an outbound stream to `endpoint`.
    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError>;
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

#[async_trait]
impl<S> PathStream for IoPathStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn provider_id(&self) -> ProviderId {
        self.provider
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_ip
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if bytes.len() > MAX_OUTER_FRAME_LEN {
            return Err(RuntimeError::FrameTooLarge {
                size: bytes.len(),
                max: MAX_OUTER_FRAME_LEN,
            });
        }
        let write_fut = async {
            self.stream.write_all(bytes).await?;
            self.stream.flush().await
        };
        match timeout(self.write_timeout, write_fut).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(RuntimeError::Io(err)),
            Err(_) => Err(RuntimeError::Timeout("stream write timed out")),
        }
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
        if self.offset < self.prefix.len() {
            let avail = self.prefix.len() - self.offset;
            let take = avail.min(buf.len());
            buf[..take].copy_from_slice(&self.prefix[self.offset..self.offset + take]);
            self.offset += take;
            return Ok(take);
        }
        self.inner.recv_chunk(buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        self.inner.close().await
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
