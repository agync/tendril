//! Direct LAN / IP TCP path provider (`direct`).

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use tendril_core::policy::ProviderId;
use tokio::net::{TcpListener, TcpStream};

use crate::error::RuntimeError;
use crate::provider::{DEFAULT_WRITE_TIMEOUT, IoPathStream, PathDialer, PathListener, PathStream};

/// TCP listener implementing the `direct` path provider.
pub struct DirectListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    write_timeout: Duration,
    allow_ips: Option<HashSet<IpAddr>>,
}

impl DirectListener {
    /// Binds a TCP listener at `addr`, optionally enforcing an IP allow-list.
    pub async fn bind(
        addr: SocketAddr,
        allow_ips: Option<HashSet<IpAddr>>,
    ) -> Result<Self, RuntimeError> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            allow_ips,
        })
    }

    /// Overrides the write backpressure timeout applied to accepted streams.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Returns the local socket address bound by this listener.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

#[async_trait]
impl PathListener for DirectListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            if let Some(allowed) = &self.allow_ips
                && !allowed.contains(&peer.ip())
            {
                drop(stream);
                continue;
            }
            let _ = stream.set_nodelay(true);
            return Ok(Box::new(IoPathStream::new(
                ProviderId::Direct,
                Some(peer.ip()),
                self.write_timeout,
                stream,
            )));
        }
    }

    fn local_endpoint(&self) -> String {
        self.local_addr.to_string()
    }
}

/// Dialer opening direct TCP streams (`direct`).
#[derive(Debug, Clone)]
pub struct DirectDialer {
    write_timeout: Duration,
}

impl Default for DirectDialer {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectDialer {
    /// Constructs a `DirectDialer` with [`DEFAULT_WRITE_TIMEOUT`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }

    /// Overrides the per-write backpressure timeout.
    #[must_use]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Connects directly to `addr`.
    pub async fn connect(&self, addr: SocketAddr) -> Result<Box<dyn PathStream>, RuntimeError> {
        let stream = TcpStream::connect(addr).await?;
        let peer_ip = stream.peer_addr().ok().map(|a| a.ip());
        let _ = stream.set_nodelay(true);
        Ok(Box::new(IoPathStream::new(
            ProviderId::Direct,
            peer_ip,
            self.write_timeout,
            stream,
        )))
    }
}

#[async_trait]
impl PathDialer for DirectDialer {
    fn provider_id(&self) -> ProviderId {
        ProviderId::Direct
    }

    async fn dial(&self, endpoint: &str) -> Result<Box<dyn PathStream>, RuntimeError> {
        let addr_str = endpoint.strip_prefix("tcp://").unwrap_or(endpoint);
        let addr: SocketAddr = addr_str.parse().map_err(|err| {
            RuntimeError::Protocol(format!("invalid tcp endpoint '{endpoint}': {err}"))
        })?;
        self.connect(addr).await
    }
}
