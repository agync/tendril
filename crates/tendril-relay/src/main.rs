//! Standalone Tendril v1 WebSocket ciphertext relay binary.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use tendril_relay::{IpCidr, RelayConfig, RelayServer};

#[derive(Debug, Parser)]
#[command(
    name = "tendril-relay",
    about = "Stateless Tendril v1 WebSocket ciphertext relay"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    #[arg(long, default_value = "localhost")]
    host: String,
    #[arg(long, default_value_t = 8)]
    max_pending: usize,
    #[arg(long, default_value_t = 4096)]
    max_connections: usize,
    #[arg(long, default_value_t = 1024)]
    max_mailboxes: usize,
    #[arg(long, default_value_t = 300)]
    idle_secs: u64,
    #[arg(long, default_value_t = 15)]
    accept_timeout_secs: u64,
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    #[arg(long)]
    tls_key: Option<PathBuf>,
    #[arg(long = "trusted-proxy")]
    trusted_proxies: Vec<IpCidr>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = RelayConfig {
        listen_addr: args.listen,
        host: args.host,
        max_pending_per_mailbox: args.max_pending,
        max_total_connections: args.max_connections,
        max_mailboxes: args.max_mailboxes,
        idle_timeout: Duration::from_secs(args.idle_secs),
        accept_timeout: Duration::from_secs(args.accept_timeout_secs),
        tls_cert_path: args.tls_cert,
        tls_key_path: args.tls_key,
        trusted_proxies: args.trusted_proxies,
        ..RelayConfig::default()
    };

    let server = RelayServer::bind(config).await?;
    let ws_url = server.ws_url();
    tracing::info!(endpoint = %ws_url, "tendril-relay listening");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(());
    });
    server.serve_until(shutdown_rx).await?;
    Ok(())
}
