//! Standalone Tendril v1 and v2 WebSocket ciphertext relay binary.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, ValueEnum};
use tendril_core::crypto::{b64url_decode_array, is_valid_ed25519_public_key};
use tendril_core::relay_auth::validate_relay_auth_secret;
use tendril_relay::{IpCidr, RelayAuthScope, RelayConfig, RelayServer};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliAuthScope {
    All,
    RegisterOnly,
}

impl From<CliAuthScope> for RelayAuthScope {
    fn from(value: CliAuthScope) -> Self {
        match value {
            CliAuthScope::All => Self::All,
            CliAuthScope::RegisterOnly => Self::RegisterOnly,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "tendril-relay",
    about = "Stateless Tendril v1/v2 WebSocket ciphertext relay"
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
    #[arg(long = "allow-mailbox", allow_hyphen_values = true)]
    allow_mailboxes: Vec<String>,
    #[arg(long = "allow-mailboxes-file")]
    allow_mailboxes_file: Option<PathBuf>,
    #[arg(long = "auth-secret-file")]
    auth_secret_file: Option<PathBuf>,
    #[arg(long = "issuer-pub", allow_hyphen_values = true)]
    issuer_pubs: Vec<String>,
    #[arg(long = "auth-scope", value_enum)]
    auth_scope: Option<CliAuthScope>,
}

fn decode_32b_key(raw: &str, label: &str, require_ed25519: bool) -> Result<[u8; 32], String> {
    let trimmed = raw.trim();
    let bytes = b64url_decode_array::<32>(trimmed)
        .map_err(|err| format!("invalid {label} base64url 32-byte key: {err}"))?;
    if require_ed25519 && !is_valid_ed25519_public_key(&bytes) {
        return Err(format!("invalid Ed25519 public key in {label}"));
    }
    Ok(bytes)
}

fn parse_allow_mailboxes_file(path: &Path) -> Result<Vec<[u8; 32]>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read allow-mailboxes file: {err}"))?;
    let mut keys = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let key = decode_32b_key(
            trimmed,
            &format!("allow-mailboxes-file line {}", idx + 1),
            false,
        )?;
        keys.push(key);
    }
    if keys.is_empty() {
        return Err("allow-mailboxes-file must contain at least one mailbox key".to_owned());
    }
    Ok(keys)
}

fn validate_secret_bytes(
    secret: Zeroizing<Vec<u8>>,
    source: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if secret.is_empty() {
        return Err(format!("{source} must not be empty"));
    }
    if secret.last().is_some_and(u8::is_ascii_whitespace) {
        return Err(format!("{source} must not have trailing whitespace"));
    }
    validate_relay_auth_secret(&secret).map_err(|err| format!("{source} length invalid: {err}"))?;
    Ok(secret)
}

fn load_auth_secret(file: Option<&Path>) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    if let Some(path) = file {
        let bytes = Zeroizing::new(
            std::fs::read(path).map_err(|err| format!("failed to read auth-secret-file: {err}"))?,
        );
        return validate_secret_bytes(bytes, "auth-secret-file").map(Some);
    }
    match std::env::var("TENDRIL_RELAY_AUTH_SECRET") {
        Ok(val) => {
            let val = Zeroizing::new(val);
            let bytes = Zeroizing::new(val.as_bytes().to_vec());
            validate_secret_bytes(bytes, "TENDRIL_RELAY_AUTH_SECRET").map(Some)
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("TENDRIL_RELAY_AUTH_SECRET must be valid UTF-8".to_owned())
        }
    }
}

fn build_relay_config(
    args: Args,
    auth_secret: Option<Zeroizing<Vec<u8>>>,
) -> Result<RelayConfig, String> {
    let mut allowed_mailboxes = Vec::with_capacity(args.allow_mailboxes.len());
    for raw in &args.allow_mailboxes {
        allowed_mailboxes.push(decode_32b_key(raw, "--allow-mailbox", false)?);
    }
    if let Some(path) = &args.allow_mailboxes_file {
        allowed_mailboxes.extend(parse_allow_mailboxes_file(path)?);
    }

    let mut trusted_issuers = Vec::with_capacity(args.issuer_pubs.len());
    for raw in &args.issuer_pubs {
        trusted_issuers.push(decode_32b_key(raw, "--issuer-pub", true)?);
    }

    let has_admission =
        !allowed_mailboxes.is_empty() || auth_secret.is_some() || !trusted_issuers.is_empty();
    if args.auth_scope.is_some() && !has_admission {
        return Err(
            "--auth-scope requires at least one admission option (--allow-mailbox, --allow-mailboxes-file, --auth-secret-file, TENDRIL_RELAY_AUTH_SECRET, or --issuer-pub)"
                .to_owned(),
        );
    }

    Ok(RelayConfig {
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
        allowed_mailboxes,
        auth_secret,
        trusted_issuers,
        auth_scope: args.auth_scope.unwrap_or(CliAuthScope::All).into(),
        ..RelayConfig::default()
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let auth_secret = load_auth_secret(args.auth_secret_file.as_deref())?;
    let config = build_relay_config(args, auth_secret)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use tempfile::NamedTempFile;
    use tendril_core::crypto::b64url_encode;

    #[test]
    fn cli_parses_admission_flags_including_hyphenated_keys_and_validates_secrets() {
        let hyphen_key = "-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let args = Args::try_parse_from([
            "tendril-relay",
            "--allow-mailbox",
            hyphen_key,
            "--issuer-pub",
            hyphen_key,
            "--auth-scope",
            "register-only",
        ])
        .expect("parse hyphenated b64url args");
        assert_eq!(args.allow_mailboxes, vec![hyphen_key]);
        assert_eq!(args.issuer_pubs, vec![hyphen_key]);
        assert_eq!(args.auth_scope, Some(CliAuthScope::RegisterOnly));

        let scope_only = Args::try_parse_from(["tendril-relay", "--auth-scope", "register-only"])
            .expect("parse scope only");
        assert!(build_relay_config(scope_only, None).is_err());

        let open_args = Args::try_parse_from(["tendril-relay"]).expect("parse open args");
        assert!(build_relay_config(open_args, None).is_ok());

        let f_empty = NamedTempFile::new().unwrap();
        assert!(load_auth_secret(Some(f_empty.path())).is_err());

        let f_ws = NamedTempFile::new().unwrap();
        std::fs::write(f_ws.path(), b"secret-with-newline\n").unwrap();
        assert!(load_auth_secret(Some(f_ws.path())).is_err());

        let f_big = NamedTempFile::new().unwrap();
        std::fs::write(f_big.path(), vec![b'a'; 4097]).unwrap();
        assert!(load_auth_secret(Some(f_big.path())).is_err());

        let f_ok = NamedTempFile::new().unwrap();
        std::fs::write(f_ok.path(), b"valid-shared-secret").unwrap();
        assert_eq!(
            load_auth_secret(Some(f_ok.path()))
                .unwrap()
                .unwrap()
                .as_slice(),
            b"valid-shared-secret"
        );

        let empty_allow_file = NamedTempFile::new().unwrap();
        assert!(parse_allow_mailboxes_file(empty_allow_file.path()).is_err());

        let comment_only_allow_file = NamedTempFile::new().unwrap();
        std::fs::write(comment_only_allow_file.path(), "# comment only\n\n  \n").unwrap();
        assert!(parse_allow_mailboxes_file(comment_only_allow_file.path()).is_err());

        let empty_file_args = Args::try_parse_from([
            "tendril-relay",
            "--allow-mailboxes-file",
            empty_allow_file.path().to_str().unwrap(),
        ])
        .unwrap();
        assert!(build_relay_config(empty_file_args, None).is_err());

        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let pk_b64 = b64url_encode(&sk.verifying_key().to_bytes());
        let allow_file = NamedTempFile::new().unwrap();
        std::fs::write(allow_file.path(), format!("# comment\n\n  {pk_b64}  \n")).unwrap();
        let loaded = parse_allow_mailboxes_file(allow_file.path()).unwrap();
        assert_eq!(loaded, vec![sk.verifying_key().to_bytes()]);

        let valid_scoped = Args::try_parse_from([
            "tendril-relay",
            "--issuer-pub",
            &pk_b64,
            "--auth-scope",
            "register-only",
        ])
        .unwrap();
        let built = build_relay_config(valid_scoped, None).unwrap();
        assert_eq!(built.auth_scope, RelayAuthScope::RegisterOnly);
    }
}
