//! Standalone Tendril v1 and v2 WebSocket ciphertext relay binary.

use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, ValueEnum};
use tendril_core::crypto::{b64url_decode_array, is_valid_ed25519_public_key};
use tendril_core::relay_auth::validate_relay_auth_secret;
use tendril_core::v2::canonical_relay_host;
use tendril_relay::server::{MAX_AUTH_SECRET_FILE_BYTES, read_private_file};
use tendril_relay::{IpCidr, RelayAuthScope, RelayConfig, RelayServer, TrustedProxyHeader};
use zeroize::Zeroizing;

const MAX_ALLOW_MAILBOXES_FILE_BYTES: usize = 1024 * 1024;
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8443";
const DEFAULT_RELAY_HOST: &str = "localhost";
const PLATFORM_HOST_ENVS: &[&str] = &[
    "RAILWAY_PUBLIC_DOMAIN",
    "RENDER_EXTERNAL_HOSTNAME",
    "KOYEB_PUBLIC_DOMAIN",
];

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliTrustedProxyHeader {
    Xff,
    Forwarded,
}

impl From<CliTrustedProxyHeader> for TrustedProxyHeader {
    fn from(value: CliTrustedProxyHeader) -> Self {
        match value {
            CliTrustedProxyHeader::Xff => Self::Xff,
            CliTrustedProxyHeader::Forwarded => Self::Forwarded,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "tendril-relay",
    about = "Stateless Tendril v1/v2 WebSocket ciphertext relay"
)]
struct Args {
    /// Listen socket address (falls back to TENDRIL_RELAY_LISTEN, 0.0.0.0:$PORT, or 127.0.0.1:8443).
    #[arg(long)]
    listen: Option<SocketAddr>,
    /// Canonical relay host name (falls back to TENDRIL_RELAY_HOST, PaaS host env vars, or localhost).
    #[arg(long)]
    host: Option<String>,
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
    #[arg(long = "trusted-proxy-header", value_enum, default_value_t = CliTrustedProxyHeader::Xff)]
    trusted_proxy_header: CliTrustedProxyHeader,
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
    let meta = std::fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat allow-mailboxes-file: {err}"))?;
    if meta.file_type().is_symlink() {
        return Err("allow-mailboxes-file must not be a symlink".to_owned());
    }
    if !meta.file_type().is_file() {
        return Err("allow-mailboxes-file must be a regular file".to_owned());
    }
    if meta.len() > MAX_ALLOW_MAILBOXES_FILE_BYTES as u64 {
        return Err(format!(
            "allow-mailboxes-file exceeds maximum size of {MAX_ALLOW_MAILBOXES_FILE_BYTES} bytes"
        ));
    }
    let file = std::fs::File::open(path)
        .map_err(|err| format!("failed to open allow-mailboxes-file: {err}"))?;
    let mut raw = Vec::new();
    file.take((MAX_ALLOW_MAILBOXES_FILE_BYTES as u64).saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|err| format!("failed to read allow-mailboxes-file: {err}"))?;
    if raw.len() > MAX_ALLOW_MAILBOXES_FILE_BYTES {
        return Err(format!(
            "allow-mailboxes-file exceeds maximum size of {MAX_ALLOW_MAILBOXES_FILE_BYTES} bytes"
        ));
    }
    let contents = String::from_utf8(raw)
        .map_err(|err| format!("allow-mailboxes-file must be valid UTF-8: {err}"))?;
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
        let bytes = read_private_file(path, MAX_AUTH_SECRET_FILE_BYTES, "auth-secret-file")?;
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

fn read_env_var(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(val) => Ok(Some(val)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8")),
    }
}

fn resolve_listen_addr<F>(
    cli_listen: Option<SocketAddr>,
    mut get_env: F,
) -> Result<SocketAddr, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    if let Some(addr) = cli_listen {
        return Ok(addr);
    }
    if let Some(raw) = get_env("TENDRIL_RELAY_LISTEN")? {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("TENDRIL_RELAY_LISTEN must not be empty".to_owned());
        }
        return trimmed
            .parse::<SocketAddr>()
            .map_err(|err| format!("invalid TENDRIL_RELAY_LISTEN '{trimmed}': {err}"));
    }
    if let Some(raw_port) = get_env("PORT")? {
        let trimmed = raw_port.trim();
        if !trimmed.is_empty() {
            let port: u16 = trimmed
                .parse()
                .map_err(|err| format!("invalid PORT '{trimmed}': {err}"))?;
            if port == 0 {
                return Err("PORT must be in 1..=65535".to_owned());
            }
            return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
        }
    }
    Ok(DEFAULT_LISTEN_ADDR
        .parse()
        .expect("default listen address parses"))
}

fn resolve_relay_host<F>(cli_host: Option<String>, mut get_env: F) -> Result<String, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    let candidate = if let Some(host) = cli_host {
        host
    } else if let Some(raw) = get_env("TENDRIL_RELAY_HOST")? {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("TENDRIL_RELAY_HOST must not be empty".to_owned());
        }
        trimmed.to_owned()
    } else {
        let mut detected = None;
        for name in PLATFORM_HOST_ENVS {
            if let Some(raw) = get_env(name)? {
                let trimmed = raw.trim();
                if !trimmed.is_empty() {
                    detected = Some(trimmed.to_owned());
                    break;
                }
            }
        }
        if detected.is_none()
            && let Some(raw) = get_env("FLY_APP_NAME")?
        {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                detected = Some(format!("{trimmed}.fly.dev"));
            }
        }
        detected.unwrap_or_else(|| DEFAULT_RELAY_HOST.to_owned())
    };
    canonical_relay_host(&candidate)
        .map_err(|err| format!("invalid relay host '{candidate}': {err}"))
}

fn build_relay_config_with_env<F>(
    args: Args,
    auth_secret: Option<Zeroizing<Vec<u8>>>,
    mut get_env: F,
) -> Result<RelayConfig, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    let listen_addr = resolve_listen_addr(args.listen, &mut get_env)?;
    let host = resolve_relay_host(args.host, &mut get_env)?;

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
        listen_addr,
        host,
        max_pending_per_mailbox: args.max_pending,
        max_total_connections: args.max_connections,
        max_mailboxes: args.max_mailboxes,
        idle_timeout: Duration::from_secs(args.idle_secs),
        accept_timeout: Duration::from_secs(args.accept_timeout_secs),
        tls_cert_path: args.tls_cert,
        tls_key_path: args.tls_key,
        trusted_proxies: args.trusted_proxies,
        trusted_proxy_header: args.trusted_proxy_header.into(),
        allowed_mailboxes,
        auth_secret,
        trusted_issuers,
        auth_scope: args.auth_scope.unwrap_or(CliAuthScope::All).into(),
        ..RelayConfig::default()
    })
}

fn build_relay_config(
    args: Args,
    auth_secret: Option<Zeroizing<Vec<u8>>>,
) -> Result<RelayConfig, String> {
    build_relay_config_with_env(args, auth_secret, read_env_var)
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
        assert_eq!(built.trusted_proxy_header, TrustedProxyHeader::Xff);

        let fwd_args =
            Args::try_parse_from(["tendril-relay", "--trusted-proxy-header", "forwarded"])
                .expect("parse forwarded header selector");
        let fwd_cfg = build_relay_config(fwd_args, None).unwrap();
        assert_eq!(fwd_cfg.trusted_proxy_header, TrustedProxyHeader::Forwarded);
    }

    #[cfg(unix)]
    #[test]
    fn sec18_auth_secret_file_rejects_symlink_and_world_readable() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::TempDir::new().unwrap();
        let secret_path = dir.path().join("secret.bin");
        std::fs::write(&secret_path, b"valid-shared-secret").unwrap();

        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load_auth_secret(Some(&secret_path)).is_err(),
            "0o644 auth-secret-file must be rejected"
        );

        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_auth_secret(Some(&secret_path)).is_ok());

        let link_path = dir.path().join("secret-link.bin");
        symlink(&secret_path, &link_path).unwrap();
        assert!(
            load_auth_secret(Some(&link_path)).is_err(),
            "symlink auth-secret-file must be rejected"
        );
    }

    #[test]
    fn paas_env_resolution_and_precedence() {
        use std::collections::HashMap;

        let map_lookup = |vars: &HashMap<&str, &str>| {
            let map: HashMap<String, String> = vars
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            move |key: &str| -> Result<Option<String>, String> { Ok(map.get(key).cloned()) }
        };

        // Defaults with empty environment.
        let empty = HashMap::new();
        let default_args = Args::try_parse_from(["tendril-relay"]).unwrap();
        let default_cfg =
            build_relay_config_with_env(default_args, None, map_lookup(&empty)).unwrap();
        assert_eq!(default_cfg.listen_addr, "127.0.0.1:8443".parse().unwrap());
        assert_eq!(default_cfg.host, "localhost");

        // PORT binds 0.0.0.0:<PORT>; FLY_APP_NAME maps to <app>.fly.dev.
        let fly_vars = HashMap::from([("PORT", "8080"), ("FLY_APP_NAME", "my-tendril")]);
        let fly_args = Args::try_parse_from(["tendril-relay"]).unwrap();
        let fly_cfg = build_relay_config_with_env(fly_args, None, map_lookup(&fly_vars)).unwrap();
        assert_eq!(fly_cfg.listen_addr, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(fly_cfg.host, "my-tendril.fly.dev");

        // TENDRIL_RELAY_LISTEN beats PORT; RAILWAY_PUBLIC_DOMAIN beats RENDER/KOYEB/FLY.
        let precedence_vars = HashMap::from([
            ("PORT", "8080"),
            ("TENDRIL_RELAY_LISTEN", "127.0.0.1:9443"),
            ("RAILWAY_PUBLIC_DOMAIN", "relay.up.railway.app"),
            ("RENDER_EXTERNAL_HOSTNAME", "relay.onrender.com"),
            ("KOYEB_PUBLIC_DOMAIN", "relay.koyeb.app"),
            ("FLY_APP_NAME", "ignored-fly"),
        ]);
        let p_args = Args::try_parse_from(["tendril-relay"]).unwrap();
        let p_cfg =
            build_relay_config_with_env(p_args, None, map_lookup(&precedence_vars)).unwrap();
        assert_eq!(p_cfg.listen_addr, "127.0.0.1:9443".parse().unwrap());
        assert_eq!(p_cfg.host, "relay.up.railway.app");

        // TENDRIL_RELAY_HOST beats platform domain vars and canonicalizes trailing dots/case.
        let host_override = HashMap::from([
            ("TENDRIL_RELAY_HOST", "RELAY.Example.COM."),
            ("RAILWAY_PUBLIC_DOMAIN", "ignored.up.railway.app"),
        ]);
        let ho_args = Args::try_parse_from(["tendril-relay"]).unwrap();
        let ho_cfg =
            build_relay_config_with_env(ho_args, None, map_lookup(&host_override)).unwrap();
        assert_eq!(ho_cfg.host, "relay.example.com");

        // Explicit CLI flags override all env vars.
        let cli_args = Args::try_parse_from([
            "tendril-relay",
            "--listen",
            "127.0.0.1:7443",
            "--host",
            "cli.example",
        ])
        .unwrap();
        let cli_cfg =
            build_relay_config_with_env(cli_args, None, map_lookup(&precedence_vars)).unwrap();
        assert_eq!(cli_cfg.listen_addr, "127.0.0.1:7443".parse().unwrap());
        assert_eq!(cli_cfg.host, "cli.example");

        // Render and Koyeb fallbacks work when higher-priority platform vars are empty or absent.
        let render_vars = HashMap::from([
            ("RAILWAY_PUBLIC_DOMAIN", "  "),
            ("RENDER_EXTERNAL_HOSTNAME", "relay-svc.onrender.com"),
            ("FLY_APP_NAME", "fallback-fly"),
        ]);
        assert_eq!(
            resolve_relay_host(None, map_lookup(&render_vars)).unwrap(),
            "relay-svc.onrender.com"
        );
        let koyeb_vars = HashMap::from([
            ("KOYEB_PUBLIC_DOMAIN", "relay-svc.koyeb.app"),
            ("FLY_APP_NAME", "fallback-fly"),
        ]);
        assert_eq!(
            resolve_relay_host(None, map_lookup(&koyeb_vars)).unwrap(),
            "relay-svc.koyeb.app"
        );

        // Blank PORT falls through to default; invalid/empty explicit overrides fail closed.
        let blank_port = HashMap::from([("PORT", "  ")]);
        assert_eq!(
            resolve_listen_addr(None, map_lookup(&blank_port)).unwrap(),
            "127.0.0.1:8443".parse::<SocketAddr>().unwrap()
        );
        for bad_port in ["0", "70000", "abc"] {
            let vars = HashMap::from([("PORT", bad_port)]);
            assert!(resolve_listen_addr(None, map_lookup(&vars)).is_err());
        }
        for bad_listen in ["", "   ", "not-an-addr"] {
            let vars = HashMap::from([("TENDRIL_RELAY_LISTEN", bad_listen)]);
            assert!(resolve_listen_addr(None, map_lookup(&vars)).is_err());
        }
        for bad_host in ["", "  ", "https://bad.example", "bad.example:8443"] {
            let vars = HashMap::from([("TENDRIL_RELAY_HOST", bad_host)]);
            assert!(resolve_relay_host(None, map_lookup(&vars)).is_err());
        }
        assert!(
            resolve_relay_host(Some("bad.example/path".to_owned()), map_lookup(&empty)).is_err()
        );
    }
}
