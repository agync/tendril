//! `tendril group` subcommands and the `serve` hook that answers group dials.
//!
//! All membership, signing, and authorization logic lives in `tendril-core` and
//! `tendril-runtime`; this module only parses arguments, calls those APIs, and prints JSON.

use std::error::Error;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use clap::{Args, Subcommand};
use serde::Serialize;
use tendril_core::error::CoreError;
use tendril_core::group::{GroupBook, GroupManifest, V2GroupSecrets};
use tendril_core::identity::EndpointIdentity;
use tendril_runtime::{
    BroadcastReport, BrokerDialer, DirectDialer, GroupEvent, GroupFrameKind, GroupHub, GroupPool,
    GroupPoolConfig, HalfOpenGuard, InboundSession, LocalDialer, OverlayDialer, P2pDialer,
    P2pOptions, PathDialer, PathStream, PowerProfile, PreAuthRateLimiter, RelayClientAuth,
    RelayDialer, SessionEvent, StateStore, V2ResponderState, group_add_member, group_create,
    group_remove_member, handle_session_group_frame,
};
use tokio::task::JoinHandle;

use crate::{
    P2pTransportArgs, RelayAuthArgs, build_p2p_dialer_options_with_profile,
    build_p2p_group_dialer_options, listener_port_mapping_override, print_json_line,
    resolve_p2p_relay_auth, resolve_relay_auth, validate_explicit_p2p_args,
};

const DEFAULT_SYNC_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, Args)]
pub struct GroupDialArgs {
    #[command(flatten)]
    relay_auth: RelayAuthArgs,
    /// Enable the p2p (iroh) dialer for `iroh://` member endpoints.
    #[arg(long)]
    p2p: bool,
    #[command(flatten)]
    p2p_args: P2pTransportArgs,
}

impl GroupDialArgs {
    fn p2p_enabled(&self) -> bool {
        self.p2p
            || self.p2p_args.p2p_local
            || !self.p2p_args.p2p_relay.is_empty()
            || self.p2p_args.p2p_pkarr
            || self.p2p_args.p2p_relay_token_file.is_some()
            || self.p2p_args.p2p_api_secret_file.is_some()
    }
}

#[derive(Debug, Subcommand)]
pub enum GroupCommand {
    /// Create a group rooted at the local identity and persist its manifest and rendezvous key.
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        wire_v2: bool,
        #[arg(long = "endpoint")]
        endpoints: Vec<String>,
    },
    /// Add an already paired peer to a group the local identity roots.
    Add {
        group_id: String,
        #[arg(long)]
        peer: String,
        #[arg(long = "cap")]
        caps: Vec<String>,
        #[arg(long = "endpoint")]
        endpoints: Vec<String>,
    },
    /// Revoke a member of a group the local identity roots and rotate its rendezvous key.
    Remove {
        group_id: String,
        #[arg(long)]
        peer: String,
    },
    /// Push the latest manifest (and rendezvous key when admin) to reachable members.
    Sync {
        group_id: String,
        #[arg(long, default_value_t = DEFAULT_SYNC_TIMEOUT_SECS)]
        timeout: u64,
        #[command(flatten)]
        dial: GroupDialArgs,
    },
    /// Broadcast one message to every reachable member holding `group.recv`.
    Broadcast {
        group_id: String,
        #[arg(long, allow_hyphen_values = true)]
        message: String,
        #[arg(long)]
        cap: Option<String>,
        #[arg(long, default_value_t = DEFAULT_SYNC_TIMEOUT_SECS)]
        timeout: u64,
        #[command(flatten)]
        dial: GroupDialArgs,
    },
    /// List stored groups without secrets.
    List,
    /// Show one stored group manifest without secrets.
    Show { group_id: String },
}

fn load_identity(store: &StateStore) -> Result<EndpointIdentity, Box<dyn Error>> {
    Ok(store.load_or_generate_identity(None)?)
}

fn manifest_json(manifest: &GroupManifest) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(serde_json::to_value(manifest)?)
}

fn is_local_root(book: &GroupBook, group_id: &str, identity: &EndpointIdentity) -> bool {
    book.root_signing_pub(group_id) == Some(identity.signing_key().public_key())
}

fn is_active_member(manifest: &GroupManifest, device_id: &str) -> bool {
    manifest.members.iter().any(|m| m.device_id == device_id)
        && !manifest.revoked_members.iter().any(|r| r == device_id)
}

/// Builds the dialer set shared by `group` subcommands and `serve`: direct, local, relay (with
/// auth), overlay, broker, and p2p when `p2p_args` is `Some`.
pub(crate) async fn build_dialers(
    relay_auth: RelayClientAuth,
    p2p_args: Option<&P2pTransportArgs>,
    power_profile: PowerProfile,
) -> Result<Vec<Arc<dyn PathDialer>>, Box<dyn Error>> {
    let mut dialers: Vec<Arc<dyn PathDialer>> = vec![
        Arc::new(DirectDialer::new()),
        Arc::new(LocalDialer::new()),
        Arc::new(RelayDialer::new().with_auth(relay_auth)),
        Arc::new(OverlayDialer::new()),
        Arc::new(BrokerDialer::new()),
    ];
    if let Some(args) = p2p_args {
        validate_explicit_p2p_args(args)?;
        let opts = build_p2p_dialer_options_with_profile(args, "", None, power_profile)?;
        dialers.push(Arc::new(P2pDialer::bind_with_options(opts).await?));
    }
    Ok(dialers)
}

async fn open_pool(
    store: &StateStore,
    identity: EndpointIdentity,
    group_id: &str,
    dial: &GroupDialArgs,
    timeout_secs: u64,
) -> Result<GroupPool, Box<dyn Error>> {
    validate_explicit_p2p_args(&dial.p2p_args)?;
    let auth = resolve_relay_auth(&dial.relay_auth)?;
    let dialers = build_dialers(
        auth.clone(),
        dial.p2p_enabled().then_some(&dial.p2p_args),
        PowerProfile::Standard,
    )
    .await?;
    let mut config = GroupPoolConfig::new(dialers)
        .with_dial_budget(Duration::from_secs(timeout_secs.max(1)))
        .with_relay_auth(auth);
    if dial.p2p_enabled() {
        let p2p_auth = resolve_p2p_relay_auth(&dial.p2p_args)?;
        config = config
            .with_p2p_options(build_p2p_group_dialer_options(&dial.p2p_args, p2p_auth)?)
            .with_p2p_listener_port_mapping(listener_port_mapping_override(&dial.p2p_args));
    }
    Ok(GroupPool::open(
        store.clone(),
        Arc::new(identity),
        group_id,
        config,
        None,
    )?)
}

#[derive(Serialize)]
struct SyncOut<'a> {
    group_id: &'a str,
    seq: u64,
    #[serde(flatten)]
    report: &'a BroadcastReport,
}

pub async fn run(store: Arc<StateStore>, cmd: GroupCommand) -> Result<(), Box<dyn Error>> {
    match cmd {
        GroupCommand::Create {
            name,
            wire_v2,
            endpoints,
        } => create(&store, &name, wire_v2, endpoints),
        GroupCommand::Add {
            group_id,
            peer,
            caps,
            endpoints,
        } => add(&store, &group_id, &peer, caps, endpoints),
        GroupCommand::Remove { group_id, peer } => remove(&store, &group_id, &peer),
        GroupCommand::Sync {
            group_id,
            timeout,
            dial,
        } => {
            let identity = load_identity(&store)?;
            let pool = open_pool(&store, identity, &group_id, &dial, timeout).await?;
            let outcome = tokio::time::timeout(Duration::from_secs(timeout.max(1)), pool.sync())
                .await
                .map_err(|_| "group sync timed out")?;
            let seq = pool.manifest().map(|m| m.seq);
            pool.close();
            let report = outcome?;
            print_json_line(&SyncOut {
                group_id: &group_id,
                seq: seq?,
                report: &report,
            });
            Ok(())
        }
        GroupCommand::Broadcast {
            group_id,
            message,
            cap,
            timeout,
            dial,
        } => {
            let identity = load_identity(&store)?;
            let pool = open_pool(&store, identity, &group_id, &dial, timeout).await?;
            let outcome = tokio::time::timeout(
                Duration::from_secs(timeout.max(1)),
                pool.broadcast(cap.as_deref(), message.as_bytes()),
            )
            .await
            .map_err(|_| "group broadcast timed out")?;
            pool.close();
            print_json_line(&outcome?);
            Ok(())
        }
        GroupCommand::List => list(&store),
        GroupCommand::Show { group_id } => show(&store, &group_id),
    }
}

fn create(
    store: &StateStore,
    name: &str,
    wire_v2: bool,
    endpoints: Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let identity = load_identity(store)?;
    let manifest = group_create(
        store,
        &identity,
        name,
        if wire_v2 { 2 } else { 1 },
        endpoints,
    )?;
    print_json_line(&serde_json::json!({
        "group_id": manifest.group_id,
        "seq": manifest.seq,
        "manifest": manifest_json(&manifest)?,
    }));
    Ok(())
}

fn add(
    store: &StateStore,
    group_id: &str,
    peer: &str,
    caps: Vec<String>,
    endpoints: Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let identity = load_identity(store)?;
    let manifest = group_add_member(store, &identity, group_id, peer, caps, endpoints)?;
    print_json_line(&manifest_json(&manifest)?);
    Ok(())
}

fn remove(store: &StateStore, group_id: &str, peer: &str) -> Result<(), Box<dyn Error>> {
    let identity = load_identity(store)?;
    let manifest = group_remove_member(store, &identity, group_id, peer)?;
    print_json_line(&manifest_json(&manifest)?);
    Ok(())
}

fn role_of(
    book: &GroupBook,
    manifest: &GroupManifest,
    identity: &EndpointIdentity,
) -> &'static str {
    if is_local_root(book, &manifest.group_id, identity) {
        "root"
    } else if is_active_member(manifest, &identity.device_id()) {
        "member"
    } else {
        "removed"
    }
}

fn list(store: &StateStore) -> Result<(), Box<dyn Error>> {
    let identity = load_identity(store)?;
    let book = store.load_group_book()?;
    let groups: Vec<serde_json::Value> = book
        .group_ids()
        .iter()
        .filter_map(|id| book.manifest(id))
        .map(|m| {
            serde_json::json!({
                "group_id": m.group_id,
                "name": m.name,
                "seq": m.seq,
                "min_wire_version": m.min_wire_version,
                "role": role_of(&book, m, &identity),
                "members": m.members.len(),
                "revoked": m.revoked_members.len(),
                "expires_at": m.expires_at,
            })
        })
        .collect();
    print_json_line(&serde_json::json!({ "groups": groups }));
    Ok(())
}

fn show(store: &StateStore, group_id: &str) -> Result<(), Box<dyn Error>> {
    let identity = load_identity(store)?;
    let book = store.load_group_book()?;
    let manifest = book
        .manifest(group_id)
        .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()))?;
    print_json_line(&serde_json::json!({
        "group_id": manifest.group_id,
        "role": role_of(&book, manifest, &identity),
        "rendezvous_seq": book.secrets(group_id).map(V2GroupSecrets::seq),
        "manifest": manifest_json(manifest)?,
    }));
    Ok(())
}

/// Ingests a `0x0A` or `0x0B` received on an ordinary session during `serve` through the
/// runtime, prints the redacted outcome, and reports whether the frame was ingested.
pub fn handle_group_frame(
    store: &StateStore,
    local_id: &str,
    peer_id: &str,
    event: &SessionEvent,
) -> bool {
    let Some(outcome) = handle_session_group_frame(store, local_id, peer_id, event) else {
        return false;
    };
    let kind = match outcome.kind {
        GroupFrameKind::Manifest => "manifest",
        GroupFrameKind::Rendezvous => "rendezvous",
    };
    let verdict = if outcome.ingested {
        "ingested"
    } else {
        "rejected"
    };
    let mut line = serde_json::json!({
        "event": format!("group_{kind}_{verdict}"),
        "group_id": outcome.group_id,
        "seq": outcome.seq,
        "peer_device_id": peer_id,
    });
    if let Some(error) = outcome.error {
        line["error"] = serde_json::Value::String(error);
    }
    print_json_line(&line);
    outcome.ingested
}

/// `serve` glue around the runtime [`GroupHub`]: keeps pools in sync with the stored book and
/// prints each pool's events. `serve` refreshes it at startup, on its 250 ms tick, after each
/// ingested group frame, and before routing an inbound session, so a relay-only member opens its
/// pools (and registers their relay mailboxes) without waiting for an inbound stream.
pub struct ServeGroups {
    hub: GroupHub,
    redact_logs: bool,
    printers: StdMutex<Vec<JoinHandle<()>>>,
}

/// P2P options forwarded by `serve` into [`ServeGroups::new`].
pub struct ServeP2pConfig {
    pub dialer_options: Option<P2pOptions>,
    pub listener_port_mapping: Option<bool>,
}

impl ServeGroups {
    /// Builds the serving hub. Its pools register the identity's relay mailboxes
    /// (`relay_listen`) with `relay_auth`, except on `served_v1_relay`, the `/v1/relay` URL
    /// whose mailbox `serve` already registers and routes to the hub itself.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<StateStore>,
        identity: Arc<EndpointIdentity>,
        dialers: Vec<Arc<dyn PathDialer>>,
        relay_auth: RelayClientAuth,
        served_v1_relay: Option<String>,
        p2p: ServeP2pConfig,
        redact_logs: bool,
        power_profile: PowerProfile,
    ) -> Arc<Self> {
        let mut config = GroupPoolConfig::new(dialers)
            .with_relay_auth(relay_auth)
            .with_relay_listen(true)
            .with_served_v1_relays(served_v1_relay.into_iter().collect())
            .with_power_profile(power_profile)
            .with_p2p_listener_port_mapping(p2p.listener_port_mapping);
        if let Some(opts) = p2p.dialer_options {
            config = config.with_p2p_options(opts);
        }
        Arc::new(Self {
            hub: GroupHub::new((*store).clone(), identity, config, None),
            redact_logs,
            printers: StdMutex::new(Vec::new()),
        })
    }

    /// Syncs pools with the stored book and reports whether any group pool is open.
    pub fn refresh(&self) -> bool {
        match self.hub.sync() {
            Ok(opened) => {
                let mut printers = self.printers.lock().unwrap_or_else(|e| e.into_inner());
                printers.retain(|p| !p.is_finished());
                for pool in opened {
                    printers.push(spawn_event_printer(pool, self.redact_logs));
                }
            }
            Err(err) => tracing::debug!(error = %err, "group pools not synced"),
        }
        !self.hub.pools().is_empty()
    }

    /// Authenticates and routes one inbound session through the hub. Ordinary sessions are
    /// returned to the caller; group sessions are installed in their pool.
    pub async fn accept(
        &self,
        stream: Box<dyn PathStream>,
        v2_state: &V2ResponderState,
        rate_limiter: &PreAuthRateLimiter,
        guard: HalfOpenGuard,
    ) -> Option<InboundSession> {
        match self
            .hub
            .accept(stream, v2_state, Some(rate_limiter), Some(guard))
            .await
        {
            Ok(InboundSession::Group {
                group_id,
                peer_device_id,
            }) => {
                print_json_line(&serde_json::json!({
                    "event": "group_session_established",
                    "group_id": group_id,
                    "peer_device_id": peer_device_id,
                }));
                None
            }
            Ok(ordinary) => Some(ordinary),
            Err(err) => {
                tracing::debug!(error = %err, "inbound session refused");
                None
            }
        }
    }

    pub fn shutdown(&self) {
        self.hub.close();
        for printer in std::mem::take(&mut *self.printers.lock().unwrap_or_else(|e| e.into_inner()))
        {
            printer.abort();
        }
    }
}

fn spawn_event_printer(pool: GroupPool, redact_logs: bool) -> JoinHandle<()> {
    tokio::spawn(async move {
        let group_id = pool.group_id().to_owned();
        loop {
            let Some(event) = pool.poll_event(Duration::from_millis(500)).await else {
                if pool.is_closed() {
                    return;
                }
                continue;
            };
            print_group_event(&group_id, &event, redact_logs);
        }
    })
}

fn print_group_event(group_id: &str, event: &GroupEvent, redact_logs: bool) {
    match event {
        GroupEvent::AppData {
            sender_device_id,
            payload,
        } => {
            let shown = if redact_logs {
                "<redacted>".to_owned()
            } else {
                String::from_utf8_lossy(payload).into_owned()
            };
            print_json_line(&serde_json::json!({
                "event": "group_data",
                "group_id": group_id,
                "sender_device_id": sender_device_id,
                "len": payload.len(),
                "utf8": shown,
            }));
        }
        GroupEvent::ManifestUpdated { seq } => print_json_line(&serde_json::json!({
            "event": "group_manifest_updated",
            "group_id": group_id,
            "seq": seq,
        })),
        GroupEvent::MemberJoined { device_id } => print_json_line(&serde_json::json!({
            "event": "group_member_joined",
            "group_id": group_id,
            "device_id": device_id,
        })),
        GroupEvent::MemberRevoked { device_id } => print_json_line(&serde_json::json!({
            "event": "group_member_revoked",
            "group_id": group_id,
            "device_id": device_id,
        })),
        GroupEvent::Audit(audit) => print_json_line(&serde_json::json!({
            "event": "group_audit",
            "group_id": group_id,
            "subject": audit.subject,
            "cap": audit.cap,
            "allow": audit.allow,
            "reason": audit.reason,
        })),
    }
}
