//! Authenticated refusal wired into the runtime listeners (`spec/wire-v1.md` Section 5.4,
//! `spec/wire-v2.md` Sections 3.1.3.3 and 3.1.4, `spec/conformance.md` `REF-nn`): the v1 close
//! sequence over real loopback TCP, the v2 decoy timing of a `msg2` refusal, audit gating,
//! half-open slots on an untrusted provider and initiator error mapping.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tendril_core::RefusalReason;
use tendril_core::crypto::{SigningKeypair, StaticKeypair};
use tendril_core::error::CoreError;
use tendril_core::identity::EndpointIdentity;
use tendril_core::policy::ProviderId;
use tendril_core::roster::{OperatorEndpoint, Roster, V2PeerSecrets};
use tendril_core::v2::PaddingPolicy;
use tendril_runtime::providers::hints::{HintDialerConfig, HintDialers};
use tendril_runtime::{
    ConnectOpts, DEFAULT_PRE_AUTH_TIMEOUT, DirectDialer, DirectListener, PathDialer, PathListener,
    PathReader, PathStream, PathWriter, PreAuthConfig, PreAuthRateLimiter, PrefixedPathStream,
    REFUSAL_LINGER, RefusalAudit, RefusalState, RosterAccess, RuntimeError, SessionDriver,
    SessionEvent, V2ResponderConfig, V2ResponderState, V2SessionDriver, peek_exact,
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn identity(tag: u8) -> EndpointIdentity {
    EndpointIdentity::from_keys(
        StaticKeypair::from_scalar([tag; 32]),
        SigningKeypair::from_seed([tag.wrapping_add(1); 32]),
    )
}

fn secrets() -> V2PeerSecrets {
    V2PeerSecrets::new([0x31; 32], [0x32; 32])
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wire {
    V1,
    V2,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Standing {
    /// Revoked with a live refusal notice.
    Revoked,
    /// Revoked with `notify: false`.
    RevokedSilent,
    /// Known but never confirmed.
    Pending,
    /// Confirmed and admitted.
    Active,
}

impl Standing {
    fn code(self) -> u16 {
        match self {
            Self::Revoked | Self::RevokedSilent => 4001,
            Self::Pending => 4004,
            Self::Active => 0,
        }
    }

    fn reason(self) -> RefusalReason {
        match self {
            Self::Pending => RefusalReason::Pending,
            _ => RefusalReason::Revoked,
        }
    }
}

/// The host's roster holding `client` in `standing`.
fn host_roster(client: &EndpointIdentity, wire: Wire, standing: Standing) -> Roster {
    let mut roster = Roster::new();
    roster
        .record_pending_pair(
            *client.static_key().public_bytes(),
            None,
            "Phone".into(),
            "phone".into(),
            "1234".into(),
        )
        .unwrap();
    if standing != Standing::Pending {
        roster
            .confirm_peer(&client.device_id(), Some("1234"))
            .unwrap();
    }
    if wire == Wire::V2 {
        roster
            .upgrade_peer_to_v2(&client.device_id(), secrets())
            .unwrap();
    }
    match standing {
        Standing::Revoked => roster
            .revoke_peer_at(&client.device_id(), true, now())
            .unwrap(),
        Standing::RevokedSilent => roster
            .revoke_peer_at(&client.device_id(), false, now())
            .unwrap(),
        Standing::Pending | Standing::Active => {}
    }
    roster
}

/// The client's roster: an `Active` pin of `host`.
fn client_roster(host: &EndpointIdentity, wire: Wire) -> Roster {
    let mut roster = Roster::new();
    roster
        .insert_pinned_host(
            host.host_id().to_owned(),
            "Studio".into(),
            *host.static_key().public_bytes(),
            Some(host.signing_key().public_key().clone()),
            host.rotation_seq(),
            Vec::new(),
        )
        .unwrap();
    if wire == Wire::V2 {
        roster
            .upgrade_peer_to_v2(host.host_id(), secrets())
            .unwrap();
    }
    roster
}

async fn listener() -> (DirectListener, String) {
    let l = DirectListener::bind("127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let addr = l.local_addr().to_string();
    (l, addr)
}

/// Accepts the next connection that starts a Tendril handshake. A host daemon may probe fresh
/// loopback ports with a stray request; it is skipped, never counted as a peer.
async fn accept_tendril(listener: &mut DirectListener) -> Box<dyn PathStream> {
    loop {
        let mut stream = listener.accept().await.unwrap();
        let peeked =
            tokio::time::timeout(Duration::from_secs(2), peek_exact(stream.as_mut(), 3)).await;
        if let Ok(Ok(prefix)) = peeked
            && prefix.starts_with(b"TND")
        {
            return Box::new(PrefixedPathStream::new(stream, prefix));
        }
    }
}

async fn dial(addr: &str) -> Box<dyn PathStream> {
    DirectDialer::new().dial(addr).await.unwrap()
}

/// Sockets a [`Wrapped`] stream parks on drop instead of closing.
type Held = Arc<Mutex<Vec<Box<dyn PathStream>>>>;

/// A [`PathStream`] decorator for the tests: overrides the provider class and transport id,
/// keeps the socket open when dropped, and runs a hook after the first write.
struct Wrapped {
    inner: Option<Box<dyn PathStream>>,
    provider: Option<ProviderId>,
    transport_id: Option<String>,
    keep: Option<Held>,
    after_first_send: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Writes allowed before every later write stalls forever.
    stall_after: Option<usize>,
    sent: usize,
}

impl Wrapped {
    fn new(inner: Box<dyn PathStream>) -> Self {
        Self {
            inner: Some(inner),
            provider: None,
            transport_id: None,
            keep: None,
            after_first_send: None,
            stall_after: None,
            sent: 0,
        }
    }

    fn stall_after_writes(mut self, writes: usize) -> Self {
        self.stall_after = Some(writes);
        self
    }

    fn untrusted(mut self, transport_id: String) -> Self {
        self.provider = Some(ProviderId::Relay);
        self.transport_id = Some(transport_id);
        self
    }

    fn keep_open(mut self, keep: Held) -> Self {
        self.keep = Some(keep);
        self
    }

    fn after_first_send(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.after_first_send = Some(hook);
        self
    }

    fn stream(&self) -> &dyn PathStream {
        self.inner.as_deref().expect("stream present")
    }

    fn stream_mut(&mut self) -> &mut dyn PathStream {
        self.inner.as_deref_mut().expect("stream present")
    }
}

impl Drop for Wrapped {
    fn drop(&mut self) {
        if let (Some(keep), Some(inner)) = (&self.keep, self.inner.take()) {
            keep.lock().unwrap().push(inner);
        }
    }
}

#[async_trait]
impl PathStream for Wrapped {
    fn provider_id(&self) -> ProviderId {
        self.provider.unwrap_or_else(|| self.stream().provider_id())
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        if self.provider.is_some() {
            None
        } else {
            self.stream().peer_ip()
        }
    }

    fn peer_transport_id(&self) -> Option<String> {
        self.transport_id.clone()
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if self.stall_after.is_some_and(|n| self.sent >= n) {
            std::future::pending::<()>().await;
        }
        self.sent += 1;
        self.stream_mut().send_chunk(bytes).await?;
        if let Some(hook) = self.after_first_send.take() {
            hook();
        }
        Ok(())
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.stream_mut().recv_chunk(buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        if self.keep.is_some() {
            return Ok(());
        }
        self.stream_mut().close().await
    }

    async fn shutdown_write(&mut self) -> Result<(), RuntimeError> {
        self.stream_mut().shutdown_write().await
    }

    fn into_split(mut self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        self.inner.take().expect("stream present").into_split()
    }
}

enum Client {
    V1(SessionDriver),
    V2(V2SessionDriver),
}

impl Client {
    async fn connect(
        wire: Wire,
        stream: Box<dyn PathStream>,
        me: &EndpointIdentity,
        host: &EndpointIdentity,
    ) -> Result<Self, RuntimeError> {
        let mut roster = client_roster(host, wire);
        match wire {
            Wire::V1 => {
                SessionDriver::connect(stream, me, host.host_id(), None, &mut roster, now())
                    .await
                    .map(Self::V1)
            }
            Wire::V2 => {
                V2SessionDriver::connect(stream, me, host.host_id(), None, &mut roster, now())
                    .await
                    .map(Self::V2)
            }
        }
    }

    async fn send_data(&mut self, data: &[u8]) -> Result<(), RuntimeError> {
        match self {
            Self::V1(s) => s.send_data(data).await,
            Self::V2(s) => s.send_data(data).await,
        }
    }

    async fn next_event(
        &mut self,
        roster: &mut Roster,
    ) -> Result<Option<SessionEvent>, RuntimeError> {
        let fut = async {
            match self {
                Self::V1(s) => s.next_event_now(roster).await,
                Self::V2(s) => s.next_event_now(roster).await,
            }
        };
        tokio::time::timeout(Duration::from_secs(5), fut)
            .await
            .expect("event in time")
    }

    /// Reads events until a close; `Ok(None)` when the stream ended without one.
    async fn next_close(
        &mut self,
        host: &EndpointIdentity,
        wire: Wire,
    ) -> Result<Option<(u16, String)>, RuntimeError> {
        let mut roster = client_roster(host, wire);
        loop {
            match self.next_event(&mut roster).await? {
                Some(SessionEvent::Closed { code, reason }) => return Ok(Some((code, reason))),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }
}

/// One accepted host connection of `wire` against `roster` with the endpoint's `limiter` and
/// `v2_state`.
async fn host_accept(
    wire: Wire,
    stream: Box<dyn PathStream>,
    host: &EndpointIdentity,
    roster: &Mutex<Roster>,
    limiter: &PreAuthRateLimiter,
    v2_state: &V2ResponderState,
) -> Result<(), RuntimeError> {
    match wire {
        Wire::V1 => SessionDriver::accept_locked(
            stream,
            host,
            roster,
            now(),
            Some(limiter),
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .map(|_| ()),
        Wire::V2 => V2SessionDriver::accept_locked(
            stream,
            host,
            roster,
            now(),
            v2_state,
            Some(limiter),
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
        .map(|_| ()),
    }
}

fn limiter_with(state: &RefusalState) -> PreAuthRateLimiter {
    PreAuthRateLimiter::new(PreAuthConfig::default()).with_refusal_state(state.clone())
}

fn audit_state() -> (RefusalState, Arc<Mutex<Vec<RefusalAudit>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    (
        RefusalState::with_audit_sink(move |ev| sink.lock().unwrap().push(ev.clone())),
        log,
    )
}

fn assert_refused_error(err: &CoreError, standing: Standing) {
    match (err, standing) {
        (CoreError::PeerRevoked(_), Standing::Revoked | Standing::RevokedSilent) => {}
        (CoreError::PeerPending(_), Standing::Pending) => {}
        other => panic!("unexpected accept error {other:?}"),
    }
}

/// REF-15 over real TCP: the initiator writes `DATA` right after it reports `Established` and
/// still receives the close with the refusal code, not a reset. Also the v1 half of REF-24.
async fn v1_refusal_survives_data_after_connect(standing: Standing) {
    let host = identity(0x60);
    let me = identity(0x50);
    let roster = Arc::new(Mutex::new(host_roster(&me, Wire::V1, standing)));
    let state = RefusalState::new();
    let limiter = limiter_with(&state);
    let (mut l, addr) = listener().await;

    let host_c = host.clone();
    let roster_c = Arc::clone(&roster);
    let accept = tokio::spawn(async move {
        let stream = accept_tendril(&mut l).await;
        host_accept(
            Wire::V1,
            stream,
            &host_c,
            &roster_c,
            &limiter,
            &V2ResponderState::new(),
        )
        .await
    });

    let mut client = Client::connect(Wire::V1, dial(&addr).await, &me, &host)
        .await
        .expect("a v1 connect must not wait for a post-msg3 frame");
    // Several chunks so unread inbound data would reset a connection closed without a drain.
    for _ in 0..4 {
        client
            .send_data(&[0x5a; 4096])
            .await
            .expect("data after connect");
    }
    let closed = client
        .next_close(&host, Wire::V1)
        .await
        .expect("close, not a reset");
    assert_eq!(closed, Some((standing.code(), String::new())));

    let err = client
        .send_data(b"late")
        .await
        .expect_err("session is closed");
    assert_eq!(err.refusal(), Some(standing.reason()), "{err:?}");

    let accepted = accept.await.unwrap();
    let Err(RuntimeError::Core(core)) = accepted else {
        panic!("the host's accept must fail: {accepted:?}");
    };
    assert_refused_error(&core, standing);
}

#[tokio::test(flavor = "multi_thread")]
async fn ref_15_v1_revoked_initiator_sees_close_after_data_over_tcp() {
    v1_refusal_survives_data_after_connect(Standing::Revoked).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ref_15_v1_pending_initiator_sees_close_after_data_over_tcp() {
    v1_refusal_survives_data_after_connect(Standing::Pending).await;
}

/// A v1 revoked initiator whose notice is off gets no frame: the stream just ends.
#[tokio::test(flavor = "multi_thread")]
async fn v1_silent_revocation_writes_nothing_after_msg2() {
    let host = identity(0x61);
    let me = identity(0x51);
    let roster = Mutex::new(host_roster(&me, Wire::V1, Standing::RevokedSilent));
    let (state, log) = audit_state();
    let limiter = limiter_with(&state);
    let (mut l, addr) = listener().await;
    let host_c = host.clone();
    let accept = tokio::spawn(async move {
        let stream = accept_tendril(&mut l).await;
        host_accept(
            Wire::V1,
            stream,
            &host_c,
            &roster,
            &limiter,
            &V2ResponderState::new(),
        )
        .await
    });
    let mut client = Client::connect(Wire::V1, dial(&addr).await, &me, &host)
        .await
        .unwrap();
    let closed = client.next_close(&host, Wire::V1).await;
    assert!(matches!(closed, Ok(None) | Err(_)), "{closed:?}");
    assert!(matches!(
        accept.await.unwrap(),
        Err(RuntimeError::Core(CoreError::PeerRevoked(_)))
    ));
    assert!(log.lock().unwrap().is_empty(), "no refusal was sent");
}

/// REF-16 on Wire v1: two attempts by one peer within the limiter window. The first is
/// refused and audited, the second is silent and not audited.
#[tokio::test(flavor = "multi_thread")]
async fn ref_16_v1_second_attempt_is_silent_and_audited_once() {
    let host = identity(0x62);
    let me = identity(0x52);
    let roster = Arc::new(Mutex::new(host_roster(&me, Wire::V1, Standing::Revoked)));
    let (state, log) = audit_state();
    let limiter = limiter_with(&state);
    let (mut l, addr) = listener().await;
    let host_c = host.clone();
    let roster_c = Arc::clone(&roster);
    let accept = tokio::spawn(async move {
        let mut verdicts = Vec::new();
        for _ in 0..2 {
            let stream = accept_tendril(&mut l).await;
            verdicts.push(
                host_accept(
                    Wire::V1,
                    stream,
                    &host_c,
                    &roster_c,
                    &limiter,
                    &V2ResponderState::new(),
                )
                .await,
            );
        }
        verdicts
    });

    let mut first = Client::connect(Wire::V1, dial(&addr).await, &me, &host)
        .await
        .unwrap();
    assert_eq!(
        first.next_close(&host, Wire::V1).await.unwrap(),
        Some((4001, String::new()))
    );
    let mut second = Client::connect(Wire::V1, dial(&addr).await, &me, &host)
        .await
        .unwrap();
    let closed = second.next_close(&host, Wire::V1).await;
    assert!(matches!(closed, Ok(None) | Err(_)), "{closed:?}");

    let verdicts = accept.await.unwrap();
    assert!(
        verdicts
            .iter()
            .all(|v| matches!(v, Err(RuntimeError::Core(CoreError::PeerRevoked(_)))))
    );
    assert_eq!(
        log.lock().unwrap().as_slice(),
        [RefusalAudit {
            peer_id: me.device_id(),
            code: 4001
        }]
    );
}

/// REF-16 on Wire v2, with the limiter shared with Wire v1 through one [`RefusalState`]: the
/// v2 attempt after a v1 refusal inside the window is a decoy.
#[tokio::test(flavor = "multi_thread")]
async fn ref_16_limiter_is_shared_across_wires() {
    let host = identity(0x63);
    let me = identity(0x53);
    let (state, log) = audit_state();
    let limiter = limiter_with(&state);
    let v2_state = V2ResponderState::new().with_refusal_state(state.clone());
    let (mut l, addr) = listener().await;
    let host_c = host.clone();
    let me_c = me.clone();
    let accept = tokio::spawn(async move {
        let roster_v1 = Mutex::new(host_roster(&me_c, Wire::V1, Standing::Revoked));
        let roster_v2 = Mutex::new(host_roster(&me_c, Wire::V2, Standing::Revoked));
        // A v2 attempt, then a v1 attempt for the same peer within the window.
        let stream = accept_tendril(&mut l).await;
        let first = host_accept(Wire::V2, stream, &host_c, &roster_v2, &limiter, &v2_state).await;
        let stream = accept_tendril(&mut l).await;
        let second = host_accept(Wire::V1, stream, &host_c, &roster_v1, &limiter, &v2_state).await;
        (first, second)
    });
    let first = Client::connect(Wire::V2, dial(&addr).await, &me, &host).await;
    let Err(err) = first else {
        panic!("refused at msg2")
    };
    assert_eq!(err.refusal(), Some(RefusalReason::Revoked), "{err:?}");
    let mut v1 = Client::connect(Wire::V1, dial(&addr).await, &me, &host)
        .await
        .unwrap();
    let closed = v1.next_close(&host, Wire::V1).await;
    assert!(matches!(closed, Ok(None) | Err(_)), "{closed:?}");
    let _ = accept.await.unwrap();
    assert_eq!(log.lock().unwrap().len(), 1, "one refusal in the window");
}

/// REF-16 on Wire v2: the second attempt inside the window is a decoy and is not audited.
#[tokio::test(flavor = "multi_thread")]
async fn ref_16_v2_second_attempt_is_a_decoy_and_audited_once() {
    let host = identity(0x6b);
    let me = identity(0x5b);
    let roster = Arc::new(Mutex::new(host_roster(&me, Wire::V2, Standing::Revoked)));
    let (state, log) = audit_state();
    let limiter = limiter_with(&state);
    let v2_state = V2ResponderState::new().with_refusal_state(state.clone());
    let (mut l, addr) = listener().await;
    let host_c = host.clone();
    let roster_c = Arc::clone(&roster);
    let accept = tokio::spawn(async move {
        for _ in 0..2 {
            let stream = accept_tendril(&mut l).await;
            let _ = host_accept(Wire::V2, stream, &host_c, &roster_c, &limiter, &v2_state).await;
        }
    });
    let first = Client::connect(Wire::V2, dial(&addr).await, &me, &host).await;
    let Err(first) = first else { panic!("refused") };
    assert_eq!(first.refusal(), Some(RefusalReason::Revoked), "{first:?}");
    let second = Client::connect(Wire::V2, dial(&addr).await, &me, &host).await;
    let Err(second) = second else { panic!("decoy") };
    assert!(
        matches!(second, RuntimeError::Core(CoreError::HostKeyUnverified)),
        "{second:?}"
    );
    accept.await.unwrap();
    assert_eq!(log.lock().unwrap().len(), 1);
}

/// A Wire v2 `msg2` refusal end to end: the initiator fails with the typed refusal before it
/// writes `msg3`, and the host keeps the decoy path: it holds the handshake until `msg3` or
/// the timeout instead of closing early.
async fn v2_msg2_refusal(standing: Standing) {
    let host = identity(0x64);
    let me = identity(0x54);
    let roster = Arc::new(Mutex::new(host_roster(&me, Wire::V2, standing)));
    let (state, log) = audit_state();
    let limiter = limiter_with(&state);
    let v2_state = V2ResponderState::new().with_refusal_state(state.clone());
    let (mut l, addr) = listener().await;
    let host_c = host.clone();
    let roster_c = Arc::clone(&roster);
    let accept = tokio::spawn(async move {
        let stream = accept_tendril(&mut l).await;
        host_accept(Wire::V2, stream, &host_c, &roster_c, &limiter, &v2_state).await
    });

    let held = Arc::new(Mutex::new(Vec::new()));
    let stream: Box<dyn PathStream> =
        Box::new(Wrapped::new(dial(&addr).await).keep_open(Arc::clone(&held)));
    let started = Instant::now();
    let Err(err) = Client::connect(Wire::V2, stream, &me, &host).await else {
        panic!("the initiator must be refused at msg2");
    };
    assert_eq!(err.refusal(), Some(standing.reason()), "{err:?}");
    assert_eq!(
        err.code(),
        if standing == Standing::Pending {
            "refused_pending"
        } else {
            "refused_revoked"
        }
    );

    // The initiator wrote no msg3 and its socket is still open: the host must still be waiting.
    let pending = tokio::time::timeout(Duration::from_millis(500), async {
        // Poll without consuming: the join handle is awaited by reference.
        let mut accept = accept;
        let res = (&mut accept).await;
        (accept, res)
    })
    .await;
    assert!(pending.is_err(), "the host closed early: {pending:?}");
    assert!(started.elapsed() >= Duration::from_millis(500));
    assert_eq!(
        log.lock().unwrap().as_slice(),
        [RefusalAudit {
            peer_id: me.device_id(),
            code: standing.code()
        }]
    );
    drop(held);
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_revoked_msg2_refusal_keeps_decoy_timing() {
    v2_msg2_refusal(Standing::Revoked).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_pending_msg2_refusal_keeps_decoy_timing() {
    v2_msg2_refusal(Standing::Pending).await;
}

/// An initiator that gets a v2 decoy because the notice is off sees `HostKeyUnverified`.
#[tokio::test(flavor = "multi_thread")]
async fn v2_silent_revocation_is_a_decoy() {
    let host = identity(0x65);
    let me = identity(0x55);
    let roster = Mutex::new(host_roster(&me, Wire::V2, Standing::RevokedSilent));
    let (state, log) = audit_state();
    let limiter = limiter_with(&state);
    let v2_state = V2ResponderState::new().with_refusal_state(state.clone());
    let (mut l, addr) = listener().await;
    let host_c = host.clone();
    let accept = tokio::spawn(async move {
        let stream = accept_tendril(&mut l).await;
        host_accept(Wire::V2, stream, &host_c, &roster, &limiter, &v2_state).await
    });
    let Err(err) = Client::connect(Wire::V2, dial(&addr).await, &me, &host).await else {
        panic!("a decoy must fail");
    };
    assert!(
        matches!(err, RuntimeError::Core(CoreError::HostKeyUnverified)),
        "{err:?}"
    );
    assert_eq!(err.refusal(), None);
    let _ = accept.await.unwrap();
    assert!(log.lock().unwrap().is_empty());
}

/// REF-11, runtime part: the entry is revoked between `msg1` and `msg3`. The initiator has
/// already reported `Established`, so the refusal arrives as a close; with padding disabled the
/// frame is a bare `0x07`.
async fn v2_msg3_race(padding: PaddingPolicy) {
    let host = identity(0x66);
    let me = identity(0x56);
    let roster = Arc::new(Mutex::new(host_roster(&me, Wire::V2, Standing::Active)));
    let (state, log) = audit_state();
    let limiter = limiter_with(&state);
    let config = V2ResponderConfig {
        padding,
        ..V2ResponderConfig::default()
    };
    let v2_state = V2ResponderState::with_config(config).with_refusal_state(state.clone());
    let (mut l, addr) = listener().await;
    let host_c = host.clone();
    let roster_c = Arc::clone(&roster);
    let me_id = me.device_id();
    let accept = tokio::spawn(async move {
        let stream = accept_tendril(&mut l).await;
        let revoke_in = Arc::clone(&roster_c);
        let stream: Box<dyn PathStream> =
            Box::new(Wrapped::new(stream).after_first_send(Arc::new(move || {
                // The host just wrote msg2: the peer is revoked before msg3 arrives.
                revoke_in
                    .lock()
                    .unwrap()
                    .revoke_peer_at(&me_id, true, now())
                    .unwrap();
            })));
        host_accept(Wire::V2, stream, &host_c, &roster_c, &limiter, &v2_state).await
    });

    let mut client = Client::connect(Wire::V2, dial(&addr).await, &me, &host)
        .await
        .expect("the initiator is established when it writes msg3");
    let closed = client.next_close(&host, Wire::V2).await.expect("close");
    assert_eq!(closed, Some((4001, String::new())));
    let err = client.send_data(b"late").await.expect_err("closed");
    assert_eq!(err.refusal(), Some(RefusalReason::Revoked), "{err:?}");
    let verdict = accept.await.unwrap();
    assert!(
        matches!(verdict, Err(RuntimeError::Core(CoreError::PeerRevoked(_)))),
        "{verdict:?}"
    );
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn ref_11_v2_msg3_race_with_default_padding() {
    v2_msg3_race(PaddingPolicy::v2_default()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ref_11_v2_msg3_race_with_padding_disabled() {
    v2_msg3_race(PaddingPolicy::disabled()).await;
}

/// REF-23: sixteen refused peers on an untrusted provider do not hold half-open slots, so a
/// seventeenth `Active` handshake is admitted; drains stay within their bound.
#[tokio::test(flavor = "multi_thread")]
async fn ref_23_sixteen_refused_peers_do_not_block_an_active_handshake() {
    let host = identity(0x67);
    let state = RefusalState::new();
    let limiter = limiter_with(&state);
    let mut revoked = Vec::new();
    let mut roster = Roster::new();
    let admit = |roster: &mut Roster, me: &EndpointIdentity| {
        roster
            .record_pending_pair(
                *me.static_key().public_bytes(),
                None,
                "p".into(),
                "phone".into(),
                "1".into(),
            )
            .unwrap();
        roster.confirm_peer(&me.device_id(), Some("1")).unwrap();
    };
    for i in 0..16u8 {
        let me = identity(0x80 + i * 2);
        admit(&mut roster, &me);
        roster.revoke_peer_at(&me.device_id(), true, now()).unwrap();
        revoked.push(me);
    }
    let active = identity(0xf0);
    admit(&mut roster, &active);
    let roster = Arc::new(Mutex::new(roster));

    let (mut l, addr) = listener().await;
    let host_c = host.clone();
    let roster_c = Arc::clone(&roster);
    let limiter_c = limiter.clone();
    let state_c = state.clone();
    let accept = tokio::spawn(async move {
        let mut tasks = Vec::new();
        for n in 0..16 {
            let stream = accept_tendril(&mut l).await;
            let stream: Box<dyn PathStream> =
                Box::new(Wrapped::new(stream).untrusted(format!("peer-{n}")));
            let (host, roster, limiter) =
                (host_c.clone(), Arc::clone(&roster_c), limiter_c.clone());
            tasks.push(tokio::spawn(async move {
                host_accept(
                    Wire::V1,
                    stream,
                    &host,
                    &roster,
                    &limiter,
                    &V2ResponderState::new(),
                )
                .await
            }));
        }
        let verdicts = futures_util::future::join_all(tasks).await;
        // Sampled right after the 16 host accepts joined: the refused connections still drain
        // (their initiators are silent and open) but hold no half-open slot.
        let held = limiter_c.untrusted_active_half_open();
        let drains_at_join = state_c.drains_in_flight();
        let refused = verdicts
            .into_iter()
            .filter(|v| matches!(v, Ok(Err(RuntimeError::Core(CoreError::PeerRevoked(_))))))
            .count();
        let stream = accept_tendril(&mut l).await;
        let stream: Box<dyn PathStream> =
            Box::new(Wrapped::new(stream).untrusted("peer-active".into()));
        let seventeenth = host_accept(
            Wire::V1,
            stream,
            &host_c,
            &roster_c,
            &limiter_c,
            &V2ResponderState::new(),
        )
        .await;
        (refused, held, drains_at_join, seventeenth)
    });

    // The peak is sampled until the host side is done, never stopped early.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampler = {
        let (state, stop) = (state.clone(), Arc::clone(&stop));
        tokio::spawn(async move {
            let mut peak = 0;
            while !stop.load(Ordering::SeqCst) {
                peak = peak.max(state.drains_in_flight());
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            peak
        })
    };
    // All 16 initiators connect at once and stay silent: an initiator that read its close
    // would half-close and end its drain early.
    let connected = futures_util::future::join_all(
        revoked
            .iter()
            .map(|me| async { Client::connect(Wire::V1, dial(&addr).await, me, &host).await }),
    )
    .await;
    let mut clients: Vec<Client> = connected.into_iter().map(Result::unwrap).collect();
    let seventeenth = Client::connect(Wire::V1, dial(&addr).await, &active, &host).await;
    let (refused, held, drains_at_join, verdict) = accept.await.unwrap();
    stop.store(true, Ordering::SeqCst);
    let observed_peak = sampler.await.unwrap();
    assert_eq!(refused, 16);
    assert_eq!(held, 0, "refused connections kept half-open slots");
    assert!(drains_at_join > 0, "the refused connections drain");
    assert_eq!(observed_peak, 8, "the drain bound is reached and held");
    assert!(seventeenth.is_ok());
    assert!(verdict.is_ok(), "{verdict:?}");
    // Every refusal frame arrives, drained or dropped at the bound, and none is a reset.
    for client in &mut clients {
        let closed = client
            .next_close(&host, Wire::V1)
            .await
            .expect("close, not a reset");
        assert_eq!(closed, Some((4001, String::new())));
    }
    drop(clients);
    // Every drain ends: at EOF or at the linger bound.
    let deadline = Instant::now() + Duration::from_secs(3);
    while state.drains_in_flight() != 0 {
        assert!(Instant::now() < deadline, "drains never ended");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// REF-14: a Day-2 v2 connect racing three routes of a host that refuses this device ends on
/// the first refusal. It does not wait for the other candidates and is not wakeable.
#[tokio::test(flavor = "multi_thread")]
async fn ref_14_day2_race_ends_on_the_first_refusal() {
    let host = Arc::new(identity(0x68));
    let me = Arc::new(identity(0x58));
    let roster = Arc::new(Mutex::new(host_roster(&me, Wire::V2, Standing::Revoked)));
    let (state, _log) = audit_state();
    let v2_state = Arc::new(V2ResponderState::new().with_refusal_state(state.clone()));
    let limiter = limiter_with(&state);

    let served = Arc::new(AtomicUsize::new(0));
    let mut hints = Vec::new();
    // Candidate 1 refuses; candidates 2 and 3 accept the TCP connection and never answer.
    for refuses in [true, false, false] {
        let (mut l, addr) = listener().await;
        hints.push(format!("direct:{addr}"));
        let (host, roster, v2_state, limiter, served) = (
            Arc::clone(&host),
            Arc::clone(&roster),
            Arc::clone(&v2_state),
            limiter.clone(),
            Arc::clone(&served),
        );
        tokio::spawn(async move {
            let mut parked = Vec::new();
            loop {
                let stream = accept_tendril(&mut l).await;
                served.fetch_add(1, Ordering::SeqCst);
                if refuses {
                    let (host, roster, v2_state, limiter) = (
                        Arc::clone(&host),
                        Arc::clone(&roster),
                        Arc::clone(&v2_state),
                        limiter.clone(),
                    );
                    tokio::spawn(async move {
                        let _ = host_accept(Wire::V2, stream, &host, &roster, &limiter, &v2_state)
                            .await;
                    });
                } else {
                    parked.push(stream);
                }
            }
        });
    }

    let mut client = client_roster(&host, Wire::V2);
    let eps = hints
        .iter()
        .map(|h| OperatorEndpoint {
            hint: h.clone(),
            relay_key: None,
        })
        .collect();
    client.set_routes(host.host_id(), eps).unwrap();
    let access = RosterAccess::memory(client);
    let opts = ConnectOpts::new(Arc::new(HintDialers::new(HintDialerConfig::default())));

    let started = Instant::now();
    let res = V2SessionDriver::connect_with_policy_and_store(
        Arc::clone(&me),
        host.host_id(),
        &access,
        opts,
    )
    .await;
    let Err(err) = res else {
        panic!("a refused device must not connect")
    };
    assert_eq!(err.error.refusal(), Some(RefusalReason::Revoked), "{err:?}");
    assert!(!err.is_wakeable_miss());
    assert!(!err.is_transient_precommit());
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the race waited for the silent candidates: {:?}",
        started.elapsed()
    );
}

/// REF-24 end to end, responder side: a responder that receives a refusal code keeps the raw
/// close; only initiators map it.
#[tokio::test(flavor = "multi_thread")]
async fn ref_24_responder_keeps_a_received_refusal_code_raw() {
    let host = identity(0x69);
    let me = identity(0x59);
    let roster = Arc::new(Mutex::new(host_roster(&me, Wire::V1, Standing::Active)));
    let limiter = limiter_with(&RefusalState::new());
    let (mut l, addr) = listener().await;
    let host_c = host.clone();
    let roster_c = Arc::clone(&roster);
    let accept = tokio::spawn(async move {
        let stream = accept_tendril(&mut l).await;
        SessionDriver::accept_locked(
            stream,
            &host_c,
            &roster_c,
            now(),
            Some(&limiter),
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
    });
    let Client::V1(mut client) = Client::connect(Wire::V1, dial(&addr).await, &me, &host)
        .await
        .unwrap()
    else {
        unreachable!()
    };
    let mut server = accept.await.unwrap().unwrap();
    client.send_close(4001, "").await.unwrap();
    let ev = tokio::time::timeout(
        Duration::from_secs(5),
        server.next_event_locked_now(&roster),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        ev,
        Some(SessionEvent::Closed {
            code: 4001,
            reason: String::new()
        })
    );
    let err = server.send_data(b"x").await.expect_err("closed");
    assert_eq!(err.refusal(), None, "{err:?}");
}

/// REF-24 end to end, initiator side: `4002`, `4003` and `1000` are plain closes.
#[tokio::test(flavor = "multi_thread")]
async fn ref_24_initiator_maps_only_refusal_codes() {
    for code in [1000u16, 4002, 4003] {
        let host = identity(0x6a);
        let me = identity(0x5a);
        let roster = Arc::new(Mutex::new(host_roster(&me, Wire::V1, Standing::Active)));
        let limiter = limiter_with(&RefusalState::new());
        let (mut l, addr) = listener().await;
        let host_c = host.clone();
        let roster_c = Arc::clone(&roster);
        let accept = tokio::spawn(async move {
            let stream = accept_tendril(&mut l).await;
            SessionDriver::accept_locked(
                stream,
                &host_c,
                &roster_c,
                now(),
                Some(&limiter),
                None,
                DEFAULT_PRE_AUTH_TIMEOUT,
            )
            .await
        });
        let mut client = Client::connect(Wire::V1, dial(&addr).await, &me, &host)
            .await
            .unwrap();
        let mut server = accept.await.unwrap().unwrap();
        server.send_close(code, "").await.unwrap();
        let closed = client.next_close(&host, Wire::V1).await.unwrap();
        assert_eq!(closed, Some((code, String::new())));
        let err = client.send_data(b"x").await.expect_err("closed");
        assert_eq!(err.refusal(), None, "code {code}: {err:?}");
    }
}

/// `true` when the serialized roster still holds a refusal notice.
#[cfg(unix)]
fn has_notice(roster: &Roster) -> bool {
    serde_json::to_string(roster)
        .unwrap()
        .contains("\"refusal\":")
}

/// Expired refusal notices are pruned whenever the roster is loaded or saved
/// (`spec/pairing-v1.md` Section 5.1), so their secrets never outlive the TTL on disk.
#[cfg(unix)]
#[test]
fn expired_refusal_notices_are_pruned_on_load_and_save() {
    use std::os::unix::fs::PermissionsExt;

    let me = identity(0x57);
    let revoked_long_ago = |notify_at: u64| {
        let mut roster = host_roster(&me, Wire::V2, Standing::Active);
        roster
            .revoke_peer_at(&me.device_id(), true, notify_at)
            .unwrap();
        roster
    };
    let expired = revoked_long_ago(1_000);
    let live = revoked_long_ago(now());
    assert!(has_notice(&expired) && has_notice(&live));

    // Save: the written file never carries an expired notice, and keeps a live one.
    let dir = tempfile::tempdir().unwrap();
    let store = tendril_runtime::StateStore::open_or_create(dir.path()).unwrap();
    store.save_roster(&expired).unwrap();
    let raw = std::fs::read_to_string(store.roster_path()).unwrap();
    assert!(!raw.contains("\"refusal\":"), "an expired notice was saved");
    store.save_roster(&live).unwrap();
    let raw = std::fs::read_to_string(store.roster_path()).unwrap();
    assert!(raw.contains("\"refusal\":"), "a live notice was dropped");

    // Load: a notice that expired on disk is gone from the loaded roster.
    std::fs::write(store.roster_path(), serde_json::to_vec(&expired).unwrap()).unwrap();
    std::fs::set_permissions(store.roster_path(), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!has_notice(&store.load_roster().unwrap()));
    std::fs::write(store.roster_path(), serde_json::to_vec(&live).unwrap()).unwrap();
    std::fs::set_permissions(store.roster_path(), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(has_notice(&store.load_roster().unwrap()));
}

/// One endpoint built the way the bindings build it: an `InboundRouter` and a plain
/// `V2ResponderState`, never given an explicit refusal state. Wire v1 and Wire v2 listeners
/// share one refusal limiter and one drain pool, so a peer refused on one wire is silent on the
/// other inside the window.
#[tokio::test(flavor = "multi_thread")]
async fn one_endpoint_refuses_a_peer_once_across_both_wires() {
    let host = identity(0x6c);
    let me = identity(0x5c);
    let router = tendril_runtime::InboundRouter::new();
    let v2_state = V2ResponderState::new();
    let roster_v1 = Arc::new(Mutex::new(host_roster(&me, Wire::V1, Standing::Revoked)));
    let roster_v2 = Arc::new(Mutex::new(host_roster(&me, Wire::V2, Standing::Revoked)));
    let (mut l, addr) = listener().await;
    let (host_c, router_limiters) = (
        host.clone(),
        (
            router.session_rate_limiter().clone(),
            router.v2_session_rate_limiter().clone(),
        ),
    );
    let (v1_roster, v2_roster) = (Arc::clone(&roster_v1), Arc::clone(&roster_v2));
    let v2_state = Arc::new(v2_state);
    let v2_c = Arc::clone(&v2_state);
    let accept = tokio::spawn(async move {
        let stream = accept_tendril(&mut l).await;
        host_accept(
            Wire::V1,
            stream,
            &host_c,
            &v1_roster,
            &router_limiters.0,
            &v2_c,
        )
        .await
        .unwrap_err();
        let stream = accept_tendril(&mut l).await;
        host_accept(
            Wire::V2,
            stream,
            &host_c,
            &v2_roster,
            &router_limiters.1,
            &v2_c,
        )
        .await
        .unwrap_err();
    });
    let mut first = Client::connect(Wire::V1, dial(&addr).await, &me, &host)
        .await
        .unwrap();
    assert_eq!(
        first.next_close(&host, Wire::V1).await.unwrap(),
        Some((4001, String::new())),
        "the first refusal is sent"
    );
    let second = Client::connect(Wire::V2, dial(&addr).await, &me, &host).await;
    let Err(second) = second else {
        panic!("the second attempt is a decoy")
    };
    assert!(
        matches!(second, RuntimeError::Core(CoreError::HostKeyUnverified)),
        "refused twice in one window: {second:?}"
    );
    accept.await.unwrap();
    // One drain pool: the v2 state's own state was never used.
    assert_eq!(v2_state.refusal_state().drains_in_flight(), 0);
}

/// A Wire v2 `msg3` refusal against a disk-backed host changes nothing on disk: the roster file
/// is neither rewritten nor re-stamped.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_disk_backed_msg3_refusal_leaves_the_roster_file_untouched() {
    let host = identity(0x6d);
    let me = identity(0x5d);
    let dir = tempfile::tempdir().unwrap();
    let store = tendril_runtime::StateStore::open_or_create(dir.path()).unwrap();
    store
        .save_roster(&host_roster(&me, Wire::V2, Standing::Active))
        .unwrap();
    let store_lock = tokio::sync::Mutex::new(());
    let stamp_after_revoke = Arc::new(Mutex::new(None));
    let (state, log) = audit_state();
    let v2_state = V2ResponderState::new().with_refusal_state(state);
    let (mut l, addr) = listener().await;
    let (host_c, me_id) = (host.clone(), me.device_id());
    let (store_c, stamp_c) = (store.clone(), Arc::clone(&stamp_after_revoke));
    let accept = tokio::spawn(async move {
        let stream = accept_tendril(&mut l).await;
        let hook_store = store_c.clone();
        let stream: Box<dyn PathStream> =
            Box::new(Wrapped::new(stream).after_first_send(Arc::new(move || {
                // msg2 is written: revoke on disk, then stamp the file before msg3 arrives.
                hook_store
                    .update_roster(|r| Ok(r.revoke_peer_at(&me_id, true, now())?))
                    .unwrap();
                *stamp_c.lock().unwrap() = Some(hook_store.roster_stamp().unwrap());
            })));
        V2SessionDriver::accept_with_store(
            stream,
            &host_c,
            &store_c,
            &store_lock,
            now(),
            &v2_state,
            None,
            None,
            DEFAULT_PRE_AUTH_TIMEOUT,
        )
        .await
    });
    let mut client = Client::connect(Wire::V2, dial(&addr).await, &me, &host)
        .await
        .unwrap();
    assert_eq!(
        client.next_close(&host, Wire::V2).await.unwrap(),
        Some((4001, String::new()))
    );
    let verdict = accept.await.unwrap();
    assert!(
        matches!(verdict, Err(RuntimeError::Core(CoreError::PeerRevoked(_)))),
        "{:?}",
        verdict.as_ref().err()
    );
    assert_eq!(log.lock().unwrap().len(), 1, "the refusal was sent");
    let before = stamp_after_revoke
        .lock()
        .unwrap()
        .clone()
        .expect("hook ran");
    assert!(before.is_some());
    assert_eq!(
        store.roster_stamp().unwrap(),
        before,
        "the refusal rewrote the roster file"
    );
}

/// `InboundRouter::close` ends refused connections that are still draining, well before the
/// linger bound, and no drain starts afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn router_close_ends_in_flight_drains_promptly() {
    let host = identity(0x6e);
    let me = identity(0x5e);
    let router = tendril_runtime::InboundRouter::new();
    let roster = Arc::new(Mutex::new(host_roster(&me, Wire::V1, Standing::Revoked)));
    let limiter = router.session_rate_limiter().clone();
    let (mut l, addr) = listener().await;
    let host_c = host.clone();
    let accept = tokio::spawn(async move {
        let stream = accept_tendril(&mut l).await;
        host_accept(
            Wire::V1,
            stream,
            &host_c,
            &roster,
            &limiter,
            &V2ResponderState::new(),
        )
        .await
    });
    // The initiator stays silent and open, so only the bound or close() can end the drain.
    let _client = Client::connect(Wire::V1, dial(&addr).await, &me, &host)
        .await
        .unwrap();
    assert!(accept.await.unwrap().is_err());
    let state = router.refusal_state().clone();
    let deadline = Instant::now() + Duration::from_secs(5);
    while state.drains_in_flight() == 0 {
        assert!(
            Instant::now() < deadline,
            "the refusal never started a drain"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    router.close();
    let closed_at = Instant::now();
    while state.drains_in_flight() != 0 {
        assert!(
            closed_at.elapsed() < REFUSAL_LINGER / 2,
            "close() left a drain running"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// A refusal frame the peer never lets the host write is bounded by the handshake deadline, so
/// the half-open slot it holds is freed.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_refusal_write_obeys_the_handshake_deadline() {
    let host = identity(0x6f);
    let me = identity(0x5f);
    let roster = Mutex::new(host_roster(&me, Wire::V1, Standing::Revoked));
    let limiter = limiter_with(&RefusalState::new());
    let (mut l, addr) = listener().await;
    let host_c = host.clone();
    let limiter_c = limiter.clone();
    let accept = tokio::spawn(async move {
        let stream = accept_tendril(&mut l).await;
        // msg2 goes out; the refusal frame stalls.
        let stream: Box<dyn PathStream> = Box::new(Wrapped::new(stream).stall_after_writes(1));
        let started = Instant::now();
        let res = SessionDriver::accept_locked(
            stream,
            &host_c,
            &roster,
            now(),
            Some(&limiter_c),
            None,
            Duration::from_millis(400),
        )
        .await;
        (res.map(|_| ()), started.elapsed())
    });
    let _client = Client::connect(Wire::V1, dial(&addr).await, &me, &host)
        .await
        .unwrap();
    let (res, elapsed) = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .expect("the accept must end at the handshake deadline")
        .unwrap();
    assert!(matches!(res, Err(RuntimeError::Timeout(_))), "{res:?}");
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    assert_eq!(limiter.active_half_open(), 0, "the half-open slot is freed");
}
