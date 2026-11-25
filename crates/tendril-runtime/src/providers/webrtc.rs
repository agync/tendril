//! Opt-in `str0m` WebRTC `RTCDataChannel("tendril/v1")` direct path upgrade (`ProviderId::P2p`).

use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use str0m::change::{SdpOffer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};
use tendril_core::WEBRTC_DATACHANNEL_LABEL;
use tendril_core::policy::ProviderId;
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time::{Instant as TokioInstant, sleep_until, timeout};

use crate::error::RuntimeError;
use crate::provider::{
    DEFAULT_WRITE_TIMEOUT, MAX_OUTER_FRAME_LEN, PathListener, PathReader, PathStream, PathWriter,
};

/// Maximum concurrent active/handshaking WebRTC upgrade sessions per endpoint (`64`).
pub const MAX_WEBRTC_SESSIONS: usize = 64;

/// Maximum time allowed for ICE + DTLS + SCTP DataChannel establishment (`15 s`).
pub const WEBRTC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum unread DataChannel bytes queued per stream before failing closed (`4 * MAX_OUTER_FRAME_LEN`).
pub const MAX_WEBRTC_QUEUED_BYTES: usize = 4 * MAX_OUTER_FRAME_LEN;

const WEBRTC_MAX_CHUNK_BYTES: usize = 16_384;
const WEBRTC_BUFFERED_LOW_THRESHOLD: usize = 32_768;
const UDP_RECV_BUF_LEN: usize = 2048;

#[derive(Default)]
struct ReadBufferState {
    queue: VecDeque<u8>,
    eof: bool,
    error: Option<String>,
}

struct SharedReadBuffer {
    state: Mutex<ReadBufferState>,
    notify: Notify,
}

impl SharedReadBuffer {
    fn new() -> Self {
        Self {
            state: Mutex::new(ReadBufferState::default()),
            notify: Notify::new(),
        }
    }

    fn push_bytes(&self, data: &[u8]) -> Result<(), ()> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.eof || st.error.is_some() {
            return Ok(());
        }
        if st.queue.len().saturating_add(data.len()) > MAX_WEBRTC_QUEUED_BYTES {
            st.error = Some("webrtc receive queue exceeded".to_string());
            self.notify.notify_waiters();
            return Err(());
        }
        st.queue.extend(data);
        self.notify.notify_waiters();
        Ok(())
    }

    fn mark_eof(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.eof = true;
        self.notify.notify_waiters();
    }

    fn mark_error(&self, msg: String) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.error.is_none() {
            st.error = Some(msg);
        }
        st.eof = true;
        self.notify.notify_waiters();
    }

    async fn recv_chunk(&self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if !st.queue.is_empty() {
                    let count = buf.len().min(st.queue.len());
                    for dst in buf.iter_mut().take(count) {
                        *dst = st.queue.pop_front().expect("checked non-empty queue");
                    }
                    return Ok(count);
                }
                if let Some(ref err) = st.error {
                    return Err(RuntimeError::Protocol(err.clone()));
                }
                if st.eof {
                    return Ok(0);
                }
            }
            notified.await;
        }
    }
}

struct PendingWrite {
    chunks: VecDeque<Vec<u8>>,
    reply: Option<oneshot::Sender<Result<(), RuntimeError>>>,
}

enum MuxCmd {
    AcceptOffer {
        offer_sdp: String,
        reply: oneshot::Sender<Result<String, RuntimeError>>,
    },
    WriteChunk {
        session_id: u64,
        bytes: Vec<u8>,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    CloseWrite {
        session_id: u64,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    DropStream {
        session_id: u64,
    },
}

enum SessionRole {
    Passive,
    Active {
        open_reply: Option<oneshot::Sender<Result<WebRtcStream, RuntimeError>>>,
    },
}

struct MuxSession {
    id: u64,
    rtc: Rtc,
    role: SessionRole,
    next_timeout: Instant,
    handshake_deadline: Instant,
    channel_id: Option<ChannelId>,
    peer_ip: Option<IpAddr>,
    read_buf: Arc<SharedReadBuffer>,
    pending_writes: VecDeque<PendingWrite>,
    pending_write_bytes: usize,
    close_write_reply: Option<oneshot::Sender<Result<(), RuntimeError>>>,
    write_closed: bool,
    write_close_sent: bool,
    dead: bool,
}

impl MuxSession {
    fn fail_pending_writes(&mut self, msg: &str) {
        self.pending_write_bytes = 0;
        while let Some(mut pw) = self.pending_writes.pop_front() {
            if let Some(reply) = pw.reply.take() {
                let _ = reply.send(Err(RuntimeError::Protocol(msg.to_string())));
            }
        }
        if let Some(reply) = self.close_write_reply.take() {
            let _ = reply.send(Ok(()));
        }
        if let SessionRole::Active { ref mut open_reply } = self.role
            && let Some(reply) = open_reply.take()
        {
            let _ = reply.send(Err(RuntimeError::Protocol(msg.to_string())));
        }
    }
}

fn discover_concrete_addrs(local_addr: SocketAddr) -> Vec<SocketAddr> {
    if !local_addr.ip().is_unspecified() {
        return vec![local_addr];
    }
    let port = local_addr.port();
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut push_unique = |ip: IpAddr| {
        if !ip.is_unspecified() && !ips.contains(&ip) {
            ips.push(ip);
        }
    };

    if local_addr.is_ipv4() {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0")
            && sock.connect("192.0.2.1:80").is_ok()
            && let Ok(addr) = sock.local_addr()
        {
            push_unique(addr.ip());
        }
        push_unique(IpAddr::V4(Ipv4Addr::LOCALHOST));
    } else {
        if let Ok(sock) = std::net::UdpSocket::bind("[::]:0")
            && sock.connect("[2001:db8::1]:80").is_ok()
            && let Ok(addr) = sock.local_addr()
        {
            push_unique(addr.ip());
        }
        push_unique(IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    ips.into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect()
}

fn add_host_candidates(rtc: &mut Rtc, addrs: &[SocketAddr]) -> Result<(), RuntimeError> {
    let mut added = 0usize;
    for &addr in addrs {
        if addr.ip().is_unspecified() {
            continue;
        }
        let cand = Candidate::host(addr, "udp")
            .map_err(|err| RuntimeError::Protocol(format!("invalid host candidate: {err}")))?;
        rtc.add_local_candidate(cand);
        added += 1;
    }
    if added == 0 {
        return Err(RuntimeError::Protocol(
            "no concrete local host candidate available for WebRTC".to_string(),
        ));
    }
    Ok(())
}

/// Immediately drains `rtc.poll_output()` until `Output::Timeout` after every `&mut Rtc` mutation.
async fn drain_rtc_outputs(
    session: &mut MuxSession,
    socket: &UdpSocket,
    local_addr: SocketAddr,
    cmd_weak: &mpsc::WeakSender<MuxCmd>,
    accept_tx: Option<&mpsc::Sender<WebRtcStream>>,
) {
    loop {
        if session.dead || !session.rtc.is_alive() {
            session.dead = true;
            session.read_buf.mark_eof();
            session.fail_pending_writes("webrtc session closed");
            session.next_timeout = Instant::now() + Duration::from_secs(3600);
            return;
        }

        let out = match session.rtc.poll_output() {
            Ok(out) => out,
            Err(err) => {
                session.dead = true;
                session.rtc.disconnect();
                session.read_buf.mark_error(format!("webrtc error: {err}"));
                session.fail_pending_writes(&format!("webrtc error: {err}"));
                return;
            }
        };

        match out {
            Output::Timeout(t) => {
                session.next_timeout = t;
                break;
            }
            Output::Transmit(tx) => {
                let _ = socket.send_to(&tx.contents, tx.destination).await;
            }
            Output::Event(ev) => match ev {
                Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                    session.dead = true;
                    session.rtc.disconnect();
                    session.read_buf.mark_eof();
                    session.fail_pending_writes("webrtc ICE disconnected");
                    return;
                }
                Event::ChannelOpen(cid, label) => {
                    if session.channel_id.is_some() {
                        session.rtc.direct_api().close_data_channel(cid);
                        continue;
                    }
                    if label != WEBRTC_DATACHANNEL_LABEL {
                        session.dead = true;
                        session.rtc.disconnect();
                        session
                            .read_buf
                            .mark_error("unexpected WebRTC DataChannel label".to_string());
                        session.fail_pending_writes("unexpected WebRTC DataChannel label");
                        return;
                    }
                    session.channel_id = Some(cid);
                    if let Some(mut chan) = session.rtc.channel(cid) {
                        chan.set_buffered_amount_low_threshold(WEBRTC_BUFFERED_LOW_THRESHOLD);
                    }
                    let Some(cmd_tx) = cmd_weak.upgrade() else {
                        session.dead = true;
                        session.rtc.disconnect();
                        session.read_buf.mark_eof();
                        session.fail_pending_writes("webrtc endpoint closed");
                        return;
                    };
                    let stream = WebRtcStream {
                        session_id: session.id,
                        peer_ip: session.peer_ip,
                        local_addr,
                        read_buf: Arc::clone(&session.read_buf),
                        cmd_tx: Some(cmd_tx),
                    };
                    match &mut session.role {
                        SessionRole::Passive => {
                            if let Some(tx) = accept_tx
                                && tx.try_send(stream).is_err()
                            {
                                session.dead = true;
                                session.rtc.disconnect();
                                session.read_buf.mark_eof();
                                session.fail_pending_writes("webrtc accept queue full");
                                return;
                            }
                        }
                        SessionRole::Active { open_reply } => {
                            if let Some(reply) = open_reply.take() {
                                let _ = reply.send(Ok(stream));
                            }
                        }
                    }
                }
                Event::ChannelData(data) => {
                    if session.channel_id == Some(data.id)
                        && session.read_buf.push_bytes(&data.data).is_err()
                    {
                        session.dead = true;
                        session.rtc.disconnect();
                        session.fail_pending_writes("webrtc receive queue exceeded");
                        return;
                    }
                }
                Event::ChannelBufferedAmountLow(cid) if session.channel_id == Some(cid) => {
                    if !matches!(step_pending_writes(session), WriteStep::Idle) {
                        // Drain after this single step on the next loop iteration or exit.
                        // `poll_output()` continues draining in the enclosing loop, and the caller
                        // flushes remaining queued chunks via `drain_and_flush`.
                    }
                }
                Event::ChannelClose(cid) if session.channel_id == Some(cid) => {
                    session.dead = true;
                    session.read_buf.mark_eof();
                    session.fail_pending_writes("webrtc DataChannel closed");
                    return;
                }
                _ => {}
            },
        }
    }
}

enum WriteStep {
    Idle,
    Continue,
    StopAfterDrain,
}

/// Performs at most one `&mut Rtc` mutation (one chunk write or channel close) so callers
/// enforce `str0m`'s single-mutation `poll_output -> Output::Timeout` invariant between steps.
fn step_pending_writes(session: &mut MuxSession) -> WriteStep {
    if session.dead {
        return WriteStep::Idle;
    }
    let Some(cid) = session.channel_id else {
        return WriteStep::Idle;
    };
    while let Some(front) = session.pending_writes.front_mut() {
        let Some(chunk) = front.chunks.front() else {
            let done = session.pending_writes.pop_front().expect("checked front");
            if let Some(reply) = done.reply {
                let _ = reply.send(Ok(()));
            }
            continue;
        };
        let chunk_len = chunk.len();
        let Some(mut chan) = session.rtc.channel(cid) else {
            session.fail_pending_writes("webrtc channel closed");
            return WriteStep::Idle;
        };
        return match chan.write(true, chunk) {
            Ok(true) => {
                session.pending_write_bytes = session.pending_write_bytes.saturating_sub(chunk_len);
                front.chunks.pop_front();
                if front.chunks.is_empty() {
                    let done = session.pending_writes.pop_front().expect("checked front");
                    if let Some(reply) = done.reply {
                        let _ = reply.send(Ok(()));
                    }
                }
                WriteStep::Continue
            }
            Ok(false) => {
                chan.set_buffered_amount_low_threshold(WEBRTC_BUFFERED_LOW_THRESHOLD);
                WriteStep::StopAfterDrain
            }
            Err(err) => {
                session.dead = true;
                session.rtc.disconnect();
                session.fail_pending_writes(&format!("webrtc write failed: {err}"));
                WriteStep::StopAfterDrain
            }
        };
    }
    if session.pending_writes.is_empty() && session.write_closed && !session.write_close_sent {
        session.rtc.direct_api().close_data_channel(cid);
        session.write_close_sent = true;
        if let Some(reply) = session.close_write_reply.take() {
            let _ = reply.send(Ok(()));
        }
        return WriteStep::StopAfterDrain;
    }
    WriteStep::Idle
}

async fn drain_and_flush(
    session: &mut MuxSession,
    socket: &UdpSocket,
    local_addr: SocketAddr,
    cmd_weak: &mpsc::WeakSender<MuxCmd>,
    accept_tx: Option<&mpsc::Sender<WebRtcStream>>,
) {
    drain_rtc_outputs(session, socket, local_addr, cmd_weak, accept_tx).await;
    loop {
        match step_pending_writes(session) {
            WriteStep::Idle => break,
            WriteStep::Continue => {
                drain_rtc_outputs(session, socket, local_addr, cmd_weak, accept_tx).await;
            }
            WriteStep::StopAfterDrain => {
                drain_rtc_outputs(session, socket, local_addr, cmd_weak, accept_tx).await;
                break;
            }
        }
    }
}

async fn flush_with_drains(
    session: &mut MuxSession,
    socket: &UdpSocket,
    local_addr: SocketAddr,
    cmd_weak: &mpsc::WeakSender<MuxCmd>,
    accept_tx: Option<&mpsc::Sender<WebRtcStream>>,
) {
    loop {
        match step_pending_writes(session) {
            WriteStep::Idle => break,
            WriteStep::Continue => {
                drain_rtc_outputs(session, socket, local_addr, cmd_weak, accept_tx).await;
            }
            WriteStep::StopAfterDrain => {
                drain_rtc_outputs(session, socket, local_addr, cmd_weak, accept_tx).await;
                break;
            }
        }
    }
}

async fn run_endpoint_mux(
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    host_candidates: Vec<SocketAddr>,
    mut cmd_rx: mpsc::Receiver<MuxCmd>,
    cmd_weak: mpsc::WeakSender<MuxCmd>,
    accept_tx: Option<mpsc::Sender<WebRtcStream>>,
    initial_session: Option<MuxSession>,
) {
    let mut sessions: Vec<MuxSession> = Vec::new();
    if let Some(mut s) = initial_session {
        drain_and_flush(&mut s, &socket, local_addr, &cmd_weak, accept_tx.as_ref()).await;
        if !s.dead {
            sessions.push(s);
        }
    }
    let mut next_session_id: u64 = 1;
    let mut recv_buf = vec![0u8; UDP_RECV_BUF_LEN];

    loop {
        if accept_tx.is_none() && sessions.is_empty() {
            break;
        }
        let now = Instant::now();
        let mut earliest = now + Duration::from_secs(1);
        for s in &sessions {
            let dl = if s.channel_id.is_none() {
                s.next_timeout.min(s.handshake_deadline)
            } else {
                s.next_timeout
            };
            if dl < earliest {
                earliest = dl;
            }
        }
        let sleep_deadline = TokioInstant::from_std(earliest);

        tokio::select! {
            recv = socket.recv_from(&mut recv_buf) => {
                let Ok((n, src)) = recv else {
                    continue;
                };
                if n == 0 {
                    continue;
                }
                let recv_now = Instant::now();
                let cand_dests: &[SocketAddr] = if local_addr.ip().is_unspecified() {
                    &host_candidates
                } else {
                    std::slice::from_ref(&local_addr)
                };
                let mut chosen = None;
                // Prefer matching loopback affinity so str0m matches host candidates deterministically.
                for &dest in cand_dests
                    .iter()
                    .filter(|d| d.ip().is_loopback() == src.ip().is_loopback())
                    .chain(
                        cand_dests
                            .iter()
                            .filter(|d| d.ip().is_loopback() != src.ip().is_loopback()),
                    )
                {
                    let Ok(contents) = recv_buf[..n].try_into() else {
                        continue;
                    };
                    let candidate_input = Input::Receive(
                        recv_now,
                        Receive {
                            proto: Protocol::Udp,
                            source: src,
                            destination: dest,
                            contents,
                        },
                    );
                    if let Some(idx) = sessions
                        .iter()
                        .position(|s| !s.dead && s.rtc.accepts(&candidate_input))
                    {
                        chosen = Some((idx, candidate_input));
                        break;
                    }
                }
                if let Some((idx, input)) = chosen {
                    let s = &mut sessions[idx];
                    if let Err(err) = s.rtc.handle_input(input) {
                        s.dead = true;
                        s.rtc.disconnect();
                        s.read_buf.mark_error(format!("webrtc input error: {err}"));
                        s.fail_pending_writes(&format!("webrtc input error: {err}"));
                    } else {
                        if s.peer_ip.is_none() {
                            s.peer_ip = Some(src.ip());
                        }
                        drain_and_flush(s, &socket, local_addr, &cmd_weak, accept_tx.as_ref()).await;
                    }
                }
            }
            maybe_cmd = cmd_rx.recv() => {
                let Some(cmd) = maybe_cmd else {
                    break;
                };
                match cmd {
                    MuxCmd::AcceptOffer { offer_sdp, reply } => {
                        if sessions.len() >= MAX_WEBRTC_SESSIONS {
                            let _ = reply.send(Err(RuntimeError::CapacityExceeded(
                                "webrtc max sessions reached",
                            )));
                            continue;
                        }
                        let res = handle_accept_offer(
                            next_session_id,
                            &offer_sdp,
                            &host_candidates,
                            &socket,
                            local_addr,
                            &cmd_weak,
                            accept_tx.as_ref(),
                        )
                        .await;
                        match res {
                            Ok((sess, answer_sdp)) => {
                                next_session_id += 1;
                                sessions.push(sess);
                                let _ = reply.send(Ok(answer_sdp));
                            }
                            Err(err) => {
                                let _ = reply.send(Err(err));
                            }
                        }
                    }
                    MuxCmd::WriteChunk { session_id, bytes, reply } => {
                        let Some(s) = sessions.iter_mut().find(|s| s.id == session_id && !s.dead) else {
                            let _ = reply.send(Err(RuntimeError::Closed));
                            continue;
                        };
                        if s.channel_id.is_none() || s.write_closed {
                            let _ = reply.send(Err(RuntimeError::Closed));
                            continue;
                        }
                        if s.pending_write_bytes.saturating_add(bytes.len()) > MAX_WEBRTC_QUEUED_BYTES {
                            let _ = reply.send(Err(RuntimeError::Protocol(
                                "webrtc send queue exceeded".to_string(),
                            )));
                            continue;
                        }
                        let chunks: VecDeque<Vec<u8>> = if bytes.is_empty() {
                            VecDeque::new()
                        } else {
                            bytes.chunks(WEBRTC_MAX_CHUNK_BYTES).map(ToOwned::to_owned).collect()
                        };
                        if chunks.is_empty() {
                            let _ = reply.send(Ok(()));
                            continue;
                        }
                        s.pending_write_bytes = s.pending_write_bytes.saturating_add(bytes.len());
                        s.pending_writes.push_back(PendingWrite { chunks, reply: Some(reply) });
                        flush_with_drains(s, &socket, local_addr, &cmd_weak, accept_tx.as_ref()).await;
                    }
                    MuxCmd::CloseWrite { session_id, reply } => {
                        let Some(s) = sessions.iter_mut().find(|s| s.id == session_id && !s.dead) else {
                            let _ = reply.send(Ok(()));
                            continue;
                        };
                        s.write_closed = true;
                        s.close_write_reply = Some(reply);
                        flush_with_drains(s, &socket, local_addr, &cmd_weak, accept_tx.as_ref()).await;
                    }
                    MuxCmd::DropStream { session_id } => {
                        if let Some(s) = sessions.iter_mut().find(|s| s.id == session_id) {
                            s.dead = true;
                            s.rtc.disconnect();
                            s.read_buf.mark_eof();
                            s.fail_pending_writes("webrtc stream dropped");
                        }
                    }
                }
            }
            () = sleep_until(sleep_deadline) => {
                let tick_now = Instant::now();
                for s in &mut sessions {
                    if s.dead {
                        continue;
                    }
                    if s.channel_id.is_none() && tick_now >= s.handshake_deadline {
                        s.dead = true;
                        s.rtc.disconnect();
                        s.read_buf.mark_error("webrtc handshake timeout".to_string());
                        s.fail_pending_writes("webrtc handshake timeout");
                        continue;
                    }
                    if tick_now >= s.next_timeout {
                        if let Err(err) = s.rtc.handle_input(Input::Timeout(tick_now)) {
                            s.dead = true;
                            s.rtc.disconnect();
                            s.read_buf.mark_error(format!("webrtc timeout error: {err}"));
                            s.fail_pending_writes(&format!("webrtc timeout error: {err}"));
                        } else {
                            drain_and_flush(s, &socket, local_addr, &cmd_weak, accept_tx.as_ref()).await;
                        }
                    }
                }
            }
        }
        sessions.retain(|s| !s.dead);
    }
}

async fn handle_accept_offer(
    id: u64,
    offer_sdp: &str,
    host_candidates: &[SocketAddr],
    socket: &UdpSocket,
    local_addr: SocketAddr,
    cmd_weak: &mpsc::WeakSender<MuxCmd>,
    accept_tx: Option<&mpsc::Sender<WebRtcStream>>,
) -> Result<(MuxSession, String), RuntimeError> {
    let offer = SdpOffer::from_sdp_string(offer_sdp)
        .map_err(|err| RuntimeError::Protocol(format!("invalid SDP offer: {err}")))?;
    let now = Instant::now();
    let mut rtc = Rtc::builder()
        .set_crypto_provider(Arc::new(str0m_rust_crypto::default_provider()))
        .set_ice_lite(true)
        .build(now);
    add_host_candidates(&mut rtc, host_candidates)?;
    let answer = rtc
        .sdp_api()
        .accept_offer(offer)
        .map_err(|err| RuntimeError::Protocol(format!("SDP accept_offer failed: {err}")))?;
    let answer_sdp = answer.to_sdp_string();

    let mut session = MuxSession {
        id,
        rtc,
        role: SessionRole::Passive,
        next_timeout: now,
        handshake_deadline: now + WEBRTC_HANDSHAKE_TIMEOUT,
        channel_id: None,
        peer_ip: None,
        read_buf: Arc::new(SharedReadBuffer::new()),
        pending_writes: VecDeque::new(),
        pending_write_bytes: 0,
        close_write_reply: None,
        write_closed: false,
        write_close_sent: false,
        dead: false,
    };
    drain_rtc_outputs(&mut session, socket, local_addr, cmd_weak, accept_tx).await;
    Ok((session, answer_sdp))
}

/// Passive host-side WebRTC DataChannel upgrade endpoint sharing a UDP socket.
pub struct WebRtcUpgradeEndpoint;

impl WebRtcUpgradeEndpoint {
    /// Binds a host-side UDP socket and launches the WebRTC multiplexer loop.
    pub async fn bind(
        bind_addr: SocketAddr,
    ) -> Result<(WebRtcUpgradeHandle, WebRtcUpgradeListener), RuntimeError> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let local_addr = socket.local_addr()?;
        let host_candidates = discover_concrete_addrs(local_addr);
        if host_candidates.is_empty() {
            return Err(RuntimeError::Protocol(
                "failed to resolve concrete WebRTC ICE host candidates".to_string(),
            ));
        }

        let (cmd_tx, cmd_rx) = mpsc::channel(MAX_WEBRTC_SESSIONS * 2);
        let (accept_tx, accept_rx) = mpsc::channel(MAX_WEBRTC_SESSIONS);
        let cmd_weak = cmd_tx.downgrade();
        tokio::spawn(async move {
            run_endpoint_mux(
                socket,
                local_addr,
                host_candidates,
                cmd_rx,
                cmd_weak,
                Some(accept_tx),
                None,
            )
            .await;
        });

        Ok((
            WebRtcUpgradeHandle {
                cmd_tx: cmd_tx.clone(),
            },
            WebRtcUpgradeListener {
                local_addr,
                accept_rx,
                _cmd_tx: cmd_tx,
            },
        ))
    }
}

/// Cheaply cloneable handle passed into inbound relay/direct session drivers to answer `0x0D` offers.
#[derive(Clone)]
pub struct WebRtcUpgradeHandle {
    cmd_tx: mpsc::Sender<MuxCmd>,
}

impl std::fmt::Debug for WebRtcUpgradeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebRtcUpgradeHandle").finish()
    }
}

impl WebRtcUpgradeHandle {
    /// Validates and answers a remote `sdp` offer, registering a passive `str0m` peer session.
    pub async fn accept_offer(&self, offer_sdp: &str) -> Result<String, RuntimeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(MuxCmd::AcceptOffer {
                offer_sdp: offer_sdp.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        rx.await.map_err(|_| RuntimeError::Closed)?
    }
}

/// [`PathListener`] yielding newly opened `RTCDataChannel("tendril/v1")` streams.
pub struct WebRtcUpgradeListener {
    local_addr: SocketAddr,
    accept_rx: mpsc::Receiver<WebRtcStream>,
    _cmd_tx: mpsc::Sender<MuxCmd>,
}

impl WebRtcUpgradeListener {
    /// Returns the concrete bound UDP socket address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

#[async_trait]
impl PathListener for WebRtcUpgradeListener {
    async fn accept(&mut self) -> Result<Box<dyn PathStream>, RuntimeError> {
        let stream = self.accept_rx.recv().await.ok_or(RuntimeError::Closed)?;
        Ok(Box::new(stream))
    }

    fn local_endpoint(&self) -> String {
        format!("webrtc://{}", self.local_addr)
    }
}

/// Bidirectional Tendril stream over an established WebRTC `"tendril/v1"` DataChannel.
pub struct WebRtcStream {
    session_id: u64,
    peer_ip: Option<IpAddr>,
    local_addr: SocketAddr,
    read_buf: Arc<SharedReadBuffer>,
    cmd_tx: Option<mpsc::Sender<MuxCmd>>,
}

impl Drop for WebRtcStream {
    fn drop(&mut self) {
        if let Some(cmd_tx) = self.cmd_tx.take() {
            let _ = cmd_tx.try_send(MuxCmd::DropStream {
                session_id: self.session_id,
            });
        }
    }
}

async fn send_webrtc_chunk(
    cmd_tx: &mpsc::Sender<MuxCmd>,
    session_id: u64,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    if bytes.len() > MAX_OUTER_FRAME_LEN {
        return Err(RuntimeError::FrameTooLarge {
            size: bytes.len(),
            max: MAX_OUTER_FRAME_LEN,
        });
    }
    let (tx, rx) = oneshot::channel();
    cmd_tx
        .send(MuxCmd::WriteChunk {
            session_id,
            bytes: bytes.to_vec(),
            reply: tx,
        })
        .await
        .map_err(|_| RuntimeError::Closed)?;
    timeout(DEFAULT_WRITE_TIMEOUT, rx)
        .await
        .map_err(|_| RuntimeError::Timeout("webrtc write backpressure timed out"))?
        .map_err(|_| RuntimeError::Closed)?
}

async fn close_webrtc_write_half(
    cmd_tx: &mpsc::Sender<MuxCmd>,
    session_id: u64,
) -> Result<(), RuntimeError> {
    let (tx, rx) = oneshot::channel();
    if cmd_tx
        .send(MuxCmd::CloseWrite {
            session_id,
            reply: tx,
        })
        .await
        .is_err()
    {
        return Ok(());
    }
    timeout(DEFAULT_WRITE_TIMEOUT, rx)
        .await
        .map_err(|_| RuntimeError::Timeout("webrtc close write half timed out"))?
        .map_err(|_| RuntimeError::Closed)?
}

impl WebRtcStream {
    /// Returns the local UDP socket address bound by this endpoint.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    async fn send_bytes(&self, bytes: &[u8]) -> Result<(), RuntimeError> {
        let Some(ref cmd_tx) = self.cmd_tx else {
            return Err(RuntimeError::Closed);
        };
        send_webrtc_chunk(cmd_tx, self.session_id, bytes).await
    }

    async fn close_write_half(&self) -> Result<(), RuntimeError> {
        let Some(ref cmd_tx) = self.cmd_tx else {
            return Ok(());
        };
        close_webrtc_write_half(cmd_tx, self.session_id).await
    }
}

/// Read half of a split [`WebRtcStream`], preserving buffered reads after [`WebRtcWriteHalf::close`].
pub struct WebRtcReadHalf {
    read_buf: Arc<SharedReadBuffer>,
    session_id: u64,
    cmd_tx: mpsc::Sender<MuxCmd>,
}

impl Drop for WebRtcReadHalf {
    fn drop(&mut self) {
        let _ = self.cmd_tx.try_send(MuxCmd::DropStream {
            session_id: self.session_id,
        });
    }
}

#[async_trait]
impl PathReader for WebRtcReadHalf {
    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.read_buf.recv_chunk(buf).await
    }
}

/// Write half of a split [`WebRtcStream`].
pub struct WebRtcWriteHalf {
    session_id: u64,
    cmd_tx: mpsc::Sender<MuxCmd>,
}

#[async_trait]
impl PathWriter for WebRtcWriteHalf {
    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        send_webrtc_chunk(&self.cmd_tx, self.session_id, bytes).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        close_webrtc_write_half(&self.cmd_tx, self.session_id).await
    }
}

#[async_trait]
impl PathStream for WebRtcStream {
    fn provider_id(&self) -> ProviderId {
        ProviderId::P2p
    }

    /// Returns the unauthenticated ICE UDP source IP observed once `str0m::handle_input` accepted a packet.
    fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_ip
    }

    async fn send_chunk(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.send_bytes(bytes).await
    }

    async fn recv_chunk(&mut self, buf: &mut [u8]) -> Result<usize, RuntimeError> {
        self.read_buf.recv_chunk(buf).await
    }

    async fn close(&mut self) -> Result<(), RuntimeError> {
        let res = self.close_write_half().await;
        if let Some(cmd_tx) = self.cmd_tx.take() {
            let _ = cmd_tx.try_send(MuxCmd::DropStream {
                session_id: self.session_id,
            });
        }
        res
    }

    fn into_split(mut self: Box<Self>) -> (Box<dyn PathReader>, Box<dyn PathWriter>) {
        let cmd_tx = self
            .cmd_tx
            .take()
            .expect("WebRtcStream cmd_tx already moved");
        (
            Box::new(WebRtcReadHalf {
                read_buf: Arc::clone(&self.read_buf),
                session_id: self.session_id,
                cmd_tx: cmd_tx.clone(),
            }),
            Box::new(WebRtcWriteHalf {
                session_id: self.session_id,
                cmd_tx,
            }),
        )
    }
}

/// Active client-side `str0m` WebRTC dialer for Rust-to-Rust upgrade testing and dialing.
pub struct WebRtcActiveDialer;

impl WebRtcActiveDialer {
    /// Creates an offer opening `RTCDataChannel("tendril/v1")`, exchanges it via `exchange_sdp`,
    /// and returns an open [`WebRtcStream`] (`ProviderId::P2p`) once connected.
    pub async fn dial<F, Fut>(
        bind_addr: SocketAddr,
        exchange_sdp: F,
    ) -> Result<WebRtcStream, RuntimeError>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = Result<String, RuntimeError>>,
    {
        Self::dial_with_channel_label(bind_addr, WEBRTC_DATACHANNEL_LABEL, exchange_sdp).await
    }

    /// Creates an offer opening a custom DataChannel label (for protocol rejection tests).
    pub async fn dial_with_channel_label<F, Fut>(
        bind_addr: SocketAddr,
        channel_label: &str,
        exchange_sdp: F,
    ) -> Result<WebRtcStream, RuntimeError>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = Result<String, RuntimeError>>,
    {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let local_addr = socket.local_addr()?;
        let host_candidates = discover_concrete_addrs(local_addr);
        let now = Instant::now();
        let mut rtc = Rtc::builder()
            .set_crypto_provider(Arc::new(str0m_rust_crypto::default_provider()))
            .set_ice_lite(false)
            .build(now);
        add_host_candidates(&mut rtc, &host_candidates)?;

        let mut changes = rtc.sdp_api();
        let _cid = changes.add_channel(channel_label.to_string());
        let (offer, pending): (SdpOffer, SdpPendingOffer) = changes.apply().ok_or_else(|| {
            RuntimeError::Protocol("failed to create WebRTC SDP offer".to_string())
        })?;
        let _ = drain_initial_outputs(&mut rtc, &socket).await?;
        let offer_sdp = offer.to_sdp_string();

        let answer_sdp = exchange_sdp(offer_sdp).await?;
        let answer = str0m::change::SdpAnswer::from_sdp_string(&answer_sdp)
            .map_err(|err| RuntimeError::Protocol(format!("invalid SDP answer: {err}")))?;
        rtc.sdp_api()
            .accept_answer(pending, answer)
            .map_err(|err| RuntimeError::Protocol(format!("accept_answer failed: {err}")))?;
        let next_timeout = drain_initial_outputs(&mut rtc, &socket).await?;

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (open_tx, open_rx) = oneshot::channel();
        let session = MuxSession {
            id: 1,
            rtc,
            role: SessionRole::Active {
                open_reply: Some(open_tx),
            },
            next_timeout,
            handshake_deadline: Instant::now() + WEBRTC_HANDSHAKE_TIMEOUT,
            channel_id: None,
            peer_ip: None,
            read_buf: Arc::new(SharedReadBuffer::new()),
            pending_writes: VecDeque::new(),
            pending_write_bytes: 0,
            close_write_reply: None,
            write_closed: false,
            write_close_sent: false,
            dead: false,
        };
        let cmd_weak = cmd_tx.downgrade();
        tokio::spawn(async move {
            run_endpoint_mux(
                socket,
                local_addr,
                host_candidates,
                cmd_rx,
                cmd_weak,
                None,
                Some(session),
            )
            .await;
        });

        let stream = timeout(WEBRTC_HANDSHAKE_TIMEOUT, open_rx)
            .await
            .map_err(|_| RuntimeError::Timeout("webrtc DataChannel open timed out"))?
            .map_err(|_| RuntimeError::Closed)??;
        drop(cmd_tx);
        Ok(stream)
    }
}

async fn drain_initial_outputs(rtc: &mut Rtc, socket: &UdpSocket) -> Result<Instant, RuntimeError> {
    loop {
        match rtc.poll_output() {
            Ok(Output::Timeout(next)) => return Ok(next),
            Ok(Output::Transmit(tx)) => {
                let _ = socket.send_to(&tx.contents, tx.destination).await;
            }
            Ok(Output::Event(_)) => {}
            Err(err) => {
                return Err(RuntimeError::Protocol(format!("webrtc error: {err}")));
            }
        }
    }
}
