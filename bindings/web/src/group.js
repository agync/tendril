const GROUP_TOKEN = Symbol("TendrilWebGroup");
const encoder = new TextEncoder();

/** Largest application payload one group frame can carry (mirrors the core frame limit). */
export const MAX_GROUP_PAYLOAD_LEN = 65499;
/** Default number of concurrent per-peer sends in one broadcast. */
export const DEFAULT_GROUP_SEND_CONCURRENCY = 8;
/** Default per-peer send timeout in milliseconds. */
export const DEFAULT_GROUP_SEND_TIMEOUT_MS = 1000;

const EVENT_QUEUE_CAP = 1024;
const CONTROL_EVENT_RESERVE = 64;
const DEFAULT_PUMP_POLL_MS = 250;

function errText(err) {
  return err && err.message ? err.message : String(err);
}

function withTimeout(promise, ms, label) {
  let timer = null;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Group fan-out and inbound delivery over the app's per-peer sessions.
 *
 * This class only moves bytes. Every membership, capability, revocation, and recipient decision is
 * answered by the WASM group book through `backend`; nothing here interprets a manifest.
 */
export class TendrilWebGroup {
  #groupId;
  #backend;
  #sessionFor;
  #concurrency;
  #sendTimeoutMs;
  #pumpPollMs;
  #sessions = new Map();
  #pumps = new Map();
  #queue = [];
  #waiters = [];
  #listeners = new Map();
  #closed = false;
  #localRevoked = false;
  #onClose;

  constructor(token, groupId, backend, options = {}, onClose = null) {
    if (token !== GROUP_TOKEN) {
      throw new Error("Use TendrilWebClient.openGroup()");
    }
    const {
      sessionFor = null,
      concurrency = DEFAULT_GROUP_SEND_CONCURRENCY,
      sendTimeoutMs = DEFAULT_GROUP_SEND_TIMEOUT_MS,
      pumpPollMs = DEFAULT_PUMP_POLL_MS,
    } = options;
    if (!Number.isInteger(concurrency) || concurrency < 1) {
      throw new RangeError("concurrency must be a positive integer");
    }
    if (!Number.isFinite(sendTimeoutMs) || sendTimeoutMs <= 0) {
      throw new RangeError("sendTimeoutMs must be positive");
    }
    if (sessionFor !== null && typeof sessionFor !== "function") {
      throw new TypeError("sessionFor must be a function");
    }
    this.#groupId = groupId;
    this.#backend = backend;
    this.#sessionFor = sessionFor;
    this.#concurrency = concurrency;
    this.#sendTimeoutMs = sendTimeoutMs;
    this.#pumpPollMs = pumpPollMs;
    this.#onClose = onClose;
  }

  static _create(groupId, backend, options, onClose) {
    return new TendrilWebGroup(GROUP_TOKEN, groupId, backend, options, onClose);
  }

  get groupId() {
    return this.#groupId;
  }

  isClosed() {
    return this.#closed;
  }

  #ensureOpen() {
    if (this.#closed) {
      throw new Error("TendrilWebGroup is closed");
    }
  }

  /** Active members of the stored manifest, as answered by the WASM group book. */
  members() {
    this.#ensureOpen();
    return this.#backend.members();
  }

  /** Resolves `true` when `peerId` holds `cap` now; rejects with the core error otherwise. */
  authorizePeer(peerId, cap) {
    this.#ensureOpen();
    this.#backend.authorize(peerId, cap);
    return true;
  }

  /**
   * Registers an established session for its authenticated peer and starts delivering its inbound
   * group data. The group owns polling of attached sessions until they are detached.
   */
  attach(session) {
    this.#ensureOpen();
    const peerId = session?.peerDeviceId;
    if (typeof peerId !== "string" || peerId.length === 0) {
      throw new Error("session has no authenticated peer");
    }
    const prev = this.#sessions.get(peerId);
    if (prev === session) {
      return peerId;
    }
    this.detach(peerId);
    this.#sessions.set(peerId, session);
    if (typeof session.pollEvent === "function") {
      this.#pumps.set(peerId, this.#pump(peerId, session));
    }
    return peerId;
  }

  /** Stops using the session for `peerId`. The session itself stays open for the app. */
  detach(peerId) {
    this.#sessions.delete(peerId);
    this.#pumps.delete(peerId);
  }

  /**
   * Asks the WASM group book whether the local device is still an active, unrevoked member. When
   * it is not, detaches every session once, emits `member_revoked` for the local device, and
   * refuses all further inbound data and broadcast.
   */
  #enforceLocalMembership() {
    if (this.#localRevoked) {
      return false;
    }
    try {
      this.#backend.checkLocal();
      return true;
    } catch {
      this.#localRevoked = true;
      for (const peerId of [...this.#sessions.keys()]) {
        this.detach(peerId);
      }
      this.#emit({ event: "member_revoked", device_id: this.#backend.localDeviceId() });
      return false;
    }
  }

  async #pump(peerId, session) {
    try {
      while (!this.#closed && this.#sessions.get(peerId) === session) {
        let polled;
        try {
          polled = await session.pollEvent(this.#pumpPollMs);
        } catch {
          break;
        }
        if (this.#closed || this.#sessions.get(peerId) !== session) {
          break;
        }
        if (!this.#enforceLocalMembership()) {
          break;
        }
        if (polled.status === "eof") {
          break;
        }
        if (polled.status === "event") {
          await this.handleSessionEvent(session, polled);
        }
      }
    } finally {
      if (this.#sessions.get(peerId) === session) {
        this.detach(peerId);
      }
    }
  }

  /**
   * Routes one event polled from `session` (for apps that poll their own sessions).
   *
   * Data is surfaced only after the WASM group book confirms the local device is still an active
   * unrevoked member and the sender holds `group.send:<group_id>`; manifests are verified by the group book before any state changes.
   */
  async handleSessionEvent(session, event) {
    if (this.#closed || !event || !this.#enforceLocalMembership()) {
      return;
    }
    const sender = session?.peerDeviceId;
    switch (event.event) {
      case "data": {
        const cap = `group.send:${this.#groupId}`;
        try {
          this.#backend.authorizeInbound(sender, cap);
        } catch (err) {
          this.#emit(this.#audit(sender, cap, errText(err)));
          return;
        }
        this.#emitData(sender, event.data_b64);
        return;
      }
      case "group_manifest_unverified": {
        if (event.group_id !== this.#groupId) {
          return;
        }
        try {
          await this.#backend.ingestManifest(session, event);
        } catch (err) {
          this.#emit(this.#audit(sender, "group.manifest", errText(err)));
        }
        return;
      }
      case "group_rendezvous_unverified": {
        if (event.group_id === this.#groupId && event.applied === false) {
          this.#emit(
            this.#audit(sender, `group.admin:${this.#groupId}`, event.error ?? "rendezvous refused")
          );
        }
        return;
      }
      case "audit": {
        this.#emit({ event: "audit", audit: event.audit });
        return;
      }
      default:
    }
  }

  /** Applies the outcome of a verified manifest ingest to this group's event stream. */
  _onManifestOutcome(outcome) {
    if (this.#closed || outcome.group_id !== this.#groupId || outcome.status !== "updated") {
      return;
    }
    this.#emit({ event: "manifest_updated", seq: outcome.seq });
    for (const id of outcome.newly_joined) {
      this.#emit({ event: "member_joined", device_id: id });
    }
    const localId = this.#backend.localDeviceId();
    for (const id of outcome.newly_revoked) {
      if (id === localId) {
        continue;
      }
      this.detach(id);
      this.#emit({ event: "member_revoked", device_id: id });
    }
    this.#enforceLocalMembership();
  }

  /**
   * Sends `data` to every active peer the WASM group book selects.
   *
   * @returns {Promise<{delivered: string[], offline: string[], failed: [string, string][]}>}
   */
  async broadcast(data, cap = null) {
    this.#ensureOpen();
    if (!this.#enforceLocalMembership()) {
      throw new Error("local device is no longer an active member of the group");
    }
    const bytes = typeof data === "string" ? encoder.encode(data) : data;
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError("data must be a Uint8Array or string");
    }
    if (bytes.length > MAX_GROUP_PAYLOAD_LEN) {
      throw new RangeError(`payload of ${bytes.length} bytes exceeds ${MAX_GROUP_PAYLOAD_LEN}`);
    }
    const targets = this.#backend.targets(cap);
    const report = { delivered: [], offline: [], failed: [] };
    const outcomes = new Array(targets.length);
    let next = 0;
    const worker = async () => {
      while (next < targets.length) {
        const index = next;
        next += 1;
        outcomes[index] = await this.#deliver(targets[index], bytes, cap);
      }
    };
    const workers = Math.min(this.#concurrency, targets.length);
    await Promise.all(Array.from({ length: workers }, worker));
    targets.forEach((peerId, index) => {
      const outcome = outcomes[index];
      if (outcome.kind === "delivered") {
        report.delivered.push(peerId);
      } else if (outcome.kind === "offline") {
        report.offline.push(peerId);
      } else {
        report.failed.push([peerId, outcome.error]);
      }
    });
    return report;
  }

  async #resolveSession(peerId) {
    const known = this.#sessions.get(peerId);
    if (known && !known.isClosed()) {
      return known;
    }
    if (known) {
      this.detach(peerId);
    }
    if (!this.#sessionFor) {
      return null;
    }
    const session = await this.#sessionFor(peerId);
    if (!session || session.isClosed()) {
      return null;
    }
    if (session.peerDeviceId !== peerId) {
      throw new Error("provided session is not authenticated as the requested peer");
    }
    this.attach(session);
    return session;
  }

  async #deliver(peerId, bytes, cap) {
    let session;
    try {
      session = await this.#resolveSession(peerId);
    } catch (err) {
      return { kind: "failed", error: errText(err) };
    }
    if (!session) {
      return { kind: "offline" };
    }
    try {
      if (this.#closed) {
        throw new Error("TendrilWebGroup is closed");
      }
      if (this.#localRevoked) {
        throw new Error("local device is no longer an active member of the group");
      }
      this.#backend.canSend(peerId, cap);
      await withTimeout(session.sendData(bytes), this.#sendTimeoutMs, "send timed out");
      return { kind: "delivered" };
    } catch (err) {
      if (session.isClosed() || errText(err) === "send timed out") {
        this.detach(peerId);
      }
      return { kind: "failed", error: errText(err) };
    }
  }

  #audit(subject, cap, reason) {
    return {
      event: "audit",
      audit: {
        ts: Math.floor(Date.now() / 1000),
        subject: subject ?? "unknown",
        cap,
        grant_nonce: null,
        allow: false,
        reason,
      },
    };
  }

  #emitData(sender, payloadB64) {
    if (this.#queue.length >= EVENT_QUEUE_CAP - CONTROL_EVENT_RESERVE) {
      this.#emit(
        this.#audit(sender, `group.send:${this.#groupId}`, "event queue full; app data dropped")
      );
      return;
    }
    this.#emit({
      event: "app_data",
      sender_device_id: sender,
      payload_b64: payloadB64,
    });
  }

  #emit(event) {
    if (this.#closed) {
      return;
    }
    for (const name of [event.event, "*"]) {
      for (const fn of this.#listeners.get(name) ?? []) {
        try {
          fn(event);
        } catch {}
      }
    }
    if (this.#waiters.length > 0) {
      this.#waiters.shift()(event);
      return;
    }
    if (this.#queue.length < EVENT_QUEUE_CAP) {
      this.#queue.push(event);
    }
  }

  /** Subscribes `fn` to `app_data`, `manifest_updated`, `member_joined`, `member_revoked`, `audit`, or `"*"`. */
  on(name, fn) {
    if (typeof fn !== "function") {
      throw new TypeError("listener must be a function");
    }
    const set = this.#listeners.get(name) ?? new Set();
    set.add(fn);
    this.#listeners.set(name, set);
    return () => set.delete(fn);
  }

  /**
   * Waits up to `timeoutMs` for the next event. Resolves the event object, or `null` on timeout or
   * once the group is closed.
   */
  pollEvent(timeoutMs = 5000) {
    if (this.#queue.length > 0) {
      return Promise.resolve(this.#queue.shift());
    }
    if (this.#closed) {
      return Promise.resolve(null);
    }
    return new Promise((resolve) => {
      const waiter = (value) => {
        clearTimeout(timer);
        resolve(value);
      };
      const timer = setTimeout(() => {
        const i = this.#waiters.indexOf(waiter);
        if (i >= 0) {
          this.#waiters.splice(i, 1);
        }
        resolve(null);
      }, timeoutMs);
      this.#waiters.push(waiter);
    });
  }

  /** Idempotently stops delivery. Attached sessions stay open and owned by the app. */
  close() {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#sessions.clear();
    this.#pumps.clear();
    this.#queue.length = 0;
    for (const waiter of this.#waiters.splice(0)) {
      waiter(null);
    }
    this.#listeners.clear();
    if (typeof this.#onClose === "function") {
      const cb = this.#onClose;
      this.#onClose = null;
      cb(this);
    }
  }
}
