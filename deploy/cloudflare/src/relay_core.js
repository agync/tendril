import {
  canonicalRelayHost,
  decodeB64UrlExact,
  decodeRelayInitFrameB64,
  getProtocolConstants,
  v2EpochForUnix,
  v2EpochWithinSkew,
  validateEd25519PubB64,
  validateRelayAuthSecretBytes,
  validateRelayTicketSchemaJson,
  verifyRelayAcceptV1,
  verifyRelayAuthHmacB64,
  verifyRelayRegisterV1,
  verifyRelayTicketJson,
  verifyV2RelayAcceptB64,
  verifyV2RelayRegisterB64,
} from "./wasm.js";

const DEFAULT_MAX_CONNECTIONS = 4096;
const DEFAULT_MAX_CONNS_PER_IP = 64;
const DEFAULT_MAX_MAILBOXES = 1024;
const DEFAULT_MAX_PENDING_PER_MAILBOX = 8;
const DEFAULT_MAX_ACTIVE_PER_MAILBOX = 64;
const DEFAULT_CONTROL_MAX_BYTES = 131_072;
const DEFAULT_ACCEPT_TIMEOUT_MS = 15_000;
const DEFAULT_IDLE_TIMEOUT_MS = 300_000;
const ACTIVITY_PERSIST_INTERVAL_MS = 15_000;

const textEncoder = new TextEncoder();

function bytesToHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

function bytesToB64Url(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function constantTimeEqual32(a, b) {
  if (a.length !== 32 || b.length !== 32) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < 32; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function isPlainObject(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function parsePositiveIntEnv(raw, fallback) {
  if (raw === undefined || raw === null) {
    return fallback;
  }
  const s = String(raw).trim();
  if (!s) {
    return fallback;
  }
  if (!/^[1-9]\d*$/.test(s)) {
    throw new Error(`invalid positive integer config value: ${s}`);
  }
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n <= 0) {
    throw new Error(`out-of-range positive integer config value: ${s}`);
  }
  return n;
}

function parseCsvList(raw) {
  if (raw === undefined || raw === null) {
    return [];
  }
  return String(raw)
    .split(/[,\s]+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

/** Parses and validates Worker/DO environment configuration using `tendril-core` WASM rules. */
export function parseRelayConfig(env = {}) {
  const secretRaw = env.TENDRIL_RELAY_AUTH_SECRET;
  let authSecretBytes = null;
  if (secretRaw !== undefined && secretRaw !== null && String(secretRaw).length > 0) {
    authSecretBytes = textEncoder.encode(String(secretRaw));
    validateRelayAuthSecretBytes(authSecretBytes);
  }

  const issuerStrs = parseCsvList(env.TENDRIL_RELAY_ISSUER_PUBS);
  for (const key of issuerStrs) {
    validateEd25519PubB64(key);
  }

  const allowMailboxStrs = parseCsvList(env.TENDRIL_RELAY_ALLOW_MAILBOXES);
  const allowedMailboxes = allowMailboxStrs.map((key) => validateEd25519PubB64(key));

  const scopeRaw = env.TENDRIL_RELAY_AUTH_SCOPE;
  const hasExplicitScope =
    scopeRaw !== undefined && scopeRaw !== null && String(scopeRaw).trim() !== "";
  const scopeStr = hasExplicitScope ? String(scopeRaw).trim() : "all";
  if (scopeStr !== "all" && scopeStr !== "register-only") {
    throw new Error(`invalid TENDRIL_RELAY_AUTH_SCOPE: ${scopeStr}`);
  }

  const hasTier2Or3 = authSecretBytes !== null || issuerStrs.length > 0;
  const requiresRegister = allowedMailboxes.length > 0 || hasTier2Or3;
  if (hasExplicitScope && !requiresRegister) {
    throw new Error(
      "TENDRIL_RELAY_AUTH_SCOPE requires TENDRIL_RELAY_AUTH_SECRET, TENDRIL_RELAY_ISSUER_PUBS, or TENDRIL_RELAY_ALLOW_MAILBOXES",
    );
  }
  const requiresDial = hasTier2Or3 && scopeStr === "all";

  return {
    authSecretBytes,
    trustedIssuersJson: issuerStrs.length > 0 ? JSON.stringify(issuerStrs) : null,
    allowedMailboxes,
    authScope: scopeStr,
    requiresRegister,
    requiresDial,
    authRequired: !requiresRegister ? null : requiresDial ? ["register", "dial"] : ["register"],
    maxConnections: parsePositiveIntEnv(env.TENDRIL_RELAY_MAX_CONNECTIONS, DEFAULT_MAX_CONNECTIONS),
    maxConnsPerIp: parsePositiveIntEnv(env.TENDRIL_RELAY_MAX_CONNS_PER_IP, DEFAULT_MAX_CONNS_PER_IP),
    maxMailboxes: parsePositiveIntEnv(env.TENDRIL_RELAY_MAX_MAILBOXES, DEFAULT_MAX_MAILBOXES),
    maxPendingPerMailbox: parsePositiveIntEnv(
      env.TENDRIL_RELAY_MAX_PENDING_PER_MAILBOX,
      DEFAULT_MAX_PENDING_PER_MAILBOX,
    ),
    maxActivePerMailbox: parsePositiveIntEnv(
      env.TENDRIL_RELAY_MAX_ACTIVE_PER_MAILBOX,
      DEFAULT_MAX_ACTIVE_PER_MAILBOX,
    ),
    controlMaxBytes: DEFAULT_CONTROL_MAX_BYTES,
    acceptTimeoutMs: DEFAULT_ACCEPT_TIMEOUT_MS,
    idleTimeoutMs: DEFAULT_IDLE_TIMEOUT_MS,
  };
}

/** Normalizes `CF-Connecting-IP` (IPv4 exact, IPv6 `/64` prefix) for per-IP limits. */
export function normalizeClientIp(rawIp) {
  if (!rawIp || typeof rawIp !== "string") {
    return "local";
  }
  const s = rawIp.trim();
  if (!s) {
    return "local";
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    const octets = s.split(".").map(Number);
    if (octets.every((n) => n >= 0 && n <= 255)) {
      return `v4:${octets.join(".")}`;
    }
  }
  const noZone = s.split("%")[0];
  if (noZone.includes(":")) {
    const halves = noZone.split("::");
    if (halves.length <= 2) {
      const left = halves[0] ? halves[0].split(":") : [];
      const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
      const missing = halves.length === 2 ? 8 - (left.length + right.length) : 0;
      if (missing >= 0 && (halves.length === 2 || left.length === 8)) {
        const groups = [...left, ...Array(missing).fill("0"), ...right];
        if (groups.length === 8 && groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) {
          const prefix = groups
            .slice(0, 4)
            .map((g) => g.toLowerCase().padStart(4, "0"))
            .join(":");
          return `v6:${prefix}`;
        }
      }
    }
  }
  return "local";
}

function resolvePublicHost(request, env) {
  const configured = env?.TENDRIL_RELAY_HOST;
  if (configured !== undefined && configured !== null && String(configured).trim() !== "") {
    return { ok: true, host: canonicalRelayHost(String(configured).trim()) };
  }
  try {
    const url = new URL(request.url);
    return { ok: true, host: canonicalRelayHost(url.hostname), status: 200 };
  } catch (err) {
    return { ok: false, error: err, status: 400 };
  }
}

/** Creates the Worker `fetch` handler routing `/healthz`, `/v1/relay`, and `/v2/relay`. */
export function createRelayHandler() {
  return {
    async fetch(request, env) {
      const constants = getProtocolConstants();
      const url = new URL(request.url);
      const upgrade = request.headers.get("upgrade");
      const wsKey = request.headers.get("sec-websocket-key");

      if (url.pathname === constants.health_path) {
        if (upgrade !== null || wsKey !== null) {
          return new Response("Not Found", { status: 404 });
        }
        if (request.method === "GET") {
          return new Response("ok", {
            status: 200,
            headers: {
              "content-type": "text/plain; charset=utf-8",
              "cache-control": "no-store",
            },
          });
        }
        if (request.method === "HEAD") {
          return new Response(null, {
            status: 200,
            headers: {
              "content-type": "text/plain; charset=utf-8",
              "cache-control": "no-store",
            },
          });
        }
        return new Response("Method Not Allowed", {
          status: 405,
          headers: { allow: "GET, HEAD" },
        });
      }

      if (url.pathname !== constants.relay_path && url.pathname !== constants.relay_v2_path) {
        return new Response("Not Found", { status: 404 });
      }

      if (request.method !== "GET" || !upgrade || upgrade.toLowerCase() !== "websocket") {
        return new Response("Upgrade Required", {
          status: 426,
          headers: { upgrade: "websocket" },
        });
      }

      let canonicalHost;
      const configured = env?.TENDRIL_RELAY_HOST;
      if (configured !== undefined && configured !== null && String(configured).trim() !== "") {
        try {
          canonicalHost = canonicalRelayHost(String(configured).trim());
        } catch {
          return new Response("Invalid relay host configuration", { status: 500 });
        }
      } else {
        const resolved = resolvePublicHost(request, env);
        if (!resolved.ok) {
          return new Response("Invalid host", { status: 400 });
        }
        canonicalHost = resolved.host;
      }

      try {
        parseRelayConfig(env);
      } catch {
        return new Response("Invalid relay configuration", { status: 500 });
      }

      const clientIp = normalizeClientIp(request.headers.get("cf-connecting-ip"));
      const headers = new Headers(request.headers);
      headers.set("x-tendril-canonical-host", canonicalHost);
      headers.set("x-tendril-client-ip", clientIp);

      const forwarded = new Request(url.toString(), {
        method: request.method,
        headers,
      });
      const stub = env.RELAY.get(env.RELAY.idFromName("global"));
      return stub.fetch(forwarded);
    },
  };
}

function toUint8Array(message) {
  if (typeof message === "string") {
    return null;
  }
  if (message instanceof Uint8Array) {
    return message;
  }
  if (message instanceof ArrayBuffer) {
    return new Uint8Array(message);
  }
  if (ArrayBuffer.isView(message)) {
    return new Uint8Array(message.buffer, message.byteOffset, message.byteLength);
  }
  return null;
}

function normalizeSqlBlob(raw) {
  if (raw === null || raw === undefined) {
    return null;
  }
  if (raw instanceof Uint8Array) {
    return raw;
  }
  if (raw instanceof ArrayBuffer) {
    return new Uint8Array(raw);
  }
  if (ArrayBuffer.isView(raw)) {
    return new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
  }
  return new Uint8Array(raw);
}

function parseStrictAuthProof(raw) {
  if (raw === undefined || raw === null) {
    return { ok: true, auth: null };
  }
  if (!isPlainObject(raw)) {
    return { ok: false };
  }
  const keys = Object.keys(raw);
  if (raw.kind === "hmac") {
    if (keys.length !== 2 || typeof raw.mac !== "string") {
      return { ok: false };
    }
    return { ok: true, auth: { kind: "hmac", mac: raw.mac } };
  }
  if (raw.kind === "ticket") {
    if (keys.length !== 2 || !isPlainObject(raw.ticket)) {
      return { ok: false };
    }
    const ticketJson = JSON.stringify(raw.ticket);
    try {
      validateRelayTicketSchemaJson(ticketJson);
    } catch {
      return { ok: false };
    }
    return { ok: true, auth: { kind: "ticket", ticketJson } };
  }
  return { ok: false };
}

/**
 * Hibernatable Durable Object state machine implementing `/v1/relay` and `/v2/relay`.
 * Keep every socket attachment compact; classic `init_frame` payloads live in SQLite only.
 */
export class TendrilRelayCore {
  constructor(ctx, env, deps = {}) {
    this.ctx = ctx;
    this.env = env || {};
    this.constants = getProtocolConstants();
    this.config = parseRelayConfig(this.env);
    this.sql = ctx.storage.sql;
    this._now = deps.now ?? (() => Date.now());
    this._randomBytes =
      deps.randomBytes ??
      ((len) => {
        const out = new Uint8Array(len);
        crypto.getRandomValues(out);
        return out;
      });
    this._newWebSocketPair = deps.newWebSocketPair ?? (() => new WebSocketPair());
    this._makeUpgradeResponse =
      deps.makeUpgradeResponse ?? ((client) => new Response(null, { status: 101, webSocket: client }));

    this.nextId = 1;
    this.totalSockets = 0;
    this.ipConns = new Map();
    this.awaitingCmd = new Map();
    this.scheduledAlarmMs = null;

    this.v1Mailboxes = new Map();
    this.v1Standby = new Map();
    this.v1Pending = new Map();
    this.v1PendingCounts = new Map();
    this.v1ActivePerMailbox = new Map();

    this.v2Mailboxes = new Map();
    this.v2Standby = new Map();
    this.v2Pending = new Map();
    this.v2PendingCounts = new Map();
    this.v2ActivePerMailbox = new Map();

    this.bridges = new Map();
    this.cleanedSockets = new WeakSet();

    this.ready = this.ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(
        "CREATE TABLE IF NOT EXISTS pending_init_frames (dial_id INTEGER PRIMARY KEY, frame BLOB NOT NULL)",
      );
      await this._hydrate();
    });
  }

  _allocId() {
    const id = this.nextId;
    this.nextId += 1;
    return id;
  }

  _bumpNextId(seenId) {
    if (typeof seenId === "number" && Number.isSafeInteger(seenId) && seenId >= this.nextId) {
      this.nextId = seenId + 1;
    }
  }

  _putInitFrame(dialId, bytes) {
    const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    this.sql.exec(
      "INSERT OR REPLACE INTO pending_init_frames (dial_id, frame) VALUES (?, ?)",
      dialId,
      ab,
    );
  }

  _takeInitFrame(dialId) {
    const rows = Array.from(
      this.sql.exec("SELECT frame FROM pending_init_frames WHERE dial_id = ?", dialId),
    );
    this.sql.exec("DELETE FROM pending_init_frames WHERE dial_id = ?", dialId);
    if (rows.length === 0) {
      return null;
    }
    const row = rows[0];
    const raw = row.frame ?? row[0];
    return normalizeSqlBlob(raw);
  }

  _deleteInitFrame(dialId) {
    this.sql.exec("DELETE FROM pending_init_frames WHERE dial_id = ?", dialId);
  }

  _pruneOrphanInitFrames(liveDialIds) {
    const rows = Array.from(this.sql.exec("SELECT dial_id FROM pending_init_frames"));
    for (const row of rows) {
      const dialId = Number(row.dial_id ?? row[0]);
      if (!liveDialIds.has(dialId)) {
        this._deleteInitFrame(dialId);
      }
    }
  }

  _getMaps(isV2) {
    if (isV2) {
      return {
        mailboxes: this.v2Mailboxes,
        standby: this.v2Standby,
        pending: this.v2Pending,
        pendingCounts: this.v2PendingCounts,
        activeCounts: this.v2ActivePerMailbox,
      };
    }
    return {
      mailboxes: this.v1Mailboxes,
      standby: this.v1Standby,
      pending: this.v1Pending,
      pendingCounts: this.v1PendingCounts,
      activeCounts: this.v1ActivePerMailbox,
    };
  }

  _incrementIp(ip) {
    this.totalSockets += 1;
    this.ipConns.set(ip, (this.ipConns.get(ip) ?? 0) + 1);
  }

  _decrementIp(ip) {
    if (this.totalSockets > 0) {
      this.totalSockets -= 1;
    }
    const cur = this.ipConns.get(ip) ?? 0;
    if (cur <= 1) {
      this.ipConns.delete(ip);
    } else {
      this.ipConns.set(ip, cur - 1);
    }
  }

  _incCount(map, key) {
    map.set(key, (map.get(key) ?? 0) + 1);
  }

  _decCount(map, key) {
    const cur = map.get(key) ?? 0;
    if (cur <= 1) {
      map.delete(key);
    } else {
      map.set(key, cur - 1);
    }
  }

  _sendJson(ws, obj) {
    try {
      ws.send(JSON.stringify(obj));
      return true;
    } catch {
      return false;
    }
  }

  _safeClose(ws, code = 1000, reason = "closed") {
    try {
      ws.close(code, reason);
    } catch {
      // Socket already closed.
    }
  }

  _setAttachment(ws, att) {
    ws.serializeAttachment(att);
  }

  _closeWithError(ws, errorCode, wsCode = 1008) {
    this._cleanupSocket(ws);
    this._sendJson(ws, { op: "error", code: errorCode });
    this._safeClose(ws, wsCode, errorCode);
  }

  async _hydrate() {
    const sockets = this.ctx.getWebSockets();
    const candidateStandby = [];
    const candidatePending = [];
    const candidateBridges = new Map();

    for (const ws of sockets) {
      let att = null;
      try {
        att = ws.deserializeAttachment();
      } catch {
        att = null;
      }
      if (!isPlainObject(att) || typeof att.state !== "string" || att.state === "closed") {
        this._cleanedMark(ws);
        this._safeClose(ws, 1000, "stale");
        continue;
      }
      const ip = typeof att.ip === "string" ? att.ip : "local";
      this._incrementIp(ip);

      switch (att.state) {
        case "awaiting_cmd": {
          this.awaitingCmd.set(ws, att.deadlineMs);
          break;
        }
        case "listener": {
          this._bumpNextId(att.regId);
          const maps = this._getMaps(Boolean(att.isV2));
          const existing = maps.mailboxes.get(att.keyHex);
          if (existing) {
            if (att.regId > existing.regId) {
              this._cleanedMark(existing.ws);
              this._decrementIp(existing.att.ip);
              this._setAttachment(existing.ws, null);
              this._safeClose(existing.ws, 1000, "replaced");
              maps.mailboxes.set(att.keyHex, { ws, att, regId: att.regId });
            } else {
              this._cleanedMark(ws);
              this._decrementIp(ip);
              this._setAttachment(ws, null);
              this._safeClose(ws, 1000, "replaced");
            }
          } else {
            maps.mailboxes.set(att.keyHex, { ws, att, regId: att.regId });
          }
          break;
        }
        case "standby": {
          this._bumpNextId(att.regId);
          this._bumpNextId(att.standbyId);
          candidateStandby.push({ ws, att });
          break;
        }
        case "dialer_waiting": {
          this._bumpNextId(att.regId);
          this._bumpNextId(att.dialId);
          candidatePending.push({ ws, att });
          break;
        }
        case "bridged": {
          this._bumpNextId(att.bridgeId);
          let group = candidateBridges.get(att.bridgeId);
          if (!group) {
            group = [];
            candidateBridges.set(att.bridgeId, group);
          }
          group.push({ ws, att });
          break;
        }
        default: {
          this._cleanedMark(ws);
          this._decrementIp(ip);
          this._setAttachment(ws, null);
          this._safeClose(ws, 1008, "invalid_state");
        }
      }
    }

    for (const { ws, att } of candidateStandby) {
      const maps = this._getMaps(Boolean(att.isV2));
      const mailbox = maps.mailboxes.get(att.keyHex);
      if (!mailbox || mailbox.regId !== att.regId || (att.isV2 && mailbox.att.epoch !== att.epoch)) {
        this._cleanedMark(ws);
        this._decrementIp(att.ip);
        this._setAttachment(ws, null);
        this._sendJson(ws, { op: "error", code: "offline" });
        this._safeClose(ws, 1000, "offline");
        continue;
      }
      let pool = maps.standby.get(att.keyHex);
      if (!pool) {
        pool = [];
        maps.standby.set(att.keyHex, pool);
      }
      pool.push({ ws, att, regId: att.regId, standbyId: att.standbyId });
    }

    for (const pool of this.v1Standby.values()) {
      pool.sort((a, b) => a.standbyId - b.standbyId);
    }
    for (const pool of this.v2Standby.values()) {
      pool.sort((a, b) => a.standbyId - b.standbyId);
    }

    const liveDialIds = new Set();
    for (const { ws, att } of candidatePending) {
      const maps = this._getMaps(Boolean(att.isV2));
      const mailbox = maps.mailboxes.get(att.keyHex);
      if (
        !mailbox ||
        mailbox.regId !== att.regId ||
        (att.isV2 && mailbox.att.epoch !== att.epoch) ||
        maps.pending.has(att.connIdHex)
      ) {
        this._cleanedMark(ws);
        this._decrementIp(att.ip);
        this._setAttachment(ws, null);
        if (att.hasStoredInit) {
          this._deleteInitFrame(att.dialId);
        }
        this._sendJson(ws, { op: "error", code: "offline" });
        this._safeClose(ws, 1000, "offline");
        continue;
      }
      maps.pending.set(att.connIdHex, { ws, att });
      this._incCount(maps.pendingCounts, att.keyHex);
      if (att.hasStoredInit) {
        liveDialIds.add(att.dialId);
      }
    }

    this._pruneOrphanInitFrames(liveDialIds);

    for (const [bridgeId, members] of candidateBridges.entries()) {
      const dialer = members.find((m) => m.att.role === "dialer");
      const acceptor = members.find((m) => m.att.role === "acceptor");
      if (!dialer || !acceptor || members.length !== 2) {
        for (const m of members) {
          this._cleanedMark(m.ws);
          this._decrementIp(m.att.ip);
          this._setAttachment(m.ws, null);
          this._safeClose(m.ws, 1001, "peer closed");
        }
        continue;
      }
      const maps = this._getMaps(Boolean(dialer.att.isV2));
      this._incCount(maps.activeCounts, dialer.att.keyHex);
      const lastActivityMs = Math.max(dialer.att.lastActivityMs ?? 0, acceptor.att.lastActivityMs ?? 0);
      this.bridges.set(bridgeId, {
        bridgeId,
        isV2: Boolean(dialer.att.isV2),
        keyHex: dialer.att.keyHex,
        dialerWs: dialer.ws,
        acceptorWs: acceptor.ws,
        dialerAtt: dialer.att,
        acceptorAtt: acceptor.att,
        lastActivityMs,
      });
    }

    await this._rescheduleAlarm();
  }

  _cleanedMark(ws) {
    this.cleanedSockets.add(ws);
  }

  _evictStandbyPool(isV2, keyHex, regId = null) {
    const maps = this._getMaps(isV2);
    const pool = maps.standby.get(keyHex);
    if (!pool) {
      return;
    }
    const keep = [];
    for (const slot of pool) {
      if (regId === null || slot.regId === regId) {
        this._cleanedMark(slot.ws);
        this._decrementIp(slot.att.ip);
        this._setAttachment(slot.ws, null);
        this._safeClose(slot.ws, 1000, "listener closed");
      } else {
        keep.push(slot);
      }
    }
    if (keep.length === 0) {
      maps.standby.delete(keyHex);
    } else {
      maps.standby.set(keyHex, keep);
    }
  }

  _failPendingForMailbox(isV2, keyHex, regId, errorCode) {
    const maps = this._getMaps(isV2);
    for (const [connIdHex, entry] of maps.pending.entries()) {
      if (entry.att.keyHex === keyHex && (regId === null || entry.att.regId === regId)) {
        maps.pending.delete(connIdHex);
        this._decCount(maps.pendingCounts, keyHex);
        if (entry.att.hasStoredInit) {
          this._deleteInitFrame(entry.att.dialId);
        }
        this._cleanedMark(entry.ws);
        this._decrementIp(entry.att.ip);
        this._setAttachment(entry.ws, null);
        this._sendJson(entry.ws, { op: "error", code: errorCode });
        this._safeClose(entry.ws, 1000, errorCode);
      }
    }
  }

  _cleanupSocket(ws, peerCloseCode = 1000, peerReason = "peer closed") {
    if (this.cleanedSockets.has(ws)) {
      return;
    }
    this.cleanedSockets.add(ws);

    let att = null;
    try {
      att = ws.deserializeAttachment();
    } catch {
      att = null;
    }
    this._setAttachment(ws, null);
    if (!isPlainObject(att) || typeof att.state !== "string" || att.state === "closed") {
      return;
    }

    this._decrementIp(typeof att.ip === "string" ? att.ip : "local");

    switch (att.state) {
      case "awaiting_cmd": {
        this.awaitingCmd.delete(ws);
        break;
      }
      case "listener": {
        const maps = this._getMaps(Boolean(att.isV2));
        const cur = maps.mailboxes.get(att.keyHex);
        if (cur && cur.ws === ws) {
          maps.mailboxes.delete(att.keyHex);
          this._evictStandbyPool(Boolean(att.isV2), att.keyHex, att.regId);
          this._failPendingForMailbox(Boolean(att.isV2), att.keyHex, att.regId, "offline");
        }
        break;
      }
      case "standby": {
        const maps = this._getMaps(Boolean(att.isV2));
        const pool = maps.standby.get(att.keyHex);
        if (pool) {
          const next = pool.filter((slot) => slot.ws !== ws);
          if (next.length === 0) {
            maps.standby.delete(att.keyHex);
          } else {
            maps.standby.set(att.keyHex, next);
          }
        }
        break;
      }
      case "dialer_waiting": {
        const maps = this._getMaps(Boolean(att.isV2));
        const cur = maps.pending.get(att.connIdHex);
        if (cur && cur.ws === ws) {
          maps.pending.delete(att.connIdHex);
          this._decCount(maps.pendingCounts, att.keyHex);
        }
        if (att.hasStoredInit) {
          this._deleteInitFrame(att.dialId);
        }
        break;
      }
      case "bridged": {
        const bridge = this.bridges.get(att.bridgeId);
        if (bridge) {
          this.bridges.delete(att.bridgeId);
          const maps = this._getMaps(bridge.isV2);
          this._decCount(maps.activeCounts, bridge.keyHex);
          const peerWs = ws === bridge.dialerWs ? bridge.acceptorWs : bridge.dialerWs;
          const peerAtt = ws === bridge.dialerWs ? bridge.acceptorAtt : bridge.dialerAtt;
          if (!this.cleanedSockets.has(peerWs)) {
            this.cleanedSockets.add(peerWs);
            this._decrementIp(peerAtt.ip);
            this._setAttachment(peerWs, null);
            this._safeClose(peerWs, peerCloseCode, peerReason);
          }
        }
        break;
      }
      default:
        break;
    }
  }

  _nextDeadlineMs() {
    let earliest = null;
    const consider = (ms) => {
      if (typeof ms === "number" && Number.isFinite(ms)) {
        if (earliest === null || ms < earliest) {
          earliest = ms;
        }
      }
    };

    for (const deadlineMs of this.awaitingCmd.values()) {
      consider(deadlineMs);
    }
    for (const entry of this.v1Pending.values()) {
      consider(entry.att.deadlineMs);
    }
    for (const entry of this.v2Pending.values()) {
      consider(entry.att.deadlineMs);
    }
    for (const entry of this.v2Mailboxes.values()) {
      consider(entry.att.expiryMs);
    }
    for (const pool of this.v2Standby.values()) {
      for (const slot of pool) {
        consider(slot.att.expiryMs);
      }
    }
    for (const bridge of this.bridges.values()) {
      consider(bridge.lastActivityMs + this.config.idleTimeoutMs);
    }
    return earliest;
  }

  async _rescheduleAlarm() {
    const earliest = this._nextDeadlineMs();
    if (earliest === null) {
      if (this.scheduledAlarmMs !== null && typeof this.ctx.storage.deleteAlarm === "function") {
        await this.ctx.storage.deleteAlarm();
      }
      this.scheduledAlarmMs = null;
      return;
    }
    if (this.scheduledAlarmMs === earliest) {
      return;
    }
    await this.ctx.storage.setAlarm(earliest);
    this.scheduledAlarmMs = earliest;
  }

  _mailboxAllowlisted(keyBytes) {
    return this.config.allowedMailboxes.some((allowed) => constantTimeEqual32(allowed, keyBytes));
  }

  _verifyAdmission(op, role, relayHost, nonceBytes, targetKeyBytes, auth) {
    const requires =
      role === "dial" ? this.config.requiresDial : this.config.requiresRegister;
    if (!requires) {
      return true;
    }
    if ((op === "register" || op === "accept") && this._mailboxAllowlisted(targetKeyBytes)) {
      return true;
    }
    if (!auth) {
      return false;
    }
    if (auth.kind === "hmac") {
      if (!this.config.authSecretBytes) {
        return false;
      }
      try {
        verifyRelayAuthHmacB64(
          this.config.authSecretBytes,
          op,
          relayHost,
          nonceBytes,
          targetKeyBytes,
          auth.mac,
        );
        return true;
      } catch {
        return false;
      }
    }
    if (auth.kind === "ticket") {
      if (!this.config.trustedIssuersJson) {
        return false;
      }
      try {
        const nowUnix = Math.floor(this._now() / 1000);
        verifyRelayTicketJson(
          auth.ticketJson,
          this.config.trustedIssuersJson,
          relayHost,
          op,
          targetKeyBytes,
          nowUnix,
        );
        return true;
      } catch {
        return false;
      }
    }
    return false;
  }

  async fetch(request) {
    await this.ready;
    const url = new URL(request.url);
    const isV2 = url.pathname === this.constants.relay_v2_path;
    if (!isV2 && url.pathname !== this.constants.relay_path) {
      return new Response("Not Found", { status: 404 });
    }
    const upgrade = request.headers.get("upgrade");
    if (request.method !== "GET" || !upgrade || upgrade.toLowerCase() !== "websocket") {
      return new Response("Upgrade Required", { status: 426, headers: { upgrade: "websocket" } });
    }

    let host = request.headers.get("x-tendril-canonical-host");
    if (!host) {
      const resolved = resolvePublicHost(request, this.env);
      if (!resolved.ok) {
        return new Response("Invalid host", { status: 400 });
      }
      host = resolved.host;
    } else {
      try {
        host = canonicalRelayHost(host);
      } catch {
        return new Response("Invalid host", { status: 400 });
      }
    }
    const ip = request.headers.get("x-tendril-client-ip") || "local";

    const [client, server] = this._newWebSocketPair();

    if (this.totalSockets >= this.config.maxConnections) {
      server.accept();
      this._sendJson(server, { op: "error", code: "capacity_exceeded" });
      this._safeClose(server, 1008, "capacity_exceeded");
      return this._makeUpgradeResponse(client);
    }
    if ((this.ipConns.get(ip) ?? 0) >= this.config.maxConnsPerIp) {
      server.accept();
      this._sendJson(server, { op: "error", code: "rate_limited" });
      this._safeClose(server, 1008, "rate_limited");
      return this._makeUpgradeResponse(client);
    }

    const nonceBytes = this._randomBytes(32);
    const nonceB64 = bytesToB64Url(nonceBytes);
    const nowMs = this._now();
    const serverEpoch = isV2 ? v2EpochForUnix(Math.floor(nowMs / 1000)) : null;

    this.ctx.acceptWebSocket(server);
    this._incrementIp(ip);

    const att = {
      state: "awaiting_cmd",
      isV2,
      host,
      ip,
      nonceB64,
      serverEpoch,
      deadlineMs: nowMs + this.config.acceptTimeoutMs,
    };
    this._setAttachment(server, att);
    this.awaitingCmd.set(server, att.deadlineMs);

    const challenge = isV2
      ? {
          op: "challenge",
          nonce: nonceB64,
          host,
          epoch: serverEpoch,
          max_frame: this.constants.max_relay_frame_len,
          fast_open: true,
          standby: true,
        }
      : {
          op: "challenge",
          nonce: nonceB64,
          host,
          max_frame: this.constants.max_relay_frame_len,
          fast_open: true,
          standby: true,
        };
    if (this.config.authRequired) {
      challenge.auth_required = this.config.authRequired;
    }
    this._sendJson(server, challenge);

    await this._rescheduleAlarm();
    return this._makeUpgradeResponse(client);
  }

  async webSocketMessage(ws, message) {
    await this.ready;
    if (this.cleanedSockets.has(ws)) {
      return;
    }

    let att = null;
    try {
      att = ws.deserializeAttachment();
    } catch {
      att = null;
    }
    if (!isPlainObject(att) || typeof att.state !== "string" || att.state === "closed") {
      this._safeClose(ws, 1008, "invalid_state");
      return;
    }

    if (att.state === "bridged") {
      const bin = toUint8Array(message);
      if (bin === null) {
        this._cleanupSocket(ws, 1008, "text frame rejected on bridged stream");
        this._safeClose(ws, 1008, "text frame rejected on bridged stream");
        await this._rescheduleAlarm();
        return;
      }
      if (bin.byteLength === 0 || bin.byteLength > this.constants.max_relay_frame_len) {
        const closeCode = bin.byteLength === 0 ? 1008 : 1009;
        this._cleanupSocket(ws, closeCode, "invalid binary frame length");
        this._safeClose(ws, closeCode, "invalid binary frame length");
        await this._rescheduleAlarm();
        return;
      }
      const bridge = this.bridges.get(att.bridgeId);
      if (!bridge) {
        this._cleanupSocket(ws, 1001, "bridge missing");
        this._safeClose(ws, 1001, "bridge missing");
        await this._rescheduleAlarm();
        return;
      }
      const peerWs = ws === bridge.dialerWs ? bridge.acceptorWs : bridge.dialerWs;
      try {
        peerWs.send(bin);
      } catch {
        this._cleanupSocket(ws, 1001, "peer send failed");
        this._safeClose(ws, 1001, "peer send failed");
        await this._rescheduleAlarm();
        return;
      }
      const nowMs = this._now();
      bridge.lastActivityMs = nowMs;
      att.lastActivityMs = nowMs;
      if (nowMs - (att.persistedActivityMs ?? 0) >= ACTIVITY_PERSIST_INTERVAL_MS) {
        att.persistedActivityMs = nowMs;
        this._setAttachment(ws, att);
        await this._rescheduleAlarm();
      }
      return;
    }

    if (att.state !== "awaiting_cmd") {
      this._cleanupSocket(ws);
      this._safeClose(ws, 1008, "unexpected_message");
      await this._rescheduleAlarm();
      return;
    }

    if (typeof message !== "string") {
      this._closeWithError(ws, "invalid_request");
      await this._rescheduleAlarm();
      return;
    }
    if (textEncoder.encode(message).byteLength > this.config.controlMaxBytes) {
      this._closeWithError(ws, "invalid_request");
      await this._rescheduleAlarm();
      return;
    }

    let msg;
    try {
      msg = JSON.parse(message);
    } catch {
      this._closeWithError(ws, "invalid_request");
      await this._rescheduleAlarm();
      return;
    }
    if (!isPlainObject(msg) || typeof msg.op !== "string") {
      this._closeWithError(ws, "invalid_request");
      await this._rescheduleAlarm();
      return;
    }

    const parsedAuth = parseStrictAuthProof(msg.auth);
    if (!parsedAuth.ok) {
      this._closeWithError(ws, "invalid_request");
      await this._rescheduleAlarm();
      return;
    }

    const nonceBytes = decodeB64UrlExact(att.nonceB64, 32);

    switch (msg.op) {
      case "register":
        this._handleRegister(ws, att, msg, nonceBytes, parsedAuth.auth);
        break;
      case "standby":
        this._handleStandby(ws, att, msg, nonceBytes, parsedAuth.auth);
        break;
      case "dial":
        this._handleDial(ws, att, msg, nonceBytes, parsedAuth.auth);
        break;
      case "accept":
        this._handleAccept(ws, att, msg, nonceBytes, parsedAuth.auth);
        break;
      default:
        this._closeWithError(ws, "invalid_request");
        break;
    }

    await this._rescheduleAlarm();
  }

  _handleRegister(ws, att, msg, nonceBytes, auth) {
    const isV2 = Boolean(att.isV2);
    const fastOpen = msg.fast_open === true;
    if (msg.fast_open !== undefined && typeof msg.fast_open !== "boolean") {
      this._closeWithError(ws, "invalid_request");
      return;
    }

    let keyBytes;
    let keyB64;
    let epoch = null;

    if (isV2) {
      if (
        typeof msg.mailbox_id !== "string" ||
        typeof msg.sig !== "string" ||
        !Number.isSafeInteger(msg.epoch) ||
        msg.epoch < 0
      ) {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      try {
        decodeB64UrlExact(msg.mailbox_id, 32);
        decodeB64UrlExact(msg.sig, 64);
      } catch {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      try {
        if (!v2EpochWithinSkew(att.serverEpoch, msg.epoch)) {
          this._closeWithError(ws, "unauthorized");
          return;
        }
        keyBytes = verifyV2RelayRegisterB64(
          msg.mailbox_id,
          msg.epoch,
          att.host,
          nonceBytes,
          msg.sig,
        );
      } catch {
        this._closeWithError(ws, "unauthorized");
        return;
      }
      keyB64 = msg.mailbox_id;
      epoch = msg.epoch;
    } else {
      if (typeof msg.pub !== "string" || typeof msg.sig !== "string") {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      try {
        keyBytes = verifyRelayRegisterV1(msg.pub, msg.sig, att.host, nonceBytes);
      } catch {
        this._closeWithError(ws, "unauthorized");
        return;
      }
      keyB64 = msg.pub;
    }

    if (!this._verifyAdmission("register", "register", att.host, nonceBytes, keyBytes, auth)) {
      this._closeWithError(ws, "unauthorized");
      return;
    }

    const keyHex = bytesToHex(keyBytes);
    const maps = this._getMaps(isV2);
    const totalMailboxes = this.v1Mailboxes.size + this.v2Mailboxes.size;
    if (!maps.mailboxes.has(keyHex) && totalMailboxes >= this.config.maxMailboxes) {
      this._closeWithError(ws, "capacity_exceeded");
      return;
    }

    const prev = maps.mailboxes.get(keyHex);
    if (prev) {
      maps.mailboxes.delete(keyHex);
      this._evictStandbyPool(isV2, keyHex, prev.regId);
      this._failPendingForMailbox(isV2, keyHex, prev.regId, "offline");
      this._cleanedMark(prev.ws);
      this._decrementIp(prev.att.ip);
      this._setAttachment(prev.ws, null);
      this._safeClose(prev.ws, 1000, "replaced");
    }

    const regId = this._allocId();
    const expiryMs = isV2
      ? (epoch + 2) * this.constants.v2_epoch_secs * 1000
      : null;

    this.awaitingCmd.delete(ws);
    const nextAtt = {
      state: "listener",
      isV2,
      host: att.host,
      ip: att.ip,
      keyHex,
      keyB64,
      regId,
      epoch,
      fastOpen,
      expiryMs,
    };
    this._setAttachment(ws, nextAtt);
    maps.mailboxes.set(keyHex, { ws, att: nextAtt, regId });

    if (isV2) {
      this._sendJson(ws, { op: "registered", mailbox_id: keyB64, epoch });
    } else {
      this._sendJson(ws, { op: "registered", pub: keyB64 });
    }
  }

  _handleStandby(ws, att, msg, nonceBytes, auth) {
    const isV2 = Boolean(att.isV2);
    let keyBytes;
    let keyB64;
    let epoch = null;

    if (isV2) {
      if (
        typeof msg.mailbox_id !== "string" ||
        typeof msg.sig !== "string" ||
        !Number.isSafeInteger(msg.epoch) ||
        msg.epoch < 0
      ) {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      try {
        decodeB64UrlExact(msg.mailbox_id, 32);
        decodeB64UrlExact(msg.sig, 64);
      } catch {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      try {
        if (!v2EpochWithinSkew(att.serverEpoch, msg.epoch)) {
          this._closeWithError(ws, "unauthorized");
          return;
        }
        keyBytes = verifyV2RelayRegisterB64(
          msg.mailbox_id,
          msg.epoch,
          att.host,
          nonceBytes,
          msg.sig,
        );
      } catch {
        this._closeWithError(ws, "unauthorized");
        return;
      }
      keyB64 = msg.mailbox_id;
      epoch = msg.epoch;
    } else {
      if (typeof msg.pub !== "string" || typeof msg.sig !== "string") {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      try {
        keyBytes = verifyRelayRegisterV1(msg.pub, msg.sig, att.host, nonceBytes);
      } catch {
        this._closeWithError(ws, "unauthorized");
        return;
      }
      keyB64 = msg.pub;
    }

    if (!this._verifyAdmission("register", "register", att.host, nonceBytes, keyBytes, auth)) {
      this._closeWithError(ws, "unauthorized");
      return;
    }

    const keyHex = bytesToHex(keyBytes);
    const maps = this._getMaps(isV2);
    const mailbox = maps.mailboxes.get(keyHex);
    if (!mailbox || (isV2 && mailbox.att.epoch !== epoch)) {
      this._closeWithError(ws, "offline");
      return;
    }

    let pool = maps.standby.get(keyHex) ?? [];
    pool = pool.filter((slot) => slot.regId === mailbox.regId && !this.cleanedSockets.has(slot.ws));
    if (pool.length >= this.constants.max_standby_per_mailbox) {
      maps.standby.set(keyHex, pool);
      this._closeWithError(ws, "rate_limited");
      return;
    }

    const standbyId = this._allocId();
    this.awaitingCmd.delete(ws);
    const nextAtt = {
      state: "standby",
      isV2,
      host: att.host,
      ip: att.ip,
      keyHex,
      regId: mailbox.regId,
      standbyId,
      epoch,
      expiryMs: mailbox.att.expiryMs,
    };
    this._setAttachment(ws, nextAtt);
    pool.push({ ws, att: nextAtt, regId: mailbox.regId, standbyId });
    maps.standby.set(keyHex, pool);

    if (isV2) {
      this._sendJson(ws, { op: "standby_ready", mailbox_id: keyB64, epoch });
    } else {
      this._sendJson(ws, { op: "standby_ready" });
    }
  }

  _handleDial(ws, att, msg, nonceBytes, auth) {
    const isV2 = Boolean(att.isV2);
    let targetBytes;
    let connIdBytes;
    let targetB64;
    let epoch = null;
    let dialTokenB64 = null;

    if (isV2) {
      if (
        typeof msg.target_mailbox_id !== "string" ||
        typeof msg.conn_id !== "string" ||
        typeof msg.dial_token !== "string" ||
        !Number.isSafeInteger(msg.epoch) ||
        msg.epoch < 0
      ) {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      try {
        targetBytes = decodeB64UrlExact(msg.target_mailbox_id, 32);
        connIdBytes = decodeB64UrlExact(msg.conn_id, 16);
        decodeB64UrlExact(msg.dial_token, 32);
      } catch {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      targetB64 = msg.target_mailbox_id;
      epoch = msg.epoch;
      dialTokenB64 = msg.dial_token;
    } else {
      if (typeof msg.target_pub !== "string" || typeof msg.conn_id !== "string") {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      try {
        targetBytes = decodeB64UrlExact(msg.target_pub, 32);
        connIdBytes = decodeB64UrlExact(msg.conn_id, 16);
      } catch {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      targetB64 = msg.target_pub;
    }

    // Option 1A: verify dial admission BEFORE init_frame/epoch/mailbox checks to avoid presence oracle.
    if (!this._verifyAdmission("dial", "dial", att.host, nonceBytes, targetBytes, auth)) {
      this._closeWithError(ws, "unauthorized");
      return;
    }

    let initFrameB64 = null;
    let initBytes = null;
    if (msg.init_frame !== undefined && msg.init_frame !== null) {
      if (typeof msg.init_frame !== "string") {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      initFrameB64 = msg.init_frame;
      try {
        initBytes = decodeRelayInitFrameB64(initFrameB64);
      } catch (err) {
        const code = err?.code === "frame_too_large" ? "frame_too_large" : "bad_request";
        this._closeWithError(ws, code);
        return;
      }
    }

    if (isV2 && !v2EpochWithinSkew(att.serverEpoch, epoch)) {
      this._closeWithError(ws, "offline");
      return;
    }

    const keyHex = bytesToHex(targetBytes);
    const connIdHex = bytesToHex(connIdBytes);
    const connIdB64 = msg.conn_id;
    const maps = this._getMaps(isV2);
    const mailbox = maps.mailboxes.get(keyHex);
    if (!mailbox || (isV2 && mailbox.att.epoch !== epoch)) {
      this._closeWithError(ws, "offline");
      return;
    }

    const activeCount = maps.activeCounts.get(keyHex) ?? 0;
    const pendingCount = maps.pendingCounts.get(keyHex) ?? 0;
    if (
      activeCount >= this.config.maxActivePerMailbox ||
      pendingCount >= this.config.maxPendingPerMailbox
    ) {
      this._closeWithError(ws, "rate_limited");
      return;
    }
    if (maps.pending.has(connIdHex)) {
      this._closeWithError(ws, "invalid_request");
      return;
    }

    const incomingMsg = isV2
      ? {
          op: "incoming",
          mailbox_id: targetB64,
          epoch: mailbox.att.epoch,
          conn_id: connIdB64,
          dial_nonce: att.nonceB64,
          dial_token: dialTokenB64,
          ...(mailbox.att.fastOpen && initFrameB64 !== null ? { init_frame: initFrameB64 } : {}),
        }
      : {
          op: "incoming",
          conn_id: connIdB64,
          ...(mailbox.att.fastOpen && initFrameB64 !== null ? { init_frame: initFrameB64 } : {}),
        };

    // Prefer a pre-warmed standby acceptor socket when available.
    const pool = maps.standby.get(keyHex);
    let standbySlot = null;
    if (pool && pool.length > 0) {
      while (pool.length > 0) {
        const candidate = pool.shift();
        if (candidate.regId === mailbox.regId && !this.cleanedSockets.has(candidate.ws)) {
          if (this._sendJson(candidate.ws, incomingMsg)) {
            standbySlot = candidate;
            break;
          }
          this._cleanupSocket(candidate.ws);
          this._safeClose(candidate.ws, 1001, "standby write failed");
        }
      }
      if (pool.length === 0) {
        maps.standby.delete(keyHex);
      }
    }

    if (standbySlot) {
      this._bridgeSockets(
        isV2,
        keyHex,
        connIdB64,
        ws,
        att,
        standbySlot.ws,
        standbySlot.att,
        mailbox.att.fastOpen ? null : initBytes,
        false,
      );
      return;
    }

    // Classic fallback: queue pending dial and notify listener.
    const dialId = this._allocId();
    const storeInit = !mailbox.att.fastOpen && initBytes !== null;
    if (storeInit) {
      this._putInitFrame(dialId, initBytes);
    }

    if (!this._sendJson(mailbox.ws, incomingMsg)) {
      if (storeInit) {
        this._deleteInitFrame(dialId);
      }
      this._cleanupSocket(mailbox.ws);
      this._safeClose(mailbox.ws, 1001, "listener write failed");
      this._closeWithError(ws, "offline");
      return;
    }

    this.awaitingCmd.delete(ws);
    const dialerAtt = {
      state: "dialer_waiting",
      isV2,
      host: att.host,
      ip: att.ip,
      keyHex,
      connIdHex,
      connIdB64,
      dialId,
      regId: mailbox.regId,
      epoch: mailbox.att.epoch,
      mailboxFastOpen: Boolean(mailbox.att.fastOpen),
      hasStoredInit: storeInit,
      deadlineMs: this._now() + this.config.acceptTimeoutMs,
    };
    this._setAttachment(ws, dialerAtt);
    maps.pending.set(connIdHex, { ws, att: dialerAtt });
    this._incCount(maps.pendingCounts, keyHex);
  }

  _handleAccept(ws, att, msg, nonceBytes, auth) {
    const isV2 = Boolean(att.isV2);
    let acceptorBytes;
    let connIdBytes;
    let epoch = null;

    if (isV2) {
      if (
        typeof msg.mailbox_id !== "string" ||
        typeof msg.conn_id !== "string" ||
        typeof msg.sig !== "string" ||
        !Number.isSafeInteger(msg.epoch) ||
        msg.epoch < 0
      ) {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      try {
        decodeB64UrlExact(msg.mailbox_id, 32);
        decodeB64UrlExact(msg.conn_id, 16);
        decodeB64UrlExact(msg.sig, 64);
      } catch {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      try {
        if (!v2EpochWithinSkew(att.serverEpoch, msg.epoch)) {
          this._closeWithError(ws, "unauthorized");
          return;
        }
        const verified = verifyV2RelayAcceptB64(
          msg.mailbox_id,
          msg.epoch,
          att.host,
          nonceBytes,
          msg.conn_id,
          msg.sig,
        );
        acceptorBytes = verified.subarray(0, 32);
        connIdBytes = verified.subarray(32, 48);
      } catch {
        this._closeWithError(ws, "unauthorized");
        return;
      }
      epoch = msg.epoch;
    } else {
      if (
        typeof msg.pub !== "string" ||
        typeof msg.conn_id !== "string" ||
        typeof msg.sig !== "string"
      ) {
        this._closeWithError(ws, "invalid_request");
        return;
      }
      try {
        const verified = verifyRelayAcceptV1(
          msg.pub,
          msg.conn_id,
          msg.sig,
          att.host,
          nonceBytes,
        );
        acceptorBytes = verified.subarray(0, 32);
        connIdBytes = verified.subarray(32, 48);
      } catch {
        this._closeWithError(ws, "unauthorized");
        return;
      }
    }

    if (!this._verifyAdmission("accept", "register", att.host, nonceBytes, acceptorBytes, auth)) {
      this._closeWithError(ws, "unauthorized");
      return;
    }

    const acceptorKeyHex = bytesToHex(acceptorBytes);
    const connIdHex = bytesToHex(connIdBytes);
    const maps = this._getMaps(isV2);
    const pending = maps.pending.get(connIdHex);
    if (!pending) {
      this._closeWithError(ws, "invalid_request");
      return;
    }
    if (pending.att.keyHex !== acceptorKeyHex || (isV2 && pending.att.epoch !== epoch)) {
      this._closeWithError(ws, "unauthorized");
      return;
    }
    if ((maps.activeCounts.get(acceptorKeyHex) ?? 0) >= this.config.maxActivePerMailbox) {
      this._closeWithError(ws, "rate_limited");
      return;
    }

    maps.pending.delete(connIdHex);
    this._decCount(maps.pendingCounts, acceptorKeyHex);

    const binaryInject = pending.att.hasStoredInit
      ? this._takeInitFrame(pending.att.dialId)
      : null;

    this._bridgeSockets(
      isV2,
      acceptorKeyHex,
      msg.conn_id,
      pending.ws,
      pending.att,
      ws,
      att,
      pending.att.mailboxFastOpen ? null : binaryInject,
      true,
    );
  }

  _bridgeSockets(
    isV2,
    keyHex,
    connIdB64,
    dialerWs,
    dialerAttPrev,
    acceptorWs,
    acceptorAttPrev,
    binaryInject,
    sendAcceptorReady,
  ) {
    const readyMsg = { op: "ready", conn_id: connIdB64 };
    if (sendAcceptorReady && !this._sendJson(acceptorWs, readyMsg)) {
      this._cleanupSocket(acceptorWs, 1001, "ready delivery failed");
      this._safeClose(acceptorWs, 1001, "ready delivery failed");
      this._closeWithError(dialerWs, "offline");
      return;
    }

    const bridgeId = this._allocId();
    const nowMs = this._now();

    this.awaitingCmd.delete(dialerWs);
    this.awaitingCmd.delete(acceptorWs);

    const dialerAtt = {
      state: "bridged",
      isV2,
      ip: dialerAttPrev.ip,
      keyHex,
      bridgeId,
      role: "dialer",
      lastActivityMs: nowMs,
      persistedActivityMs: nowMs,
    };
    const acceptorAtt = {
      state: "bridged",
      isV2,
      ip: acceptorAttPrev.ip,
      keyHex,
      bridgeId,
      role: "acceptor",
      lastActivityMs: nowMs,
      persistedActivityMs: nowMs,
    };

    this._setAttachment(dialerWs, dialerAtt);
    this._setAttachment(acceptorWs, acceptorAtt);

    const maps = this._getMaps(isV2);
    this._incCount(maps.activeCounts, keyHex);
    this.bridges.set(bridgeId, {
      bridgeId,
      isV2,
      keyHex,
      dialerWs,
      acceptorWs,
      dialerAtt,
      acceptorAtt,
      lastActivityMs: nowMs,
    });

    if (!this._sendJson(dialerWs, readyMsg)) {
      this._cleanupSocket(dialerWs, 1001, "ready delivery failed");
      this._safeClose(dialerWs, 1001, "ready delivery failed");
      return;
    }

    if (binaryInject !== null && binaryInject.byteLength > 0) {
      try {
        acceptorWs.send(binaryInject);
      } catch {
        this._cleanupSocket(acceptorWs, 1001, "init_frame inject failed");
        this._safeClose(acceptorWs, 1001, "init_frame inject failed");
      }
    }
  }

  async webSocketClose(ws) {
    await this.ready;
    this._cleanupSocket(ws);
    await this._rescheduleAlarm();
  }

  async webSocketError(ws) {
    await this.ready;
    this._cleanupSocket(ws, 1011, "websocket error");
    await this._rescheduleAlarm();
  }

  async alarm() {
    await this.ready;
    this.scheduledAlarmMs = null;
    const nowMs = this._now();

    for (const [ws, deadlineMs] of Array.from(this.awaitingCmd.entries())) {
      if (deadlineMs !== undefined && nowMs >= deadlineMs) {
        this._closeWithError(ws, "timeout");
      }
    }

    for (const entry of [...this.v1Pending.values(), ...this.v2Pending.values()]) {
      if (nowMs >= entry.att.deadlineMs) {
        this._closeWithError(entry.ws, "timeout");
      }
    }

    for (const entry of Array.from(this.v2Mailboxes.values())) {
      if (typeof entry.att.expiryMs === "number" && nowMs >= entry.att.expiryMs) {
        this._cleanupSocket(entry.ws);
        this._safeClose(entry.ws, 1000, "epoch expired");
      }
    }

    for (const pool of Array.from(this.v2Standby.values())) {
      for (const slot of Array.from(pool)) {
        if (typeof slot.att.expiryMs === "number" && nowMs >= slot.att.expiryMs) {
          this._cleanupSocket(slot.ws);
          this._safeClose(slot.ws, 1000, "epoch expired");
        }
      }
    }

    for (const bridge of Array.from(this.bridges.values())) {
      if (nowMs - bridge.lastActivityMs >= this.config.idleTimeoutMs) {
        this._cleanupSocket(bridge.dialerWs, 1000, "idle timeout");
        this._safeClose(bridge.dialerWs, 1000, "idle timeout");
      }
    }

    await this._rescheduleAlarm();
  }
}
