// Browser WebSocket relay client implementing spec/relay-v1.md and /v2/relay dialer framing.

import {
  canonical_relay_host,
  compute_relay_auth_hmac_b64,
  v2_epoch_within_skew,
} from "../pkg/tendril_wasm.js";
import { redactHint } from "./redact.js";

export const MAX_RELAY_FRAME_LEN = 65521;
export const MAX_QUEUED_BYTES = 16 * MAX_RELAY_FRAME_LEN;
export const MAX_QUEUED_FRAMES = 256;

const relayTextEncoder = new TextEncoder();

function stripHostBrackets(host) {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function normalizeRelayHostInput(host) {
  if (typeof host !== "string") {
    throw new Error("relay host must be a string");
  }
  const trimmed = host.trim();
  if (trimmed.includes(":") && !trimmed.startsWith("[") && !trimmed.endsWith("]")) {
    return `[${trimmed}]`;
  }
  return trimmed;
}

function canonicalizeHostForCompare(host) {
  return canonical_relay_host(normalizeRelayHostInput(host));
}

function parseIpv4Octets(host) {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets = [];
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const val = Number(part);
    if (val > 255) return null;
    octets.push(val);
  }
  return octets;
}

function parseIpv6Words(host) {
  if (!host.includes(":")) return null;
  const zoneIdx = host.indexOf("%");
  const clean = zoneIdx >= 0 ? host.slice(0, zoneIdx) : host;
  const halves = clean.split("::");
  if (halves.length > 2) return null;

  const parseSide = (side, allowTrailingV4) => {
    if (!side) return [];
    const tokens = side.split(":");
    const words = [];
    for (let i = 0; i < tokens.length; i += 1) {
      const tok = tokens[i];
      if (!tok) return null;
      if (tok.includes(".")) {
        if (!allowTrailingV4 || i !== tokens.length - 1) return null;
        const v4 = parseIpv4Octets(tok);
        if (!v4) return null;
        words.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(tok)) return null;
        words.push(parseInt(tok, 16));
      }
    }
    return words;
  };

  if (halves.length === 1) {
    const words = parseSide(halves[0], true);
    return words && words.length === 8 ? words : null;
  }
  const left = parseSide(halves[0], halves[1] === "");
  const right = parseSide(halves[1], true);
  if (!left || !right) return null;
  const missing = 8 - (left.length + right.length);
  if (missing < 1) return null;
  return [...left, ...new Array(missing).fill(0), ...right];
}

function extractMappedIpv4(words) {
  if (
    words[0] === 0 &&
    words[1] === 0 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0xffff
  ) {
    return [words[6] >> 8, words[6] & 0xff, words[7] >> 8, words[7] & 0xff];
  }
  return null;
}

function isIpv4MetadataOrLinkLocal(v4) {
  return (v4[0] === 169 && v4[1] === 254) || (v4[0] === 0 && v4[1] === 0 && v4[2] === 0 && v4[3] === 0);
}

function isMetadataOrLinkLocalHost(host) {
  const bare = stripHostBrackets(host).replace(/\.+$/, "");
  if (bare.toLowerCase() === "metadata.google.internal") {
    return true;
  }
  const v4 = parseIpv4Octets(bare);
  if (v4) {
    return isIpv4MetadataOrLinkLocal(v4);
  }
  const v6 = parseIpv6Words(bare);
  if (v6) {
    const mapped = extractMappedIpv4(v6);
    if (mapped) {
      return isIpv4MetadataOrLinkLocal(mapped);
    }
    if (v6.every((w) => w === 0)) return true;
    if ((v6[0] & 0xffc0) === 0xfe80) return true;
    if (
      v6[0] === 0xfd00 &&
      v6[1] === 0x0ec2 &&
      v6[2] === 0 &&
      v6[3] === 0 &&
      v6[4] === 0 &&
      v6[5] === 0 &&
      v6[6] === 0 &&
      v6[7] === 0x0254
    ) {
      return true;
    }
  }
  return false;
}

export function isLoopbackHost(host) {
  if (typeof host !== "string" || !host) return false;
  const bare = stripHostBrackets(host).replace(/\.+$/, "");
  const v4 = parseIpv4Octets(bare);
  if (v4) {
    return v4[0] === 127;
  }
  const v6 = parseIpv6Words(bare);
  if (v6) {
    const mapped = extractMappedIpv4(v6);
    if (mapped) {
      return mapped[0] === 127;
    }
    return (
      v6[0] === 0 &&
      v6[1] === 0 &&
      v6[2] === 0 &&
      v6[3] === 0 &&
      v6[4] === 0 &&
      v6[5] === 0 &&
      v6[6] === 0 &&
      v6[7] === 1
    );
  }
  const lower = bare.toLowerCase();
  return lower === "localhost" || lower.endsWith(".localhost");
}

export function validateRelayWsUrl(relayUrl, allowInsecureWs = false) {
  if (typeof relayUrl !== "string") {
    throw new Error("relayUrl must be a string");
  }
  for (let i = 0; i < relayUrl.length; i += 1) {
    const code = relayUrl.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      throw new Error("relayUrl contains control characters");
    }
  }
  const trimmed = relayUrl.trim();
  if (!trimmed) {
    throw new Error("relayUrl must not be empty");
  }
  if (trimmed.includes("#")) {
    throw new Error("relayUrl fragments are not permitted");
  }
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`invalid relayUrl '${redactHint(relayUrl)}'`);
  }
  if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") {
    throw new Error(`relayUrl must use ws:// or wss://: ${redactHint(relayUrl)}`);
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new Error("relayUrl userinfo credentials are not permitted");
  }
  const host = parsed.hostname;
  const bareHost = stripHostBrackets(host);
  if (!bareHost) {
    throw new Error("relayUrl is missing a hostname");
  }
  if (isMetadataOrLinkLocalHost(bareHost)) {
    throw new Error(`relayUrl link-local or metadata host '${bareHost}' is not permitted`);
  }
  if (parsed.protocol === "ws:" && !allowInsecureWs && !isLoopbackHost(bareHost)) {
    throw new Error("cleartext ws:// relayUrl requires allowInsecureWs: true outside loopback");
  }
  return { url: parsed.toString(), bareHost, host };
}

export function validateBrokerWsUrl(brokerUrl, allowInsecureWs = false) {
  if (typeof brokerUrl !== "string") {
    throw new Error("brokerUrl must be a string");
  }
  for (let i = 0; i < brokerUrl.length; i += 1) {
    const code = brokerUrl.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      throw new Error("brokerUrl contains control characters");
    }
  }
  const trimmed = brokerUrl.trim();
  const target = /^broker\+/i.test(trimmed) ? trimmed.slice(7) : trimmed;
  if (/^broker\+/i.test(trimmed) && !/^wss?:\/\//i.test(target)) {
    throw new Error(`brokerUrl must use broker+ws(s):// or ws(s)://: ${redactHint(brokerUrl)}`);
  }
  return validateRelayWsUrl(target, allowInsecureWs);
}

function abortError(signal) {
  if (signal?.reason instanceof Error) {
    return signal.reason;
  }
  const err = new Error("dial aborted");
  err.name = "AbortError";
  return err;
}

function waitForWsOpen(ws, canonicalUrl, label, timeoutMs, signal = null) {
  if (signal?.aborted) {
    return Promise.reject(abortError(signal));
  }
  if (ws.readyState === WebSocket.OPEN) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;
    const cleanup = () => {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      ws.removeEventListener("open", onOpen);
      ws.removeEventListener("error", onErr);
      ws.removeEventListener("close", onClose);
      signal?.removeEventListener("abort", onAbort);
    };
    const finish = (err) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    };
    const onOpen = () => finish(null);
    const onErr = () => finish(new Error(`failed connecting to ${label} ${redactHint(canonicalUrl)}`));
    const onClose = () => finish(new Error(`${label} WebSocket closed before open`));
    const onAbort = () => finish(abortError(signal));
    timer = setTimeout(() => {
      finish(new Error(`${label} WebSocket open timed out`));
    }, timeoutMs);
    ws.addEventListener("open", onOpen, { once: true });
    ws.addEventListener("error", onErr, { once: true });
    ws.addEventListener("close", onClose, { once: true });
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function randomConnIdB64() {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  let bin = "";
  for (let i = 0; i < buf.length; i += 1) {
    bin += String.fromCharCode(buf[i]);
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export class RelayStream {
  #ws;
  #queue = [];
  #queuedBytes = 0;
  #maxQueuedBytes;
  #maxQueuedFrames;
  #waiters = [];
  #eof = false;
  #closed = false;
  #error = null;
  #maxFrame = MAX_RELAY_FRAME_LEN;
  #fastOpenSent = false;

  constructor(ws, maxQueuedBytes = MAX_QUEUED_BYTES, maxQueuedFrames = MAX_QUEUED_FRAMES) {
    this.#ws = ws;
    this.#maxQueuedBytes = maxQueuedBytes;
    this.#maxQueuedFrames = maxQueuedFrames;
  }

  get fastOpenSent() {
    return this.#fastOpenSent;
  }

  _setFastOpenSent(sent) {
    this.#fastOpenSent = Boolean(sent);
  }

  maxFrame() {
    return this.#maxFrame;
  }

  _setMaxFrame(maxFrame) {
    if (!Number.isInteger(maxFrame) || maxFrame < MAX_RELAY_FRAME_LEN) {
      throw new Error(`relay max_frame ${maxFrame} below required ${MAX_RELAY_FRAME_LEN}`);
    }
    this.#maxFrame = MAX_RELAY_FRAME_LEN;
  }

  _shiftFrame() {
    const frame = this.#queue.shift();
    if (frame) {
      this.#queuedBytes = Math.max(0, this.#queuedBytes - frame.byteLength);
    }
    return frame;
  }

  _pushFrame(bytes) {
    if (this.#closed || this.#eof || this.#error) {
      return;
    }
    if (bytes.byteLength === 0) {
      this.#queue = [];
      this.#queuedBytes = 0;
      this._fail(new Error("empty relay binary frame"));
      try {
        this.#ws.close(1002, "empty binary frame");
      } catch {}
      return;
    }
    if (bytes.byteLength > this.#maxFrame) {
      this.#queue = [];
      this.#queuedBytes = 0;
      this._fail(new Error(`relay frame exceeded ${this.#maxFrame} bytes`));
      try {
        this.#ws.close(1009, "frame too large");
      } catch {}
      return;
    }
    if (
      this.#queue.length >= this.#maxQueuedFrames ||
      this.#queuedBytes + bytes.byteLength > this.#maxQueuedBytes
    ) {
      this.#queue = [];
      this.#queuedBytes = 0;
      this._fail(
        new Error(
          `relay receive queue exceeded ${this.#maxQueuedBytes} bytes / ${this.#maxQueuedFrames} frames`
        )
      );
      try {
        this.#ws.close(1008, "receive queue overflow");
      } catch {}
      return;
    }
    this.#queue.push(bytes);
    this.#queuedBytes += bytes.byteLength;
    this._wakeNext();
  }

  _fail(err) {
    if (!this.#error && !this.#eof) {
      this.#error = err;
      this._wakeAll();
    }
  }

  _close() {
    if (!this.#eof) {
      this.#eof = true;
      this._wakeAll();
    }
  }

  _wakeNext() {
    if (this.#waiters.length > 0 && this.#queue.length > 0) {
      const w = this.#waiters.shift();
      w.resolve({ status: "data", bytes: this._shiftFrame() });
    }
  }

  _wakeAll() {
    while (this.#waiters.length > 0) {
      const w = this.#waiters.shift();
      if (this.#queue.length > 0) {
        w.resolve({ status: "data", bytes: this._shiftFrame() });
      } else if (this.#error) {
        w.reject(this.#error);
      } else {
        w.resolve({ status: "eof" });
      }
    }
  }

  send(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError("RelayStream.send expects Uint8Array");
    }
    if (bytes.byteLength > this.#maxFrame) {
      throw new RangeError(`relay frame exceeds ${this.#maxFrame} bytes`);
    }
    if (this.#ws.readyState !== WebSocket.OPEN) {
      throw new Error("relay WebSocket is not open");
    }
    this.#ws.send(bytes);
  }

  recv(timeoutMs = 5000) {
    if (this.#queue.length > 0) {
      return Promise.resolve({ status: "data", bytes: this._shiftFrame() });
    }
    if (this.#error) {
      return Promise.reject(this.#error);
    }
    if (this.#eof) {
      return Promise.resolve({ status: "eof" });
    }
    if (timeoutMs <= 0) {
      return Promise.resolve({ status: "would_block" });
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.#waiters.indexOf(waiter);
        if (idx >= 0) {
          this.#waiters.splice(idx, 1);
        }
        resolve({ status: "would_block" });
      }, timeoutMs);
      const waiter = {
        resolve: (val) => {
          clearTimeout(timer);
          resolve(val);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      };
      this.#waiters.push(waiter);
    });
  }

  close() {
    this.#closed = true;
    this.#queue = [];
    this.#queuedBytes = 0;
    this._close();
    try {
      if (
        this.#ws.readyState === WebSocket.OPEN ||
        this.#ws.readyState === WebSocket.CONNECTING
      ) {
        this.#ws.close(1000, "closed");
      }
    } catch {}
  }
}

function encodeB64url(buf) {
  let bin = "";
  for (let i = 0; i < buf.length; i += 1) {
    bin += String.fromCharCode(buf[i]);
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeB64url(str) {
  if (typeof str !== "string" || !str) {
    return new Uint8Array(0);
  }
  const pad = "=".repeat((4 - (str.length % 4)) % 4);
  const b64 = (str + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function randomConnIdBytes() {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return buf;
}

function validateRelayAuthSecretInput(relayAuthSecret) {
  if (relayAuthSecret === null || relayAuthSecret === undefined) {
    return;
  }
  if (relayAuthSecret instanceof Uint8Array) {
    if (relayAuthSecret.length === 0 || relayAuthSecret.every((b) => b === 0)) {
      throw new Error("relayAuthSecret must not be empty or all-zero");
    }
    return;
  }
  if (typeof relayAuthSecret === "string") {
    if (relayAuthSecret.length === 0) {
      throw new Error("relayAuthSecret must not be empty");
    }
    return;
  }
  throw new TypeError("relayAuthSecret must be a Uint8Array or string");
}

function buildRelayDialAuth({ relayAuthTicket, relayAuthSecret, challenge, targetBytes }) {
  const authRequired =
    Array.isArray(challenge.auth_required) && challenge.auth_required.includes("dial");
  if (!authRequired) {
    return null;
  }
  if (relayAuthTicket !== null && relayAuthTicket !== undefined) {
    const ticket =
      typeof relayAuthTicket === "string" ? JSON.parse(relayAuthTicket) : relayAuthTicket;
    if (!ticket || typeof ticket !== "object") {
      throw new Error("relayAuthTicket must be a JSON string or ticket object");
    }
    return { kind: "ticket", ticket };
  }
  if (relayAuthSecret !== null && relayAuthSecret !== undefined) {
    let secretBytes;
    if (relayAuthSecret instanceof Uint8Array) {
      secretBytes = relayAuthSecret;
    } else if (typeof relayAuthSecret === "string") {
      secretBytes = relayTextEncoder.encode(relayAuthSecret);
    } else {
      throw new TypeError("relayAuthSecret must be a Uint8Array or string");
    }
    try {
      const nonceBytes = decodeB64url(challenge.nonce);
      const mac = compute_relay_auth_hmac_b64(
        secretBytes,
        "dial",
        challenge.host,
        nonceBytes,
        targetBytes
      );
      return { kind: "hmac", mac };
    } finally {
      secretBytes.fill(0);
    }
  }
  throw new Error("relay requires dial authentication (relayAuthTicket or relayAuthSecret)");
}

async function openRelayHandshake({
  relayUrl,
  expectedHost = null,
  allowInsecureWs = false,
  timeoutMs = 15000,
  signal = null,
  buildDialMsg,
}) {
  if (signal?.aborted) {
    throw abortError(signal);
  }
  const { url: canonicalUrl, host: urlHost } = validateRelayWsUrl(relayUrl, allowInsecureWs);
  const expHost = canonicalizeHostForCompare(expectedHost || urlHost);

  const ws = new WebSocket(canonicalUrl);
  ws.binaryType = "arraybuffer";
  const stream = new RelayStream(ws);

  const ctrlQueue = [];
  const ctrlWaiters = [];
  let ctrlErr = null;
  let ready = false;

  const wakeCtrl = () => {
    while (ctrlWaiters.length > 0 && (ctrlQueue.length > 0 || ctrlErr)) {
      const w = ctrlWaiters.shift();
      if (ctrlErr) {
        w.reject(ctrlErr);
      } else {
        w.resolve(ctrlQueue.shift());
      }
    }
  };

  const failCtrl = (err) => {
    if (!ctrlErr) {
      ctrlErr = err;
    }
    wakeCtrl();
    stream._fail(err);
    try {
      ws.close(1002, "protocol error");
    } catch {}
  };

  const onAbort = () => {
    if (!ready) {
      failCtrl(abortError(signal));
    }
  };
  signal?.addEventListener("abort", onAbort, { once: true });

  ws.addEventListener("message", (ev) => {
    if (!ready) {
      if (typeof ev.data !== "string") {
        failCtrl(new Error("expected text control frame before relay ready"));
        return;
      }
      if (ev.data.length > 65536 || ctrlQueue.length >= 16) {
        failCtrl(new Error("relay control frame limit exceeded"));
        return;
      }
      try {
        ctrlQueue.push(JSON.parse(ev.data));
        wakeCtrl();
      } catch (e) {
        failCtrl(new Error(`invalid relay control json: ${e.message}`));
      }
      return;
    }

    if (typeof ev.data === "string") {
      stream._fail(new Error("unexpected text frame after relay ready"));
      try {
        ws.close(1002, "unexpected text frame");
      } catch {}
      return;
    }
    if (ev.data instanceof ArrayBuffer) {
      stream._pushFrame(new Uint8Array(ev.data));
    } else if (ev.data instanceof Blob) {
      ev.data
        .arrayBuffer()
        .then((buf) => stream._pushFrame(new Uint8Array(buf)))
        .catch((err) => stream._fail(err));
    } else {
      stream._fail(new Error("unsupported WebSocket frame payload"));
    }
  });

  ws.addEventListener("error", () => {
    const err = new Error(`relay WebSocket error (${redactHint(canonicalUrl)})`);
    if (!ready) {
      failCtrl(err);
    } else {
      stream._fail(err);
    }
  });

  ws.addEventListener("close", () => {
    if (!ready && !ctrlErr) {
      ctrlErr = new Error("relay WebSocket closed before ready");
      wakeCtrl();
    }
    stream._close();
  });

  const nextControl = () => {
    if (ctrlQueue.length > 0) {
      return Promise.resolve(ctrlQueue.shift());
    }
    if (ctrlErr) {
      return Promise.reject(ctrlErr);
    }
    if (signal?.aborted) {
      return Promise.reject(abortError(signal));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = ctrlWaiters.indexOf(w);
        if (idx >= 0) {
          ctrlWaiters.splice(idx, 1);
        }
        reject(new Error("relay control handshake timed out"));
      }, timeoutMs);
      const w = {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      };
      ctrlWaiters.push(w);
    });
  };

  try {
    await waitForWsOpen(ws, canonicalUrl, "relay", timeoutMs, signal);

    const challenge = await nextControl();
    if (!challenge || challenge.op !== "challenge") {
      throw new Error(`expected relay challenge, got ${JSON.stringify(challenge)}`);
    }
    if (typeof challenge.host !== "string") {
      throw new Error("relay challenge missing host");
    }
    let challengeHost;
    try {
      challengeHost = canonicalizeHostForCompare(challenge.host);
    } catch (err) {
      throw new Error(`invalid relay challenge host '${challenge.host}': ${err.message || err}`);
    }
    if (challengeHost !== expHost) {
      throw new Error(
        `relay challenge host mismatch: expected '${expHost}', got '${challengeHost}'`
      );
    }
    if (challenge.max_frame !== undefined) {
      stream._setMaxFrame(challenge.max_frame);
    }

    const { connId, payload, fastOpenSent = false } = await buildDialMsg(challenge);
    if (signal?.aborted) {
      throw abortError(signal);
    }
    ws.send(JSON.stringify(payload));

    const reply = await nextControl();
    if (!reply) {
      throw new Error("missing relay dial response");
    }
    if (reply.op === "error") {
      throw new Error(`relay error: ${reply.code}`);
    }
    if (reply.op !== "ready" || reply.conn_id !== connId) {
      throw new Error(`unexpected relay ready frame: ${JSON.stringify(reply)}`);
    }
    stream._setFastOpenSent(fastOpenSent);
    ready = true;
    return stream;
  } catch (err) {
    stream.close();
    throw err;
  } finally {
    signal?.removeEventListener("abort", onAbort);
  }
}

export async function dialBrokerStream(urlOrOpts, maybeOpts = {}) {
  let rawUrl;
  let opts;
  if (typeof urlOrOpts === "string") {
    rawUrl = urlOrOpts;
    opts = maybeOpts ?? {};
  } else if (urlOrOpts && typeof urlOrOpts === "object") {
    opts = urlOrOpts;
    rawUrl = opts.brokerUrl ?? opts.url ?? opts.endpoint;
  } else {
    throw new TypeError("dialBrokerStream requires a broker URL or options object");
  }
  const { allowInsecureWs = false, timeoutMs = 15000, signal = null } = opts;
  if (signal?.aborted) {
    throw abortError(signal);
  }
  const { url: canonicalUrl } = validateBrokerWsUrl(rawUrl, allowInsecureWs);
  const ws = new WebSocket(canonicalUrl);
  ws.binaryType = "arraybuffer";
  const stream = new RelayStream(ws);

  let opened = false;
  ws.addEventListener("message", (ev) => {
    if (typeof ev.data === "string") {
      stream._fail(new Error("unexpected text frame on broker stream"));
      try {
        ws.close(1002, "unexpected text frame");
      } catch {}
      return;
    }
    if (ev.data instanceof ArrayBuffer) {
      stream._pushFrame(new Uint8Array(ev.data));
    } else if (ev.data instanceof Blob) {
      ev.data
        .arrayBuffer()
        .then((buf) => stream._pushFrame(new Uint8Array(buf)))
        .catch((err) => stream._fail(err));
    } else {
      stream._fail(new Error("unsupported WebSocket frame payload"));
    }
  });
  ws.addEventListener("error", () => {
    if (opened) {
      stream._fail(new Error(`broker WebSocket error (${redactHint(canonicalUrl)})`));
    }
  });
  ws.addEventListener("close", () => {
    stream._close();
  });

  try {
    await waitForWsOpen(ws, canonicalUrl, "broker", timeoutMs, signal);
    opened = true;
    return stream;
  } catch (err) {
    stream.close();
    throw err;
  }
}

function validateFastOpenInitFrame(initFrame) {
  if (initFrame === null || initFrame === undefined) {
    return null;
  }
  if (!(initFrame instanceof Uint8Array)) {
    throw new TypeError("initFrame must be a Uint8Array");
  }
  if (initFrame.byteLength === 0 || initFrame.byteLength > MAX_RELAY_FRAME_LEN) {
    throw new RangeError(
      `initFrame length ${initFrame.byteLength} must be within 1..=${MAX_RELAY_FRAME_LEN}`
    );
  }
  return initFrame;
}

function applyFastOpenInitFrame(payload, initBytes, challenge) {
  const fastOpenSent = Boolean(initBytes && challenge?.fast_open === true);
  if (fastOpenSent) {
    payload.init_frame = encodeB64url(initBytes);
  }
  return fastOpenSent;
}

export async function dialRelayStream({
  relayUrl,
  targetPub,
  expectedHost = null,
  allowInsecureWs = false,
  relayAuthTicket = null,
  relayAuthSecret = null,
  initFrame = null,
  timeoutMs = 15000,
  signal = null,
}) {
  try {
    validateRelayAuthSecretInput(relayAuthSecret);
    const validatedInit = validateFastOpenInitFrame(initFrame);
    if (!targetPub) {
      throw new Error("targetPub is required for relay dial");
    }
    const targetBytes = decodeB64url(targetPub);
    return await openRelayHandshake({
      relayUrl,
      expectedHost,
      allowInsecureWs,
      timeoutMs,
      signal,
      buildDialMsg: (challenge) => {
        const connId = encodeB64url(randomConnIdBytes());
        const auth = buildRelayDialAuth({
          relayAuthTicket,
          relayAuthSecret,
          challenge,
          targetBytes,
        });
        const payload = { op: "dial", target_pub: targetPub, conn_id: connId };
        if (auth) {
          payload.auth = auth;
        }
        const fastOpenSent = applyFastOpenInitFrame(payload, validatedInit, challenge);
        return { connId, payload, fastOpenSent };
      },
    });
  } finally {
    if (relayAuthSecret instanceof Uint8Array) {
      relayAuthSecret.fill(0);
    }
  }
}

export async function dialRelayV2Stream({
  relayUrl,
  deriveV2Dial = null,
  expectedHost = null,
  allowInsecureWs = false,
  relayAuthTicket = null,
  relayAuthSecret = null,
  initFrame = null,
  timeoutMs = 15000,
  signal = null,
}) {
  try {
    validateRelayAuthSecretInput(relayAuthSecret);
    const validatedInit = validateFastOpenInitFrame(initFrame);
    if (typeof deriveV2Dial !== "function") {
      throw new Error(
        "dialRelayV2Stream requires a deriveV2Dial callback (dial_token binds server nonce and per-dial conn_id)"
      );
    }
    return await openRelayHandshake({
      relayUrl,
      expectedHost,
      allowInsecureWs,
      timeoutMs,
      signal,
      buildDialMsg: async (challenge) => {
        if (!Number.isInteger(challenge.epoch) || challenge.epoch < 0) {
          throw new Error(`invalid /v2/relay challenge epoch: ${challenge.epoch}`);
        }
        const connIdBytes = randomConnIdBytes();
        const connId = encodeB64url(connIdBytes);
        const derived = await deriveV2Dial({
          relayHost: challenge.host,
          nonceBytes: decodeB64url(challenge.nonce),
          connIdBytes,
          connId,
          serverEpoch: challenge.epoch,
        });
        const mailboxId = derived.mailbox_id;
        const dialEpoch = derived.epoch;
        const token = derived.dial_token;
        if (!v2_epoch_within_skew(challenge.epoch, dialEpoch)) {
          throw new Error(
            `relay v2 epoch out of skew: server=${challenge.epoch}, client=${dialEpoch}`
          );
        }
        const targetBytes = decodeB64url(mailboxId);
        const auth = buildRelayDialAuth({
          relayAuthTicket,
          relayAuthSecret,
          challenge,
          targetBytes,
        });
        const payload = {
          op: "dial",
          target_mailbox_id: mailboxId,
          epoch: dialEpoch,
          conn_id: connId,
          dial_token: token,
        };
        if (auth) {
          payload.auth = auth;
        }
        const fastOpenSent = applyFastOpenInitFrame(payload, validatedInit, challenge);
        return { connId, payload, fastOpenSent };
      },
    });
  } finally {
    if (relayAuthSecret instanceof Uint8Array) {
      relayAuthSecret.fill(0);
    }
  }
}
