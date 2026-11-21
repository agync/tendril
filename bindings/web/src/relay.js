// Browser WebSocket relay client implementing spec/relay-v1.md dialer framing.

export const MAX_RELAY_FRAME_LEN = 65521;
export const MAX_QUEUED_BYTES = 16 * MAX_RELAY_FRAME_LEN;
export const MAX_QUEUED_FRAMES = 256;

function stripHostBrackets(host) {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
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
  } catch (err) {
    throw new Error(`invalid relayUrl '${relayUrl}': ${err.message}`);
  }
  if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") {
    throw new Error(`relayUrl must use ws:// or wss://: ${relayUrl}`);
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new Error("relayUrl userinfo credentials are not permitted");
  }
  const bareHost = stripHostBrackets(parsed.hostname);
  if (!bareHost) {
    throw new Error("relayUrl is missing a hostname");
  }
  if (isMetadataOrLinkLocalHost(bareHost)) {
    throw new Error(`relayUrl link-local or metadata host '${bareHost}' is not permitted`);
  }
  if (parsed.protocol === "ws:" && !allowInsecureWs && !isLoopbackHost(bareHost)) {
    throw new Error("cleartext ws:// relayUrl requires allowInsecureWs: true outside loopback");
  }
  return { url: parsed.toString(), bareHost };
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

  constructor(ws, maxQueuedBytes = MAX_QUEUED_BYTES, maxQueuedFrames = MAX_QUEUED_FRAMES) {
    this.#ws = ws;
    this.#maxQueuedBytes = maxQueuedBytes;
    this.#maxQueuedFrames = maxQueuedFrames;
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

export async function dialRelayStream({
  relayUrl,
  targetPub,
  expectedHost = null,
  allowInsecureWs = false,
  timeoutMs = 15000,
}) {
  const { url: canonicalUrl, bareHost } = validateRelayWsUrl(relayUrl, allowInsecureWs);
  const expHost = expectedHost || bareHost;
  if (!targetPub) {
    throw new Error("targetPub is required for relay dial");
  }

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
    const err = new Error(`relay WebSocket error (${canonicalUrl})`);
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
    await new Promise((resolve, reject) => {
      if (ws.readyState === WebSocket.OPEN) {
        resolve();
        return;
      }
      const timer = setTimeout(() => {
        reject(new Error("relay WebSocket open timed out"));
      }, timeoutMs);
      ws.addEventListener(
        "open",
        () => {
          clearTimeout(timer);
          resolve();
        },
        { once: true }
      );
      ws.addEventListener(
        "error",
        () => {
          clearTimeout(timer);
          reject(new Error(`failed connecting to relay ${canonicalUrl}`));
        },
        { once: true }
      );
    });

    const challenge = await nextControl();
    if (!challenge || challenge.op !== "challenge") {
      throw new Error(`expected relay challenge, got ${JSON.stringify(challenge)}`);
    }
    if (challenge.host !== expHost) {
      throw new Error(
        `relay challenge host mismatch: expected '${expHost}', got '${challenge.host}'`
      );
    }
    if (challenge.max_frame !== undefined) {
      stream._setMaxFrame(challenge.max_frame);
    }

    const connId = randomConnIdB64();
    ws.send(JSON.stringify({ op: "dial", target_pub: targetPub, conn_id: connId }));

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
    ready = true;
    return stream;
  } catch (err) {
    stream.close();
    throw err;
  }
}
