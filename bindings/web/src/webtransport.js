// Browser WebTransport (HTTP/3 over QUIC) direct transport stream (wt://).

import { redactHint } from "./redact.js";

export const MAX_WT_FRAME_LEN = 65521;
export const MAX_WT_QUEUED_BYTES = 16 * MAX_WT_FRAME_LEN;

const B64URL_43 = /^[A-Za-z0-9_-]{43}$/;

function makeAbortError(signal) {
  if (signal?.reason instanceof Error) {
    return signal.reason;
  }
  const err = new Error("dial aborted");
  err.name = "AbortError";
  return err;
}

function stripBrackets(host) {
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

function unwrapEmbeddedV4(words) {
  const tail = () => [words[6] >> 8, words[6] & 0xff, words[7] >> 8, words[7] & 0xff];
  if (
    words[0] === 0 &&
    words[1] === 0 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0xffff
  ) {
    return tail();
  }
  if (
    words[0] === 0 &&
    words[1] === 0 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0xffff &&
    words[5] === 0
  ) {
    return tail();
  }
  if (
    words[0] === 0x0064 &&
    words[1] === 0xff9b &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0
  ) {
    return tail();
  }
  if (
    words[0] === 0 &&
    words[1] === 0 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0 &&
    (words[6] !== 0 || words[7] > 1)
  ) {
    return tail();
  }
  if (words[0] === 0x2002) {
    return [words[1] >> 8, words[1] & 0xff, words[2] >> 8, words[2] & 0xff];
  }
  return null;
}

function isBlockedHost(host) {
  const bare = stripBrackets(host).replace(/\.+$/, "");
  if (bare.toLowerCase() === "metadata.google.internal") {
    return true;
  }
  const v4 = parseIpv4Octets(bare);
  if (v4) {
    return (
      v4[0] === 0 ||
      v4[0] >= 224 ||
      (v4[0] === 169 && v4[1] === 254)
    );
  }
  const v6 = parseIpv6Words(bare);
  if (v6) {
    const emb = unwrapEmbeddedV4(v6);
    if (emb) {
      return emb[0] === 0 || emb[0] >= 224 || (emb[0] === 169 && emb[1] === 254);
    }
    if (v6.every((w) => w === 0)) return true;
    if ((v6[0] & 0xff00) === 0xff00) return true;
    if ((v6[0] & 0xffc0) === 0xfe80) return true;
    if ((v6[0] & 0xffc0) === 0xfec0) return true;
    if (v6[0] === 0x0064 && v6[1] === 0xff9b && v6[2] === 0x0001) return true;
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

function isLanOrLoopbackHost(host) {
  const bare = stripBrackets(host).replace(/\.+$/, "");
  const v4 = parseIpv4Octets(bare);
  if (v4) {
    return (
      v4[0] === 127 ||
      v4[0] === 10 ||
      (v4[0] === 172 && v4[1] >= 16 && v4[1] <= 31) ||
      (v4[0] === 192 && v4[1] === 168)
    );
  }
  const v6 = parseIpv6Words(bare);
  if (v6) {
    const emb = unwrapEmbeddedV4(v6);
    if (emb) {
      return (
        emb[0] === 127 ||
        emb[0] === 10 ||
        (emb[0] === 172 && emb[1] >= 16 && emb[1] <= 31) ||
        (emb[0] === 192 && emb[1] === 168)
      );
    }
    if (
      v6[0] === 0 &&
      v6[1] === 0 &&
      v6[2] === 0 &&
      v6[3] === 0 &&
      v6[4] === 0 &&
      v6[5] === 0 &&
      v6[6] === 0 &&
      v6[7] === 1
    ) {
      return true;
    }
    return (v6[0] & 0xfe00) === 0xfc00;
  }
  return false;
}

function decodeCerthashB64url(val) {
  if (typeof val !== "string" || !B64URL_43.test(val)) {
    throw new Error("invalid webtransport certhash");
  }
  const std = val.replace(/-/g, "+").replace(/_/g, "/") + "=";
  const bin = atob(std);
  if (bin.length !== 32) {
    throw new Error("invalid webtransport certhash length");
  }
  // Ensure canonical trailing zero bits on the 43rd base64url sextet (258 - 256 = 2 pad bits).
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const lastIdx = alphabet.indexOf(val[42]);
  if (lastIdx < 0 || (lastIdx & 0x03) !== 0) {
    throw new Error("non-canonical webtransport certhash");
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

async function raceWithTimeout(promise, ms) {
  let timer = null;
  try {
    await Promise.race([
      Promise.resolve(promise).catch(() => {}),
      new Promise((resolve) => {
        timer = setTimeout(resolve, ms);
      }),
    ]);
  } finally {
    if (timer !== null) {
      clearTimeout(timer);
    }
  }
}

export function validateWtUrl(endpoint) {
  if (typeof endpoint !== "string") {
    throw new Error("wt endpoint must be a string");
  }
  for (let i = 0; i < endpoint.length; i += 1) {
    const code = endpoint.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) {
      throw new Error("wt endpoint contains invalid whitespace or control characters");
    }
  }
  if (endpoint.includes("#") || endpoint.includes("@") || endpoint.includes("\\")) {
    throw new Error("wt endpoint contains disallowed characters");
  }
  if (!endpoint.startsWith("wt://")) {
    throw new Error(`wt endpoint must start with wt://: ${redactHint(endpoint)}`);
  }
  const rest = endpoint.slice(5);
  const authority = rest.split(/[/?]/)[0];
  if (!authority || authority.includes("%")) {
    throw new Error("wt endpoint authority is invalid");
  }
  let portStr = null;
  if (authority.startsWith("[")) {
    const closeIdx = authority.indexOf("]");
    if (closeIdx < 0 || authority[closeIdx + 1] !== ":") {
      throw new Error("wt endpoint requires an explicit non-zero port");
    }
    portStr = authority.slice(closeIdx + 2);
  } else {
    const colonIdx = authority.lastIndexOf(":");
    if (colonIdx <= 0 || authority.slice(0, colonIdx).includes(":")) {
      throw new Error("wt endpoint requires an explicit non-zero port");
    }
    portStr = authority.slice(colonIdx + 1);
  }
  if (!/^\d{1,5}$/.test(portStr)) {
    throw new Error("wt endpoint port is invalid");
  }
  const portNum = Number(portStr);
  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
    throw new Error("wt endpoint port must be in 1..=65535");
  }

  const qIdx = rest.indexOf("?");
  const baseRest = qIdx >= 0 ? rest.slice(0, qIdx) : rest;
  let certhashBytes = null;
  if (qIdx >= 0) {
    const query = rest.slice(qIdx + 1);
    if (!query.startsWith("certhash=")) {
      throw new Error("wt endpoint supports only a single certhash query parameter");
    }
    certhashBytes = decodeCerthashB64url(query.slice("certhash=".length));
  }

  let parsed;
  try {
    parsed = new URL(`https://${baseRest}`);
  } catch (err) {
    throw new Error(`invalid wt endpoint ${redactHint(endpoint)}: ${err.message}`);
  }
  if (parsed.username !== "" || parsed.password !== "" || !parsed.hostname) {
    throw new Error(`invalid wt endpoint ${redactHint(endpoint)}`);
  }
  const bareHost = stripBrackets(parsed.hostname);
  const trimmedHost = bareHost.replace(/\.+$/, "");
  if (!trimmedHost) {
    throw new Error(`invalid wt endpoint ${redactHint(endpoint)}`);
  }
  if (isBlockedHost(bareHost)) {
    const err = new Error(`blocked_address: wt host '${bareHost}' is not permitted`);
    err.blocked = true;
    throw err;
  }
  const canonicalAuthorityHost = bareHost.includes(":") ? `[${bareHost}]` : bareHost;
  const pathSuffix =
    parsed.pathname === "/" && !baseRest.slice(authority.length).startsWith("/")
      ? ""
      : parsed.pathname;
  const httpsUrl = `https://${canonicalAuthorityHost}:${portNum}${pathSuffix}`;

  return {
    httpsUrl,
    bareHost,
    port: portNum,
    certhashBytes,
    isLanOrLoopback: isLanOrLoopbackHost(bareHost),
  };
}

export class WtStream {
  #wt;
  #reader;
  #writer;
  #queue = [];
  #queuedBytes = 0;
  #drainWaiter = null;
  #waiters = [];
  #eof = false;
  #error = null;
  #closed = false;
  #closePromise = null;
  #writeChain = Promise.resolve();
  #readLoopPromise = null;

  constructor(wt, reader, writer) {
    this.#wt = wt;
    this.#reader = reader;
    this.#writer = writer;
    this.#readLoopPromise = this._runReadLoop();
  }

  get provider() {
    return "direct";
  }

  get fastOpenSent() {
    return false;
  }

  maxFrame() {
    return MAX_WT_FRAME_LEN;
  }

  _shiftChunk() {
    const chunk = this.#queue.shift();
    if (chunk) {
      this.#queuedBytes = Math.max(0, this.#queuedBytes - chunk.byteLength);
      if (this.#drainWaiter && this.#queuedBytes < MAX_WT_QUEUED_BYTES) {
        const wake = this.#drainWaiter;
        this.#drainWaiter = null;
        wake();
      }
    }
    return chunk;
  }

  _wakeDrain() {
    if (this.#drainWaiter) {
      const wake = this.#drainWaiter;
      this.#drainWaiter = null;
      wake();
    }
  }

  async _runReadLoop() {
    try {
      while (!this.#closed) {
        if (this.#queuedBytes >= MAX_WT_QUEUED_BYTES) {
          await new Promise((resolve) => {
            this.#drainWaiter = resolve;
          });
          continue;
        }
        const { value, done } = await this.#reader.read();
        if (done) {
          this._closeRead();
          break;
        }
        if (!value || value.byteLength === 0) {
          continue;
        }
        const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
        for (let off = 0; off < bytes.byteLength; ) {
          if (this.#closed) {
            break;
          }
          while (this.#queuedBytes >= MAX_WT_QUEUED_BYTES && !this.#closed) {
            await new Promise((resolve) => {
              this.#drainWaiter = resolve;
            });
          }
          if (this.#closed) {
            break;
          }
          const room = MAX_WT_QUEUED_BYTES - this.#queuedBytes;
          const take = Math.min(MAX_WT_FRAME_LEN, room, bytes.byteLength - off);
          const slice = bytes.slice(off, off + take);
          this.#queue.push(slice);
          this.#queuedBytes += slice.byteLength;
          off += take;
          this._wakeNext();
        }
      }
    } catch (err) {
      if (!this.#closed) {
        this._fail(err instanceof Error ? err : new Error(String(err)));
      } else {
        this._closeRead();
      }
    }
  }

  _fail(err) {
    if (!this.#error && !this.#eof) {
      this.#error = err;
      this._wakeAll();
    }
  }

  _closeRead() {
    if (!this.#eof) {
      this.#eof = true;
      this._wakeAll();
    }
  }

  _wakeNext() {
    if (this.#waiters.length > 0 && this.#queue.length > 0) {
      const w = this.#waiters.shift();
      w.resolve({ status: "data", bytes: this._shiftChunk() });
    }
  }

  _wakeAll() {
    while (this.#waiters.length > 0) {
      const w = this.#waiters.shift();
      if (this.#queue.length > 0) {
        w.resolve({ status: "data", bytes: this._shiftChunk() });
      } else if (this.#error) {
        w.reject(this.#error);
      } else {
        w.resolve({ status: "eof" });
      }
    }
  }

  async send(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError("WtStream.send expects Uint8Array");
    }
    if (bytes.byteLength > MAX_WT_FRAME_LEN) {
      throw new RangeError(`webtransport frame exceeds ${MAX_WT_FRAME_LEN} bytes`);
    }
    if (this.#closed) {
      throw new Error("webtransport stream is closed");
    }
    const copy = new Uint8Array(bytes);
    const job = this.#writeChain.then(() => {
      if (this.#closed) {
        throw new Error("webtransport stream is closed");
      }
      return this.#writer.write(copy);
    });
    this.#writeChain = job.catch(() => {});
    return job;
  }

  recv(timeoutMs = 5000) {
    if (this.#queue.length > 0) {
      return Promise.resolve({ status: "data", bytes: this._shiftChunk() });
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

  abort(reason) {
    const err = reason instanceof Error ? reason : new Error(String(reason || "aborted"));
    if (!this.#closed) {
      this.#closed = true;
      this.#queue.length = 0;
      this.#queuedBytes = 0;
      this._wakeDrain();
      this._fail(err);
      try {
        void Promise.resolve(this.#writer.abort(err)).catch(() => {});
      } catch {}
      try {
        void Promise.resolve(this.#reader.cancel(err)).catch(() => {});
      } catch {}
      try {
        this.#wt.close({ closeCode: 0, reason: "abort" });
      } catch {}
    }
  }

  close() {
    if (!this.#closePromise) {
      this.#closePromise = this._closeInternal();
    }
    return this.#closePromise;
  }

  async _closeInternal() {
    this.#closed = true;
    this.#queue.length = 0;
    this.#queuedBytes = 0;
    this._wakeDrain();
    this._closeRead();
    await raceWithTimeout(this.#writeChain, 150);
    await raceWithTimeout(this.#writer.close(), 150);
    await raceWithTimeout(this.#reader.cancel(), 150);
    try {
      this.#wt.close({ closeCode: 0, reason: "close" });
    } catch {}
    if (this.#readLoopPromise) {
      try {
        await this.#readLoopPromise;
      } catch {}
    }
  }
}

export async function dialWtStream(endpointOrOpts, maybeOpts = {}) {
  let endpoint;
  let opts;
  if (typeof endpointOrOpts === "string") {
    endpoint = endpointOrOpts;
    opts = maybeOpts ?? {};
  } else if (endpointOrOpts && typeof endpointOrOpts === "object") {
    opts = endpointOrOpts;
    endpoint = opts.endpoint ?? opts.url;
  } else {
    throw new TypeError("dialWtStream requires a wt:// endpoint string or options object");
  }

  const {
    timeoutMs = 15000,
    signal = null,
    webTransportImpl = globalThis.WebTransport,
  } = opts;

  if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError("dialWtStream timeoutMs must be a positive finite number");
  }
  if (signal?.aborted) {
    throw makeAbortError(signal);
  }
  if (typeof webTransportImpl !== "function") {
    throw new Error("WebTransport API is not available in this environment");
  }

  const { httpsUrl, certhashBytes } = validateWtUrl(endpoint);
  const wtOptions = certhashBytes
    ? { serverCertificateHashes: [{ algorithm: "sha-256", value: certhashBytes }] }
    : undefined;

  const wt = wtOptions ? new webTransportImpl(httpsUrl, wtOptions) : new webTransportImpl(httpsUrl);
  let settled = false;
  let timer = null;
  let onAbort = null;

  const cleanup = () => {
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
    if (signal && onAbort) {
      signal.removeEventListener("abort", onAbort);
    }
  };

  const abortClose = () => {
    settled = true;
    try {
      wt.close({ closeCode: 0, reason: "dial aborted" });
    } catch {}
  };

  const cancelHandles = (reader, writer) => {
    try {
      void Promise.resolve(writer?.abort()).catch(() => {});
    } catch {}
    try {
      void Promise.resolve(reader?.cancel()).catch(() => {});
    } catch {}
  };

  try {
    const connectPromise = (async () => {
      await wt.ready;
      if (settled) {
        throw new Error("webtransport dial aborted");
      }
      const bi = await wt.createBidirectionalStream();
      const reader = bi.readable.getReader();
      const writer = bi.writable.getWriter();
      if (settled) {
        cancelHandles(reader, writer);
        throw new Error("webtransport dial aborted");
      }
      return { reader, writer };
    })();
    connectPromise.then(
      ({ reader, writer }) => {
        if (settled) {
          cancelHandles(reader, writer);
        }
      },
      () => {}
    );
    connectPromise.catch(() => {});

    const timeoutPromise = new Promise((_, reject) => {
      timer = setTimeout(() => {
        if (!settled) {
          abortClose();
          reject(new Error(`webtransport dial timed out (${redactHint(endpoint)})`));
        }
      }, timeoutMs);
    });

    const racers = [connectPromise, timeoutPromise];
    if (signal) {
      racers.push(
        new Promise((_, reject) => {
          onAbort = () => {
            if (!settled) {
              abortClose();
              reject(makeAbortError(signal));
            }
          };
          if (signal.aborted) {
            onAbort();
          } else {
            signal.addEventListener("abort", onAbort, { once: true });
          }
        })
      );
    }

    const { reader, writer } = await Promise.race(racers);
    settled = true;
    return new WtStream(wt, reader, writer);
  } catch (err) {
    abortClose();
    throw err;
  } finally {
    cleanup();
  }
}
