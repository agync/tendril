const MAX_IROH_FRAME_LEN = 65521;
const MAX_QUEUED_BYTES = 16 * MAX_IROH_FRAME_LEN;

let p2pModule = null;
let p2pWasmReadyPromise = null;

async function ensureP2pModule() {
  if (!p2pModule) {
    p2pModule = await import("../pkg-p2p/tendril_wasm.js");
  }
  return p2pModule;
}

async function ensureP2pReady(wasmUrl) {
  if (!p2pWasmReadyPromise) {
    p2pWasmReadyPromise = ensureP2pModule()
      .then((mod) => mod.default(wasmUrl))
      .then(() => p2pModule)
      .catch((err) => {
        p2pWasmReadyPromise = null;
        throw err;
      });
  }
  return p2pWasmReadyPromise;
}

export async function initTendrilP2p(wasmUrl) {
  await ensureP2pReady(wasmUrl);
}

export async function parseP2pEndpoint(endpoint) {
  const mod = await ensureP2pReady();
  return JSON.parse(mod.parse_p2p_endpoint_json(endpoint));
}

class IrohStream {
  #inner;
  #queue = [];
  #queuedBytes = 0;
  #drainWaiter = null;
  #waiters = [];
  #eof = false;
  #error = null;
  #closed = false;
  #freed = false;
  #closePromise = null;
  #writeChain = Promise.resolve();
  #readLoopPromise = null;

  constructor(inner) {
    this.#inner = inner;
    this.#readLoopPromise = this._runReadLoop();
  }

  maxFrame() {
    return MAX_IROH_FRAME_LEN;
  }

  _shiftChunk() {
    const chunk = this.#queue.shift();
    if (chunk) {
      this.#queuedBytes = Math.max(0, this.#queuedBytes - chunk.byteLength);
      if (this.#drainWaiter && this.#queuedBytes < MAX_QUEUED_BYTES) {
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
        if (this.#queuedBytes >= MAX_QUEUED_BYTES) {
          await new Promise((resolve) => {
            this.#drainWaiter = resolve;
          });
          continue;
        }
        const chunk = await this.#inner.recv_chunk();
        if (!chunk || chunk.length === 0) {
          this._closeRead();
          break;
        }
        const copy = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
        this.#queue.push(copy);
        this.#queuedBytes += copy.byteLength;
        this._wakeNext();
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
      throw new TypeError("IrohStream.send expects Uint8Array");
    }
    if (bytes.byteLength > MAX_IROH_FRAME_LEN) {
      throw new RangeError(`iroh frame exceeds ${MAX_IROH_FRAME_LEN} bytes`);
    }
    if (this.#closed) {
      throw new Error("iroh stream is closed");
    }
    const copy = new Uint8Array(bytes);
    const job = this.#writeChain.then(() => {
      if (this.#closed || this.#freed) {
        throw new Error("iroh stream is closed");
      }
      return this.#inner.send_chunk(copy);
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

  close() {
    if (!this.#closePromise) {
      this.#closePromise = this._closeInternal();
    }
    return this.#closePromise;
  }

  async _closeInternal() {
    this.#closed = true;
    this._wakeDrain();
    this._closeRead();
    try {
      await Promise.race([
        this.#writeChain,
        new Promise((resolve) => setTimeout(resolve, 150)),
      ]);
    } catch {}
    try {
      await this.#inner.close();
    } catch {}
    try {
      await this.#writeChain;
    } catch {}
    if (this.#readLoopPromise) {
      try {
        await this.#readLoopPromise;
      } catch {}
    }
    if (!this.#freed) {
      this.#freed = true;
      this.#inner.free();
    }
  }
}

const textDecoder = new TextDecoder("utf-8", { fatal: true });

export async function dialIrohStream({
  endpoint,
  relayUrlOverride = null,
  p2pRelayUrls = null,
  p2pRelayAuthToken = null,
  p2pApiSecret = null,
  hint = false,
  timeoutMs = 15000,
}) {
  if (p2pApiSecret) {
    throw new Error(
      "p2pApiSecret is not permitted in browser clients; pass a scoped p2pRelayAuthToken"
    );
  }
  if (!endpoint || !endpoint.startsWith("iroh://")) {
    throw new Error(`iroh endpoint must start with iroh://: ${endpoint}`);
  }
  let authTokenStr = null;
  if (p2pRelayAuthToken !== null && p2pRelayAuthToken !== undefined) {
    if (p2pRelayAuthToken instanceof Uint8Array) {
      try {
        authTokenStr = textDecoder.decode(p2pRelayAuthToken);
      } finally {
        p2pRelayAuthToken.fill(0);
      }
    } else if (typeof p2pRelayAuthToken === "string") {
      authTokenStr = p2pRelayAuthToken;
    } else {
      throw new TypeError("p2pRelayAuthToken must be a string or Uint8Array");
    }
    if (!authTokenStr) {
      throw new Error("p2pRelayAuthToken must not be empty");
    }
  }
  let relayUrlsJson = null;
  if (relayUrlOverride !== null && relayUrlOverride !== undefined && typeof relayUrlOverride !== "string") {
    throw new TypeError("relayUrlOverride must be a string");
  }
  const trimmedRelayOverride =
    typeof relayUrlOverride === "string" ? relayUrlOverride.trim() : "";
  if (p2pRelayUrls !== null && p2pRelayUrls !== undefined) {
    if (!Array.isArray(p2pRelayUrls)) {
      throw new TypeError("p2pRelayUrls must be an array of relay URLs");
    }
    relayUrlsJson = JSON.stringify(p2pRelayUrls);
  } else if (trimmedRelayOverride && authTokenStr !== null) {
    relayUrlsJson = JSON.stringify([trimmedRelayOverride]);
  }
  const mod = await ensureP2pReady();
  let timer = null;
  let timedOut = false;
  const useOptions = relayUrlsJson !== null || authTokenStr !== null;
  const dialPromise = (useOptions
    ? mod.WasmIrohStream.dial_with_options(
        endpoint,
        relayUrlsJson,
        authTokenStr,
        timeoutMs,
        Boolean(hint)
      )
    : mod.WasmIrohStream.dial(endpoint, trimmedRelayOverride || null, timeoutMs, Boolean(hint))
  )
    .then(async (stream) => {
      if (timedOut) {
        try {
          await stream.close();
        } catch {}
        stream.free();
        return null;
      }
      return stream;
    })
    .catch((err) => {
      if (timedOut) {
        return null;
      }
      throw err;
    });
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      reject(new Error("timed out connecting to iroh endpoint"));
    }, timeoutMs);
  });
  let inner;
  try {
    inner = await Promise.race([dialPromise, timeoutPromise]);
  } finally {
    if (timer !== null) {
      clearTimeout(timer);
    }
  }
  return new IrohStream(inner);
}
