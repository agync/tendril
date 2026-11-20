import initP2pWasm, {
  WasmIrohStream,
  parse_p2p_endpoint_json,
} from "../pkg-p2p/tendril_wasm.js";

const MAX_IROH_FRAME_LEN = 65521;

let p2pWasmReadyPromise = null;

export async function initTendrilP2p(wasmUrl) {
  if (!p2pWasmReadyPromise) {
    p2pWasmReadyPromise = initP2pWasm(wasmUrl).then(() => {});
  }
  return p2pWasmReadyPromise;
}

export async function parseP2pEndpoint(endpoint) {
  await initTendrilP2p();
  return JSON.parse(parse_p2p_endpoint_json(endpoint));
}

class IrohStream {
  #inner;
  #queue = [];
  #waiters = [];
  #eof = false;
  #error = null;
  #closed = false;
  #freed = false;
  #writeChain = Promise.resolve();
  #readLoopPromise = null;

  constructor(inner) {
    this.#inner = inner;
    this.#readLoopPromise = this._runReadLoop();
  }

  maxFrame() {
    return MAX_IROH_FRAME_LEN;
  }

  async _runReadLoop() {
    try {
      while (!this.#closed) {
        const chunk = await this.#inner.recv_chunk();
        if (!chunk || chunk.length === 0) {
          this._closeRead();
          break;
        }
        const copy = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
        this.#queue.push(copy);
        this._wakeNext();
      }
    } catch (err) {
      this._fail(err instanceof Error ? err : new Error(String(err)));
    } finally {
      if (this.#closed && !this.#freed) {
        this.#freed = true;
        try {
          this.#inner.free();
        } catch {}
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
      w.resolve({ status: "data", bytes: this.#queue.shift() });
    }
  }

  _wakeAll() {
    while (this.#waiters.length > 0) {
      const w = this.#waiters.shift();
      if (this.#queue.length > 0) {
        w.resolve({ status: "data", bytes: this.#queue.shift() });
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
    const job = this.#writeChain.then(() => this.#inner.send_chunk(copy));
    this.#writeChain = job.catch(() => {});
    return job;
  }

  recv(timeoutMs = 5000) {
    if (this.#queue.length > 0) {
      return Promise.resolve({ status: "data", bytes: this.#queue.shift() });
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

  async close() {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this._closeRead();
    try {
      await this.#writeChain;
    } catch {}
    try {
      await this.#inner.close();
    } catch {}
    if (this.#readLoopPromise) {
      try {
        await this.#readLoopPromise;
      } catch {}
    }
    if (!this.#freed) {
      this.#freed = true;
      try {
        this.#inner.free();
      } catch {}
    }
  }
}

export async function dialIrohStream({
  endpoint,
  relayUrlOverride = null,
  timeoutMs = 15000,
}) {
  if (!endpoint || !endpoint.startsWith("iroh://")) {
    throw new Error(`iroh endpoint must start with iroh://: ${endpoint}`);
  }
  await initTendrilP2p();
  let timer = null;
  let timedOut = false;
  const dialPromise = WasmIrohStream.dial(endpoint, relayUrlOverride || null).then(
    async (stream) => {
      if (timedOut) {
        try {
          await stream.close();
        } catch {}
        try {
          stream.free();
        } catch {}
      }
      return stream;
    }
  );
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
