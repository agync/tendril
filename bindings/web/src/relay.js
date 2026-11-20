// Browser WebSocket relay client implementing spec/relay-v1.md dialer framing.

const MAX_RELAY_FRAME_LEN = 65521;

function randomConnIdB64() {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  let bin = "";
  for (let i = 0; i < buf.length; i += 1) {
    bin += String.fromCharCode(buf[i]);
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

class RelayStream {
  #ws;
  #queue = [];
  #waiters = [];
  #eof = false;
  #error = null;
  #maxFrame = MAX_RELAY_FRAME_LEN;

  constructor(ws) {
    this.#ws = ws;
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

  _pushFrame(bytes) {
    if (bytes.byteLength > this.#maxFrame) {
      this._fail(new Error(`relay frame exceeded ${this.#maxFrame} bytes`));
      try {
        this.#ws.close(1009, "frame too large");
      } catch {}
      return;
    }
    this.#queue.push(bytes);
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

  close() {
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
  timeoutMs = 15000,
}) {
  if (!relayUrl || (!relayUrl.startsWith("ws://") && !relayUrl.startsWith("wss://"))) {
    throw new Error(`relayUrl must use ws:// or wss://: ${relayUrl}`);
  }
  const parsedUrl = new URL(relayUrl);
  const rawHost = parsedUrl.hostname;
  const normalizedHost =
    rawHost.startsWith("[") && rawHost.endsWith("]") ? rawHost.slice(1, -1) : rawHost;
  const expHost = expectedHost || normalizedHost;
  if (!targetPub) {
    throw new Error("targetPub is required for relay dial");
  }

  const ws = new WebSocket(relayUrl);
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
    const err = new Error(`relay WebSocket error (${relayUrl})`);
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
          reject(new Error(`failed connecting to relay ${relayUrl}`));
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
