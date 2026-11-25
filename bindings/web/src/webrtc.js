export const MAX_WEBRTC_FRAME_LEN = 65521;
export const MAX_WEBRTC_QUEUED_BYTES = 4 * MAX_WEBRTC_FRAME_LEN;
const WEBRTC_CHUNK_SIZE = 16384;
const WEBRTC_HIGH_WATER = 65536;
const WEBRTC_LOW_WATER = 16384;
const ICE_GATHER_WAIT_MS = 2500;

function makeAbortError(signal) {
  if (signal?.reason instanceof Error) {
    return signal.reason;
  }
  const err = new Error("webrtc dial aborted");
  err.name = "AbortError";
  return err;
}

export function hasWebRtcSupport() {
  return typeof globalThis.RTCPeerConnection === "function";
}

function makeUnsupportedError() {
  const err = new Error("WebRTC RTCPeerConnection is not supported in this environment");
  err.code = "webrtc_unsupported";
  return err;
}

function sdpHasCandidate(sdp) {
  return typeof sdp === "string" && /(?:^|\r?\n)a=candidate:/m.test(sdp);
}

/**
 * Framed WebRTC DataChannel stream implementing Tendril's browser transport contract
 * (`provider = "p2p"`, `send`, `recv`, `close`, `maxFrame`).
 */
export class WebRtcStream {
  #pc;
  #dc;
  #queue = [];
  #queuedBytes = 0;
  #waiters = [];
  #drainWaiter = null;
  #writeChain = Promise.resolve();
  #closed = false;
  #eof = false;
  #error = null;
  #closePromise = null;
  #onMessage;
  #onClose;
  #onError;
  #onConnectionStateChange;
  #onBufferedAmountLow;

  constructor(pc, dc) {
    if (!pc || !dc) {
      throw new TypeError("WebRtcStream requires RTCPeerConnection and RTCDataChannel");
    }
    this.#pc = pc;
    this.#dc = dc;
    try {
      this.#dc.binaryType = "arraybuffer";
    } catch {}
    try {
      if (typeof this.#dc.bufferedAmountLowThreshold === "number") {
        this.#dc.bufferedAmountLowThreshold = WEBRTC_LOW_WATER;
      }
    } catch {}

    this.#onMessage = (ev) => {
      this.#handleMessage(ev?.data);
    };
    this.#onClose = () => {
      this._closeRead();
    };
    this.#onError = (ev) => {
      const msg = ev?.error?.message || ev?.message || "webrtc datachannel error";
      this._fail(new Error(msg));
    };
    this.#onConnectionStateChange = () => {
      const state = this.#pc.connectionState;
      if (state === "closed") {
        this._closeRead();
      } else if (state === "failed") {
        this._fail(new Error("webrtc peer connection failed"));
      }
    };
    this.#onBufferedAmountLow = () => {
      this._wakeDrain();
    };

    this.#dc.addEventListener("message", this.#onMessage);
    this.#dc.addEventListener("close", this.#onClose);
    this.#dc.addEventListener("error", this.#onError);
    this.#dc.addEventListener("bufferedamountlow", this.#onBufferedAmountLow);
    this.#pc.addEventListener("connectionstatechange", this.#onConnectionStateChange);

    if (this.#dc.readyState === "closing" || this.#dc.readyState === "closed") {
      this._closeRead();
    }
  }

  get provider() {
    return "p2p";
  }

  get fastOpenSent() {
    return false;
  }

  maxFrame() {
    return MAX_WEBRTC_FRAME_LEN;
  }

  #handleMessage(data) {
    if (this.#closed || this.#eof || this.#error) {
      return;
    }
    let bytes;
    if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data);
    } else if (ArrayBuffer.isView(data)) {
      bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    } else {
      this._fail(new Error("webrtc datachannel received non-binary message"));
      try {
        this.#dc.close();
      } catch {}
      return;
    }
    if (bytes.byteLength === 0) {
      return;
    }
    if (bytes.byteLength > MAX_WEBRTC_FRAME_LEN) {
      this._fail(new Error(`webrtc message exceeds ${MAX_WEBRTC_FRAME_LEN} bytes`));
      try {
        this.#dc.close();
      } catch {}
      return;
    }
    if (this.#queuedBytes + bytes.byteLength > MAX_WEBRTC_QUEUED_BYTES) {
      this._fail(new Error(`webrtc receive buffer exceeded ${MAX_WEBRTC_QUEUED_BYTES} bytes`));
      try {
        this.#dc.close();
      } catch {}
      return;
    }
    const copy = new Uint8Array(bytes);
    this.#queue.push(copy);
    this.#queuedBytes += copy.byteLength;
    this._wakeNext();
  }

  _shiftChunk() {
    const chunk = this.#queue.shift();
    this.#queuedBytes -= chunk.byteLength;
    return chunk;
  }

  _wakeDrain() {
    if (this.#drainWaiter) {
      const resolve = this.#drainWaiter;
      this.#drainWaiter = null;
      resolve();
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

  _fail(err) {
    if (!this.#error && !this.#eof) {
      this.#error = err;
      this._wakeDrain();
      this._wakeAll();
    }
  }

  _closeRead() {
    if (!this.#eof) {
      this.#eof = true;
      this._wakeDrain();
      this._wakeAll();
    }
  }

  async #waitBufferedLow() {
    while (
      !this.#closed &&
      !this.#eof &&
      !this.#error &&
      this.#dc.readyState === "open" &&
      (this.#dc.bufferedAmount ?? 0) >= WEBRTC_HIGH_WATER
    ) {
      await new Promise((resolve) => {
        const timer = setTimeout(() => {
          if (this.#drainWaiter === done) {
            this.#drainWaiter = null;
          }
          resolve();
        }, 25);
        const done = () => {
          clearTimeout(timer);
          resolve();
        };
        this.#drainWaiter = done;
      });
    }
  }

  async send(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError("WebRtcStream.send expects Uint8Array");
    }
    if (bytes.byteLength > MAX_WEBRTC_FRAME_LEN) {
      throw new RangeError(`webrtc frame exceeds ${MAX_WEBRTC_FRAME_LEN} bytes`);
    }
    if (this.#closed || this.#dc.readyState !== "open") {
      throw new Error("webrtc stream is closed");
    }
    const copy = new Uint8Array(bytes);
    const job = this.#writeChain.then(async () => {
      if (this.#closed || this.#dc.readyState !== "open") {
        throw new Error("webrtc stream is closed");
      }
      for (let off = 0; off < copy.byteLength; ) {
        await this.#waitBufferedLow();
        if (this.#closed || this.#dc.readyState !== "open") {
          throw new Error("webrtc stream is closed");
        }
        const end = Math.min(off + WEBRTC_CHUNK_SIZE, copy.byteLength);
        this.#dc.send(copy.subarray(off, end));
        off = end;
      }
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
    if (this.#eof || this.#closed) {
      return Promise.resolve({ status: "eof" });
    }
    if (timeoutMs <= 0) {
      return Promise.resolve({ status: "would_block" });
    }
    return new Promise((resolve, reject) => {
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
      const timer = setTimeout(() => {
        const idx = this.#waiters.indexOf(waiter);
        if (idx >= 0) {
          this.#waiters.splice(idx, 1);
        }
        resolve({ status: "would_block" });
      }, timeoutMs);
      this.#waiters.push(waiter);
    });
  }

  close() {
    if (!this.#closePromise) {
      this.#closePromise = this.#closeInternal();
    }
    return this.#closePromise;
  }

  async #closeInternal() {
    this.#closed = true;
    this.#queue.length = 0;
    this.#queuedBytes = 0;
    this._wakeDrain();
    this._closeRead();
    try {
      this.#dc.removeEventListener("message", this.#onMessage);
      this.#dc.removeEventListener("close", this.#onClose);
      this.#dc.removeEventListener("error", this.#onError);
      this.#dc.removeEventListener("bufferedamountlow", this.#onBufferedAmountLow);
      this.#pc.removeEventListener("connectionstatechange", this.#onConnectionStateChange);
    } catch {}
    let closeTimer = null;
    await Promise.race([
      this.#writeChain,
      new Promise((resolve) => {
        closeTimer = setTimeout(resolve, 150);
      }),
    ]);
    if (closeTimer !== null) {
      clearTimeout(closeTimer);
    }
    try {
      this.#dc.close();
    } catch {}
    try {
      this.#pc.close();
    } catch {}
  }
}

/**
 * Initiates an offer-side WebRTC DataChannel (`"tendril/v1"`) over an already-authenticated
 * external signaling channel (`sendOfferAndWaitAnswer(offerSdp)`).
 */
export async function dialWebRtcUpgrade(options = {}) {
  const {
    signal = null,
    timeoutMs = 15000,
    iceServers = [],
    rtcPeerConnectionImpl = globalThis.RTCPeerConnection,
    sendOfferAndWaitAnswer,
  } = options;

  if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError("dialWebRtcUpgrade timeoutMs must be a positive finite number");
  }
  if (!Array.isArray(iceServers)) {
    throw new TypeError("iceServers must be an array");
  }
  if (typeof sendOfferAndWaitAnswer !== "function") {
    throw new TypeError("dialWebRtcUpgrade requires sendOfferAndWaitAnswer");
  }
  if (signal?.aborted) {
    throw makeAbortError(signal);
  }
  if (typeof rtcPeerConnectionImpl !== "function") {
    throw makeUnsupportedError();
  }

  const deadlineMs = performance.now() + timeoutMs;
  const remainingMs = () => Math.max(0, Math.ceil(deadlineMs - performance.now()));
  const pc = new rtcPeerConnectionImpl({ iceServers: [...iceServers] });
  const dc = pc.createDataChannel("tendril/v1", { ordered: true });
  dc.binaryType = "arraybuffer";

  let handedOff = false;
  const cleanups = [];
  const abortCleanup = () => {
    try {
      dc.close();
    } catch {}
    try {
      pc.close();
    } catch {}
  };

  try {
    if (signal) {
      signal.addEventListener("abort", abortCleanup, { once: true });
      cleanups.push(() => signal.removeEventListener("abort", abortCleanup));
    }

    const gatherIce = () =>
      new Promise((resolve, reject) => {
        if (signal?.aborted) {
          reject(makeAbortError(signal));
          return;
        }
        if (pc.iceGatheringState === "complete") {
          resolve();
          return;
        }
        let settled = false;
        let sawCandidate = sdpHasCandidate(pc.localDescription?.sdp);
        let timer = null;
        let candidateTimer = null;

        const finish = (err = null) => {
          if (settled) return;
          settled = true;
          if (timer !== null) clearTimeout(timer);
          if (candidateTimer !== null) clearTimeout(candidateTimer);
          pc.removeEventListener("icegatheringstatechange", onState);
          pc.removeEventListener("icecandidate", onCandidate);
          signal?.removeEventListener("abort", onAbort);
          if (err) reject(err);
          else resolve();
        };
        const onState = () => {
          if (pc.iceGatheringState === "complete") {
            finish();
          }
        };
        const onCandidate = (ev) => {
          if (ev?.candidate) {
            sawCandidate = true;
            if (candidateTimer === null) {
              candidateTimer = setTimeout(() => {
                if (sawCandidate || sdpHasCandidate(pc.localDescription?.sdp)) {
                  finish();
                }
              }, Math.min(ICE_GATHER_WAIT_MS, remainingMs()));
            }
          } else {
            finish();
          }
        };
        const onAbort = () => finish(makeAbortError(signal));

        const budget = remainingMs();
        if (budget <= 0) {
          finish(new Error("webrtc ICE gathering timed out"));
          return;
        }
        timer = setTimeout(() => {
          if (sawCandidate || sdpHasCandidate(pc.localDescription?.sdp)) {
            finish();
          } else {
            finish(new Error("webrtc ICE gathering timed out without local candidates"));
          }
        }, Math.min(ICE_GATHER_WAIT_MS, budget));
        if (sawCandidate) {
          candidateTimer = setTimeout(() => finish(), Math.min(250, budget));
        }

        pc.addEventListener("icegatheringstatechange", onState);
        pc.addEventListener("icecandidate", onCandidate);
        signal?.addEventListener("abort", onAbort, { once: true });
      });

    const offer = await pc.createOffer();
    if (signal?.aborted) {
      throw makeAbortError(signal);
    }
    await pc.setLocalDescription(offer);
    await gatherIce();
    if (signal?.aborted) {
      throw makeAbortError(signal);
    }

    const offerSdp = pc.localDescription?.sdp || offer?.sdp || "";
    if (!offerSdp) {
      throw new Error("webrtc local SDP offer is empty");
    }

    const answerBudget = remainingMs();
    if (answerBudget <= 0) {
      throw new Error("webrtc upgrade timed out before signaling offer");
    }
    const answerSdp = await new Promise((resolve, reject) => {
      let settled = false;
      let timer = null;
      const offerAbort = new AbortController();
      const finish = (fn, val) => {
        if (settled) return;
        settled = true;
        if (timer !== null) clearTimeout(timer);
        if (signal && onAbort) {
          signal.removeEventListener("abort", onAbort);
        }
        fn(val);
      };
      const onAbort = () => {
        const abortErr = makeAbortError(signal);
        offerAbort.abort(abortErr);
        finish(reject, abortErr);
      };
      timer = setTimeout(() => {
        const timeoutErr = new Error("webrtc upgrade timed out waiting for SDP answer");
        offerAbort.abort(timeoutErr);
        finish(reject, timeoutErr);
      }, answerBudget);
      if (signal) {
        signal.addEventListener("abort", onAbort, { once: true });
      }
      Promise.resolve()
        .then(() => sendOfferAndWaitAnswer(offerSdp, answerBudget, offerAbort.signal))
        .then(
          (val) => finish(resolve, val),
          (err) => finish(reject, err)
        );
    });
    if (signal?.aborted) {
      throw makeAbortError(signal);
    }
    if (typeof answerSdp !== "string" || answerSdp.trim().length === 0) {
      throw new Error("webrtc remote SDP answer is empty");
    }

    await pc.setRemoteDescription({ type: "answer", sdp: answerSdp });
    if (signal?.aborted) {
      throw makeAbortError(signal);
    }

    await new Promise((resolve, reject) => {
      if (dc.readyState === "open") {
        resolve();
        return;
      }
      if (dc.readyState === "closing" || dc.readyState === "closed") {
        reject(new Error("webrtc datachannel closed before opening"));
        return;
      }
      const budget = remainingMs();
      if (budget <= 0) {
        reject(new Error("webrtc datachannel open timed out"));
        return;
      }
      let settled = false;
      let timer = null;
      const finish = (err = null) => {
        if (settled) return;
        settled = true;
        if (timer !== null) clearTimeout(timer);
        dc.removeEventListener("open", onOpen);
        dc.removeEventListener("close", onClose);
        dc.removeEventListener("error", onError);
        pc.removeEventListener("connectionstatechange", onConn);
        signal?.removeEventListener("abort", onAbort);
        if (err) reject(err);
        else resolve();
      };
      const onOpen = () => finish();
      const onClose = () => finish(new Error("webrtc datachannel closed during ICE/DTLS setup"));
      const onError = (ev) =>
        finish(new Error(ev?.error?.message || ev?.message || "webrtc datachannel setup failed"));
      const onConn = () => {
        if (pc.connectionState === "failed" || pc.connectionState === "closed") {
          finish(new Error(`webrtc peer connection ${pc.connectionState}`));
        }
      };
      const onAbort = () => finish(makeAbortError(signal));

      timer = setTimeout(() => finish(new Error("webrtc datachannel open timed out")), budget);
      dc.addEventListener("open", onOpen);
      dc.addEventListener("close", onClose);
      dc.addEventListener("error", onError);
      pc.addEventListener("connectionstatechange", onConn);
      signal?.addEventListener("abort", onAbort, { once: true });
    });

    while (cleanups.length > 0) {
      cleanups.pop()();
    }
    const stream = new WebRtcStream(pc, dc);
    handedOff = true;
    return stream;
  } finally {
    while (cleanups.length > 0) {
      cleanups.pop()();
    }
    if (!handedOff) {
      abortCleanup();
    }
  }
}
