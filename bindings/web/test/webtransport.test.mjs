import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_WT_FRAME_LEN,
  MAX_WT_QUEUED_BYTES,
  WtStream,
  dialWtStream,
  filterWebCompatibleEndpoints,
  validateWtUrl,
} from "../src/index.js";

const VALID_CERTHASH = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function createMockWebTransportClass({
  failReady = null,
  hangReady = false,
  hangOpenBi = false,
  lateResolveBi = false,
  onConstruct = null,
} = {}) {
  const instances = [];
  class MockWebTransport {
    constructor(url, options) {
      this.url = url;
      this.options = options;
      this.closed = false;
      this.closeArgs = null;
      this.written = [];
      this.writerClosed = false;
      this.readerCancelled = false;
      this.aborted = false;
      this.readCalls = 0;
      this.incoming = [];
      this.incomingWaiters = [];
      this.incomingClosed = false;
      this._readyReject = null;
      this._biWaiters = [];
      this._lateBiResolvers = [];
      onConstruct?.(this, url, options);
      instances.push(this);

      if (hangReady) {
        this.ready = new Promise((_, reject) => {
          this._readyReject = reject;
        });
      } else if (failReady) {
        this.ready = Promise.reject(failReady);
      } else {
        this.ready = Promise.resolve();
      }
    }

    pushIncoming(bytes) {
      if (this.incomingWaiters.length > 0) {
        this.incomingWaiters.shift()({ value: bytes, done: false });
      } else {
        this.incoming.push({ value: bytes, done: false });
      }
    }

    closeIncoming() {
      this.incomingClosed = true;
      while (this.incomingWaiters.length > 0) {
        this.incomingWaiters.shift()({ value: undefined, done: true });
      }
    }

    _makeBiStream() {
      const self = this;
      return {
        readable: {
          getReader() {
            return {
              read() {
                self.readCalls += 1;
                if (self.incoming.length > 0) {
                  return Promise.resolve(self.incoming.shift());
                }
                if (self.incomingClosed) {
                  return Promise.resolve({ value: undefined, done: true });
                }
                return new Promise((resolve) => self.incomingWaiters.push(resolve));
              },
              cancel() {
                self.readerCancelled = true;
                self.closeIncoming();
                return Promise.resolve();
              },
            };
          },
        },
        writable: {
          getWriter() {
            return {
              write(chunk) {
                self.written.push(new Uint8Array(chunk));
                return Promise.resolve();
              },
              close() {
                self.writerClosed = true;
                return Promise.resolve();
              },
              abort() {
                self.aborted = true;
                return Promise.resolve();
              },
            };
          },
        },
      };
    }

    createBidirectionalStream() {
      if (lateResolveBi) {
        return new Promise((resolve) => {
          this._lateBiResolvers.push(() => resolve(this._makeBiStream()));
        });
      }
      if (hangOpenBi) {
        return new Promise((_, reject) => {
          this._biWaiters.push(reject);
        });
      }
      return Promise.resolve(this._makeBiStream());
    }

    resolveLateBi() {
      while (this._lateBiResolvers.length > 0) {
        this._lateBiResolvers.shift()();
      }
    }

    close(info) {
      this.closed = true;
      this.closeArgs = info;
      this.closeIncoming();
      if (this._readyReject) {
        const rej = this._readyReject;
        this._readyReject = null;
        rej(new Error("WebTransport closed"));
      }
      while (this._biWaiters.length > 0) {
        this._biWaiters.shift()(new Error("WebTransport closed"));
      }
    }
  }
  return { MockWebTransport, instances };
}

test("validateWtUrl validates ports, certhash, SSRF hosts, and LAN/loopback classification", () => {
  const okLan = validateWtUrl(`wt://192.168.1.10:4433/path?certhash=${VALID_CERTHASH}`);
  assert.equal(okLan.httpsUrl, "https://192.168.1.10:4433/path");
  assert.equal(okLan.port, 4433);
  assert.equal(okLan.certhashBytes?.byteLength, 32);
  assert.equal(okLan.isLanOrLoopback, true);

  const okV6 = validateWtUrl("wt://[fd00::1]:4433");
  assert.equal(okV6.httpsUrl, "https://[fd00::1]:4433");
  assert.equal(okV6.certhashBytes, null);
  assert.equal(okV6.isLanOrLoopback, true);

  const okPub = validateWtUrl(`wt://peer.example:443?certhash=${VALID_CERTHASH}`);
  assert.equal(okPub.isLanOrLoopback, false);
  assert.equal(okPub.port, 443);

  for (const loopbackAlt of ["wt://2130706433:4433", "wt://0x7f000001:4433"]) {
    const canon = validateWtUrl(loopbackAlt);
    assert.equal(canon.bareHost, "127.0.0.1");
    assert.equal(canon.httpsUrl, "https://127.0.0.1:4433");
    assert.equal(canon.isLanOrLoopback, true);
  }

  for (const bad of [
    "https://127.0.0.1:4433",
    "wt://127.0.0.1",
    "wt://127.0.0.1:0",
    "wt://127.0.0.1:70000",
    "wt://user@127.0.0.1:4433",
    "wt://127.0.0.1:4433#frag",
    "wt://127.0.0.1:4433\\x",
    "wt://127.0.0.1:4433?",
    "wt://127.0.0.1:4433?foo=bar",
    `wt://127.0.0.1:4433?certhash=${VALID_CERTHASH}&extra=1`,
    "wt://127.0.0.1:4433?certhash=too-short",
    "wt://127.0.0.1:4433?certhash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
    "wt://169.254.169.254:4433",
    "wt://2852039166:4433",
    "wt://0xa9fea9fe:4433",
    "wt://[::ffff:169.254.169.254]:4433",
    "wt://%31%36%39.254.169.254:4433",
    "wt://.:4433",
    "wt://240.0.0.1:4433",
    "wt://[fe80::1]:4433",
    "wt://metadata.google.internal:4433",
  ]) {
    assert.throws(() => validateWtUrl(bad), `must reject ${bad}`);
  }
});

test("filterWebCompatibleEndpoints admits wt:// under webtransport: true ahead of p2p and relay", () => {
  const wt = `wt://127.0.0.1:4433?certhash=${VALID_CERTHASH}`;
  const wss = "wss://relay.example/v1/relay";
  const withoutWt = filterWebCompatibleEndpoints([wss, wt], { webtransport: false });
  assert.deepEqual(
    withoutWt.candidates.map((c) => c.provider),
    ["relay"]
  );
  assert.deepEqual(withoutWt.skipped, [{ hint: wt, reason: "webtransport_feature_disabled" }]);

  const withWt = filterWebCompatibleEndpoints([wss, wt], { webtransport: true });
  assert.deepEqual(
    withWt.candidates.map((c) => c.provider),
    ["direct", "relay"]
  );
  assert.equal(withWt.candidates[0].endpoint, wt);
});

test("dialWtStream pins serverCertificateHashes, enforces frame bounds, slices reads, and aborts", async () => {
  const { MockWebTransport, instances } = createMockWebTransportClass();
  const stream = await dialWtStream(`wt://127.0.0.1:4433/tendril?certhash=${VALID_CERTHASH}`, {
    webTransportImpl: MockWebTransport,
  });
  assert.equal(stream.provider, "direct");
  assert.equal(stream.fastOpenSent, false);
  assert.equal(stream.maxFrame(), MAX_WT_FRAME_LEN);
  assert.equal(instances[0].url, "https://127.0.0.1:4433/tendril");
  assert.equal(instances[0].options.serverCertificateHashes.length, 1);
  assert.equal(instances[0].options.serverCertificateHashes[0].algorithm, "sha-256");
  assert.equal(instances[0].options.serverCertificateHashes[0].value.byteLength, 32);

  await stream.send(new Uint8Array([1, 2, 3]));
  assert.deepEqual(instances[0].written[0], new Uint8Array([1, 2, 3]));
  await assert.rejects(() => stream.send("not-u8"), TypeError);
  await assert.rejects(() => stream.send(new Uint8Array(MAX_WT_FRAME_LEN + 1)), RangeError);

  // Oversized incoming chunk is sliced to MAX_WT_FRAME_LEN.
  const big = new Uint8Array(MAX_WT_FRAME_LEN + 17).fill(0x5a);
  instances[0].pushIncoming(big);
  const r1 = await stream.recv(500);
  const r2 = await stream.recv(500);
  assert.equal(r1.status, "data");
  assert.equal(r1.bytes.byteLength, MAX_WT_FRAME_LEN);
  assert.equal(r2.status, "data");
  assert.equal(r2.bytes.byteLength, 17);

  const wb = await stream.recv(10);
  assert.equal(wb.status, "would_block");

  const pending = stream.recv(5000);
  await stream.close();
  assert.deepEqual(await pending, { status: "eof" });
  await assert.rejects(() => stream.send(new Uint8Array([1])), /closed/i);

  // Close discards stale buffered chunks so post-close recv() yields eof.
  const staleCloseMock = createMockWebTransportClass();
  const staleCloseStream = await dialWtStream(`wt://127.0.0.1:4433?certhash=${VALID_CERTHASH}`, {
    webTransportImpl: staleCloseMock.MockWebTransport,
  });
  staleCloseMock.instances[0].pushIncoming(new Uint8Array([9, 8, 7]));
  await new Promise((r) => setTimeout(r, 15));
  await staleCloseStream.close();
  assert.deepEqual(await staleCloseStream.recv(50), { status: "eof" });

  // Timeout, hangOpenBi, late bi resolution, and AbortSignal cancel cleanly without unhandled rejections.
  for (const badTimeout of [0, -5, Number.NaN, Number.POSITIVE_INFINITY]) {
    await assert.rejects(
      () =>
        dialWtStream("wt://peer.example:4433", {
          timeoutMs: badTimeout,
          webTransportImpl: createMockWebTransportClass().MockWebTransport,
        }),
      RangeError
    );
  }

  const hangMock = createMockWebTransportClass({ hangReady: true });
  await assert.rejects(
    () =>
      dialWtStream("wt://peer.example:4433", {
        timeoutMs: 25,
        webTransportImpl: hangMock.MockWebTransport,
      }),
    /timed out/
  );
  assert.equal(hangMock.instances[0].closed, true);

  const hangBiMock = createMockWebTransportClass({ hangOpenBi: true });
  await assert.rejects(
    () =>
      dialWtStream("wt://peer.example:4433", {
        timeoutMs: 25,
        webTransportImpl: hangBiMock.MockWebTransport,
      }),
    /timed out/
  );
  assert.equal(hangBiMock.instances[0].closed, true);

  const lateBiMock = createMockWebTransportClass({ lateResolveBi: true });
  await assert.rejects(
    () =>
      dialWtStream("wt://peer.example:4433", {
        timeoutMs: 25,
        webTransportImpl: lateBiMock.MockWebTransport,
      }),
    /timed out/
  );
  lateBiMock.instances[0].resolveLateBi();
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(lateBiMock.instances[0].aborted, true);
  assert.equal(lateBiMock.instances[0].readerCancelled, true);

  const ac = new AbortController();
  const abortMock = createMockWebTransportClass({ hangReady: true });
  const p = dialWtStream("wt://peer.example:4433", {
    timeoutMs: 5000,
    signal: ac.signal,
    webTransportImpl: abortMock.MockWebTransport,
  });
  ac.abort(new Error("user cancelled"));
  await assert.rejects(() => p, /user cancelled/);
  assert.equal(abortMock.instances[0].closed, true);
});

test("WtStream abort discards queued chunks and read loop pauses at MAX_WT_QUEUED_BYTES", async () => {
  const { MockWebTransport, instances } = createMockWebTransportClass();
  const abortStream = await dialWtStream(`wt://127.0.0.1:4433?certhash=${VALID_CERTHASH}`, {
    webTransportImpl: MockWebTransport,
  });
  instances[0].pushIncoming(new Uint8Array([1, 2, 3, 4]));
  instances[0].pushIncoming(new Uint8Array([5, 6, 7, 8]));
  await new Promise((r) => setTimeout(r, 15));
  abortStream.abort(new Error("stream reset"));
  await assert.rejects(() => abortStream.recv(50), /stream reset/);
  await assert.rejects(() => abortStream.send(new Uint8Array([1])), /closed/i);
  assert.equal(instances[0].aborted, true);
  assert.equal(instances[0].closed, true);

  // Oversized single read spanning > MAX_WT_QUEUED_BYTES pauses before queueing past budget
  // and delivers all bytes in order once drained.
  const bpMock = createMockWebTransportClass();
  const bpStream = await dialWtStream(`wt://127.0.0.1:4433?certhash=${VALID_CERTHASH}`, {
    webTransportImpl: bpMock.MockWebTransport,
  });
  assert.ok(bpStream instanceof WtStream);
  const totalBytes = MAX_WT_QUEUED_BYTES + 2 * MAX_WT_FRAME_LEN + 37;
  const payload = new Uint8Array(totalBytes);
  for (let i = 0; i < totalBytes; i += 1) {
    payload[i] = i & 0xff;
  }
  bpMock.instances[0].pushIncoming(payload);
  await new Promise((r) => setTimeout(r, 20));
  // Because read loop stalls once queuedBytes == MAX_WT_QUEUED_BYTES before next read(),
  // only the first reader.read() call has happened so far.
  assert.equal(bpMock.instances[0].readCalls, 1);

  const received = new Uint8Array(totalBytes);
  let offset = 0;
  while (offset < totalBytes) {
    const chunk = await bpStream.recv(500);
    assert.equal(chunk.status, "data");
    assert.ok(chunk.bytes.byteLength <= MAX_WT_FRAME_LEN);
    received.set(chunk.bytes, offset);
    offset += chunk.bytes.byteLength;
  }
  assert.deepEqual(received, payload);
  await bpStream.close();
});
