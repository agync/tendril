import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  MAX_WEBRTC_FRAME_LEN,
  MAX_WEBRTC_QUEUED_BYTES,
  TendrilWebClient,
  WasmV2SessionInitiator,
  b64urlDecode,
  initTendril,
  hasWebRtcSupport,
} from "../src/index.js";
import { WebRtcStream, dialWebRtcUpgrade } from "../src/webrtc.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = path.resolve(__dirname, "..");
const REPO_ROOT = path.resolve(WEB_ROOT, "..", "..");
const RELAY_BIN = path.join(REPO_ROOT, "target", "debug", "tendril-relay");
const PEER_BIN = path.join(REPO_ROOT, "target", "debug", "tendril-conformance-peer");
const WASM_PATH = path.join(WEB_ROOT, "pkg", "tendril_wasm_bg.wasm");

let wasmReady = false;
async function ensureWasm() {
  if (!wasmReady) {
    const bytes = fs.readFileSync(WASM_PATH);
    await initTendril({ module_or_path: bytes });
    wasmReady = true;
  }
}

class MockEventTarget {
  #listeners = new Map();

  addEventListener(type, fn, opts = false) {
    let list = this.#listeners.get(type);
    if (!list) {
      list = [];
      this.#listeners.set(type, list);
    }
    const once = typeof opts === "boolean" ? opts : Boolean(opts?.once);
    list.push({ fn, once });
  }

  removeEventListener(type, fn) {
    const list = this.#listeners.get(type);
    if (!list) return;
    const idx = list.findIndex((entry) => entry.fn === fn);
    if (idx >= 0) {
      list.splice(idx, 1);
    }
  }

  dispatchEvent(type, ev = {}) {
    const list = [...(this.#listeners.get(type) ?? [])];
    for (const entry of list) {
      if (entry.once) {
        this.removeEventListener(type, entry.fn);
      }
      entry.fn(ev);
    }
  }
}

class MockDataChannel extends MockEventTarget {
  constructor(label, options) {
    super();
    this.label = label;
    this.options = options;
    this.binaryType = "blob";
    this.readyState = "connecting";
    this.bufferedAmount = 0;
    this.bufferedAmountLowThreshold = 0;
    this.sent = [];
    this.closed = false;
  }

  send(data) {
    if (this.readyState !== "open") {
      throw new Error("datachannel not open");
    }
    this.sent.push(new Uint8Array(data));
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.readyState = "closed";
    this.dispatchEvent("close", {});
  }
}

class MockPeerConnection extends MockEventTarget {
  static configs = [];
  static nextBehavior = {};

  constructor(config) {
    super();
    this.config = config;
    MockPeerConnection.configs.push(config);
    this.iceGatheringState = "new";
    this.connectionState = "new";
    this.localDescription = null;
    this.remoteDescription = null;
    this.channels = [];
    this.closed = false;
    this.behavior = { ...MockPeerConnection.nextBehavior };
  }

  createDataChannel(label, options) {
    const dc = new MockDataChannel(label, options);
    this.channels.push(dc);
    return dc;
  }

  async createOffer() {
    if (this.behavior.throwError) {
      throw this.behavior.throwError;
    }
    return {
      type: "offer",
      sdp: "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=candidate:1 1 UDP 2130706431 127.0.0.1 50000 typ host\r\n",
    };
  }

  async setLocalDescription(desc) {
    this.localDescription = desc;
    queueMicrotask(() => {
      if (this.closed) return;
      if (this.behavior.hangIce) return;
      this.iceGatheringState = "complete";
      this.dispatchEvent("icecandidate", { candidate: null });
      this.dispatchEvent("icegatheringstatechange", {});
    });
  }

  async setRemoteDescription(desc) {
    this.remoteDescription = desc;
    if (this.behavior.failRemote) {
      throw new Error("bad answer SDP");
    }
    queueMicrotask(() => {
      if (this.closed) return;
      const dc = this.channels[0];
      if (this.behavior.closeOnRemote) {
        this.connectionState = "failed";
        this.dispatchEvent("connectionstatechange", {});
        dc?.close();
        return;
      }
      if (dc) {
        dc.readyState = "open";
        dc.dispatchEvent("open", {});
      }
    });
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.connectionState = "closed";
    for (const dc of this.channels) {
      dc.close();
    }
  }
}

function spawnRelay() {
  return new Promise((resolve, reject) => {
    const child = spawn(RELAY_BIN, ["--listen", "127.0.0.1:0", "--host", "127.0.0.1"], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, RUST_LOG: "info" },
    });
    let acc = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`tendril-relay startup timed out: ${acc}`));
    }, 10000);
    const onData = (chunk) => {
      acc += chunk.toString("utf8").replace(/\x1b\[[0-9;]*m/g, "");
      const m = acc.match(/ws:\/\/127\.0\.0\.1:(\d+)\/v1\/relay/);
      if (m) {
        clearTimeout(timer);
        resolve({ child, wsUrl: m[0], port: Number(m[1]) });
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`relay exited early (${code}): ${acc}`));
    });
  });
}

function spawnPeer() {
  const child = spawn(PEER_BIN, [], { stdio: ["pipe", "pipe", "pipe"] });
  const rl = readline.createInterface({ input: child.stdout });
  const waiters = [];
  const lines = [];
  rl.on("line", (line) => {
    const msg = JSON.parse(line);
    if (waiters.length > 0) waiters.shift()(msg);
    else lines.push(msg);
  });
  return {
    send(cmd) {
      child.stdin.write(`${JSON.stringify(cmd)}\n`);
    },
    recv(timeoutMs = 15000) {
      if (lines.length > 0) return Promise.resolve(lines.shift());
      return new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error("peer response timed out")), timeoutMs);
        waiters.push((m) => {
          clearTimeout(t);
          resolve(m);
        });
      });
    },
    async call(cmd) {
      this.send(cmd);
      const res = await this.recv();
      if (!res.ok) throw new Error(`peer error for ${cmd.op}: ${res.error}`);
      return res;
    },
    close() {
      rl.close();
      child.kill();
    },
  };
}

test("WebRtcStream validates, chunks, applies backpressure, bounds queues, and closes cleanly", async () => {
  assert.equal(MAX_WEBRTC_QUEUED_BYTES, 4 * MAX_WEBRTC_FRAME_LEN);
  assert.equal(MAX_WEBRTC_QUEUED_BYTES, 262084);
  const pc = new MockPeerConnection({ iceServers: [] });
  const dc = pc.createDataChannel("tendril/v1", { ordered: true });
  dc.readyState = "open";
  const stream = new WebRtcStream(pc, dc);

  assert.equal(stream.provider, "p2p");
  assert.equal(stream.fastOpenSent, false);
  assert.equal(stream.maxFrame(), MAX_WEBRTC_FRAME_LEN);
  assert.equal(dc.binaryType, "arraybuffer");

  await assert.rejects(() => stream.send("not-u8"), TypeError);
  await assert.rejects(() => stream.send(new Uint8Array(MAX_WEBRTC_FRAME_LEN + 1)), RangeError);

  const bigPayload = new Uint8Array(40000);
  for (let i = 0; i < bigPayload.length; i += 1) {
    bigPayload[i] = i & 0xff;
  }
  await stream.send(bigPayload);
  assert.equal(dc.sent.length, 3);
  assert.equal(dc.sent[0].byteLength, 16384);
  assert.equal(dc.sent[1].byteLength, 16384);
  assert.equal(dc.sent[2].byteLength, 40000 - 32768);
  assert.deepEqual(Buffer.concat(dc.sent), Buffer.from(bigPayload));

  // Backpressure waits on bufferedamountlow before sending next chunk.
  dc.sent.length = 0;
  dc.bufferedAmount = 70000;
  let sendDone = false;
  const bpPromise = stream.send(new Uint8Array([1, 2, 3])).then(() => {
    sendDone = true;
  });
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(sendDone, false);
  dc.bufferedAmount = 0;
  dc.dispatchEvent("bufferedamountlow", {});
  await bpPromise;
  assert.equal(sendDone, true);
  assert.deepEqual(dc.sent, [new Uint8Array([1, 2, 3])]);

  // Recv timeout -> would_block, inbound ArrayBuffer -> data.
  assert.deepEqual(await stream.recv(10), { status: "would_block" });
  const inbound = new Uint8Array([9, 8, 7, 6]);
  dc.dispatchEvent("message", { data: inbound.buffer });
  const got = await stream.recv(100);
  assert.equal(got.status, "data");
  assert.deepEqual(got.bytes, inbound);

  // Close unblocks parked recv() with eof.
  const parked = stream.recv(5000);
  await stream.close();
  assert.deepEqual(await parked, { status: "eof" });
  assert.equal(dc.closed, true);
  assert.equal(pc.closed, true);
});

test("WebRtcStream fails closed on queue overflow, oversized message, and non-binary frames", async () => {
  for (const kind of ["overflow", "oversized", "nonbinary"]) {
    const pc = new MockPeerConnection({ iceServers: [] });
    const dc = pc.createDataChannel("tendril/v1", { ordered: true });
    dc.readyState = "open";
    const stream = new WebRtcStream(pc, dc);

    if (kind === "overflow") {
      for (let i = 0; i < 4; i += 1) {
        dc.dispatchEvent("message", { data: new Uint8Array(MAX_WEBRTC_FRAME_LEN).buffer });
      }
      dc.dispatchEvent("message", { data: new Uint8Array([1]).buffer });
      for (let i = 0; i < 4; i += 1) {
        const res = await stream.recv(50);
        assert.equal(res.status, "data");
      }
      await assert.rejects(() => stream.recv(50), /receive buffer exceeded/);
    } else if (kind === "oversized") {
      dc.dispatchEvent("message", { data: new Uint8Array(MAX_WEBRTC_FRAME_LEN + 1).buffer });
      await assert.rejects(() => stream.recv(50), /exceeds/);
    } else {
      dc.dispatchEvent("message", { data: "hello" });
      await assert.rejects(() => stream.recv(50), /non-binary/);
    }
    await stream.close();
  }
});

test("dialWebRtcUpgrade enforces iceServers: [] default, tendril/v1 channel before offer, and clean cleanup", async () => {
  await assert.rejects(
    () =>
      dialWebRtcUpgrade({
        rtcPeerConnectionImpl: null,
        sendOfferAndWaitAnswer: async () => "v=0\r\n",
      }),
    (err) => err.code === "webrtc_unsupported"
  );

  MockPeerConnection.configs.length = 0;
  MockPeerConnection.nextBehavior = {};
  let channelBeforeOffer = false;
  let capturedOffer = null;
  const origCreateOffer = MockPeerConnection.prototype.createOffer;
  MockPeerConnection.prototype.createOffer = async function () {
    channelBeforeOffer =
      this.channels.length === 1 &&
      this.channels[0].label === "tendril/v1" &&
      this.channels[0].options?.ordered === true;
    return origCreateOffer.call(this);
  };
  try {
    const stream = await dialWebRtcUpgrade({
      rtcPeerConnectionImpl: MockPeerConnection,
      timeoutMs: 2000,
      sendOfferAndWaitAnswer: async (offerSdp) => {
        capturedOffer = offerSdp;
        return "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
      },
    });
    assert.equal(channelBeforeOffer, true);
    assert.ok(capturedOffer.includes("a=candidate:"));
    assert.deepEqual(MockPeerConnection.configs, [{ iceServers: [] }]);
    await stream.close();
  } finally {
    MockPeerConnection.prototype.createOffer = origCreateOffer;
  }

  // Abort cleans up pc & dc with no hanging promises.
  const ac = new AbortController();
  MockPeerConnection.configs.length = 0;
  const p = dialWebRtcUpgrade({
    rtcPeerConnectionImpl: MockPeerConnection,
    timeoutMs: 5000,
    signal: ac.signal,
    sendOfferAndWaitAnswer: async () => {
      ac.abort(new Error("user cancelled"));
      return new Promise(() => {});
    },
  });
  await assert.rejects(() => p, /user cancelled/);

  // Non-function hasWebRtcSupport matches environment in Node.
  assert.equal(hasWebRtcSupport(), typeof globalThis.RTCPeerConnection === "function");
});

test("WasmV2SessionInitiator supports with_upgrade_caps pre-start only", async () => {
  await ensureWasm();
  // Verify class exposes expected methods cleanly without violating post-start guard.
  assert.equal(typeof WasmV2SessionInitiator.prototype.with_upgrade_caps, "function");
  assert.equal(typeof WasmV2SessionInitiator.prototype.negotiated_upgrade_caps_json, "function");
  assert.equal(typeof WasmV2SessionInitiator.prototype.can_send_path_upgrade, "function");
  assert.equal(typeof WasmV2SessionInitiator.prototype.send_path_upgrade, "function");
});

test("TendrilWebSession.upgradeToWebRtc handles not_negotiated, webrtc_unsupported, already_direct, and keeps relay usable on rejection or upgrade limit", async () => {
  await ensureWasm();
  if (!fs.existsSync(RELAY_BIN) || !fs.existsSync(PEER_BIN)) {
    return;
  }

  const relay = await spawnRelay();
  const peer = spawnPeer();
  let client = null;
  const origRtc = globalThis.RTCPeerConnection;

  try {
    const peerInit = await peer.call({ op: "init", host_id: "webrtc-node-test" });
    client = await TendrilWebClient.create({ hostId: "webrtc-node-test" });

    // Host without webrtc_upgrade_bind: negotiatedUpgradeCaps() is empty.
    await peer.call({ op: "serve_relay", relay_url: relay.wsUrl, expected_host: "127.0.0.1" });
    const pairCode = (await peer.call({ op: "issue_code", kind: "remote" })).code;
    peer.send({ op: "pair" });
    const browserPair = await client.pair({
      relayUrl: relay.wsUrl,
      targetPub: peerInit.relay_pub,
      expectedHost: "127.0.0.1",
      code: pairCode,
      allowInsecureWs: true,
    });
    const peerPair = await peer.recv();
    assert.equal(peerPair.ok, true);
    await peer.call({ op: "confirm", peer_id: peerPair.device_id, sas: peerPair.sas });
    await client.confirmPeer("webrtc-node-test", browserPair.sas);
    const grant = (
      await peer.call({ op: "mint", peer_id: peerPair.device_id, caps: ["fs.read"] })
    ).grant;

    // 1. Peer omits "webrtc/v1" -> not_negotiated.
    globalThis.RTCPeerConnection = MockPeerConnection;
    peer.send({ op: "connect" });
    const s1 = await client.connect({
      relayUrl: relay.wsUrl,
      targetPub: peerInit.relay_pub,
      expectedHost: "127.0.0.1",
      targetHostId: "webrtc-node-test",
      grantJson: JSON.stringify(grant),
      allowInsecureWs: true,
    });
    assert.equal((await peer.recv()).ok, true);
    assert.deepEqual(s1.negotiatedUpgradeCaps(), []);
    const r1 = await s1.upgradeToWebRtc();
    assert.equal(r1.upgraded, false);
    assert.equal(r1.reason, "not_negotiated");
    // Session remains usable.
    await s1.sendData("still-works-1");
    assert.equal((await peer.call({ op: "recv", timeout_ms: 2000 })).data_utf8, "still-works-1");
    await s1.close();
    await peer.call({ op: "recv", timeout_ms: 2000 });

    // 2. Host enables webrtc_upgrade_bind, test single-flight, rejection + 4-offer cap + unsupported fallback.
    await peer.call({ op: "serve_webrtc", bind: "127.0.0.1:0" });
    peer.send({ op: "connect" });
    const s2 = await client.connect({
      relayUrl: relay.wsUrl,
      targetPub: peerInit.relay_pub,
      expectedHost: "127.0.0.1",
      targetHostId: "webrtc-node-test",
      grantJson: JSON.stringify(grant),
      allowInsecureWs: true,
    });
    assert.equal((await peer.recv()).ok, true);
    assert.deepEqual(s2.negotiatedUpgradeCaps(), ["webrtc/v1"]);

    // Missing global RTCPeerConnection at upgrade time -> webrtc_unsupported.
    globalThis.RTCPeerConnection = undefined;
    const unsupported = await s2.upgradeToWebRtc();
    assert.deepEqual(unsupported, { upgraded: false, reason: "webrtc_unsupported", route: null });

    const recvNextData = async () => {
      for (let i = 0; i < 6; i += 1) {
        const ev = await peer.call({ op: "recv", timeout_ms: 2000 });
        if (ev.event === "data") return ev;
      }
      throw new Error("did not observe expected app data event");
    };

    // Single-flight mutex + rejection/failed ICE preserves existing relay stream.
    globalThis.RTCPeerConnection = MockPeerConnection;
    MockPeerConnection.configs.length = 0;
    MockPeerConnection.nextBehavior = { failRemote: true };
    const [sfA, sfB] = await Promise.all([
      s2.upgradeToWebRtc({ timeoutMs: 2000 }),
      s2.upgradeToWebRtc({ timeoutMs: 2000 }),
    ]);
    assert.equal(sfA.upgraded, false);
    assert.deepEqual(sfA, sfB);
    assert.equal(
      MockPeerConnection.configs.length,
      1,
      "concurrent upgradeToWebRtc calls must share one single-flight attempt"
    );
    // Relay session must remain alive and exchange data!
    await s2.sendData("alive-after-failed-ice");
    assert.equal((await recvNextData()).data_utf8, "alive-after-failed-ice");

    // Exhaust remaining 3 upgrade offers (total 4 offers), 5th triggers upgrade_limit_reached.
    for (let attempt = 2; attempt <= 4; attempt += 1) {
      const r = await s2.upgradeToWebRtc({ timeoutMs: 2000 });
      assert.equal(r.upgraded, false);
    }
    const overLimit = await s2.upgradeToWebRtc({ timeoutMs: 2000 });
    assert.equal(overLimit.upgraded, false);
    assert.equal(overLimit.reason, "upgrade_limit_reached");

    // already_direct short-circuit when route.provider is direct or p2p.
    s2.route = { hint: null, endpoint: "wt://127.0.0.1:4433", provider: "direct" };
    assert.deepEqual(await s2.upgradeToWebRtc(), {
      upgraded: false,
      reason: "already_direct",
      route: s2.route,
    });

    await s2.close();
  } finally {
    globalThis.RTCPeerConnection = origRtc;
    client?.free();
    peer.close();
    relay.child.kill();
  }
});

test("Wire v2 upgradeToWebRtc rejects cleanly while keeping relay alive and autoUpgradeWebRtc handles fallback and fatal errors", async () => {
  await ensureWasm();
  if (!fs.existsSync(RELAY_BIN) || !fs.existsSync(PEER_BIN)) {
    return;
  }

  const relay = await spawnRelay();
  const v2RelayUrl = relay.wsUrl.replace("/v1/relay", "/v2/relay");
  const peer = spawnPeer();
  let client = null;
  const origRtc = globalThis.RTCPeerConnection;

  try {
    const peerInit = await peer.call({ op: "init", host_id: "webrtc-v2-node-test" });
    client = await TendrilWebClient.create({ hostId: "webrtc-v2-node-test" });

    await peer.call({ op: "serve_relay", relay_url: relay.wsUrl, expected_host: "127.0.0.1" });
    const pairCode = (await peer.call({ op: "issue_code", kind: "remote" })).code;
    peer.send({ op: "pair_v2_accept", timeout_ms: 10000 });
    const browserPair = await client.pairV2({
      relayUrl: relay.wsUrl,
      targetPub: peerInit.relay_pub,
      expectedHost: "127.0.0.1",
      code: pairCode,
      allowInsecureWs: true,
    });
    const peerPair = await peer.recv();
    assert.equal(peerPair.ok, true);
    assert.equal(browserPair.sas, peerPair.sas);
    await peer.call({ op: "confirm", peer_id: peerPair.device_id, sas: peerPair.sas });
    await client.confirmPeer("webrtc-v2-node-test", browserPair.sas);
    const grant = (
      await peer.call({ op: "mint", peer_id: peerPair.device_id, caps: ["fs.read"] })
    ).grant;

    await peer.call({ op: "serve_webrtc", bind: "127.0.0.1:0" });
    await peer.call({
      op: "serve_relay_v2",
      relay_url: v2RelayUrl,
      expected_host: "127.0.0.1",
      peer_id: peerPair.device_id,
    });

    const recvNextData = async () => {
      for (let i = 0; i < 6; i += 1) {
        const ev = await peer.call({ op: "recv", timeout_ms: 2000 });
        if (ev.event === "data") return ev;
      }
      throw new Error("did not observe expected app data event");
    };

    globalThis.RTCPeerConnection = MockPeerConnection;

    // 1. Wire v2 negotiated caps + Offer/Answer + non-fatal WebRTC failure preserves relay.
    MockPeerConnection.nextBehavior = { failRemote: true };
    peer.send({ op: "accept_v2", timeout_ms: 10000 });
    const sV2 = await client.connectV2({
      relayUrl: v2RelayUrl,
      targetPub: peerInit.relay_pub,
      expectedHost: "127.0.0.1",
      targetHostId: "webrtc-v2-node-test",
      grantJson: JSON.stringify(grant),
      useRelayV2: true,
      allowInsecureWs: true,
    });
    assert.equal((await peer.recv()).ok, true);
    assert.equal(sV2.canSendPathUpgrade(), true);
    assert.ok(sV2.negotiatedUpgradeCaps().includes("webrtc/v1"));

    const [failUp] = await Promise.all([
      sV2.upgradeToWebRtc({ timeoutMs: 2000 }),
      peer.call({ op: "recv", timeout_ms: 2000 }),
    ]);
    assert.equal(failUp.upgraded, false);
    assert.equal(sV2.route, undefined);

    await sV2.sendData("v2-relay-still-works");
    assert.equal((await recvNextData()).data_utf8, "v2-relay-still-works");
    await sV2.close();
    await peer.call({ op: "recv", timeout_ms: 2000 });

    // 2. autoUpgradeWebRtc: true falls back cleanly on non-fatal WebRTC failure.
    MockPeerConnection.nextBehavior = { failRemote: true };
    peer.send({ op: "accept_v2", timeout_ms: 10000 });
    const fallbackPromise = client.connectV2({
      relayUrl: v2RelayUrl,
      targetPub: peerInit.relay_pub,
      expectedHost: "127.0.0.1",
      targetHostId: "webrtc-v2-node-test",
      grantJson: JSON.stringify(grant),
      useRelayV2: true,
      allowInsecureWs: true,
      autoUpgradeWebRtc: true,
    });
    assert.equal((await peer.recv()).ok, true);
    // Drive the host session while it receives the Offer and replies with Answer.
    await peer.call({ op: "recv", timeout_ms: 2000 });
    const sFallback = await fallbackPromise;
    assert.equal(sFallback.route, undefined);
    await sFallback.sendData("v2-fallback-still-works");
    assert.equal((await recvNextData()).data_utf8, "v2-fallback-still-works");
    await sFallback.close();
    await peer.call({ op: "recv", timeout_ms: 2000 });

    // 3. Fatal security error during autoUpgradeWebRtc is rethrown (not swallowed as fallback).
    const fatalErr = new Error("simulated pin mismatch");
    fatalErr.code = "host_key_unverified";
    MockPeerConnection.nextBehavior = { throwError: fatalErr };
    peer.send({ op: "accept_v2", timeout_ms: 10000 });
    await assert.rejects(
      () =>
        client.connectV2({
          relayUrl: v2RelayUrl,
          targetPub: peerInit.relay_pub,
          expectedHost: "127.0.0.1",
          targetHostId: "webrtc-v2-node-test",
          grantJson: JSON.stringify(grant),
          useRelayV2: true,
          allowInsecureWs: true,
          autoUpgradeWebRtc: true,
        }),
      (err) => err.code === "host_key_unverified"
    );
    await peer.recv();
  } finally {
    globalThis.RTCPeerConnection = origRtc;
    client?.free();
    peer.close();
    relay.child.kill();
  }
});
