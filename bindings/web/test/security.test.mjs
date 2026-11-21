import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  MAX_QUEUED_BYTES,
  MAX_QUEUED_FRAMES,
  MAX_RELAY_FRAME_LEN,
  RelayStream,
  TendrilWebClient,
  WasmV2PakePairInitiator,
  WasmV2SessionInitiator,
  computeCodeMac,
  computeCodeMacBytes,
  computeCodeMacWorker,
  computeRelayAuthHmacB64,
  deriveV2RelayDial,
  dialIrohStream,
  dialRelayStream,
  dialRelayV2Stream,
  initTendril,
  v2EpochWithinSkew,
  validateRelayWsUrl,
} from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = path.resolve(__dirname, "..");
const REPO_ROOT = path.resolve(WEB_ROOT, "..", "..");
const RELAY_BIN = path.join(REPO_ROOT, "target", "debug", "tendril-relay");
const PEER_BIN = path.join(REPO_ROOT, "target", "debug", "tendril-conformance-peer");
const SERVER_SCRIPT = path.join(WEB_ROOT, "demo", "server.mjs");
const WASM_PATH = path.join(WEB_ROOT, "pkg", "tendril_wasm_bg.wasm");

let wasmReady = false;
async function ensureWasm() {
  if (!wasmReady) {
    const bytes = fs.readFileSync(WASM_PATH);
    await initTendril({ module_or_path: bytes });
    wasmReady = true;
  }
}

function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
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
      acc += stripAnsi(chunk.toString("utf8"));
      const m = acc.match(/ws:\/\/127\.0\.0\.1:(\d+)\/v1\/relay/);
      if (m) {
        clearTimeout(timer);
        resolve({ child, wsUrl: m[0], port: Number(m[1]) });
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`tendril-relay exited early (${code}): ${acc}`));
    });
  });
}

function spawnPeer() {
  const child = spawn(PEER_BIN, [], { stdio: ["pipe", "pipe", "inherit"] });
  const rl = readline.createInterface({ input: child.stdout });
  const lines = [];
  const waiters = [];
  rl.on("line", (line) => {
    const parsed = JSON.parse(line);
    if (waiters.length > 0) {
      waiters.shift()(parsed);
    } else {
      lines.push(parsed);
    }
  });
  return {
    send(cmd) {
      child.stdin.write(`${JSON.stringify(cmd)}\n`);
    },
    recv() {
      if (lines.length > 0) {
        return Promise.resolve(lines.shift());
      }
      return new Promise((resolve) => waiters.push(resolve));
    },
    async call(cmd) {
      this.send(cmd);
      const res = await this.recv();
      if (!res.ok) {
        throw new Error(`peer ${cmd.op} failed: ${JSON.stringify(res)}`);
      }
      return res;
    },
    close() {
      rl.close();
      child.kill();
    },
  };
}

function spawnDemoServer({ relayHost, relayPort, demoConfigFile = null }) {
  return new Promise((resolve, reject) => {
    const args = [SERVER_SCRIPT, "--listen", "127.0.0.1:0"];
    if (relayHost && relayPort) {
      args.push("--relay-upstream", `${relayHost}:${relayPort}`);
    }
    if (demoConfigFile) {
      args.push("--demo-config", demoConfigFile);
    }
    const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "pipe"] });
    let acc = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`demo server timed out: ${acc}`));
    }, 10000);
    child.stdout.on("data", (chunk) => {
      acc += chunk.toString("utf8");
      const m = acc.match(/listening=(http:\/\/127\.0\.0\.1:(\d+))/);
      if (m) {
        clearTimeout(timer);
        resolve({ child, baseUrl: m[1], port: Number(m[2]) });
      }
    });
    child.stderr.on("data", (d) => {
      acc += d.toString("utf8");
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`demo server exited early (${code}): ${acc}`));
    });
  });
}

function sendRawTcpRequest(port, rawRequest) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, "127.0.0.1");
    let response = Buffer.alloc(0);
    sock.on("connect", () => {
      sock.write(rawRequest);
    });
    sock.on("data", (chunk) => {
      response = Buffer.concat([response, chunk]);
      const text = response.toString("utf8");
      if (text.includes("\r\n\r\n")) {
        sock.end();
      }
    });
    sock.on("end", () => resolve(response.toString("utf8")));
    sock.on("error", reject);
  });
}

test("SEC-14 validateRelayWsUrl enforces wss, SSRF, userinfo, fragment, and control char checks", () => {
  assert.throws(() => validateRelayWsUrl("http://relay.example.com/v1/relay"), /ws:\/\/ or wss:\/\//);
  assert.throws(() => validateRelayWsUrl("javascript:alert(1)"), /ws:\/\/ or wss:\/\//);
  assert.throws(() => validateRelayWsUrl("file:" + "///etc/passwd"), /ws:\/\/ or wss:\/\//);
  assert.throws(() => validateRelayWsUrl("ws://127.0.0.1:8080/v1/relay\r\n"), /control characters/);
  assert.throws(() => validateRelayWsUrl("wss://relay.example.com/v1/relay\0"), /control characters/);
  assert.throws(() => validateRelayWsUrl(" \nwss://relay.example.com/v1/relay"), /control characters/);
  assert.throws(() => validateRelayWsUrl("wss://user:pass@relay.example.com/v1/relay"), /userinfo/);
  assert.throws(() => validateRelayWsUrl("wss://relay.example.com/v1/relay#frag"), /fragments/);
  assert.throws(() => validateRelayWsUrl("wss://relay.example.com/v1/relay#"), /fragments/);

  for (const blocked of [
    "wss://169.254.169.254/latest/meta-data",
    "wss://metadata.google.internal/computeMetadata/v1",
    "wss://metadata.google.internal./computeMetadata/v1",
    "wss://[::ffff:169.254.169.254]/v1/relay",
    "wss://[::ffff:a9fe:a9fe]/v1/relay",
    "wss://[fe80::1]/v1/relay",
    "wss://[fd00:ec2::254]/v1/relay",
    "wss://0.0.0.0/v1/relay",
    "wss://[::]/v1/relay",
    "wss://0xa9fea9fe/v1/relay",
  ]) {
    assert.throws(() => validateRelayWsUrl(blocked), /metadata|link-local|not permitted/i, blocked);
  }

  assert.throws(() => validateRelayWsUrl("ws://relay.example.com/v1/relay"), /allowInsecureWs/);
  assert.equal(
    validateRelayWsUrl("ws://relay.example.com/v1/relay", true).bareHost,
    "relay.example.com"
  );
  assert.equal(validateRelayWsUrl("wss://relay.example.com/v1/relay").bareHost, "relay.example.com");
  for (const loopback of [
    "ws://127.0.0.1:8080/v1/relay",
    "ws://localhost:8080/v1/relay",
    "ws://app.localhost:8080/v1/relay",
    "ws://[::1]:8080/v1/relay",
    "ws://[::ffff:127.0.0.1]:8080/v1/relay",
  ]) {
    assert.ok(validateRelayWsUrl(loopback).url.startsWith("ws://"), loopback);
  }
});

test("SEC-21 RelayStream enforces byte/frame caps, drops post-close frames, and clears queue on close", async () => {
  const closeCalls = [];
  const fakeWs = {
    readyState: 1,
    close(code, reason) {
      closeCalls.push({ code, reason });
    },
    send() {},
  };

  assert.equal(MAX_QUEUED_BYTES, 16 * MAX_RELAY_FRAME_LEN);
  assert.equal(MAX_QUEUED_FRAMES, 256);

  const bounded = new RelayStream(fakeWs, 100);
  bounded._pushFrame(new Uint8Array(60));
  bounded._pushFrame(new Uint8Array(50));
  assert.deepEqual(closeCalls, [{ code: 1008, reason: "receive queue overflow" }]);
  await assert.rejects(() => bounded.recv(10), /receive queue exceeded 100 bytes/);

  closeCalls.length = 0;
  const frameCapped = new RelayStream(fakeWs);
  for (let i = 0; i < MAX_QUEUED_FRAMES; i += 1) {
    frameCapped._pushFrame(new Uint8Array(1));
  }
  assert.equal(closeCalls.length, 0);
  frameCapped._pushFrame(new Uint8Array(1));
  assert.deepEqual(closeCalls, [{ code: 1008, reason: "receive queue overflow" }]);
  await assert.rejects(() => frameCapped.recv(10), /receive queue exceeded/);

  closeCalls.length = 0;
  const zeroFrame = new RelayStream(fakeWs);
  zeroFrame._pushFrame(new Uint8Array(0));
  assert.deepEqual(closeCalls, [{ code: 1002, reason: "empty binary frame" }]);
  await assert.rejects(() => zeroFrame.recv(10), /empty relay binary frame/);

  closeCalls.length = 0;
  const closable = new RelayStream(fakeWs);
  closable._pushFrame(new Uint8Array([1, 2, 3]));
  closable.close();
  closable._pushFrame(new Uint8Array([4, 5, 6]));
  assert.deepEqual(await closable.recv(10), { status: "eof" });
  assert.deepEqual(closeCalls, [{ code: 1000, reason: "closed" }]);
});

test("SEC-23 & SEC-27 demo/server.mjs emits security headers, 404s server.mjs, and validates WebSocket upgrades", async () => {
  const upstreamCaptured = [];
  const upstreamServer = net.createServer((sock) => {
    let acc = Buffer.alloc(0);
    sock.on("data", (chunk) => {
      acc = Buffer.concat([acc, chunk]);
      const str = acc.toString("utf8");
      const endIdx = str.indexOf("\r\n\r\n");
      if (endIdx >= 0) {
        upstreamCaptured.push(str.slice(0, endIdx + 4));
        sock.write(
          "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        );
        sock.end();
      }
    });
  });
  await new Promise((resolve) => upstreamServer.listen(0, "127.0.0.1", resolve));
  const upstreamPort = upstreamServer.address().port;

  let demoServer;
  try {
    demoServer = await spawnDemoServer({
      relayHost: "127.0.0.1",
      relayPort: upstreamPort,
    });

    for (const p of ["/", "/demo/app.js", "/demo-config.json", "/nonexistent"]) {
      const resp = await fetch(`${demoServer.baseUrl}${p}`);
      assert.equal(resp.headers.get("x-frame-options"), "DENY", p);
      assert.equal(resp.headers.get("referrer-policy"), "no-referrer", p);
      assert.equal(resp.headers.get("x-content-type-options"), "nosniff", p);
      assert.equal(resp.headers.get("cache-control"), "no-store", p);
      const csp = resp.headers.get("content-security-policy") || "";
      assert.ok(csp.includes("frame-ancestors 'none'"), p);
      assert.ok(csp.includes("'wasm-unsafe-eval'"), p);
    }

    const leakedSource = await fetch(`${demoServer.baseUrl}/demo/server.mjs`);
    assert.equal(leakedSource.status, 404);

    const validKey = "dGhlIHNhbXBsZSBub25jZQ==";
    const badUpgrades = [
      `GET /v1/relay?leak=1 HTTP/1.1\r\nHost: 127.0.0.1:${demoServer.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${validKey}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
      `GET /other HTTP/1.1\r\nHost: 127.0.0.1:${demoServer.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${validKey}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
      `GET /v1/relay HTTP/1.1\r\nHost: 127.0.0.1:${demoServer.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: not-valid-key\r\nSec-WebSocket-Version: 13\r\n\r\n`,
      `GET /v1/relay HTTP/1.1\r\nHost: 127.0.0.1:${demoServer.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${validKey}\r\nSec-WebSocket-Version: 12\r\n\r\n`,
      `GET /v1/relay HTTP/1.1\r\nHost: 127.0.0.1:${demoServer.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${validKey}\r\nSec-WebSocket-Version: 13\r\nContent-Length: 5\r\n\r\n`,
      `GET /v1/relay HTTP/1.1\r\nHost: 127.0.0.1:${demoServer.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${validKey}\r\nSec-WebSocket-Version: 13\r\nTransfer-Encoding: chunked\r\n\r\n`,
      `GET /v1/relay HTTP/1.1\r\nHost: 127.0.0.1:${demoServer.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${validKey}\r\nSec-WebSocket-Version: 13\r\n\r\nSMUGGLED`,
    ];
    for (const raw of badUpgrades) {
      const resp = await sendRawTcpRequest(demoServer.port, raw);
      assert.ok(resp.startsWith("HTTP/1.1 400 ") || resp.startsWith("HTTP/1.1 404 "), resp);
    }
    assert.equal(upstreamCaptured.length, 0);

    const goodUpgrade =
      `GET /v1/relay HTTP/1.1\r\n` +
      `Host: 127.0.0.1:${demoServer.port}\r\n` +
      `Upgrade: websocket\r\n` +
      `Connection: Upgrade\r\n` +
      `Sec-WebSocket-Key: ${validKey}\r\n` +
      `Sec-WebSocket-Version: 13\r\n` +
      `X-Forwarded-For: 203.0.113.10\r\n` +
      `Cookie: session=secret\r\n\r\n`;
    const okResp = await sendRawTcpRequest(demoServer.port, goodUpgrade);
    assert.ok(okResp.startsWith("HTTP/1.1 101 "), okResp);
    assert.equal(upstreamCaptured.length, 1);
    assert.match(upstreamCaptured[0], /^GET \/v1\/relay HTTP\/1\.1\r\n/);
    assert.doesNotMatch(upstreamCaptured[0], /X-Forwarded-For:/i);
    assert.doesNotMatch(upstreamCaptured[0], /Cookie:/i);
  } finally {
    if (demoServer) demoServer.child.kill();
    upstreamServer.close();
  }
});

test("SEC-18, SEC-22, and SEC-33 live WASM client/session concurrency, persistence failure, and free safety", async () => {
  await ensureWasm();

  const relay = await spawnRelay();
  const peer = spawnPeer();
  const mitmSockets = [];
  const mitmServer = net.createServer((clientSock) => {
    const upstream = net.connect(relay.port, "127.0.0.1");
    mitmSockets.push({ clientSock, upstream });
    clientSock.pipe(upstream);
    upstream.pipe(clientSock);
    clientSock.on("error", () => upstream.destroy());
    upstream.on("error", () => clientSock.destroy());
  });
  await new Promise((resolve) => mitmServer.listen(0, "127.0.0.1", resolve));
  const mitmPort = mitmServer.address().port;
  const mitmWsUrl = `ws://127.0.0.1:${mitmPort}/v1/relay`;

  try {
    const peerInit = await peer.call({ op: "init", host_id: "sec-host" });
    await peer.call({
      op: "serve_relay",
      relay_url: relay.wsUrl,
      expected_host: "127.0.0.1",
    });

    // SEC-22: pair(), removePendingPeer(), and confirmPeer() roll back in-memory roster if onPersistRoster fails.
    let failPersist = true;
    const client = await TendrilWebClient.create({
      hostId: "sec-client",
      onPersistRoster: async () => {
        if (failPersist) {
          throw new Error("storage quota exceeded");
        }
      },
    });

    const code1 = (await peer.call({ op: "issue_code", kind: "remote" })).code;
    const peerPair1 = peer.call({ op: "pair" });
    await assert.rejects(
      () =>
        client.pair({
          relayUrl: relay.wsUrl,
          targetPub: peerInit.relay_pub,
          expectedHost: "127.0.0.1",
          code: code1,
        }),
      /storage quota exceeded/
    );
    await peerPair1;
    assert.equal(client.getPeer("sec-host"), null);

    failPersist = false;
    const code2 = (await peer.call({ op: "issue_code", kind: "remote" })).code;
    const peerPair2 = peer.call({ op: "pair" });
    const paired = await client.pair({
      relayUrl: relay.wsUrl,
      targetPub: peerInit.relay_pub,
      expectedHost: "127.0.0.1",
      code: code2,
    });
    const hostPair = await peerPair2;
    assert.equal(paired.sas, hostPair.sas);
    assert.equal(client.getPeer("sec-host")?.state, "pending");

    failPersist = true;
    await assert.rejects(
      () => client.removePendingPeer("sec-host"),
      /storage quota exceeded/
    );
    assert.equal(client.getPeer("sec-host")?.state, "pending");

    await assert.rejects(
      () => client.confirmPeer("sec-host", paired.sas),
      /storage quota exceeded/
    );
    assert.equal(client.getPeer("sec-host")?.state, "pending");

    failPersist = false;
    await client.confirmPeer("sec-host", paired.sas);
    assert.equal(client.getPeer("sec-host")?.state, "active");

    await peer.call({ op: "confirm", peer_id: hostPair.device_id, sas: hostPair.sas });
    const grantObj = (
      await peer.call({ op: "mint", peer_id: hostPair.device_id, caps: ["fs.read"] })
    ).grant;

    // SEC-18: concurrent sendData (forced multi-chunk) + ping() serialize without interleaving.
    const connectPeer = peer.call({ op: "connect" });
    const session1 = await client.connect({
      relayUrl: mitmWsUrl,
      targetPub: peerInit.relay_pub,
      expectedHost: "127.0.0.1",
      targetHostId: "sec-host",
      grantJson: JSON.stringify(grantObj),
    });
    await connectPeer;
    const activeMitm = mitmSockets[mitmSockets.length - 1];

    const origMaxFrame = RelayStream.prototype.maxFrame;
    const origSend = RelayStream.prototype.send;
    const sendLog = [];
    RelayStream.prototype.maxFrame = function patchedMaxFrame() {
      return 16;
    };
    RelayStream.prototype.send = async function patchedSend(bytes) {
      sendLog.push(bytes.byteLength);
      await new Promise((r) => setTimeout(r, 2));
      return origSend.call(this, bytes);
    };
    try {
      await Promise.all([
        session1.sendData("A".repeat(80)),
        session1.ping(88),
        session1.sendData("B".repeat(20)),
      ]);
      // Three serialized transmissions with 16-byte chunks: each ends with a single <16 tail chunk.
      const tailIndices = sendLog
        .map((n, idx) => (n < 16 ? idx : -1))
        .filter((idx) => idx >= 0);
      assert.equal(tailIndices.length, 3, `unexpected chunk layout: ${JSON.stringify(sendLog)}`);
      assert.equal(tailIndices[2], sendLog.length - 1);
      const chunk0Sum = sendLog.slice(0, tailIndices[0] + 1).reduce((a, b) => a + b, 0);
      const chunk1Sum = sendLog
        .slice(tailIndices[0] + 1, tailIndices[1] + 1)
        .reduce((a, b) => a + b, 0);
      const chunk2Sum = sendLog
        .slice(tailIndices[1] + 1, tailIndices[2] + 1)
        .reduce((a, b) => a + b, 0);
      assert.ok(chunk0Sum > 80 && chunk1Sum < chunk2Sum && chunk2Sum > 20);
    } finally {
      RelayStream.prototype.maxFrame = origMaxFrame;
      RelayStream.prototype.send = origSend;
    }

    const r1 = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(r1.data_utf8, "A".repeat(80));
    const r2 = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(r2.data_utf8, "B".repeat(20));

    let gotPong = false;
    for (let i = 0; i < 4; i += 1) {
      const ev = await session1.pollEvent(500);
      if (ev.event === "pong" && ev.cookie === 88) {
        gotPong = true;
        break;
      }
    }
    assert.equal(gotPong, true);

    // SEC-22: roster persistence error during pollEvent() error path locks session fail-closed.
    failPersist = true;
    activeMitm.upstream.unpipe(activeMitm.clientSock);
    // Unmasked server->client RFC 6455 binary frame carrying bogus ciphertext bytes.
    activeMitm.clientSock.write(Buffer.from([0x82, 0x06, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]));
    await assert.rejects(() => session1.pollEvent(2000), /failed to persist roster update/);
    assert.throws(() => session1.authorize("fs.read"), /session locked after roster persistence failure/);
    assert.throws(() => session1.sendData("late"), /session locked after roster persistence failure/);
    await session1.close(1000, "locked");

    // SEC-33: client.free() while a session is active never traps WASM with null pointer passed to rust.
    failPersist = false;
    const peer2 = spawnPeer();
    try {
      const init2 = await peer2.call({ op: "init", host_id: "sec-host-2" });
      await peer2.call({
        op: "serve_relay",
        relay_url: relay.wsUrl,
        expected_host: "127.0.0.1",
      });
      const c2 = (await peer2.call({ op: "issue_code", kind: "remote" })).code;
      const pp2 = peer2.call({ op: "pair" });
      const b2 = await client.pair({
        relayUrl: relay.wsUrl,
        targetPub: init2.relay_pub,
        expectedHost: "127.0.0.1",
        code: c2,
      });
      const hp2 = await pp2;
      await client.confirmPeer("sec-host-2", b2.sas);
      await peer2.call({ op: "confirm", peer_id: hp2.device_id, sas: hp2.sas });
      const g2 = (
        await peer2.call({ op: "mint", peer_id: hp2.device_id, caps: ["fs.read"] })
      ).grant;
      const cp2 = peer2.call({ op: "connect" });
      const sess2 = await client.connect({
        relayUrl: relay.wsUrl,
        targetPub: init2.relay_pub,
        expectedHost: "127.0.0.1",
        targetHostId: "sec-host-2",
        grantJson: JSON.stringify(g2),
      });
      await cp2;

      const pendingPoll = sess2.pollEvent(5000);
      client.free();
      assert.equal(sess2.isClosed(), true);
      assert.throws(() => sess2.authorize("fs.read"), (e) => !/null pointer/i.test(e.message));
      assert.throws(() => sess2.tick(), (e) => !/null pointer/i.test(e.message));
      assert.throws(() => sess2.sendData("hi"), (e) => !/null pointer/i.test(e.message));
      assert.throws(() => sess2.pollEvent(10), (e) => !/null pointer/i.test(e.message));
      const polled = await pendingPoll;
      assert.equal(polled.status, "eof");
      assert.throws(() => client.info(), /freed/);
    } finally {
      peer2.close();
    }
  } finally {
    for (const pair of mitmSockets) {
      pair.clientSock.destroy();
      pair.upstream.destroy();
    }
    mitmServer.close();
    peer.close();
    relay.child.kill();
  }
});

test("computeCodeMacBytes matches computeCodeMac and zeroes caller buffer", async () => {
  await ensureWasm();
  const hh = new Uint8Array(32).fill(0x5a);
  const expected = computeCodeMac("TND-4829-1704", hh);
  const rawCode = new TextEncoder().encode("TND-4829-1704");
  const actual = computeCodeMacBytes(rawCode, hh);
  assert.deepEqual(actual, expected);
  assert.deepEqual(rawCode, new Uint8Array(rawCode.length));
});

test("computeCodeMacWorker handles timeout and messageerror with termination", async () => {
  await ensureWasm();
  const hh = new Uint8Array(32).fill(0x33);
  const savedWorker = globalThis.Worker;
  let terminatedCount = 0;

  class HangingWorker {
    constructor() {
      this.listeners = new Map();
    }
    addEventListener(name, fn) {
      if (!this.listeners.has(name)) {
        this.listeners.set(name, []);
      }
      this.listeners.get(name).push(fn);
    }
    postMessage(msg) {
      assert.ok(msg.codeBytes instanceof Uint8Array);
      assert.equal(msg.op, "compute_code_mac");
    }
    terminate() {
      terminatedCount += 1;
    }
  }

  class MessageErrorWorker extends HangingWorker {
    postMessage() {
      queueMicrotask(() => {
        for (const fn of this.listeners.get("messageerror") || []) {
          fn({});
        }
      });
    }
  }

  class ThrowingWorker extends HangingWorker {
    postMessage() {
      throw new Error("sync postMessage failed");
    }
  }

  try {
    globalThis.Worker = HangingWorker;
    const rawTimeout = new TextEncoder().encode("TND-AAAA-BBBB");
    await assert.rejects(
      () => computeCodeMacWorker(rawTimeout, hh, { timeoutMs: 25 }),
      /timed out after 25 ms/
    );
    assert.deepEqual(rawTimeout, new Uint8Array(rawTimeout.length));

    globalThis.Worker = MessageErrorWorker;
    await assert.rejects(
      () => computeCodeMacWorker("TND-AAAA-BBBB", hh, { timeoutMs: 5000 }),
      /worker message deserialization failed/
    );

    globalThis.Worker = ThrowingWorker;
    const rawThrow = new TextEncoder().encode("TND-CCCC-DDDD");
    await assert.rejects(
      () => computeCodeMacWorker(rawThrow, hh, { timeoutMs: 15000 }),
      /sync postMessage failed/
    );
    assert.deepEqual(rawThrow, new Uint8Array(rawThrow.length));
    assert.equal(terminatedCount, 3);
  } finally {
    globalThis.Worker = savedWorker;
  }
});

test("TendrilWebClient M2M enrollment over WSS relay, single-use replay, and anchor revocation", async () => {
  await ensureWasm();
  const relay = await spawnRelay();
  const peer = spawnPeer();
  try {
    const hostInit = await peer.call({ op: "init", host_id: "web-m2m-host" });
    await peer.call({
      op: "serve_relay",
      relay_url: relay.wsUrl,
      expected_host: "127.0.0.1",
    });

    let persistedCount = 0;
    const anchorClient = await TendrilWebClient.create({ hostId: "web-m2m-anchor" });
    const client = await TendrilWebClient.create({
      hostId: "web-m2m-cli",
      onPersistRoster: () => {
        persistedCount += 1;
      },
    });
    const cli2 = await TendrilWebClient.create({ hostId: "web-m2m-cli2" });

    try {
      const anchorInfo = anchorClient.info();
      await peer.call({
        op: "add_trust_anchor",
        anchor_id: "web-m2m-anchor",
        signing_pub: anchorInfo.signing_pub,
      });
      const beforePersist = persistedCount;
      await client.addTrustAnchor("web-m2m-anchor", anchorInfo.signing_pub);
      assert.equal(persistedCount, beforePersist + 1);
      const addedRoster = JSON.parse(client.exportRosterJson());
      assert.equal(addedRoster.trust_anchors["web-m2m-anchor"].state, "active");
      await client.revokeTrustAnchor("web-m2m-anchor");
      assert.equal(persistedCount, beforePersist + 2);
      const revokedRoster = JSON.parse(client.exportRosterJson());
      assert.equal(revokedRoster.trust_anchors["web-m2m-anchor"].state, "revoked");

      const tokenJson = anchorClient.mintEnrollmentToken({
        targetHostId: "web-m2m-host",
        ttlSecs: 900,
      });

      const pairP = peer.call({ op: "pair" });
      const enrollRes = await client.enroll({
        relayUrl: relay.wsUrl,
        targetPub: hostInit.relay_pub,
        expectedHost: "127.0.0.1",
        allowInsecureWs: true,
        hostId: "web-m2m-host",
        hostStaticPubB64: hostInit.static_pub,
        hostSigningPubB64: hostInit.signing_pub,
        tokenJson,
        deviceName: "web-worker",
        deviceKind: "machine",
      });
      const hostRes = await pairP;
      assert.equal(enrollRes.status, "active");
      assert.equal(hostRes.status, "active");
      assert.equal(enrollRes.device_id, hostRes.device_id);
      assert.equal(persistedCount, beforePersist + 3);

      const repPairP = peer.call({ op: "pair" }).catch(() => null);
      await assert.rejects(
        () =>
          client.enroll({
            relayUrl: relay.wsUrl,
            targetPub: hostInit.relay_pub,
            expectedHost: "127.0.0.1",
            allowInsecureWs: true,
            hostId: "web-m2m-host",
            hostStaticPubB64: hostInit.static_pub,
            hostSigningPubB64: hostInit.signing_pub,
            tokenJson,
          }),
        /token_replayed/
      );
      await repPairP;

      const grant = (
        await peer.call({ op: "mint", peer_id: hostRes.device_id, caps: ["fs.read"] })
      ).grant;
      const connP = peer.call({ op: "connect" });
      const sess = await client.connect({
        relayUrl: relay.wsUrl,
        targetPub: hostInit.relay_pub,
        expectedHost: "127.0.0.1",
        allowInsecureWs: true,
        targetHostId: "web-m2m-host",
        grantJson: JSON.stringify(grant),
      });
      await connP;
      assert.equal((await peer.call({ op: "authorize", cap: "fs.read" })).allowed, true);
      assert.equal((await peer.call({ op: "authorize", cap: "shell.exec" })).allowed, false);
      await sess.close(1000, "done");

      await peer.call({ op: "revoke_trust_anchor", anchor_id: "web-m2m-anchor" });
      const freshTok = anchorClient.mintEnrollmentToken({
        targetHostId: "web-m2m-host",
        ttlSecs: 900,
      });
      const revPairP = peer.call({ op: "pair" }).catch(() => null);
      await assert.rejects(
        () =>
          cli2.enroll({
            relayUrl: relay.wsUrl,
            targetPub: hostInit.relay_pub,
            expectedHost: "127.0.0.1",
            allowInsecureWs: true,
            hostId: "web-m2m-host",
            hostStaticPubB64: hostInit.static_pub,
            hostSigningPubB64: hostInit.signing_pub,
            tokenJson: freshTok,
          }),
        /unauthorized/
      );
      await revPairP;

      const selfTok = (
        await peer.call({
          op: "mint_enrollment_token",
          target_host_id: "web-m2m-host",
          ttl_secs: 900,
        })
      ).token_json;
      const revPairP2 = peer.call({ op: "pair" }).catch(() => null);
      await assert.rejects(
        () =>
          cli2.enroll({
            relayUrl: relay.wsUrl,
            targetPub: hostInit.relay_pub,
            expectedHost: "127.0.0.1",
            allowInsecureWs: true,
            hostId: "web-m2m-host",
            hostStaticPubB64: hostInit.static_pub,
            hostSigningPubB64: hostInit.signing_pub_hash,
            tokenJson: freshTok,
          }),
        /untrusted_anchor/
      );
      await revPairP2;

      const selfPairP = peer.call({ op: "pair" });
      const selfEnrollRes = await cli2.enroll({
        relayUrl: relay.wsUrl,
        targetPub: hostInit.relay_pub,
        expectedHost: "127.0.0.1",
        allowInsecureWs: true,
        hostId: "web-m2m-host",
        hostStaticPubB64: hostInit.static_pub,
        hostSigningPubB64: hostInit.signing_pub_hash,
        tokenJson: selfTok,
        deviceName: "web-worker-2",
        deviceKind: "machine",
      });
      const selfHostRes = await selfPairP;
      assert.equal(selfEnrollRes.status, "active");
      assert.equal(selfHostRes.status, "active");
    } finally {
      cli2.free();
      client.free();
      anchorClient.free();
    }
  } finally {
    peer.close();
    relay.child.kill();
  }
});

function encodeWsTextFrame(text) {
  const payload = Buffer.from(text, "utf8");
  if (payload.length < 126) {
    return Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
  }
  const hdr = Buffer.alloc(4);
  hdr[0] = 0x81;
  hdr[1] = 126;
  hdr.writeUInt16BE(payload.length, 2);
  return Buffer.concat([hdr, payload]);
}

function decodeWsClientFrame(buf) {
  if (buf.length < 2) return null;
  const opcode = buf[0] & 0x0f;
  const lenByte = buf[1] & 0x7f;
  const masked = (buf[1] & 0x80) !== 0;
  let offset = 2;
  let payloadLen = lenByte;
  if (lenByte === 126) {
    if (buf.length < 4) return null;
    payloadLen = buf.readUInt16BE(2);
    offset = 4;
  }
  const maskLen = masked ? 4 : 0;
  if (buf.length < offset + maskLen + payloadLen) return null;
  if (opcode === 0x08) {
    return { close: true };
  }
  const out = Buffer.alloc(payloadLen);
  if (masked) {
    const mask = buf.subarray(offset, offset + 4);
    offset += 4;
    for (let i = 0; i < payloadLen; i += 1) {
      out[i] = buf[offset + i] ^ mask[i % 4];
    }
  } else {
    buf.copy(out, 0, offset, offset + payloadLen);
  }
  return { close: false, text: out.toString("utf8") };
}

function startMockRelayWsServer(onDial) {
  return new Promise((resolve) => {
    const seenUrls = [];
    const sockets = new Set();
    const server = http.createServer();
    server.on("upgrade", (req, socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
      socket.on("error", () => {});
      seenUrls.push(req.url || "");
      const key = req.headers["sec-websocket-key"];
      const accept = crypto
        .createHash("sha1")
        .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
        .digest("base64");
      socket.write(
        "HTTP/1.1 101 Switching Protocols\r\n" +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
      );
      const { challenge, handleDial } = onDial(req.url || "");
      socket.write(encodeWsTextFrame(JSON.stringify(challenge)));
      let acc = Buffer.alloc(0);
      socket.on("data", (chunk) => {
        acc = Buffer.concat([acc, chunk]);
        const frame = decodeWsClientFrame(acc);
        if (frame !== null) {
          acc = Buffer.alloc(0);
          if (frame.close) {
            socket.end();
            return;
          }
          const reply = handleDial(JSON.parse(frame.text));
          if (reply) {
            socket.write(encodeWsTextFrame(JSON.stringify(reply)));
          }
        }
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve({
        port: addr.port,
        seenUrls,
        close: () =>
          new Promise((r) => {
            for (const s of sockets) {
              s.destroy();
            }
            server.closeAllConnections?.();
            server.close(r);
          }),
      });
    });
  });
}

test("mintRelayTicket, computeRelayAuthHmacB64 KAT + zeroization, and deriveV2RelayDial KAT", async () => {
  await ensureWasm();
  const vectors = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, "spec", "vectors", "wire_v2.json"), "utf8")
  );
  const client = await TendrilWebClient.create({ hostId: "web-ticket-test" });
  try {
    const info = client.info();
    const ticketJson = client.mintRelayTicket("Relay.Example.", "dial", "*", 900);
    const ticket = JSON.parse(ticketJson);
    assert.equal(ticket.v, 1);
    assert.equal(ticket.issuer_pub, info.relay_pub);
    assert.equal(ticket.relay_host, "relay.example");
    assert.equal(ticket.role, "dial");
    assert.equal(ticket.target_pub, "*");
    assert.ok(ticket.not_after - ticket.not_before === 900);
    assert.ok(typeof ticket.sig === "string" && ticket.sig.length > 0);

    // Known-answer check against spec/vectors/wire_v2.json relay_admission
    const ra = vectors.relay_admission;
    const katSecret = new Uint8Array(Buffer.from(ra.shared_secret_hex, "hex"));
    const katNonce = new Uint8Array(Buffer.from(ra.challenge_nonce_hex, "hex"));
    const katTarget = new Uint8Array(Buffer.from(ra.pub_or_target_hex, "hex"));
    const katMac = computeRelayAuthHmacB64(
      katSecret,
      ra.op,
      ra.relay_host_raw,
      katNonce,
      katTarget
    );
    assert.equal(katMac, ra.hmac_mac_b64url);
    assert.equal(katSecret.every((b) => b === 0), true, "KAT secret buffer must be zeroized");

    const badSecret = new Uint8Array(32).fill(0x55);
    assert.throws(() =>
      computeRelayAuthHmacB64(badSecret, "bad_op", "relay.example", katNonce, katTarget)
    );
    assert.equal(
      badSecret.every((b) => b === 0),
      true,
      "secret buffer must be zeroized on error too"
    );

    // Known-answer check against spec/vectors/wire_v2.json blinded_relay
    const br = vectors.blinded_relay;
    const mbSecret = new Uint8Array(Buffer.from(br.mailbox_secret_hex, "hex"));
    const brNonce = new Uint8Array(Buffer.from(br.challenge_nonce_hex, "hex"));
    const connId = new Uint8Array(Buffer.from(br.conn_id_hex, "hex"));
    const dial = deriveV2RelayDial(mbSecret, br.relay_host_raw, br.unix_secs, brNonce, connId);
    assert.equal(dial.mailbox_id, br.mailbox_id_b64url);
    assert.equal(dial.epoch, br.epoch);
    assert.equal(dial.dial_token, br.dial_token_b64url);
    assert.equal(v2EpochWithinSkew(dial.epoch, dial.epoch + 1), true);
    assert.equal(v2EpochWithinSkew(dial.epoch, dial.epoch + 2), false);
  } finally {
    client.free();
  }
});

test("p2pApiSecret is rejected across dialIrohStream and TendrilWebClient", async () => {
  await ensureWasm();
  const client = await TendrilWebClient.create({ hostId: "web-p2p-reject" });
  try {
    await assert.rejects(
      () =>
        dialIrohStream({
          endpoint: "iroh://invalid",
          p2pApiSecret: "raw-secret",
        }),
      /p2pApiSecret is not permitted/
    );
    await assert.rejects(
      () =>
        client.pair({
          endpoint: "iroh://invalid",
          code: "1234-5678",
          p2pApiSecret: "raw-secret",
        }),
      /p2pApiSecret is not permitted/
    );
    await assert.rejects(
      () =>
        client.pairV2({
          endpoint: "iroh://invalid",
          code: "1234-5678",
          p2pApiSecret: "raw-secret",
        }),
      /p2pApiSecret is not permitted/
    );
    await assert.rejects(
      () =>
        client.connect({
          endpoint: "iroh://invalid",
          targetHostId: "host-1",
          p2pApiSecret: "raw-secret",
        }),
      /p2pApiSecret is not permitted/
    );
    await assert.rejects(
      () =>
        client.connectV2({
          endpoint: "iroh://invalid",
          targetHostId: "host-1",
          p2pApiSecret: "raw-secret",
        }),
      /p2pApiSecret is not permitted/
    );

    const tokenBuf = new TextEncoder().encode("scoped-p2p-token");
    await assert.rejects(() =>
      dialIrohStream({
        endpoint: "iroh://not-a-valid-endpoint-id",
        p2pRelayAuthToken: tokenBuf,
      })
    );
    assert.equal(tokenBuf.every((b) => b === 0), true, "p2pRelayAuthToken buffer must be zeroized");
  } finally {
    client.free();
  }
});

test("dialRelayStream and dialRelayV2Stream enforce dial auth, zeroize secrets, and reject skew/static dialToken", async () => {
  await ensureWasm();
  const nonceBytes = new Uint8Array(32).fill(0x99);
  const nonceB64 = Buffer.from(nonceBytes).toString("base64url");
  const targetPub = Buffer.from(new Uint8Array(32).fill(0xaa)).toString("base64url");
  const serverEpoch = Math.floor(Date.now() / 1000 / 3600);
  const dialMessages = [];
  let mode = "auth_all";

  const mock = await startMockRelayWsServer((reqUrl) => {
    const isV2 = reqUrl.startsWith("/v2/relay");
    const authRequired = mode === "register_only" ? ["register"] : ["register", "dial"];
    return {
      challenge: isV2
        ? {
            op: "challenge",
            host: "127.0.0.1",
            nonce: nonceB64,
            epoch: serverEpoch,
            max_frame: MAX_RELAY_FRAME_LEN,
            auth_required: authRequired,
          }
        : {
            op: "challenge",
            host: "127.0.0.1",
            nonce: nonceB64,
            max_frame: MAX_RELAY_FRAME_LEN,
            auth_required: authRequired,
          },
      handleDial: (msg) => {
        dialMessages.push(msg);
        return { op: "ready", conn_id: msg.conn_id };
      },
    };
  });

  const client = await TendrilWebClient.create({ hostId: "web-ticket-dial" });
  try {
    // 1. Missing dial auth fails closed
    await assert.rejects(
      () =>
        dialRelayStream({
          relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
          targetPub,
          expectedHost: "127.0.0.1",
          allowInsecureWs: true,
        }),
      /relay requires dial authentication/
    );

    // 2. Empty or all-zero relayAuthSecret rejected
    await assert.rejects(
      () =>
        dialRelayStream({
          relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
          targetPub,
          expectedHost: "127.0.0.1",
          allowInsecureWs: true,
          relayAuthSecret: new Uint8Array(32),
        }),
      /empty or all-zero/
    );

    // 3. Zeroized on host mismatch failure
    const mismatchSecret = new TextEncoder().encode("mismatch-secret");
    await assert.rejects(
      () =>
        dialRelayStream({
          relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
          targetPub,
          expectedHost: "wrong.example",
          allowInsecureWs: true,
          relayAuthSecret: mismatchSecret,
        }),
      /host mismatch/
    );
    assert.equal(mismatchSecret.every((b) => b === 0), true, "secret must zeroize on host mismatch");

    // 4. HMAC dial path
    const secretBuf = new TextEncoder().encode("shared-hmac-secret");
    const s1 = await dialRelayStream({
      relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
      targetPub,
      expectedHost: "127.0.0.1",
      allowInsecureWs: true,
      relayAuthSecret: secretBuf,
    });
    assert.equal(secretBuf.every((b) => b === 0), true, "relayAuthSecret buffer must be zeroized");
    s1.close();
    assert.equal(dialMessages.at(-1).auth.kind, "hmac");
    assert.ok(typeof dialMessages.at(-1).auth.mac === "string");

    // 5. Ticket dial path
    const ticketJson = client.mintRelayTicket("127.0.0.1", "dial", targetPub, 900);
    const sTicket = await dialRelayStream({
      relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
      targetPub,
      expectedHost: "127.0.0.1",
      allowInsecureWs: true,
      relayAuthTicket: ticketJson,
    });
    sTicket.close();
    assert.equal(dialMessages.at(-1).auth.kind, "ticket");
    assert.equal(dialMessages.at(-1).auth.ticket.target_pub, targetPub);

    // 6. auth_required: ["register"] sends NO dial auth, and still zeroes relayAuthSecret
    mode = "register_only";
    const unusedSecret = new TextEncoder().encode("unused-when-register-only");
    const sRegOnly = await dialRelayStream({
      relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
      targetPub,
      expectedHost: "127.0.0.1",
      allowInsecureWs: true,
      relayAuthSecret: unusedSecret,
    });
    sRegOnly.close();
    assert.equal(dialMessages.at(-1).auth, undefined, "must not send auth when dial not required");
    assert.equal(unusedSecret.every((b) => b === 0), true);
    mode = "auth_all";

    // 7. dialRelayV2Stream rejects static dialToken without deriveV2Dial
    await assert.rejects(
      () =>
        dialRelayV2Stream({
          relayUrl: `ws://127.0.0.1:${mock.port}/v2/relay`,
          targetMailboxId: targetPub,
          epoch: serverEpoch,
          dialToken: "static-token",
          expectedHost: "127.0.0.1",
          allowInsecureWs: true,
        }),
      /requires a deriveV2Dial callback/
    );

    // 8. dialRelayV2Stream rejects out-of-skew epoch
    const mbSecret = new Uint8Array(32).fill(0x31);
    await assert.rejects(
      () =>
        dialRelayV2Stream({
          relayUrl: `ws://127.0.0.1:${mock.port}/v2/relay`,
          expectedHost: "127.0.0.1",
          allowInsecureWs: true,
          relayAuthTicket: ticketJson,
          deriveV2Dial: ({ relayHost, nonceBytes: n, connIdBytes }) =>
            deriveV2RelayDial(mbSecret, relayHost, (serverEpoch + 3) * 3600, n, connIdBytes),
        }),
      /epoch out of skew/
    );

    // 9. dialRelayV2Stream valid path
    const v2Secret = new TextEncoder().encode("v2-hmac-secret");
    const s2 = await dialRelayV2Stream({
      relayUrl: `ws://127.0.0.1:${mock.port}/v2/relay`,
      expectedHost: "127.0.0.1",
      allowInsecureWs: true,
      relayAuthSecret: v2Secret,
      deriveV2Dial: ({ relayHost, nonceBytes: n, connIdBytes }) =>
        deriveV2RelayDial(mbSecret, relayHost, serverEpoch * 3600, n, connIdBytes),
    });
    assert.equal(v2Secret.every((b) => b === 0), true);
    s2.close();

    const v2Dial = dialMessages.at(-1);
    assert.equal(v2Dial.op, "dial");
    assert.equal(v2Dial.epoch, serverEpoch);
    assert.ok(typeof v2Dial.target_mailbox_id === "string");
    assert.ok(typeof v2Dial.dial_token === "string");
    assert.equal(v2Dial.auth.kind, "hmac");

    for (const url of mock.seenUrls) {
      assert.equal(url.includes("token="), false, "URL must never contain query tokens");
    }
  } finally {
    client.free();
    await mock.close();
  }
});

test("WasmV2PakePairInitiator emits v2 PAKE preamble and connectV2 fails closed without v2 peer", async () => {
  await ensureWasm();
  const vectors = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, "spec", "vectors", "wire_v2.json"), "utf8")
  );
  const client = await TendrilWebClient.create({ hostId: "web-v2-init" });
  try {
    assert.equal(client.pairingFloor(new Uint8Array(32).fill(0x01)), 1);
    assert.throws(() => client.peerV2Summary("missing-host"));

    await assert.rejects(
      () =>
        client.connectV2({
          relayUrl: "ws://127.0.0.1:1/v1/relay",
          targetHostId: "missing-host",
          allowInsecureWs: true,
        }),
      /peer not found/
    );

    // Verify WasmV2PakePairInitiator emits the exact v2 PAKE preamble from spec/vectors/wire_v2.json
    // followed by a valid length-prefixed Noise msg1 frame, and fails closed on empty/bad input.
    const { WasmIdentity, WasmRoster } = await import("../pkg/tendril_wasm.js");
    const id = WasmIdentity.generate("web-v2-pake");
    const roster = new WasmRoster();
    const pairInit = new WasmV2PakePairInitiator(id, "web", "browser", "4829-1704", null);
    try {
      const msg1 = pairInit.start();
      const expectedPre = Buffer.from(vectors.v2_pake_pair_preamble_hex, "hex");
      assert.equal(
        Buffer.from(msg1.subarray(0, expectedPre.length)).equals(expectedPre),
        true,
        "v2 PAKE start() must emit exact v2_pake_pair_preamble_hex"
      );
      assert.ok(msg1.length > expectedPre.length + 2);
      assert.throws(() => pairInit.start(), /already started/);
      assert.throws(() => pairInit.feed_bytes(new Uint8Array([0, 2, 0xff, 0xff]), roster));
    } finally {
      pairInit.free();
      roster.free();
      id.free();
    }
    assert.equal(typeof WasmV2SessionInitiator, "function");
  } finally {
    client.free();
  }
});

test("TendrilWebSession v2 tick() self-terminates when grant expires", async () => {
  await ensureWasm();
  const relay = await spawnRelay();
  const peer = spawnPeer();
  const client = await TendrilWebClient.create({ hostId: "web-v2-tick" });
  let sess = null;
  try {
    const init = await peer.call({ op: "init", host_id: "sec-v2-tick-host" });
    await peer.call({
      op: "serve_relay",
      relay_url: relay.wsUrl,
      expected_host: "127.0.0.1",
    });
    const code = (await peer.call({ op: "issue_code", kind: "remote" })).code;
    const pairPromise = peer.call({ op: "pair_v2_accept", timeout_ms: 10000 });
    const bound = await client.pairV2({
      relayUrl: relay.wsUrl,
      targetPub: init.relay_pub,
      expectedHost: "127.0.0.1",
      code,
      allowInsecureWs: true,
    });
    const hostBound = await pairPromise;
    await client.confirmPeer("sec-v2-tick-host", bound.sas);
    await peer.call({ op: "confirm", peer_id: hostBound.device_id, sas: hostBound.sas });

    const { grant } = await peer.call({
      op: "mint",
      peer_id: hostBound.device_id,
      caps: ["fs.read"],
      ttl_secs: 1,
    });
    const acceptPromise = peer.call({ op: "accept_v2", timeout_ms: 10000 });
    sess = await client.connectV2({
      relayUrl: relay.wsUrl,
      targetPub: init.relay_pub,
      expectedHost: "127.0.0.1",
      targetHostId: "sec-v2-tick-host",
      grantJson: JSON.stringify(grant),
      allowInsecureWs: true,
    });
    await acceptPromise;

    await new Promise((r) => setTimeout(r, 1500));
    await assert.rejects(() => sess.tick(), /expired|grant|closed/i);
    assert.equal(sess.isClosed(), true);
    assert.equal(sess.authorize("fs.read"), false);
    await assert.rejects(() => sess.sendData("late"), /closed/i);
  } finally {
    if (sess && !sess.isClosed()) {
      await sess.close(1000, "done").catch(() => {});
    }
    client.free();
    peer.close();
    relay.child.kill();
  }
});
