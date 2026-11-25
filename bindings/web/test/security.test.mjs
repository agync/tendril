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
  b64urlEncode,
  canonicalRelayHost,
  computeCodeMac,
  computeCodeMacBytes,
  computeCodeMacWorker,
  computeRelayAuthHmacB64,
  createIndexedDbVault,
  deriveV2RelayDial,
  dialIrohStream,
  dialBrokerStream,
  dialRelayStream,
  dialRelayV2Stream,
  dialWtStream,
  initTendril,
  initTendrilP2p,
  openTendrilVault,
  v2EpochWithinSkew,
  validateBrokerWsUrl,
  validateRelayWsUrl,
  validateWtUrl,
} from "../src/index.js";
import { redactHint } from "../src/redact.js";
import "./webrtc.test.mjs";

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

test("raw endpoint and relay URL errors never echo pairing codes or tokens", async () => {
  await ensureWasm();
  const leaks = ["tnd-", "AAAA-BBBB", "abcd-efgh", "code=", "s3cretTok"];
  const check = (re) => (err) => {
    assert.match(err.message, re);
    for (const leak of leaks) {
      assert.ok(!err.message.includes(leak), `leaked ${leak}: ${err.message}`);
    }
    return true;
  };
  for (const endpoint of [
    "tendril://pair?code=tnd-AAAA-BBBB-CCCC",
    "abcd-efgh",
    "",
    undefined,
  ]) {
    await assert.rejects(dialIrohStream({ endpoint }), check(/must start with iroh:\/\//));
  }
  for (const url of [
    "tendril://pair?code=tnd-AAAA-BBBB-CCCC",
    "http://abcd-efgh.example/",
    "http://example.com/pair?token=s3cretTok",
  ]) {
    assert.throws(() => validateRelayWsUrl(url), check(/ws:\/\/ or wss:\/\//));
    assert.throws(() => validateBrokerWsUrl(url), check(/ws:\/\/ or wss:\/\//));
    assert.throws(
      () => validateBrokerWsUrl(`broker+${url}`),
      check(/broker\+ws\(s\):\/\/ or ws\(s\):\/\//)
    );
  }
  assert.throws(
    () => validateRelayWsUrl("not a url tnd-AAAA-BBBB-CCCC"),
    check(/invalid relayUrl/)
  );

  const RealWebSocket = globalThis.WebSocket;
  class FailingWebSocket extends EventTarget {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    readyState = 0;
    constructor() {
      super();
      setTimeout(() => this.dispatchEvent(new Event("error")), 0);
    }
    close() {}
    send() {}
  }
  globalThis.WebSocket = FailingWebSocket;
  try {
    const secretUrl = "wss://relay.example/v1/relay?token=s3cretTok";
    await assert.rejects(
      dialBrokerStream({ url: secretUrl, timeoutMs: 1000 }),
      check(/failed connecting to broker wss:\/\/relay\.example/)
    );
    await assert.rejects(
      dialRelayStream({ relayUrl: secretUrl, targetPub: "AA", timeoutMs: 1000 }),
      check(/failed connecting to relay wss:\/\/relay\.example/)
    );
  } finally {
    globalThis.WebSocket = RealWebSocket;
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

// Fake relay upstream for the demo/server.mjs proxy tests. A loopback listener can also be
// reached by other processes on the host (local service discovery sends `GET /`), so a connection
// counts only if its first request targets a relay path or carries this test's random WebSocket
// key, which every request the test sends through the proxy does. Ignored requests are kept for
// messages. Every complete request head on a counted connection is captured, so a proxy that
// forwards the upgrade twice on one socket is seen as two requests.
async function startFakeRelayUpstream(wsKey) {
  const captured = [];
  const ignored = [];
  const server = net.createServer((sock) => {
    let acc = Buffer.alloc(0);
    let counted = false;
    sock.on("error", () => {});
    sock.on("data", (chunk) => {
      acc = Buffer.concat([acc, chunk]);
      for (let endIdx = acc.indexOf("\r\n\r\n"); endIdx >= 0; endIdx = acc.indexOf("\r\n\r\n")) {
        const head = acc.subarray(0, endIdx + 4).toString("utf8");
        acc = acc.subarray(endIdx + 4);
        if (counted) {
          captured.push(head);
          continue;
        }
        if (!/^GET \/v[12]\/relay[ ?]/.test(head) && !head.includes(wsKey)) {
          ignored.push(head.split("\r\n", 1)[0]);
          sock.destroy();
          return;
        }
        counted = true;
        captured.push(head);
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
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    server,
    port: server.address().port,
    captured,
    describeIgnored: () => `ignored foreign requests: ${JSON.stringify(ignored)}`,
  };
}

test("fake relay upstream captures every request head written to one socket", async () => {
  const key = crypto.randomBytes(16).toString("base64");
  const upstream = await startFakeRelayUpstream(key);
  const head =
    `GET /v1/relay HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n` +
    `Connection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`;
  const writeOnOneSocket = (chunks) =>
    new Promise((resolve, reject) => {
      const opts = { port: upstream.port, host: "127.0.0.1", allowHalfOpen: true };
      const sock = net.connect(opts, async () => {
        for (const chunk of chunks) {
          sock.write(chunk);
          await new Promise((r) => setTimeout(r, 20));
        }
        sock.end();
      });
      sock.on("error", reject);
      sock.on("data", () => {});
      sock.on("close", resolve);
    });
  const waitForCaptured = async (n) => {
    for (let i = 0; i < 100 && upstream.captured.length < n; i++) {
      await new Promise((r) => setTimeout(r, 10));
    }
  };
  try {
    await writeOnOneSocket([head + head]);
    await waitForCaptured(2);
    assert.equal(upstream.captured.length, 2, "two heads in one write");
    await writeOnOneSocket([head, head]);
    await waitForCaptured(4);
    assert.equal(upstream.captured.length, 4, "two heads in separate writes");
  } finally {
    upstream.server.close();
  }
});

test("SEC-23 & SEC-27 demo/server.mjs emits security headers, 404s server.mjs, and validates WebSocket upgrades", async () => {
  const validKey = crypto.randomBytes(16).toString("base64");
  const upstream = await startFakeRelayUpstream(validKey);
  const upstreamCaptured = upstream.captured;
  const upstreamServer = upstream.server;
  const upstreamPort = upstream.port;

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
    assert.equal(upstreamCaptured.length, 0, upstream.describeIgnored());

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
    assert.equal(upstreamCaptured.length, 1, upstream.describeIgnored());
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

    // SEC-22: a pollEvent() error path that changed the roster persists it; a persistence error
    // there locks the session and the client fail-closed.
    const { WasmIdentity, WasmSessionClient } = await import("../pkg/tendril_wasm.js");
    const evidenceId = WasmIdentity.generate("sec-22-evidence");
    const evidencePub = JSON.parse(evidenceId.info_json()).signing_pub;
    evidenceId.free();
    const realFeed = WasmSessionClient.prototype.feed_bytes;
    // Stands in for authenticated evidence the failing frame left in the roster.
    WasmSessionClient.prototype.feed_bytes = function (bytes, now, elapsed, roster) {
      roster.add_trust_anchor("sec-22-evidence", evidencePub);
      return realFeed.call(this, bytes, now, elapsed, roster);
    };
    failPersist = true;
    activeMitm.upstream.unpipe(activeMitm.clientSock);
    // Unmasked server->client RFC 6455 binary frame carrying bogus ciphertext bytes.
    activeMitm.clientSock.write(Buffer.from([0x82, 0x06, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]));
    try {
      await assert.rejects(() => session1.pollEvent(2000), /failed to persist roster update/);
    } finally {
      WasmSessionClient.prototype.feed_bytes = realFeed;
    }
    assert.throws(() => session1.authorize("fs.read"), /session locked after roster persistence failure/);
    assert.throws(() => session1.sendData("late"), /session locked after roster persistence failure/);
    await session1.close(1000, "locked");
    await assert.rejects(
      () => client.setPeerRoutes("sec-host", []),
      /client locked after roster persistence failure/
    );
    // The unpersisted evidence stays in memory for an export; it is never rolled back.
    const anchorsAfterLock = JSON.parse(client.exportRosterJson()).trust_anchors;
    assert.ok(Object.keys(anchorsAfterLock).includes("sec-22-evidence"));
    client.free();

    // SEC-33: client.free() while a session is active never traps WASM with null pointer passed to rust.
    const client2 = await TendrilWebClient.create({ hostId: "sec-client-2" });
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
      const b2 = await client2.pair({
        relayUrl: relay.wsUrl,
        targetPub: init2.relay_pub,
        expectedHost: "127.0.0.1",
        code: c2,
      });
      const hp2 = await pp2;
      await client2.confirmPeer("sec-host-2", b2.sas);
      await peer2.call({ op: "confirm", peer_id: hp2.device_id, sas: hp2.sas });
      const g2 = (
        await peer2.call({ op: "mint", peer_id: hp2.device_id, caps: ["fs.read"] })
      ).grant;
      const cp2 = peer2.call({ op: "connect" });
      const sess2 = await client2.connect({
        relayUrl: relay.wsUrl,
        targetPub: init2.relay_pub,
        expectedHost: "127.0.0.1",
        targetHostId: "sec-host-2",
        grantJson: JSON.stringify(g2),
      });
      await cp2;

      const pendingPoll = sess2.pollEvent(5000);
      client2.free();
      assert.equal(sess2.isClosed(), true);
      assert.throws(() => sess2.authorize("fs.read"), (e) => !/null pointer/i.test(e.message));
      assert.throws(() => sess2.tick(), (e) => !/null pointer/i.test(e.message));
      assert.throws(() => sess2.sendData("hi"), (e) => !/null pointer/i.test(e.message));
      assert.throws(() => sess2.pollEvent(10), (e) => !/null pointer/i.test(e.message));
      const polled = await pendingPoll;
      assert.equal(polled.status, "eof");
      assert.throws(() => client2.info(), /freed/);
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

test("W2-0RTT dialRelayStream and dialRelayV2Stream gate init_frame on Challenge.fast_open", async () => {
  await ensureWasm();
  const nonceBytes = crypto.randomBytes(32);
  const nonceB64 = b64urlEncode(nonceBytes);
  const targetPub = b64urlEncode(crypto.randomBytes(32));
  const mbSecret = crypto.randomBytes(32);
  const serverEpoch = Math.floor(Date.now() / 1000 / 3600);

  let challengeFastOpen = true;
  const capturedDials = [];
  const mock = await startMockRelayWsServer((reqUrl) => {
    const isV2 = reqUrl.startsWith("/v2/relay");
    const challenge = {
      op: "challenge",
      host: "127.0.0.1",
      nonce: nonceB64,
      max_frame: MAX_RELAY_FRAME_LEN,
    };
    if (isV2) {
      challenge.epoch = serverEpoch;
    }
    if (challengeFastOpen !== undefined) {
      challenge.fast_open = challengeFastOpen;
    }
    return {
      challenge,
      handleDial: (msg) => {
        capturedDials.push({ path: reqUrl, msg });
        return { op: "ready", conn_id: msg.conn_id };
      },
    };
  });

  try {
    const sampleInit = new Uint8Array([0x54, 0x4e, 0x44, 0x31, 0xaa, 0xbb]);
    const expectedB64 = b64urlEncode(sampleInit);

    // Validation before network: non-Uint8Array, empty, or oversize initFrame must throw.
    await assert.rejects(
      () =>
        dialRelayStream({
          relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
          targetPub,
          allowInsecureWs: true,
          initFrame: "not-bytes",
        }),
      TypeError
    );
    await assert.rejects(
      () =>
        dialRelayStream({
          relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
          targetPub,
          allowInsecureWs: true,
          initFrame: new Uint8Array(0),
        }),
      RangeError
    );
    await assert.rejects(
      () =>
        dialRelayV2Stream({
          relayUrl: `ws://127.0.0.1:${mock.port}/v2/relay`,
          allowInsecureWs: true,
          deriveV2Dial: ({ relayHost, nonceBytes: n, connIdBytes }) =>
            deriveV2RelayDial(mbSecret, relayHost, serverEpoch * 3600, n, connIdBytes),
          initFrame: new Uint8Array(MAX_RELAY_FRAME_LEN + 1),
        }),
      RangeError
    );
    assert.equal(capturedDials.length, 0);

    // 1. Challenge.fast_open === true -> Dial.init_frame carries b64url(initFrame), fastOpenSent === true.
    challengeFastOpen = true;
    const v1Fast = await dialRelayStream({
      relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
      targetPub,
      allowInsecureWs: true,
      initFrame: sampleInit,
    });
    assert.equal(v1Fast.fastOpenSent, true);
    assert.equal(capturedDials.at(-1).msg.init_frame, expectedB64);
    v1Fast.close();

    const v2Fast = await dialRelayV2Stream({
      relayUrl: `ws://127.0.0.1:${mock.port}/v2/relay`,
      allowInsecureWs: true,
      deriveV2Dial: ({ relayHost, nonceBytes: n, connIdBytes }) =>
        deriveV2RelayDial(mbSecret, relayHost, serverEpoch * 3600, n, connIdBytes),
      initFrame: sampleInit,
    });
    assert.equal(v2Fast.fastOpenSent, true);
    assert.equal(capturedDials.at(-1).msg.init_frame, expectedB64);
    v2Fast.close();

    // 2. Old relay without Challenge.fast_open -> init_frame omitted, fastOpenSent === false.
    challengeFastOpen = undefined;
    const v1Old = await dialRelayStream({
      relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
      targetPub,
      allowInsecureWs: true,
      initFrame: sampleInit,
    });
    assert.equal(v1Old.fastOpenSent, false);
    assert.equal(capturedDials.at(-1).msg.init_frame, undefined);
    v1Old.close();

    challengeFastOpen = false;
    const v2Old = await dialRelayV2Stream({
      relayUrl: `ws://127.0.0.1:${mock.port}/v2/relay`,
      allowInsecureWs: true,
      deriveV2Dial: ({ relayHost, nonceBytes: n, connIdBytes }) =>
        deriveV2RelayDial(mbSecret, relayHost, serverEpoch * 3600, n, connIdBytes),
      initFrame: sampleInit,
    });
    assert.equal(v2Old.fastOpenSent, false);
    assert.equal(capturedDials.at(-1).msg.init_frame, undefined);
    v2Old.close();
  } finally {
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
    assert.match(sess.peerDeviceId, /^dev_/);

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

test("SEC-12 relay challenge host canonicalization accepts [::1], bare ::1, trailing dot, mixed case, and preserves raw HMAC host", async (t) => {
  await ensureWasm();
  const nonceBytes = new Uint8Array(32).fill(0x42);
  const nonceB64 = Buffer.from(nonceBytes).toString("base64url");
  const targetBytes = new Uint8Array(32).fill(0x77);
  const targetPub = Buffer.from(targetBytes).toString("base64url");
  const serverEpoch = Math.floor(Date.now() / 1000 / 3600);
  const mbSecret = new Uint8Array(32).fill(0x21);

  let challengeHostToSend = "[::1]";
  let authRequiredToSend = undefined;
  const capturedDials = [];
  const mock = await startMockRelayWsServer((reqUrl) => {
    const isV2 = reqUrl.startsWith("/v2/relay");
    const challenge = isV2
      ? {
          op: "challenge",
          host: challengeHostToSend,
          nonce: nonceB64,
          epoch: serverEpoch,
          max_frame: MAX_RELAY_FRAME_LEN,
        }
      : {
          op: "challenge",
          host: challengeHostToSend,
          nonce: nonceB64,
          max_frame: MAX_RELAY_FRAME_LEN,
        };
    if (authRequiredToSend) {
      challenge.auth_required = authRequiredToSend;
    }
    return {
      challenge,
      handleDial: (msg) => {
        capturedDials.push(msg);
        return { op: "ready", conn_id: msg.conn_id };
      },
    };
  });

  // Also test real IPv6 loopback URL ws://[::1]:port/v2/relay without explicit expectedHost
  let ipv6Server = null;
  const ipv6Sockets = new Set();
  try {
    ipv6Server = await new Promise((resolve, reject) => {
      const srv = http.createServer();
      srv.on("upgrade", (req, socket) => {
        ipv6Sockets.add(socket);
        socket.on("close", () => ipv6Sockets.delete(socket));
        socket.on("error", () => {});
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
        socket.write(
          encodeWsTextFrame(
            JSON.stringify({
              op: "challenge",
              host: "[::1]",
              nonce: nonceB64,
              epoch: serverEpoch,
              max_frame: MAX_RELAY_FRAME_LEN,
            })
          )
        );
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
            const msg = JSON.parse(frame.text);
            socket.write(encodeWsTextFrame(JSON.stringify({ op: "ready", conn_id: msg.conn_id })));
          }
        });
      });
      srv.on("error", reject);
      srv.listen(0, "::1", () => resolve(srv));
    });
  } catch {
    ipv6Server = null;
  }

  try {
    // Trailing dot and mixed case must canonicalize to equal host AND preserve raw challenge.host for v1 HMAC
    challengeHostToSend = "Relay.Example.";
    authRequiredToSend = ["dial"];
    const hmacSecretRaw = new TextEncoder().encode("sec12-raw-host-hmac-secret");
    const expectedRawMac = computeRelayAuthHmacB64(
      new Uint8Array(hmacSecretRaw),
      "dial",
      "Relay.Example.",
      nonceBytes,
      targetBytes
    );
    const sCase = await dialRelayStream({
      relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
      targetPub,
      expectedHost: "RELAY.EXAMPLE",
      allowInsecureWs: true,
      relayAuthSecret: hmacSecretRaw,
    });
    sCase.close();
    assert.equal(capturedDials.at(-1).auth.kind, "hmac");
    assert.equal(
      capturedDials.at(-1).auth.mac,
      expectedRawMac,
      "v1 dial HMAC must use raw challenge.host without mutating it"
    );
    authRequiredToSend = undefined;

    // Bare IPv6 "::1" from relay matches bracketed expectedHost "[::1]"
    challengeHostToSend = "::1";
    const sBareV6 = await dialRelayStream({
      relayUrl: `ws://127.0.0.1:${mock.port}/v1/relay`,
      targetPub,
      expectedHost: "[::1]",
      allowInsecureWs: true,
    });
    sBareV6.close();

    // [::1] via expectedHost
    challengeHostToSend = "[::1]";
    const sV6Exp = await dialRelayV2Stream({
      relayUrl: `ws://127.0.0.1:${mock.port}/v2/relay`,
      expectedHost: "[0:0:0:0:0:0:0:1]",
      allowInsecureWs: true,
      deriveV2Dial: ({ relayHost, nonceBytes: n, connIdBytes }) =>
        deriveV2RelayDial(mbSecret, relayHost, serverEpoch * 3600, n, connIdBytes),
    });
    sV6Exp.close();

    // Real ws://[::1]:port/v2/relay with default expectedHost from URL hostname
    if (ipv6Server) {
      const v6Port = ipv6Server.address().port;
      const sV6Url = await dialRelayV2Stream({
        relayUrl: `ws://[::1]:${v6Port}/v2/relay`,
        allowInsecureWs: true,
        deriveV2Dial: ({ relayHost, nonceBytes: n, connIdBytes }) =>
          deriveV2RelayDial(mbSecret, relayHost, serverEpoch * 3600, n, connIdBytes),
      });
      sV6Url.close();
    } else {
      t.diagnostic("skipping live ws://[::1] leg: ::1 loopback bind unavailable in sandbox");
    }
  } finally {
    if (ipv6Server) {
      for (const s of ipv6Sockets) {
        s.destroy();
      }
      await new Promise((r) => {
        ipv6Server.closeAllConnections?.();
        ipv6Server.close(r);
      });
    }
    await mock.close();
  }
});

test("PRIV-04 & PRIV-05 v1 connect fails pre-flight on v2 peer before dialing; v2 session.ping() works", async () => {
  await ensureWasm();
  const relay = await spawnRelay();
  const peer = spawnPeer();
  const client = await TendrilWebClient.create({ hostId: "web-priv04-05" });
  let sess = null;
  let dialAttempts = 0;
  const spyServer = net.createServer((sock) => {
    dialAttempts += 1;
    sock.destroy();
  });
  await new Promise((r) => spyServer.listen(0, "127.0.0.1", r));
  const spyPort = spyServer.address().port;

  try {
    const init = await peer.call({ op: "init", host_id: "priv04-v2-host" });
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
    await client.confirmPeer("priv04-v2-host", bound.sas);
    await peer.call({ op: "confirm", peer_id: hostBound.device_id, sas: hostBound.sas });

    // PRIV-04: v1 client.connect() MUST fail closed BEFORE dialing the relay socket
    await assert.rejects(
      () =>
        client.connect({
          relayUrl: `ws://127.0.0.1:${spyPort}/v1/relay`,
          targetPub: init.relay_pub,
          expectedHost: "127.0.0.1",
          targetHostId: "priv04-v2-host",
          allowInsecureWs: true,
        }),
      /downgrade|version/i
    );
    assert.equal(dialAttempts, 0, "v1 connect must fail pre-flight before opening a socket");

    // PRIV-05: v2 session.ping() sends encrypted 0x05 PING and receives 0x06 PONG
    const { grant } = await peer.call({
      op: "mint",
      peer_id: hostBound.device_id,
      caps: ["fs.read"],
      ttl_secs: 300,
    });
    const acceptPromise = peer.call({ op: "accept_v2", timeout_ms: 10000 });
    sess = await client.connectV2({
      relayUrl: relay.wsUrl,
      targetPub: init.relay_pub,
      expectedHost: "127.0.0.1",
      targetHostId: "priv04-v2-host",
      grantJson: JSON.stringify(grant),
      allowInsecureWs: true,
    });
    await acceptPromise;

    await sess.ping(4242);
    await sess.sendData("after-v2-ping");
    const rPing = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(rPing.data_utf8, "after-v2-ping");
    let gotPong = false;
    for (let i = 0; i < 4; i += 1) {
      const ev = await sess.pollEvent(1000);
      if (ev.event === "pong" && ev.cookie === 4242) {
        gotPong = true;
        break;
      }
    }
    assert.equal(gotPong, true, "v2 session must receive matching pong after ping()");
  } finally {
    if (sess && !sess.isClosed()) {
      await sess.close(1000, "done").catch(() => {});
    }
    spyServer.close();
    client.free();
    peer.close();
    relay.child.kill();
  }
});

test("PRIV-08 demo/server.mjs allows /v2/relay upgrade while rejecting query strings", async () => {
  const validKey = crypto.randomBytes(16).toString("base64");
  const upstream = await startFakeRelayUpstream(validKey);
  const upstreamCaptured = upstream.captured;
  const upstreamServer = upstream.server;
  const upstreamPort = upstream.port;

  let demoServer;
  try {
    demoServer = await spawnDemoServer({
      relayHost: "127.0.0.1",
      relayPort: upstreamPort,
    });
    const badV2Query =
      `GET /v2/relay?leak=1 HTTP/1.1\r\n` +
      `Host: 127.0.0.1:${demoServer.port}\r\n` +
      `Upgrade: websocket\r\n` +
      `Connection: Upgrade\r\n` +
      `Sec-WebSocket-Key: ${validKey}\r\n` +
      `Sec-WebSocket-Version: 13\r\n\r\n`;
    const badResp = await sendRawTcpRequest(demoServer.port, badV2Query);
    assert.ok(badResp.startsWith("HTTP/1.1 400 "), badResp);

    const goodV2 =
      `GET /v2/relay HTTP/1.1\r\n` +
      `Host: 127.0.0.1:${demoServer.port}\r\n` +
      `Upgrade: websocket\r\n` +
      `Connection: Upgrade\r\n` +
      `Sec-WebSocket-Key: ${validKey}\r\n` +
      `Sec-WebSocket-Version: 13\r\n\r\n`;
    const okResp = await sendRawTcpRequest(demoServer.port, goodV2);
    assert.ok(okResp.startsWith("HTTP/1.1 101 "), okResp);
    assert.equal(upstreamCaptured.length, 1, upstream.describeIgnored());
    assert.match(upstreamCaptured[0], /^GET \/v2\/relay HTTP\/1\.1\r\n/);
  } finally {
    if (demoServer) demoServer.child.kill();
    upstreamServer.close();
  }
});

test("PRIV-01 dialIrohStream fails closed when p2pRelayAuthToken is passed without explicit relay", async () => {
  const p2pWasmPath = path.join(WEB_ROOT, "pkg-p2p", "tendril_wasm_bg.wasm");
  await initTendrilP2p({ module_or_path: fs.readFileSync(p2pWasmPath) });
  const bareEndpoint = `iroh://${"0".repeat(64)}`;
  const attackerUriWithRelay = `${bareEndpoint}?relay=https://attacker.example/`;

  const tok1 = new TextEncoder().encode("scoped-bearer-secret-1");
  await assert.rejects(
    () =>
      dialIrohStream({
        endpoint: bareEndpoint,
        p2pRelayAuthToken: tok1,
      }),
    /refusing to attach bearer token/i
  );
  assert.equal(tok1.every((b) => b === 0), true, "p2pRelayAuthToken tok1 must be zeroized");

  const tok2 = new TextEncoder().encode("scoped-bearer-secret-2");
  await assert.rejects(
    () =>
      dialIrohStream({
        endpoint: attackerUriWithRelay,
        p2pRelayAuthToken: tok2,
      }),
    /refusing to attach bearer token/i
  );
  assert.equal(tok2.every((b) => b === 0), true, "p2pRelayAuthToken tok2 must be zeroized");
});

test("PRIV-07 byte-slice identity, roster, and PAKE code APIs zeroize caller buffers", async () => {
  await ensureWasm();
  assert.equal(canonicalRelayHost("[0:0:0:0:0:0:0:1]"), "[::1]");
  assert.equal(canonicalRelayHost("Relay.Example."), "relay.example");

  const c1 = await TendrilWebClient.create({ hostId: "priv07-client" });
  const info1 = c1.info();
  const idBytes = c1.exportIdentityBytes();
  const rosterBytes = c1.exportRosterBytes();
  assert.ok(idBytes instanceof Uint8Array && idBytes.length > 0);
  assert.ok(rosterBytes instanceof Uint8Array && rosterBytes.length > 0);
  c1.free();

  const c2 = await TendrilWebClient.create({
    identityBytes: idBytes,
    rosterBytes,
  });
  try {
    assert.equal(idBytes.every((b) => b === 0), true, "identityBytes must be zeroized");
    assert.equal(rosterBytes.every((b) => b === 0), true, "rosterBytes must be zeroized");
    assert.deepEqual(c2.info(), info1);

    const { WasmIdentity } = await import("../pkg/tendril_wasm.js");
    const wid = WasmIdentity.generate("priv07-pake");
    const codeBuf = new TextEncoder().encode("4829-1704-9999");
    const pake = WasmV2PakePairInitiator.new_bytes(wid, "web", "browser", codeBuf, null);
    try {
      assert.equal(codeBuf.every((b) => b === 0), true, "PAKE code buffer must be zeroized");
      assert.ok(pake.start().length > 0);
    } finally {
      pake.free();
      wid.free();
    }

    // Nit #4: throwing on invalid identityBytes must still zeroize rosterBytes
    const badIdBytes = new TextEncoder().encode("not-json");
    const untouchedRosterBytes = c2.exportRosterBytes();
    await assert.rejects(() =>
      TendrilWebClient.create({
        identityBytes: badIdBytes,
        rosterBytes: untouchedRosterBytes,
      })
    );
    assert.equal(badIdBytes.every((b) => b === 0), true, "bad identityBytes must be zeroized");
    assert.equal(
      untouchedRosterBytes.every((b) => b === 0),
      true,
      "rosterBytes must be zeroized even when identityBytes fails"
    );

    // Major #3: onPersistRosterBytes receives Uint8Array and zeroes it after await
    let capturedPersistBuf = null;
    let persistedLen = 0;
    const cBytesPersist = await TendrilWebClient.create({
      hostId: "priv07-persist-bytes",
      onPersistRosterBytes: async (bytes) => {
        assert.ok(bytes instanceof Uint8Array);
        assert.ok(bytes.length > 0);
        persistedLen = bytes.length;
        capturedPersistBuf = bytes;
      },
    });
    try {
      const anchorInfo = c2.info();
      await cBytesPersist.addTrustAnchor("priv07-anchor", anchorInfo.signing_pub);
      assert.ok(persistedLen > 0);
      assert.equal(
        capturedPersistBuf.every((b) => b === 0),
        true,
        "onPersistRosterBytes buffer must be zeroized after callback completes"
      );
    } finally {
      cBytesPersist.free();
    }

    // Major #1: verify generated wasm-bindgen glue for to_json/to_json_bytes does NOT free un-zeroed copies
    const glueJs = fs.readFileSync(path.join(WEB_ROOT, "pkg", "tendril_wasm.js"), "utf8");
    for (const className of ["WasmIdentity", "WasmRoster"]) {
      const clsMatch = glueJs.match(new RegExp(`export class ${className} \\{[\\s\\S]*?\\n\\}`));
      assert.ok(clsMatch, `missing ${className} in generated tendril_wasm.js`);
      for (const method of ["to_json", "to_json_bytes"]) {
        const mMatch = clsMatch[0].match(new RegExp(`${method}\\(\\) \\{[\\s\\S]*?\\n    \\}`));
        assert.ok(mMatch, `missing ${className}.${method} in generated tendril_wasm.js`);
        assert.equal(
          /getStringFromWasm0|getArrayU8FromWasm0|__wbindgen_free|__wbindgen_export/.test(
            mMatch[0]
          ),
          false,
          `${className}.${method} must return JsValue directly without un-zeroed wasm-bindgen linear memory copy:\n${mMatch[0]}`
        );
      }
    }
  } finally {
    c2.free();
  }
});

test("PRIV-09 createIndexedDbVault encrypts with non-extractable AES-256-GCM and index.d.ts covers all exports", async () => {
  // 1. In-memory mock IndexedDB + real WebCrypto AES-256-GCM verification
  const stores = new Map();
  const fakeIdb = {
    open(name) {
      const req = { result: null, error: null, onupgradeneeded: null, onsuccess: null, onerror: null };
      queueMicrotask(() => {
        if (!stores.has(name)) {
          stores.set(name, new Map());
        }
        const dbStores = stores.get(name);
        const db = {
          objectStoreNames: {
            contains: (s) => dbStores.has(s),
          },
          createObjectStore(s) {
            if (!dbStores.has(s)) dbStores.set(s, new Map());
          },
          transaction(s) {
            const map = dbStores.get(s);
            const tx = { oncomplete: null, onerror: null, onabort: null };
            const scheduleComplete = () => {
              setTimeout(() => tx.oncomplete?.(), 0);
            };
            tx.objectStore = () => ({
              get(k) {
                const r = { result: undefined, onsuccess: null, onerror: null };
                queueMicrotask(() => {
                  r.result = map.get(k);
                  r.onsuccess?.();
                  scheduleComplete();
                });
                return r;
              },
              put(v, k) {
                map.set(k, v);
                scheduleComplete();
              },
              delete(k) {
                map.delete(k);
                scheduleComplete();
              },
              clear() {
                map.clear();
                scheduleComplete();
              },
            });
            return tx;
          },
          close() {},
        };
        req.result = db;
        req.onupgradeneeded?.();
        req.onsuccess?.();
      });
      return req;
    },
  };

  assert.equal(openTendrilVault, createIndexedDbVault);
  const vault = createIndexedDbVault({
    dbName: "test-vault",
    isSecureContext: true,
    cryptoSubtle: globalThis.crypto.subtle,
    getRandomValues: (b) => globalThis.crypto.getRandomValues(b),
    indexedDB: fakeIdb,
  });
  await vault.writeString("identity", '{"secret":"value"}');
  const rawRecord = stores.get("test-vault").get("vault").get("identity");
  assert.ok(rawRecord.iv instanceof Uint8Array && rawRecord.iv.length === 12);
  assert.ok(rawRecord.ct instanceof Uint8Array);
  assert.equal(Buffer.from(rawRecord.ct).toString("utf8").includes("secret"), false);
  const wrapKey = stores.get("test-vault").get("vault").get("wrapping-key");
  assert.equal(wrapKey.extractable, false, "wrapping key must be non-extractable");
  assert.equal(await vault.readString("identity"), '{"secret":"value"}');
  await vault.delete("identity");
  assert.equal(await vault.readString("identity"), null);
  await vault.close();

  // 2. Verify every runtime export from bindings/web/src/index.js is declared in bindings/web/index.d.ts
  const sdkMod = await import("../src/index.js");
  const dts = fs.readFileSync(path.join(WEB_ROOT, "index.d.ts"), "utf8");
  for (const name of Object.keys(sdkMod)) {
    const declRe = new RegExp(`export\\s+(?:declare\\s+)?(?:function|class|const|let|var)\\s+${name}\\b`);
    assert.match(dts, declRe, `index.d.ts missing export declaration for '${name}'`);
  }

  // 3. Verify redactHint strips wt:// paths and ?certhash= secrets.
  assert.equal(
    redactHint("wt://127.0.0.1:4433/secret?certhash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    "wt://127.0.0.1:4433"
  );
  assert.equal(redactHint("wt://TND-ABCD-EFGH:4433/"), "<redacted>");
  assert.equal(redactHint("wt://127.0.0.1:4433/path@host"), "<redacted>");
  assert.equal(redactHint("wt://127.0.0.1:4433/?q=@x"), "<redacted>");
});
import "./group.test.mjs";
import "./webtransport.test.mjs";
