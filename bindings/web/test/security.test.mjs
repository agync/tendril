import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
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
  computeCodeMac,
  computeCodeMacBytes,
  computeCodeMacWorker,
  initTendril,
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
    frameCapped._pushFrame(new Uint8Array(0));
  }
  assert.equal(closeCalls.length, 0);
  frameCapped._pushFrame(new Uint8Array(0));
  assert.deepEqual(closeCalls, [{ code: 1008, reason: "receive queue overflow" }]);
  await assert.rejects(() => frameCapped.recv(10), /receive queue exceeded/);

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
          targetPub: peerInit.signing_pub,
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
      targetPub: peerInit.signing_pub,
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
      targetPub: peerInit.signing_pub,
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
        targetPub: init2.signing_pub,
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
        targetPub: init2.signing_pub,
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
    assert.equal(terminatedCount, 2);
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
        targetPub: hostInit.signing_pub,
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
            targetPub: hostInit.signing_pub,
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
        targetPub: hostInit.signing_pub,
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
            targetPub: hostInit.signing_pub,
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
            targetPub: hostInit.signing_pub,
            expectedHost: "127.0.0.1",
            allowInsecureWs: true,
            hostId: "web-m2m-host",
            hostStaticPubB64: hostInit.static_pub,
            hostSigningPubB64: hostInit.signing_pub,
            tokenJson: freshTok,
          }),
        /untrusted_anchor/
      );
      await revPairP2;

      const selfPairP = peer.call({ op: "pair" });
      const selfEnrollRes = await cli2.enroll({
        relayUrl: relay.wsUrl,
        targetPub: hostInit.signing_pub,
        expectedHost: "127.0.0.1",
        allowInsecureWs: true,
        hostId: "web-m2m-host",
        hostStaticPubB64: hostInit.static_pub,
        hostSigningPubB64: hostInit.signing_pub,
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
