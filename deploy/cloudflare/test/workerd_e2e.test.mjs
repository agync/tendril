import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import test from "node:test";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

import {
  TendrilWebClient,
  computeRelayAuthHmacB64,
  initTendril,
} from "../../../bindings/web/src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CF_DIR = path.resolve(__dirname, "..");
const REPO_ROOT = path.resolve(CF_DIR, "..", "..");
const WRANGLER_BIN = path.join(CF_DIR, "node_modules", ".bin", "wrangler");
const PEER_BIN = path.join(REPO_ROOT, "target", "debug", "tendril-conformance-peer");
const WEB_WASM_PATH = path.join(REPO_ROOT, "bindings", "web", "pkg", "tendril_wasm_bg.wasm");

let webWasmReady = false;
async function ensureWebWasm() {
  if (!webWasmReady) {
    const bytes = fs.readFileSync(WEB_WASM_PATH);
    await initTendril({ module_or_path: bytes });
    webWasmReady = true;
  }
}

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function walkFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkFiles(full));
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

function killProcessGroup(child) {
  if (!child || child.pid === undefined) {
    return;
  }
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    try {
      child.kill("SIGTERM");
    } catch {
      // Already exited.
    }
  }
  setTimeout(() => {
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already exited.
      }
    }
  }, 500).unref();
}

function spawnWranglerDev(persistDir, vars = {}) {
  return new Promise((resolve, reject) => {
    const args = [
      "dev",
      "--local",
      "--ip",
      "127.0.0.1",
      "--port",
      "0",
      "--inspector-port",
      "0",
      "--persist-to",
      persistDir,
    ];
    for (const [k, v] of Object.entries(vars)) {
      args.push("--var", `${k}:${v}`);
    }
    const child = spawn(WRANGLER_BIN, args, {
      cwd: CF_DIR,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        TENDRIL_SKIP_WASM_BUILD: "1",
        WRANGLER_SEND_METRICS: "false",
        CI: "1",
      },
    });
    let output = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        killProcessGroup(child);
        reject(new Error(`wrangler dev timed out:\n${output}`));
      }
    }, 30_000);

    const onChunk = (chunk) => {
      output += stripAnsi(chunk.toString("utf8"));
      const match = output.match(/Ready on (http:\/\/127\.0\.0\.1:(\d+))/);
      if (match && !settled) {
        settled = true;
        clearTimeout(timer);
        resolve({
          child,
          baseUrl: match[1],
          port: Number(match[2]),
          close() {
            killProcessGroup(child);
          },
        });
      }
    };
    child.stdout.on("data", onChunk);
    child.stderr.on("data", onChunk);
    child.on("exit", (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error(`wrangler dev exited early (${code}):\n${output}`));
      }
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

function connectRawWs(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    const queue = [];
    const waiters = [];
    let closed = null;

    ws.addEventListener("message", (ev) => {
      const item =
        typeof ev.data === "string"
          ? { type: "text", data: JSON.parse(ev.data) }
          : { type: "binary", data: new Uint8Array(ev.data) };
      if (waiters.length > 0) {
        waiters.shift()(item);
      } else {
        queue.push(item);
      }
    });
    ws.addEventListener("close", (ev) => {
      closed = { code: ev.code, reason: ev.reason };
      while (waiters.length > 0) {
        waiters.shift()({ type: "close", code: ev.code, reason: ev.reason });
      }
    });
    ws.addEventListener("open", () => {
      resolve({
        ws,
        sendJson(obj) {
          ws.send(JSON.stringify(obj));
        },
        sendBinary(bytes) {
          ws.send(bytes);
        },
        nextEvent() {
          if (queue.length > 0) {
            return Promise.resolve(queue.shift());
          }
          if (closed !== null) {
            return Promise.resolve({ type: "close", ...closed });
          }
          return new Promise((res) => waiters.push(res));
        },
        close() {
          ws.close();
        },
      });
    });
    ws.addEventListener("error", (err) => {
      reject(err?.error ?? new Error("websocket connection failed"));
    });
  });
}

test("wrangler dry-run bundle stays under 1.5 MiB gzipped with Durable Object binding", () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "cf-dry-run-"));
  try {
    const res = spawnSync(WRANGLER_BIN, ["deploy", "--dry-run", "--outdir", outDir], {
      cwd: CF_DIR,
      encoding: "utf8",
      env: {
        ...process.env,
        TENDRIL_SKIP_WASM_BUILD: "1",
        WRANGLER_SEND_METRICS: "false",
        CI: "1",
      },
    });
    assert.equal(res.status, 0, `wrangler deploy --dry-run failed:\n${res.stdout}\n${res.stderr}`);
    const runtimeFiles = walkFiles(outDir).filter(
      (f) => f.endsWith(".js") || f.endsWith(".wasm"),
    );
    assert.ok(runtimeFiles.some((f) => f.endsWith(".wasm")), "expected bundled .wasm file");
    const totalGzipBytes = runtimeFiles.reduce(
      (sum, f) => sum + zlib.gzipSync(fs.readFileSync(f)).byteLength,
      0,
    );
    assert.ok(
      totalGzipBytes < 1.5 * 1024 * 1024,
      `bundle gzipped size ${totalGzipBytes} exceeded 1.5 MiB`,
    );
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});

test("standalone deploy/cloudflare fork builds tendril-wasm via build.sh outside workspace", () => {
  const standaloneDir = fs.mkdtempSync(path.join(os.tmpdir(), "cf-standalone-fork-"));
  try {
    for (const item of ["package.json", "wrangler.jsonc", "scripts", "src"]) {
      fs.cpSync(path.join(CF_DIR, item), path.join(standaloneDir, item), { recursive: true });
    }
    const res = spawnSync("bash", ["scripts/build.sh"], {
      cwd: standaloneDir,
      encoding: "utf8",
      env: {
        ...process.env,
        TENDRIL_SKIP_WASM_BUILD: "0",
        TENDRIL_SOURCE_REPO: REPO_ROOT,
        TENDRIL_SOURCE_REF: "HEAD",
        CARGO_TARGET_DIR: path.join(REPO_ROOT, "target"),
      },
    });
    assert.equal(res.status, 0, `standalone build.sh failed:\n${res.stdout}\n${res.stderr}`);
    assert.ok(
      fs.existsSync(path.join(standaloneDir, "pkg", "tendril_wasm_bg.wasm")),
      "expected compiled tendril_wasm_bg.wasm in standalone fork pkg/",
    );
  } finally {
    fs.rmSync(standaloneDir, { recursive: true, force: true });
  }
});

test("workerd local E2E serves healthz, /v1/relay PAKE pairing, /v2/relay Day-2 session, classic SQLite init_frame, Tier 3 ticket, and v1/v2 standby+fast_open", async () => {
  await ensureWebWasm();
  const persistDir = fs.mkdtempSync(path.join(os.tmpdir(), "cf-workerd-"));
  const secret = "cf-workerd-e2e-secret";
  const secretBytes = new TextEncoder().encode(secret);
  const issuerKp = crypto.generateKeyPairSync("ed25519");
  const issuerSpki = issuerKp.publicKey.export({ format: "der", type: "spki" });
  const issuerPubB64 = b64url(issuerSpki.subarray(issuerSpki.length - 32));
  const dev = await spawnWranglerDev(persistDir, {
    TENDRIL_RELAY_AUTH_SECRET: secret,
    TENDRIL_RELAY_ISSUER_PUBS: issuerPubB64,
    TENDRIL_RELAY_HOST: "127.0.0.1",
  });
  const peer = spawnPeer();
  let client = null;
  let sessV1 = null;
  let sessV2 = null;

  try {
    // 1. Plain /healthz probes vs WebSocket rejection.
    const healthGet = await fetch(`${dev.baseUrl}/healthz`);
    assert.equal(healthGet.status, 200);
    assert.equal(await healthGet.text(), "ok");

    const healthHead = await fetch(`${dev.baseUrl}/healthz`, { method: "HEAD" });
    assert.equal(healthHead.status, 200);

    const wsV1Url = `ws://127.0.0.1:${dev.port}/v1/relay`;
    const wsV2Url = `ws://127.0.0.1:${dev.port}/v2/relay`;
    const wsHealthUrl = `ws://127.0.0.1:${dev.port}/healthz`;
    await assert.rejects(() => connectRawWs(wsHealthUrl));

    // 2. Option 1A unauthenticated dial rejected inside live workerd.
    const rawUnauth = await connectRawWs(wsV1Url);
    try {
      const challenge = await rawUnauth.nextEvent();
      assert.equal(challenge.type, "text");
      assert.equal(challenge.data.op, "challenge");
      assert.deepEqual(challenge.data.auth_required, ["register", "dial"]);
      rawUnauth.sendJson({
        op: "dial",
        target_pub: b64url(crypto.randomBytes(32)),
        conn_id: b64url(crypto.randomBytes(16)),
      });
      const errEv = await rawUnauth.nextEvent();
      assert.equal(errEv.type, "text");
      assert.equal(errEv.data.op, "error");
      assert.equal(errEv.data.code, "unauthorized");
    } finally {
      rawUnauth.close();
    }

    // 3. Full TendrilWebClient <-> tendril-conformance-peer /v1/relay pairing + /v2/relay session.
    const hostId = "cf-workerd-host";
    const hostInit = await peer.call({ op: "init", host_id: hostId });
    await peer.call({ op: "configure_transports", relay_auth_secret: secret });
    await peer.call({
      op: "serve_relay",
      relay_url: wsV1Url,
      expected_host: "127.0.0.1",
    });

    client = await TendrilWebClient.create({ hostId: "cf-workerd-browser" });
    const code = (await peer.call({ op: "issue_code", kind: "remote" })).code;
    const pairPromise = peer.call({ op: "pair_v2_accept", timeout_ms: 15_000 });
    const bound = await client.pairV2({
      relayUrl: wsV1Url,
      targetPub: hostInit.relay_pub,
      expectedHost: "127.0.0.1",
      code,
      allowInsecureWs: true,
      relayAuthSecret: new Uint8Array(secretBytes),
      relayAuthOrigins: [`ws://127.0.0.1:${dev.port}`],
    });
    const hostBound = await pairPromise;
    await client.confirmPeer(hostId, bound.sas);
    await peer.call({ op: "confirm", peer_id: hostBound.device_id, sas: hostBound.sas });

    const { grant } = await peer.call({
      op: "mint",
      peer_id: hostBound.device_id,
      caps: ["fs.read"],
      ttl_secs: 300,
    });

    // Day-2 /v1/relay connect + sealed Noise payload round-trip.
    const acceptV1 = peer.call({ op: "accept_v2", timeout_ms: 15_000 });
    sessV1 = await client.connectV2({
      relayUrl: wsV1Url,
      targetPub: hostInit.relay_pub,
      expectedHost: "127.0.0.1",
      targetHostId: hostId,
      grantJson: JSON.stringify(grant),
      allowInsecureWs: true,
      relayAuthSecret: new Uint8Array(secretBytes),
      relayAuthOrigins: [`ws://127.0.0.1:${dev.port}`],
    });
    await acceptV1;
    await sessV1.sendData("hello-cf-v1");
    const recvV1 = await peer.call({ op: "recv", timeout_ms: 10_000 });
    assert.equal(recvV1.data_utf8, "hello-cf-v1");
    await sessV1.close(1000, "v1 done");

    // Day-2 /v2/relay blinded-epoch listener + connect + sealed Noise payload round-trip.
    await peer.call({
      op: "serve_relay_v2",
      relay_url: wsV2Url,
      expected_host: "127.0.0.1",
      peer_id: hostBound.device_id,
    });
    const acceptV2 = peer.call({ op: "accept_v2", timeout_ms: 15_000 });
    sessV2 = await client.connectV2({
      relayUrl: wsV2Url,
      targetPub: hostInit.relay_pub,
      expectedHost: "127.0.0.1",
      targetHostId: hostId,
      grantJson: JSON.stringify(grant),
      useRelayV2: true,
      allowInsecureWs: true,
      relayAuthSecret: new Uint8Array(secretBytes),
      relayAuthOrigins: [`ws://127.0.0.1:${dev.port}`],
    });
    await acceptV2;
    await sessV2.sendData("hello-cf-v2");
    const recvV2 = await peer.call({ op: "recv", timeout_ms: 10_000 });
    assert.equal(recvV2.data_utf8, "hello-cf-v2");
    await sessV2.close(1000, "v2 done");

    // 4. Standby + fast_open init_frame flow over live workerd /v1/relay.
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const spki = publicKey.export({ format: "der", type: "spki" });
    const rawPub = new Uint8Array(spki.subarray(spki.length - 32));
    const pubB64 = b64url(rawPub);

    const signReg = (nonceB64) =>
      b64url(
        crypto.sign(
          null,
          Buffer.concat([
            Buffer.from("tendril-relay-reg-v1\0"),
            Buffer.from("127.0.0.1", "utf8"),
            Buffer.from(nonceB64, "base64url"),
          ]),
          privateKey,
        ),
      );
    const hmacFor = (op, nonceB64) => ({
      kind: "hmac",
      mac: computeRelayAuthHmacB64(
        new Uint8Array(secretBytes),
        op,
        "127.0.0.1",
        Buffer.from(nonceB64, "base64url"),
        rawPub,
      ),
    });

    const listenerWs = await connectRawWs(wsV1Url);
    const standbyWs = await connectRawWs(wsV1Url);
    const dialerWs = await connectRawWs(wsV1Url);
    try {
      const lc = await listenerWs.nextEvent();
      listenerWs.sendJson({
        op: "register",
        pub: pubB64,
        sig: signReg(lc.data.nonce),
        auth: hmacFor("register", lc.data.nonce),
        fast_open: true,
      });
      const lr = await listenerWs.nextEvent();
      assert.equal(lr.data.op, "registered");

      const sc = await standbyWs.nextEvent();
      standbyWs.sendJson({
        op: "standby",
        pub: pubB64,
        sig: signReg(sc.data.nonce),
        auth: hmacFor("register", sc.data.nonce),
      });
      const sr = await standbyWs.nextEvent();
      assert.equal(sr.data.op, "standby_ready");

      const dc = await dialerWs.nextEvent();
      const cid = b64url(crypto.randomBytes(16));
      const initB64 = b64url(Uint8Array.from([1, 2, 3, 4]));
      dialerWs.sendJson({
        op: "dial",
        target_pub: pubB64,
        conn_id: cid,
        auth: hmacFor("dial", dc.data.nonce),
        init_frame: initB64,
      });

      const sbInc = await standbyWs.nextEvent();
      assert.equal(sbInc.data.op, "incoming");
      assert.equal(sbInc.data.conn_id, cid);
      assert.equal(sbInc.data.init_frame, initB64);
      const dReady = await dialerWs.nextEvent();
      assert.equal(dReady.data.op, "ready");

      const pingFrame = Uint8Array.from([9, 8, 7, 6]);
      dialerWs.sendBinary(pingFrame);
      const forwarded = await standbyWs.nextEvent();
      assert.equal(forwarded.type, "binary");
      assert.deepEqual(forwarded.data, pingFrame);

      // 5. Classic non-fast_open fallback exercises SQLite ArrayBuffer spillover + binary inject in live workerd.
      const classicL = await connectRawWs(wsV1Url);
      const classicDial = await connectRawWs(wsV1Url);
      const classicAcc = await connectRawWs(wsV1Url);
      try {
        const cId = crypto.generateKeyPairSync("ed25519");
        const cSpki = cId.publicKey.export({ format: "der", type: "spki" });
        const cRaw = new Uint8Array(cSpki.subarray(cSpki.length - 32));
        const cPub = b64url(cRaw);
        const cHmac = (op, n) => ({
          kind: "hmac",
          mac: computeRelayAuthHmacB64(
            new Uint8Array(secretBytes),
            op,
            "127.0.0.1",
            Buffer.from(n, "base64url"),
            cRaw,
          ),
        });
        const cReg = (n) =>
          b64url(
            crypto.sign(
              null,
              Buffer.concat([
                Buffer.from("tendril-relay-reg-v1\0"),
                Buffer.from("127.0.0.1", "utf8"),
                Buffer.from(n, "base64url"),
              ]),
              cId.privateKey,
            ),
          );
        const clc = await classicL.nextEvent();
        classicL.sendJson({
          op: "register",
          pub: cPub,
          sig: cReg(clc.data.nonce),
          auth: cHmac("register", clc.data.nonce),
          fast_open: false,
        });
        assert.equal((await classicL.nextEvent()).data.op, "registered");

        const cdc = await classicDial.nextEvent();
        const classicCidBytes = crypto.randomBytes(16);
        const classicCid = b64url(classicCidBytes);
        const spillFrame = crypto.randomBytes(4096);
        classicDial.sendJson({
          op: "dial",
          target_pub: cPub,
          conn_id: classicCid,
          auth: cHmac("dial", cdc.data.nonce),
          init_frame: b64url(spillFrame),
        });
        const incClassic = await classicL.nextEvent();
        assert.equal(incClassic.data.op, "incoming");
        assert.equal(incClassic.data.init_frame, undefined);

        const cac = await classicAcc.nextEvent();
        classicAcc.sendJson({
          op: "accept",
          pub: cPub,
          conn_id: classicCid,
          sig: b64url(
            crypto.sign(
              null,
              Buffer.concat([
                Buffer.from("tendril-relay-accept-v1\0"),
                Buffer.from("127.0.0.1", "utf8"),
                Buffer.from(cac.data.nonce, "base64url"),
                classicCidBytes,
              ]),
              cId.privateKey,
            ),
          ),
          auth: cHmac("accept", cac.data.nonce),
        });
        assert.equal((await classicAcc.nextEvent()).data.op, "ready");
        const injected = await classicAcc.nextEvent();
        assert.equal(injected.type, "binary");
        assert.deepEqual(Buffer.from(injected.data), spillFrame);
        assert.equal((await classicDial.nextEvent()).data.op, "ready");
      } finally {
        classicL.close();
        classicDial.close();
        classicAcc.close();
      }

      // 6. Tier 3 JCS RelayTicket admission verified inside live workerd.
      const ticketWs = await connectRawWs(wsV1Url);
      try {
        await ticketWs.nextEvent();
        const now = Math.floor(Date.now() / 1000);
        const unsignedTicket = {
          v: 1,
          issuer_pub: issuerPubB64,
          relay_host: "127.0.0.1",
          role: "dial",
          target_pub: "*",
          not_before: now - 60,
          not_after: now + 300,
        };
        const canonicalUnsigned = JSON.stringify({
          issuer_pub: unsignedTicket.issuer_pub,
          not_after: unsignedTicket.not_after,
          not_before: unsignedTicket.not_before,
          relay_host: unsignedTicket.relay_host,
          role: unsignedTicket.role,
          target_pub: unsignedTicket.target_pub,
          v: unsignedTicket.v,
        });
        const ticketSig = b64url(
          crypto.sign(
            null,
            Buffer.concat([
              Buffer.from("tendril-relay-ticket-v1\0"),
              Buffer.from(canonicalUnsigned, "utf8"),
            ]),
            issuerKp.privateKey,
          ),
        );
        ticketWs.sendJson({
          op: "dial",
          target_pub: b64url(crypto.randomBytes(32)),
          conn_id: b64url(crypto.randomBytes(16)),
          auth: { kind: "ticket", ticket: { ...unsignedTicket, sig: ticketSig } },
        });
        const ticketRes = await ticketWs.nextEvent();
        assert.equal(ticketRes.data.op, "error");
        assert.equal(ticketRes.data.code, "offline");
      } finally {
        ticketWs.close();
      }

      // 7. /v2/relay standby + fast_open flow inside live workerd.
      const v2L = await connectRawWs(wsV2Url);
      const v2Sb = await connectRawWs(wsV2Url);
      const v2D = await connectRawWs(wsV2Url);
      try {
        const v2Kp = crypto.generateKeyPairSync("ed25519");
        const v2Spki = v2Kp.publicKey.export({ format: "der", type: "spki" });
        const v2Raw = new Uint8Array(v2Spki.subarray(v2Spki.length - 32));
        const v2Pub = b64url(v2Raw);
        const v2RegSig = (nonceB64, epoch) => {
          const epBuf = Buffer.alloc(8);
          epBuf.writeBigUInt64BE(BigInt(epoch));
          return b64url(
            crypto.sign(
              null,
              Buffer.concat([
                Buffer.from("tendril-relay-reg-v2\0"),
                Buffer.from("127.0.0.1", "utf8"),
                Buffer.from(nonceB64, "base64url"),
                epBuf,
              ]),
              v2Kp.privateKey,
            ),
          );
        };
        const v2Hmac = (op, n) => ({
          kind: "hmac",
          mac: computeRelayAuthHmacB64(
            new Uint8Array(secretBytes),
            op,
            "127.0.0.1",
            Buffer.from(n, "base64url"),
            v2Raw,
          ),
        });
        const lc2 = await v2L.nextEvent();
        const ep = lc2.data.epoch;
        v2L.sendJson({
          op: "register",
          mailbox_id: v2Pub,
          epoch: ep,
          sig: v2RegSig(lc2.data.nonce, ep),
          auth: v2Hmac("register", lc2.data.nonce),
          fast_open: true,
        });
        assert.equal((await v2L.nextEvent()).data.op, "registered");

        const sc2 = await v2Sb.nextEvent();
        v2Sb.sendJson({
          op: "standby",
          mailbox_id: v2Pub,
          epoch: ep,
          sig: v2RegSig(sc2.data.nonce, ep),
          auth: v2Hmac("register", sc2.data.nonce),
        });
        assert.equal((await v2Sb.nextEvent()).data.op, "standby_ready");

        const dc2 = await v2D.nextEvent();
        const cid2 = b64url(crypto.randomBytes(16));
        const init2 = b64url(Uint8Array.from([5, 6, 7, 8]));
        v2D.sendJson({
          op: "dial",
          target_mailbox_id: v2Pub,
          epoch: ep,
          conn_id: cid2,
          dial_token: b64url(crypto.randomBytes(32)),
          auth: v2Hmac("dial", dc2.data.nonce),
          init_frame: init2,
        });
        const sbInc2 = await v2Sb.nextEvent();
        assert.equal(sbInc2.data.op, "incoming");
        assert.equal(sbInc2.data.epoch, ep);
        assert.equal(sbInc2.data.init_frame, init2);
        assert.equal((await v2D.nextEvent()).data.op, "ready");
        const frame2 = Uint8Array.from([0x12, 0x34]);
        v2D.sendBinary(frame2);
        const rx2 = await v2Sb.nextEvent();
        assert.equal(rx2.type, "binary");
        assert.deepEqual(rx2.data, frame2);
      } finally {
        v2L.close();
        v2Sb.close();
        v2D.close();
      }
    } finally {
      listenerWs.close();
      standbyWs.close();
      dialerWs.close();
    }
  } finally {
    if (sessV1 && !sessV1.isClosed()) {
      await sessV1.close(1000, "cleanup").catch(() => {});
    }
    if (sessV2 && !sessV2.isClosed()) {
      await sessV2.close(1000, "cleanup").catch(() => {});
    }
    if (client) {
      client.free();
    }
    peer.close();
    dev.close();
    fs.rmSync(persistDir, { recursive: true, force: true });
  }
});
