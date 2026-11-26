import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const RELAY_BIN = path.join(REPO_ROOT, "target", "debug", "tendril-relay");
const PEER_BIN = path.join(REPO_ROOT, "target", "debug", "tendril-conformance-peer");
const CLI_BIN = path.join(REPO_ROOT, "target", "debug", "tendril");
const SERVER_SCRIPT = path.join(REPO_ROOT, "bindings", "web", "demo", "server.mjs");

function findChrome() {
  for (const cand of ["google-chrome", "chromium", "chromium-browser"]) {
    const abs = path.join("/usr/bin", cand);
    if (fs.existsSync(abs)) return abs;
  }
  throw new Error("Chrome or Chromium binary not found under /usr/bin");
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

function spawnDemoServer(relayPort) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        SERVER_SCRIPT,
        "--listen",
        "127.0.0.1:0",
        "--relay-upstream",
        `127.0.0.1:${relayPort}`,
        "--serve-vectors",
      ],
      { stdio: ["ignore", "pipe", "pipe"] }
    );
    let acc = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`demo server startup timed out: ${acc}`));
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
    send(obj) {
      child.stdin.write(`${JSON.stringify(obj)}\n`);
    },
    recv() {
      if (lines.length > 0) return Promise.resolve(lines.shift());
      return new Promise((resolve) => waiters.push(resolve));
    },
    async call(obj) {
      this.send(obj);
      const res = await this.recv();
      assert.equal(res.ok, true, `peer op ${obj.op} failed: ${JSON.stringify(res)}`);
      return res;
    },
    close() {
      rl.close();
      child.kill();
    },
  };
}

function launchChrome(userDataDir) {
  return new Promise((resolve, reject) => {
    const chromeBin = findChrome();
    const chromeEnv = { ...process.env };
    if (chromeEnv.DBUS_SESSION_BUS_ADDRESS === "/dev/null") {
      delete chromeEnv.DBUS_SESSION_BUS_ADDRESS;
    }
    const child = spawn(
      chromeBin,
      [
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--password-store=basic",
        "--disable-background-networking",
        "--remote-debugging-port=0",
        `--user-data-dir=${userDataDir}`,
        "about:blank",
      ],
      { stdio: ["ignore", "pipe", "pipe"], env: chromeEnv }
    );
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`chrome CDP startup timed out: ${stderr}`));
    }, 45000);
    const onData = (chunk) => {
      stderr += chunk.toString("utf8");
      const m = stderr.match(/DevTools listening on (ws:\/\/127\.0\.0\.1:(\d+)\/[^\s]+)/);
      if (m) {
        clearTimeout(timer);
        resolve({ child, port: Number(m[2]) });
      }
    };
    child.stderr.on("data", onData);
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`chrome exited early (${code}): ${stderr}`));
    });
  });
}

class CdpClient {
  #ws;
  #nextId = 1;
  #pending = new Map();
  #eventWaiters = new Map();

  constructor(ws) {
    this.#ws = ws;
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (typeof msg.id === "number") {
        const p = this.#pending.get(msg.id);
        if (p) {
          this.#pending.delete(msg.id);
          if (msg.error) {
            p.reject(new Error(msg.error.message || JSON.stringify(msg.error)));
          } else {
            p.resolve(msg.result);
          }
        }
      } else if (msg.method) {
        const list = this.#eventWaiters.get(msg.method);
        if (list && list.length > 0) {
          list.shift()(msg.params);
        }
      }
    });
  }

  static async connect(wsUrl) {
    const ws = new WebSocket(wsUrl);
    await new Promise((resolve, reject) => {
      ws.addEventListener("open", resolve, { once: true });
      ws.addEventListener("error", (e) => reject(new Error(e.message || "CDP error")), {
        once: true,
      });
    });
    return new CdpClient(ws);
  }

  send(method, params = {}) {
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#ws.send(JSON.stringify({ id, method, params }));
    });
  }

  waitForEvent(method, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`timed out waiting for CDP ${method}`)),
        timeoutMs
      );
      const list = this.#eventWaiters.get(method) || [];
      list.push((params) => {
        clearTimeout(timer);
        resolve(params);
      });
      this.#eventWaiters.set(method, list);
    });
  }

  async evalAsync(expression) {
    const res = await this.send("Runtime.evaluate", {
      expression: `(async () => { ${expression} })()`,
      awaitPromise: true,
      returnByValue: true,
    });
    if (res.exceptionDetails) {
      throw new Error(
        res.exceptionDetails.exception?.description || JSON.stringify(res.exceptionDetails)
      );
    }
    return res.result?.value;
  }

  close() {
    this.#ws.close();
  }
}

async function main() {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "tendril-chrome-"));
  let relay;
  let server;
  let peer;
  let chrome;
  let cdp;

  try {
    relay = await spawnRelay();
    server = await spawnDemoServer(relay.port);
    peer = spawnPeer();
    chrome = await launchChrome(userDataDir);

    const targets = await (await fetch(`http://127.0.0.1:${chrome.port}/json/list`)).json();
    const pageTarget = targets.find((t) => t.type === "page") || targets[0];
    assert.ok(pageTarget && pageTarget.webSocketDebuggerUrl, "missing Chrome page target");

    cdp = await CdpClient.connect(pageTarget.webSocketDebuggerUrl);
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");

    const rootResp = await fetch(`${server.baseUrl}/`);
    assert.equal(rootResp.status, 200);
    assert.equal(rootResp.headers.get("x-frame-options"), "DENY");
    assert.equal(rootResp.headers.get("referrer-policy"), "no-referrer");
    assert.equal(rootResp.headers.get("x-content-type-options"), "nosniff");
    const rootCsp = rootResp.headers.get("content-security-policy") || "";
    assert.ok(rootCsp.includes("frame-ancestors 'none'"));
    assert.ok(rootCsp.includes("'wasm-unsafe-eval'"));
    const leakedServer = await fetch(`${server.baseUrl}/demo/server.mjs`);
    assert.equal(leakedServer.status, 404);

    const loaded = cdp.waitForEvent("Page.loadEventFired");
    await cdp.send("Page.navigate", { url: `${server.baseUrl}/?code=1111-2222-3333#pub=testpub` });
    await loaded;

    const demoSecurityState = await cdp.evalAsync(`
      for (let i = 0; i < 100; i += 1) {
        if ((document.getElementById('status')?.textContent || '').includes('WASM core ready')) {
          break;
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      return {
        status: document.getElementById('status')?.textContent || '',
        search: window.location.search,
        hash: window.location.hash,
        codeValue: document.getElementById('pair-code')?.value || '',
        pubValue: document.getElementById('target-pub')?.value || '',
        warningHidden: Boolean(document.getElementById('url-warning')?.hidden),
        warningText: document.getElementById('url-warning')?.textContent || '',
        redactChecked: Boolean(document.getElementById('redact-log-toggle')?.checked),
        localStorageKeys: Object.keys(localStorage),
      };
    `);
    assert.ok(demoSecurityState.status.includes("WASM core ready"));
    assert.equal(demoSecurityState.search, "");
    assert.equal(demoSecurityState.hash, "");
    // PRIV-08: query string secrets must NEVER populate pair-code; warning must be shown.
    assert.equal(demoSecurityState.codeValue, "");
    assert.equal(demoSecurityState.pubValue, "testpub");
    assert.equal(demoSecurityState.warningHidden, false);
    assert.ok(demoSecurityState.warningText.includes("query string"));
    assert.equal(demoSecurityState.redactChecked, true);
    assert.deepEqual(demoSecurityState.localStorageKeys, []);

    // Verify fragment (#code=...) IS accepted and immediately scrubbed.
    const loadedHash = cdp.waitForEvent("Page.loadEventFired");
    await cdp.send("Page.navigate", { url: `${server.baseUrl}/index.html#code=1111-2222-3333&pub=hashpub` });
    await loadedHash;
    const hashState = await cdp.evalAsync(`
      for (let i = 0; i < 100; i += 1) {
        if ((document.getElementById('status')?.textContent || '').includes('WASM core ready')) {
          break;
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      return {
        hash: window.location.hash,
        codeValue: document.getElementById('pair-code')?.value || '',
        pubValue: document.getElementById('target-pub')?.value || '',
        warningHidden: Boolean(document.getElementById('url-warning')?.hidden),
      };
    `);
    assert.equal(hashState.hash, "");
    assert.equal(hashState.codeValue, "1111-2222-3333");
    assert.equal(hashState.pubValue, "hashpub");
    assert.equal(hashState.warningHidden, true);

    // 1. Offline conformance vectors & Gate #8 Chrome WASM Argon2 benchmark.
    const offline = await cdp.evalAsync(`
      const sdk = await import('/src/index.js');
      await sdk.initTendril();

      const hexToBytes = (h) => {
        const out = new Uint8Array(h.length / 2);
        for (let i = 0; i < out.length; i += 1) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
        return out;
      };
      const hexToB64Url = (h) => sdk.b64urlEncode(hexToBytes(h));

      const fp = await (await fetch('/spec/vectors/fingerprints.json')).json();
      const rawPub = hexToBytes(fp.raw_pubkey_hex);
      const hh = hexToBytes(fp.handshake_hash_hex);
      if (sdk.deviceId(rawPub) !== fp.raw_device_id) throw new Error('deviceId mismatch');
      if (sdk.fingerprintHost(rawPub) !== fp.raw_host_fingerprint) throw new Error('host fp mismatch');
      if (sdk.fingerprintDevice(rawPub) !== fp.raw_device_fingerprint) throw new Error('dev fp mismatch');
      if (sdk.pairingSas(hh) !== fp.pairing_sas) throw new Error('sas mismatch');

      const pm = await (await fetch('/spec/vectors/pairing_mac.json')).json();
      const pmHh = hexToBytes(pm.handshake_hash_hex);
      const macRemote = sdk.computeCodeMac(pm.remote_3group.code_normalized, pmHh);
      if (sdk.b64urlEncode(macRemote) !== sdk.b64urlEncode(hexToBytes(pm.remote_3group.code_mac_hex))) {
        throw new Error('argon2 remote_3group mac mismatch');
      }
      const macLan = sdk.computeCodeMac(pm.lan_2group.code_normalized, pmHh);
      if (sdk.b64urlEncode(macLan) !== sdk.b64urlEncode(hexToBytes(pm.lan_2group.code_mac_hex))) {
        throw new Error('argon2 lan_2group mac mismatch');
      }

      const rot = await (await fetch('/spec/vectors/rotation.json')).json();
      const finalSeq = sdk.verifyRotationChainJson(
        hexToB64Url(rot.pinned_signing_pub_hex),
        hexToB64Url(rot.pinned_static_pub_hex),
        0,
        JSON.stringify(rot.chain.map((e) => e.record)),
        rot.chain[1].record.new_static_pub,
        rot.chain[1].record.new_signing_pub
      );
      if (finalSeq !== 2) throw new Error('rotation seq mismatch');
      let forkRejected = false;
      try {
        sdk.verifyRotationChainJson(
          hexToB64Url(rot.pinned_signing_pub_hex),
          hexToB64Url(rot.pinned_static_pub_hex),
          0,
          JSON.stringify([rot.chain[0].record, rot.fork_record.record]),
          rot.chain[1].record.new_static_pub,
          rot.chain[1].record.new_signing_pub
        );
      } catch {
        forkRejected = true;
      }
      if (!forkRejected) throw new Error('fork rotation chain was not rejected');

      const gv = await (await fetch('/spec/vectors/grants.json')).json();
      const keys = JSON.stringify({
        [gv.root_issuer_id]: hexToB64Url(gv.root_signing_pub_hex),
        [gv.delegate_id]: hexToB64Url(gv.delegate_signing_pub_hex),
      });
      const now = 1795564800;
      if (!sdk.verifyGrantJson(JSON.stringify(gv.delegated_valid), keys, gv.leaf_id, gv.root_issuer_id, 'fs.read:/photos/2026/a.jpg', now)) {
        throw new Error('valid grant rejected');
      }
      if (sdk.verifyGrantJson(JSON.stringify(gv.delegated_widened), keys, gv.leaf_id, gv.root_issuer_id, 'fs.read:/photos/2026/a.jpg', now)) {
        throw new Error('widened grant allowed');
      }
      if (!sdk.verifyGrantJson(JSON.stringify(gv.delegated_valid), keys, gv.leaf_id, gv.root_issuer_id, 'fs.read:/photos/2026/a.jpg', now, JSON.stringify(gv.revocation_list))) {
        throw new Error('valid grant with signed CRL rejected');
      }
      const forgedCrl = { ...gv.revocation_list, revoked_devices: [] };
      if (sdk.verifyGrantJson(JSON.stringify(gv.delegated_valid), keys, gv.leaf_id, gv.root_issuer_id, 'fs.read:/photos/2026/a.jpg', now, JSON.stringify(forgedCrl))) {
        throw new Error('forged CRL was accepted');
      }

      const benchMain = await sdk.benchmarkArgon2(3, { useWorker: false });
      const benchWorker = await sdk.benchmarkArgon2(2, { useWorker: true });

      return { benchMain, benchWorker };
    `);

    console.log("CHROME_VECTORS_OK=true");
    console.log(`CHROME_ARGON2_MAIN=${JSON.stringify(offline.benchMain)}`);
    console.log(`CHROME_ARGON2_WORKER=${JSON.stringify(offline.benchWorker)}`);
    assert.ok(offline.benchMain.maxMs < 3000, `Chrome Argon2 main too slow: ${offline.benchMain.maxMs}`);
    assert.ok(offline.benchWorker.maxMs < 3000, `Chrome Argon2 worker too slow: ${offline.benchWorker.maxMs}`);

    // 2. Live Browser WASM <-> /v1/relay <-> Rust tendril-conformance-peer E2E test.
    const peerInit = await peer.call({ op: "init", host_id: "web-e2e-host" });
    await peer.call({
      op: "serve_relay",
      relay_url: relay.wsUrl,
      expected_host: "127.0.0.1",
    });
    const pairCode = (await peer.call({ op: "issue_code", kind: "remote" })).code;

    const chromePairEval = cdp.evalAsync(`
      const sdk = await import('/src/index.js');
      window.__e2eSdk = sdk;
      window.__e2eClient = await sdk.TendrilWebClient.create({ hostId: 'chrome-client' });
      const res = await window.__e2eClient.pair({
        relayUrl: 'ws://127.0.0.1:${server.port}/v1/relay',
        targetPub: ${JSON.stringify(peerInit.relay_pub)},
        expectedHost: '127.0.0.1',
        code: ${JSON.stringify(pairCode)},
        deviceName: 'chrome-browser',
        deviceKind: 'web',
      });
      return res;
    `);
    const peerPair = await peer.call({ op: "pair" });
    const browserPair = await chromePairEval;
    assert.equal(browserPair.sas, peerPair.sas);
    assert.equal(browserPair.host_confirmed, false);
    // The explicit relay endpoint of a pairing call is stored as an operator route.
    const proxiedRelay = `ws://127.0.0.1:${server.port}/v1/relay`;
    assert.deepEqual(browserPair.routes_persisted, [{ hint: proxiedRelay, source: "operator" }]);
    const browserChecks = await cdp.evalAsync(`
      const sdk = window.__e2eSdk;
      const filtered = sdk.filterWebCompatibleEndpoints([
        'direct:192.0.2.1:7000',
        'wss://relay.example/v1/relay',
        'wss://relay.example/v2/relay',
      ]);
      return {
        candidates: filtered.candidates.map((c) => c.endpoint),
        skipped: filtered.skipped.map((s) => s.reason),
        kind: sdk.classifyPairingCode(${JSON.stringify(pairCode)}),
        routes: window.__e2eClient.peerRoutes('web-e2e-host').routes,
      };
    `);
    assert.deepEqual(browserChecks.candidates, ["wss://relay.example/v1/relay"]);
    assert.deepEqual(browserChecks.skipped, ["browser_unsupported", "relay_v2_not_authorized"]);
    assert.equal(browserChecks.kind, "remote3_group");
    assert.deepEqual(browserChecks.routes, [{ hint: proxiedRelay, source: "operator" }]);

    await peer.call({ op: "confirm", peer_id: peerPair.device_id, sas: peerPair.sas });
    const grantObj = (
      await peer.call({ op: "mint", peer_id: peerPair.device_id, caps: ["fs.read"] })
    ).grant;

    // Session connect MUST fail closed in the browser until confirmPeer is called.
    peer.send({ op: "connect" });
    const preConfirmRejected = await cdp.evalAsync(`
      try {
        await window.__e2eClient.connect({
          relayUrl: 'ws://127.0.0.1:${server.port}/v1/relay',
          targetPub: ${JSON.stringify(peerInit.relay_pub)},
          expectedHost: '127.0.0.1',
          targetHostId: 'web-e2e-host',
          grantJson: ${JSON.stringify(JSON.stringify(grantObj))},
        });
        return false;
      } catch (err) {
        return String(err);
      }
    `);
    assert.ok(typeof preConfirmRejected === "string" && preConfirmRejected.includes("pending"));
    assert.equal((await peer.recv()).ok, false);

    await cdp.evalAsync(`
      await window.__e2eClient.confirmPeer('web-e2e-host', ${JSON.stringify(browserPair.sas)});
    `);

    // Endpoint-free Day-2 connect over the stored operator route (verifying 0-RTT Dial.init_frame).
    const chromeConnEval = cdp.evalAsync(`
      const origSend = WebSocket.prototype.send;
      let capturedDialInit = null;
      const binaryLengths = [];
      let firstBinaryPrefix = null;
      WebSocket.prototype.send = function (data) {
        if (typeof data === 'string') {
          try {
            const msg = JSON.parse(data);
            if (msg.op === 'dial' && typeof msg.init_frame === 'string') {
              capturedDialInit = msg.init_frame;
            }
          } catch {}
        } else {
          const u8 = new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer, data.byteOffset || 0, data.byteLength);
          binaryLengths.push(u8.byteLength);
          if (firstBinaryPrefix === null) {
            firstBinaryPrefix = Array.from(u8.slice(0, 3));
          }
        }
        return origSend.call(this, data);
      };
      try {
        window.__e2eSession = await window.__e2eClient.connect({
          targetHostId: 'web-e2e-host',
          grantJson: ${JSON.stringify(JSON.stringify(grantObj))},
        });
      } finally {
        WebSocket.prototype.send = origSend;
      }
      const decodedInit = capturedDialInit ? window.__e2eSdk.b64urlDecode(capturedDialInit) : null;
      return {
        route: window.__e2eSession.route,
        established: window.__e2eSession.isEstablished(),
        allowRead: window.__e2eSession.authorize('fs.read'),
        denyExec: window.__e2eSession.authorize('shell.exec'),
        dialInitPrefix: decodedInit ? Array.from(decodedInit.slice(0, 3)) : null,
        dialInitLen: decodedInit ? decodedInit.byteLength : 0,
        binaryCount: binaryLengths.length,
        firstBinaryPrefix,
      };
    `);
    await peer.call({ op: "connect" });
    const connState = await chromeConnEval;
    assert.deepEqual(connState.route, {
      hint: proxiedRelay,
      endpoint: proxiedRelay,
      provider: "relay",
    });
    assert.equal(connState.established, true);
    assert.equal(connState.allowRead, true);
    assert.equal(connState.denyExec, false);
    assert.deepEqual(
      connState.dialInitPrefix,
      [0x54, 0x4e, 0x44],
      "Chrome relay Dial.init_frame must carry Tendril TND preamble + msg1"
    );
    assert.ok(connState.dialInitLen > 100, `unexpected init_frame length: ${connState.dialInitLen}`);
    assert.equal(
      connState.binaryCount,
      1,
      `expected only msg3 over binary WS (not duplicate msg1), got ${connState.binaryCount}`
    );
    assert.notDeepEqual(connState.firstBinaryPrefix, [0x54, 0x4e, 0x44]);
    assert.equal((await peer.call({ op: "authorize", cap: "fs.read" })).allowed, true);
    assert.equal((await peer.call({ op: "authorize", cap: "shell.exec" })).allowed, false);

    // Bidirectional encrypted data + rekey + ping/pong + revocation + close.
    await cdp.evalAsync(`await window.__e2eSession.sendData('hello-from-chrome');`);
    const ev1 = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(ev1.data_utf8, "hello-from-chrome");

    await cdp.evalAsync(`
      await window.__e2eSession.rekey();
      await window.__e2eSession.ping(42);
      await window.__e2eSession.sendData('after-ping-rekey');
    `);
    const evRk = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(evRk.event, "rekeyed");
    const ev2 = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(ev2.data_utf8, "after-ping-rekey");

    const browserPollAfterRekey = await cdp.evalAsync(`
      const evs = [];
      for (let i = 0; i < 4; i += 1) {
        const ev = await window.__e2eSession.pollEvent(500);
        if (ev.status === 'would_block') break;
        evs.push(ev);
      }
      return evs;
    `);
    assert.ok(browserPollAfterRekey.some((e) => e.event === "pong" && e.cookie === 42));

    await peer.call({ op: "send", data_utf8: "back-to-chrome" });
    const backPayload = await cdp.evalAsync(`
      const ev = await window.__e2eSession.pollEvent(2000);
      if (ev.event !== 'data') throw new Error('expected data event: ' + JSON.stringify(ev));
      return new TextDecoder().decode(window.__e2eSdk.b64urlDecode(ev.data_b64));
    `);
    assert.equal(backPayload, "back-to-chrome");

    await cdp.evalAsync(`
      await window.__e2eSession.sendData(new Uint8Array(65502).fill(65));
    `);
    const evLarge = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(evLarge.data_utf8.length, 65502);

    await peer.call({ op: "revoke", peer_id: peerPair.device_id });
    assert.equal((await peer.call({ op: "authorize", cap: "fs.read" })).allowed, false);

    const pollCloseRes = await cdp.evalAsync(`
      const pendingPoll = window.__e2eSession.pollEvent(2000);
      await window.__e2eSession.close(1000, 'done');
      const res = await pendingPoll;
      window.__e2eClient.free();
      return res;
    `);
    assert.equal(pollCloseRes.status, "eof");
    const evClosed = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(evClosed.event, "closed");
    await peer.call({ op: "shutdown" });

    // Verify default sans-I/O + relay flows never eagerly load iroh.js or pkg-p2p.
    const eagerP2pUrls = await cdp.evalAsync(`
      return performance
        .getEntriesByType('resource')
        .map((e) => e.name)
        .filter((u) => u.includes('iroh.js') || u.includes('pkg-p2p'));
    `);
    assert.deepEqual(eagerP2pUrls, []);

    // Now invoke opt-in parseP2pEndpoint and verify lazy loading works.
    await cdp.evalAsync(`
      const sampleId = '0'.repeat(64);
      const parsedP2p = await window.__e2eSdk.parseP2pEndpoint('iroh://' + sampleId + '?relay=https://relay.example/');
      if (parsedP2p.endpoint_id !== sampleId || parsedP2p.relays.length !== 1) {
        throw new Error('parseP2pEndpoint valid mismatch: ' + JSON.stringify(parsedP2p));
      }
      let p2pBadRejected = false;
      try {
        await window.__e2eSdk.parseP2pEndpoint('https://not-iroh.example');
      } catch {
        p2pBadRejected = true;
      }
      if (!p2pBadRejected) throw new Error('invalid iroh URI was not rejected');
    `);
    console.log("CHROME_LIVE_RELAY_E2E_OK=true");

    // 3. Headless Chrome E2E: serve_broker (broker+ws://), Happy Eyeballs multi-route fallback,
    //    and /v2/relay > /v1/relay preference in connectV2.
    const brokerPeer = spawnPeer();
    try {
      const bInit = await brokerPeer.call({ op: "init", host_id: "chrome-broker-host" });
      const brokerInfo = await brokerPeer.call({ op: "serve_broker" });
      assert.ok(brokerInfo.endpoint.startsWith("broker+ws://127.0.0.1:"));
      await brokerPeer.call({
        op: "serve_relay",
        relay_url: relay.wsUrl,
        expected_host: "127.0.0.1",
      });
      const bCode = (await brokerPeer.call({ op: "issue_code", kind: "remote" })).code;
      const deadEndpoint = "ws://127.0.0.1:1/v1/relay";
      const chromeBrokerPair = cdp.evalAsync(`
        const sdk = window.__e2eSdk;
        window.__brokerClient = await sdk.TendrilWebClient.create({ hostId: 'chrome-broker-client' });
        const uri = 'tendril://pair?v=1&host=chrome-broker-host&code=' + encodeURIComponent(${JSON.stringify(bCode)}) +
          '&k=' + encodeURIComponent(${JSON.stringify(bInit.static_pub)}) +
          '&sh=' + encodeURIComponent(${JSON.stringify(bInit.signing_pub_hash)}) +
          '&id=chrome-broker-host&rp=' + encodeURIComponent(${JSON.stringify(bInit.relay_pub)}) +
          '&ep=' + encodeURIComponent(${JSON.stringify(deadEndpoint)}) + ',' + encodeURIComponent(${JSON.stringify(brokerInfo.endpoint)});
        const res = await window.__brokerClient.pair({ pairingUri: uri, timeoutMs: 8000 });
        return res;
      `);
      const bPeerPair = await brokerPeer.call({ op: "pair" });
      const bRes = await chromeBrokerPair;
      assert.equal(bRes.sas, bPeerPair.sas);
      assert.equal(bRes.route.provider, "broker");
      assert.equal(bRes.route.hint, brokerInfo.endpoint);

      await brokerPeer.call({ op: "confirm", peer_id: bPeerPair.device_id, sas: bPeerPair.sas });
      const bGrant = (
        await brokerPeer.call({ op: "mint", peer_id: bPeerPair.device_id, caps: ["fs.read"] })
      ).grant;
      await cdp.evalAsync(`
        await window.__brokerClient.setPeerRoutes('chrome-broker-host', [
          ${JSON.stringify(deadEndpoint)},
          ${JSON.stringify(brokerInfo.endpoint)}
        ]);
      `);
      const chromeBrokerConn = cdp.evalAsync(`
        const sess = await window.__brokerClient.connect({
          targetHostId: 'chrome-broker-host',
          grantJson: ${JSON.stringify(JSON.stringify(bGrant))},
          timeoutMs: 8000,
        });
        await sess.sendData('hello-chrome-broker');
        const route = sess.route;
        await sess.close(1000, 'done');
        window.__brokerClient.free();
        return route;
      `);
      await brokerPeer.call({ op: "connect" });
      const bConnRoute = await chromeBrokerConn;
      assert.equal(bConnRoute.provider, "broker");
      assert.equal(bConnRoute.hint, brokerInfo.endpoint);
      const bMsg = await brokerPeer.call({ op: "recv", timeout_ms: 2000 });
      assert.equal(bMsg.data_utf8, "hello-chrome-broker");
      await brokerPeer.call({ op: "recv", timeout_ms: 2000 }).catch(() => {});

      // Verify /v2/relay priority over /v1/relay in Chrome via Wire v2 pairV2 + connectV2.
      const v2Code = (await brokerPeer.call({ op: "issue_code", kind: "remote" })).code;
      const v2RelayUrl = relay.wsUrl.replace("/v1/relay", "/v2/relay");
      const chromeV2Pair = cdp.evalAsync(`
        const sdk = window.__e2eSdk;
        window.__v2Client = await sdk.TendrilWebClient.create({ hostId: 'chrome-v2-client' });
        const uri = 'tendril://pair?v=1&host=chrome-broker-host&code=' + encodeURIComponent(${JSON.stringify(v2Code)}) +
          '&k=' + encodeURIComponent(${JSON.stringify(bInit.static_pub)}) +
          '&sh=' + encodeURIComponent(${JSON.stringify(bInit.signing_pub_hash)}) +
          '&id=chrome-broker-host&rp=' + encodeURIComponent(${JSON.stringify(bInit.relay_pub)}) +
          '&ep=' + encodeURIComponent(${JSON.stringify(relay.wsUrl)});
        return await window.__v2Client.pairV2({ pairingUri: uri, timeoutMs: 8000 });
      `);
      const v2PeerPair = await brokerPeer.call({ op: "pair_v2_accept" });
      const v2Res = await chromeV2Pair;
      assert.equal(v2Res.sas, v2PeerPair.sas);
      await brokerPeer.call({ op: "confirm", peer_id: v2PeerPair.device_id, sas: v2PeerPair.sas });
      const v2Grant = (
        await brokerPeer.call({ op: "mint", peer_id: v2PeerPair.device_id, caps: ["fs.read"] })
      ).grant;
      await brokerPeer.call({ op: "serve_relay_v2", relay_url: v2RelayUrl, expected_host: "127.0.0.1" });
      await cdp.evalAsync(`
        await window.__v2Client.setPeerRoutes('chrome-broker-host', [
          ${JSON.stringify(relay.wsUrl)},
          ${JSON.stringify(v2RelayUrl)}
        ]);
      `);
      const chromeV2Conn = cdp.evalAsync(`
        const origSend = WebSocket.prototype.send;
        let capturedDialInit = null;
        const binaryLengths = [];
        let firstBinaryPrefix = null;
        WebSocket.prototype.send = function (data) {
          if (typeof data === 'string') {
            try {
              const msg = JSON.parse(data);
              if (
                msg.op === 'dial' &&
                typeof msg.target_mailbox_id === 'string' &&
                typeof msg.init_frame === 'string'
              ) {
                capturedDialInit = msg.init_frame;
              }
            } catch {}
          } else {
            const u8 = new Uint8Array(
              data instanceof ArrayBuffer ? data : data.buffer,
              data.byteOffset || 0,
              data.byteLength
            );
            binaryLengths.push(u8.byteLength);
            if (firstBinaryPrefix === null) {
              firstBinaryPrefix = Array.from(u8.slice(0, 3));
            }
          }
          return origSend.call(this, data);
        };
        let sess;
        try {
          sess = await window.__v2Client.connectV2({
            targetHostId: 'chrome-broker-host',
            grantJson: ${JSON.stringify(JSON.stringify(v2Grant))},
            timeoutMs: 8000,
          });
        } finally {
          WebSocket.prototype.send = origSend;
        }
        await sess.sendData('hello-chrome-v2-relay');
        const route = sess.route;
        await sess.close(1000, 'done');
        window.__v2Client.free();
        const decodedInit = capturedDialInit ? window.__e2eSdk.b64urlDecode(capturedDialInit) : null;
        return {
          route,
          dialInitPrefix: decodedInit ? Array.from(decodedInit.slice(0, 3)) : null,
          dialInitLen: decodedInit ? decodedInit.byteLength : 0,
          binaryCount: binaryLengths.length,
          firstBinaryPrefix,
        };
      `);
      await brokerPeer.call({ op: "accept_v2" });
      const v2ConnState = await chromeV2Conn;
      assert.equal(v2ConnState.route.hint, v2RelayUrl);
      assert.equal(v2ConnState.route.provider, "relay");
      assert.deepEqual(
        v2ConnState.dialInitPrefix,
        [0x54, 0x4e, 0x44],
        "Chrome /v2/relay Dial.init_frame must carry Tendril TND preamble + msg1"
      );
      assert.ok(
        v2ConnState.dialInitLen > 100,
        `unexpected v2 init_frame length: ${v2ConnState.dialInitLen}`
      );
      assert.equal(
        v2ConnState.binaryCount,
        1,
        `expected only v2 msg3 over binary WS (not duplicate msg1), got ${v2ConnState.binaryCount}`
      );
      assert.notDeepEqual(v2ConnState.firstBinaryPrefix, [0x54, 0x4e, 0x44]);
      const v2Msg = await brokerPeer.call({ op: "recv", timeout_ms: 2000 });
      assert.equal(v2Msg.data_utf8, "hello-chrome-v2-relay");
      await brokerPeer.call({ op: "shutdown" });
    } finally {
      brokerPeer.close();
    }
    console.log("CHROME_LIVE_BROKER_AND_V2_PRIORITY_E2E_OK=true");

    // 4. Headless Chrome E2E: live WebTransport direct (wt://127.0.0.1:<port>?certhash=...)
    //    pair (including lan2_group) + Day-2 connect winning provider: "direct" ahead of relay.
    const wtPeer = spawnPeer();
    try {
      const wtInit = await wtPeer.call({ op: "init", host_id: "chrome-wt-host" });
      const wtInfo = await wtPeer.call({ op: "serve_wt" });
      assert.ok(
        wtInfo.endpoint.startsWith("wt://127.0.0.1:") && wtInfo.endpoint.includes("?certhash="),
        `unexpected wt endpoint: ${wtInfo.endpoint}`
      );
      await wtPeer.call({
        op: "serve_relay",
        relay_url: relay.wsUrl,
        expected_host: "127.0.0.1",
      });
      const wtLanCode = (await wtPeer.call({ op: "issue_code", kind: "lan" })).code;
      const chromeWtPair = cdp.evalAsync(`
        const sdk = window.__e2eSdk;
        window.__wtClient = await sdk.TendrilWebClient.create({ hostId: 'chrome-wt-client' });
        const uri = 'tendril://pair?v=1&host=chrome-wt-host&code=' + encodeURIComponent(${JSON.stringify(wtLanCode)}) +
          '&k=' + encodeURIComponent(${JSON.stringify(wtInit.static_pub)}) +
          '&sh=' + encodeURIComponent(${JSON.stringify(wtInit.signing_pub_hash)}) +
          '&id=chrome-wt-host' +
          '&ep=' + encodeURIComponent(${JSON.stringify(wtInfo.endpoint)});
        return await window.__wtClient.pair({ pairingUri: uri, timeoutMs: 8000 });
      `);
      const wtPeerPair = await wtPeer.call({ op: "pair" });
      const wtPairRes = await chromeWtPair;
      assert.equal(wtPairRes.sas, wtPeerPair.sas);
      assert.equal(wtPairRes.route.provider, "direct");
      assert.equal(wtPairRes.route.endpoint, wtInfo.endpoint);

      await wtPeer.call({ op: "confirm", peer_id: wtPeerPair.device_id, sas: wtPeerPair.sas });
      const wtGrant = (
        await wtPeer.call({ op: "mint", peer_id: wtPeerPair.device_id, caps: ["fs.read"] })
      ).grant;

      // Store relay ahead of wt:// to verify PathPlanner picks direct (provider: "direct") first.
      const proxiedWtRelay = `ws://127.0.0.1:${server.port}/v1/relay`;
      await cdp.evalAsync(`
        await window.__wtClient.setPeerRoutes('chrome-wt-host', [
          ${JSON.stringify(proxiedWtRelay)},
          ${JSON.stringify(wtInfo.endpoint)}
        ]);
      `);
      const chromeWtConn = cdp.evalAsync(`
        window.__wtSession = await window.__wtClient.connect({
          targetHostId: 'chrome-wt-host',
          grantJson: ${JSON.stringify(JSON.stringify(wtGrant))},
          timeoutMs: 8000,
        });
        await window.__wtSession.sendData('hello-from-chrome-wt');
        return {
          route: window.__wtSession.route,
          established: window.__wtSession.isEstablished(),
          allowRead: window.__wtSession.authorize('fs.read'),
        };
      `);
      await wtPeer.call({ op: "connect" });
      const wtConnState = await chromeWtConn;
      assert.equal(wtConnState.established, true);
      assert.equal(wtConnState.allowRead, true);
      assert.equal(wtConnState.route.provider, "direct");
      assert.equal(wtConnState.route.endpoint, wtInfo.endpoint);

      const wtMsg = await wtPeer.call({ op: "recv", timeout_ms: 2000 });
      assert.equal(wtMsg.data_utf8, "hello-from-chrome-wt");

      await wtPeer.call({ op: "send", data_utf8: "back-to-chrome-wt" });
      const wtBack = await cdp.evalAsync(`
        const ev = await window.__wtSession.pollEvent(2000);
        if (ev.event !== 'data') throw new Error('expected data event: ' + JSON.stringify(ev));
        const text = new TextDecoder().decode(window.__e2eSdk.b64urlDecode(ev.data_b64));
        await window.__wtSession.close(1000, 'done');
        window.__wtClient.free();
        return text;
      `);
      assert.equal(wtBack, "back-to-chrome-wt");
      await wtPeer.call({ op: "recv", timeout_ms: 2000 }).catch(() => {});
      await wtPeer.call({ op: "shutdown" });
    } finally {
      wtPeer.close();
    }
    console.log("CHROME_LIVE_WEBTRANSPORT_DIRECT_E2E_OK=true");

    if (process.env.TENDRIL_WEB_P2P_LIVE === "1") {
      assert.ok(fs.existsSync(CLI_BIN), `missing tendril binary at ${CLI_BIN}`);
      const p2pHostDir = fs.mkdtempSync(path.join(os.tmpdir(), "tendril-web-p2p-host-"));
      execFileSync(CLI_BIN, ["--state-dir", p2pHostDir, "init", "--host-id", "web-p2p-host"], {
        stdio: "pipe",
      });
      const serveChild = spawn(
        CLI_BIN,
        ["--state-dir", p2pHostDir, "serve", "--p2p", "--issue-code", "remote"],
        { stdio: ["ignore", "pipe", "pipe"] }
      );
      const serveRl = readline.createInterface({ input: serveChild.stdout });
      const serveLines = [];
      const serveWaiters = [];
      serveRl.on("line", (line) => {
        const obj = JSON.parse(line);
        if (serveWaiters.length > 0) serveWaiters.shift()(obj);
        else serveLines.push(obj);
      });
      const nextServeEvent = (timeoutMs = 20000) => {
        if (serveLines.length > 0) return Promise.resolve(serveLines.shift());
        return new Promise((resolve, reject) => {
          const t = setTimeout(
            () => reject(new Error("timed out waiting for tendril serve stdout event")),
            timeoutMs
          );
          serveWaiters.push((obj) => {
            clearTimeout(t);
            resolve(obj);
          });
        });
      };

      try {
        const listening = await nextServeEvent(15000);
        assert.equal(listening.event, "listening");
        const bareP2p = listening.p2p_endpoint.split("?")[0];
        assert.ok(bareP2p.startsWith("iroh://"), `missing iroh endpoint: ${listening.p2p_endpoint}`);

        assert.ok(listening.pairing_uri, "tendril serve --issue-code remote printed no pairing URI");
        // The URI's iroh:// hint is a hint dial: no address lookup, Default relay map.
        const p2pPairPromise = cdp.evalAsync(`
          window.__p2pClient = await window.__e2eSdk.TendrilWebClient.create({ hostId: 'chrome-p2p' });
          return await window.__p2pClient.pair({
            pairingUri: ${JSON.stringify(listening.pairing_uri)},
            deviceName: 'chrome-iroh',
            deviceKind: 'web',
            timeoutMs: 25000,
          });
        `);
        const [p2pBrowserPair, p2pServerPair] = await Promise.all([
          p2pPairPromise,
          nextServeEvent(25000),
        ]);
        assert.equal(p2pServerPair.event, "paired");
        assert.equal(p2pBrowserPair.sas, p2pServerPair.sas);
        assert.equal(p2pBrowserPair.route.provider, "p2p");
        // The URI pins the host key, so the browser records the host as confirmed.
        assert.equal(p2pBrowserPair.host_confirmed, true);

        execFileSync(
          CLI_BIN,
          ["--state-dir", p2pHostDir, "confirm", p2pBrowserPair.device_id, "--sas", p2pBrowserPair.sas],
          { stdio: "pipe" }
        );
        const p2pGrant = execFileSync(
          CLI_BIN,
          ["--state-dir", p2pHostDir, "mint", p2pBrowserPair.device_id, "--cap", "fs.read"],
          { encoding: "utf8" }
        ).trim();

        const connInfo = await cdp.evalAsync(`
          const sess = await window.__p2pClient.connect({
            endpoint: ${JSON.stringify(bareP2p)},
            targetHostId: 'web-p2p-host',
            grantJson: ${JSON.stringify(p2pGrant)},
            timeoutMs: 25000,
          });
          await sess.ping(77);
          let gotPong = false;
          for (let i = 0; i < 4; i += 1) {
            const ev = await sess.pollEvent(2000);
            if (ev.event === 'pong' && ev.cookie === 77) { gotPong = true; break; }
          }
          await sess.rekey();
          await sess.sendData('hello-from-chrome-iroh');
          const pendingClose = sess.pollEvent(3000);
          await sess.close(1000, 'done');
          const closeRes = await pendingClose;
          window.__p2pClient.free();
          return { established: true, gotPong, closeStatus: closeRes.status };
        `);
        assert.equal(connInfo.gotPong, true);
        assert.equal(connInfo.closeStatus, "eof");

        const p2pEst = await nextServeEvent(10000);
        assert.equal(p2pEst.event, "session_established");
        assert.equal(p2pEst.provider, "P2p");
        const p2pData = await nextServeEvent(10000);
        assert.equal(p2pData.event, "data");
        assert.equal(p2pData.utf8, "hello-from-chrome-iroh");
        const p2pClosed = await nextServeEvent(10000);
        assert.equal(p2pClosed.event, "closed");

        // Verify idempotent concurrent close() unblocks a parked recv_chunk() with zero borrow panic.
        const parkCloseRes = await cdp.evalAsync(`
          const errs = [];
          const onErr = (ev) => errs.push(String(ev.error || ev.message || ev));
          window.addEventListener('error', onErr);
          const parkedStream = await window.__e2eSdk.dialIrohStream({
            endpoint: ${JSON.stringify(bareP2p)},
            timeoutMs: 25000,
          });
          const pendingRecv = parkedStream.recv(60000);
          const t0 = performance.now();
          await Promise.all([parkedStream.close(), parkedStream.close()]);
          const closeElapsedMs = performance.now() - t0;
          const recvAfterClose = await pendingRecv;
          window.removeEventListener('error', onErr);
          return { closeElapsedMs, recvStatus: recvAfterClose.status, errors: errs };
        `);
        assert.equal(parkCloseRes.recvStatus, "eof");
        assert.deepEqual(parkCloseRes.errors, []);
        assert.ok(parkCloseRes.closeElapsedMs < 15000, `parked close took ${parkCloseRes.closeElapsedMs}ms`);
        console.log("CHROME_LIVE_IROH_P2P_E2E_OK=true");
      } finally {
        serveRl.close();
        serveChild.kill();
        fs.rmSync(p2pHostDir, { recursive: true, force: true });
      }
    }

    // 5. Live Headless Chrome <-> str0m in-band WebRTC DataChannel upgrade & cutover E2E test.
    const webrtcRelay = await spawnRelay();
    const webrtcPeer = spawnPeer();
    try {
      const wInit = await webrtcPeer.call({ op: "init", host_id: "web-webrtc-e2e-host" });
      const srRes = await webrtcPeer.call({
        op: "serve_relay",
        relay_url: webrtcRelay.wsUrl,
        expected_host: "127.0.0.1",
        webrtc_upgrade_bind: "127.0.0.1:0",
      });
      assert.ok(srRes.webrtc_upgrade_addr, "serve_relay must return webrtc_upgrade_addr");

      const wPairCode = (await webrtcPeer.call({ op: "issue_code", kind: "remote" })).code;
      const wPairPromise = webrtcPeer.call({ op: "pair" });
      const browserPair = await cdp.evalAsync(`
        window.__webrtcClient = await window.__e2eSdk.TendrilWebClient.create({ hostId: 'chrome-webrtc-client' });
        return await window.__webrtcClient.pair({
          relayUrl: ${JSON.stringify(webrtcRelay.wsUrl)},
          targetPub: ${JSON.stringify(wInit.relay_pub)},
          expectedHost: '127.0.0.1',
          code: ${JSON.stringify(wPairCode)},
          deviceName: 'chrome-webrtc',
          deviceKind: 'web',
          allowInsecureWs: true,
        });
      `);
      const peerPair = await wPairPromise;
      assert.equal(browserPair.sas, peerPair.sas);
      await webrtcPeer.call({ op: "confirm", peer_id: peerPair.device_id, sas: peerPair.sas });
      await cdp.evalAsync(`
        await window.__webrtcClient.confirmPeer('web-webrtc-e2e-host', ${JSON.stringify(browserPair.sas)});
      `);
      const wGrant = (
        await webrtcPeer.call({ op: "mint", peer_id: peerPair.device_id, caps: ["fs.read"] })
      ).grant;

      webrtcPeer.send({ op: "connect" });
      const preUpgradeState = await cdp.evalAsync(`
        window.__webrtcSession = await window.__webrtcClient.connect({
          targetHostId: 'web-webrtc-e2e-host',
          grantJson: ${JSON.stringify(JSON.stringify(wGrant))},
          allowInsecureWs: true,
        });
        return {
          route: window.__webrtcSession.route,
          caps: window.__webrtcSession.negotiatedUpgradeCaps(),
        };
      `);
      const connRes = await webrtcPeer.recv();
      assert.equal(connRes.ok, true);
      assert.equal(preUpgradeState.route?.provider, "relay");
      assert.ok(
        preUpgradeState.caps.includes("webrtc/v1"),
        `expected webrtc/v1 capability, got ${JSON.stringify(preUpgradeState.caps)}`
      );

      // Trigger concurrent pollEvent on the old WS relay stream, upgrade in-band to WebRTC DataChannel,
      // then kill the WS relay to prove encrypted traffic continues strictly over WebRTC UDP/SCTP.
      webrtcPeer.send({ op: "accept_upgraded_session", timeout_ms: 15000 });
      const upgradeRes = await cdp.evalAsync(`
        window.__webrtcPendingPoll = window.__webrtcSession.pollEvent(15000);
        const res = await window.__webrtcSession.upgradeToWebRtc({ timeoutMs: 15000 });
        return {
          res,
          route: window.__webrtcSession.route,
          allowRead: window.__webrtcSession.authorize('fs.read'),
          denyExec: window.__webrtcSession.authorize('shell.exec'),
        };
      `);
      const acceptRes = await webrtcPeer.recv(15000);
      assert.equal(
        upgradeRes.res.upgraded,
        true,
        `Chrome upgradeToWebRtc failed: ${JSON.stringify(upgradeRes)} (peer: ${JSON.stringify(acceptRes)})`
      );
      assert.equal(acceptRes.ok, true, `accept_upgraded_session failed: ${acceptRes.error}`);
      assert.deepEqual(upgradeRes.route, {
        hint: null,
        endpoint: "webrtc://tendril/v1",
        provider: "p2p",
      });
      assert.equal(upgradeRes.allowRead, true);
      assert.equal(upgradeRes.denyExec, false);

      // Sever the relay server completely so only direct Chrome <-> str0m WebRTC remains.
      webrtcRelay.child.kill();

      await webrtcPeer.call({ op: "send", data_utf8: "webrtc-host-to-chrome" });
      const concurrentPollGot = await cdp.evalAsync(`
        const ev = await window.__webrtcPendingPoll;
        if (ev.status !== 'event' || ev.event !== 'data') {
          throw new Error('concurrent pollEvent across cutover unexpected: ' + JSON.stringify(ev));
        }
        return new TextDecoder().decode(window.__e2eSdk.b64urlDecode(ev.data_b64));
      `);
      assert.equal(concurrentPollGot, "webrtc-host-to-chrome");

      await cdp.evalAsync(`
        await window.__webrtcSession.rekey();
        await window.__webrtcSession.ping(77);
        await window.__webrtcSession.sendData('webrtc-chrome-to-host');
      `);
      const evRekey = await webrtcPeer.call({ op: "recv", timeout_ms: 5000 });
      assert.equal(evRekey.event, "rekeyed");
      const evData = await webrtcPeer.call({ op: "recv", timeout_ms: 5000 });
      assert.equal(evData.data_utf8, "webrtc-chrome-to-host");

      const pongCheck = await cdp.evalAsync(`
        const ev = await window.__webrtcSession.pollEvent(5000);
        return ev;
      `);
      assert.equal(pongCheck.event, "pong");
      assert.equal(pongCheck.cookie, 77);

      await cdp.evalAsync(`
        await window.__webrtcSession.close(1000, 'webrtc-done');
        window.__webrtcClient.free();
      `);
      const evClosed = await webrtcPeer.call({ op: "recv", timeout_ms: 3000 });
      assert.equal(evClosed.event, "closed");
    } finally {
      webrtcPeer.close();
      webrtcRelay.child.kill();
    }

    // 6. Live Headless Chrome <-> str0m Wire v2 autoUpgradeWebRtc E2E test.
    const webrtcV2Relay = await spawnRelay();
    const webrtcV2Peer = spawnPeer();
    try {
      const w2Init = await webrtcV2Peer.call({ op: "init", host_id: "web-webrtc-v2-e2e-host" });
      await webrtcV2Peer.call({
        op: "serve_relay",
        relay_url: webrtcV2Relay.wsUrl,
        expected_host: "127.0.0.1",
      });
      await webrtcV2Peer.call({ op: "serve_webrtc", bind: "127.0.0.1:0" });

      const w2PairCode = (await webrtcV2Peer.call({ op: "issue_code", kind: "remote" })).code;
      const w2PairPromise = webrtcV2Peer.call({ op: "pair_v2_accept", timeout_ms: 10000 });
      const w2BrowserPair = await cdp.evalAsync(`
        window.__webrtcV2Client = await window.__e2eSdk.TendrilWebClient.create({ hostId: 'chrome-webrtc-v2-client' });
        return await window.__webrtcV2Client.pairV2({
          relayUrl: ${JSON.stringify(webrtcV2Relay.wsUrl)},
          targetPub: ${JSON.stringify(w2Init.relay_pub)},
          expectedHost: '127.0.0.1',
          code: ${JSON.stringify(w2PairCode)},
          deviceName: 'chrome-webrtc-v2',
          deviceKind: 'web',
          allowInsecureWs: true,
        });
      `);
      const w2PeerPair = await w2PairPromise;
      assert.equal(w2BrowserPair.sas, w2PeerPair.sas);
      await webrtcV2Peer.call({ op: "confirm", peer_id: w2PeerPair.device_id, sas: w2PeerPair.sas });
      await cdp.evalAsync(`
        await window.__webrtcV2Client.confirmPeer('web-webrtc-v2-e2e-host', ${JSON.stringify(w2BrowserPair.sas)});
      `);
      const w2Grant = (
        await webrtcV2Peer.call({ op: "mint", peer_id: w2PeerPair.device_id, caps: ["fs.read"] })
      ).grant;

      const v2RelayUrl = webrtcV2Relay.wsUrl.replace("/v1/relay", "/v2/relay");
      await webrtcV2Peer.call({
        op: "serve_relay_v2",
        relay_url: v2RelayUrl,
        expected_host: "127.0.0.1",
        peer_id: w2PeerPair.device_id,
      });

      webrtcV2Peer.send({ op: "accept_v2", timeout_ms: 10000 });
      const autoUpgradeEval = cdp.evalAsync(`
        window.__webrtcV2Session = await window.__webrtcV2Client.connectV2({
          relayUrl: ${JSON.stringify(v2RelayUrl)},
          targetPub: ${JSON.stringify(w2Init.relay_pub)},
          expectedHost: '127.0.0.1',
          targetHostId: 'web-webrtc-v2-e2e-host',
          grantJson: ${JSON.stringify(JSON.stringify(w2Grant))},
          useRelayV2: true,
          allowInsecureWs: true,
          autoUpgradeWebRtc: true,
        });
        return {
          route: window.__webrtcV2Session.route,
          allowRead: window.__webrtcV2Session.authorize('fs.read'),
          denyExec: window.__webrtcV2Session.authorize('shell.exec'),
        };
      `);
      const w2Conn = await webrtcV2Peer.recv();
      assert.equal(w2Conn.ok, true);
      webrtcV2Peer.send({ op: "accept_upgraded_session", timeout_ms: 15000, v2: true });
      const [v2AutoState, w2AcceptRes] = await Promise.all([
        autoUpgradeEval,
        webrtcV2Peer.recv(15000),
      ]);
      assert.equal(w2AcceptRes.ok, true, `v2 accept_upgraded_session failed: ${w2AcceptRes.error}`);
      assert.equal(w2AcceptRes.wire_version, 2);
      assert.deepEqual(v2AutoState.route, {
        hint: null,
        endpoint: "webrtc://tendril/v1",
        provider: "p2p",
      });
      assert.equal(v2AutoState.allowRead, true);
      assert.equal(v2AutoState.denyExec, false);

      webrtcV2Relay.child.kill();
      await webrtcV2Peer.call({ op: "send", data_utf8: "webrtc-v2-host-to-chrome" });
      const v2Data = await cdp.evalAsync(`
        const ev1 = await window.__webrtcV2Session.pollEvent(3000);
        if (ev1.status !== 'event' || ev1.event !== 'established') {
          throw new Error('expected single initial v2 established event, got: ' + JSON.stringify(ev1));
        }
        const ev2 = await window.__webrtcV2Session.pollEvent(3000);
        if (ev2.status !== 'event' || ev2.event !== 'data') {
          throw new Error('v2 post-cutover pollEvent unexpected (duplicate established?): ' + JSON.stringify(ev2));
        }
        await window.__webrtcV2Session.sendData('webrtc-v2-chrome-to-host');
        return new TextDecoder().decode(window.__e2eSdk.b64urlDecode(ev2.data_b64));
      `);
      assert.equal(v2Data, "webrtc-v2-host-to-chrome");
      const w2Ev = await webrtcV2Peer.call({ op: "recv", timeout_ms: 3000 });
      assert.equal(w2Ev.data_utf8, "webrtc-v2-chrome-to-host");

      await cdp.evalAsync(`
        await window.__webrtcV2Session.close(1000, 'webrtc-v2-done');
        window.__webrtcV2Client.free();
      `);
      const w2Closed = await webrtcV2Peer.call({ op: "recv", timeout_ms: 3000 });
      assert.equal(w2Closed.event, "closed");
      console.log("CHROME_LIVE_WEBRTC_UPGRADE_E2E_OK=true");
    } finally {
      webrtcV2Peer.close();
      webrtcV2Relay.child.kill();
    }
  } finally {
    if (cdp) {
      try {
        cdp.close();
      } catch {}
    }
    if (peer) peer.close();
    if (chrome) {
      chrome.child.kill("SIGKILL");
      await new Promise((resolve) => {
        chrome.child.once("exit", resolve);
        setTimeout(resolve, 1000);
      });
    }
    if (server) server.child.kill();
    if (relay) relay.child.kill();
    try {
      fs.rmSync(userDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    } catch {}
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
