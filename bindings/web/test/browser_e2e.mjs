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
    const child = spawn(
      chromeBin,
      [
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--remote-debugging-port=0",
        `--user-data-dir=${userDataDir}`,
        "about:blank",
      ],
      { stdio: ["ignore", "pipe", "pipe"] }
    );
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`chrome CDP startup timed out: ${stderr}`));
    }, 15000);
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
    const loaded = cdp.waitForEvent("Page.loadEventFired");
    await cdp.send("Page.navigate", { url: `${server.baseUrl}/` });
    await loaded;

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
        targetPub: ${JSON.stringify(peerInit.signing_pub)},
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

    await peer.call({ op: "confirm", peer_id: peerPair.device_id, sas: peerPair.sas });
    const grantObj = (
      await peer.call({ op: "mint", peer_id: peerPair.device_id, caps: ["fs.read"] })
    ).grant;

    const chromeConnEval = cdp.evalAsync(`
      window.__e2eSession = await window.__e2eClient.connect({
        relayUrl: 'ws://127.0.0.1:${server.port}/v1/relay',
        targetPub: ${JSON.stringify(peerInit.signing_pub)},
        expectedHost: '127.0.0.1',
        targetHostId: 'web-e2e-host',
        grantJson: ${JSON.stringify(JSON.stringify(grantObj))},
      });
      return {
        established: window.__e2eSession.isEstablished(),
        allowRead: window.__e2eSession.authorize('fs.read'),
        denyExec: window.__e2eSession.authorize('shell.exec'),
      };
    `);
    await peer.call({ op: "connect" });
    const connState = await chromeConnEval;
    assert.equal(connState.established, true);
    assert.equal(connState.allowRead, true);
    assert.equal(connState.denyExec, false);
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

        const p2pPairPromise = cdp.evalAsync(`
          window.__p2pClient = await window.__e2eSdk.TendrilWebClient.create({ hostId: 'chrome-p2p' });
          return await window.__p2pClient.pair({
            endpoint: ${JSON.stringify(bareP2p)},
            code: ${JSON.stringify(listening.pairing_code)},
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
