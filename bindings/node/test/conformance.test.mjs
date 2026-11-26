import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import test from "node:test";
import { fileURLToPath } from "node:url";

import tendril from "../index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..", "..");
const VECTORS = path.join(ROOT, "spec", "vectors");
const PEER_BIN = path.join(ROOT, "target", "debug", "tendril-conformance-peer");
const RELAY_BIN = path.join(ROOT, "target", "debug", "tendril-relay");

function ensureRelayBin() {
  if (!fs.existsSync(RELAY_BIN)) {
    const res = spawnSync("cargo", ["build", "-p", "tendril-relay", "--bin", "tendril-relay"], {
      cwd: ROOT,
      stdio: "inherit",
    });
    assert.equal(res.status, 0, "failed to build tendril-relay");
  }
}

function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

function spawnGatedRelay(authSecretFile, issuerPub) {
  ensureRelayBin();
  return new Promise((resolve, reject) => {
    const child = spawn(
      RELAY_BIN,
      [
        "--listen",
        "127.0.0.1:0",
        "--host",
        "127.0.0.1",
        "--auth-secret-file",
        authSecretFile,
        "--issuer-pub",
        issuerPub,
      ],
      {
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, RUST_LOG: "info" },
      }
    );
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
        resolve({
          child,
          v1Url: m[0],
          v2Url: `ws://127.0.0.1:${m[1]}/v2/relay`,
          port: Number(m[1]),
        });
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

function readVec(name) {
  return JSON.parse(fs.readFileSync(path.join(VECTORS, name), "utf8"));
}

function hexToB64Url(hex) {
  return Buffer.from(hex, "hex").toString("base64url");
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
      child.stdin.write(JSON.stringify(obj) + "\n");
    },
    recv() {
      if (lines.length > 0) {
        return Promise.resolve(lines.shift());
      }
      return new Promise((resolve) => waiters.push(resolve));
    },
    async call(obj) {
      this.send(obj);
      const resp = await this.recv();
      assert.equal(resp.ok, true, `peer call failed: ${JSON.stringify(resp)}`);
      return resp;
    },
    close() {
      rl.close();
      if (!child.killed) child.kill();
    },
  };
}

test("Node binding reproduces all v1 conformance vectors", async () => {
  const fp = readVec("fingerprints.json");
  const pub = Buffer.from(fp.raw_pubkey_hex, "hex");
  const hh = Buffer.from(fp.handshake_hash_hex, "hex");
  assert.equal(tendril.deviceId(pub), fp.raw_device_id);
  assert.equal(tendril.fingerprintHost(pub), fp.raw_host_fingerprint);
  assert.equal(tendril.fingerprintDevice(pub), fp.raw_device_fingerprint);
  assert.equal(tendril.pairingSas(hh), fp.pairing_sas);

  const pm = readVec("pairing_mac.json");
  const mac = await tendril.computeCodeMac(
    pm.remote_3group.code,
    Buffer.from(pm.handshake_hash_hex, "hex")
  );
  assert.equal(mac.toString("hex"), pm.remote_3group.code_mac_hex);

  const rot = readVec("rotation.json");
  const records = rot.chain.map((e) => e.record);
  const psig = hexToB64Url(rot.pinned_signing_pub_hex);
  const pstat = hexToB64Url(rot.pinned_static_pub_hex);
  const last = records[records.length - 1];
  assert.equal(
    tendril.verifyRotationChainJson(
      psig,
      pstat,
      0,
      JSON.stringify(records),
      last.new_static_pub,
      last.new_signing_pub
    ),
    2
  );
  assert.throws(() =>
    tendril.verifyRotationChainJson(
      psig,
      pstat,
      0,
      JSON.stringify([...records, rot.fork_record.record]),
      last.new_static_pub,
      last.new_signing_pub
    )
  );

  const gv = readVec("grants.json");
  const keys = JSON.stringify({
    [gv.root_issuer_id]: hexToB64Url(gv.root_signing_pub_hex),
    [gv.delegate_id]: hexToB64Url(gv.delegate_signing_pub_hex),
  });
  const now = 1795564800;
  assert.equal(
    tendril.verifyGrantJson(
      JSON.stringify(gv.delegated_valid),
      keys,
      gv.leaf_id,
      gv.root_issuer_id,
      "fs.read:/photos/2026/a.jpg",
      now
    ),
    true
  );
  assert.equal(
    tendril.verifyGrantJson(
      JSON.stringify(gv.delegated_widened),
      keys,
      gv.leaf_id,
      gv.root_issuer_id,
      "fs.read:/photos/2026/a.jpg",
      now
    ),
    false
  );
  assert.equal(
    tendril.verifyGrantJson(
      JSON.stringify(gv.delegated_valid),
      keys,
      gv.leaf_id,
      gv.root_issuer_id,
      "fs.read:/photos/2026/a.jpg",
      now,
      JSON.stringify(gv.revocation_list)
    ),
    true
  );
  const forgedCrl = { ...gv.revocation_list, revoked_devices: [] };
  assert.equal(
    tendril.verifyGrantJson(
      JSON.stringify(gv.delegated_valid),
      keys,
      gv.leaf_id,
      gv.root_issuer_id,
      "fs.read:/photos/2026/a.jpg",
      now,
      JSON.stringify(forgedCrl)
    ),
    false
  );
});

test("Node N-API keeps JS event loop responsive during Argon2 computeCodeMac", async () => {
  let ticks = 0;
  const timer = setInterval(() => {
    ticks += 1;
  }, 5);
  try {
    const macs = await Promise.all(
      [0, 1, 2, 3].map((i) => tendril.computeCodeMac("4829-1704", Buffer.alloc(32, i)))
    );
    for (const mac of macs) {
      assert.equal(mac.length, 32);
    }
  } finally {
    clearInterval(timer);
  }
  assert.ok(ticks >= 2, `expected event loop ticks during Argon2, got ${ticks}`);
});

test("Node N-API bidirectional async interop with Rust tendril-conformance-peer", async () => {
  const peer = spawnPeer();
  const hostEp = new tendril.Endpoint(null, "node-host");
  try {
    const info = JSON.parse(hostEp.infoJson());
    assert.equal(info.host_id, "node-host");
    assert.ok(info.device_id.startsWith("dev_"));
    assert.throws(() => hostEp.issueCode("invalid"));

    const addr = await hostEp.serveDirect("127.0.0.1:0");
    const code = hostEp.issueCode("lan");
    await peer.call({ op: "init", host_id: "rust-cli" });

    const [acceptRaw, peerPair] = await Promise.all([
      hostEp.pairAccept(5000),
      peer.call({ op: "pair", endpoint: addr, code, name: "rust-cli" }),
    ]);
    const accepted = JSON.parse(acceptRaw);
    assert.equal(accepted.sas, peerPair.sas);

    hostEp.confirmPeer(accepted.device_id, accepted.sas);
    await peer.call({ op: "confirm", peer_id: "node-host", sas: accepted.sas });
    const grantJson = hostEp.mintGrant(accepted.device_id, ["fs.read"], 3600);
    const grantObj = JSON.parse(grantJson);

    const [hostSess, cliConn] = await Promise.all([
      hostEp.acceptSession(5000),
      peer.call({
        op: "connect",
        endpoint: addr,
        target_host_id: "node-host",
        grant: grantObj,
      }),
    ]);
    assert.equal(cliConn.ok, true);
    assert.equal(hostSess.peerId, accepted.device_id);
    assert.equal(await hostSess.authorize("fs.read"), true);
    assert.equal(await hostSess.authorize("shell.exec"), false);

    await peer.call({ op: "send", data_utf8: "hello-to-node" });
    const ev = JSON.parse(await hostSess.pollEvent(2000));
    assert.equal(ev.event, "data");
    assert.equal(Buffer.from(ev.data_b64, "base64url").toString("utf8"), "hello-to-node");

    await hostSess.rekey();
    const rkLocal = JSON.parse(await hostSess.pollEvent(2000));
    assert.equal(rkLocal.event, "rekeyed");
    const rkPeer = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(rkPeer.event, "rekeyed");

    await hostSess.sendData(Buffer.from("reply-from-node", "utf8"));
    const peerEv = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(peerEv.data_utf8, "reply-from-node");

    hostEp.revokePeer(accepted.device_id);
    assert.equal(await hostSess.authorize("fs.read"), false);
    assert.equal(hostSess.peerId, accepted.device_id);

    await hostSess.close(1000, "done");
    await peer.call({ op: "shutdown" });
  } finally {
    hostEp.close();
    peer.close();
  }

  // Direction 2: Node client -> Rust conformance peer host.
  const peer2 = spawnPeer();
  const cliEp = new tendril.Endpoint(null, "node-cli");
  try {
    await peer2.call({ op: "init", host_id: "rust-host" });
    const srv = await peer2.call({ op: "serve_direct" });
    const code2 = (await peer2.call({ op: "issue_code", kind: "lan" })).code;

    const [pairRaw, peerPair2] = await Promise.all([
      cliEp.pairInitiate(srv.endpoint, code2, null, "node-dev", "node"),
      peer2.call({ op: "pair" }),
    ]);
    const pairRes = JSON.parse(pairRaw);
    assert.equal(pairRes.sas, peerPair2.sas);

    await peer2.call({ op: "confirm", peer_id: peerPair2.device_id, sas: pairRes.sas });
    const grantObj2 = (
      await peer2.call({
        op: "mint",
        peer_id: peerPair2.device_id,
        caps: ["fs.read"],
      })
    ).grant;

    // Connecting before client confirmPeer must fail closed.
    peer2.send({ op: "connect" });
    await assert.rejects(cliEp.connect(srv.endpoint, "rust-host", JSON.stringify(grantObj2)));
    assert.equal((await peer2.recv()).ok, false);
    cliEp.confirmPeer("rust-host", pairRes.sas);

    const [cliSess, hostConn] = await Promise.all([
      cliEp.connect(srv.endpoint, "rust-host", JSON.stringify(grantObj2)),
      peer2.call({ op: "connect" }),
    ]);
    assert.equal(hostConn.ok, true);
    assert.equal(cliSess.peerId, "rust-host");

    await cliSess.sendData(Buffer.from("hello-from-node-client", "utf8"));
    const hostRecv = await peer2.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(hostRecv.data_utf8, "hello-from-node-client");

    await cliSess.rekey();
    const rkCli = JSON.parse(await cliSess.pollEvent(2000));
    assert.equal(rkCli.event, "rekeyed");

    await peer2.call({ op: "send", data_utf8: "back-to-node-client" });
    const cliEv = JSON.parse(await cliSess.pollEvent(2000));
    assert.equal(cliEv.event, "data");
    assert.equal(
      Buffer.from(cliEv.data_b64, "base64url").toString("utf8"),
      "back-to-node-client"
    );

    await cliSess.close(1000, "done");
    await peer2.call({ op: "shutdown" });
  } finally {
    cliEp.close();
    peer2.close();
  }
});

test("Node binding pairs and connects over local P2p (disabled relay mode)", async () => {
  const hostEp = new tendril.Endpoint(null, "node-p2p-host");
  const cliEp = new tendril.Endpoint(null, "node-p2p-cli");
  try {
    const p2pAddr = await hostEp.serveP2p("disabled");
    assert.ok(p2pAddr.startsWith("iroh://"), `expected iroh:// endpoint, got ${p2pAddr}`);

    const lanCode = hostEp.issueCode("lan");
    await assert.rejects(
      Promise.all([
        cliEp.pairInitiate(p2pAddr, lanCode, "disabled", "node-p2p-lan", "node"),
        hostEp.pairAccept(5000),
      ])
    );

    const code = hostEp.issueCode("remote");
    const [pairRaw, accRaw] = await Promise.all([
      cliEp.pairInitiate(p2pAddr, code, "disabled", "node-p2p-dev", "node"),
      hostEp.pairAccept(8000),
    ]);
    const pairCli = JSON.parse(pairRaw);
    const acc = JSON.parse(accRaw);
    assert.equal(pairCli.sas, acc.sas);

    hostEp.confirmPeer(acc.device_id, pairCli.sas);
    cliEp.confirmPeer("node-p2p-host", pairCli.sas);
    const grantJson = hostEp.mintGrant(acc.device_id, ["fs.read"], 3600);
    const [cliSess, hostSess] = await Promise.all([
      cliEp.connect(p2pAddr, "node-p2p-host", grantJson, "disabled"),
      hostEp.acceptSession(8000),
    ]);
    await cliSess.sendData(Buffer.from("node-p2p-ok", "utf8"));
    const ev = JSON.parse(await hostSess.pollEvent(2000));
    assert.equal(ev.event, "data");
    assert.equal(Buffer.from(ev.data_b64, "base64url").toString("utf8"), "node-p2p-ok");
    await cliSess.close(1000, "done");
    const closeEv = JSON.parse(await hostSess.pollEvent(2000));
    assert.ok(closeEv.event === "closed" || closeEv.status === "eof", `expected close/eof, got ${JSON.stringify(closeEv)}`);
  } finally {
    hostEp.close();
    cliEp.close();
  }
});

test("Node binding isolates Intent::Pair flood from acceptSession", async () => {
  const hostEp = new tendril.Endpoint(null, "node-sec03-host");
  const cliEp = new tendril.Endpoint(null, "node-sec03-cli");
  const sockets = [];
  try {
    const addr = await hostEp.serveDirect("127.0.0.1:0");
    const code = hostEp.issueCode("lan");
    const [pairRaw, accRaw] = await Promise.all([
      cliEp.pairInitiate(addr, code, null, "node-sec03", "node"),
      hostEp.pairAccept(5000),
    ]);
    const pairCli = JSON.parse(pairRaw);
    const acc = JSON.parse(accRaw);
    hostEp.confirmPeer(acc.device_id, pairCli.sas);
    cliEp.confirmPeer("node-sec03-host", pairCli.sas);
    const grantJson = hostEp.mintGrant(acc.device_id, ["fs.read"], 3600);

    const port = Number(addr.split(":").pop());
    for (let i = 0; i < 32; i += 1) {
      if (i === 24) {
        await new Promise((r) => setTimeout(r, 1500));
      }
      const sock = net.createConnection({ host: "127.0.0.1", port });
      await new Promise((resolve, reject) => {
        sock.once("connect", () => sock.write(Buffer.from("TND\x01\x02\x00", "latin1"), resolve));
        sock.once("error", reject);
      });
      sockets.push(sock);
    }
    await new Promise((r) => setTimeout(r, 300));

    const [cliSess, hostSess] = await Promise.all([
      cliEp.connect(addr, "node-sec03-host", grantJson),
      hostEp.acceptSession(4000),
    ]);
    await cliSess.sendData(Buffer.from("after-pair-flood", "utf8"));
    const ev = JSON.parse(await hostSess.pollEvent(2000));
    assert.equal(ev.event, "data");
    await cliSess.close(1000, "done");
  } finally {
    for (const s of sockets) s.destroy();
    hostEp.close();
    cliEp.close();
  }
});

test("Node binding validates safe integers and runs full-duplex session ops concurrently", async () => {
  const gv = readVec("grants.json");
  const keysJson = JSON.stringify({
    [gv.root_issuer_id]: hexToB64Url(gv.root_signing_pub_hex),
    [gv.delegate_id]: hexToB64Url(gv.delegate_signing_pub_hex),
  });
  const grantJson = JSON.stringify(gv.delegated_valid);
  const rot = readVec("rotation.json");
  const records = rot.chain.map((e) => e.record);
  const psig = hexToB64Url(rot.pinned_signing_pub_hex);
  const pstat = hexToB64Url(rot.pinned_static_pub_hex);
  const last = records[records.length - 1];

  // SEC-07: reject NaN, Infinity, negative, fractional, and unsafe integers across helpers & methods.
  for (const bad of [NaN, Infinity, -Infinity, -1, 1.5, 2 ** 53, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() =>
      tendril.verifyGrantJson(
        grantJson,
        keysJson,
        gv.leaf_id,
        gv.root_issuer_id,
        "fs.read:/photos/2026/a.jpg",
        bad
      )
    );
    assert.throws(() =>
      tendril.verifyRotationChainJson(
        psig,
        pstat,
        bad,
        JSON.stringify(records),
        last.new_static_pub,
        last.new_signing_pub
      )
    );
  }

  const hostEp = new tendril.Endpoint(null, "node-sec07-host");
  const cliEp = new tendril.Endpoint(null, "node-sec07-cli");
  try {
    const addr = await hostEp.serveDirect("127.0.0.1:0");
    const code = hostEp.issueCode("lan");
    const [pairRaw, accRaw] = await Promise.all([
      cliEp.pairInitiate(addr, code, null, "node-conc", "node"),
      hostEp.pairAccept(5000),
    ]);
    const pairCli = JSON.parse(pairRaw);
    const acc = JSON.parse(accRaw);
    hostEp.confirmPeer(acc.device_id, pairCli.sas);
    cliEp.confirmPeer("node-sec07-host", pairCli.sas);

    for (const badTtl of [-1, NaN, Infinity, 1.5, 2 ** 53]) {
      assert.throws(() => hostEp.mintGrant(acc.device_id, ["fs.read"], badTtl));
    }
    const largeTtlGrant = JSON.parse(hostEp.mintGrant(acc.device_id, ["fs.read"], 2 ** 32 + 5));
    const nbf = Date.parse(largeTtlGrant.not_before) / 1000;
    const exp = Date.parse(largeTtlGrant.not_after) / 1000;
    assert.equal(exp - nbf, 2 ** 32 + 5);

    for (const badTimeout of [-1, NaN, Infinity, 1.5, 2 ** 32]) {
      await assert.rejects(hostEp.pairAccept(badTimeout));
      await assert.rejects(hostEp.acceptSession(badTimeout));
    }

    const grantJson = hostEp.mintGrant(acc.device_id, ["fs.read"], 3600);
    const [cliSess, hostSess] = await Promise.all([
      cliEp.connect(addr, "node-sec07-host", grantJson),
      hostEp.acceptSession(5000),
    ]);
    for (const badTimeout of [-1, NaN, Infinity, 1.5, 2 ** 32]) {
      await assert.rejects(hostSess.pollEvent(badTimeout));
    }
    for (const badCode of [-1, NaN, 1.5, 65536]) {
      await assert.rejects(cliSess.close(badCode, "bad"));
    }

    // SEC-17: Concurrent sendData + authorize + rekey must not wait on an active pollEvent(5000).
    const pollPromise = hostSess.pollEvent(5000);
    await new Promise((r) => setTimeout(r, 60));
    const t0 = Date.now();
    assert.equal(await hostSess.authorize("fs.read"), true);
    assert.equal(hostSess.peerId, acc.device_id);
    assert.equal(cliSess.peerId, "node-sec07-host");
    await hostSess.sendData(Buffer.from("node-duplex-reply", "utf8"));
    const cliEv = JSON.parse(await cliSess.pollEvent(2000));
    assert.equal(cliEv.event, "data");
    assert.equal(Buffer.from(cliEv.data_b64, "base64url").toString("utf8"), "node-duplex-reply");
    await cliSess.sendData(Buffer.from("wake-host-poll", "utf8"));
    const hostEv = JSON.parse(await pollPromise);
    assert.equal(hostEv.event, "data");
    assert.ok(Date.now() - t0 < 1500, "full-duplex Node ops stalled behind pollEvent");

    // SEC-31: grant expiring while hostSess.pollEvent(6000) is awaiting rejects incoming rekey.
    const shortGrant = hostEp.mintGrant(acc.device_id, ["fs.read"], 3);
    const [cliSess2, hostSess2] = await Promise.all([
      cliEp.connect(addr, "node-sec07-host", shortGrant),
      hostEp.acceptSession(5000),
    ]);
    const expPollCheck = assert.rejects(hostSess2.pollEvent(6000));
    await new Promise((r) => setTimeout(r, 3500));
    await cliSess2.rekey();
    await expPollCheck;
    await cliSess2.close(1000, "done");
    await cliSess.close(1000, "done");
  } finally {
    hostEp.close();
    cliEp.close();
  }
});

const ADVERTISED_ROUTE = "direct:192.168.77.5:9";

async function enrollInto(hostEp, cliEp, cfg) {
  if (cfg) cliEp.configureTransportsJson(JSON.stringify(cfg));
  hostEp.configureTransportsJson(
    JSON.stringify({ advertise: "explicit", advertised_endpoints: [ADVERTISED_ROUTE] }),
  );
  const hostInfo = JSON.parse(hostEp.infoJson());
  const cliInfo = JSON.parse(cliEp.infoJson());
  const addr = await hostEp.serveDirect("127.0.0.1:0");
  // The announcer starts on first use: publish the host's route set before enrolling.
  await hostEp.refreshRoutes();
  const token = hostEp.mintEnrollmentToken(hostInfo.host_id, cliInfo.device_id, 900);
  const [res] = await Promise.all([
    cliEp.enrollInitiate(
      addr,
      hostInfo.host_id,
      Buffer.from(hostInfo.static_pub, "base64url"),
      Buffer.from(hostInfo.signing_pub, "base64url"),
      token,
    ),
    hostEp.pairAccept(5000),
  ]);
  const routes = JSON.parse(await cliEp.peerRoutes(hostInfo.host_id));
  return { res: JSON.parse(res), routes };
}

test("Node enrollInitiate stores routes per route policy and none without a state dir", async () => {
  const dirs = [];
  const tmp = () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), "tendril-node-enroll-"));
    dirs.push(d);
    return d;
  };
  const eps = [];
  const open = (dir, name) => {
    const ep = new tendril.Endpoint(dir, name);
    eps.push(ep);
    return ep;
  };
  const sources = (routes) => routes.routes.map((r) => [r.source, r.hint]);
  try {
    let { res, routes } = await enrollInto(open(tmp(), "node-enr-host"), open(tmp(), null));
    assert.equal(res.status, "active");
    assert.ok(res.routes_persisted.length > 0, JSON.stringify(res));
    assert.ok(
      sources(routes).some(([s, h]) => s === "signed" && h === ADVERTISED_ROUTE),
      JSON.stringify(routes),
    );
    assert.ok(sources(routes).some(([s]) => s === "committed"), JSON.stringify(routes));

    ({ res, routes } = await enrollInto(open(tmp(), "node-enr-host"), open(tmp(), null), {
      route_policy: "committed_only",
    }));
    assert.equal(res.status, "active");
    assert.ok(
      sources(routes).length > 0 && sources(routes).every(([s]) => s === "committed"),
      JSON.stringify(routes),
    );

    ({ res, routes } = await enrollInto(open(tmp(), "node-enr-host"), open(tmp(), null), {
      route_policy: "none",
    }));
    assert.equal(res.status, "active");
    assert.deepEqual(res.routes_persisted, []);
    assert.deepEqual(routes.routes, []);

    ({ res, routes } = await enrollInto(open(tmp(), "node-enr-host"), open(null, null)));
    assert.equal(res.status, "active");
    assert.deepEqual(res.routes_persisted, []);
    assert.equal(res.routes_reason, "no_state_dir");
    assert.deepEqual(routes.routes, []);
  } finally {
    for (const ep of eps) ep.close();
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  }
});

test("Node M2M enrollment, single-use replay, and anchor revocation", async () => {
  const hostEp = new tendril.Endpoint(null, "node-m2m-host");
  const anchorEp = new tendril.Endpoint(null, "node-m2m-anchor");
  const cliEp = new tendril.Endpoint(null, "node-m2m-cli");
  const cli2Ep = new tendril.Endpoint(null, "node-m2m-cli2");
  try {
    const hostInfo = JSON.parse(hostEp.infoJson());
    const anchorInfo = JSON.parse(anchorEp.infoJson());
    const hostStatic = Buffer.from(hostInfo.static_pub, "base64url");
    const hostSigning = Buffer.from(hostInfo.signing_pub, "base64url");
    const hostSigningHash = Buffer.from(hostInfo.signing_pub_hash, "base64url");
    const anchorSigning = Buffer.from(anchorInfo.signing_pub, "base64url");
    assert.equal(hostSigning.length, 1984);
    assert.equal(hostSigningHash.length, 32);
    assert.equal(anchorSigning.length, 1984);

    hostEp.addTrustAnchor("node-m2m-anchor", anchorSigning);
    const addr = await hostEp.serveDirect("127.0.0.1:0");
    const tokJson = anchorEp.mintEnrollmentToken("node-m2m-host", null, 900);

    for (const badTtl of [-1, NaN, Infinity, 1.5, 2 ** 53]) {
      assert.throws(() => anchorEp.mintEnrollmentToken("node-m2m-host", null, badTtl));
    }
    for (const badSeq of [-1, NaN, Infinity, 1.5, 2 ** 53]) {
      await assert.rejects(
        cliEp.enrollInitiate(addr, "node-m2m-host", hostStatic, hostSigning, tokJson, null, badSeq)
      );
    }

    const [initRaw, accRaw] = await Promise.all([
      cliEp.enrollInitiate(
        addr,
        "node-m2m-host",
        hostStatic,
        hostSigning,
        tokJson,
        null,
        0,
        "node-worker",
        "machine"
      ),
      hostEp.pairAccept(5000),
    ]);
    const initRes = JSON.parse(initRaw);
    const accRes = JSON.parse(accRaw);
    assert.equal(initRes.status, "active");
    assert.equal(accRes.status, "active");
    assert.equal(initRes.device_id, accRes.device_id);

    const [repInitRes] = await Promise.allSettled([
      cliEp.enrollInitiate(addr, "node-m2m-host", hostStatic, hostSigning, tokJson),
      hostEp.pairAccept(5000).catch(() => null),
    ]);
    assert.equal(repInitRes.status, "rejected");
    assert.match(String(repInitRes.reason), /token_replayed/);

    const grantJson = hostEp.mintGrant(initRes.device_id, ["fs.read"], 3600);
    const [cliSess, hostSess] = await Promise.all([
      cliEp.connect(addr, "node-m2m-host", grantJson),
      hostEp.acceptSession(5000),
    ]);
    assert.equal(await hostSess.authorize("fs.read"), true);
    assert.equal(await hostSess.authorize("shell.exec"), false);
    assert.equal(cliSess.peerId, "node-m2m-host");
    assert.equal(hostSess.peerId, initRes.device_id);
    await cliSess.close(1000, "done");

    hostEp.revokeTrustAnchor("node-m2m-anchor");
    const freshTok = anchorEp.mintEnrollmentToken("node-m2m-host", null, 900);
    const [revRes] = await Promise.allSettled([
      cli2Ep.enrollInitiate(addr, "node-m2m-host", hostStatic, hostSigning, freshTok),
      hostEp.pairAccept(5000).catch(() => null),
    ]);
    assert.equal(revRes.status, "rejected");
    assert.match(String(revRes.reason), /unauthorized/);

    const selfTok = hostEp.mintEnrollmentToken("node-m2m-host", null, 900);
    const [revAnchorRes] = await Promise.allSettled([
      cli2Ep.enrollInitiate(addr, "node-m2m-host", hostStatic, hostSigning, freshTok),
      hostEp.pairAccept(5000).catch(() => null),
    ]);
    assert.equal(revAnchorRes.status, "rejected");
    assert.match(String(revAnchorRes.reason), /untrusted_anchor/);

    const [selfInitRaw, selfAccRaw] = await Promise.all([
      cli2Ep.enrollInitiate(addr, "node-m2m-host", hostStatic, hostSigningHash, selfTok),
      hostEp.pairAccept(5000),
    ]);
    assert.equal(JSON.parse(selfInitRaw).status, "active");
    assert.equal(JSON.parse(selfAccRaw).status, "active");
  } finally {
    cli2Ep.close();
    cliEp.close();
    anchorEp.close();
    hostEp.close();
  }
});

test("Node p2p_port_mapping and p2p_bind_addrs reach the listener and are validated", async () => {
  const ep = new tendril.Endpoint(null, "node-p2p-net");
  try {
    ep.configureTransportsJson(
      JSON.stringify({ p2pPortMapping: false, p2pBindAddrs: ["127.0.0.1:0"] }),
    );
    const addr = await ep.serveP2p("disabled");
    const hints = [...addr.matchAll(/[?&]addr=([^&]+)/g)].map((m) => m[1]);
    assert.ok(hints.length > 0, addr);
    for (const hint of hints) {
      assert.ok(hint.startsWith("127.0.0.1:"), addr);
    }
    for (const bad of [["not-an-addr"], ["127.0.0.1:0", "127.0.0.2:0"]]) {
      assert.throws(
        () => ep.configureTransportsJson(JSON.stringify({ p2p_bind_addrs: bad })),
        /p2p_bind_addrs/,
      );
    }
    assert.throws(() => ep.configureTransportsJson('{"p2p_port_mapping":"no"}'));
    ep.configureTransportsJson('{"p2p_relay_mode":"n0","p2p_port_mapping":true}');
  } finally {
    ep.close();
  }
});

test("Node binding configures transports strictly, redacts scalar secrets, and validates v2 bounds", async () => {
  const ep = new tendril.Endpoint(null, "node-cfg-host");
  try {
    // Unknown field rejected
    assert.throws(() => ep.configureTransportsJson(JSON.stringify({ unknown_field: true })));

    // Scalar secret redaction: error must NOT contain the secret value
    let caughtMsg = "";
    try {
      ep.configureTransportsJson('{"relay_auth_secret":123456}');
      assert.fail("expected configureTransportsJson to throw");
    } catch (err) {
      caughtMsg = String(err);
    }
    assert.ok(!caughtMsg.includes("123456"), `scalar secret leaked in error: ${caughtMsg}`);

    // Mutual-exclusion checks
    const ticketJson = ep.mintRelayTicket("127.0.0.1", "any", "*", 300);
    const ticket = JSON.parse(ticketJson);
    assert.throws(() =>
      ep.configureTransportsJson(
        JSON.stringify({ relay_auth_secret: "shared-secret", relay_ticket: ticket })
      )
    );
    assert.throws(() =>
      ep.configureTransportsJson(
        JSON.stringify({ p2p_relay_auth_token: "tok", p2p_api_secret: "sec" })
      )
    );
    assert.throws(() =>
      ep.configureTransportsJson(
        JSON.stringify({ p2p_relay_mode: "disabled", p2p_relay_urls: ["https://relay.example"] })
      )
    );

    // Valid configuration succeeds
    ep.configureTransportsJson(JSON.stringify({ relay_ticket: ticket }));
    ep.configureTransportsJson(JSON.stringify({}));

    // Safe integer bounds on ttlSecs & timeoutMs
    for (const bad of [-1, NaN, Infinity, 1.5, 2 ** 53]) {
      assert.throws(() => ep.mintRelayTicket("127.0.0.1", "any", "*", bad));
    }
    assert.throws(() => ep.mintRelayTicket("127.0.0.1", "bogus-role", "*", 60));

    for (const badTimeout of [-1, NaN, Infinity, 1.5, 2 ** 32]) {
      await assert.rejects(ep.pairV2Accept(badTimeout));
      await assert.rejects(ep.acceptV2(badTimeout));
    }
  } finally {
    ep.close();
  }
});

test("Node binding enforces mintRelayTicket and relay auth across /v1/relay and /v2/relay", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tendril-node-relay-"));
  const secretFile = path.join(tmpDir, "relay-secret.txt");
  const secretValue = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(secretFile, secretValue, { mode: 0o600 });

  const issuerEp = new tendril.Endpoint(null, "node-relay-issuer");
  const hostEp = new tendril.Endpoint(null, "node-relay-host");
  const cliEp = new tendril.Endpoint(null, "node-relay-cli");
  let relay;
  try {
    const issuerInfo = JSON.parse(issuerEp.infoJson());
    relay = await spawnGatedRelay(secretFile, issuerInfo.relay_pub);

    // 1. /v1/relay gating: unauth, wrong secret, and wrong-role ticket must fail closed.
    await assert.rejects(hostEp.serveRelay(relay.v1Url, "127.0.0.1"));

    hostEp.configureTransportsJson(JSON.stringify({ relay_auth_secret: "wrong-secret" }));
    await assert.rejects(hostEp.serveRelay(relay.v1Url, "127.0.0.1"));

    const dialOnlyTicket = JSON.parse(issuerEp.mintRelayTicket("127.0.0.1", "dial", "*", 300));
    hostEp.configureTransportsJson(JSON.stringify({ relay_ticket: dialOnlyTicket }));
    await assert.rejects(hostEp.serveRelay(relay.v1Url, "127.0.0.1"));

    // Matching register ticket succeeds on /v1/relay
    const regTicket = JSON.parse(issuerEp.mintRelayTicket("127.0.0.1", "register", "*", 300));
    hostEp.configureTransportsJson(JSON.stringify({ relay_ticket: regTicket }));
    const v1HostEp = await hostEp.serveRelay(relay.v1Url, "127.0.0.1");

    // Client with wrong-role (register) ticket fails closed on /v1/relay dial
    const code1 = hostEp.issueCode("remote");
    cliEp.configureTransportsJson(JSON.stringify({ relay_ticket: regTicket }));
    await assert.rejects(cliEp.pairInitiate(v1HostEp, code1, "127.0.0.1", "cli-bad", "node"));

    // Client with matching dial ticket succeeds on /v1/relay
    cliEp.configureTransportsJson(JSON.stringify({ relay_ticket: dialOnlyTicket }));
    const [p1CliRaw, p1AccRaw] = await Promise.all([
      cliEp.pairInitiate(v1HostEp, code1, "127.0.0.1", "cli-v1", "node"),
      hostEp.pairAccept(5000),
    ]);
    const p1Cli = JSON.parse(p1CliRaw);
    const p1Acc = JSON.parse(p1AccRaw);
    assert.equal(p1Cli.sas, p1Acc.sas);

    // 2. Establish Wire v2 pairing over direct so both sides have v2_secrets, then test /v2/relay gating.
    const directAddr = await hostEp.serveDirect("127.0.0.1:0");
    const v2Code = hostEp.issueCode("lan");
    const [v2PairRaw, v2AccRaw] = await Promise.all([
      cliEp.pairV2Initiate(directAddr, v2Code, null, "cli-v2", "node", null),
      hostEp.pairV2Accept(5000),
    ]);
    const v2Pair = JSON.parse(v2PairRaw);
    const v2Acc = JSON.parse(v2AccRaw);
    assert.equal(v2Pair.sas, v2Acc.sas);
    hostEp.confirmPeer(v2Acc.device_id, v2Pair.sas);
    cliEp.confirmPeer("node-relay-host", v2Pair.sas);
    const grantJson = hostEp.mintGrant(v2Acc.device_id, ["fs.read"], 3600);

    // /v2/relay unauth, wrong secret, and wrong-role ticket fail closed
    hostEp.configureTransportsJson(JSON.stringify({}));
    await assert.rejects(hostEp.serveRelayV2(relay.v2Url, "127.0.0.1", v2Acc.device_id));

    hostEp.configureTransportsJson(JSON.stringify({ relay_auth_secret: "wrong-secret" }));
    await assert.rejects(hostEp.serveRelayV2(relay.v2Url, "127.0.0.1", v2Acc.device_id));

    hostEp.configureTransportsJson(JSON.stringify({ relay_ticket: dialOnlyTicket }));
    await assert.rejects(hostEp.serveRelayV2(relay.v2Url, "127.0.0.1", v2Acc.device_id));

    // Matching HMAC secret succeeds on serveRelayV2
    hostEp.configureTransportsJson(JSON.stringify({ relay_auth_secret: secretValue }));
    const v2MailboxEp = await hostEp.serveRelayV2(relay.v2Url, "127.0.0.1", null);
    assert.ok(v2MailboxEp.includes("/v2/relay#"), `expected /v2/relay# ep, got ${v2MailboxEp}`);

    // Client with wrong-role (register) ticket fails closed on connectV2 over /v2/relay
    cliEp.configureTransportsJson(JSON.stringify({ relay_ticket: regTicket }));
    await assert.rejects(cliEp.connectV2(relay.v2Url, "node-relay-host", grantJson, "127.0.0.1"));

    // Client with matching dial ticket succeeds on connectV2 over /v2/relay
    cliEp.configureTransportsJson(JSON.stringify({ relay_ticket: dialOnlyTicket }));
    const [cliSess, hostSess] = await Promise.all([
      cliEp.connectV2(relay.v2Url, "node-relay-host", grantJson, "127.0.0.1"),
      hostEp.acceptV2(5000),
    ]);
    assert.equal(cliSess.peerId, "node-relay-host");
    assert.equal(hostSess.peerId, v2Acc.device_id);
    await cliSess.sendData(Buffer.from("v2-gated-relay-ok", "utf8"));
    const ev = JSON.parse(await hostSess.pollEvent(3000));
    assert.equal(ev.event, "data");
    assert.equal(Buffer.from(ev.data_b64, "base64url").toString("utf8"), "v2-gated-relay-ok");
    await cliSess.close(1000, "done");
  } finally {
    cliEp.close();
    hostEp.close();
    issuerEp.close();
    if (relay && !relay.child.killed) {
      relay.child.kill();
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Node binding runs Wire v2 PAKE pairing, session ops, and wrong-code rejection with tendril-conformance-peer", async () => {
  const peer = spawnPeer();
  const hostEp = new tendril.Endpoint(null, "node-v2-host");
  const cliEp = new tendril.Endpoint(null, "node-v2-cli");
  try {
    const addr = await hostEp.serveDirect("127.0.0.1:0");
    await peer.call({ op: "init", host_id: "rust-v2-cli" });

    // Wrong-code rejection
    const goodCode = hostEp.issueCode("lan");
    const wrongCode = goodCode === "0000-0000" ? "1111-1111" : "0000-0000";
    const [wrongHostRes, wrongPeerRes] = await Promise.allSettled([
      hostEp.pairV2Accept(5000),
      peer.call({
        op: "pair_v2_initiate",
        endpoint: addr,
        code: wrongCode,
        name: "rust-v2-cli",
      }),
    ]);
    assert.equal(wrongHostRes.status, "rejected");
    assert.equal(wrongPeerRes.status, "rejected");

    // Valid Wire v2 PAKE pairing (Rust peer -> Node host)
    const code = hostEp.issueCode("lan");
    const [accRaw, peerPair] = await Promise.all([
      hostEp.pairV2Accept(5000),
      peer.call({
        op: "pair_v2_initiate",
        endpoint: addr,
        code,
        name: "rust-v2-cli",
      }),
    ]);
    const acc = JSON.parse(accRaw);
    assert.equal(acc.wire_version, 2);
    assert.equal(acc.sas, peerPair.sas);

    hostEp.confirmPeer(acc.device_id, acc.sas);
    await peer.call({ op: "confirm", peer_id: "node-v2-host", sas: acc.sas });
    const grantJson = hostEp.mintGrant(acc.device_id, ["fs.read"], 3600);
    const grantObj = JSON.parse(grantJson);

    const [hostSess, peerConn] = await Promise.all([
      hostEp.acceptV2(5000),
      peer.call({
        op: "connect_v2",
        endpoint: addr,
        target_host_id: "node-v2-host",
        grant: grantObj,
      }),
    ]);
    assert.equal(peerConn.ok, true);
    assert.equal(hostSess.peerId, acc.device_id);
    assert.equal(await hostSess.authorize("fs.read"), true);
    assert.equal(await hostSess.authorize("shell.exec"), false);

    await peer.call({ op: "send", data_utf8: "v2-hello-to-node" });
    const ev = JSON.parse(await hostSess.pollEvent(2000));
    assert.equal(ev.event, "data");
    assert.equal(Buffer.from(ev.data_b64, "base64url").toString("utf8"), "v2-hello-to-node");

    await hostSess.rekey();
    const rkLocal = JSON.parse(await hostSess.pollEvent(2000));
    assert.equal(rkLocal.event, "rekeyed");
    const rkPeer = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(rkPeer.event, "rekeyed");

    await hostSess.sendData(Buffer.from("v2-reply-from-node", "utf8"));
    const peerEv = await peer.call({ op: "recv", timeout_ms: 2000 });
    assert.equal(peerEv.data_utf8, "v2-reply-from-node");

    hostEp.revokePeer(acc.device_id);
    assert.equal(await hostSess.authorize("fs.read"), false);
    assert.equal(hostSess.peerId, acc.device_id);

    await hostSess.close(1000, "done");
    await peer.call({ op: "shutdown" });

    // Direction 2: Node client -> Rust conformance peer host (pairV2Initiate + connectV2 + accept_v2)
    const peer2 = spawnPeer();
    try {
      await peer2.call({ op: "init", host_id: "rust-v2-host" });
      const srv2 = await peer2.call({ op: "serve_direct" });
      const code2 = (await peer2.call({ op: "issue_code", kind: "lan" })).code;
      const [cliPairRaw, hostAcc2] = await Promise.all([
        cliEp.pairV2Initiate(srv2.endpoint, code2, null, "node-v2-dev", "node", null),
        peer2.call({ op: "pair_v2_accept", timeout_ms: 5000 }),
      ]);
      const cliPair = JSON.parse(cliPairRaw);
      assert.equal(cliPair.wire_version, 2);
      assert.equal(cliPair.sas, hostAcc2.sas);

      await peer2.call({ op: "confirm", peer_id: hostAcc2.device_id, sas: cliPair.sas });
      cliEp.confirmPeer("rust-v2-host", cliPair.sas);
      const grant2 = (
        await peer2.call({ op: "mint", peer_id: hostAcc2.device_id, caps: ["fs.read"] })
      ).grant;

      const [cliSess2, hostConn2] = await Promise.all([
        cliEp.connectV2(srv2.endpoint, "rust-v2-host", JSON.stringify(grant2), null),
        peer2.call({ op: "accept_v2", timeout_ms: 5000 }),
      ]);
      assert.equal(hostConn2.ok, true);
      assert.equal(cliSess2.peerId, "rust-v2-host");
      await cliSess2.sendData(Buffer.from("v2-node-to-rust", "utf8"));
      const r2 = await peer2.call({ op: "recv", timeout_ms: 2000 });
      assert.equal(r2.data_utf8, "v2-node-to-rust");
      await cliSess2.close(1000, "done");
      await peer2.call({ op: "shutdown" });
    } finally {
      peer2.close();
    }
  } finally {
    cliEp.close();
    hostEp.close();
    peer.close();
  }
});

test("Node binding delivers wake_and_dial_v2 HTTP wake on connectV2", async () => {
  const wakeRequests = [];
  const wakeServer = http.createServer((req, res) => {
    if (req.method !== "POST") {
      res.writeHead(405);
      res.end();
      return;
    }
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      wakeRequests.push({
        method: req.method,
        url: req.url,
        auth: req.headers.authorization,
        body,
      });
      res.writeHead(202);
      res.end();
    });
  });
  await new Promise((resolve) => wakeServer.listen(0, "127.0.0.1", resolve));
  const wakePort = wakeServer.address().port;

  const hostEp = new tendril.Endpoint(null, "node-wake-host");
  const cliEp = new tendril.Endpoint(null, "node-wake-cli");
  try {
    const directAddr = await hostEp.serveDirect("127.0.0.1:0");
    const code = hostEp.issueCode("lan");
    const [pairRaw, accRaw] = await Promise.all([
      cliEp.pairV2Initiate(directAddr, code, null, "node-wake-cli", "node", null),
      hostEp.pairV2Accept(5000),
    ]);
    const pairRes = JSON.parse(pairRaw);
    const accRes = JSON.parse(accRaw);
    assert.equal(pairRes.sas, accRes.sas);

    hostEp.confirmPeer(accRes.device_id, pairRes.sas);
    cliEp.confirmPeer("node-wake-host", pairRes.sas);
    const grantJson = hostEp.mintGrant(accRes.device_id, ["fs.read"], 3600);

    const wakeSecretB64 = crypto.randomBytes(32).toString("base64url");
    cliEp.configureTransportsJson(
      JSON.stringify({
        wake_url: `http://127.0.0.1:${wakePort}/wake`,
        wake_adapter: "webhook",
        wake_secret_b64: wakeSecretB64,
        wake_auth_token: "node-wake-token",
        wake_pre_wake: true,
        wake_retry_delay_ms: 25,
        wake_max_attempts: 10,
        wake_timeout_ms: 2000,
      }),
    );

    const [cliSess, hostSess] = await Promise.all([
      cliEp.connectV2(directAddr, "node-wake-host", grantJson, null),
      hostEp.acceptV2(5000),
    ]);
    assert.ok(wakeRequests.length >= 1, "expected at least one POST wake request");
    assert.equal(wakeRequests[0].url, "/wake");
    assert.equal(wakeRequests[0].auth, "Bearer node-wake-token");
    assert.equal(typeof wakeRequests[0].body.wake_tag, "string");
    assert.ok(wakeRequests[0].body.wake_tag.length > 0);

    await cliSess.sendData(Buffer.from("wake-v2-ok", "utf8"));
    const ev = JSON.parse(await hostSess.pollEvent(2000));
    assert.equal(ev.event, "data");
    assert.equal(Buffer.from(ev.data_b64, "base64url").toString("utf8"), "wake-v2-ok");
    await cliSess.close(1000, "done");
  } finally {
    cliEp.close();
    hostEp.close();
    await new Promise((resolve) => wakeServer.close(resolve));
  }
});

test("verifyWakeTag and camelCase APNs wake config with coalescing", async () => {
  const secret = Buffer.alloc(32, 0x33);
  const wrong = Buffer.alloc(32, 0x99);
  const now = 1_764_115_200;
  const epochBuf = Buffer.alloc(8);
  epochBuf.writeBigUInt64BE(BigInt(Math.floor(now / 3600)));
  const prk = crypto.createHmac("sha256", epochBuf).update(secret).digest();
  const okm = crypto
    .createHmac("sha256", prk)
    .update(Buffer.from("tendril/wake/epoch-tag/v1\x01"))
    .digest();
  const tagB64 = okm.subarray(0, 16).toString("base64url");

  for (const checkNow of [now - 3600, now, now + 3600]) {
    assert.equal(tendril.verifyWakeTag(secret, tagB64, checkNow), true);
  }
  for (const checkNow of [now - 7200, now + 7200]) {
    assert.equal(tendril.verifyWakeTag(secret, tagB64, checkNow), false);
  }
  assert.equal(tendril.verifyWakeTag(wrong, tagB64, now), false);
  assert.throws(() => tendril.verifyWakeTag(Buffer.alloc(16), tagB64, now));
  assert.throws(() => tendril.verifyWakeTag(secret, "not-valid-b64", now));
  assert.throws(() => tendril.verifyWakeTag(secret, tagB64, -1));

  const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const p8Pem = privateKey.export({ type: "pkcs8", format: "pem" });

  const apnsRequests = [];
  const apnsServer = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      apnsRequests.push({
        url: req.url,
        headers: req.headers,
        body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
      });
      res.writeHead(200);
      res.end();
    });
  });
  await new Promise((resolve) => apnsServer.listen(0, "127.0.0.1", resolve));
  const apnsPort = apnsServer.address().port;

  const hostEp = new tendril.Endpoint(null, "node-apns-host");
  const cliEp = new tendril.Endpoint(null, "node-apns-cli");
  try {
    const secretB64 = secret.toString("base64url");
    const devTok = "0".repeat(64);
    cliEp.configureTransportsJson(
      JSON.stringify({
        wakeUrl: `https://api.sandbox.push.apple.com/3/device/${devTok}`,
        wakeAdapter: "apns_h2",
        wakeSecretB64: secretB64,
        wakeApnsMode: "mutable_alert",
        wakeApnsTopic: "app.tendril.node",
        wakeApnsLocKey: "TENDRIL_WAKE_NODE",
        wakeApnsTeamId: "TEAM123456",
        wakeApnsKeyId: "KEY1234567",
        wakeApnsP8Pem: p8Pem,
        wakeCoalesceSecs: 15,
      }),
    );
    for (const bad of [
      {
        wakeUrl: `http://127.0.0.1:${apnsPort}/3/device/${devTok}`,
        wakeAdapter: "apns_h2",
        wakeSecretB64: secretB64,
        wakeAuthToken: "tok",
        wakeApnsTopic: "app.tendril.node",
      },
      {
        wakeUrl: `https://api.push.apple.com/3/device/${devTok}`,
        wakeAdapter: "apns_h2",
        wakeSecretB64: secretB64,
        wakeAuthToken: "tok",
      },
      {
        wakeUrl: `https://api.push.apple.com/3/device/${devTok}`,
        wakeAdapter: "apns_h2",
        wakeSecretB64: secretB64,
        wakeAuthToken: "tok",
        wakeApnsTopic: "app.tendril.node",
        wakeApnsMode: "mutable_alert",
        wakeApnsLocKey: "BAD KEY",
      },
    ]) {
      assert.throws(() => cliEp.configureTransportsJson(JSON.stringify(bad)));
    }

    const directAddr = await hostEp.serveDirect("127.0.0.1:0");
    const code = hostEp.issueCode("lan");
    const [pairRaw, accRaw] = await Promise.all([
      cliEp.pairV2Initiate(directAddr, code, null, "node-apns-cli", "node", null),
      hostEp.pairV2Accept(5000),
    ]);
    const pairRes = JSON.parse(pairRaw);
    const accRes = JSON.parse(accRaw);
    hostEp.confirmPeer(accRes.device_id, pairRes.sas);
    cliEp.confirmPeer("node-apns-host", pairRes.sas);
    const grantJson = hostEp.mintGrant(accRes.device_id, ["fs.read"], 3600);

    cliEp.configureTransportsJson(
      JSON.stringify({
        wakeUrl: `http://127.0.0.1:${apnsPort}/3/device/deadbeef`,
        wakeAdapter: "apns",
        wakeSecretB64: secretB64,
        wakeAuthToken: "node-apns-tok",
        wakePreWake: true,
        wakeCoalesceSecs: 60,
        wakeApnsMode: "mutable_alert",
        wakeApnsTopic: "app.tendril.node",
        wakeApnsLocKey: "TENDRIL_WAKE_NODE",
      }),
    );

    for (let i = 0; i < 2; i += 1) {
      const [cliSess, hostSess] = await Promise.all([
        cliEp.connectV2(directAddr, "node-apns-host", grantJson, null),
        hostEp.acceptV2(5000),
      ]);
      await cliSess.close(1000, "done");
      await hostSess.close(1000, "done");
    }

    assert.equal(apnsRequests.length, 1);
    const req = apnsRequests[0];
    assert.equal(req.url, "/3/device/deadbeef");
    assert.equal(req.headers.authorization, "Bearer node-apns-tok");
    assert.equal(req.headers["apns-push-type"], "alert");
    assert.equal(req.headers["apns-priority"], "10");
    assert.equal(req.headers["apns-topic"], "app.tendril.node");
    assert.equal(req.body.aps["mutable-content"], 1);
    assert.equal(req.body.aps.alert["loc-key"], "TENDRIL_WAKE_NODE");
    assert.equal(
      tendril.verifyWakeTag(secret, req.body.wake_tag, Math.floor(Date.now() / 1000)),
      true,
    );
  } finally {
    cliEp.close();
    hostEp.close();
    await new Promise((resolve) => apnsServer.close(resolve));
  }
});
