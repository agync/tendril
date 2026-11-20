import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import test from "node:test";
import { fileURLToPath } from "node:url";

import tendril from "../index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..", "..");
const VECTORS = path.join(ROOT, "spec", "vectors");
const PEER_BIN = path.join(ROOT, "target", "debug", "tendril-conformance-peer");

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
