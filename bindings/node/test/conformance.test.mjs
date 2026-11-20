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
});

test("Node N-API live async interop with Rust tendril-conformance-peer", async () => {
  const peer = spawnPeer();
  const hostEp = new tendril.Endpoint(null, "node-host");
  try {
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
});
