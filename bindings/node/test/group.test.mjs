import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import tendril from "../index.js";

const { Endpoint } = tendril;

function b64urlDecode(text) {
  return Buffer.from(text, "base64url");
}

function freeAddr() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(`127.0.0.1:${port}`));
    });
  });
}

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "tendril-node-group-"));
}

/** Enrolls `cli` with `host` over the M2M flow, which pins both signing keys. */
async function pair(host, cli) {
  const info = JSON.parse(host.infoJson());
  const addr = await host.serveDirect("127.0.0.1:0");
  const token = host.mintEnrollmentToken(info.host_id, null, 900);
  const accepted = host.pairAccept(8000);
  const res = JSON.parse(
    await cli.enrollInitiate(
      addr,
      info.host_id,
      b64urlDecode(info.static_pub),
      b64urlDecode(info.signing_pub),
      token,
      null,
      null,
      "node-group",
      "machine"
    )
  );
  const acc = JSON.parse(await accepted);
  assert.equal(res.status, "active");
  assert.equal(acc.status, "active");
}

async function nextEvent(group, kind, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const raw = await group.pollEvent(500);
    if (raw === null || raw === undefined) continue;
    const ev = JSON.parse(raw);
    if (ev.event === kind) return ev;
  }
  throw new Error(`no ${kind} event within ${timeoutMs}ms`);
}

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const RELAY_BIN = path.join(ROOT, "target", "debug", "tendril-relay");
const RELAY_SECRET = "tendril-group-relay-hmac-secret-32";

/**
 * Starts a loopback `tendril-relay` that requires HMAC admission with `RELAY_SECRET`. `host` is
 * the relay's canonical host and the host of its URLs; it always binds 127.0.0.1.
 */
function spawnAuthRelay(host = "127.0.0.1") {
  if (!fs.existsSync(RELAY_BIN)) {
    const res = spawnSync("cargo", ["build", "-p", "tendril-relay", "--bin", "tendril-relay"], {
      cwd: ROOT,
      stdio: "inherit",
    });
    assert.equal(res.status, 0, "failed to build tendril-relay");
  }
  const dir = tmpDir();
  const secretFile = path.join(dir, "relay.secret");
  fs.writeFileSync(secretFile, RELAY_SECRET, { mode: 0o600 });
  return new Promise((resolve, reject) => {
    const child = spawn(
      RELAY_BIN,
      ["--listen", "127.0.0.1:0", "--host", host, "--auth-secret-file", secretFile],
      { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, RUST_LOG: "info" } }
    );
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
        resolve({
          child,
          v1Url: `ws://${host}:${m[1]}/v1/relay`,
          v2Url: `ws://${host}:${m[1]}/v2/relay`,
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

test("group create, add, open, broadcast, and use-after-close", async () => {
  const a = new Endpoint(tmpDir());
  const b = new Endpoint(tmpDir());
  try {
    await pair(a, b);
    const aId = JSON.parse(a.infoJson()).device_id;
    const bId = JSON.parse(b.infoJson()).device_id;
    const addrA = await freeAddr();
    const addrB = await freeAddr();

    const m1 = JSON.parse(await a.groupCreate("node-group", 1, [addrA]));
    const gid = m1.group_id;
    const m2Json = await a.groupAddMember(gid, bId, null, [addrB]);
    assert.equal(JSON.parse(m2Json).seq, m1.seq + 1);
    assert.ok(!m2Json.includes("rendezvous"));
    assert.equal(await b.groupIngestManifest(m2Json, aId), gid);

    const ga = await a.groupOpen(gid, addrA);
    const gb = await b.groupOpen(gid, addrB);
    try {
      assert.equal(ga.groupId, gid);
      assert.equal(ga.localEndpoint, addrA);
      assert.equal(ga.authorizePeer(bId, `group.send:${gid}`), true);
      assert.throws(() => ga.authorizePeer(bId, `group.admin:${gid}`));

      const report = JSON.parse(await ga.broadcast(Buffer.from("hello group")));
      assert.deepEqual(report.delivered, [bId], JSON.stringify(report));
      const ev = await nextEvent(gb, "app_data");
      assert.equal(ev.sender_device_id, aId);
      assert.equal(b64urlDecode(ev.payload_b64).toString(), "hello group");

      const back = JSON.parse(await gb.broadcast(Buffer.from("reply"), `group.send:${gid}`));
      assert.deepEqual(back.delivered, [aId], JSON.stringify(back));
      const ev2 = await nextEvent(ga, "app_data");
      assert.equal(b64urlDecode(ev2.payload_b64).toString(), "reply");

      await assert.rejects(gb.broadcast(Buffer.from("x"), `group.admin:${gid}`), /denied/);

      await gb.close();
      await gb.close();
      await assert.rejects(gb.broadcast(Buffer.from("x")), /closed/);
      await assert.rejects(gb.pollEvent(10), /closed/);
      assert.throws(() => gb.authorizePeer(aId, `group.send:${gid}`), /closed/);
    } finally {
      await ga.close();
      await gb.close();
    }
  } finally {
    b.close();
    a.close();
  }
});

test("wire v2 group: root sync, then broadcast both ways", async () => {
  const a = new Endpoint(tmpDir());
  const b = new Endpoint(tmpDir());
  try {
    await pair(a, b);
    const aId = JSON.parse(a.infoJson()).device_id;
    const bId = JSON.parse(b.infoJson()).device_id;
    const addrA = await freeAddr();
    const addrB = await freeAddr();
    const gid = JSON.parse(await a.groupCreate("node-group-v2", 2, [addrA])).group_id;
    const m2 = await a.groupAddMember(gid, bId, null, [addrB]);
    assert.equal(await b.groupIngestManifest(m2, aId), gid);

    const gb = await b.groupOpen(gid, addrB);
    const ga = await a.groupOpen(gid, addrA);
    try {
      const synced = JSON.parse(await ga.sync());
      assert.deepEqual(synced.delivered, [bId], JSON.stringify(synced));

      const deadline = Date.now() + 10000;
      let report;
      for (;;) {
        report = JSON.parse(await ga.broadcast(Buffer.from("v2 hello")));
        if (report.delivered.length === 1 || Date.now() > deadline) break;
        await new Promise((r) => setTimeout(r, 200));
      }
      assert.deepEqual(report.delivered, [bId], JSON.stringify(report));
      const ev = await nextEvent(gb, "app_data");
      assert.equal(ev.sender_device_id, aId);
      assert.equal(b64urlDecode(ev.payload_b64).toString(), "v2 hello");

      const back = JSON.parse(await gb.broadcast(Buffer.from("v2 reply")));
      assert.deepEqual(back.delivered, [aId], JSON.stringify(back));
      const ev2 = await nextEvent(ga, "app_data");
      assert.equal(b64urlDecode(ev2.payload_b64).toString(), "v2 reply");

      await ga.close();
      await assert.rejects(ga.sync(), /closed/);
    } finally {
      await ga.close();
      await gb.close();
    }
  } finally {
    b.close();
    a.close();
  }
});

test("v2 relay sibling with relay auth", async () => {
  const relay = await spawnAuthRelay();
  const a = new Endpoint(tmpDir());
  const b = new Endpoint(tmpDir());
  try {
    for (const ep of [a, b]) {
      ep.configureTransportsJson(JSON.stringify({ relay_auth_secret: RELAY_SECRET }));
    }
    await pair(a, b);
    const aId = JSON.parse(a.infoJson()).device_id;
    const bId = JSON.parse(b.infoJson()).device_id;
    const addrB = await freeAddr();
    const gid = JSON.parse(await a.groupCreate("node-relay", 2, [relay.v2Url])).group_id;
    const m2 = await a.groupAddMember(gid, bId, null, [addrB]);
    assert.equal(await b.groupIngestManifest(m2, aId), gid);

    const gb = await b.groupOpen(gid, addrB);
    const ga = await a.groupOpen(gid, null, true);
    try {
      const synced = JSON.parse(await ga.sync());
      assert.deepEqual(synced.delivered, [bId], JSON.stringify(synced));

      const deadline = Date.now() + 15000;
      let report;
      for (;;) {
        report = JSON.parse(await gb.broadcast(Buffer.from("over the relay")));
        if (report.delivered.includes(aId) || Date.now() > deadline) break;
        await new Promise((r) => setTimeout(r, 200));
      }
      assert.deepEqual(report.delivered, [aId], JSON.stringify(report));
      const ev = await nextEvent(ga, "app_data");
      assert.equal(ev.sender_device_id, bId);
      assert.equal(b64urlDecode(ev.payload_b64).toString(), "over the relay");
    } finally {
      await ga.close();
      await gb.close();
    }
  } finally {
    b.close();
    a.close();
    relay.child.kill();
  }
});

test("relayListen leaves a served v1 relay to the endpoint", async () => {
  // The control relay is addressed as `localhost`, so its host differs from the served
  // `127.0.0.1` relay. It is not served, so the root's pool registers the identity there, and a
  // dial that the control stops answering `offline` proves the mailbox plan ran.
  const servedRelay = await spawnAuthRelay();
  const control = await spawnAuthRelay("localhost");
  const a = new Endpoint(tmpDir());
  const b = new Endpoint(tmpDir());
  try {
    for (const ep of [a, b]) {
      ep.configureTransportsJson(JSON.stringify({ relay_auth_secret: RELAY_SECRET }));
    }
    await pair(a, b);
    const aInfo = JSON.parse(a.infoJson());
    const served = await a.serveRelay(servedRelay.v1Url);
    const gid = JSON.parse(
      await a.groupCreate("node-served", 1, [control.v1Url, servedRelay.v1Url])
    ).group_id;
    const controlEp = `${control.v1Url}#${aInfo.relay_pub}`;
    const ga = await a.groupOpen(gid, null, true);
    try {
      const deadline = Date.now() + 15000;
      for (;;) {
        try {
          await b.connect(controlEp, aInfo.host_id, null, null);
          break;
        } catch (err) {
          assert.match(String(err), /offline/);
          assert.ok(Date.now() < deadline, "pool never registered");
          await new Promise((r) => setTimeout(r, 100));
        }
      }

      const accepted = a.acceptSession(10000).then(
        (sess) => ({ sess }),
        (err) => ({ err })
      );
      const connected = await b.connect(served, aInfo.host_id, null, null).then(
        (sess) => ({ sess }),
        (err) => ({ err })
      );
      const acc = await accepted;
      assert.ok(acc.sess, `served mailbox displaced: ${acc.err} / ${connected.err}`);
      assert.ok(connected.sess, `connect failed: ${connected.err}`);
    } finally {
      await ga.close();
    }
  } finally {
    b.close();
    a.close();
    servedRelay.child.kill();
    control.child.kill();
  }
});

test("group remove and non-root refusals", async () => {
  const a = new Endpoint(tmpDir());
  const b = new Endpoint(tmpDir());
  try {
    await pair(a, b);
    const aId = JSON.parse(a.infoJson()).device_id;
    const bId = JSON.parse(b.infoJson()).device_id;
    const gid = JSON.parse(await a.groupCreate("node-group", 1, [await freeAddr()])).group_id;
    const m2 = await a.groupAddMember(gid, bId, [], [await freeAddr()]);
    await b.groupIngestManifest(m2, aId);

    await assert.rejects(b.groupAddMember(gid, aId, [], []), /authorization denied/);
    await assert.rejects(b.groupRemoveMember(gid, aId), /authorization denied/);

    const m3 = JSON.parse(await a.groupRemoveMember(gid, bId));
    assert.ok(m3.revoked_members.includes(bId));
    assert.equal(m3.seq, JSON.parse(m2).seq + 1);
  } finally {
    b.close();
    a.close();
  }
});

test("ingest refuses a non-signer sender and malformed input", async () => {
  const a = new Endpoint(tmpDir());
  const b = new Endpoint(tmpDir());
  try {
    await pair(a, b);
    const aId = JSON.parse(a.infoJson()).device_id;
    const bId = JSON.parse(b.infoJson()).device_id;
    const gid = JSON.parse(await a.groupCreate("node-group", 1, [await freeAddr()])).group_id;
    const m2 = await a.groupAddMember(gid, bId, [], [await freeAddr()]);

    await assert.rejects(b.groupIngestManifest(m2, bId), /authorization denied/);
    await assert.rejects(b.groupIngestManifest("{not json", aId));
    assert.equal(await b.groupIngestManifest(m2, aId), gid);
  } finally {
    b.close();
    a.close();
  }
});

test("session group frames report runtime ingest outcomes", async () => {
  const a = new Endpoint(tmpDir());
  const b = new Endpoint(tmpDir());
  try {
    await pair(a, b);
    const bId = JSON.parse(b.infoJson()).device_id;
    const addrA = await freeAddr();
    const addrB = await b.serveDirect("127.0.0.1:0");
    const gid = JSON.parse(await a.groupCreate("node-session", 2, [addrA])).group_id;
    await a.groupAddMember(gid, bId, null, [addrB]);

    const seen = [];
    const member = (async () => {
      const sess = await b.acceptSession(10000);
      // The admin counts the push as delivered only after this session answers its ping, and
      // the answer is produced only while polling: keep polling until the admin closes it.
      const deadline = Date.now() + 30000;
      while (Date.now() < deadline) {
        const ev = JSON.parse(await sess.pollEvent(100));
        if (ev.status === "eof" || (ev.status === "event" && ev.event === "closed")) break;
        if (ev.status === "event" && ev.event.startsWith("group_")) seen.push(ev);
      }
    })();
    const ga = await a.groupOpen(gid, addrA);
    try {
      const report = JSON.parse(await ga.sync());
      await member;
      assert.deepEqual(report.delivered, [bId], JSON.stringify(report));
    } finally {
      await ga.close();
    }
    assert.deepEqual(
      seen.map((ev) => ev.event),
      ["group_manifest_ingested", "group_rendezvous_ingested"]
    );
    for (const ev of seen) {
      assert.equal(ev.group_id, gid);
      assert.deepEqual(Object.keys(ev).sort(), ["event", "group_id", "seq", "status"]);
    }
    const gb = await b.groupOpen(gid, null);
    assert.equal(gb.groupId, gid);
    await gb.close();
  } finally {
    b.close();
    a.close();
  }
});

test("endpoint close closes open groups", async () => {
  const dir = tmpDir();
  const ep = new Endpoint(dir, null);
  try {
    const gid = JSON.parse(await ep.groupCreate("node-close", 1, [])).group_id;
    const g1 = await ep.groupOpen(gid, await freeAddr());
    const g2 = await ep.groupOpen(gid, null);
    ep.close();
    for (const g of [g1, g2]) {
      await assert.rejects(g.sync(), /group is closed/);
      await assert.rejects(g.broadcast(Buffer.from("x")), /group is closed/);
      await assert.rejects(g.pollEvent(10), /group is closed/);
    }
  } finally {
    ep.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("group open works with p2p configured", async () => {
  const dir = tmpDir();
  const ep = new Endpoint(dir, null);
  try {
    ep.configureTransportsJson(JSON.stringify({ p2p_relay_mode: "disabled" }));
    const gid = JSON.parse(await ep.groupCreate("node-p2p", 1, [])).group_id;
    const g = await ep.groupOpen(gid, null);
    assert.equal(g.groupId, gid);
    await g.close();
  } finally {
    ep.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("group open without a relay mode adds no p2p dialer", async () => {
  const settings = [
    { p2p_pkarr: true },
    { p2p_allow_private_addrs: true },
    { p2p_advertise_direct_addrs: true },
    { p2p_relay_auth_token: "tok" },
  ];
  for (const cfg of settings) {
    const dir = tmpDir();
    const ep = new Endpoint(dir, null);
    try {
      ep.configureTransportsJson(JSON.stringify(cfg));
      const gid = JSON.parse(await ep.groupCreate("node-nop2p", 1, [])).group_id;
      const g = await ep.groupOpen(gid, null);
      assert.equal(g.groupId, gid);
      await g.close();
    } finally {
      ep.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("group operations require a state dir", async () => {
  const ep = new Endpoint(null, null);
  try {
    await assert.rejects(ep.groupCreate("g", 1, []), /state_dir/);
  } finally {
    ep.close();
  }
});
