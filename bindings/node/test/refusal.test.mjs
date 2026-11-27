import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import tendril from "../index.js";

const { Endpoint } = tendril;

const tmpDir = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));

/** A paired host and client over loopback on the given wire. */
async function pair(v2, { confirmHost = true } = {}) {
  const dir = tmpDir("tendril-node-refusal-");
  const host = new Endpoint(dir, "refusal-host");
  const client = new Endpoint(null, "refusal-client");
  const addr = await host.serveDirect("127.0.0.1:0");
  const code = host.issueCode("lan");
  const [cliRaw, accRaw] = await Promise.all(
    v2
      ? [client.pairV2Initiate(addr, code, null, "cli", "node", null), host.pairV2Accept(5000)]
      : [client.pairInitiate(addr, code, null, "cli", "node"), host.pairAccept(5000)],
  );
  const sas = JSON.parse(cliRaw).sas;
  const deviceId = JSON.parse(accRaw).device_id;
  client.confirmPeer("refusal-host", sas);
  let grant = null;
  if (confirmHost) {
    host.confirmPeer(deviceId, sas);
    grant = host.mintGrant(deviceId, ["fs.read"], 3600);
  }
  const accept = () => (v2 ? host.acceptV2(3000) : host.acceptSession(3000));
  const connect = () =>
    v2 ? client.connectV2(addr, "refusal-host", grant, null) : client.connect(addr, "refusal-host", grant, null);
  return {
    host,
    client,
    deviceId,
    accept,
    connect,
    close() {
      host.close();
      client.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** Connects while the host accepts, as the server loop of an app does. */
async function connectOnce(p) {
  const accepting = p.accept().then(
    (s) => s,
    () => null,
  );
  try {
    return await p.connect();
  } finally {
    await accepting;
  }
}

async function refusedError(p) {
  const accepting = p.accept().catch(() => null);
  try {
    await p.connect();
  } catch (err) {
    return err;
  } finally {
    await accepting;
  }
  throw new Error("the connect succeeded");
}

async function nextClosed(session) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    const ev = JSON.parse(await session.pollEvent(500));
    if (ev.event === "closed") return ev;
  }
  throw new Error("no closed event");
}

test("a refused Wire v2 connect rejects with a typed error", async () => {
  const p = await pair(true);
  try {
    p.host.revokePeer(p.deviceId);
    const err = await refusedError(p);
    assert.ok(err instanceof Error);
    assert.equal(err.code, "refused_revoked");
    assert.equal(err.closeCode, 4001);
    assert.match(err.message, /revoked/);
    assert.ok(!err.message.includes("[tendril:"));
    assert.ok(tendril.isRefusedError(err));
    assert.ok(!tendril.isRefusedError(new Error("x")));
  } finally {
    p.close();
  }
});

test("a pending Wire v2 peer is refused with refused_pending", async () => {
  const p = await pair(true, { confirmHost: false });
  try {
    const err = await refusedError(p);
    assert.equal(err.code, "refused_pending");
    assert.equal(err.closeCode, 4004);
  } finally {
    p.close();
  }
});

test("a Wire v1 refusal arrives after connect as a closed event and typed errors", async () => {
  const p = await pair(false);
  try {
    p.host.revokePeer(p.deviceId);
    const accepting = p.accept().catch(() => null);
    const sess = await p.connect();
    const closed = await nextClosed(sess);
    assert.equal(closed.refusal, "revoked");
    assert.equal(closed.code, 4001);
    await assert.rejects(sess.sendData(Buffer.from("x")), { code: "refused_revoked", closeCode: 4001 });
    await assert.rejects(sess.rekey(), { code: "refused_revoked", closeCode: 4001 });
    await assert.rejects(sess.close(), { code: "refused_revoked" });
    await accepting;
  } finally {
    p.close();
  }
});

test("a plain close carries no refusal", async () => {
  const p = await pair(false);
  try {
    const accepting = p.accept();
    const sess = await p.connect();
    const hostSess = await accepting;
    await hostSess.close(1000, "bye");
    const closed = await nextClosed(sess);
    assert.equal(closed.refusal, null);
  } finally {
    p.close();
  }
});

test("an error text that looks like a refusal tag is never typed", async () => {
  const tag = "[tendril:refused_revoked:4001] ";
  const p = await pair(false);
  try {
    // An unknown target echoes into the error message.
    await assert.rejects(p.client.connect(null, `${tag}x`, null, null), (err) => {
      assert.ok(!tendril.isRefusedError(err));
      assert.equal(err.code, "GenericFailure");
      assert.equal(err.closeCode, undefined);
      return true;
    });
    // A peer-chosen close reason of a plain close echoes into later errors.
    const accepting = p.accept();
    const sess = await p.connect();
    const hostSess = await accepting;
    await hostSess.close(1000, `${tag}bye`);
    const closed = await nextClosed(sess);
    assert.equal(closed.refusal, null);
    await assert.rejects(sess.sendData(Buffer.from("x")), (err) => {
      assert.ok(!tendril.isRefusedError(err));
      assert.equal(err.code, "GenericFailure");
      assert.equal(err.closeCode, undefined);
      return true;
    });
  } finally {
    p.close();
  }
});

test("a silent revoke leaves no notice", async () => {
  const p = await pair(true);
  try {
    p.host.revokePeer(p.deviceId, false);
    const err = await refusedError(p);
    assert.notEqual(err.code, "refused_revoked");
    assert.equal(err.closeCode, undefined);
  } finally {
    p.close();
  }
});

test("a policy without notices leaves no notice", async () => {
  const p = await pair(true);
  try {
    p.host.setRefusalPolicy(true, 0);
    p.host.revokePeer(p.deviceId);
    const err = await refusedError(p);
    assert.ok(!String(err.code).startsWith("refused"));
  } finally {
    p.close();
  }
});

test("clearRefusalNotice keeps the peer revoked and rejects an unknown peer", async () => {
  const p = await pair(true);
  try {
    p.host.revokePeer(p.deviceId);
    p.host.clearRefusalNotice(p.deviceId);
    const err = await refusedError(p);
    assert.ok(!String(err.code).startsWith("refused"));
    assert.throws(() => p.host.clearRefusalNotice("no-such-peer"));
  } finally {
    p.close();
  }
});

test("setRefusalPolicy validates its arguments", async () => {
  const p = await pair(true);
  try {
    assert.throws(() => p.host.setRefusalPolicy("yes", 0));
  } finally {
    p.close();
  }
});

test("an unrevoked peer still connects", async () => {
  const p = await pair(true);
  try {
    const sess = await connectOnce(p);
    assert.equal(sess.peerId, "refusal-host");
    await sess.close();
  } finally {
    p.close();
  }
});
