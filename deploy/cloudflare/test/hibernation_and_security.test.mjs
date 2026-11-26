import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, randomBytes, sign as cryptoSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import {
  TendrilRelayCore,
  createRelayHandler,
  normalizeClientIp,
  parseRelayConfig,
} from "../src/relay_core.js";
import { initWasm } from "../src/wasm.js";

const wasmBytes = readFileSync(new URL("../pkg/tendril_wasm_bg.wasm", import.meta.url));
initWasm(wasmBytes);

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function unb64url(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64");
}

function genEd25519Identity() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPub = new Uint8Array(spki.subarray(spki.length - 32));
  return { rawPub, pubB64: b64url(rawPub), privateKey };
}

function signEd25519(privateKey, bytes) {
  return b64url(cryptoSign(null, Buffer.from(bytes), privateKey));
}

function signV1Register(id, host, nonceB64) {
  const msg = Buffer.concat([
    Buffer.from("tendril-relay-reg-v1\0"),
    Buffer.from(host, "utf8"),
    unb64url(nonceB64),
  ]);
  return signEd25519(id.privateKey, msg);
}

function signV1Accept(id, host, nonceB64, connIdB64) {
  const msg = Buffer.concat([
    Buffer.from("tendril-relay-accept-v1\0"),
    Buffer.from(host, "utf8"),
    unb64url(nonceB64),
    unb64url(connIdB64),
  ]);
  return signEd25519(id.privateKey, msg);
}

function signV2Register(id, host, nonceB64, epoch) {
  const epBuf = Buffer.alloc(8);
  epBuf.writeBigUInt64BE(BigInt(epoch));
  const msg = Buffer.concat([
    Buffer.from("tendril-relay-reg-v2\0"),
    Buffer.from(host, "utf8"),
    unb64url(nonceB64),
    epBuf,
  ]);
  return signEd25519(id.privateKey, msg);
}

function signV2Accept(id, host, nonceB64, connIdB64, epoch) {
  const epBuf = Buffer.alloc(8);
  epBuf.writeBigUInt64BE(BigInt(epoch));
  const msg = Buffer.concat([
    Buffer.from("tendril-relay-accept-v2\0"),
    Buffer.from(host, "utf8"),
    unb64url(nonceB64),
    unb64url(connIdB64),
    epBuf,
  ]);
  return signEd25519(id.privateKey, msg);
}

function computeHmacAuth(secretStr, op, host, nonceB64, targetBytes) {
  const mac = createHmac("sha256", Buffer.from(secretStr, "utf8"))
    .update(Buffer.from("tendril-relay-auth-v1\0"))
    .update(Buffer.from(op, "utf8"))
    .update(Buffer.from("\0"))
    .update(Buffer.from(host, "utf8"))
    .update(unb64url(nonceB64))
    .update(Buffer.from(targetBytes))
    .digest();
  return { kind: "hmac", mac: b64url(mac) };
}

function canonicalTicketJson(unsigned) {
  return JSON.stringify({
    issuer_pub: unsigned.issuer_pub,
    not_after: unsigned.not_after,
    not_before: unsigned.not_before,
    relay_host: unsigned.relay_host,
    role: unsigned.role,
    target_pub: unsigned.target_pub,
    v: unsigned.v,
  });
}

function mintTicket(issuer, relayHost, role, targetPubOrWild, notBefore, notAfter) {
  const unsigned = {
    v: 1,
    issuer_pub: issuer.pubB64,
    relay_host: relayHost,
    role,
    target_pub: targetPubOrWild,
    not_before: notBefore,
    not_after: notAfter,
  };
  const payload = Buffer.concat([
    Buffer.from("tendril-relay-ticket-v1\0"),
    Buffer.from(canonicalTicketJson(unsigned), "utf8"),
  ]);
  return {
    kind: "ticket",
    ticket: {
      ...unsigned,
      sig: signEd25519(issuer.privateKey, payload),
    },
  };
}

class MockSocket {
  constructor(peer = null) {
    this.peer = peer;
    this.sent = [];
    this.closed = null;
    this.accepted = false;
    this._attachmentJson = null;
  }

  accept() {
    this.accepted = true;
  }

  send(data) {
    if (this.closed !== null) {
      throw new Error("socket closed");
    }
    const copy = typeof data === "string" ? data : new Uint8Array(data);
    this.peer.sent.push(copy);
  }

  close(code = 1000, reason = "") {
    if (this.closed === null) {
      this.closed = { code, reason };
    }
    if (this.peer && this.peer.closed === null) {
      this.peer.closed = { code, reason };
    }
  }

  serializeAttachment(value) {
    if (value === null || value === undefined) {
      this._attachmentJson = null;
      return;
    }
    const encoded = JSON.stringify(value);
    assert.ok(
      Buffer.byteLength(encoded, "utf8") <= 16_384,
      `attachment exceeded 16 KiB limit: ${encoded.length}`,
    );
    this._attachmentJson = encoded;
  }

  deserializeAttachment() {
    return this._attachmentJson === null ? null : JSON.parse(this._attachmentJson);
  }

  drainJson() {
    const out = [];
    while (this.sent.length > 0 && typeof this.sent[0] === "string") {
      out.push(JSON.parse(this.sent.shift()));
    }
    return out;
  }

  drainAll() {
    return this.sent.splice(0, this.sent.length);
  }
}

function createHibernatingHarness(env = {}, initialNowMs = 1_760_000_000_000) {
  const db = new DatabaseSync(":memory:");
  let nowMs = initialNowMs;
  const acceptedSockets = new Set();
  let alarmMs = null;

  const ctx = {
    storage: {
      sql: {
        exec(query, ...params) {
          const bound = params.map((p) => (p instanceof ArrayBuffer ? new Uint8Array(p) : p));
          const stmt = db.prepare(query);
          if (/^\s*select\b/i.test(query)) {
            return stmt.all(...bound);
          }
          stmt.run(...bound);
          return [];
        },
      },
      async setAlarm(ms) {
        alarmMs = ms;
      },
      async deleteAlarm() {
        alarmMs = null;
      },
    },
    async blockConcurrencyWhile(fn) {
      return await fn();
    },
    acceptWebSocket(ws) {
      ws.accepted = true;
      acceptedSockets.add(ws);
    },
    getWebSockets() {
      return Array.from(acceptedSockets).filter((ws) => ws.closed === null);
    },
  };

  function makeCore() {
    return new TendrilRelayCore(ctx, env, {
      now: () => nowMs,
      newWebSocketPair: () => {
        const client = new MockSocket();
        const server = new MockSocket(client);
        client.peer = server;
        return [client, server];
      },
      makeUpgradeResponse: (client) => ({ status: 101, webSocket: client }),
    });
  }

  let core = makeCore();

  return {
    db,
    get core() {
      return core;
    },
    get alarmMs() {
      return alarmMs;
    },
    setNow(ms) {
      nowMs = ms;
    },
    advanceMs(delta) {
      nowMs += delta;
    },
    async evictAndRecreate() {
      core = makeCore();
      await core.ready;
      return core;
    },
    async connect(path = "/v1/relay", { host = "relay.example", ip = "v4:198.51.100.1" } = {}) {
      const req = new Request(`https://${host}${path}`, {
        headers: {
          upgrade: "websocket",
          "x-tendril-canonical-host": host,
          "x-tendril-client-ip": ip,
        },
      });
      const res = await core.fetch(req);
      assert.equal(res.status, 101);
      const client = res.webSocket;
      const server = client.peer;
      const messages = client.drainJson();
      return {
        client,
        server,
        challenge: messages[0],
        async sendJson(obj) {
          await core.webSocketMessage(server, JSON.stringify(obj));
        },
        async sendRaw(msg) {
          await core.webSocketMessage(server, msg);
        },
        async disconnect() {
          server.close(1000, "client disconnect");
          await core.webSocketClose(server, 1000, "client disconnect", true);
        },
      };
    },
    async triggerAlarm() {
      await core.alarm();
    },
  };
}

test("worker front door validates healthz, strips caller x-tendril headers, and normalizes IP", async () => {
  const handler = createRelayHandler();
  let forwardedReq = null;
  const env = {
    RELAY: {
      idFromName: (name) => {
        assert.equal(name, "global");
        return "global-id";
      },
      get: () => ({
        async fetch(req) {
          forwardedReq = req;
          return new Response("ok", { status: 200 });
        },
      }),
    },
  };

  const healthGet = await handler.fetch(new Request("https://relay.example/healthz"), env);
  assert.equal(healthGet.status, 200);
  assert.equal(await healthGet.text(), "ok");

  const healthHead = await handler.fetch(
    new Request("https://relay.example/healthz", { method: "HEAD" }),
    env,
  );
  assert.equal(healthHead.status, 200);

  const healthPost = await handler.fetch(
    new Request("https://relay.example/healthz", { method: "POST" }),
    env,
  );
  assert.equal(healthPost.status, 405);

  const healthWs = await handler.fetch(
    new Request("https://relay.example/healthz", { headers: { upgrade: "websocket" } }),
    env,
  );
  assert.equal(healthWs.status, 404);

  const nonWs = await handler.fetch(new Request("https://relay.example/v1/relay"), env);
  assert.equal(nonWs.status, 426);

  const wsReq = new Request("https://Relay.Example./v2/relay", {
    headers: {
      upgrade: "websocket",
      "cf-connecting-ip": "2001:db8:abcd:0001::99",
      "x-tendril-canonical-host": "spoofed.evil",
      "x-tendril-client-ip": "v4:127.0.0.1",
    },
  });
  await handler.fetch(wsReq, env);
  assert.equal(forwardedReq.headers.get("x-tendril-canonical-host"), "relay.example");
  assert.equal(forwardedReq.headers.get("x-tendril-client-ip"), "v6:2001:0db8:abcd:0001");
  assert.equal(normalizeClientIp("203.0.113.5"), "v4:203.0.113.5");
});

test("DO reconstructs listener, 4 standby sockets, SQLite 65521 B init_frame, and bridged streams after cold eviction", async () => {
  const h = createHibernatingHarness();
  const listenerId = genEd25519Identity();

  const l = await h.connect("/v1/relay");
  assert.equal(l.challenge.fast_open, true);
  assert.equal(l.challenge.standby, true);
  await l.sendJson({
    op: "register",
    pub: listenerId.pubB64,
    sig: signV1Register(listenerId, "relay.example", l.challenge.nonce),
    fast_open: false,
  });
  assert.deepEqual(l.client.drainJson(), [{ op: "registered", pub: listenerId.pubB64 }]);

  // Park 4 standby acceptors and reject a 5th.
  const standbys = [];
  for (let i = 0; i < 4; i += 1) {
    const sb = await h.connect("/v1/relay");
    await sb.sendJson({
      op: "standby",
      pub: listenerId.pubB64,
      sig: signV1Register(listenerId, "relay.example", sb.challenge.nonce),
    });
    assert.deepEqual(sb.client.drainJson(), [{ op: "standby_ready" }]);
    standbys.push(sb);
  }
  const sb5 = await h.connect("/v1/relay");
  await sb5.sendJson({
    op: "standby",
    pub: listenerId.pubB64,
    sig: signV1Register(listenerId, "relay.example", sb5.challenge.nonce),
  });
  assert.deepEqual(sb5.client.drainJson(), [{ op: "error", code: "rate_limited" }]);
  assert.notEqual(sb5.client.closed, null);

  // Cold DO eviction before standby dial: verify FIFO #1 wakes up with ready + binary init_frame.
  await h.evictAndRecreate();

  const fastInit = randomBytes(1200);
  const conn1 = b64url(randomBytes(16));
  const d1 = await h.connect("/v1/relay");
  await d1.sendJson({
    op: "dial",
    target_pub: listenerId.pubB64,
    conn_id: conn1,
    init_frame: b64url(fastInit),
  });
  assert.deepEqual(standbys[0].client.drainJson(), [{ op: "incoming", conn_id: conn1 }]);
  const injectedFast = standbys[0].client.drainAll();
  assert.equal(injectedFast.length, 1);
  assert.deepEqual(Buffer.from(injectedFast[0]), fastInit);
  assert.deepEqual(d1.client.drainJson(), [{ op: "ready", conn_id: conn1 }]);

  // Drain remaining 3 standbys cleanly so classic fallback can be tested.
  for (let i = 1; i < 4; i += 1) {
    await standbys[i].disconnect();
  }

  // Classic fallback with maximum 65521 B init_frame stored in SQLite (NOT attachment).
  const maxInit = randomBytes(65_521);
  const conn2 = b64url(randomBytes(16));
  const d2 = await h.connect("/v1/relay");
  await d2.sendJson({
    op: "dial",
    target_pub: listenerId.pubB64,
    conn_id: conn2,
    init_frame: b64url(maxInit),
  });
  const dialerAttJson = JSON.stringify(d2.server.deserializeAttachment());
  assert.ok(dialerAttJson.length < 512, `attachment grew too large: ${dialerAttJson.length}`);
  assert.equal(h.db.prepare("SELECT COUNT(*) AS c FROM pending_init_frames").get().c, 1);
  assert.deepEqual(l.client.drainJson(), [{ op: "incoming", conn_id: conn2 }]);

  // Evict DO while dialer awaits accept with SQLite init_frame, then accept after wake.
  await h.evictAndRecreate();

  const acc2 = await h.connect("/v1/relay");
  await acc2.sendJson({
    op: "accept",
    pub: listenerId.pubB64,
    conn_id: conn2,
    sig: signV1Accept(listenerId, "relay.example", acc2.challenge.nonce, conn2),
  });
  assert.deepEqual(acc2.client.drainJson(), [{ op: "ready", conn_id: conn2 }]);
  const accMsgs = acc2.client.drainAll();
  assert.equal(accMsgs.length, 1);
  assert.deepEqual(Buffer.from(accMsgs[0]), maxInit);
  assert.deepEqual(d2.client.drainJson(), [{ op: "ready", conn_id: conn2 }]);
  assert.equal(h.db.prepare("SELECT COUNT(*) AS c FROM pending_init_frames").get().c, 0);

  // Evict again mid-bridge and verify bidirectional binary relay still forwards cleanly.
  await h.evictAndRecreate();
  const payload = Uint8Array.from([1, 2, 3, 4, 5]);
  await d2.sendRaw(payload);
  assert.deepEqual(acc2.client.drainAll(), [payload]);
});

test("bridgeId isolates streams even if a subsequent bridge reuses conn_id", async () => {
  const h = createHibernatingHarness();
  const listener = genEd25519Identity();
  const l = await h.connect("/v1/relay");
  await l.sendJson({
    op: "register",
    pub: listener.pubB64,
    sig: signV1Register(listener, "relay.example", l.challenge.nonce),
  });
  l.client.drainJson();

  const sharedConnId = b64url(randomBytes(16));

  const dA = await h.connect("/v1/relay");
  await dA.sendJson({ op: "dial", target_pub: listener.pubB64, conn_id: sharedConnId });
  const aA = await h.connect("/v1/relay");
  await aA.sendJson({
    op: "accept",
    pub: listener.pubB64,
    conn_id: sharedConnId,
    sig: signV1Accept(listener, "relay.example", aA.challenge.nonce, sharedConnId),
  });
  dA.client.drainJson();
  aA.client.drainJson();

  // Same conn_id after Bridge A left pending.
  const dB = await h.connect("/v1/relay");
  await dB.sendJson({ op: "dial", target_pub: listener.pubB64, conn_id: sharedConnId });
  const aB = await h.connect("/v1/relay");
  await aB.sendJson({
    op: "accept",
    pub: listener.pubB64,
    conn_id: sharedConnId,
    sig: signV1Accept(listener, "relay.example", aB.challenge.nonce, sharedConnId),
  });
  dB.client.drainJson();
  aB.client.drainJson();

  await dA.sendRaw(Uint8Array.from([0xAA]));
  await dB.sendRaw(Uint8Array.from([0xBB]));
  assert.deepEqual(aA.client.drainAll(), [Uint8Array.from([0xAA])]);
  assert.deepEqual(aB.client.drainAll(), [Uint8Array.from([0xBB])]);

  await dA.disconnect();
  assert.notEqual(aA.client.closed, null);
  assert.equal(aB.client.closed, null);
  await dB.sendRaw(Uint8Array.from([0xCC]));
  assert.deepEqual(aB.client.drainAll(), [Uint8Array.from([0xCC])]);
});

test("Option 1A enforces zero-presence-leak order, strict auth schema, and Tiers 1-3 across v1 and v2", async () => {
  const issuer = genEd25519Identity();
  const allowlisted = genEd25519Identity();
  const peer = genEd25519Identity();
  const secret = "super-secret-relay-hmac-key";

  const h = createHibernatingHarness(
    {
      TENDRIL_RELAY_AUTH_SECRET: secret,
      TENDRIL_RELAY_ISSUER_PUBS: issuer.pubB64,
      TENDRIL_RELAY_ALLOW_MAILBOXES: allowlisted.pubB64,
      TENDRIL_RELAY_AUTH_SCOPE: "all",
    },
    1_760_000_000_000,
  );

  // Unknown field on auth fails closed as invalid_request.
  const badSchema = await h.connect("/v1/relay");
  assert.deepEqual(badSchema.challenge.auth_required, ["register", "dial"]);
  await badSchema.sendJson({
    op: "dial",
    target_pub: peer.pubB64,
    conn_id: b64url(randomBytes(16)),
    auth: { kind: "hmac", mac: "AAAA", extra: 1 },
  });
  assert.deepEqual(badSchema.client.drainJson(), [{ op: "error", code: "invalid_request" }]);

  // Missing or bad auth on offline target with bad init_frame MUST return unauthorized (zero presence leak).
  const unauthDial = await h.connect("/v1/relay");
  await unauthDial.sendJson({
    op: "dial",
    target_pub: peer.pubB64,
    conn_id: b64url(randomBytes(16)),
    init_frame: "",
  });
  assert.deepEqual(unauthDial.client.drainJson(), [{ op: "error", code: "unauthorized" }]);

  // Valid HMAC followed by another valid HMAC proves secretBytes was not zeroed in config.
  const connOk = b64url(randomBytes(16));
  const authDial1 = await h.connect("/v1/relay");
  await authDial1.sendJson({
    op: "dial",
    target_pub: peer.pubB64,
    conn_id: connOk,
    init_frame: b64url(Buffer.alloc(65_522, 0x11)),
    auth: computeHmacAuth(secret, "dial", "relay.example", authDial1.challenge.nonce, peer.rawPub),
  });
  assert.deepEqual(authDial1.client.drainJson(), [{ op: "error", code: "frame_too_large" }]);

  const authDial2 = await h.connect("/v1/relay");
  await authDial2.sendJson({
    op: "dial",
    target_pub: peer.pubB64,
    conn_id: b64url(randomBytes(16)),
    auth: computeHmacAuth(secret, "dial", "relay.example", authDial2.challenge.nonce, peer.rawPub),
  });
  assert.deepEqual(authDial2.client.drainJson(), [{ op: "error", code: "offline" }]);

  // Tier 1 allowlist permits register WITHOUT proof under v1, while dial still demands auth.
  const l = await h.connect("/v1/relay");
  await l.sendJson({
    op: "register",
    pub: allowlisted.pubB64,
    sig: signV1Register(allowlisted, "relay.example", l.challenge.nonce),
  });
  assert.deepEqual(l.client.drainJson(), [{ op: "registered", pub: allowlisted.pubB64 }]);

  // Tier 3 JCS RelayTicket authorizes dial and fast_open sends init_frame inside Incoming.
  const fastL = await h.connect("/v2/relay");
  const serverEpoch = fastL.challenge.epoch;
  await fastL.sendJson({
    op: "register",
    mailbox_id: peer.pubB64,
    epoch: serverEpoch,
    sig: signV2Register(peer, "relay.example", fastL.challenge.nonce, serverEpoch),
    auth: mintTicket(issuer, "relay.example", "register", peer.pubB64, 1_759_999_900, 1_760_000_600),
    fast_open: true,
  });
  assert.deepEqual(fastL.client.drainJson(), [
    { op: "registered", mailbox_id: peer.pubB64, epoch: serverEpoch },
  ]);

  // V2 dial on stale epoch after valid admission returns "offline" (not "stale_epoch").
  const v2Stale = await h.connect("/v2/relay");
  await v2Stale.sendJson({
    op: "dial",
    target_mailbox_id: peer.pubB64,
    epoch: serverEpoch + 5,
    conn_id: b64url(randomBytes(16)),
    dial_token: b64url(randomBytes(32)),
    auth: mintTicket(issuer, "relay.example", "dial", "*", 1_759_999_900, 1_760_000_600),
  });
  assert.deepEqual(v2Stale.client.drainJson(), [{ op: "error", code: "offline" }]);

  // V2 accept works with HMAC or Ticket; verify fast_open omits duplicate post-ready binary frame.
  const v2Cid = b64url(randomBytes(16));
  const v2Init = b64url(Buffer.from([0x42, 0x43, 0x44]));
  const v2Dial = await h.connect("/v2/relay");
  await v2Dial.sendJson({
    op: "dial",
    target_mailbox_id: peer.pubB64,
    epoch: serverEpoch,
    conn_id: v2Cid,
    dial_token: b64url(randomBytes(32)),
    auth: mintTicket(issuer, "relay.example", "dial", peer.pubB64, 1_759_999_900, 1_760_000_600),
    init_frame: v2Init,
  });
  const notes = fastL.client.drainJson();
  assert.equal(notes.length, 1);
  assert.equal(notes[0].init_frame, v2Init);

  const v2Acc = await h.connect("/v2/relay");
  await v2Acc.sendJson({
    op: "accept",
    mailbox_id: peer.pubB64,
    epoch: serverEpoch,
    conn_id: v2Cid,
    sig: signV2Accept(peer, "relay.example", v2Acc.challenge.nonce, v2Cid, serverEpoch),
    auth: computeHmacAuth(secret, "accept", "relay.example", v2Acc.challenge.nonce, peer.rawPub),
  });
  assert.deepEqual(v2Acc.client.drainJson(), [{ op: "ready", conn_id: v2Cid }]);
  assert.equal(v2Acc.client.drainAll().length, 0);
});

test("post-ready invalid frames close both sockets and alarm spares quiet listeners past 300s", async () => {
  const h = createHibernatingHarness({}, 1_760_000_000_000);
  const v1Listener = genEd25519Identity();
  const v2Listener = genEd25519Identity();

  const l1 = await h.connect("/v1/relay");
  await l1.sendJson({
    op: "register",
    pub: v1Listener.pubB64,
    sig: signV1Register(v1Listener, "relay.example", l1.challenge.nonce),
  });
  l1.client.drainJson();

  const sb1 = await h.connect("/v1/relay");
  await sb1.sendJson({
    op: "standby",
    pub: v1Listener.pubB64,
    sig: signV1Register(v1Listener, "relay.example", sb1.challenge.nonce),
  });
  sb1.client.drainJson();

  const l2 = await h.connect("/v2/relay");
  const ep = l2.challenge.epoch;
  await l2.sendJson({
    op: "register",
    mailbox_id: v2Listener.pubB64,
    epoch: ep,
    sig: signV2Register(v2Listener, "relay.example", l2.challenge.nonce, ep),
  });
  l2.client.drainJson();

  // Establish bridge #1 and test text rejection -> both sockets close.
  const cid1 = b64url(randomBytes(16));
  const d1 = await h.connect("/v1/relay");
  await d1.sendJson({ op: "dial", target_pub: v1Listener.pubB64, conn_id: cid1 });
  d1.client.drainJson();
  assert.equal(sb1.client.drainJson()[0].op, "incoming");
  await d1.sendRaw("unexpected-text-frame");
  assert.equal(d1.client.closed?.code, 1008);
  assert.equal(sb1.client.closed?.code, 1008);

  // Establish bridge #2 (for 0 B / >65521 B binary invalid check) + idle bridge #3 + hanging dialer + awaiting_cmd.
  const cid2 = b64url(randomBytes(16));
  const d2 = await h.connect("/v1/relay");
  await d2.sendJson({ op: "dial", target_pub: v1Listener.pubB64, conn_id: cid2 });
  const a2 = await h.connect("/v1/relay");
  await a2.sendJson({
    op: "accept",
    pub: v1Listener.pubB64,
    conn_id: cid2,
    sig: signV1Accept(v1Listener, "relay.example", a2.challenge.nonce, cid2),
  });
  await d2.sendRaw(new Uint8Array(0));
  assert.equal(d2.client.closed?.code, 1008);
  assert.equal(a2.client.closed?.code, 1008);

  const cid3 = b64url(randomBytes(16));
  const d3 = await h.connect("/v1/relay");
  await d3.sendJson({ op: "dial", target_pub: v1Listener.pubB64, conn_id: cid3 });
  const a3 = await h.connect("/v1/relay");
  await a3.sendJson({
    op: "accept",
    pub: v1Listener.pubB64,
    conn_id: cid3,
    sig: signV1Accept(v1Listener, "relay.example", a3.challenge.nonce, cid3),
  });
  d3.client.drainJson();
  a3.client.drainJson();

  const hanging = await h.connect("/v1/relay");
  await hanging.sendJson({
    op: "dial",
    target_pub: v1Listener.pubB64,
    conn_id: b64url(randomBytes(16)),
  });
  const uncmd = await h.connect("/v1/relay");
  const quietSb = await h.connect("/v1/relay");
  await quietSb.sendJson({
    op: "standby",
    pub: v1Listener.pubB64,
    sig: signV1Register(v1Listener, "relay.example", quietSb.challenge.nonce),
  });
  quietSb.client.drainJson();

  // At +16s: awaiting_cmd and dialer_waiting expire; quiet listeners, standby, and bridge stay alive.
  h.advanceMs(16_000);
  await h.triggerAlarm();
  assert.deepEqual(uncmd.client.drainJson(), [{ op: "error", code: "timeout" }]);
  assert.deepEqual(hanging.client.drainJson(), [{ op: "error", code: "timeout" }]);
  assert.equal(l1.client.closed, null);
  assert.equal(quietSb.client.closed, null);
  assert.equal(l2.client.closed, null);
  assert.equal(d3.client.closed, null);

  // At +305s: idle bridge expires; quiet v1 listener, quiet standby, and in-window v2 listener remain open!
  h.advanceMs(300_000);
  await h.triggerAlarm();
  assert.notEqual(d3.client.closed, null);
  assert.notEqual(a3.client.closed, null);
  assert.equal(l1.client.closed, null);
  assert.equal(quietSb.client.closed, null);
  assert.equal(l2.client.closed, null);

  // Past (epoch + 2) * 3600s: v2 listener expires while v1 listener remains open.
  h.setNow((ep + 2) * 3_600_000 + 1);
  await h.triggerAlarm();
  assert.notEqual(l2.client.closed, null);
  assert.equal(l1.client.closed, null);
  assert.equal(quietSb.client.closed, null);
});

test("config defaults match spec, orphan auth scope fails closed, open relay checks ticket schema, and acceptor ready failure emits offline", async () => {
  const defaults = parseRelayConfig({});
  assert.equal(defaults.maxConnections, 4096);
  assert.equal(defaults.maxConnsPerIp, 64);
  assert.equal(defaults.maxMailboxes, 1024);
  assert.equal(defaults.maxPendingPerMailbox, 8);
  assert.equal(defaults.maxActivePerMailbox, 64);

  assert.throws(
    () => parseRelayConfig({ TENDRIL_RELAY_AUTH_SCOPE: "register-only" }),
    /TENDRIL_RELAY_AUTH_SCOPE/,
  );

  const handler = createRelayHandler();
  const res = await handler.fetch(
    new Request("https://relay.example/v1/relay", { headers: { upgrade: "websocket" } }),
    { TENDRIL_RELAY_AUTH_SCOPE: "register-only" },
  );
  assert.equal(res.status, 500);

  const h = createHibernatingHarness();
  const listenerId = genEd25519Identity();

  const bogusTicketDial = await h.connect("/v1/relay");
  await bogusTicketDial.sendJson({
    op: "dial",
    target_pub: listenerId.pubB64,
    conn_id: b64url(randomBytes(16)),
    auth: { kind: "ticket", ticket: { bogus: 1 } },
  });
  assert.deepEqual(bogusTicketDial.client.drainJson(), [{ op: "error", code: "invalid_request" }]);

  const l = await h.connect("/v1/relay");
  await l.sendJson({
    op: "register",
    pub: listenerId.pubB64,
    sig: signV1Register(listenerId, "relay.example", l.challenge.nonce),
  });
  l.client.drainJson();

  const cid = b64url(randomBytes(16));
  const d = await h.connect("/v1/relay");
  await d.sendJson({ op: "dial", target_pub: listenerId.pubB64, conn_id: cid });

  const acc = await h.connect("/v1/relay");
  acc.server.send = () => {
    throw new Error("simulated acceptor write failure");
  };
  await acc.sendJson({
    op: "accept",
    pub: listenerId.pubB64,
    conn_id: cid,
    sig: signV1Accept(listenerId, "relay.example", acc.challenge.nonce, cid),
  });
  assert.deepEqual(d.client.drainJson(), [{ op: "error", code: "offline" }]);
  assert.notEqual(d.client.closed, null);
  assert.notEqual(acc.client.closed, null);
});

test("ticket-admitted registrations and standby sockets end after not_after plus skew while bridged streams run on", async () => {
  const issuer = genEd25519Identity();
  const listener = genEd25519Identity();
  const v2Listener = genEd25519Identity();
  const nowUnix = 1_760_000_000;
  const h = createHibernatingHarness(
    { TENDRIL_RELAY_ISSUER_PUBS: issuer.pubB64, TENDRIL_RELAY_AUTH_SCOPE: "register-only" },
    nowUnix * 1000,
  );
  const notAfter = nowUnix + 60;
  const deadlineMs = (notAfter + 30 + 1) * 1000;
  const ticket = mintTicket(issuer, "relay.example", "register", listener.pubB64, nowUnix - 10, notAfter);

  const l = await h.connect("/v1/relay");
  await l.sendJson({
    op: "register",
    pub: listener.pubB64,
    sig: signV1Register(listener, "relay.example", l.challenge.nonce),
    auth: ticket,
  });
  assert.deepEqual(l.client.drainJson(), [{ op: "registered", pub: listener.pubB64 }]);
  const standbys = [];
  for (let i = 0; i < 2; i += 1) {
    const sb = await h.connect("/v1/relay");
    await sb.sendJson({
      op: "standby",
      pub: listener.pubB64,
      sig: signV1Register(listener, "relay.example", sb.challenge.nonce),
      auth: ticket,
    });
    assert.deepEqual(sb.client.drainJson(), [{ op: "standby_ready" }]);
    standbys.push(sb);
  }

  const v2 = await h.connect("/v2/relay");
  const epoch = v2.challenge.epoch;
  const v2Ticket = mintTicket(issuer, "relay.example", "register", v2Listener.pubB64, nowUnix - 10, notAfter);
  await v2.sendJson({
    op: "register",
    mailbox_id: v2Listener.pubB64,
    epoch,
    sig: signV2Register(v2Listener, "relay.example", v2.challenge.nonce, epoch),
    auth: v2Ticket,
  });
  assert.deepEqual(v2.client.drainJson(), [
    { op: "registered", mailbox_id: v2Listener.pubB64, epoch },
  ]);
  const v2Sb = await h.connect("/v2/relay");
  await v2Sb.sendJson({
    op: "standby",
    mailbox_id: v2Listener.pubB64,
    epoch,
    sig: signV2Register(v2Listener, "relay.example", v2Sb.challenge.nonce, epoch),
    auth: v2Ticket,
  });
  assert.deepEqual(v2Sb.client.drainJson(), [
    { op: "standby_ready", mailbox_id: v2Listener.pubB64, epoch },
  ]);

  // A stream bridged before expiry runs until it closes.
  const conn = b64url(randomBytes(16));
  const d = await h.connect("/v1/relay");
  await d.sendJson({ op: "dial", target_pub: listener.pubB64, conn_id: conn });
  assert.deepEqual(d.client.drainJson(), [{ op: "ready", conn_id: conn }]);
  assert.deepEqual(standbys[0].client.drainJson(), [{ op: "incoming", conn_id: conn }]);

  assert.ok(h.alarmMs !== null && h.alarmMs <= deadlineMs, `alarm ${h.alarmMs} after ${deadlineMs}`);
  h.setNow(deadlineMs - 1000);
  await h.triggerAlarm();
  for (const s of [l, standbys[1], v2, v2Sb]) {
    assert.equal(s.client.closed, null);
  }

  h.setNow(deadlineMs);
  await h.triggerAlarm();
  for (const s of [l, standbys[1], v2, v2Sb]) {
    assert.notEqual(s.client.closed, null);
  }
  assert.equal(d.client.closed, null);
  assert.equal(standbys[0].client.closed, null);
  const payload = Uint8Array.from([9, 8, 7]);
  await d.sendRaw(payload);
  assert.deepEqual(standbys[0].client.drainAll(), [payload]);

  const late = await h.connect("/v1/relay");
  await late.sendJson({ op: "dial", target_pub: listener.pubB64, conn_id: b64url(randomBytes(16)) });
  assert.deepEqual(late.client.drainJson(), [{ op: "error", code: "offline" }]);
});

test("a replaced registration fails its pending dials offline and closes with replaced", async () => {
  const h = createHibernatingHarness();
  const listener = genEd25519Identity();

  const old = await h.connect("/v1/relay");
  await old.sendJson({
    op: "register",
    pub: listener.pubB64,
    sig: signV1Register(listener, "relay.example", old.challenge.nonce),
  });
  assert.deepEqual(old.client.drainJson(), [{ op: "registered", pub: listener.pubB64 }]);
  const conn = b64url(randomBytes(16));
  const d = await h.connect("/v1/relay");
  await d.sendJson({ op: "dial", target_pub: listener.pubB64, conn_id: conn });
  assert.deepEqual(old.client.drainJson(), [{ op: "incoming", conn_id: conn }]);

  const next = await h.connect("/v1/relay");
  await next.sendJson({
    op: "register",
    pub: listener.pubB64,
    sig: signV1Register(listener, "relay.example", next.challenge.nonce),
  });
  assert.deepEqual(next.client.drainJson(), [{ op: "registered", pub: listener.pubB64 }]);
  assert.deepEqual(d.client.drainJson(), [{ op: "error", code: "offline" }]);
  assert.deepEqual(old.client.drainJson(), [{ op: "error", code: "replaced" }]);
  assert.notEqual(old.client.closed, null);
  assert.equal(next.client.closed, null);
});

test("auth scope defaults to register-only when only a mailbox allowlist is configured", () => {
  const key = genEd25519Identity().pubB64;
  const tier1 = parseRelayConfig({ TENDRIL_RELAY_ALLOW_MAILBOXES: key });
  assert.equal(tier1.authScope, "register-only");
  assert.deepEqual(tier1.authRequired, ["register"]);
  const tier3 = parseRelayConfig({ TENDRIL_RELAY_ISSUER_PUBS: key });
  assert.equal(tier3.authScope, "all");
  assert.deepEqual(tier3.authRequired, ["register", "dial"]);
  const tier1And2 = parseRelayConfig({
    TENDRIL_RELAY_ALLOW_MAILBOXES: key,
    TENDRIL_RELAY_AUTH_SECRET: "shared-secret",
  });
  assert.equal(tier1And2.authScope, "all");
  assert.throws(
    () => parseRelayConfig({ TENDRIL_RELAY_ALLOW_MAILBOXES: b64url(new Uint8Array(32)) }),
    /./,
  );
});

test("expired registrations and standby sockets are refused at lookup before the alarm runs", async () => {
  const issuer = genEd25519Identity();
  const listener = genEd25519Identity();
  const other = genEd25519Identity();
  const nowUnix = 1_760_000_000;
  const h = createHibernatingHarness(
    { TENDRIL_RELAY_ISSUER_PUBS: issuer.pubB64, TENDRIL_RELAY_AUTH_SCOPE: "register-only" },
    nowUnix * 1000,
  );
  const ticket = mintTicket(issuer, "relay.example", "register", listener.pubB64, nowUnix - 10, nowUnix + 60);
  const l = await h.connect("/v1/relay");
  await l.sendJson({
    op: "register",
    pub: listener.pubB64,
    sig: signV1Register(listener, "relay.example", l.challenge.nonce),
    auth: ticket,
  });
  assert.deepEqual(l.client.drainJson(), [{ op: "registered", pub: listener.pubB64 }]);

  // A registration that no dial will touch, so its standby lookup meets the expiry itself.
  const third = genEd25519Identity();
  const thirdTicket = mintTicket(issuer, "relay.example", "register", third.pubB64, nowUnix - 10, nowUnix + 60);
  const t = await h.connect("/v1/relay");
  await t.sendJson({
    op: "register",
    pub: third.pubB64,
    sig: signV1Register(third, "relay.example", t.challenge.nonce),
    auth: thirdTicket,
  });
  assert.deepEqual(t.client.drainJson(), [{ op: "registered", pub: third.pubB64 }]);

  // A second listener keeps a long registration with a short-lived standby socket.
  const long = mintTicket(issuer, "relay.example", "register", other.pubB64, nowUnix - 10, nowUnix + 3600);
  const short = mintTicket(issuer, "relay.example", "register", other.pubB64, nowUnix - 10, nowUnix + 60);
  const o = await h.connect("/v1/relay");
  await o.sendJson({
    op: "register",
    pub: other.pubB64,
    sig: signV1Register(other, "relay.example", o.challenge.nonce),
    auth: long,
  });
  assert.deepEqual(o.client.drainJson(), [{ op: "registered", pub: other.pubB64 }]);
  const sb = await h.connect("/v1/relay");
  await sb.sendJson({
    op: "standby",
    pub: other.pubB64,
    sig: signV1Register(other, "relay.example", sb.challenge.nonce),
    auth: short,
  });
  assert.deepEqual(sb.client.drainJson(), [{ op: "standby_ready" }]);

  // Past the deadline, without running the alarm.
  h.setNow((nowUnix + 60 + 30 + 1) * 1000);
  const d = await h.connect("/v1/relay");
  await d.sendJson({ op: "dial", target_pub: listener.pubB64, conn_id: b64url(randomBytes(16)) });
  assert.deepEqual(d.client.drainJson(), [{ op: "error", code: "offline" }]);
  assert.notEqual(l.client.closed, null);

  assert.equal(t.client.closed, null);
  const lateSb = await h.connect("/v1/relay");
  const fresh = mintTicket(issuer, "relay.example", "register", third.pubB64, nowUnix + 80, nowUnix + 150);
  await lateSb.sendJson({
    op: "standby",
    pub: third.pubB64,
    sig: signV1Register(third, "relay.example", lateSb.challenge.nonce),
    auth: fresh,
  });
  assert.deepEqual(lateSb.client.drainJson(), [{ op: "error", code: "offline" }]);
  assert.notEqual(t.client.closed, null);

  const conn = b64url(randomBytes(16));
  const d2 = await h.connect("/v1/relay");
  await d2.sendJson({ op: "dial", target_pub: other.pubB64, conn_id: conn });
  assert.deepEqual(d2.client.drainJson(), []);
  assert.deepEqual(o.client.drainJson(), [{ op: "incoming", conn_id: conn }]);
  assert.deepEqual(sb.client.drainJson(), []);
  assert.notEqual(sb.client.closed, null);
});

test("v2 replacement closes parked standbys and sends replaced", async () => {
  const h = createHibernatingHarness();
  const listener = genEd25519Identity();

  const old = await h.connect("/v2/relay");
  const epoch = old.challenge.epoch;
  await old.sendJson({
    op: "register",
    mailbox_id: listener.pubB64,
    epoch,
    sig: signV2Register(listener, "relay.example", old.challenge.nonce, epoch),
  });
  assert.deepEqual(old.client.drainJson(), [{ op: "registered", mailbox_id: listener.pubB64, epoch }]);
  const sb = await h.connect("/v2/relay");
  await sb.sendJson({
    op: "standby",
    mailbox_id: listener.pubB64,
    epoch,
    sig: signV2Register(listener, "relay.example", sb.challenge.nonce, epoch),
  });
  assert.deepEqual(sb.client.drainJson(), [{ op: "standby_ready", mailbox_id: listener.pubB64, epoch }]);

  const next = await h.connect("/v2/relay");
  await next.sendJson({
    op: "register",
    mailbox_id: listener.pubB64,
    epoch,
    sig: signV2Register(listener, "relay.example", next.challenge.nonce, epoch),
  });
  assert.deepEqual(next.client.drainJson(), [{ op: "registered", mailbox_id: listener.pubB64, epoch }]);
  assert.deepEqual(old.client.drainJson(), [{ op: "error", code: "replaced" }]);
  assert.notEqual(old.client.closed, null);
  assert.notEqual(sb.client.closed, null);
  assert.equal(next.client.closed, null);
});

test("v1 replacement closes the replaced registration's parked standby sockets", async () => {
  const h = createHibernatingHarness();
  const listener = genEd25519Identity();
  const old = await h.connect("/v1/relay");
  await old.sendJson({
    op: "register",
    pub: listener.pubB64,
    sig: signV1Register(listener, "relay.example", old.challenge.nonce),
  });
  assert.deepEqual(old.client.drainJson(), [{ op: "registered", pub: listener.pubB64 }]);
  const sb = await h.connect("/v1/relay");
  await sb.sendJson({
    op: "standby",
    pub: listener.pubB64,
    sig: signV1Register(listener, "relay.example", sb.challenge.nonce),
  });
  assert.deepEqual(sb.client.drainJson(), [{ op: "standby_ready" }]);

  const next = await h.connect("/v1/relay");
  await next.sendJson({
    op: "register",
    pub: listener.pubB64,
    sig: signV1Register(listener, "relay.example", next.challenge.nonce),
  });
  assert.deepEqual(old.client.drainJson(), [{ op: "error", code: "replaced" }]);
  assert.notEqual(sb.client.closed, null);
  const conn = b64url(randomBytes(16));
  const d = await h.connect("/v1/relay");
  await d.sendJson({ op: "dial", target_pub: listener.pubB64, conn_id: conn });
  assert.deepEqual(d.client.drainJson(), []);
  assert.deepEqual(next.client.drainJson(), [
    { op: "registered", pub: listener.pubB64 },
    { op: "incoming", conn_id: conn },
  ]);
});

test("explicit auth scope all fails closed when only a mailbox allowlist is configured", () => {
  const key = genEd25519Identity().pubB64;
  assert.throws(
    () => parseRelayConfig({ TENDRIL_RELAY_ALLOW_MAILBOXES: key, TENDRIL_RELAY_AUTH_SCOPE: "all" }),
    /TENDRIL_RELAY_AUTH_SCOPE/,
  );
  const ok = parseRelayConfig({
    TENDRIL_RELAY_ALLOW_MAILBOXES: key,
    TENDRIL_RELAY_AUTH_SECRET: "shared-secret",
    TENDRIL_RELAY_AUTH_SCOPE: "all",
  });
  assert.deepEqual(ok.authRequired, ["register", "dial"]);
});

test("an expired registration accepted against or taken over ends quietly", async () => {
  const issuer = genEd25519Identity();
  const nowUnix = 1_760_000_000;
  const later = nowUnix + 60 + 30 + 1;
  const h = createHibernatingHarness(
    {
      TENDRIL_RELAY_ISSUER_PUBS: issuer.pubB64,
      TENDRIL_RELAY_AUTH_SCOPE: "register-only",
      TENDRIL_RELAY_MAX_MAILBOXES: "2",
    },
    nowUnix * 1000,
  );
  const register = async (id, notBefore, notAfter) => {
    const s = await h.connect("/v1/relay");
    await s.sendJson({
      op: "register",
      pub: id.pubB64,
      sig: signV1Register(id, "relay.example", s.challenge.nonce),
      auth: mintTicket(issuer, "relay.example", "register", id.pubB64, notBefore, notAfter),
    });
    return s;
  };

  const a = genEd25519Identity();
  const b = genEd25519Identity();
  const oldA = await register(a, nowUnix - 10, nowUnix + 60);
  assert.deepEqual(oldA.client.drainJson(), [{ op: "registered", pub: a.pubB64 }]);
  const oldB = await register(b, nowUnix - 10, nowUnix + 60);
  assert.deepEqual(oldB.client.drainJson(), [{ op: "registered", pub: b.pubB64 }]);
  const conn = b64url(randomBytes(16));
  const d = await h.connect("/v1/relay");
  await d.sendJson({ op: "dial", target_pub: b.pubB64, conn_id: conn });
  assert.deepEqual(oldB.client.drainJson(), [{ op: "incoming", conn_id: conn }]);

  // Past the deadline, without running the alarm.
  h.setNow(later * 1000);

  // The accept carries its own valid ticket; only the registration has expired.
  const acc = await h.connect("/v1/relay");
  await acc.sendJson({
    op: "accept",
    pub: b.pubB64,
    conn_id: conn,
    sig: signV1Accept(b, "relay.example", acc.challenge.nonce, conn),
    auth: mintTicket(issuer, "relay.example", "register", b.pubB64, later - 5, later + 60),
  });
  assert.deepEqual(acc.client.drainJson(), [{ op: "error", code: "invalid_request" }]);
  assert.deepEqual(d.client.drainJson(), [{ op: "error", code: "offline" }]);
  assert.notEqual(oldB.client.closed, null);

  // Registering again ends the expired registration without telling it `replaced`.
  const newA = await register(a, later - 5, later + 60);
  assert.deepEqual(newA.client.drainJson(), [{ op: "registered", pub: a.pubB64 }]);
  assert.deepEqual(oldA.client.drainJson(), []);
  assert.notEqual(oldA.client.closed, null);
});

test("expired registrations do not count against mailbox capacity", async () => {
  const issuer = genEd25519Identity();
  const nowUnix = 1_760_000_000;
  const later = nowUnix + 60 + 30 + 1;
  const h = createHibernatingHarness(
    {
      TENDRIL_RELAY_ISSUER_PUBS: issuer.pubB64,
      TENDRIL_RELAY_AUTH_SCOPE: "register-only",
      TENDRIL_RELAY_MAX_MAILBOXES: "1",
    },
    nowUnix * 1000,
  );
  const register = async (id, notBefore, notAfter) => {
    const s = await h.connect("/v1/relay");
    await s.sendJson({
      op: "register",
      pub: id.pubB64,
      sig: signV1Register(id, "relay.example", s.challenge.nonce),
      auth: mintTicket(issuer, "relay.example", "register", id.pubB64, notBefore, notAfter),
    });
    return s;
  };
  const a = genEd25519Identity();
  const oldA = await register(a, nowUnix - 10, nowUnix + 60);
  assert.deepEqual(oldA.client.drainJson(), [{ op: "registered", pub: a.pubB64 }]);

  h.setNow(later * 1000);
  const b = genEd25519Identity();
  const newB = await register(b, later - 5, later + 60);
  assert.deepEqual(newB.client.drainJson(), [{ op: "registered", pub: b.pubB64 }]);
  assert.deepEqual(oldA.client.drainJson(), []);
  assert.notEqual(oldA.client.closed, null);
});
