import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { TendrilWebClient, initTendril } from "../src/index.js";
import { RelayStream } from "../src/relay.js";
import { buildUri, cliOnCopy, deadPort, liveHost } from "./live_peer.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH = path.join(__dirname, "..", "pkg", "tendril_wasm_bg.wasm");

let wasmReady = false;
async function ensureWasm() {
  if (!wasmReady) {
    await initTendril({ module_or_path: fs.readFileSync(WASM_PATH) });
    wasmReady = true;
  }
}

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function identityInfo(hostId) {
  const { WasmIdentity } = await import("../pkg/tendril_wasm.js");
  const id = WasmIdentity.generate(hostId);
  try {
    return JSON.parse(id.info_json());
  } finally {
    id.free();
  }
}

/** A client whose roster pins `host` (active unless `pending`), with optional legacy hints. */
async function clientWith(host, { pending = false, relayHints = null, ...options } = {}) {
  const { WasmRoster } = await import("../pkg/tendril_wasm.js");
  const roster = new WasmRoster();
  try {
    roster.insert_pinned_host(
      host.host_id,
      host.host_id,
      host.static_pub,
      host.signing_pub,
      0,
      relayHints ? JSON.stringify(relayHints) : null
    );
    let bytes = roster.to_json_bytes();
    if (pending) {
      const json = JSON.parse(new TextDecoder().decode(bytes));
      for (const entry of Object.values(json.entries ?? json.peers ?? {})) {
        entry.state = "pending";
      }
      bytes = new TextEncoder().encode(JSON.stringify(json));
    }
    return await TendrilWebClient.create({ hostId: "lock-client", rosterBytes: bytes, ...options });
  } finally {
    roster.free();
  }
}

function anchors(client) {
  return Object.keys(JSON.parse(client.exportRosterJson()).trust_anchors ?? {});
}

/** WebSockets that stay connecting until the test fails them. */
function installStalledWebSocket() {
  const sockets = [];
  const Original = globalThis.WebSocket;
  class StalledWebSocket extends EventTarget {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    constructor(url) {
      super();
      this.url = url;
      this.readyState = StalledWebSocket.CONNECTING;
      sockets.push(this);
    }
    send() {}
    fail() {
      this.dispatchEvent(new Event("error"));
      this.close();
    }
    close() {
      if (this.readyState === StalledWebSocket.CLOSED) return;
      this.readyState = StalledWebSocket.CLOSED;
      setTimeout(() => this.dispatchEvent(new Event("close")), 0);
    }
  }
  globalThis.WebSocket = StalledWebSocket;
  return {
    sockets,
    restore() {
      globalThis.WebSocket = Original;
    },
  };
}

function within(promise, ms, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} blocked for ${ms} ms`)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

async function waitFor(pred, label, timeoutMs = 2000) {
  const end = Date.now() + timeoutMs;
  while (!pred()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${label}`);
    await delay(5);
  }
}

test("roster mutations run one at a time, FIFO, with the persist inside the critical section", async () => {
  await ensureWasm();
  const host = await identityInfo("lock-fifo-host");
  let inFlight = 0;
  let maxInFlight = 0;
  const persisted = [];
  const client = await clientWith(host, {
    onPersistRoster: async (json) => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await delay(5);
      persisted.push(JSON.parse(json));
      inFlight -= 1;
    },
  });
  try {
    const routes = [
      "wss://a.example/v1/relay",
      "wss://b.example/v1/relay",
      "wss://c.example/v1/relay",
    ];
    await Promise.all(routes.map((r) => client.setPeerRoutes(host.host_id, [r])));
    assert.equal(maxInFlight, 1);
    const seen = persisted.map((roster) => {
      const entry = Object.values(roster.entries ?? roster.peers)[0];
      return entry.routes.map((r) => r.hint);
    });
    assert.deepEqual(
      seen,
      routes.map((r) => [r])
    );
    assert.deepEqual(client.peerRoutes(host.host_id).routes, [
      { hint: routes[2], source: "operator" },
    ]);
  } finally {
    client.free();
  }
});

test("a failed persist rolls back only its own mutation, never a queued later one", async () => {
  await ensureWasm();
  const host = await identityInfo("lock-rollback-host");
  const anchor = await identityInfo("lock-anchor");
  let calls = 0;
  const client = await clientWith(host, {
    onPersistRoster: async () => {
      calls += 1;
      if (calls === 1) {
        await delay(20);
        throw new Error("storage quota exceeded");
      }
    },
  });
  try {
    const first = client.setPeerRoutes(host.host_id, ["wss://lost.example/v1/relay"]);
    const second = client.addTrustAnchor("lock-anchor", anchor.signing_pub);
    await assert.rejects(first, /storage quota exceeded/);
    await second;
    assert.deepEqual(client.peerRoutes(host.host_id).routes, []);
    assert.deepEqual(anchors(client), ["lock-anchor"]);
  } finally {
    client.free();
  }
});

test("a persist callback may call client methods without awaiting them; they run after it", async () => {
  await ensureWasm();
  const host = await identityInfo("lock-reentry-host");
  const anchor = await identityInfo("lock-reentry-anchor");
  const log = [];
  let inner = null;
  const client = await clientWith(host, {
    onPersistRoster: async () => {
      log.push("persist-start");
      if (inner === null) {
        inner = client.addTrustAnchor("reentry-anchor", anchor.signing_pub).then(() => {
          log.push("inner-done");
        });
      }
      await delay(5);
      log.push("persist-end");
    },
  });
  try {
    await client.setPeerRoutes(host.host_id, ["wss://outer.example/v1/relay"]);
    log.push("outer-done");
    await inner;
    assert.deepEqual(log, [
      "persist-start",
      "persist-end",
      "outer-done",
      "persist-start",
      "persist-end",
      "inner-done",
    ]);
    assert.deepEqual(anchors(client), ["reentry-anchor"]);
  } finally {
    client.free();
  }
});

test("awaiting a client call inside a persist callback deadlocks and logs a warning after 5 s", async (t) => {
  await ensureWasm();
  const host = await identityInfo("lock-deadlock-host");
  const anchor = await identityInfo("lock-deadlock-anchor");
  const warn = t.mock.method(console, "warn", () => {});
  let entered;
  const inCallback = new Promise((r) => {
    entered = r;
  });
  let nested = false;
  const client = await clientWith(host, {
    onPersistRoster: async () => {
      if (nested) return;
      nested = true;
      t.mock.timers.enable({ apis: ["setTimeout"] });
      const pending = client.addTrustAnchor("deadlock-anchor", anchor.signing_pub);
      entered();
      await pending;
    },
  });
  const outer = client.setPeerRoutes(host.host_id, ["wss://deadlock.example/v1/relay"]);
  let settled = false;
  outer.then(
    () => (settled = true),
    () => (settled = true)
  );
  await inCallback;
  t.mock.timers.tick(4999);
  assert.equal(warn.mock.callCount(), 0);
  t.mock.timers.tick(1);
  assert.equal(warn.mock.callCount(), 1);
  assert.match(warn.mock.calls[0].arguments[0], /persist callbacks must not await client methods/);
  t.mock.timers.reset();
  await delay(10);
  assert.equal(settled, false, "the awaiting callback never completes");
});

test("endpoint-free connect fails before dialing when no stored route is dialable", async () => {
  await ensureWasm();
  const host = await identityInfo("lock-noroute-host");
  const client = await clientWith(host, { relayHints: ["wss://legacy.example/v1/relay"] });
  try {
    await assert.rejects(
      () => client.connect({ targetHostId: host.host_id }),
      (err) =>
        err.message.startsWith(
          `no dialable stored routes for ${host.host_id}; legacy relay hints`
        ) && err.message.endsWith("connect with it as a recovery URI")
    );
    const iroh = `iroh://${"a".repeat(64)}`;
    const irohAddr = `${iroh}?addr=203.0.113.5:4433`;
    await client.setPeerRoutes(host.host_id, ["direct:192.0.2.1:7000", irohAddr]);
    await assert.rejects(
      () => client.connect({ targetHostId: host.host_id }),
      (err) =>
        err.message.includes("direct:192.0.2.1:7000 [browser_unsupported]") &&
        err.message.includes(`${iroh} [p2p_feature_disabled]`) &&
        !err.message.includes("addr=") &&
        err.skipped.some((s) => s.hint === irohAddr) &&
        err.skipped.length === 2
    );
    await assert.rejects(
      () => client.connect({ targetHostId: "missing-host" }),
      (err) => err.code === "peer_not_found"
    );
  } finally {
    client.free();
  }
  const pendingClient = await clientWith(host, { pending: true });
  try {
    await assert.rejects(
      () => pendingClient.connect({ targetHostId: host.host_id }),
      (err) => err.code === "peer_pending"
    );
  } finally {
    pendingClient.free();
  }
});

test("pair and connect never hold the roster lock across socket I/O", async () => {
  await ensureWasm();
  const host = await identityInfo("lock-io-host");
  const anchor = await identityInfo("lock-io-anchor");
  const ws = installStalledWebSocket();
  const client = await clientWith(host, { onPersistRoster: async () => {} });
  try {
    await client.setPeerRoutes(host.host_id, ["wss://stalled.example/v1/relay"]);
    const connecting = client.connect({ targetHostId: host.host_id, timeoutMs: 10000 });
    await waitFor(() => ws.sockets.length === 1, "the connect dial");
    await within(
      client.addTrustAnchor("io-anchor-1", anchor.signing_pub),
      1000,
      "a mutation during connect I/O"
    );
    ws.sockets[0].fail();
    await assert.rejects(connecting, (err) => err.failures.length === 1);

    const pairing = client.pair({
      relayUrl: "wss://stalled.example/v1/relay",
      targetPub: host.relay_pub,
      code: "TND-ABCD-EFGH-JKLM",
      timeoutMs: 10000,
    });
    await waitFor(() => ws.sockets.length === 2, "the pairing dial");
    await within(client.revokeTrustAnchor("io-anchor-1"), 1000, "a mutation during pairing I/O");
    ws.sockets[1].fail();
    await assert.rejects(pairing, /failed connecting to relay/);
  } finally {
    ws.restore();
    client.free();
  }
});

const PKG = "../pkg/tendril_wasm.js";

/**
 * Pairs `client` with a new live host over a signed URI (`rq` 3, one relay route), confirmed and
 * granted `fs.read`.
 */
async function pairLiveHost(client, hostId) {
  const host = await liveHost(hostId);
  const { relay, peer, fields, seedB64 } = host;
  try {
    const peerPair = peer.call({ op: "pair" });
    await client.pair({ pairingUri: buildUri({ ...fields, ep: [relay.wsUrl], rq: 3, seedB64 }) });
    const hostPair = await peerPair;
    await peer.call({ op: "confirm", peer_id: hostPair.device_id, sas: hostPair.sas });
    const grantJson = JSON.stringify(
      (await peer.call({ op: "mint", peer_id: hostPair.device_id, caps: ["fs.read"] })).grant
    );
    return {
      host,
      hostId,
      grantJson,
      /** Connects with the host accepting; `hostAccepts: false` for pre-dial failures. */
      async connect(extra = {}, { hostAccepts = true } = {}) {
        const accepted = hostAccepts ? peer.call({ op: "connect" }).catch((err) => err) : null;
        try {
          return await client.connect({ targetHostId: hostId, grantJson, ...extra });
        } finally {
          await accepted;
        }
      },
    };
  } catch (err) {
    host.close();
    throw err;
  }
}

/**
 * A live host paired with a fresh client (see `pairLiveHost`). Every roster persist yields to
 * the event loop and is then recorded in `persist.log`, so a persist that is not awaited shows
 * up late; with `persist.fail` it throws instead, and it waits for `persist.gate` when set.
 */
async function livePair(hostId, clientOptions = {}) {
  const persist = { log: [], fail: false, gate: null };
  const client = await TendrilWebClient.create({
    hostId: `${hostId}-client`,
    onPersistRoster: async (json) => {
      if (persist.gate) {
        await persist.gate;
      }
      await delay(5);
      if (persist.fail) {
        throw new Error("disk full");
      }
      persist.log.push(JSON.parse(json));
    },
    ...clientOptions,
  });
  try {
    const paired = await pairLiveHost(client, hostId);
    return {
      ...paired,
      client,
      persist,
      close() {
        client.free();
        paired.host.close();
      },
    };
  } catch (err) {
    client.free();
    throw err;
  }
}

/** Replaces the client roster entry of `peerId` in place, standing in for a concurrent change. */
function editEntry(wasmRoster, peerId, edit) {
  const json = JSON.parse(wasmRoster.to_json());
  edit(json.entries[peerId]);
  wasmRoster.replace_from_json(JSON.stringify(json));
}

/** The host's session saw the client close the stream (not a timeout, not data). */
async function assertHostSessionClosed(peer) {
  peer.send({ op: "recv", timeout_ms: 3000 });
  const res = await peer.recv();
  assert.ok(
    res.event === "eof" ||
      res.event === "closed" ||
      (res.ok === false && !/timed out/.test(res.error)),
    JSON.stringify(res)
  );
}

for (const race of [
  {
    name: "a revocation",
    code: "peer_revoked",
    edit: (entry) => {
      entry.state = "revoked";
    },
  },
  {
    name: "a v2 floor raise",
    code: "version_downgrade",
    edit: (entry) => {
      entry.min_wire_version = 2;
    },
  },
]) {
  test(`live: ${race.name} landing between the candidate win and reconciliation fails ${race.code} and closes the winner`, async () => {
    await ensureWasm();
    const { WasmRoster, WasmSessionClient } = await import(PKG);
    const anchor = await identityInfo("race-anchor");
    const fx = await livePair(`race-${race.code}`);
    const realFeed = WasmSessionClient.prototype.feed_bytes;
    const realAdd = WasmRoster.prototype.add_trust_anchor;
    const realReconcile = WasmRoster.prototype.reconcile_rotation_evidence;
    const log = [];
    let holder = null;
    let mutation = null;
    let release = null;
    try {
      // On the candidate win, one mutation holds the roster lock (its persist waits) and the
      // race queues behind it, so the race lands while the connect waits for the lock: without
      // the lock the reconciliation and final check would run first. The stubbed WASM call
      // applies the race.
      WasmSessionClient.prototype.feed_bytes = function (...args) {
        const out = realFeed.apply(this, args);
        if (JSON.parse(out).established && mutation === null) {
          log.push("win");
          fx.persist.gate = new Promise((r) => {
            release = r;
          });
          holder = fx.client.setPeerRoutes(fx.hostId, []);
          mutation = fx.client.addTrustAnchor("race", anchor.signing_pub);
          setTimeout(() => {
            fx.persist.gate = null;
            release();
          }, 200);
        }
        return out;
      };
      WasmRoster.prototype.add_trust_anchor = function (id, pub) {
        realAdd.call(this, id, pub);
        editEntry(this, fx.hostId, race.edit);
        log.push("race");
      };
      WasmRoster.prototype.reconcile_rotation_evidence = function (...args) {
        log.push("reconcile");
        return realReconcile.apply(this, args);
      };
      await assert.rejects(
        () => fx.connect(),
        (err) => err.code === race.code && err.committed === false
      );
      await holder;
      await mutation;
      assert.deepEqual(log, ["win", "race", "reconcile"]);
      await assertHostSessionClosed(fx.host.peer);
    } finally {
      WasmSessionClient.prototype.feed_bytes = realFeed;
      WasmRoster.prototype.add_trust_anchor = realAdd;
      WasmRoster.prototype.reconcile_rotation_evidence = realReconcile;
      fx.close();
    }
  });
}

test("live: fork records from two candidates fail rotation_fork_detected after persisting the revocation", async () => {
  await ensureWasm();
  const { WasmSessionClient } = await import(PKG);
  const fx = await livePair("fork-host");
  const { relay, stateDir } = fx.host;
  // Two rotations of the same pinned key at sequence 1: authentic, divergent evidence.
  const records = ["fork-a", "fork-b"].map(() => {
    const { dir } = cliOnCopy(stateDir, ["rotate"]);
    try {
      return JSON.parse(fs.readFileSync(path.join(dir, "identity.json"), "utf8")).rotation_chain;
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  const pinned = () => {
    const entry = JSON.parse(fx.client.exportRosterJson()).entries[fx.hostId];
    return { static_pub: entry.static_pub, rotation_seq: entry.rotation_seq };
  };
  const realPresented = WasmSessionClient.prototype.presented_rotation_json;
  const realFeed = WasmSessionClient.prototype.feed_bytes;
  const shown = new WeakMap();
  const order = [];
  try {
    const dead = `ws://127.0.0.1:${await deadPort()}/v1/relay`;
    await fx.client.clearPeerRoutes(fx.hostId, "signed");
    await fx.client.setPeerRoutes(fx.hostId, [dead, relay.wsUrl]);
    const before = pinned();
    // Each candidate machine presents its own chain: the dead route's the first rotation, the
    // live winner's the second. The winner also verifies its chain into the roster it was handed
    // on its last handshake frame, so that roster must be a clone: the client roster keeps the
    // snapshot pin until the reconciliation.
    WasmSessionClient.prototype.presented_rotation_json = function () {
      if (!shown.has(this)) {
        shown.set(this, JSON.stringify(records[order.filter((o) => o === "candidate").length]));
        order.push("candidate");
      }
      return shown.get(this);
    };
    WasmSessionClient.prototype.feed_bytes = function (bytes, now, elapsed, roster) {
      const out = realFeed.call(this, bytes, now, elapsed, roster);
      if (JSON.parse(out).established) {
        roster.apply_verified_rotation_json(fx.hostId, JSON.stringify(records[1]));
        order.push(`winner-rotated:${JSON.stringify(pinned()) === JSON.stringify(before)}`);
      }
      return out;
    };
    const persisted = fx.persist.log.length;
    // The rejection is observed as it settles, before the host side finishes: the revocation
    // persist must already have completed.
    const accepted = fx.host.peer.call({ op: "connect" }).catch((e) => e);
    const err = await fx.client
      .connect({ targetHostId: fx.hostId, grantJson: fx.grantJson })
      .catch((e) => {
        order.push(`rejected:${fx.persist.log.length - persisted}`);
        return e;
      });
    await accepted;
    assert.equal(err.code, "rotation_fork_detected", err.message);
    assert.deepEqual(order, ["candidate", "winner-rotated:true", "candidate", "rejected:1"]);
    assert.equal(fx.persist.log.at(-1).entries[fx.hostId].state, "revoked");
    assert.equal(fx.client.getPeer(fx.hostId).state, "revoked");
    assert.deepEqual(
      err.failures.map((f) => f.hint),
      [dead]
    );
    await assertHostSessionClosed(fx.host.peer);
  } finally {
    WasmSessionClient.prototype.presented_rotation_json = realPresented;
    WasmSessionClient.prototype.feed_bytes = realFeed;
    fx.close();
  }
});

test("live: a CRL a candidate clone ingested is merged and persisted", async () => {
  await ensureWasm();
  const { WasmSessionClient } = await import(PKG);
  const fx = await livePair("crl-host");
  const { dir } = cliOnCopy(fx.host.stateDir, ["revoke-token", "AAAAAAAAAAAAAAAAAAAAAA"]);
  const crl = JSON.parse(fs.readFileSync(path.join(dir, "roster.json"), "utf8")).crls[fx.hostId];
  fs.rmSync(dir, { recursive: true, force: true });
  const realFeed = WasmSessionClient.prototype.feed_bytes;
  const fed = new WeakSet();
  try {
    // Stands in for a CRL frame the candidate fed into its own roster clone.
    WasmSessionClient.prototype.feed_bytes = function (bytes, now, elapsed, roster) {
      if (!fed.has(this)) {
        fed.add(this);
        roster.merge_crl_evidence(JSON.stringify([{ issuer: fx.hostId, crl }]));
      }
      return realFeed.call(this, bytes, now, elapsed, roster);
    };
    assert.equal(fx.client.getPeer(fx.hostId) !== null, true);
    const before = fx.persist.log.length;
    const session = await fx.connect();
    assert.equal(session.isEstablished(), true);
    assert.equal(fx.persist.log.length, before + 1);
    assert.equal(fx.persist.log.at(-1).crls[fx.hostId].seq, crl.seq);
    assert.equal(JSON.parse(fx.client.exportRosterJson()).crls[fx.hostId].seq, crl.seq);
    await session.close(1000, "done");
  } finally {
    WasmSessionClient.prototype.feed_bytes = realFeed;
    fx.close();
  }
});

test("live: route_seq is set before start, and a recovery URI with foreign keys fails host_key_unverified on both paths", async () => {
  await ensureWasm();
  const { WasmSessionClient } = await import(PKG);
  const fx = await livePair("seq-host");
  const { relay, fields } = fx.host;
  const realSeq = WasmSessionClient.prototype.with_route_seq;
  const realStart = WasmSessionClient.prototype.start;
  const calls = [];
  try {
    WasmSessionClient.prototype.with_route_seq = function (seq) {
      calls.push(`route_seq:${seq}`);
      return realSeq.call(this, seq);
    };
    WasmSessionClient.prototype.start = function () {
      calls.push("start");
      return realStart.call(this);
    };
    // Route metadata from a URI sends `route_seq` 0, fixed on the
    // candidate machine before `start()` and so before `msg3`.
    const session = await fx.connect();
    assert.deepEqual(calls, ["route_seq:0", "start"]);
    await session.close(1000, "done");
    await fx.host.peer.call({ op: "recv", timeout_ms: 2000 }).catch(() => {});

    // A recovery URI that names the genuine host and its mailbox but carries another identity's
    // keys: the dial reaches the genuine host, whose keys pass the pin and the final check, so
    // only the route expectation the URI sets can reject it.
    const other = await identityInfo("seq-other-host");
    const foreign = buildUri({
      host: fx.hostId,
      code: "TND-ABCD-EFGH-JKLM",
      k: other.static_pub,
      sh: other.signing_pub_hash,
      id: fx.hostId,
      rp: fields.rp,
      ep: [relay.wsUrl],
    });
    for (const explicit of [{}, { relayUrl: relay.wsUrl, targetPub: fields.rp }]) {
      const err = await fx.connect({ recoveryUri: foreign, ...explicit }).catch((e) => e);
      assert.equal(err?.code, "host_key_unverified", err?.message ?? "connect succeeded");
      await assertHostSessionClosed(fx.host.peer);
    }
  } finally {
    WasmSessionClient.prototype.with_route_seq = realSeq;
    WasmSessionClient.prototype.start = realStart;
    fx.close();
  }
});

test("live: msg3 writes and group hooks run outside the roster lock", async () => {
  await ensureWasm();
  const { WasmSessionClient } = await import(PKG);
  const anchor = await identityInfo("outside-anchor");
  let groupGate = null;
  const fx = await livePair("outside-host", {
    onPersistGroupBook: async () => {
      if (groupGate) {
        await groupGate.promise;
      }
    },
  });
  const { relay, fields, peer } = fx.host;
  const realSend = RelayStream.prototype.send;
  const realFeed = WasmSessionClient.prototype.feed_bytes;
  const realRendezvous = WasmSessionClient.prototype.apply_group_rendezvous;
  const gated = () => {
    let release;
    const promise = new Promise((r) => {
      release = r;
    });
    let entered;
    const reached = new Promise((r) => {
      entered = r;
    });
    return { promise, release, reached, entered };
  };
  try {
    // An explicit connect feeds the client roster under the lock; the first write after that
    // feed (msg3) is held open while an unrelated roster mutation must still complete.
    let fed = false;
    let held = false;
    const msg3Gate = gated();
    WasmSessionClient.prototype.feed_bytes = function (...args) {
      fed = true;
      return realFeed.apply(this, args);
    };
    RelayStream.prototype.send = async function (bytes) {
      if (fed && !held) {
        held = true;
        msg3Gate.entered();
        await msg3Gate.promise;
      }
      return realSend.call(this, bytes);
    };
    const connecting = fx.connect({ relayUrl: relay.wsUrl, targetPub: fields.rp });
    await msg3Gate.reached;
    await within(
      fx.client.addTrustAnchor("outside-1", anchor.signing_pub),
      1000,
      "a roster mutation while msg3 is written"
    );
    msg3Gate.release();
    const session = await connecting;
    RelayStream.prototype.send = realSend;

    // A group rendezvous event runs the group hook after the feed section released: a roster
    // mutation completes while the hook's group persist is held open.
    WasmSessionClient.prototype.feed_bytes = function (...args) {
      const res = JSON.parse(realFeed.apply(this, args));
      res.events = [
        ...(res.events ?? []),
        { event: "group_rendezvous_unverified", group_id: "grp_outside", seq: 1 },
      ];
      return JSON.stringify(res);
    };
    WasmSessionClient.prototype.apply_group_rendezvous = function () {
      groupGate.entered();
      return JSON.stringify({ applied: [{ group_id: "grp_outside", seq: 1 }], rejected: [] });
    };
    groupGate = gated();
    await peer.call({ op: "send", data_utf8: "group" });
    const polled = session.pollEvent(5000);
    await groupGate.reached;
    await within(
      fx.client.revokeTrustAnchor("outside-1"),
      1000,
      "a roster mutation while the group hook runs"
    );
    groupGate.release();
    const ev = await polled;
    assert.equal(ev.status, "event");
    WasmSessionClient.prototype.feed_bytes = realFeed;
    WasmSessionClient.prototype.apply_group_rendezvous = realRendezvous;
    await session.close(1000, "done");
  } finally {
    groupGate?.release();
    RelayStream.prototype.send = realSend;
    WasmSessionClient.prototype.feed_bytes = realFeed;
    WasmSessionClient.prototype.apply_group_rendezvous = realRendezvous;
    fx.close();
  }
});

test("live: a connect that changes nothing persists nothing, and a recovery-route persist failure rolls back", async () => {
  await ensureWasm();
  const fx = await livePair("noop-host");
  const { relay, fields, seedB64, peer } = fx.host;
  try {
    // A transient storage error cannot lock the client through a no-op connect.
    const before = fx.persist.log.length;
    fx.persist.fail = true;
    const session = await fx.connect();
    assert.equal(session.isEstablished(), true);
    await session.close(1000, "done");
    await peer.call({ op: "recv", timeout_ms: 2000 }).catch(() => {});
    fx.persist.fail = false;
    await fx.client.setPeerRoutes(fx.hostId, []);
    assert.equal(fx.persist.log.length, before + 1);

    // Recovery routes are a route-only change: the failed persist rolls them back.
    const newRelay = "wss://moved.example.test/v1/relay";
    const moved = buildUri({ ...fields, ep: [relay.wsUrl, newRelay], rq: 9, seedB64 });
    fx.persist.fail = true;
    await assert.rejects(
      () => fx.connect({ recoveryUri: moved }),
      /failed to persist recovery routes: disk full/
    );
    await assertHostSessionClosed(peer);
    fx.persist.fail = false;
    const view = fx.client.getPeer(fx.hostId);
    assert.equal(view.route_meta.seq, 3);
    assert.equal(
      view.routes.some((r) => r.hint === newRelay),
      false
    );
    await fx.client.setPeerRoutes(fx.hostId, []);
  } finally {
    fx.close();
  }
});

test("live: a session rolls back a route set whose persist fails, and locks the client when evidence cannot be persisted", async () => {
  await ensureWasm();
  const { WasmRoster, WasmSessionClient } = await import(PKG);
  const fx = await livePair("session-persist-host");
  const { peer } = fx.host;
  const announced = "wss://announced.example.test/v1/relay";
  const realTake = WasmSessionClient.prototype.take_route_sets;
  const realApply = WasmRoster.prototype.apply_route_announcement;
  const realFeed = WasmSessionClient.prototype.feed_bytes;
  try {
    const session = await fx.connect();
    let pending = 1;
    WasmSessionClient.prototype.take_route_sets = function () {
      realTake.call(this);
      if (pending > 0) {
        pending -= 1;
        return JSON.stringify(["AA"]);
      }
      return "[]";
    };
    // Stands in for a verified route set: a real route change in the client roster.
    WasmRoster.prototype.apply_route_announcement = function (peerId) {
      this.set_routes(peerId, JSON.stringify([announced]));
      return JSON.stringify({ outcome: "applied", added: [announced], removed: [] });
    };
    fx.persist.fail = true;
    await peer.call({ op: "send", data_utf8: "routes" });
    assert.equal((await session.pollEvent(5000)).status, "event");
    assert.deepEqual(session.lastRouteSet, { outcome: "ignored", reason: "persist_failed" });
    assert.equal(
      fx.client.peerRoutes(fx.hostId).routes.some((r) => r.hint === announced),
      false
    );
    fx.persist.fail = false;
    assert.equal(session.isEstablished(), true);
    await session.sendData("still-up");
    assert.equal((await peer.call({ op: "recv", timeout_ms: 2000 })).data_utf8, "still-up");
    await fx.client.setPeerRoutes(fx.hostId, []);

    // Revocation evidence that cannot be persisted fails the session and locks the client.
    WasmSessionClient.prototype.feed_bytes = function (...args) {
      const res = JSON.parse(realFeed.apply(this, args));
      res.events = [
        ...(res.events ?? []),
        { event: "revocation_updated", issuer: fx.hostId, seq: 1 },
      ];
      return JSON.stringify(res);
    };
    fx.persist.fail = true;
    await peer.call({ op: "send", data_utf8: "revocation" });
    await assert.rejects(
      () => session.pollEvent(5000),
      /failed to persist revocation update: disk full/
    );
    fx.persist.fail = false;
    await assert.rejects(
      () => fx.client.setPeerRoutes(fx.hostId, []),
      /client locked after roster persistence failure/
    );
  } finally {
    WasmSessionClient.prototype.take_route_sets = realTake;
    WasmRoster.prototype.apply_route_announcement = realApply;
    WasmSessionClient.prototype.feed_bytes = realFeed;
    fx.close();
  }
});

test("live: a client lock fails and closes every open session and gates group calls", async () => {
  await ensureWasm();
  const { WasmSessionClient } = await import(PKG);
  const fx = await livePair("lock-all-a");
  const sibling = await pairLiveHost(fx.client, "lock-all-b");
  const realFeed = WasmSessionClient.prototype.feed_bytes;
  const locked = /client locked after roster persistence failure: disk full/;
  const sessionLocked = /session locked after roster persistence failure: disk full/;
  try {
    const sessionB = await sibling.connect();
    const sessionA = await fx.connect();
    assert.equal(sessionB.authorize("fs.read"), true);

    // Revocation evidence on session A that cannot be persisted locks the client.
    WasmSessionClient.prototype.feed_bytes = function (...args) {
      const res = JSON.parse(realFeed.apply(this, args));
      res.events = [
        ...(res.events ?? []),
        { event: "revocation_updated", issuer: fx.hostId, seq: 1 },
      ];
      return JSON.stringify(res);
    };
    fx.persist.fail = true;
    await fx.host.peer.call({ op: "send", data_utf8: "revocation" });
    await assert.rejects(() => sessionA.pollEvent(5000), /failed to persist revocation update/);
    WasmSessionClient.prototype.feed_bytes = realFeed;
    fx.persist.fail = false;

    // The sibling session authorized against the same unpersisted roster: it fails and closes.
    assert.equal(sessionB.isClosed(), true);
    assert.throws(() => sessionB.authorize("fs.read"), sessionLocked);
    assert.throws(() => sessionB.sendData("late"), sessionLocked);
    assert.throws(() => sessionB.rekey(), sessionLocked);
    assert.throws(() => sessionB.ping(), sessionLocked);
    assert.throws(() => sessionB.pollEvent(100), sessionLocked);
    await assertHostSessionClosed(sibling.host.peer);

    assert.throws(
      () => fx.client.groupAuthorizePeer("grp_locked", sibling.hostId, "fs.read"),
      locked
    );
    assert.throws(() => fx.client.openGroup("grp_locked"), locked);
    await assert.rejects(
      () => fx.client.ingestGroupManifest("{}", { peerDeviceId: sibling.hostId }),
      locked
    );
    await assert.rejects(() => sibling.connect({}, { hostAccepts: false }), locked);
  } finally {
    WasmSessionClient.prototype.feed_bytes = realFeed;
    sibling.host.close();
    fx.close();
  }
});

test("live: a session error that changed nothing persists nothing and never locks the client", async () => {
  await ensureWasm();
  const { WasmSessionClient } = await import(PKG);
  const fx = await livePair("unchanged-host");
  const { peer } = fx.host;
  const realFeed = WasmSessionClient.prototype.feed_bytes;
  const realTick = WasmSessionClient.prototype.tick;
  try {
    const session = await fx.connect();
    const persisted = fx.persist.log.length;
    fx.persist.fail = true;
    WasmSessionClient.prototype.tick = function () {
      throw Object.assign(new Error("tick failed"), { code: "protocol_error" });
    };
    await assert.rejects(() => session.tick(), (err) => err.code === "protocol_error");
    WasmSessionClient.prototype.tick = realTick;

    WasmSessionClient.prototype.feed_bytes = function () {
      throw Object.assign(new Error("bad frame"), { code: "protocol_error" });
    };
    await peer.call({ op: "send", data_utf8: "bad" });
    await assert.rejects(() => session.pollEvent(5000), (err) => err.code === "protocol_error");
    WasmSessionClient.prototype.feed_bytes = realFeed;
    fx.persist.fail = false;

    assert.equal(fx.persist.log.length, persisted);
    await fx.client.setPeerRoutes(fx.hostId, []);
    assert.equal(fx.persist.log.length, persisted + 1);
    await session.close(1000, "done");
  } finally {
    WasmSessionClient.prototype.feed_bytes = realFeed;
    WasmSessionClient.prototype.tick = realTick;
    fx.close();
  }
});

test("live: an explicit handshake persists evidence from a feed that neither fails nor establishes", async () => {
  await ensureWasm();
  const { WasmSessionClient } = await import(PKG);
  const anchor = await identityInfo("unestablished-anchor");
  const fx = await livePair("unestablished-host");
  const { relay, fields } = fx.host;
  const realFeed = WasmSessionClient.prototype.feed_bytes;
  try {
    // Stands in for a frame whose evidence (for example a CRL) lands with a close: the roster
    // changes, and the session neither establishes nor fails on this feed.
    WasmSessionClient.prototype.feed_bytes = function (bytes, now, elapsed, roster) {
      const res = JSON.parse(realFeed.call(this, bytes, now, elapsed, roster));
      roster.add_trust_anchor("unestablished", anchor.signing_pub);
      return JSON.stringify({ ...res, established: false, write_b64: null });
    };
    const persisted = fx.persist.log.length;
    await assert.rejects(() =>
      fx.connect({ relayUrl: relay.wsUrl, targetPub: fields.rp, timeoutMs: 1500 })
    );
    const saved = fx.persist.log.slice(persisted);
    assert.equal(saved.length, 1);
    assert.ok(Object.keys(saved[0].trust_anchors ?? {}).includes("unestablished"));
  } finally {
    WasmSessionClient.prototype.feed_bytes = realFeed;
    fx.close();
  }
});

test("live: Happy Eyeballs connect wins in <1500 ms when candidate 0 stalls and closes the loser", async () => {
  await ensureWasm();
  const fx = await livePair("he-connect-host");
  const { relay } = fx.host;
  const stalledUrl = "wss://192.0.2.1/v1/relay";
  const stalledSockets = [];
  const OriginalWebSocket = globalThis.WebSocket;

  class StalledOrRealWebSocket extends EventTarget {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    constructor(url, protocols) {
      super();
      if (String(url).includes("192.0.2.1")) {
        this.url = url;
        this.readyState = StalledOrRealWebSocket.CONNECTING;
        this.closedByCaller = false;
        stalledSockets.push(this);
        return;
      }
      const real = protocols ? new OriginalWebSocket(url, protocols) : new OriginalWebSocket(url);
      return real;
    }
    send() {}
    close() {
      this.closedByCaller = true;
      if (this.readyState === StalledOrRealWebSocket.CLOSED) return;
      this.readyState = StalledOrRealWebSocket.CLOSED;
      setTimeout(() => this.dispatchEvent(new Event("close")), 0);
    }
  }
  globalThis.WebSocket = StalledOrRealWebSocket;
  try {
    await fx.client.clearPeerRoutes(fx.hostId, "signed");
    await fx.client.setPeerRoutes(fx.hostId, [stalledUrl, relay.wsUrl]);
    const t0 = performance.now();
    const session = await fx.connect({ timeoutMs: 8000 });
    const elapsedMs = performance.now() - t0;
    assert.ok(elapsedMs < 1500, `expected <1500 ms Happy Eyeballs win, got ${elapsedMs} ms`);
    assert.equal(session.isEstablished(), true);
    assert.equal(session.route.endpoint, relay.wsUrl);
    assert.equal(stalledSockets.length, 1);
    assert.equal(stalledSockets[0].closedByCaller, true);
    assert.equal(stalledSockets[0].readyState, StalledOrRealWebSocket.CLOSED);
    await session.close(1000, "done");
  } finally {
    globalThis.WebSocket = OriginalWebSocket;
    fx.close();
  }
});

test("live: Wire v1 pair uses Happy Eyeballs (<1500 ms) and commits only once when two routes race", async () => {
  await ensureWasm();
  const { WasmPairInitiator } = await import(PKG);
  const host = await liveHost("he-pair-host");
  const { relay, peer, fields, seedB64 } = host;
  const stalledUrl = "wss://192.0.2.2/v1/relay";
  const stalledSockets = [];
  const OriginalWebSocket = globalThis.WebSocket;
  class StalledOrRealWebSocket extends EventTarget {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    constructor(url, protocols) {
      super();
      if (String(url).includes("192.0.2.2")) {
        this.url = url;
        this.readyState = StalledOrRealWebSocket.CONNECTING;
        this.closedByCaller = false;
        stalledSockets.push(this);
        return;
      }
      return protocols ? new OriginalWebSocket(url, protocols) : new OriginalWebSocket(url);
    }
    send() {}
    close() {
      this.closedByCaller = true;
      if (this.readyState === StalledOrRealWebSocket.CLOSED) return;
      this.readyState = StalledOrRealWebSocket.CLOSED;
      setTimeout(() => this.dispatchEvent(new Event("close")), 0);
    }
  }
  globalThis.WebSocket = StalledOrRealWebSocket;
  const realCommit = WasmPairInitiator.prototype.commit_claim;
  let commitCount = 0;
  WasmPairInitiator.prototype.commit_claim = function (...args) {
    commitCount += 1;
    return realCommit.apply(this, args);
  };
  let persists = 0;
  const client = await TendrilWebClient.create({
    hostId: "he-pair-client",
    onPersistRoster: async () => {
      persists += 1;
    },
  });
  try {
    // 1. Stalled primary route + live relay route wins in <1500 ms and aborts loser.
    const peerPair = peer.call({ op: "pair" });
    const t0 = performance.now();
    const paired = await client.pair({
      pairingUri: buildUri({ ...fields, ep: [stalledUrl, relay.wsUrl], rq: 3, seedB64 }),
      timeoutMs: 8000,
    });
    const elapsedMs = performance.now() - t0;
    await peerPair;
    assert.ok(elapsedMs < 1500, `expected <1500 ms Happy Eyeballs pair, got ${elapsedMs} ms`);
    assert.equal(paired.route.endpoint, relay.wsUrl);
    assert.equal(commitCount, 1);
    assert.equal(persists, 1);
    assert.equal(stalledSockets.length, 1);
    assert.equal(stalledSockets[0].closedByCaller, true);

    // 2. Two live-capable routes racing: second route reaching msg2 does not call commit_claim.
    const host2 = await liveHost("he-pair-race-host");
    const client2 = await TendrilWebClient.create({ hostId: "he-pair-race-client" });
    commitCount = 0;
    try {
      const code2 = (await host2.peer.call({ op: "issue_code", kind: "remote" })).code;
      const relay2 = await (await import("./live_peer.mjs")).spawnRelay();
      await host2.peer.call({
        op: "serve_relay",
        relay_url: relay2.wsUrl,
        expected_host: "127.0.0.1",
      });
      try {
        const peerPair2 = host2.peer.call({ op: "pair" });
        const paired2 = await client2.pair({
          pairingUri: buildUri({
            ...host2.fields,
            code: code2,
            ep: [host2.relay.wsUrl, relay2.wsUrl],
            rq: 4,
            seedB64: host2.seedB64,
          }),
          timeoutMs: 8000,
        });
        await peerPair2;
        assert.equal(commitCount, 1);
        assert.equal(paired2.host_confirmed, true);
      } finally {
        relay2.child.kill();
      }
    } finally {
      client2.free();
      host2.close();
    }
  } finally {
    WasmPairInitiator.prototype.commit_claim = realCommit;
    globalThis.WebSocket = OriginalWebSocket;
    client.free();
    host.close();
  }
});

test("pairV2 stays strictly sequential and does not launch candidate 1 while candidate 0 stalls", async () => {
  await ensureWasm();
  const host = await identityInfo("seq-pairv2-host");
  const ws = installStalledWebSocket();
  const client = await TendrilWebClient.create({ hostId: "seq-pairv2-client" });
  try {
    const uri = buildUri({
      code: "TND-ABCD-EFGH-JKLM",
      k: host.static_pub,
      sh: host.signing_pub_hash,
      rp: host.relay_pub,
      ep: ["wss://stall-a.example/v1/relay", "wss://stall-b.example/v1/relay"],
    });
    const pairing = client.pairV2({ pairingUri: uri, timeoutMs: 2000 });
    await waitFor(() => ws.sockets.length === 1, "first pairV2 socket");
    await delay(400);
    assert.equal(ws.sockets.length, 1, "pairV2 must not dial second candidate concurrently");
    ws.sockets[0].fail();
    await waitFor(() => ws.sockets.length === 2, "second pairV2 socket after first fails");
    ws.sockets[1].fail();
    await assert.rejects(pairing, (err) => err.failures.length === 2);
  } finally {
    ws.restore();
    client.free();
  }
});

test("planner exhaustion populates err.failures on single-route and multi-route timeouts (including fractional timeoutMs)", async () => {
  await ensureWasm();
  const host = await identityInfo("exhaust-failures-host");
  const ws = installStalledWebSocket();
  const client = await clientWith(host);
  try {
    await client.setPeerRoutes(host.host_id, ["wss://192.0.2.10/v1/relay"]);
    await assert.rejects(
      () => client.connect({ targetHostId: host.host_id, timeoutMs: 300.5 }),
      (err) =>
        err.committed === false &&
        Array.isArray(err.failures) &&
        err.failures.length === 1 &&
        err.failures[0].hint === "wss://192.0.2.10/v1/relay" &&
        /timed out/i.test(err.failures[0].error)
    );

    await client.setPeerRoutes(host.host_id, [
      "wss://192.0.2.11/v1/relay",
      "wss://192.0.2.12/v1/relay",
    ]);
    await assert.rejects(
      () => client.connect({ targetHostId: host.host_id, timeoutMs: 450 }),
      (err) =>
        err.committed === false &&
        Array.isArray(err.failures) &&
        err.failures.length === 2 &&
        err.failures.every((f) => /timed out/i.test(f.error))
    );
  } finally {
    ws.restore();
    client.free();
  }
});

test("aborted handshake loser never leaks spurious stream-closed failure onto winning session.failures", async () => {
  await ensureWasm();
  const fx = await livePair("loser-abort-host");
  const { relay } = fx.host;
  const OriginalWebSocket = globalThis.WebSocket;
  class SlowHandshakeOrRealWebSocket extends EventTarget {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    constructor(url, protocols) {
      super();
      if (String(url).includes("192.0.2.20")) {
        this.url = url;
        this.readyState = SlowHandshakeOrRealWebSocket.CONNECTING;
        this.binaryType = "blob";
        this.closedByCaller = false;
        setTimeout(() => {
          if (this.readyState !== SlowHandshakeOrRealWebSocket.CONNECTING) return;
          this.readyState = SlowHandshakeOrRealWebSocket.OPEN;
          this.dispatchEvent(new Event("open"));
          const msg = new Event("message");
          msg.data = JSON.stringify({
            op: "challenge",
            host: "192.0.2.20",
            nonce: Buffer.alloc(32, 1).toString("base64url"),
            auth_required: [],
          });
          this.dispatchEvent(msg);
        }, 10);
        return;
      }
      return protocols ? new OriginalWebSocket(url, protocols) : new OriginalWebSocket(url);
    }
    send(data) {
      if (typeof data === "string") {
        const parsed = JSON.parse(data);
        setTimeout(() => {
          if (this.readyState !== SlowHandshakeOrRealWebSocket.OPEN) return;
          const msg = new Event("message");
          msg.data = JSON.stringify({ op: "ready", conn_id: parsed.conn_id });
          this.dispatchEvent(msg);
        }, 10);
      }
    }
    close() {
      this.closedByCaller = true;
      if (this.readyState === SlowHandshakeOrRealWebSocket.CLOSED) return;
      this.readyState = SlowHandshakeOrRealWebSocket.CLOSED;
      setTimeout(() => this.dispatchEvent(new Event("close")), 0);
    }
  }
  globalThis.WebSocket = SlowHandshakeOrRealWebSocket;
  try {
    await fx.client.clearPeerRoutes(fx.hostId, "signed");
    await fx.client.setPeerRoutes(fx.hostId, ["wss://192.0.2.20/v1/relay", relay.wsUrl]);
    const session = await fx.connect({ timeoutMs: 8000 });
    assert.equal(session.isEstablished(), true);
    assert.equal(session.route.endpoint, relay.wsUrl);
    assert.deepEqual(session.failures, []);
    await session.close(1000, "done");
  } finally {
    globalThis.WebSocket = OriginalWebSocket;
    fx.close();
  }
});

test("lowPower option, LKG route affinity, and app-data idleTimeoutMs", async () => {
  await ensureWasm();
  const fx = await livePair("web-low-power-host");
  const { relay } = fx.host;
  const deadUrl = `ws://127.0.0.1:${await deadPort()}/v1/relay`;
  const OriginalWebSocket = globalThis.WebSocket;
  const dialedUrls = [];
  let failDeadImmediately = true;

  class TrackingWebSocket extends EventTarget {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    constructor(url, protocols) {
      super();
      dialedUrls.push(String(url));
      if (String(url) === deadUrl && !failDeadImmediately) {
        this.url = url;
        this.readyState = TrackingWebSocket.CONNECTING;
        setTimeout(() => {
          if (this.readyState !== TrackingWebSocket.CONNECTING) return;
          this.readyState = TrackingWebSocket.CLOSED;
          this.dispatchEvent(new Event("error"));
          this.dispatchEvent(new Event("close"));
        }, 120);
        return;
      }
      return protocols ? new OriginalWebSocket(url, protocols) : new OriginalWebSocket(url);
    }
    send() {}
    close() {
      if (this.readyState === TrackingWebSocket.CLOSED) return;
      this.readyState = TrackingWebSocket.CLOSED;
      setTimeout(() => this.dispatchEvent(new Event("close")), 0);
    }
  }

  globalThis.WebSocket = TrackingWebSocket;
  try {
    for (const bad of [0, -10, Number.NaN, "500", 2_147_483_648]) {
      await assert.rejects(
        () => fx.client.connect({ targetHostId: fx.hostId, grantJson: fx.grantJson, idleTimeoutMs: bad }),
        RangeError
      );
    }
    for (const badMax of [-1, 1.5]) {
      await assert.rejects(
        () => fx.client.connect({ targetHostId: fx.hostId, grantJson: fx.grantJson, maxInFlight: badMax }),
        RangeError
      );
    }

    await fx.client.clearPeerRoutes(fx.hostId, "signed");
    await fx.client.setPeerRoutes(fx.hostId, [deadUrl, relay.wsUrl]);

    const first = await fx.connect({
      allowInsecureWs: true,
      lowPower: true,
      maxInFlight: 1,
      timeoutMs: 8000,
    });
    assert.equal(first.route.endpoint, relay.wsUrl);
    await first.close(1000, "first_done");

    dialedUrls.length = 0;
    failDeadImmediately = false;
    const second = await fx.connect({
      allowInsecureWs: true,
      lowPower: true,
      maxInFlight: 1,
      idleTimeoutMs: 220,
      timeoutMs: 8000,
    });
    assert.equal(dialedUrls[0], relay.wsUrl, "LKG route must be dialed first");
    await delay(120);
    assert.equal(second.isClosed(), false);
    await second.sendData("reset-idle-timer");
    await delay(140);
    assert.equal(second.isClosed(), false, "app-data sendData resets idle timer");
    for (let i = 0; i < 20 && !second.isClosed(); i += 1) {
      await delay(30);
    }
    assert.equal(second.isClosed(), true, "idle session closes after idleTimeoutMs");

    await fx.client.setPeerRoutes(fx.hostId, [deadUrl, relay.wsUrl]);
    dialedUrls.length = 0;
    const third = await fx.connect({
      allowInsecureWs: true,
      lowPower: true,
      maxInFlight: 1,
      timeoutMs: 8000,
    });
    assert.equal(dialedUrls[0], deadUrl, "setPeerRoutes clears LKG affinity");
    await third.close(1000, "third_done");
  } finally {
    globalThis.WebSocket = OriginalWebSocket;
    fx.close();
  }
});
