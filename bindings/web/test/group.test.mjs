import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { TendrilWebClient, TendrilWebGroup, b64urlDecode, b64urlEncode, initTendril } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH = path.join(__dirname, "..", "pkg", "tendril_wasm_bg.wasm");
const FX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "group.json"), "utf8"));
const GID = FX.group_id;
const { a: PEER_A, b: PEER_B, c: PEER_C } = FX.peers;
const SEND = `group.send:${GID}`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function ensureWasm() {
  await initTendril({ module_or_path: fs.readFileSync(WASM_PATH) });
}

/** Pins the clock inside the fixture manifest validity window for the duration of `fn`. */
async function atFixtureTime(fn) {
  const realNow = Date.now;
  Date.now = () => FX.now * 1000;
  try {
    return await fn();
  } finally {
    Date.now = realNow;
  }
}

class MockSession {
  constructor(peerDeviceId, { sendDelayMs = 0, sendError = null, hang = false } = {}) {
    this.peerDeviceId = peerDeviceId;
    this.sent = [];
    this.inbound = [];
    this.closed = false;
    this.inFlight = 0;
    this.maxInFlight = 0;
    this.sendDelayMs = sendDelayMs;
    this.sendError = sendError;
    this.hang = hang;
  }

  isClosed() {
    return this.closed;
  }

  async sendData(bytes) {
    this.inFlight += 1;
    this.maxInFlight = Math.max(this.maxInFlight, this.inFlight);
    try {
      if (this.hang) {
        await new Promise(() => {});
      }
      if (this.sendDelayMs) {
        await sleep(this.sendDelayMs);
      }
      if (this.sendError) {
        throw new Error(this.sendError);
      }
      this.sent.push(Buffer.from(bytes).toString("utf8"));
    } finally {
      this.inFlight -= 1;
    }
  }

  async pollEvent(timeoutMs) {
    if (this.inbound.length > 0) {
      return { status: "event", ...this.inbound.shift() };
    }
    if (this.closed) {
      return { status: "eof" };
    }
    await sleep(Math.min(timeoutMs, 10));
    return { status: "would_block" };
  }
}

async function newClient(extra = {}) {
  await ensureWasm();
  return TendrilWebClient.create({
    identityJson: FX.local.identity_json,
    rosterJson: FX.roster_json,
    ...extra,
  });
}

async function clientWithGroup(extra = {}) {
  const client = await newClient(extra);
  await client.ingestGroupManifest(FX.manifest, new MockSession(FX.root_device_id));
  return client;
}

async function drain(group, n) {
  const out = [];
  for (let i = 0; i < n; i += 1) {
    const ev = await group.pollEvent(500);
    assert.ok(ev, `expected event ${i + 1} of ${n}`);
    out.push(ev);
  }
  return out;
}

test("group: manifest from the signer peer pins the group and WASM answers membership", async () => {
  await atFixtureTime(async () => {
    const saved = [];
    const client = await newClient({
      onPersistGroupBookBytes: async (bytes) => saved.push(Uint8Array.from(bytes)),
    });
    try {
      assert.deepEqual(client.groupIds(), []);
      const out = await client.ingestGroupManifest(FX.manifest, new MockSession(FX.root_device_id));
      assert.equal(out.status, "created");
      assert.equal(out.group_id, GID);
      assert.deepEqual(client.groupIds(), [GID]);
      assert.equal(saved.length, 1);

      const view = client.groupMembers(GID);
      assert.equal(view.members.length, 5);
      assert.equal(client.groupAuthorizePeer(GID, PEER_A, SEND), true);
      assert.equal(client.groupAuthorizePeer(GID, PEER_B, SEND), true);
      assert.throws(() => client.groupAuthorizePeer(GID, PEER_B, `group.recv:${GID}`), /authorization denied/);
      assert.throws(() => client.groupAuthorizePeer(GID, PEER_C, SEND), /authorization denied/);
      assert.throws(() => client.groupAuthorizePeer(GID, PEER_A, "group.send:grp_other"), /./);
      assert.throws(() => client.groupAuthorizePeer(GID, "dev_unknown", SEND), /not a member/);

      const restored = await newClient({ groupBookBytes: Uint8Array.from(saved[0]) });
      try {
        assert.deepEqual(restored.groupIds(), [GID]);
        assert.equal(restored.groupAuthorizePeer(GID, PEER_A, SEND), true);
      } finally {
        restored.free();
      }
    } finally {
      client.free();
    }
  });
});

test("group: first contact from a non-signer, an unpaired signer, or an unrelated root never pins", async () => {
  await atFixtureTime(async () => {
    const client = await newClient();
    try {
      await assert.rejects(
        () => client.ingestGroupManifest(FX.manifest, new MockSession(PEER_A)),
        /manifest signer/
      );
      await assert.rejects(
        () => client.ingestGroupManifest(FX.stranger_manifest, new MockSession(FX.root_device_id)),
        /manifest signer/
      );
      await assert.rejects(
        () => client.ingestGroupManifest(FX.stranger_manifest, new MockSession(FX.stranger_root_device_id)),
        /not an active paired peer/
      );
      await assert.rejects(() => client.ingestGroupManifest(FX.manifest, {}), /authenticated session/);
      const tampered = structuredClone(FX.manifest);
      tampered.members[1].caps.push("group.admin");
      await assert.rejects(() => client.ingestGroupManifest(tampered, new MockSession(FX.root_device_id)));
      assert.deepEqual(client.groupIds(), []);
      assert.throws(() => client.openGroup(GID), /not found/);
    } finally {
      client.free();
    }
  });
});

test("group: persistence failure rolls the group book back", async () => {
  await atFixtureTime(async () => {
    let fail = true;
    const client = await newClient({
      onPersistGroupBookBytes: async () => {
        if (fail) {
          throw new Error("disk full");
        }
      },
    });
    try {
      await assert.rejects(
        () => client.ingestGroupManifest(FX.manifest, new MockSession(FX.root_device_id)),
        /disk full/
      );
      assert.deepEqual(client.groupIds(), []);
      fail = false;
      await client.ingestGroupManifest(FX.manifest, new MockSession(FX.root_device_id));
      assert.deepEqual(client.groupIds(), [GID]);
    } finally {
      client.free();
    }
  });
});

test("group: overlapping mutations are serialized and a failed persist keeps the later revocation", async () => {
  await atFixtureTime(async () => {
    let calls = 0;
    let releaseFirst;
    const firstGate = new Promise((r) => {
      releaseFirst = r;
    });
    const saved = [];
    const client = await newClient({
      onPersistGroupBookBytes: async (bytes) => {
        calls += 1;
        if (calls === 1) {
          await firstGate;
          throw new Error("disk full");
        }
        saved.push(Uint8Array.from(bytes));
      },
    });
    try {
      const root = new MockSession(FX.root_device_id);
      const first = client.ingestGroupManifest(FX.manifest, root);
      const second = client.ingestGroupManifest(FX.manifest_revoke_a, root);
      await sleep(20);
      assert.equal(calls, 1);
      releaseFirst();
      await assert.rejects(() => first, /disk full/);
      const out = await second;
      assert.equal(calls, 2);
      assert.notEqual(out.status, "rejected");
      assert.equal(saved.length, 1);
      assert.deepEqual(client.groupIds(), [GID]);
      assert.throws(() => client.groupAuthorizePeer(GID, PEER_A, SEND), /revoked/);
      const restored = await newClient({ groupBookBytes: Uint8Array.from(saved[0]) });
      try {
        assert.throws(() => restored.groupAuthorizePeer(GID, PEER_A, SEND), /revoked/);
      } finally {
        restored.free();
      }
    } finally {
      client.free();
    }
  });
});

test("group: broadcast asks WASM for recipients and isolates offline and failing peers", async () => {
  await atFixtureTime(async () => {
    const client = await clientWithGroup();
    const group = client.openGroup(GID, { sendTimeoutMs: 80 });
    try {
      const a = new MockSession(PEER_A);
      group.attach(a);
      let report = await group.broadcast("hello");
      // Recipients are exactly the active members holding group.recv; b has only group.send.
      assert.deepEqual(report, { delivered: [PEER_A], offline: [PEER_C], failed: [] });
      assert.deepEqual(a.sent, ["hello"]);

      const c = new MockSession(PEER_C, { sendError: "link reset" });
      group.attach(c);
      report = await group.broadcast(new TextEncoder().encode("again"));
      assert.deepEqual(report.delivered, [PEER_A]);
      assert.deepEqual(report.failed, [[PEER_C, "link reset"]]);

      const stuck = new MockSession(PEER_C, { hang: true });
      group.attach(stuck);
      report = await group.broadcast("x");
      assert.deepEqual(report.failed, [[PEER_C, "send timed out"]]);
      // A timed-out peer is dropped from the pool and reported offline until re-attached.
      report = await group.broadcast("y");
      assert.deepEqual(report.offline, [PEER_C]);

      await assert.rejects(() => group.broadcast("z", `group.admin:${GID}`), /not a group admin/);
      await assert.rejects(() => group.broadcast(new Uint8Array(65_500)), RangeError);
      await assert.rejects(() => group.broadcast(42), TypeError);
    } finally {
      group.close();
      client.free();
    }
  });
});

test("group: broadcast concurrency is bounded and closed sessions count as offline", async () => {
  await atFixtureTime(async () => {
    const client = await clientWithGroup();
    try {
      for (const [limit, expected] of [
        [1, 1],
        [2, 2],
      ]) {
        const group = client.openGroup(GID, { concurrency: limit });
        const sessions = [
          new MockSession(PEER_A, { sendDelayMs: 30 }),
          new MockSession(PEER_C, { sendDelayMs: 30 }),
        ];
        let live = 0;
        let peak = 0;
        for (const s of sessions) {
          const send = s.sendData.bind(s);
          s.sendData = async (bytes) => {
            live += 1;
            peak = Math.max(peak, live);
            try {
              return await send(bytes);
            } finally {
              live -= 1;
            }
          };
          group.attach(s);
        }
        const report = await group.broadcast("go");
        assert.equal(report.delivered.length, 2);
        assert.equal(peak, expected);
        sessions[0].closed = true;
        const after = await group.broadcast("go");
        assert.deepEqual(after.offline, [PEER_A]);
        group.close();
      }
    } finally {
      client.free();
    }
  });
});

test("group: sessionFor supplies sessions lazily and must match the authenticated peer", async () => {
  await atFixtureTime(async () => {
    const client = await clientWithGroup();
    const dialed = [];
    const sessions = new Map([
      [PEER_A, new MockSession(PEER_A)],
      [PEER_C, new MockSession(PEER_A)],
    ]);
    const group = client.openGroup(GID, {
      sessionFor: async (peerId) => {
        dialed.push(peerId);
        return sessions.get(peerId) ?? null;
      },
    });
    try {
      const report = await group.broadcast("lazy");
      assert.deepEqual(dialed, [PEER_A, PEER_C]);
      assert.deepEqual(report.delivered, [PEER_A]);
      assert.equal(report.failed.length, 1);
      assert.match(report.failed[0][1], /not authenticated as the requested peer/);
    } finally {
      group.close();
      client.free();
    }
  });
});

test("group: inbound data is delivered only after WASM authorizes the sender", async () => {
  await atFixtureTime(async () => {
    const client = await clientWithGroup();
    const group = client.openGroup(GID);
    try {
      const a = new MockSession(PEER_A);
      const c = new MockSession(PEER_C);
      group.attach(a);
      group.attach(c);
      const payload = b64urlEncode(new TextEncoder().encode("ping"));
      c.inbound.push({ event: "data", data_b64: payload });
      a.inbound.push({ event: "data", data_b64: payload });

      const events = await drain(group, 2);
      const data = events.find((e) => e.event === "app_data");
      const audit = events.find((e) => e.event === "audit");
      assert.deepEqual(data, { event: "app_data", sender_device_id: PEER_A, payload_b64: payload });
      assert.equal(new TextDecoder().decode(b64urlDecode(data.payload_b64)), "ping");
      assert.equal(audit.audit.subject, PEER_C);
      assert.equal(audit.audit.cap, SEND);
      assert.equal(audit.audit.allow, false);
      assert.equal(await group.pollEvent(30), null);
    } finally {
      group.close();
      client.free();
    }
  });
});

test("group: a newer manifest revokes a member, emits events, and removes it from fan-out", async () => {
  await atFixtureTime(async () => {
    const client = await clientWithGroup();
    const group = client.openGroup(GID);
    try {
      const a = new MockSession(PEER_A);
      const c = new MockSession(PEER_C);
      group.attach(a);
      group.attach(c);
      const seen = [];
      group.on("member_revoked", (ev) => seen.push(ev));

      // Second-hand delivery on a non-signer session: allowed for a known group, verified by core.
      c.inbound.push({
        event: "group_manifest_unverified",
        group_id: GID,
        seq: FX.manifest_revoke_a.seq,
        manifest_json: JSON.stringify(FX.manifest_revoke_a),
      });
      const events = await drain(group, 2);
      assert.deepEqual(events[0], { event: "manifest_updated", seq: FX.manifest_revoke_a.seq });
      assert.deepEqual(events[1], { event: "member_revoked", device_id: PEER_A });
      assert.deepEqual(seen, [{ event: "member_revoked", device_id: PEER_A }]);

      assert.throws(() => group.authorizePeer(PEER_A, SEND), /revoked/);
      const report = await group.broadcast("after");
      assert.deepEqual(report.delivered, [PEER_C]);
      assert.deepEqual(a.sent, []);

      // Data from the revoked peer is refused even if its session is still open.
      await group.handleSessionEvent(a, { event: "data", data_b64: "AA" });
      const refused = await group.pollEvent(500);
      assert.equal(refused.event, "audit");
      assert.equal(refused.audit.subject, PEER_A);

      // A rollback to the old manifest is refused and surfaces as an audit event.
      await group.handleSessionEvent(c, {
        event: "group_manifest_unverified",
        group_id: GID,
        manifest_json: JSON.stringify(FX.manifest),
      });
      const rollback = await group.pollEvent(500);
      assert.equal(rollback.event, "audit");
      assert.equal(rollback.audit.cap, "group.manifest");
    } finally {
      group.close();
      client.free();
    }
  });
});

test("group: events for other groups are ignored and close is idempotent", async () => {
  await atFixtureTime(async () => {
    const client = await clientWithGroup();
    const group = client.openGroup(GID);
    const c = new MockSession(PEER_C);
    group.attach(c);
    await group.handleSessionEvent(c, {
      event: "group_manifest_unverified",
      group_id: "grp_other",
      manifest_json: JSON.stringify(FX.stranger_manifest),
    });
    assert.equal(await group.pollEvent(30), null);
    assert.deepEqual(client.groupIds(), [GID]);

    const waiting = group.pollEvent(2000);
    group.close();
    group.close();
    assert.equal(await waiting, null);
    assert.equal(group.isClosed(), true);
    assert.equal(await group.pollEvent(10), null);
    await assert.rejects(() => group.broadcast("late"), /closed/);
    assert.throws(() => group.members(), /closed/);
    assert.throws(() => new TendrilWebGroup(Symbol("x"), GID, {}), /openGroup/);
    client.free();
  });
});

test("group: openGroup requires an active local membership and freeing the client closes groups", async () => {
  await atFixtureTime(async () => {
    const client = await clientWithGroup();
    const group = client.openGroup(GID);
    client.free();
    assert.equal(group.isClosed(), true);

    const other = await newClient({ identityJson: null });
    try {
      assert.throws(() => other.openGroup(GID), /not found/);
    } finally {
      other.free();
    }
  });
});

test("group: local revoked by a manifest drops inbound data, closes sessions, and refuses broadcast", async () => {
  await atFixtureTime(async () => {
    const client = await clientWithGroup();
    const group = client.openGroup(GID);
    try {
      const a = new MockSession(PEER_A);
      const c = new MockSession(PEER_C);
      group.attach(a);
      group.attach(c);
      const seen = [];
      group.on("member_revoked", (ev) => seen.push(ev));

      await client.ingestGroupManifest(FX.manifest_revoke_local, new MockSession(FX.root_device_id));
      const events = await drain(group, 2);
      assert.deepEqual(events[0], { event: "manifest_updated", seq: FX.manifest_revoke_local.seq });
      assert.deepEqual(events[1], { event: "member_revoked", device_id: FX.local.device_id });
      assert.deepEqual(seen, [{ event: "member_revoked", device_id: FX.local.device_id }]);

      const payload = b64urlEncode(new TextEncoder().encode("late"));
      await group.handleSessionEvent(a, { event: "data", data_b64: payload });
      a.inbound.push({ event: "data", data_b64: payload });
      await sleep(60);
      assert.equal(await group.pollEvent(30), null);

      await assert.rejects(() => group.broadcast("after"), /no longer an active member/);
      assert.deepEqual(a.sent, []);
      assert.deepEqual(c.sent, []);
      assert.throws(() => client.openGroup(GID), /not an active member/);
    } finally {
      group.close();
      client.free();
    }
  });
});

test("group: openGroup refuses a local device revoked by the root CRL", async () => {
  await atFixtureTime(async () => {
    const seed = await clientWithGroup();
    const bookJson = seed.exportGroupBookJson();
    seed.free();
    const client = await newClient({ rosterJson: FX.roster_local_crl_json, groupBookJson: bookJson });
    try {
      assert.throws(() => client.openGroup(GID), /revoked/);
    } finally {
      client.free();
    }
  });
});

test("group: a CRL revoking the local device after open detaches everything on the next inbound or send", async () => {
  await atFixtureTime(async () => {
    let revoked = false;
    const backend = {
      members: () => ({}),
      authorize: () => {},
      authorizeInbound: () => {
        if (revoked) {
          throw new Error("revoked");
        }
      },
      checkLocal: () => {
        if (revoked) {
          throw new Error("revoked");
        }
      },
      localDeviceId: () => "dev_local",
      targets: () => [PEER_A],
      canSend: () => {},
      ingestManifest: async () => {},
    };
    const group = TendrilWebGroup._create(GID, backend, { pumpPollMs: 20 }, null);
    try {
      const a = new MockSession(PEER_A);
      group.attach(a);
      const payload = b64urlEncode(new TextEncoder().encode("ok"));
      a.inbound.push({ event: "data", data_b64: payload });
      assert.equal((await group.pollEvent(500)).event, "app_data");

      revoked = true;
      a.inbound.push({ event: "data", data_b64: payload });
      const ev = await group.pollEvent(500);
      assert.deepEqual(ev, { event: "member_revoked", device_id: "dev_local" });
      assert.equal(await group.pollEvent(60), null);
      await assert.rejects(() => group.broadcast("x"), /no longer an active member/);
      assert.deepEqual(a.sent, []);
    } finally {
      group.close();
    }
  });
});
