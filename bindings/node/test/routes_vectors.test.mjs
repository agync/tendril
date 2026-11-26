// Replays spec/vectors/routes.json through the Node binding.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import tendril from "../index.js";

const { Endpoint, deviceId, verifyRouteSet } = tendril;

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const VECTORS = JSON.parse(
  fs.readFileSync(path.join(ROOT, "spec", "vectors", "routes.json"), "utf8")
);

const COVERED_SECTIONS = ["pairing_route_statement", "pairing_route_check", "route_set"];
const SKIPPED_SECTIONS = {
  session_hello_route_seq:
    "SessionHello is built inside the core handshake; no binding exposes the wire JSON.",
};
// Cases whose URI names a host key the pinned vector host does not hold, so the offline apply
// path can only report that no paired host matches.
// - route_key_rotated, route_key_rotated_stale_rs: the URI carries the pre-rotation key. Pinning
//   it and following the rotation needs a RotationRecord, which no binding API or vector exposes.
// - unchained_key: a pin_ok=false / host_key_unverified handshake outcome (responder
//   "unrelated_key"); the apply path sees only a host that is not paired.
const NO_HOST_MATCH_CASES = new Set([
  "route_key_rotated",
  "route_key_rotated_stale_rs",
  "unchained_key",
]);
// Case fields the offline apply path does not model. A new field must fail the field test until
// it is covered or listed here with a reason.
const COVERED_CASE_FIELDS = ["name", "uri", "route_check"];
const HANDSHAKE_ONLY_FIELDS = {
  pin_ok: "outcome of the host key pin check in the pairing handshake",
  commit_error: "error raised when the handshake commits the pairing",
  relay_pub_ok: "rp relay key check, made by the pairing initiator against the dialed relay",
  operator_relay_key_hex: "operator relay key given to the pairing initiator",
  responder: "which identity answers the handshake in the replay",
  wires: "wire versions the handshake replay runs on",
  presented_static_pub_hex: "key material the responder presents in the handshake",
  presented_ed25519_pub_hex: "key material the responder presents in the handshake",
  presented_signing_pub_sha256_hex: "key material the responder presents in the handshake",
  presented_rotation_seq: "rotation chain length the responder presents in the handshake",
};

const SIGNING_PUB = Buffer.from(VECTORS.route_set.signing_pub_hex, "hex");

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const payloadOf = (c) => Buffer.from(c.body_hex + c.sig_hex, "hex");
const queryParam = (uri, name) => new URL(uri).searchParams.get(name);

test("every section is covered or explicitly skipped", () => {
  assert.deepEqual(
    Object.keys(VECTORS).sort(),
    [...COVERED_SECTIONS, ...Object.keys(SKIPPED_SECTIONS)].sort()
  );
  for (const reason of Object.values(SKIPPED_SECTIONS)) {
    assert.ok(reason.length > 0);
  }
  const names = new Set(VECTORS.pairing_route_check.cases.map((c) => c.name));
  for (const name of NO_HOST_MATCH_CASES) {
    assert.ok(names.has(name), name);
  }
});

test("every pairing_route_check case field is covered or handshake-only", () => {
  for (const reason of Object.values(HANDSHAKE_ONLY_FIELDS)) {
    assert.ok(reason.length > 0);
  }
  const known = new Set([...COVERED_CASE_FIELDS, ...Object.keys(HANDSHAKE_ONLY_FIELDS)]);
  for (const c of VECTORS.pairing_route_check.cases) {
    for (const key of Object.keys(c)) {
      assert.ok(known.has(key), `${c.name}: unexpected field ${key}`);
    }
  }
});

test("sign_deterministic vectors verify and decode", () => {
  const cases = VECTORS.route_set.sign_deterministic;
  assert.ok(cases.length > 0);
  for (const c of cases) {
    assert.deepEqual(
      JSON.parse(verifyRouteSet(payloadOf(c), SIGNING_PUB)),
      { seq: c.seq, issued_at: c.issued_at, routes: c.routes },
      c.name
    );
  }
});

test("a flipped signature byte fails the signature check", () => {
  for (const c of VECTORS.route_set.sign_deterministic) {
    const sigLen = c.sig_hex.length / 2;
    for (const offset of [0, 31, 32, sigLen - 1]) {
      const payload = payloadOf(c);
      payload[payload.length - sigLen + offset] ^= 0x01;
      assert.throws(() => verifyRouteSet(payload, SIGNING_PUB), /signature/, `${c.name}[${offset}]`);
    }
  }
});

test("a flipped body byte or a wrong key fails verification", () => {
  const c = VECTORS.route_set.sign_deterministic[0];
  const payload = payloadOf(c);
  payload[40] ^= 0x01;
  assert.throws(() => verifyRouteSet(payload, SIGNING_PUB), /signature/);
  const other = Buffer.from(SIGNING_PUB);
  other[40] ^= 0x01;
  assert.throws(() => verifyRouteSet(payloadOf(c), other), /signature/);
  assert.throws(() => verifyRouteSet(payloadOf(c), SIGNING_PUB.subarray(1)), /signing key/);
});

test("an appended byte fails the decode check", () => {
  for (const c of VECTORS.route_set.sign_deterministic) {
    const payload = Buffer.concat([payloadOf(c), Buffer.from([0])]);
    assert.throws(() => verifyRouteSet(payload, SIGNING_PUB), /decode/, c.name);
  }
});

test("decode_rejections fail the decode check", () => {
  const cases = VECTORS.route_set.decode_rejections;
  assert.ok(cases.length > 0);
  for (const c of cases) {
    const payload = Buffer.concat([Buffer.from(c.body_hex, "hex"), Buffer.alloc(c.zero_filler_len)]);
    assert.throws(() => verifyRouteSet(payload, SIGNING_PUB), /decode/, c.name);
  }
});

function clientWithVectorHost() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tendril-node-routes-"));
  const staticPub = Buffer.from(VECTORS.route_set.static_pub_hex, "hex");
  const hostId = deviceId(staticPub);
  // This writes roster.json by hand, coupling the test to the internal roster schema: no public
  // API pins a host from raw key material (pairing needs a live handshake).
  const roster = {
    entries: {
      [hostId]: {
        device_id: hostId,
        name: "vector-host",
        kind: "host",
        static_pub: [...staticPub],
        signing_pub: b64url(SIGNING_PUB),
        rotation_seq: 0,
        state: "active",
        min_wire_version: 1,
      },
    },
    crls: {},
  };
  fs.writeFileSync(path.join(dir, "roster.json"), JSON.stringify(roster), { mode: 0o600 });
  const client = new Endpoint(dir, "node-routes-vectors");
  const cleanup = () => {
    client.close();
    fs.rmSync(dir, { recursive: true, force: true });
  };
  return { client, hostId, cleanup };
}

async function signedRoutes(client, hostId) {
  const { routes } = JSON.parse(await client.peerRoutes(hostId));
  return routes.filter((r) => r.source === "signed").map((r) => r.hint);
}

test("pairing_route_statement applies its hints and rejects a tampered rq", async () => {
  const stmt = VECTORS.pairing_route_statement;
  const { client, hostId, cleanup } = clientWithVectorHost();
  try {
    assert.equal(b64url(Buffer.from(VECTORS.route_set.sh_hex, "hex")), queryParam(stmt.uri, "sh"));
    await assert.rejects(
      client.applyRouteUri(stmt.uri.replace("&rq=7", "&rq=8")),
      /does not verify/
    );
    assert.deepEqual(await signedRoutes(client, hostId), []);
    assert.deepEqual(JSON.parse(await client.applyRouteUri(stmt.uri)), {
      peer_id: hostId,
      applied: true,
      reason: null,
      route_seq: stmt.route_seq,
    });
    assert.deepEqual(await signedRoutes(client, hostId), stmt.hints);
  } finally {
    cleanup();
  }
});

test("pairing_route_check route_check outcomes", async () => {
  const hostK = b64url(Buffer.from(VECTORS.route_set.static_pub_hex, "hex"));
  for (const c of VECTORS.pairing_route_check.cases) {
    const { client, hostId, cleanup } = clientWithVectorHost();
    try {
      const uriK = queryParam(c.uri, "k");
      if (NO_HOST_MATCH_CASES.has(c.name)) {
        assert.notEqual(uriK, hostK, c.name);
        await assert.rejects(client.applyRouteUri(c.uri), /no paired host matches/, c.name);
        continue;
      }
      assert.equal(uriK, hostK, c.name);
      if (c.route_check === "verified") {
        assert.equal(JSON.parse(await client.applyRouteUri(c.uri)).applied, true, c.name);
        assert.ok((await signedRoutes(client, hostId)).length > 0, c.name);
      } else if (c.route_check === "unsigned") {
        await assert.rejects(client.applyRouteUri(c.uri), /not host-signed/, c.name);
      } else {
        assert.equal(c.route_check, "invalid", c.name);
        await assert.rejects(client.applyRouteUri(c.uri), /does not verify/, c.name);
      }
    } finally {
      cleanup();
    }
  }
});
