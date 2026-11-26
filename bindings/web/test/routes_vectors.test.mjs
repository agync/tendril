// Replays spec/vectors/routes.json through the browser WASM build.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { initTendril, parsePairingUri } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH = path.resolve(__dirname, "..", "pkg", "tendril_wasm_bg.wasm");
const ROOT = path.resolve(__dirname, "..", "..", "..");
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
const DECODE_ERROR = /^invalid inner transport frame payload: route set$/;
const HOST_ID = "dev_vector_host";

let wasmReady = false;
async function ensureWasm() {
  if (!wasmReady) {
    await initTendril({ module_or_path: fs.readFileSync(WASM_PATH) });
    wasmReady = true;
  }
}

const b64url = (hex) => Buffer.from(hex, "hex").toString("base64url");
const queryParam = (uri, name) => new URL(uri).searchParams.get(name);
const message = (err) => String(err?.message ?? err);

async function rosterWithVectorHost(signingPubHex = VECTORS.route_set.signing_pub_hex) {
  const { WasmRoster } = await import("../pkg/tendril_wasm.js");
  const roster = new WasmRoster();
  const keys = VECTORS.route_set;
  roster.insert_pinned_host(
    HOST_ID,
    "vector-host",
    b64url(keys.static_pub_hex),
    b64url(signingPubHex),
    0,
    null
  );
  return roster;
}

function throwsMatching(fn, pattern, label) {
  assert.throws(fn, (err) => pattern.test(message(err)), label);
}

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

test("sign_deterministic vectors decode, verify and apply to a pinned host", async () => {
  await ensureWasm();
  const cases = VECTORS.route_set.sign_deterministic;
  assert.ok(cases.length > 0);
  for (const c of cases) {
    const roster = await rosterWithVectorHost();
    try {
      const res = JSON.parse(
        roster.apply_route_announcement(
          HOST_ID,
          Buffer.from(c.body_hex + c.sig_hex, "hex"),
          c.issued_at
        )
      );
      assert.equal(res.outcome, "applied", c.name);
      assert.deepEqual(res.added, c.routes, c.name);
      assert.deepEqual(res.removed, [], c.name);
      const entry = JSON.parse(Buffer.from(roster.to_json_bytes()).toString("utf8")).entries[HOST_ID];
      assert.deepEqual(
        (entry.routes ?? []).filter((r) => r.source === "signed").map((r) => r.hint),
        c.routes,
        c.name
      );
      assert.equal(entry.route_meta.seq, c.seq, c.name);
      assert.equal(entry.route_meta.issued_at, c.issued_at, c.name);
    } finally {
      roster.free();
    }
  }
});

test("a flipped signature byte is ignored as a bad signature", async () => {
  await ensureWasm();
  for (const c of VECTORS.route_set.sign_deterministic) {
    const sigLen = c.sig_hex.length / 2;
    for (const offset of [0, 31, 32, sigLen - 1]) {
      const payload = Buffer.from(c.body_hex + c.sig_hex, "hex");
      payload[payload.length - sigLen + offset] ^= 0x01;
      const roster = await rosterWithVectorHost();
      try {
        const res = JSON.parse(roster.apply_route_announcement(HOST_ID, payload, c.issued_at));
        assert.deepEqual(res, { outcome: "ignored", reason: "bad_signature" }, `${c.name}[${offset}]`);
      } finally {
        roster.free();
      }
    }
  }
});

test("a flipped body byte or a wrong pinned key is ignored as a bad signature", async () => {
  await ensureWasm();
  const c = VECTORS.route_set.sign_deterministic[0];
  const body = Buffer.from(c.body_hex + c.sig_hex, "hex");
  body[80] ^= 0x01; // low byte of issued_at, past the key-binding fields
  const wrongKey = Buffer.from(VECTORS.route_set.signing_pub_hex, "hex");
  wrongKey[40] ^= 0x01;
  const cases = [
    [body, VECTORS.route_set.signing_pub_hex, "bad_signature"],
    [Buffer.from(c.body_hex + c.sig_hex, "hex"), wrongKey.toString("hex"), "key_mismatch"],
  ];
  for (const [payload, pubHex, reason] of cases) {
    const roster = await rosterWithVectorHost(pubHex);
    try {
      const res = JSON.parse(roster.apply_route_announcement(HOST_ID, payload, c.issued_at));
      assert.equal(res.outcome, "ignored");
      assert.equal(res.reason, reason);
    } finally {
      roster.free();
    }
  }
});

test("an appended byte fails to decode", async () => {
  await ensureWasm();
  for (const c of VECTORS.route_set.sign_deterministic) {
    const payload = Buffer.concat([Buffer.from(c.body_hex + c.sig_hex, "hex"), Buffer.from([0])]);
    const roster = await rosterWithVectorHost();
    try {
      throwsMatching(
        () => roster.apply_route_announcement(HOST_ID, payload, c.issued_at),
        DECODE_ERROR,
        c.name
      );
    } finally {
      roster.free();
    }
  }
});

test("decode_rejections fail to decode", async () => {
  await ensureWasm();
  const cases = VECTORS.route_set.decode_rejections;
  assert.ok(cases.length > 0);
  for (const c of cases) {
    const payload = Buffer.concat([Buffer.from(c.body_hex, "hex"), Buffer.alloc(c.zero_filler_len)]);
    const roster = await rosterWithVectorHost();
    try {
      throwsMatching(
        () => roster.apply_route_announcement(HOST_ID, payload, 1795564800),
        DECODE_ERROR,
        c.name
      );
    } finally {
      roster.free();
    }
  }
});

test("pairing_route_statement parses as signed and applies its hints", async () => {
  await ensureWasm();
  const stmt = VECTORS.pairing_route_statement;
  const parsed = parsePairingUri(stmt.uri);
  assert.equal(parsed.route_seq, stmt.route_seq);
  assert.equal(parsed.route_signed, true);
  assert.equal(b64url(VECTORS.route_set.sh_hex), queryParam(stmt.uri, "sh"));

  const roster = await rosterWithVectorHost();
  try {
    throwsMatching(
      () => roster.apply_signed_route_uri(stmt.uri.replace("&rq=7", "&rq=8")),
      /does not verify/,
      "tampered rq"
    );
    const applied = JSON.parse(roster.apply_signed_route_uri(stmt.uri));
    assert.equal(applied.applied, true);
    assert.equal(applied.peer_id, HOST_ID);
    assert.deepEqual(
      applied.routes.filter((r) => r.source === "signed").map((r) => r.hint),
      stmt.hints
    );
  } finally {
    roster.free();
  }
});

test("pairing_route_check route_check outcomes", async () => {
  await ensureWasm();
  const hostK = b64url(VECTORS.route_set.static_pub_hex);
  for (const c of VECTORS.pairing_route_check.cases) {
    const roster = await rosterWithVectorHost();
    try {
      const uriK = queryParam(c.uri, "k");
      if (NO_HOST_MATCH_CASES.has(c.name)) {
        assert.notEqual(uriK, hostK, c.name);
        throwsMatching(() => roster.apply_signed_route_uri(c.uri), /no paired host matches/, c.name);
        continue;
      }
      assert.equal(uriK, hostK, c.name);
      if (c.route_check === "verified") {
        const applied = JSON.parse(roster.apply_signed_route_uri(c.uri));
        assert.equal(applied.applied, true, c.name);
        assert.ok(applied.routes.some((r) => r.source === "signed"), c.name);
        const entry = JSON.parse(Buffer.from(roster.to_json_bytes()).toString("utf8")).entries[HOST_ID];
        assert.ok(entry.routes.some((r) => r.source === "signed"), c.name);
      } else if (c.route_check === "unsigned") {
        throwsMatching(() => roster.apply_signed_route_uri(c.uri), /not host-signed/, c.name);
      } else {
        assert.equal(c.route_check, "invalid", c.name);
        throwsMatching(() => roster.apply_signed_route_uri(c.uri), /does not verify/, c.name);
      }
    } finally {
      roster.free();
    }
  }
});
