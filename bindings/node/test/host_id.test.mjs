import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import tendril from "../index.js";

const { Endpoint } = tendril;

const tmpDir = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));

test("an invalid host_id cannot be configured", () => {
  for (const bad of ["has#hash", "ctl\u0007char", "x".repeat(257)]) {
    assert.throws(() => new Endpoint(null, bad), undefined, JSON.stringify(bad));
    const state = tmpDir("tendril-node-badid-");
    assert.throws(() => new Endpoint(state, bad), undefined, JSON.stringify(bad));
    assert.equal(fs.existsSync(path.join(state, "identity.json")), false);
  }
});

test("a tampered identity file is refused", () => {
  const state = tmpDir("tendril-node-tamper-");
  new Endpoint(state, "good-host").close();
  const file = path.join(state, "identity.json");
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  doc.host_id = "has#hash";
  fs.writeFileSync(file, JSON.stringify(doc), { mode: 0o600 });
  assert.throws(() => new Endpoint(state, null));
});
