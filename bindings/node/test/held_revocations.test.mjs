// Revocations survive commits, reloads and restarts through the Node binding.
//
// A memory-only revocation (one a live session learned and the store lacks) needs a session
// that forks a rotation chain or receives a revocation frame, which the public API cannot
// produce. These tests are regression guards for the roster handle every path now shares: they
// pass on a binding without the shared fold too, and the runtime and FFI tests carry the red
// cases (crates/tendril-runtime/tests/held_revocations.rs).

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import tendril from "../index.js";

const { Endpoint } = tendril;

function b64urlDecode(text) {
  return Buffer.from(text.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function signingPubOf(ep) {
  return b64urlDecode(JSON.parse(ep.infoJson()).signing_pub);
}

function readRoster(stateDir) {
  return JSON.parse(fs.readFileSync(path.join(stateDir, "roster.json"), "utf8"));
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

async function pairV2(host, cli, hostAddr, hostId) {
  const code = host.issueCode("lan");
  const [accepted, cliRaw] = await Promise.all([
    host.pairV2Accept(8000),
    cli.pairV2Initiate(hostAddr, code, null, "held-cli", "node", null),
  ]);
  const devId = JSON.parse(accepted).device_id;
  const sas = JSON.parse(cliRaw).sas;
  host.confirmPeer(devId, sas);
  cli.confirmPeer(hostId, sas);
  return devId;
}

test("a stale handle and a restart never unrevoke a peer or an anchor", async () => {
  const hostDir = tmpDir("tendril-node-held-host-");
  const cliDir = tmpDir("tendril-node-held-cli-");
  const host = new Endpoint(hostDir, "held-host");
  const cli = new Endpoint(cliDir, "held-cli");
  const anchor = new Endpoint(null, "held-anchor");
  const other = new Endpoint(null, "held-other");
  // Loaded before any revocation: its copy of the roster is stale.
  const stale = new Endpoint(hostDir, null);
  try {
    const hostAddr = await host.serveDirect("127.0.0.1:0");
    const devId = await pairV2(host, cli, hostAddr, "held-host");
    host.addTrustAnchor("held-anchor", signingPubOf(anchor));
    host.revokePeer(devId);
    host.revokeTrustAnchor("held-anchor");

    stale.addTrustAnchor("held-other", signingPubOf(other));

    const disk = readRoster(hostDir);
    assert.equal(disk.entries[devId].state, "revoked");
    assert.equal(disk.trust_anchors["held-anchor"].state, "revoked");
    assert.equal(disk.trust_anchors["held-other"].state, "active");

    host.close();
    const reopened = new Endpoint(hostDir, null);
    try {
      assert.throws(() => reopened.mintGrant(devId, ["fs.read"], 60));
      assert.throws(() => reopened.addTrustAnchor("held-anchor", signingPubOf(anchor)));
    } finally {
      reopened.close();
    }
  } finally {
    host.close();
    cli.close();
    anchor.close();
    other.close();
    stale.close();
    fs.rmSync(hostDir, { recursive: true, force: true });
    fs.rmSync(cliDir, { recursive: true, force: true });
  }
});

test("a policy connect refuses a host revoked on disk", async () => {
  const hostDir = tmpDir("tendril-node-held-host-");
  const cliDir = tmpDir("tendril-node-held-cli-");
  const host = new Endpoint(hostDir, "held-host");
  const cli = new Endpoint(cliDir, "held-cli");
  try {
    const hostAddr = await host.serveDirect("127.0.0.1:0");
    const devId = await pairV2(host, cli, hostAddr, "held-host");
    const grant = host.mintGrant(devId, ["fs.read"], 3600);
    cli.revokePeer("held-host");

    await assert.rejects(cli.connectV2(hostAddr, "held-host", grant, null));
    assert.equal(readRoster(cliDir).entries["held-host"].state, "revoked");
  } finally {
    host.close();
    cli.close();
    fs.rmSync(hostDir, { recursive: true, force: true });
    fs.rmSync(cliDir, { recursive: true, force: true });
  }
});
