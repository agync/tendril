import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import tendril from "../index.js";

const { Endpoint } = tendril;

const tmpDir = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));

async function pairUnpinned(host, cli) {
  const addr = await host.serveDirect("127.0.0.1:0");
  const code = host.issueCode("lan");
  await Promise.all([host.pairAccept(5000), cli.pairInitiate(addr, code)]);
}

test("pendingHosts lists, revokes by device id and removes unconfirmed claims", async () => {
  const hostDir = tmpDir("tendril-node-pend-host-");
  const cliDir = tmpDir("tendril-node-pend-cli-");
  const host = new Endpoint(hostDir, "pend-host");
  const cli = new Endpoint(cliDir, "pend-cli");
  try {
    await pairUnpinned(host, cli);
    const claims = JSON.parse(await cli.pendingHosts());
    assert.deepEqual(
      claims.map((c) => c.host_id),
      ["pend-host"],
    );
    const deviceId = JSON.parse(host.infoJson()).device_id;
    assert.equal(claims[0].device_id, deviceId);
    assert.ok(claims[0].pairing_sas);

    // A claimed host_id is not an authenticated id.
    assert.throws(() => cli.revokePendingHost("pend-host"));
    assert.equal(JSON.parse(await cli.pendingHosts()).length, 1);

    cli.revokePendingHost(deviceId);
    assert.deepEqual(JSON.parse(await cli.pendingHosts()), []);
    assert.throws(() => cli.removePendingHost("pend-host"));
  } finally {
    host.close();
    cli.close();
  }
});

test("removePendingHost drops the claim and survives a reopen", async () => {
  const hostDir = tmpDir("tendril-node-rm-host-");
  const cliDir = tmpDir("tendril-node-rm-cli-");
  const host = new Endpoint(hostDir, "rm-host");
  const cli = new Endpoint(cliDir, "rm-cli");
  try {
    await pairUnpinned(host, cli);
    assert.equal(JSON.parse(await cli.pendingHosts()).length, 1);
    cli.removePendingHost("rm-host");
    assert.deepEqual(JSON.parse(await cli.pendingHosts()), []);
    const reopened = new Endpoint(cliDir, null);
    assert.deepEqual(JSON.parse(await reopened.pendingHosts()), []);
    reopened.close();
  } finally {
    host.close();
    cli.close();
  }
});

test("removePendingHost never touches an inbound pending device or an active entry", async () => {
  const hostDir = tmpDir("tendril-node-inb-host-");
  const cliDir = tmpDir("tendril-node-inb-cli-");
  const host = new Endpoint(hostDir, "inb-host");
  const cli = new Endpoint(cliDir, "inb-cli");
  try {
    const addr = await host.serveDirect("127.0.0.1:0");
    const code = host.issueCode("lan");
    const [accepted, paired] = await Promise.all([
      host.pairAccept(5000),
      cli.pairInitiate(addr, code),
    ]);
    const inbound = JSON.parse(accepted).device_id;
    const sas = JSON.parse(paired).sas;

    // The host holds the client as a pending device, not a claim.
    assert.throws(() => host.removePendingHost(inbound));
    host.confirmPeer(inbound, sas);

    // An active entry is no claim either.
    cli.confirmPeer("inb-host", sas);
    assert.throws(() => cli.removePendingHost("inb-host"));
  } finally {
    host.close();
    cli.close();
  }
});
