import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import test from "node:test";
import { fileURLToPath } from "node:url";

import tendril from "../index.js";

const { Endpoint } = tendril;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..", "..");
const TENDRIL_BIN = path.join(ROOT, "target", "debug", "tendril");

function ensureTendrilBin() {
  if (!fs.existsSync(TENDRIL_BIN)) {
    const res = spawnSync("cargo", ["build", "-p", "tendril-cli", "--bin", "tendril"], {
      cwd: ROOT,
      stdio: "inherit",
    });
    assert.equal(res.status, 0, "failed to build tendril");
  }
}

function runCli(stateDir, ...args) {
  const res = spawnSync(TENDRIL_BIN, ["--state-dir", stateDir, ...args], {
    cwd: ROOT,
    encoding: "utf8",
  });
  assert.equal(res.status, 0, `tendril ${args.join(" ")} failed: ${res.stderr}`);
  const lines = res.stdout.trim().split(/\r?\n/).filter(Boolean);
  return JSON.parse(lines[lines.length - 1]);
}

function startCliServe(stateDir, issueCode = false) {
  const args = ["--state-dir", stateDir, "serve", "--listen", "127.0.0.1:0"];
  if (issueCode) {
    args.push("--issue-code", "lan");
  }
  const child = spawn(TENDRIL_BIN, args, {
    cwd: ROOT,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return new Promise((resolve, reject) => {
    const rl = readline.createInterface({ input: child.stdout });
    let stderr = "";
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });
    const timer = setTimeout(() => {
      rl.close();
      child.kill();
      reject(new Error(`tendril serve timed out: ${stderr}`));
    }, 10000);
    rl.on("line", (line) => {
      if (!line.trim()) return;
      const ev = JSON.parse(line);
      if (ev.event === "listening") {
        clearTimeout(timer);
        rl.close();
        resolve({ child, ev });
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      rl.close();
      reject(new Error(`tendril serve exited (${code}): ${stderr}`));
    });
  });
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  await new Promise((resolve) => {
    child.once("exit", resolve);
    child.kill("SIGTERM");
    setTimeout(() => {
      if (child.exitCode === null) child.kill("SIGKILL");
    }, 3000);
  });
}

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

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function pairV2(host, cli, hostAddr, hostId) {
  const code = host.issueCode("lan");
  const [accepted, cliRaw] = await Promise.all([
    host.pairV2Accept(8000),
    cli.pairV2Initiate(hostAddr, code, null, "node-cli", "node", null),
  ]);
  const devId = JSON.parse(accepted).device_id;
  const sas = JSON.parse(cliRaw).sas;
  host.confirmPeer(devId, sas);
  cli.confirmPeer(hostId, sas);
  return devId;
}

async function openV2Session(host, cli, hostAddr, hostId, grant) {
  const [hostSess, cliSess] = await Promise.all([
    host.acceptV2(3000),
    cli.connectV2(hostAddr, hostId, grant, null),
  ]);
  return [hostSess, cliSess];
}

test("concurrent revoke vs pollEvent, authorize, session churn and trust anchors", async () => {
  const hostDir = tmpDir("tendril-node-race-host-");
  const cliDir = tmpDir("tendril-node-race-cli-");
  const host = new Endpoint(hostDir, "race-host");
  const cli = new Endpoint(cliDir, "race-cli");
  const anchorEps = Array.from({ length: 5 }, (_, i) => new Endpoint(null, `race-anchor-${i}`));
  try {
    const hostAddr = await host.serveDirect("127.0.0.1:0");
    const devId = await pairV2(host, cli, hostAddr, "race-host");
    const grant = host.mintGrant(devId, ["fs.read"], 3600);
    const [hostSess] = await openV2Session(host, cli, hostAddr, "race-host", grant);
    assert.equal(await hostSess.authorize("fs.read"), true);

    let stop = false;
    let revokeDone = false;
    const violations = [];
    const errors = [];

    const poller = async () => {
      while (!stop) {
        try {
          await hostSess.pollEvent(1);
        } catch {
          // the session may legitimately fail after revocation
        }
        const revokedBefore = revokeDone;
        const allowed = await hostSess.authorize("fs.read");
        if (revokedBefore && allowed) {
          violations.push("authorize succeeded after revokePeer returned");
        }
      }
    };

    const sessionChurn = async () => {
      for (let i = 0; i < 30 && !stop; i += 1) {
        await Promise.allSettled([
          host.acceptV2(1500),
          cli.connectV2(hostAddr, "race-host", grant, null),
        ]);
      }
    };

    const anchorChurn = async () => {
      try {
        for (let i = 0; i < anchorEps.length; i += 1) {
          host.addTrustAnchor(`race-anchor-${i}`, signingPubOf(anchorEps[i]));
          await sleep(5);
          host.revokeTrustAnchor(`race-anchor-${i}`);
          await sleep(5);
        }
      } catch (err) {
        errors.push(String(err));
      }
    };

    const revoker = async () => {
      await sleep(150);
      try {
        host.revokePeer(devId);
      } catch (err) {
        errors.push(String(err));
      }
      revokeDone = true;
    };

    const pollers = [poller(), poller(), poller()];
    await Promise.all([sessionChurn(), anchorChurn(), revoker()]);
    await sleep(200);
    stop = true;
    await Promise.all(pollers);

    assert.deepEqual(errors, []);
    assert.deepEqual(violations, []);
    assert.equal(await hostSess.authorize("fs.read"), false);
    assert.throws(() => host.mintGrant(devId, ["fs.read"], 60));

    const disk = readRoster(hostDir);
    assert.equal(disk.entries[devId].state, "revoked");
    for (let i = 0; i < anchorEps.length; i += 1) {
      assert.equal(disk.trust_anchors[`race-anchor-${i}`].state, "revoked");
    }

    const reopened = new Endpoint(hostDir, null);
    assert.throws(() => reopened.mintGrant(devId, ["fs.read"], 60));
    reopened.close();
  } finally {
    host.close();
    cli.close();
    anchorEps.forEach((ep) => ep.close());
    fs.rmSync(hostDir, { recursive: true, force: true });
    fs.rmSync(cliDir, { recursive: true, force: true });
  }
});

test("externally persisted revocation reaches memory on connectV2 and acceptV2", async () => {
  const hostDir = tmpDir("tendril-node-sync-host-");
  const cliDir = tmpDir("tendril-node-sync-cli-");
  const host = new Endpoint(hostDir, "sync-host");
  const cli = new Endpoint(cliDir, "sync-cli");
  try {
    const hostAddr = await host.serveDirect("127.0.0.1:0");
    const devId = await pairV2(host, cli, hostAddr, "sync-host");
    const grant = host.mintGrant(devId, ["fs.read"], 3600);
    const [hostSess, cliSess] = await openV2Session(host, cli, hostAddr, "sync-host", grant);
    assert.equal(await hostSess.authorize("fs.read"), true);
    assert.equal(await cliSess.authorize("fs.read"), true);

    const external = new Endpoint(hostDir, null);
    external.revokePeer(devId);
    external.close();
    assert.equal(await hostSess.authorize("fs.read"), true);
    const [hostRes, cliRes] = await Promise.allSettled([
      host.acceptV2(3000),
      cli.connectV2(hostAddr, "sync-host", grant, null),
    ]);
    assert.equal(hostRes.status, "rejected");
    assert.equal(cliRes.status, "rejected");
    assert.equal(await hostSess.authorize("fs.read"), false);

    const externalCli = new Endpoint(cliDir, null);
    externalCli.revokePeer("sync-host");
    externalCli.close();
    assert.equal(await cliSess.authorize("fs.read"), true);
    await assert.rejects(cli.connectV2(hostAddr, "sync-host", grant, null));
    assert.equal(await cliSess.authorize("fs.read"), false);
  } finally {
    host.close();
    cli.close();
    fs.rmSync(hostDir, { recursive: true, force: true });
    fs.rmSync(cliDir, { recursive: true, force: true });
  }
});

test("v1 connect refuses a v2-pinned peer before any bytes reach the socket", async () => {
  const cliDir = tmpDir("tendril-node-floor-cli-");
  try {
    for (const cliState of [cliDir, null]) {
      const host = new Endpoint(null, "floor-host");
      const cli = new Endpoint(cliState, "floor-cli");
      let connections = 0;
      const mock = net.createServer((sock) => {
        connections += 1;
        sock.destroy();
      });
      await new Promise((resolve) => mock.listen(0, "127.0.0.1", resolve));
      try {
        const hostAddr = await host.serveDirect("127.0.0.1:0");
        await pairV2(host, cli, hostAddr, "floor-host");
        const mockAddr = `127.0.0.1:${mock.address().port}`;
        await assert.rejects(cli.connect(mockAddr, "floor-host", null, null), /downgrade/i);
        await sleep(200);
        assert.equal(connections, 0);
      } finally {
        await new Promise((resolve) => mock.close(resolve));
        host.close();
        cli.close();
      }
    }
  } finally {
    fs.rmSync(cliDir, { recursive: true, force: true });
  }
});

test("custom ?relay= URI refuses bearer auth before touching the network", async () => {
  const host = new Endpoint(null, "relay-host");
  const cli = new Endpoint(null, "relay-cli");
  try {
    // Day-2 connects read the pinned peer before dialing, so pair first.
    await pairV2(host, cli, await host.serveDirect("127.0.0.1:0"), "relay-host");
    const p2pAddr = await host.serveP2p("disabled");
    const endpointId = p2pAddr.split("://")[1].split("?")[0];
    const uri = `iroh://${endpointId}?relay=http://127.0.0.1:9/`;
    cli.configureTransportsJson(
      JSON.stringify({
        p2p_allow_private_addrs: true,
        p2p_relay_auth_token: "secret-bearer-token",
      })
    );
    await assert.rejects(cli.connectV2(uri, "relay-host", null, null), (err) => {
      assert.match(err.message, /peer URI/);
      assert.ok(!err.message.includes("secret-bearer-token"));
      return true;
    });
  } finally {
    host.close();
    cli.close();
  }
});

test("v1 host rotation persists to disk and reconnects cleanly", async () => {
  ensureTendrilBin();
  const hostDir = tmpDir("tendril-node-rot-host-");
  const cliDir = tmpDir("tendril-node-rot-cli-");
  runCli(hostDir, "init", "--host-id", "rot-host");
  const cli = new Endpoint(cliDir, "rot-cli");
  const cliId = JSON.parse(cli.infoJson()).device_id;
  let child1 = null;
  let child2 = null;
  let child3 = null;
  try {
    const s1 = await startCliServe(hostDir, true);
    child1 = s1.child;
    const pair = JSON.parse(
      await cli.pairInitiate(s1.ev.direct_endpoint, s1.ev.pairing_code, null, "rot-cli", "node")
    );
    cli.confirmPeer("rot-host", pair.sas);
    await stopChild(child1);
    child1 = null;

    runCli(hostDir, "confirm", cliId, "--sas", pair.sas);

    const rot1 = runCli(hostDir, "rotate");
    assert.equal(rot1.rotation_seq, 1);
    const grant1 = JSON.stringify(runCli(hostDir, "mint", cliId, "--cap", "fs.read"));
    const s2 = await startCliServe(hostDir);
    child2 = s2.child;
    const sess1 = await cli.connect(s2.ev.direct_endpoint, "rot-host", grant1, null);
    await sess1.sendData(Buffer.from("rot1"));
    await sess1.close();
    await stopChild(child2);
    child2 = null;

    const disk1 = readRoster(cliDir);
    assert.equal(disk1.entries["rot-host"].rotation_seq, 1);
    assert.ok(Buffer.from(disk1.entries["rot-host"].static_pub).equals(b64urlDecode(rot1.static_pub)));

    const rot2 = runCli(hostDir, "rotate");
    assert.equal(rot2.rotation_seq, 2);
    const grant2 = JSON.stringify(runCli(hostDir, "mint", cliId, "--cap", "fs.read"));
    const s3 = await startCliServe(hostDir);
    child3 = s3.child;
    const sess2 = await cli.connect(s3.ev.direct_endpoint, "rot-host", grant2, null);
    await sess2.sendData(Buffer.from("rot2"));
    await sess2.close();

    const disk2 = readRoster(cliDir);
    assert.equal(disk2.entries["rot-host"].rotation_seq, 2);
    assert.ok(Buffer.from(disk2.entries["rot-host"].static_pub).equals(b64urlDecode(rot2.static_pub)));

    const reopened = new Endpoint(cliDir, null);
    try {
      const sess3 = await reopened.connect(s3.ev.direct_endpoint, "rot-host", grant2, null);
      await sess3.sendData(Buffer.from("rot3"));
      await sess3.close();
    } finally {
      reopened.close();
    }
  } finally {
    await stopChild(child1);
    await stopChild(child2);
    await stopChild(child3);
    cli.close();
    fs.rmSync(hostDir, { recursive: true, force: true });
    fs.rmSync(cliDir, { recursive: true, force: true });
  }
});
