/** Live-test helpers: a relay, a conformance host, the CLI, and signed pairing URIs. */
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const RELAY_BIN = path.join(REPO_ROOT, "target", "debug", "tendril-relay");
const PEER_BIN = path.join(REPO_ROOT, "target", "debug", "tendril-conformance-peer");
const CLI_BIN = path.join(REPO_ROOT, "target", "debug", "tendril");
const ROUTES_DOMAIN = Buffer.from("tendril-pairing-routes-v1\0", "latin1");

export function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

export function pct(value) {
  let out = "";
  for (const b of Buffer.from(value, "utf8")) {
    const ch = String.fromCharCode(b);
    out += /[A-Za-z0-9\-._~]/.test(ch) ? ch : `%${b.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

export function ed25519Key(seedB64) {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seedB64, "base64url"),
  ]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Builds a pairing URI in the canonical field order; with `rq` it is signed by `seedB64`. */
export function buildUri({
  host = "host",
  code,
  k,
  sh,
  id = null,
  rp = null,
  ep = [],
  rq = null,
  seedB64 = null,
}) {
  let out = `tendril://pair?v=1&host=${pct(host)}&code=${pct(code)}&k=${k}&sh=${sh}`;
  if (id) out += `&id=${pct(id)}`;
  if (rp) out += `&rp=${rp}`;
  if (ep.length > 0) out += `&ep=${ep.map(pct).join(",")}`;
  if (rq !== null) {
    out += `&rq=${rq}`;
    const sig = crypto.sign(
      null,
      Buffer.concat([ROUTES_DOMAIN, Buffer.from(out)]),
      ed25519Key(seedB64)
    );
    out += `&rs=${b64url(sig)}`;
  }
  return out;
}

function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

export function spawnRelay() {
  return new Promise((resolve, reject) => {
    const child = spawn(RELAY_BIN, ["--listen", "127.0.0.1:0", "--host", "127.0.0.1"], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, RUST_LOG: "info" },
    });
    let acc = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`tendril-relay startup timed out: ${acc}`));
    }, 10000);
    const onData = (chunk) => {
      acc += stripAnsi(chunk.toString("utf8"));
      const m = acc.match(/ws:\/\/127\.0\.0\.1:(\d+)\/v1\/relay/);
      if (m) {
        clearTimeout(timer);
        resolve({ child, wsUrl: m[0], port: Number(m[1]) });
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`tendril-relay exited early (${code}): ${acc}`));
    });
  });
}

export function spawnPeer() {
  const child = spawn(PEER_BIN, [], { stdio: ["pipe", "pipe", "inherit"] });
  const rl = readline.createInterface({ input: child.stdout });
  const lines = [];
  const waiters = [];
  rl.on("line", (line) => {
    const parsed = JSON.parse(line);
    if (waiters.length > 0) waiters.shift()(parsed);
    else lines.push(parsed);
  });
  return {
    send(cmd) {
      child.stdin.write(`${JSON.stringify(cmd)}\n`);
    },
    recv() {
      if (lines.length > 0) return Promise.resolve(lines.shift());
      return new Promise((resolve) => waiters.push(resolve));
    },
    async call(cmd) {
      this.send(cmd);
      const res = await this.recv();
      if (!res.ok) throw new Error(`peer ${cmd.op} failed: ${JSON.stringify(res)}`);
      return res;
    },
    close() {
      rl.close();
      child.kill();
    },
  };
}

/** A loopback port with nothing listening on it. */
export async function deadPort() {
  const srv = net.createServer();
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const { port } = srv.address();
  await new Promise((r) => srv.close(r));
  return port;
}

/** Starts a relay and a conformance host serving it (and optional broker), with a fresh remote code. */
export async function liveHost(hostId, { serveBroker = false } = {}) {
  const relay = await spawnRelay();
  const peer = spawnPeer();
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "tendril-web-uri-"));
  const peerInit = await peer.call({ op: "init", state_dir: stateDir, host_id: hostId });
  const seedB64 = JSON.parse(
    fs.readFileSync(path.join(stateDir, "identity.json"), "utf8")
  ).signing_seed_b64;
  await peer.call({ op: "serve_relay", relay_url: relay.wsUrl, expected_host: "127.0.0.1" });
  const broker = serveBroker ? await peer.call({ op: "serve_broker" }) : null;
  const code = (await peer.call({ op: "issue_code", kind: "remote" })).code;
  const fields = {
    host: hostId,
    code,
    k: peerInit.static_pub,
    sh: peerInit.signing_pub_hash,
    id: hostId,
    rp: peerInit.relay_pub,
  };
  return {
    relay,
    broker,
    peer,
    seedB64,
    fields,
    stateDir,
    close() {
      peer.close();
      relay.child.kill();
      fs.rmSync(stateDir, { recursive: true, force: true });
    },
  };
}

/** Runs the `tendril` CLI against a copy of `stateDir` and returns the copy and the JSON line. */
export function cliOnCopy(stateDir, args) {
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), "tendril-web-cli-"));
  fs.cpSync(stateDir, copy, { recursive: true });
  const res = spawnSync(CLI_BIN, ["--state-dir", copy, ...args], { encoding: "utf8" });
  if (res.status !== 0) {
    throw new Error(`tendril ${args.join(" ")} failed: ${res.stderr}`);
  }
  return { dir: copy, out: JSON.parse(res.stdout.trim().split("\n").pop()) };
}
