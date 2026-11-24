// Pairing URI, route policy, endpoint-free connect and route announcement flows.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import tendril from "../index.js";

const { Endpoint } = tendril;

const tmpDirs = [];
const endpoints = [];

function tmpState() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tendril-node-uri-"));
  tmpDirs.push(dir);
  return dir;
}

function endpoint(stateDir, hostId) {
  const ep = new Endpoint(stateDir, hostId);
  endpoints.push(ep);
  return ep;
}

test.afterEach(() => {
  for (const ep of endpoints.splice(0)) {
    ep.close();
  }
  for (const dir of tmpDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function snapshot(...addrs) {
  return JSON.stringify({
    networks: [
      { id: "wlan0", iface: "wlan0", if_index: 3, transports: ["wifi"], addrs },
    ],
  });
}

/** The `ep` hints of a pairing URI, percent-decoded. */
function hints(uri) {
  const query = new URLSearchParams(uri.slice(uri.indexOf("?") + 1));
  return query.getAll("ep").flatMap((ep) => ep.split(","));
}

/** Awaits both sides of a handshake and surfaces the first failure without stray rejections. */
async function both(a, b) {
  const [ra, rb] = await Promise.allSettled([a, b]);
  if (rb.status === "rejected") throw rb.reason;
  if (ra.status === "rejected") throw ra.reason;
  return [ra.value, rb.value];
}

async function pairOverUri(host, cli, uri, { v2 = false, options = null } = {}) {
  const opts = options === null ? null : JSON.stringify(options);
  const accepted = v2 ? host.pairV2Accept(8000) : host.pairAccept(8000);
  const paired = v2
    ? cli.pairV2Uri(uri, "node-uri-cli", "node", opts)
    : cli.pairUri(uri, "node-uri-cli", "node", opts);
  const [, raw] = await both(accepted, paired);
  const res = JSON.parse(raw);
  // The URI pins the host, so the client side is already active; the host confirms the device.
  assert.ok(res.host_confirmed && res.status === "active", JSON.stringify(res));
  host.confirmPeer(res.device_id, res.sas);
  return res;
}

async function openSession(host, cli, target, grant, { endpoint: ep = null, v2 = false } = {}) {
  const accepted = v2 ? host.acceptV2(10000) : host.acceptSession(10000);
  const connected = v2 ? cli.connectV2(ep, target, grant) : cli.connect(ep, target, grant);
  const [hostSess, cliSess] = await both(accepted, connected);
  return [cliSess, hostSess];
}

async function issue(host, options = null) {
  return JSON.parse(await host.issuePairingUri(options === null ? null : JSON.stringify(options)));
}

const invalidArg = (err) => {
  assert.equal(err.code, "InvalidArg", err.message);
  return true;
};
const failure = (pattern) => (err) => {
  assert.equal(err.code, "GenericFailure", err.message);
  if (pattern) assert.match(err.message, pattern);
  return true;
};

function signedHints(view) {
  return view.routes.filter((r) => r.source === "signed").map((r) => r.hint);
}

function newPair(prefix = "node-uri") {
  const dir = tmpState();
  return [
    endpoint(`${dir}/host`, `${prefix}-host`),
    endpoint(`${dir}/cli`, `${prefix}-cli`),
    dir,
  ];
}

test("new transport config keys are validated", () => {
  const ep = endpoint(null, "node-cfg");
  ep.configureTransportsJson(
    JSON.stringify({
      relay_auth_origins: ["wss://relay.example", "ws://127.0.0.1:8080"],
      advertise: "explicit",
      advertised_endpoints: ["wss://relay.example/v1/relay"],
      route_policy: "committed_only",
      sign_routes: false,
    })
  );
  for (const bad of [
    { advertise: "sometimes" },
    { relay_auth_origins: ["wss://relay.example/with/path"] },
    { relay_auth_origins: ["not an origin"] },
    { route_policy: "most" },
    { relay_origins: [] },
  ]) {
    assert.throws(
      () => ep.configureTransportsJson(JSON.stringify(bad)),
      invalidArg,
      JSON.stringify(bad)
    );
  }
});

test("issuePairingUri reports the announced set", async () => {
  const [host] = newPair();
  const addr = await host.serveDirect("127.0.0.1:0");
  const issued = await issue(host);
  assert.deepEqual(Object.keys(issued).sort(), [
    "code_kind",
    "dropped",
    "qr_version_m",
    "route_seq",
    "uri",
    "uri_len",
  ]);
  assert.equal(issued.code_kind, "lan");
  assert.equal(issued.route_seq, 1);
  assert.deepEqual(issued.dropped, []);
  assert.equal(issued.uri_len, issued.uri.length);
  assert.deepEqual(hints(issued.uri), [`direct:${addr}`]);
  assert.match(issued.uri, /&rq=1&/);
  assert.match(issued.uri, /&rs=/);

  const unsigned = await issue(host, { sign_routes: false, host_name: "named" });
  assert.equal(unsigned.route_seq, null);
  assert.ok(!unsigned.uri.includes("&rs="));
  assert.match(unsigned.uri, /host=named/);

  await assert.rejects(host.issuePairingUri(JSON.stringify({ kind: "sideways" })), invalidArg);
  await assert.rejects(
    host.issuePairingUri(JSON.stringify({ extra_endpoints: ["direct:1.2.3.4:5"] })),
    invalidArg
  );
});

test("issuePairingUri reports announced-set drops", async () => {
  const [host] = newPair();
  host.configureTransportsJson(
    JSON.stringify({ advertise: "explicit", advertised_endpoints: ["direct:0.0.0.0:7000"] })
  );
  await host.serveDirect("127.0.0.1:0");
  const issued = await issue(host, { kind: "lan" });
  assert.deepEqual(issued.dropped, [{ hint: "direct:0.0.0.0:7000", reason: "unspecified_bind" }]);
});

test("dropped hints are printed redacted", async () => {
  const [host] = newPair();
  host.configureTransportsJson(
    JSON.stringify({
      advertise: "explicit",
      advertised_endpoints: ["ws://user:SECRETPW@relay.example/v1/relay?t=SECRETTOKEN"],
    })
  );
  await host.serveDirect("127.0.0.1:0");
  const raw = await host.issuePairingUri(null);
  assert.ok(!raw.includes("SECRETPW") && !raw.includes("SECRETTOKEN"), raw);
  assert.deepEqual(JSON.parse(raw).dropped, [{ hint: "ws://relay.example", reason: "invalid" }]);
});

test("code kind names are case-insensitive", async () => {
  const [host] = newPair();
  await host.serveDirect("127.0.0.1:0");
  assert.equal((await issue(host, { kind: "REMOTE" })).code_kind, "remote");
  assert.equal((await issue(host, { kind: "Auto" })).code_kind, "lan");
  assert.ok(host.issueCode("Remote").split("-").length > host.issueCode("LAN").split("-").length);
  assert.throws(() => host.issueCode("sideways"), (err) => err.code === "GenericFailure" || err.code === "InvalidArg");
});

test("pairUri over v1 persists signed routes and connects endpoint-free", async () => {
  const [host, cli] = newPair();
  const addr = await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host);
  const res = await pairOverUri(host, cli, uri);

  assert.equal(res.provider, "direct");
  assert.equal(res.endpoint, `direct:${addr}`);
  assert.equal(res.committed, true);
  assert.equal(res.route_check, "verified");
  assert.deepEqual(res.routes_persisted, [{ hint: `direct:${addr}`, source: "signed" }]);
  assert.deepEqual(res.skipped, []);
  assert.equal(res.status, "active");
  assert.ok(!("wire_version" in res));

  const view = JSON.parse(await cli.peerRoutes("node-uri-host"));
  assert.deepEqual(view.routes, [{ hint: `direct:${addr}`, source: "signed" }]);
  assert.equal(view.route_meta.seq, 1);
  assert.equal(view.route_meta.origin, "uri");
  assert.equal(view.last_route_set, null);

  const grant = host.mintGrant(res.device_id, ["fs.read"], 3600);
  const [sess, hostSess] = await openSession(host, cli, "node-uri-host", grant);
  await sess.sendData(Buffer.from("endpoint-free"));
  assert.equal(JSON.parse(await hostSess.pollEvent(3000)).event, "data");
  await sess.close();
});

test("pairUri with route_policy none persists no routes", async () => {
  const [host, cli] = newPair();
  await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host);
  const res = await pairOverUri(host, cli, uri, { options: { route_policy: "none" } });
  assert.equal(res.route_check, "verified");
  assert.deepEqual(res.routes_persisted, []);
  assert.deepEqual(JSON.parse(await cli.peerRoutes("node-uri-host")).routes, []);
  await assert.rejects(cli.connect(null, "node-uri-host", null), failure(/no dialable stored routes/));
});

test("the configured route policy is the pairing default", async () => {
  const [host, cli] = newPair();
  cli.configureTransportsJson(JSON.stringify({ route_policy: "none" }));
  await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host);
  const res = await pairOverUri(host, cli, uri);
  assert.deepEqual(res.routes_persisted, []);
});

test("an unsigned URI saves the committed route only on request", async () => {
  const [host, cli, dir] = newPair();
  const addr = await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host, { sign_routes: false });
  const res = await pairOverUri(host, cli, uri, { options: { save_route: true } });
  assert.equal(res.route_check, "unsigned");
  assert.deepEqual(res.routes_persisted, [{ hint: `direct:${addr}`, source: "committed" }]);

  const other = endpoint(`${dir}/other`, "node-uri-other");
  const second = await issue(host, { sign_routes: false });
  const res2 = await pairOverUri(host, other, second.uri);
  assert.equal(res2.route_check, "unsigned");
  assert.deepEqual(res2.routes_persisted, []);

  await assert.rejects(
    cli.pairUri(second.uri, null, null, JSON.stringify({ route_policy: "none", save_route: true })),
    failure()
  );
});

test("pairV2Uri and endpoint-free connectV2", async () => {
  const [host, cli] = newPair();
  const addr = await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host);
  const res = await pairOverUri(host, cli, uri, { v2: true });
  assert.equal(res.wire_version, 2);
  assert.equal(res.route_check, "verified");
  assert.equal(res.provider, "direct");
  assert.deepEqual(res.routes_persisted, [{ hint: `direct:${addr}`, source: "signed" }]);

  const grant = host.mintGrant(res.device_id, ["fs.read"], 3600);
  const [sess, hostSess] = await openSession(host, cli, "node-uri-host", grant, { v2: true });
  await sess.sendData(Buffer.from("v2-endpoint-free"));
  assert.equal(JSON.parse(await hostSess.pollEvent(3000)).event, "data");
  await sess.close();
});

test("store-less endpoints pair and connect endpoint-free", async () => {
  const host = endpoint(null, "node-mem-host");
  const cli = endpoint(null, "node-mem-cli");
  const addr = await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host);
  const res = await pairOverUri(host, cli, uri);
  assert.equal(res.route_check, "verified");
  const view = JSON.parse(await cli.peerRoutes("node-mem-host"));
  assert.deepEqual(view.routes, [{ hint: `direct:${addr}`, source: "signed" }]);
  await cli.setPeerRoutes("node-mem-host", JSON.stringify(["127.0.0.1:19"]));
  const sources = JSON.parse(await cli.peerRoutes("node-mem-host")).routes.map((r) => r.source);
  assert.deepEqual(sources.sort(), ["operator", "signed"]);
  const grant = host.mintGrant(res.device_id, ["fs.read"], 3600);
  const [sess, hostSess] = await openSession(host, cli, "node-mem-host", grant);
  await sess.sendData(Buffer.from("store-less"));
  assert.equal(JSON.parse(await hostSess.pollEvent(3000)).event, "data");
  await sess.close();
});

test("a pairUri endpoint override is dialed alone and saved as operator", async () => {
  const [host, cli] = newPair();
  host.configureTransportsJson(
    JSON.stringify({ advertise: "explicit", advertised_endpoints: ["direct:192.168.77.5:9"] })
  );
  const addr = await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host, { kind: "lan" });
  assert.ok(hints(uri).includes("direct:192.168.77.5:9"));
  const res = await pairOverUri(host, cli, uri, { options: { endpoint: addr } });
  assert.equal(res.endpoint, `direct:${addr}`);
  const bySource = Object.fromEntries(res.routes_persisted.map((r) => [r.source, r.hint]));
  assert.equal(bySource.operator, `direct:${addr}`);
  assert.equal(bySource.signed, "direct:192.168.77.5:9");
});

test("pairUri refusals happen before any dial", async () => {
  const [host, cli] = newPair();
  await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host);
  await assert.rejects(cli.pairUri("not a pairing uri"), invalidArg);
  await assert.rejects(
    cli.pairUri(uri, null, null, JSON.stringify({ route_polcy: "none" })),
    invalidArg
  );
  await assert.rejects(
    cli.pairUri(uri, null, null, JSON.stringify({ route_policy: "none " })),
    invalidArg
  );
  await assert.rejects(
    cli.pairUri(uri, null, null, JSON.stringify({ code: "0000-0000" })),
    (err) => {
      assert.match(err.message.toLowerCase(), /pairing code/);
      return true;
    }
  );
  await assert.rejects(
    cli.pairUri(uri, null, null, JSON.stringify({ endpoint: "direct:169.254.169.254:80" })),
    failure(/169\.254\.169\.254/)
  );
  await assert.rejects(
    cli.pairV2Uri(uri, null, null, JSON.stringify({ endpoint: "ws://127.0.0.1:9/v2/relay" })),
    failure(/\/v2\/relay is not used for pairing/)
  );
});

test("peer route setter roundtrip", async () => {
  const [host, cli] = newPair();
  const addr = await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host);
  await pairOverUri(host, cli, uri);

  const setRes = JSON.parse(
    await cli.setPeerRoutes(
      "node-uri-host",
      JSON.stringify(["127.0.0.1:19", "/tmp/tendril-uri-test.sock"])
    )
  );
  assert.deepEqual(
    setRes.map((r) => [r.source, r.hint]).sort(),
    [
      ["operator", "direct:127.0.0.1:19"],
      ["operator", "local:/tmp/tendril-uri-test.sock"],
      ["signed", `direct:${addr}`],
    ]
  );

  // A bad entry fails the whole batch and writes nothing.
  await assert.rejects(
    cli.setPeerRoutes("node-uri-host", JSON.stringify(["127.0.0.1:20", "direct:169.254.169.254:80"])),
    failure()
  );
  await assert.rejects(
    cli.setPeerRoutes(
      "node-uri-host",
      JSON.stringify([30, 31, 32, 33, 34, 35, 36].map((n) => `127.0.0.1:${n}`))
    ),
    failure()
  );
  await assert.rejects(
    cli.setPeerRoutes("node-uri-host", JSON.stringify({ not: "a list" })),
    invalidArg
  );
  await assert.rejects(cli.setPeerRoutes("nobody", JSON.stringify(["127.0.0.1:19"])), failure());
  const kept = JSON.parse(await cli.peerRoutes("node-uri-host")).routes;
  assert.equal(kept.filter((r) => r.source === "operator").length, 2);

  await cli.clearPeerRoutes("node-uri-host");
  assert.deepEqual(JSON.parse(await cli.peerRoutes("node-uri-host")).routes, [
    { hint: `direct:${addr}`, source: "signed" },
  ]);

  await cli.setPeerRoutes("node-uri-host", JSON.stringify(["127.0.0.1:19"]));
  await cli.clearPeerRoutes("node-uri-host", "signed");
  assert.deepEqual(JSON.parse(await cli.peerRoutes("node-uri-host")).routes, [
    { hint: "direct:127.0.0.1:19", source: "operator" },
  ]);
  await cli.clearPeerRoutes("node-uri-host", "all");
  assert.deepEqual(JSON.parse(await cli.peerRoutes("node-uri-host")).routes, []);
  await assert.rejects(cli.clearPeerRoutes("node-uri-host", "everything"), invalidArg);
  await assert.rejects(cli.peerRoutes("nobody"), failure());
});

test("refreshRoutes with a snapshot, then applyRouteUri", async () => {
  const [host, cli, dir] = newPair();
  const portAddr = await host.serveDirect("0.0.0.0:0");
  const port = portAddr.split(":").pop();
  assert.deepEqual(JSON.parse(await host.refreshRoutes(snapshot("192.168.1.20/24"))), {
    route_seq: 1,
    changed: true,
  });
  assert.deepEqual(JSON.parse(await host.refreshRoutes(snapshot("192.168.1.20"))), {
    route_seq: 1,
    changed: false,
  });
  await assert.rejects(host.refreshRoutes("{not json"), invalidArg);

  const uriA = (await issue(host, { kind: "lan" })).uri;
  assert.deepEqual(hints(uriA), [`direct:192.168.1.20:${port}`]);

  // The LAN address is not reachable here: dial the loopback bind as the operator.
  const res = await pairOverUri(host, cli, uriA, { options: { endpoint: `127.0.0.1:${port}` } });
  assert.equal(res.route_check, "verified");

  assert.deepEqual(JSON.parse(await host.refreshRoutes(snapshot("192.168.1.99"))), {
    route_seq: 2,
    changed: true,
  });
  const uriB = (await issue(host, { kind: "lan" })).uri;
  assert.deepEqual(hints(uriB), [`direct:192.168.1.99:${port}`]);

  assert.deepEqual(JSON.parse(await cli.applyRouteUri(uriB)), {
    peer_id: "node-uri-host",
    applied: true,
    reason: null,
    route_seq: 2,
  });
  assert.deepEqual(signedHints(JSON.parse(await cli.peerRoutes("node-uri-host"))), [
    `direct:192.168.1.99:${port}`,
  ]);

  const stale = JSON.parse(await cli.applyRouteUri(uriA));
  assert.equal(stale.applied, false);
  assert.equal(stale.reason, "stale_route_seq");
  const approved = JSON.parse(
    await cli.applyRouteUri(uriA, JSON.stringify({ replace_routes: true }))
  );
  assert.equal(approved.applied, true);
  const nonePolicy = JSON.parse(
    await cli.applyRouteUri(uriB, JSON.stringify({ route_policy: "none" }))
  );
  assert.equal(nonePolicy.applied, false);
  assert.equal(nonePolicy.reason, "route_policy");

  const stranger = endpoint(null, "node-uri-stranger");
  await assert.rejects(stranger.applyRouteUri(uriB), failure(/no paired host matches/));
  await assert.rejects(cli.applyRouteUri(uriB, JSON.stringify({ replace: true })), invalidArg);
  assert.ok(dir);
});

test("connectWithOptions honours the recovery URI and the route policy", async () => {
  const [host, cli] = newPair();
  const portAddr = await host.serveDirect("0.0.0.0:0");
  const port = portAddr.split(":").pop();
  await host.refreshRoutes(snapshot("192.168.1.20"));
  const uriA = (await issue(host, { kind: "lan" })).uri;
  const res = await pairOverUri(host, cli, uriA, { options: { endpoint: `127.0.0.1:${port}` } });
  const grant = JSON.parse(host.mintGrant(res.device_id, ["fs.read"], 3600));
  await host.refreshRoutes(snapshot("192.168.1.99"));
  const uriB = (await issue(host, { kind: "lan" })).uri;

  for (const bad of [{ wire: 3 }, { wire: 1, bogus: true }, { route_policy: "sometimes" }]) {
    await assert.rejects(
      cli.connectWithOptions("node-uri-host", JSON.stringify(bad)),
      invalidArg,
      JSON.stringify(bad)
    );
  }

  const options = {
    wire: 1,
    grant,
    endpoint: `127.0.0.1:${port}`,
    recovery_uri: uriB,
  };
  const [hostSess, sess] = await both(
    host.acceptSession(10000),
    cli.connectWithOptions("node-uri-host", JSON.stringify(options))
  );
  await sess.sendData(Buffer.from("recovered"));
  assert.equal(JSON.parse(await hostSess.pollEvent(3000)).event, "data");
  assert.deepEqual(signedHints(JSON.parse(await cli.peerRoutes("node-uri-host"))), [
    `direct:192.168.1.99:${port}`,
  ]);
  await sess.close();

  // A recovery URI under route_policy none checks the host keys but changes no routes.
  await host.refreshRoutes(snapshot("192.168.1.150"));
  const uriC = (await issue(host, { kind: "lan" })).uri;
  const [hostSess2, sess2] = await both(
    host.acceptSession(10000),
    cli.connectWithOptions(
      "node-uri-host",
      JSON.stringify({
        grant,
        endpoint: `127.0.0.1:${port}`,
        recovery_uri: uriC,
        route_policy: "none",
      })
    )
  );
  assert.ok(hostSess2);
  assert.deepEqual(signedHints(JSON.parse(await cli.peerRoutes("node-uri-host"))), [
    `direct:192.168.1.99:${port}`,
  ]);
  await sess2.close();
});

async function pairForRouteSets(host, cli) {
  const portAddr = await host.serveDirect("0.0.0.0:0");
  const port = portAddr.split(":").pop();
  await host.refreshRoutes(snapshot("192.168.1.20"));
  const { uri } = await issue(host, { kind: "lan" });
  const res = await pairOverUri(host, cli, uri, { options: { endpoint: `127.0.0.1:${port}` } });
  return [port, res];
}

async function waitForRouteSet(cli, sess, seq, seconds) {
  const deadline = Date.now() + seconds * 1000;
  let view = {};
  while (Date.now() < deadline) {
    const ev = JSON.parse(await sess.pollEvent(250));
    assert.notEqual(ev.status, "eof");
    assert.notEqual(ev.event, "data");
    view = JSON.parse(await cli.peerRoutes("node-uri-host"));
    if (view.last_route_set && view.last_route_set.seq === seq) return view;
    await sleep(10);
  }
  assert.fail(`route set ${seq} not applied in time: ${JSON.stringify(view)}`);
  return view;
}

test("a session start sends the current route set", { timeout: 60000 }, async () => {
  const [host, cli] = newPair();
  const [port, res] = await pairForRouteSets(host, cli);
  assert.equal(JSON.parse(await host.refreshRoutes(snapshot("192.168.1.77"))).route_seq, 2);
  const grant = host.mintGrant(res.device_id, ["fs.read"], 3600);
  const [sess, hostSess] = await openSession(host, cli, "node-uri-host", grant, {
    endpoint: `127.0.0.1:${port}`,
  });
  try {
    const view = await waitForRouteSet(cli, sess, 2, 20);
    assert.deepEqual(view.last_route_set, { outcome: "applied", seq: 2 });
    assert.deepEqual(signedHints(view), [`direct:192.168.1.77:${port}`]);
    assert.equal(view.route_meta.seq, 2);
    assert.equal(view.route_meta.origin, "session");
    // The route set never surfaced as an application event.
    await sess.sendData(Buffer.from("still-open"));
    assert.equal(JSON.parse(await hostSess.pollEvent(3000)).event, "data");
  } finally {
    await sess.close();
  }
});

test("a live session receives a refreshed route set", { timeout: 120000 }, async () => {
  const [host, cli] = newPair();
  const [port, res] = await pairForRouteSets(host, cli);
  const grant = host.mintGrant(res.device_id, ["fs.read"], 3600);
  const [sess] = await openSession(host, cli, "node-uri-host", grant, {
    endpoint: `127.0.0.1:${port}`,
  });
  try {
    await waitForRouteSet(cli, sess, 1, 20);
    assert.equal(JSON.parse(await host.refreshRoutes(snapshot("192.168.1.88"))).route_seq, 2);
    // The host sends at most one route set per session every 30 s.
    const view = await waitForRouteSet(cli, sess, 2, 60);
    assert.deepEqual(signedHints(view), [`direct:192.168.1.88:${port}`]);
  } finally {
    await sess.close();
  }
});

/** A webhook endpoint that records every wake request it receives. */
async function wakeServer(onWake = null) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", async () => {
      requests.push(JSON.parse(raw));
      if (onWake !== null) await onWake();
      res.writeHead(202, { "Content-Length": "0" });
      res.end();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    requests,
    url: `http://127.0.0.1:${server.address().port}/wake`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function configureWake(cli, wake, preWake) {
  cli.configureTransportsJson(
    JSON.stringify({
      wake_url: wake.url,
      wake_adapter: "webhook",
      wake_secret_b64: crypto.randomBytes(32).toString("base64url"),
      wake_pre_wake: preWake,
      wake_retry_delay_ms: 25,
      wake_max_attempts: 3,
      wake_timeout_ms: 2000,
    })
  );
}

async function wakePair(preWake) {
  const [host, cli] = newPair("node-wake");
  const wake = await wakeServer();
  configureWake(cli, wake, preWake);
  const addr = await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host);
  const res = await pairOverUri(host, cli, uri, { v2: true });
  return { host, cli, wake, addr, res };
}

async function wakeOptions(host, res, endpoint) {
  const grant = JSON.parse(host.mintGrant(res.device_id, ["fs.read"], 3600));
  const recovery = (await issue(host)).uri;
  return JSON.stringify({ wire: 2, grant, endpoint, recovery_uri: recovery });
}

async function freePort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

test("pre_wake wakes the host before the connect", async () => {
  const { host, cli, wake, addr, res } = await wakePair(true);
  try {
    const options = await wakeOptions(host, res, addr);
    const [hostSess, sess] = await both(
      host.acceptV2(10000),
      cli.connectWithOptions("node-wake-host", options)
    );
    assert.equal(wake.requests.length, 1);
    await sess.sendData(Buffer.from("woken"));
    assert.equal(JSON.parse(await hostSess.pollEvent(3000)).event, "data");
    await sess.close();
  } finally {
    await wake.close();
  }
});

test("connect-first does not wake a reachable host", async () => {
  const { host, cli, wake, addr, res } = await wakePair(false);
  try {
    const options = await wakeOptions(host, res, addr);
    const [, sess] = await both(
      host.acceptV2(10000),
      cli.connectWithOptions("node-wake-host", options)
    );
    assert.deepEqual(wake.requests, []);
    await sess.close();
  } finally {
    await wake.close();
  }
});

test("connect-first wakes on a transient miss and retries", async () => {
  const [host, cli] = newPair("node-wake");
  const port = await freePort();
  let accepted = null;
  // The wake hint arrives: the sleeping host starts listening on the dialed port.
  const wake = await wakeServer(async () => {
    await host.serveDirect(`127.0.0.1:${port}`);
    accepted = host.acceptV2(10000);
  });
  try {
    configureWake(cli, wake, false);
    await host.serveDirect("127.0.0.1:0");
    const { uri } = await issue(host);
    const res = await pairOverUri(host, cli, uri, { v2: true });
    const options = await wakeOptions(host, res, `127.0.0.1:${port}`);
    const sess = await cli.connectWithOptions("node-wake-host", options);
    const hostSess = await accepted;
    assert.equal(wake.requests.length, 1);
    await sess.sendData(Buffer.from("woken"));
    assert.equal(JSON.parse(await hostSess.pollEvent(3000)).event, "data");
    await sess.close();
  } finally {
    await wake.close();
  }
});

test("a transient miss after the wake exhausts the attempts", async () => {
  const { host, cli, wake, res } = await wakePair(false);
  try {
    const options = await wakeOptions(host, res, `127.0.0.1:${await freePort()}`);
    await assert.rejects(cli.connectWithOptions("node-wake-host", options), failure());
    assert.equal(wake.requests.length, 1);
  } finally {
    await wake.close();
  }
});

for (const preWake of [false, true]) {
  test(`a wake connect refuses a blocked destination without a legacy dial (pre_wake ${preWake})`, async () => {
    const { host, cli, wake, res } = await wakePair(preWake);
    try {
      const grant = host.mintGrant(res.device_id, ["fs.read"], 3600);
      await assert.rejects(
        cli.connectV2("169.254.169.254:9", "node-wake-host", grant),
        failure(/invalid endpoint/)
      );
      // A policy refusal is final. Connect-first never wakes the host for it; pre-wake has
      // already sent its one hint.
      assert.equal(wake.requests.length, preWake ? 1 : 0);
    } finally {
      await wake.close();
    }
  });
}

test("errors never echo origins, hints or nested URLs", async () => {
  const [host, cli] = newPair("node-hard");
  const secret = "SECRETPW";
  const ticket = "SECRETTICKET";
  const clean = (err) => {
    assert.ok(!err.message.includes(secret), err.message);
    assert.ok(!err.message.includes(ticket), err.message);
    return true;
  };
  assert.throws(
    () =>
      cli.configureTransportsJson(
        JSON.stringify({ relay_auth_origins: [`wss://user:${secret}@relay.example/p?t=${ticket}`] })
      ),
    (err) => invalidArg(err) && clean(err)
  );
  await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host);
  const hint = `wss://user:${secret}@169.254.169.254:9/v1/relay?ticket=${ticket}`;
  await assert.rejects(
    cli.pairUri(uri, null, null, JSON.stringify({ endpoint: hint })),
    (err) => clean(err) && failure(/169\.254\.169\.254/)(err)
  );
  await assert.rejects(
    cli.connectWithOptions("node-hard-host", JSON.stringify({ wire: 1, endpoint: hint })),
    clean
  );
  await assert.rejects(
    cli.pairUri(`tendril://pair?v=1&host=x&code=${secret}&junk=${ticket}`),
    clean
  );
});

test("an empty code override is rejected before any dial", async () => {
  const [host, cli] = newPair("node-code");
  await host.serveDirect("127.0.0.1:0");
  const { uri } = await issue(host);
  const waiting = host.pairAccept(1500).then(
    () => "paired",
    (err) => err.message
  );
  await assert.rejects(
    cli.pairUri(uri, null, null, JSON.stringify({ code: "" })),
    (err) => {
      assert.match(err.message.toLowerCase(), /pairing code/);
      return true;
    }
  );
  // Nothing dialed: the host timed out waiting, and the URI code is still unspent.
  assert.match(await waiting, /timed out/);
});

test("close is terminal for the announcer", async () => {
  const [host] = newPair("node-close");
  await host.serveDirect("127.0.0.1:0");
  await issue(host);
  host.close();
  await assert.rejects(host.refreshRoutes(null), failure(/closed/));
  await assert.rejects(host.issuePairingUri(null), failure(/closed/));
});

const camel = (key) => key.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
const camelKeys = (obj) => Object.fromEntries(Object.entries(obj).map(([k, v]) => [camel(k), v]));

test("every transport key has a camelCase alias that behaves like the snake_case key", () => {
  const ticketHost = newPair("node-camel-ticket")[0];
  const ticket = ticketHost.mintRelayTicket("127.0.0.1", "any", "*", 300);
  const configs = [
    { relay_auth_secret: "s3cret" },
    { relay_ticket: JSON.parse(ticket) },
    {
      p2p_relay_mode: "disabled",
      p2p_pkarr: false,
      p2p_advertise_direct_addrs: true,
      p2p_allow_private_addrs: false,
    },
    { p2p_relay_urls: ["https://relay.example"], p2p_relay_auth_token: "tok" },
    // Needs the p2p-iroh-services feature, which the test build lacks: the key still has to be
    // recognised, so both spellings fail at the same later stage.
    { p2p_relay_urls: ["https://relay.example"], p2p_api_secret: "api" },
    {
      wake_url: "http://127.0.0.1:9/wake",
      wake_adapter: "webhook",
      wake_secret_b64: crypto.randomBytes(32).toString("base64url"),
      wake_auth_token: "wake-tok",
      wake_pre_wake: true,
      wake_retry_delay_ms: 5,
      wake_max_attempts: 2,
      wake_timeout_ms: 100,
    },
    {
      relay_auth_origins: ["wss://relay.example"],
      advertise: "explicit",
      advertised_endpoints: ["192.0.2.9:7000"],
      route_policy: "committed_only",
      sign_routes: false,
    },
  ];
  const keys = new Set();
  const outcome = (host, cfg) => {
    try {
      host.configureTransportsJson(JSON.stringify(cfg));
      return "ok";
    } catch (err) {
      return err.message;
    }
  };
  for (const cfg of configs) {
    const [host] = newPair("node-camel");
    // Every key in camelCase behaves exactly like the snake_case spelling.
    const snake = outcome(host, cfg);
    assert.equal(outcome(host, camelKeys(cfg)), snake, Object.keys(cfg).join(","));
    if ("p2p_api_secret" in cfg) {
      assert.match(snake, /p2p-iroh-services/);
    } else {
      assert.equal(snake, "ok");
    }
    for (const key of Object.keys(cfg)) {
      keys.add(key);
      assert.throws(
        () => host.configureTransportsJson(JSON.stringify({ [`${camel(key)}_`]: cfg[key] })),
        invalidArg,
        key
      );
    }
  }
  assert.equal(keys.size, 22, [...keys].join(","));
  const [host] = newPair("node-camel");
  assert.throws(
    () => host.configureTransportsJson(JSON.stringify({ relayAuthOrigins: ["not an origin"] })),
    invalidArg
  );
  assert.throws(
    () => host.configureTransportsJson(JSON.stringify({ routePolicy: "most" })),
    invalidArg
  );
});

test("camelCase advertising keys reach the announced set", async () => {
  const [host] = newPair("node-camel-adv");
  host.configureTransportsJson(
    JSON.stringify({ advertise: "explicit", advertisedEndpoints: ["192.0.2.9:7000"] })
  );
  const issued = await issue(host);
  assert.deepEqual(hints(issued.uri), ["direct:192.0.2.9:7000"]);
});

test("publishing waits on the state lock without stalling the JS thread", async () => {
  const [host, , dir] = newPair("node-lock");
  await host.serveDirect("127.0.0.1:0");
  await issue(host); // starts the announcer
  const holder = spawn(
    "python3",
    [
      "-c",
      "import fcntl,sys,time;f=open(sys.argv[1],'a+');" +
        "fcntl.flock(f,fcntl.LOCK_EX);print('held',flush=True);time.sleep(1.5)",
      `${dir}/host/.roster.lock`,
    ],
    { stdio: ["ignore", "pipe", "inherit"] }
  );
  const exited = new Promise((resolve) => holder.on("exit", resolve));
  await new Promise((resolve) => holder.stdout.once("data", resolve));
  const stamps = [];
  const ticker = setInterval(() => stamps.push(performance.now()), 10);
  try {
    await sleep(100);
    host.configureTransportsJson(
      JSON.stringify({ advertise: "explicit", advertisedEndpoints: ["192.0.2.9:7000"] })
    );
    const deadline = Date.now() + 10_000;
    while (holder.exitCode === null && Date.now() < deadline) {
      await sleep(25);
    }
    assert.notEqual(holder.exitCode, null, "the lock holder did not exit");
  } finally {
    clearInterval(ticker);
    await exited;
  }
  const gaps = stamps.slice(1).map((t, i) => t - stamps[i]);
  assert.ok(Math.max(...gaps) < 500, `the JS thread stalled for ${Math.max(...gaps)} ms`);
  // The detached publish ran once the lock was released: the roster holds the new set, with
  // no issuance or refresh to publish it for us.
  const published = () =>
    JSON.parse(fs.readFileSync(`${dir}/host/roster.json`, "utf8")).local_routes?.routes ?? [];
  for (let i = 0; i < 100 && !published().includes("direct:192.0.2.9:7000"); i += 1) {
    await sleep(50);
  }
  assert.ok(published().includes("direct:192.0.2.9:7000"), JSON.stringify(published()));
});

test("an issuance right after configureTransportsJson sees the new inputs", async () => {
  const [host] = newPair("node-order");
  await host.serveDirect("127.0.0.1:0");
  await host.refreshRoutes(null); // starts the announcer
  for (let i = 0; i < 3; i += 1) {
    const endpoint = `192.0.2.${10 + i}:7000`;
    host.configureTransportsJson(
      JSON.stringify({ advertise: "explicit", advertisedEndpoints: [endpoint] })
    );
    // The publish started by the configuration is settled, then this issuance runs on its
    // inputs: the new endpoint is announced and no earlier one is.
    const announced = hints((await issue(host)).uri);
    assert.ok(announced.includes(`direct:${endpoint}`), announced.join(","));
    assert.equal(announced.filter((h) => h.includes("192.0.2.")).length, 1, announced.join(","));
  }
});

test("issuing URIs while pairings run on a state-dir host completes", async () => {
  const [host] = newPair("node-lock-order");
  await host.serveDirect("127.0.0.1:0");
  const clients = Array.from({ length: 10 }, (_, i) => endpoint(null, `node-lock-cli-${i}`));
  let stop = false;
  let refusals = 0;
  // An issuance that fails after the publish (an empty host name is refused by the core
  // builder) takes no pairing code, so hammering it never fills the live-code cap, yet it keeps
  // the publish-then-issue path busy next to the pairings.
  const hammer = async () => {
    while (!stop) {
      await host.issuePairingUri(JSON.stringify({ host_name: "\u0001" })).catch(() => (refusals += 1));
    }
  };
  const pairings = async () => {
    for (let i = 0; i < clients.length; i += 1) {
      const { uri } = await issue(host);
      await pairOverUri(host, clients[i], uri, { v2: i % 2 === 1 });
    }
  };
  let timer;
  const deadlock = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("issuing and pairing deadlocked")), 90000);
  });
  const hammers = [hammer(), hammer(), hammer()];
  try {
    await Promise.race([pairings(), deadlock]);
  } finally {
    clearTimeout(timer);
    stop = true;
  }
  await Promise.race([Promise.all(hammers), sleep(10000).then(() => assert.fail("hammer stuck"))]);
  assert.ok(refusals > 0);
});
