import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  TendrilWebClient,
  classifyPairingCode,
  filterWebCompatibleEndpoints,
  initTendril,
  initTendrilP2p,
  parsePairingUri,
  relayAuthOriginAllowed,
} from "../src/index.js";
import { redactHint } from "../src/redact.js";
import {
  b64url,
  buildUri,
  deadPort,
  ed25519Key,
  liveHost,
  spawnPeer,
  spawnRelay,
} from "./live_peer.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = path.resolve(__dirname, "..");
const WASM_PATH = path.join(WEB_ROOT, "pkg", "tendril_wasm_bg.wasm");
const P2P_WASM_PATH = path.join(WEB_ROOT, "pkg-p2p", "tendril_wasm_bg.wasm");
const NO_BROWSER =
  /pairing URI contains no browser-compatible endpoints \(need iroh:\/\/ or wss:\/\/\)/;

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

/**
 * Counts WebSocket upgrades to `/v1/relay` and answers none of them. Other requests (for example
 * a host service probing new loopback listeners with `GET /`) are ignored, never counted.
 */
async function upgradeCounter() {
  let upgrades = 0;
  const server = net.createServer((sock) => {
    let head = "";
    sock.on("data", (chunk) => {
      head += chunk.toString("latin1");
      if (head.includes("\r\n\r\n")) {
        if (/^GET \/v1\/relay /.test(head) && /upgrade: websocket/i.test(head)) upgrades += 1;
        sock.destroy();
      }
    });
    sock.on("error", () => {});
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `ws://127.0.0.1:${server.address().port}/v1/relay`,
    count: () => upgrades,
    close: () => new Promise((r) => server.close(r)),
  };
}

/** Records the relay dial messages a client sends; every dial is refused after the challenge. */
function installFakeWebSocket() {
  const dials = [];
  const opened = [];
  const Original = globalThis.WebSocket;
  class FakeWebSocket extends EventTarget {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    constructor(url) {
      super();
      this.url = url;
      opened.push(url);
      this.readyState = FakeWebSocket.CONNECTING;
      this.binaryType = "blob";
      setTimeout(() => {
        this.readyState = FakeWebSocket.OPEN;
        this.dispatchEvent(new Event("open"));
        const host = new URL(url).hostname;
        this.#message({
          op: "challenge",
          host,
          nonce: b64url(crypto.randomBytes(32)),
          auth_required: ["dial"],
        });
      }, 0);
    }
    #message(obj) {
      const ev = new Event("message");
      ev.data = JSON.stringify(obj);
      this.dispatchEvent(ev);
    }
    send(data) {
      const msg = JSON.parse(data);
      dials.push({ url: this.url, msg });
      setTimeout(() => this.#message({ op: "error", code: "unauthorized" }), 0);
    }
    close() {
      if (this.readyState === FakeWebSocket.CLOSED) return;
      this.readyState = FakeWebSocket.CLOSED;
      setTimeout(() => this.dispatchEvent(new Event("close")), 0);
    }
  }
  globalThis.WebSocket = FakeWebSocket;
  return {
    dials,
    opened,
    restore() {
      globalThis.WebSocket = Original;
    },
  };
}

async function hostFixture(hostId = "uri-host") {
  const { WasmIdentity } = await import("../pkg/tendril_wasm.js");
  const id = WasmIdentity.generate(hostId);
  try {
    const info = JSON.parse(id.info_json());
    const persisted = JSON.parse(id.to_json());
    return { info, seedB64: persisted.signing_seed_b64 };
  } finally {
    id.free();
  }
}

async function clientWithActiveHost(host, extra = {}) {
  const { WasmRoster } = await import("../pkg/tendril_wasm.js");
  const roster = new WasmRoster();
  try {
    roster.insert_pinned_host(
      host.info.host_id,
      host.info.host_id,
      host.info.static_pub,
      host.info.signing_pub,
      0,
      extra.relayHintsJson ?? null
    );
    return await TendrilWebClient.create({
      hostId: "uri-client",
      rosterBytes: roster.to_json_bytes(),
      ...extra.options,
    });
  } finally {
    roster.free();
  }
}

test("signing fixture: the identity signing seed is the Ed25519 key of rp", async () => {
  await ensureWasm();
  const host = await hostFixture();
  const pub = crypto
    .createPublicKey(ed25519Key(host.seedB64))
    .export({ format: "der", type: "spki" });
  assert.equal(b64url(pub.subarray(-32)), host.info.relay_pub);
});

test("parsePairingUri reports providers, rp, rq and whether the URI is signed", async () => {
  await ensureWasm();
  const host = await hostFixture();
  const common = {
    code: "TND-ABCD-EFGH-JKLM",
    k: host.info.static_pub,
    sh: host.info.signing_pub_hash,
    rp: host.info.relay_pub,
    ep: ["wss://relay.example/v1/relay", "direct:192.0.2.1:7000"],
  };
  const signed = parsePairingUri(buildUri({ ...common, rq: 7, seedB64: host.seedB64 }));
  assert.deepEqual(signed.providers, ["relay", "direct"]);
  assert.equal(signed.relay_pub_b64, host.info.relay_pub);
  assert.equal(signed.route_seq, 7);
  assert.equal(signed.route_signed, true);
  const unsigned = parsePairingUri(buildUri(common));
  assert.equal(unsigned.route_signed, false);
  assert.equal(unsigned.route_seq, null);
  assert.throws(() => parsePairingUri("tendril://pair?v=1"), Error);
});

test("filterWebCompatibleEndpoints keeps iroh with p2p, wss, loopback ws, in provider order", () => {
  const id = "a".repeat(64);
  const hints = [
    "wss://relay.example/v1/relay",
    `iroh://${id}?relay=https://r.example/&addr=192.0.2.1:4433`,
    "direct:192.0.2.1:7000",
    "overlay://100.64.0.2:7000",
    "broker+wss://broker.example/b",
    "wss://relay.example/v2/relay",
    "wss://relay.example/x/../v2/relay",
    "local:/tmp/sock",
    "unix:///tmp/sock",
    "ws://192.0.2.9/v1/relay",
    "ws://127.0.0.1:9/v1/relay",
    "wss://169.254.169.254/v1/relay",
  ];
  const { candidates, skipped } = filterWebCompatibleEndpoints(hints, { p2p: true });
  assert.deepEqual(candidates, [
    { hint: hints[1], endpoint: `iroh://${id}?addr=192.0.2.1:4433`, provider: "p2p" },
    { hint: hints[0], endpoint: hints[0], provider: "relay" },
    { hint: hints[10], endpoint: hints[10], provider: "relay" },
    { hint: hints[4], endpoint: "wss://broker.example/b", provider: "broker" },
  ]);
  assert.deepEqual(Object.fromEntries(skipped.map((s) => [s.hint, s.reason])), {
    [hints[2]]: "browser_unsupported",
    [hints[3]]: "browser_unsupported",
    [hints[5]]: "relay_v2_not_authorized",
    [hints[6]]: "relay_v2_not_authorized",
    [hints[7]]: "ipc_from_uri",
    [hints[8]]: "ipc_from_uri",
    [hints[9]]: "insecure_ws",
    [hints[11]]: "blocked_address",
  });

  const brokerWsInsecure = filterWebCompatibleEndpoints(["broker+ws://broker.example/b"], {
    allowInsecureWs: true,
  });
  assert.deepEqual(brokerWsInsecure.candidates, [
    {
      hint: "broker+ws://broker.example/b",
      endpoint: "ws://broker.example/b",
      provider: "broker",
    },
  ]);
  assert.throws(
    () => filterWebCompatibleEndpoints(["broker+ws://broker.example/b"]),
    (err) =>
      NO_BROWSER.test(err.message) &&
      err.skipped.length === 1 &&
      err.skipped[0].reason === "insecure_ws"
  );
  assert.deepEqual(
    filterWebCompatibleEndpoints(["broker+ws://127.0.0.1:8080/b"]).candidates,
    [
      {
        hint: "broker+ws://127.0.0.1:8080/b",
        endpoint: "ws://127.0.0.1:8080/b",
        provider: "broker",
      },
    ]
  );

  const noP2p = filterWebCompatibleEndpoints(hints.slice(0, 2));
  assert.deepEqual(
    noP2p.candidates.map((c) => c.provider),
    ["relay"]
  );
  assert.equal(noP2p.skipped[0].reason, "p2p_feature_disabled");
  assert.equal(
    filterWebCompatibleEndpoints(["ws://192.0.2.9/v1/relay"], { allowInsecureWs: true }).candidates
      .length,
    1
  );
  assert.equal(
    filterWebCompatibleEndpoints([`iroh://${id}?relay=https://r.example/`], { p2p: true })
      .candidates[0].endpoint,
    `iroh://${id}`
  );
  assert.throws(
    () => filterWebCompatibleEndpoints(["direct:192.0.2.1:7000", "local:/x"]),
    (err) => NO_BROWSER.test(err.message) && err.skipped.length === 2
  );
});

test("redactHint keeps only ws(s) standard hosts, host:port hints and iroh ids", () => {
  const id = "ab".repeat(32);
  const kept = [
    ["direct:192.0.2.1:7000", "direct:192.0.2.1:7000"],
    ["overlay://[fd7a::1]:9100", "overlay://[fd7a::1]:9100"],
    ["wss://relay.example.com/v1/relay?tok=secret", "wss://relay.example.com"],
    ["WSS://Relay.Example.com:8443/v2/relay", "wss://relay.example.com:8443"],
    ["wss://relay-host.example.com/v1/relay", "wss://relay-host.example.com"],
    ["ws://127.0.0.1:9000/v1/relay#key", "ws://127.0.0.1:9000"],
    ["relay:wss://relay.example.com/v1/relay", "relay:wss://relay.example.com"],
    ["broker+wss://broker.example.com/x?y=z", "broker+wss://broker.example.com"],
    [`iroh://${id}?relay=https://r.example/&addr=192.0.2.1:4433`, `iroh://${id}`],
    [`p2p:iroh://${id.toUpperCase()}`, `p2p:iroh://${id}`],
  ];
  for (const [hint, want] of kept) {
    assert.equal(redactHint(hint), want, hint);
  }
  for (const hint of [
    "iroh://code=TND-ABCD-EFGH-JKLM&tok=secret",
    `iroh://${id}x`,
    "foo://TND-ABCD-EFGH",
    "foo://opaque-host/secret",
    "https://relay.example.com/v1/relay",
    "wss://user:pw@relay.example.com/v1/relay",
    "wss://tnd-abcd-efgh-jklm.example/v1/relay",
    "wss://abcd-efgh.x/",
    "relay:wss://Ab12-cd34.example/v1/relay",
    "direct:abcd-efgh:9",
    "overlay://node-abcd-efgh.ts.net:9100",
    "wss://relay.example.com\u00e9/x",
    "broker+iroh://" + id,
    "p2p:wss://relay.example.com/v1/relay",
    "direct:192.0.2.1:7000?tok=secret",
    "local:/run/tendril.sock",
    "not a url",
  ]) {
    assert.equal(redactHint(hint), "<redacted>", hint);
  }
});

test("classifyPairingCode and relayAuthOriginAllowed call the core rules", async () => {
  await ensureWasm();
  assert.equal(classifyPairingCode("TND-ABCD-EFGH"), "lan2_group");
  assert.equal(classifyPairingCode("TND-ABCD-EFGH-JKLM"), "remote3_group");
  assert.throws(
    () => classifyPairingCode("1234-5678"),
    (err) => err.code === "pairing_code_invalid"
  );
  assert.equal(
    relayAuthOriginAllowed("wss://relay.example/v1/relay", ["wss://relay.example:443"]),
    true
  );
  assert.equal(
    relayAuthOriginAllowed("wss://relay.example:8443/v1/relay", ["wss://relay.example"]),
    false
  );
  assert.equal(
    relayAuthOriginAllowed("wss://other.example/v1/relay", ["wss://relay.example"]),
    false
  );
  assert.throws(
    () => relayAuthOriginAllowed("wss://relay.example/", "wss://relay.example"),
    TypeError
  );
});

test("pair rejects malformed and 2-group codes, and URIs without browser routes, with zero dials", async () => {
  await ensureWasm();
  const host = await hostFixture();
  const counter = await upgradeCounter();
  const client = await TendrilWebClient.create({ hostId: "uri-zero-dial" });
  try {
    await assert.rejects(
      () =>
        client.pair({ relayUrl: counter.url, targetPub: host.info.relay_pub, code: "1234-5678" }),
      (err) => err.code === "pairing_code_invalid"
    );
    await assert.rejects(
      () => client.pairV2({ relayUrl: counter.url, code: new TextEncoder().encode("bad") }),
      (err) => err.code === "pairing_code_invalid"
    );
    await assert.rejects(
      () =>
        client.pair({
          relayUrl: counter.url,
          targetPub: host.info.relay_pub,
          code: "TND-ABCD-EFGH",
        }),
      (err) => err.code === "pairing_path_disallowed"
    );
    const lanUri = buildUri({
      code: "TND-ABCD-EFGH",
      k: host.info.static_pub,
      sh: host.info.signing_pub_hash,
      ep: ["direct:127.0.0.1:7000"],
    });
    await assert.rejects(
      () => client.pairV2({ pairingUri: lanUri }),
      (err) => err.code === "pairing_path_disallowed"
    );
    const directOnly = buildUri({
      code: "TND-ABCD-EFGH-JKLM",
      k: host.info.static_pub,
      sh: host.info.signing_pub_hash,
      ep: ["direct:192.0.2.1:7000", "overlay://100.64.0.2:7000"],
    });
    await assert.rejects(() => client.pair({ pairingUri: directOnly }), NO_BROWSER);
    await assert.rejects(
      () =>
        client.pair({
          pairingUri: directOnly,
          code: "TND-ABCD-EFGH-JKLM",
          saveRoute: true,
          routePolicy: "none",
        }),
      /saveRoute conflicts with routePolicy none/
    );
    assert.equal(counter.count(), 0);
    assert.equal(client.getPeer(host.info.host_id), null);
  } finally {
    client.free();
    await counter.close();
  }
});

test("relay credentials reach URI relays only when their origin is configured", async () => {
  await ensureWasm();
  const host = await hostFixture();
  const fake = installFakeWebSocket();
  const client = await TendrilWebClient.create({ hostId: "uri-d14" });
  try {
    const uri = buildUri({
      code: "TND-ABCD-EFGH-JKLM",
      k: host.info.static_pub,
      sh: host.info.signing_pub_hash,
      rp: host.info.relay_pub,
      ep: ["wss://relay-a.example/v1/relay", "wss://relay-b.example:8443/v1/relay"],
    });
    const secret = new Uint8Array(32).fill(7);
    let failures = null;
    await assert.rejects(
      () =>
        client.pair({
          pairingUri: uri,
          relayAuthSecret: secret,
          relayAuthOrigins: ["wss://relay-b.example:8443"],
          timeoutMs: 5000,
        }),
      (err) => {
        failures = err.failures;
        return err.committed === false;
      }
    );
    assert.equal(
      secret.every((b) => b === 0),
      true,
      "caller secret must be zeroized"
    );
    assert.deepEqual(
      fake.opened.map((u) => new URL(u).host),
      ["relay-a.example", "relay-b.example:8443"]
    );
    assert.match(failures[0].error, /^relay_auth_unconfigured: /);
    assert.deepEqual(
      fake.dials.map((d) => [new URL(d.url).host, d.msg.auth?.kind ?? null]),
      [["relay-b.example:8443", "hmac"]]
    );
    assert.equal(fake.dials[0].msg.target_pub, host.info.relay_pub);

    fake.dials.length = 0;
    await assert.rejects(() =>
      client.pair({
        relayUrl: "wss://relay-c.example/v1/relay",
        targetPub: host.info.relay_pub,
        code: "TND-ABCD-EFGH-JKLM",
        relayAuthTicket: JSON.stringify({ v: 1 }),
        timeoutMs: 5000,
      })
    );
    assert.equal(
      fake.dials[0].msg.auth?.kind,
      "ticket",
      "the explicit relayUrl always gets credentials"
    );
  } finally {
    fake.restore();
    client.free();
  }
});

test("explicit pairing rejects /v2/relay before dialing and dials a URL#key relay with that key", async () => {
  await ensureWasm();
  const host = await hostFixture();
  const fake = installFakeWebSocket();
  const client = await TendrilWebClient.create({ hostId: "uri-explicit-key" });
  try {
    const key = host.info.relay_pub;
    for (const relayUrl of [
      "wss://relay-c.example/v2/relay",
      `wss://relay-c.example/v2/relay#${key}`,
      "WSS://relay-c.example/v2/relay",
      `Wss://relay-c.example/v2/relay#${key}`,
    ]) {
      await assert.rejects(
        () => client.pair({ relayUrl, code: "TND-ABCD-EFGH-JKLM" }),
        /\/v2\/relay is not used for pairing; pair over another route, then use connectV2/
      );
    }
    assert.deepEqual(fake.opened, []);
    await assert.rejects(() =>
      client.pair({
        relayUrl: `wss://relay-c.example/v1/relay#${key}`,
        targetPub: b64url(crypto.randomBytes(32)),
        code: "TND-ABCD-EFGH-JKLM",
        relayAuthTicket: JSON.stringify({ v: 1 }),
        timeoutMs: 5000,
      })
    );
    assert.deepEqual(fake.opened, ["wss://relay-c.example/v1/relay"]);
    assert.equal(fake.dials[0].msg.target_pub, key);
    // URL schemes are case-insensitive: an upper-case `URL#key` is split the same way.
    await assert.rejects(() =>
      client.pair({
        relayUrl: `WSS://relay-c.example/v1/relay#${key}`,
        targetPub: b64url(crypto.randomBytes(32)),
        code: "TND-ABCD-EFGH-JKLM",
        relayAuthTicket: JSON.stringify({ v: 1 }),
        timeoutMs: 5000,
      })
    );
    assert.equal(fake.opened.length, 2);
    assert.equal(fake.opened[1], "wss://relay-c.example/v1/relay");
    assert.equal(fake.dials[1].msg.target_pub, key);
  } finally {
    fake.restore();
    client.free();
  }
});

test("live: an explicit URL#key pairing reaches the key's mailbox and stores the relay once", async () => {
  await ensureWasm();
  const host = await liveHost("explicit-key-host");
  const { relay, peer, fields } = host;
  const client = await TendrilWebClient.create({ hostId: "explicit-key-client" });
  try {
    const peerPair = peer.call({ op: "pair" });
    const paired = await client.pair({
      relayUrl: `${relay.wsUrl}#${fields.rp}`,
      code: fields.code,
    });
    await peerPair;
    assert.deepEqual(paired.routes_persisted, [{ hint: relay.wsUrl, source: "operator" }]);
    assert.deepEqual(client.peerRoutes(paired.host_id).routes, [
      { hint: relay.wsUrl, source: "operator" },
    ]);
  } finally {
    client.free();
    host.close();
  }
});

test("applyRouteUri applies signed routes offline and the route setters persist", async () => {
  await ensureWasm();
  const host = await hostFixture();
  const persisted = [];
  const client = await clientWithActiveHost(host, {
    options: { onPersistRoster: async (json) => persisted.push(JSON.parse(json)) },
  });
  const peerId = host.info.host_id;
  try {
    assert.deepEqual(client.getPeer(peerId).routes, []);
    const signedUri = (rq, ep) =>
      buildUri({
        code: "TND-ABCD-EFGH-JKLM",
        k: host.info.static_pub,
        sh: host.info.signing_pub_hash,
        rp: host.info.relay_pub,
        ep,
        rq,
        seedB64: host.seedB64,
      });
    const applied = await client.applyRouteUri(
      signedUri(4, ["wss://relay.example/v1/relay", "direct:192.0.2.1:7000"])
    );
    assert.equal(applied.applied, true);
    assert.deepEqual(applied.routes, [
      { hint: "wss://relay.example/v1/relay", source: "signed" },
      { hint: "direct:192.0.2.1:7000", source: "signed" },
    ]);
    assert.equal(client.peerRoutes(peerId).route_meta.seq, 4);
    const stale = await client.applyRouteUri(signedUri(3, ["wss://old.example/v1/relay"]));
    assert.equal(stale.applied, false);
    assert.equal(stale.reason, "stale_route_seq");
    const approved = await client.applyRouteUri(signedUri(3, ["wss://old.example/v1/relay"]), {
      replaceRoutes: true,
    });
    assert.equal(approved.applied, true);
    await assert.rejects(
      () =>
        client.applyRouteUri(
          buildUri({
            code: "TND-ABCD-EFGH-JKLM",
            k: host.info.static_pub,
            sh: host.info.signing_pub_hash,
            ep: ["direct:192.0.2.1:7000"],
          })
        ),
      (err) => err.code === "invalid_pairing_uri" && /not host-signed/.test(err.message)
    );

    const routes = await client.setPeerRoutes(peerId, ["wss://mine.example/v1/relay"]);
    assert.ok(
      routes.some((r) => r.hint === "wss://mine.example/v1/relay" && r.source === "operator")
    );
    await assert.rejects(
      () => client.setPeerRoutes(peerId, ["wss://169.254.169.254/v1/relay"]),
      (err) => err.code === "invalid_pairing_uri" && !err.message.includes("169.254")
    );
    await client.clearPeerRoutes(peerId, "signed");
    assert.deepEqual(client.peerRoutes(peerId).routes, [
      { hint: "wss://mine.example/v1/relay", source: "operator" },
    ]);
    await client.clearPeerRoutes(peerId);
    assert.deepEqual(client.peerRoutes(peerId).routes, []);
    assert.equal(persisted.length, 5, "every successful route mutation persists once");
  } finally {
    client.free();
  }
});

/** Replaces the `pkg-p2p` dial exports with stubs that record their arguments and refuse. */
async function stubIrohDials() {
  const p2p = await import("../pkg-p2p/tendril_wasm.js");
  await initTendrilP2p({ module_or_path: fs.readFileSync(P2P_WASM_PATH) });
  const calls = [];
  const { dial, dial_with_options: dialWithOptions } = p2p.WasmIrohStream;
  p2p.WasmIrohStream.dial = async (...args) => {
    calls.push({ endpoint: args[0], hint: args[3] });
    throw new Error("stub iroh dial refused");
  };
  p2p.WasmIrohStream.dial_with_options = async (...args) => {
    calls.push({ endpoint: args[0], hint: args[4] });
    throw new Error("stub iroh dial refused");
  };
  return {
    calls,
    restore() {
      p2p.WasmIrohStream.dial = dial;
      p2p.WasmIrohStream.dial_with_options = dialWithOptions;
    },
  };
}

test("iroh hints dial lookup-free; operator iroh endpoints keep relay= and lookup", async () => {
  await ensureWasm();
  const stub = await stubIrohDials();
  const host = await hostFixture("uri-iroh-host");
  const peerId = host.info.host_id;
  const nodeId = "a".repeat(64);
  const signedUri = (ep, rq = 2) =>
    buildUri({
      code: "TND-ABCD-EFGH-JKLM",
      k: host.info.static_pub,
      sh: host.info.signing_pub_hash,
      ep,
      rq,
      seedB64: host.seedB64,
    });
  const pairer = await TendrilWebClient.create({ hostId: "uri-iroh-pairer" });
  const client = await clientWithActiveHost(host);
  try {
    await assert.rejects(() =>
      pairer.pair({
        pairingUri: signedUri([`iroh://${nodeId}?relay=https://r.example/`]),
        timeoutMs: 2000,
      })
    );
    const operator = `iroh://${nodeId}?relay=https://op.example/`;
    await assert.rejects(() =>
      pairer.pair({ endpoint: operator, code: "TND-ABCD-EFGH-JKLM", timeoutMs: 2000 })
    );
    assert.deepEqual(stub.calls.splice(0), [
      { endpoint: `iroh://${nodeId}`, hint: true },
      { endpoint: operator, hint: false },
    ]);

    await client.setPeerRoutes(peerId, [operator]);
    await assert.rejects(() => client.connect({ targetHostId: peerId, timeoutMs: 2000 }));
    assert.deepEqual(stub.calls.splice(0), [{ endpoint: operator, hint: false }]);

    await client.clearPeerRoutes(peerId);
    const applied = await client.applyRouteUri(
      signedUri([`iroh://${nodeId}?relay=https://r.example/`], 5)
    );
    assert.equal(applied.applied, true);
    await assert.rejects(() => client.connect({ targetHostId: peerId, timeoutMs: 2000 }));
    assert.deepEqual(stub.calls.splice(0), [{ endpoint: `iroh://${nodeId}`, hint: true }]);
  } finally {
    stub.restore();
    pairer.free();
    client.free();
  }
});

test("endpoint-free connect skips off-loopback ws:// stored routes as insecure_ws", async () => {
  await ensureWasm();
  const host = await hostFixture("uri-insecure-host");
  const peerId = host.info.host_id;
  const loopback = "ws://127.0.0.1:9/v1/relay";
  const insecure = "ws://relay.example.net:9/v1/relay";
  // Pairing URIs and route setters refuse an off-loopback ws:// route; a roster written
  // elsewhere can still hold one, and connect reports it as insecure_ws without dialing.
  const seed = await clientWithActiveHost(host);
  let rosterJson;
  try {
    await seed.setPeerRoutes(peerId, [loopback]);
    rosterJson = seed.exportRosterJson().replaceAll(loopback, insecure);
  } finally {
    seed.free();
  }
  const fake = installFakeWebSocket();
  const client = await TendrilWebClient.create({
    hostId: "uri-client",
    rosterBytes: new TextEncoder().encode(rosterJson),
  });
  try {
    assert.deepEqual(client.peerRoutes(peerId).routes, [{ hint: insecure, source: "operator" }]);
    await assert.rejects(
      () => client.connect({ targetHostId: peerId, timeoutMs: 2000 }),
      (err) =>
        err.skipped.some((s) => s.hint === insecure && s.reason === "insecure_ws") &&
        (err.failures ?? []).length === 0
    );
    assert.equal(fake.opened.length, 0);
  } finally {
    fake.restore();
    client.free();
  }
});

test("live: a URI pairing tries routes in order, aborts on a bad rs, persists signed routes, and connects endpoint-free", async () => {
  await ensureWasm();
  const relay = await spawnRelay();
  const peer = spawnPeer();
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "tendril-web-uri-"));
  try {
    const peerInit = await peer.call({ op: "init", state_dir: stateDir, host_id: "uri-live-host" });
    const seedB64 = JSON.parse(
      fs.readFileSync(path.join(stateDir, "identity.json"), "utf8")
    ).signing_seed_b64;
    await peer.call({ op: "serve_relay", relay_url: relay.wsUrl, expected_host: "127.0.0.1" });
    const code = (await peer.call({ op: "issue_code", kind: "remote" })).code;
    const dead = `ws://127.0.0.1:${await deadPort()}/v1/relay`;
    const ep = [dead, relay.wsUrl, "direct:127.0.0.1:9"];
    const uriFields = {
      host: "uri-live-host",
      code,
      k: peerInit.static_pub,
      sh: peerInit.signing_pub_hash,
      id: "uri-live-host",
      rp: peerInit.relay_pub,
      ep,
      rq: 3,
    };
    const dead2 = `ws://127.0.0.1:${await deadPort()}/v1/relay`;
    const forged = buildUri({
      ...uriFields,
      ep: [dead, relay.wsUrl, dead2],
      seedB64: b64url(crypto.randomBytes(32)),
    });
    const signed = buildUri({ ...uriFields, seedB64 });

    let persists = 0;
    const client = await TendrilWebClient.create({
      hostId: "uri-live-client",
      onPersistRoster: async () => {
        persists += 1;
      },
    });
    try {
      // An invalid route statement aborts before msg3: nothing persisted, the code stays live.
      peer.send({ op: "pair" });
      await assert.rejects(
        () => client.pair({ pairingUri: forged }),
        (err) =>
          err.code === "invalid_pairing_uri" &&
          /route statement does not verify/.test(err.message) &&
          err.committed === false &&
          err.failures.length === 1 &&
          err.failures[0].hint === dead
      );
      assert.equal((await peer.recv()).ok, false);
      assert.equal(client.getPeer("uri-live-host"), null);
      assert.equal(persists, 0);

      const peerPair = peer.call({ op: "pair" });
      const paired = await client.pair({ pairingUri: signed, deviceName: "uri-web" });
      const hostPair = await peerPair;
      assert.equal(paired.sas, hostPair.sas);
      assert.equal(paired.host_confirmed, true);
      assert.equal(paired.route_check, "verified");
      assert.deepEqual(paired.route, {
        hint: relay.wsUrl,
        endpoint: relay.wsUrl,
        provider: "relay",
      });
      assert.deepEqual(
        paired.failures.map((f) => f.hint),
        [dead]
      );
      assert.deepEqual(paired.skipped, [
        { hint: "direct:127.0.0.1:9", reason: "browser_unsupported" },
      ]);
      assert.deepEqual(
        paired.routes_persisted.map((r) => [r.hint, r.source]),
        ep.map((h) => [h, "signed"])
      );
      assert.equal(client.getPeer("uri-live-host").route_meta.seq, 3);
      assert.equal(persists, 1);

      await peer.call({ op: "confirm", peer_id: hostPair.device_id, sas: hostPair.sas });
      const grant = (
        await peer.call({ op: "mint", peer_id: hostPair.device_id, caps: ["fs.read"] })
      ).grant;

      // Endpoint-free Day-2 connect: the stored dead relay fails, the live one wins.
      const peerConnect = peer.call({ op: "connect" });
      const session = await client.connect({
        targetHostId: "uri-live-host",
        grantJson: JSON.stringify(grant),
      });
      await peerConnect;
      assert.equal(session.isEstablished(), true);
      assert.equal(session.route.endpoint, relay.wsUrl);
      assert.deepEqual(
        session.failures.map((f) => f.hint),
        [dead]
      );
      assert.equal(session.authorize("fs.read"), true);
      await session.sendData("hello-stored-route");
      assert.equal(
        (await peer.call({ op: "recv", timeout_ms: 2000 })).data_utf8,
        "hello-stored-route"
      );
      await session.close(1000, "done");
      await peer.call({ op: "recv", timeout_ms: 2000 });

      // With every stored route dead the error is typed and lists the recovery paths.
      await client.setPeerRoutes("uri-live-host", []);
      await client.clearPeerRoutes("uri-live-host", "signed");
      await assert.rejects(
        () => client.connect({ targetHostId: "uri-live-host", grantJson: JSON.stringify(grant) }),
        /no dialable stored routes for uri-live-host; advertise a configured relay as a stable route/
      );
    } finally {
      client.free();
    }

    // An unsigned URI stores nothing by default and the committed route with saveRoute.
    const unsigned = buildUri({ ...uriFields, ep: [relay.wsUrl], rq: null });
    for (const saveRoute of [false, true]) {
      const c = await TendrilWebClient.create({ hostId: `uri-unsigned-${saveRoute}` });
      try {
        const freshCode = (await peer.call({ op: "issue_code", kind: "remote" })).code;
        const pp = peer.call({ op: "pair" });
        const res = await c.pair({ pairingUri: unsigned, code: freshCode, saveRoute });
        await pp;
        assert.equal(res.route_check, "unsigned");
        assert.deepEqual(
          res.routes_persisted,
          saveRoute ? [{ hint: relay.wsUrl, source: "committed" }] : []
        );
        if (!saveRoute) assert.equal(res.routes_reason, "unsigned_uri");
      } finally {
        c.free();
      }
    }
  } finally {
    peer.close();
    relay.child.kill();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});


test("live: pairing checks rp before rs and ranks failures by error code", async () => {
  await ensureWasm();
  const { WasmPairInitiator } = await import("../pkg/tendril_wasm.js");
  const host = await liveHost("rank-host");
  const { relay, peer, fields } = host;
  const realFeed = WasmPairInitiator.prototype.feed_bytes;
  let forge = null;
  WasmPairInitiator.prototype.feed_bytes = function (bytes, roster) {
    const out = realFeed.call(this, bytes, roster);
    const res = JSON.parse(out);
    return res.host_verified && forge ? JSON.stringify({ ...res, ...forge }) : out;
  };
  const client = await TendrilWebClient.create({ hostId: "rank-client" });
  try {
    // A transport failure first, then an rp mismatch: exhaustion reports the rp mismatch.
    const dead = `ws://127.0.0.1:${await deadPort()}/v1/relay`;
    forge = { relay_pub_ok: false };
    peer.send({ op: "pair" });
    await assert.rejects(
      () => client.pair({ pairingUri: buildUri({ ...fields, ep: [dead, relay.wsUrl] }) }),
      (err) =>
        err.code === "host_key_unverified" &&
        err.committed === false &&
        err.failures.map((f) => f.hint).join(",") === `${dead},${relay.wsUrl}`
    );
    assert.equal((await peer.recv()).ok, false);

    // A wrong rp and an invalid statement on one candidate: rp ranks first, so the next
    // candidate is still tried instead of aborting.
    const dead2 = `ws://127.0.0.1:${await deadPort()}/v1/relay`;
    forge = { relay_pub_ok: false, route_check: "invalid" };
    peer.send({ op: "pair" });
    await assert.rejects(
      () => client.pair({ pairingUri: buildUri({ ...fields, ep: [relay.wsUrl, dead2] }) }),
      (err) =>
        err.code === "host_key_unverified" &&
        err.failures.map((f) => f.hint).join(",") === `${relay.wsUrl},${dead2}`
    );
    assert.equal((await peer.recv()).ok, false);

    // An invalid statement alone is fatal and coded.
    forge = { route_check: "invalid" };
    peer.send({ op: "pair" });
    await assert.rejects(
      () => client.pair({ pairingUri: buildUri({ ...fields, ep: [relay.wsUrl, dead2] }) }),
      (err) => err.code === "invalid_pairing_uri" && err.failures.length === 0
    );
    assert.equal((await peer.recv()).ok, false);
  } finally {
    WasmPairInitiator.prototype.feed_bytes = realFeed;
    client.free();
    host.close();
  }
});

test("live: explicit connect binds the recovery rp, keeps persistence fail-closed, and rate-limits route sets inside the lock", async () => {
  await ensureWasm();
  const { WasmRoster, WasmSessionClient } = await import("../pkg/tendril_wasm.js");
  const host = await liveHost("explicit-host");
  const { relay, peer, fields, seedB64 } = host;
  const hostId = fields.id;
  let persists = 0;
  let failAt = null;
  let gate = null;
  const client = await TendrilWebClient.create({
    hostId: "explicit-client",
    onPersistRoster: async () => {
      persists += 1;
      if (gate) await gate;
      if (persists === failAt) throw new Error("disk full");
    },
  });
  const realNow = performance.now;
  const realFeed = WasmSessionClient.prototype.feed_bytes;
  const realTake = WasmSessionClient.prototype.take_route_sets;
  const realApply = WasmRoster.prototype.apply_route_announcement;
  try {
    const peerPair = peer.call({ op: "pair" });
    await client.pair({ pairingUri: buildUri({ ...fields, ep: [relay.wsUrl], rq: 3, seedB64 }) });
    const hostPair = await peerPair;
    await peer.call({ op: "confirm", peer_id: hostPair.device_id, sas: hostPair.sas });
    const grantJson = JSON.stringify(
      (await peer.call({ op: "mint", peer_id: hostPair.device_id, caps: ["fs.read"] })).grant
    );
    const explicit = async (extra) => {
      const peerConnect = peer.call({ op: "connect" });
      const session = await client.connect({
        relayUrl: relay.wsUrl,
        targetHostId: hostId,
        grantJson,
        ...extra,
      });
      await peerConnect;
      return session;
    };

    // The recovery URI's rp names the mailbox: no targetPub, or a stale one, still reaches it.
    const recovery = buildUri({ ...fields, ep: [relay.wsUrl], rq: 5, seedB64 });
    for (const targetPub of [null, b64url(crypto.randomBytes(32))]) {
      const session = await explicit({ recoveryUri: recovery, targetPub, timeoutMs: 5000 });
      assert.equal(session.isEstablished(), true);
      await session.close(1000, "done");
      await peer.call({ op: "recv", timeout_ms: 2000 });
    }
    assert.equal(client.getPeer(hostId).route_meta.seq, 5);

    // A failed persist of recovery routes rolls the route change back; the client stays usable.
    // The handshake itself changed nothing, so the recovery routes are the first persist.
    const newRelay = "wss://new.example.test/v1/relay";
    const moved = buildUri({ ...fields, ep: [relay.wsUrl, newRelay], rq: 9, seedB64 });
    failAt = persists + 1;
    const peerConnect = peer.call({ op: "connect" });
    await assert.rejects(
      () =>
        client.connect({
          relayUrl: relay.wsUrl,
          targetHostId: hostId,
          grantJson,
          recoveryUri: moved,
        }),
      /disk full/
    );
    await peerConnect;
    await peer.call({ op: "recv", timeout_ms: 2000 }).catch(() => {});
    failAt = null;
    const view = client.getPeer(hostId);
    assert.equal(view.route_meta.seq, 5);
    assert.equal(
      view.routes.some((r) => r.hint === newRelay),
      false
    );
    await client.setPeerRoutes(hostId, []);

    // Route sets: the 10 s limit is checked and stamped inside the roster critical section, so
    // a lock held past the window cannot let two sets through back to back.
    const session = await explicit({ targetPub: fields.rp });
    let applied = 0;
    let kick = null;
    let release = null;
    WasmSessionClient.prototype.take_route_sets = function () {
      realTake.call(this);
      if (kick) {
        const k = kick;
        kick = null;
        k();
      }
      return JSON.stringify(["AA"]);
    };
    WasmRoster.prototype.apply_route_announcement = function () {
      applied += 1;
      return JSON.stringify({ outcome: "applied", added: [], removed: [] });
    };
    let skew = 0;
    performance.now = () => realNow.call(performance) + skew;
    let held = null;
    gate = new Promise((r) => {
      release = r;
    });
    kick = () => {
      held = client.setPeerRoutes(hostId, []);
    };
    await peer.call({ op: "send", data_utf8: "first" });
    const first = session.pollEvent(5000);
    await delay(100);
    skew += 11000;
    gate = null;
    release();
    await held;
    assert.equal((await first).status, "event");
    assert.equal(applied, 1);
    await peer.call({ op: "send", data_utf8: "second" });
    assert.equal((await session.pollEvent(5000)).status, "event");
    assert.equal(applied, 1);
    assert.deepEqual(session.lastRouteSet, { outcome: "ignored", reason: "rate_limited" });
    WasmSessionClient.prototype.take_route_sets = realTake;
    WasmRoster.prototype.apply_route_announcement = realApply;
    performance.now = realNow;
    await session.close(1000, "done");
    await peer.call({ op: "recv", timeout_ms: 2000 });

    // A connect that changes nothing persists nothing.
    const quiet = persists;
    const plain = await explicit({ targetPub: fields.rp });
    assert.equal(persists, quiet);
    await plain.close(1000, "done");
    await peer.call({ op: "recv", timeout_ms: 2000 });

    // A failed persist of handshake evidence fails the client closed. The stub stands in for
    // evidence the handshake wrote to the roster.
    const anchor = await hostFixture("explicit-evidence");
    WasmSessionClient.prototype.feed_bytes = function (bytes, now, elapsed, roster) {
      const out = realFeed.call(this, bytes, now, elapsed, roster);
      if (JSON.parse(out).established) {
        roster.add_trust_anchor("handshake-evidence", anchor.info.signing_pub);
      }
      return out;
    };
    failAt = persists + 1;
    const peerConnect2 = peer.call({ op: "connect" });
    await assert.rejects(
      () =>
        client.connect({
          relayUrl: relay.wsUrl,
          targetPub: fields.rp,
          targetHostId: hostId,
          grantJson,
        }),
      /disk full/
    );
    await peerConnect2.catch(() => {});
    await assert.rejects(
      () => client.setPeerRoutes(hostId, []),
      /client locked after roster persistence failure/
    );
  } finally {
    WasmSessionClient.prototype.feed_bytes = realFeed;
    WasmSessionClient.prototype.take_route_sets = realTake;
    WasmRoster.prototype.apply_route_announcement = realApply;
    performance.now = realNow;
    client.free();
    host.close();
  }
});

test("session_candidates ranks /v2/relay ahead of /v1/relay and admits broker with allowInsecureWs", async () => {
  await ensureWasm();
  const { WasmRoster } = await import("../pkg/tendril_wasm.js");
  const host = await hostFixture("v2-rank-host");
  const roster = new WasmRoster();
  try {
    roster.insert_pinned_host(
      host.info.host_id,
      host.info.host_id,
      host.info.static_pub,
      host.info.signing_pub,
      0,
      null
    );
    const json = JSON.parse(roster.to_json());
    json.entries[host.info.host_id].v2_secrets = {
      mailbox_secret: b64url(crypto.randomBytes(32)),
      reconnect_secret: b64url(crypto.randomBytes(32)),
    };
    json.entries[host.info.host_id].routes = [
      { hint: "wss://198.51.100.10/v1/relay", source: "operator" },
      { hint: "wss://dns.example.test/v2/relay", source: "operator" },
      { hint: "broker+ws://insecure-broker.example.test/b", source: "operator" },
      { hint: "broker+wss://broker.example.test/b", source: "operator" },
    ];
    roster.replace_from_json(JSON.stringify(json));

    const defaultV2 = JSON.parse(
      roster.session_candidates(host.info.host_id, JSON.stringify({ wire: 2 }))
    );
    assert.deepEqual(
      defaultV2.candidates.map((c) => c.hint),
      [
        "wss://dns.example.test/v2/relay",
        "wss://198.51.100.10/v1/relay",
        "broker+wss://broker.example.test/b",
      ]
    );
    assert.deepEqual(defaultV2.skipped, [
      { hint: "broker+ws://insecure-broker.example.test/b", reason: "insecure_ws" },
    ]);

    const insecureV2 = JSON.parse(
      roster.session_candidates(
        host.info.host_id,
        JSON.stringify({ wire: 2, allow_insecure_ws: true })
      )
    );
    assert.deepEqual(
      insecureV2.candidates.map((c) => c.hint),
      [
        "wss://dns.example.test/v2/relay",
        "wss://198.51.100.10/v1/relay",
        "broker+ws://insecure-broker.example.test/b",
        "broker+wss://broker.example.test/b",
      ]
    );
  } finally {
    roster.free();
  }
});

test("live: broker+ws:// pairs, connects endpoint-free, falls back across dead route, and connectV2 prefers /v2/relay over /v1/relay", async () => {
  await ensureWasm();
  const host = await liveHost("broker-v2-host", { serveBroker: true });
  const { relay, broker, peer, fields, seedB64 } = host;
  assert.ok(broker?.endpoint?.startsWith("broker+ws://127.0.0.1:"), JSON.stringify(broker));
  const client = await TendrilWebClient.create({ hostId: "broker-v2-client" });
  try {
    // 1. Pair over broker+ws:// via pairing URI with a dead primary relay route.
    const dead = `ws://127.0.0.1:${await deadPort()}/v1/relay`;
    const peerPair = peer.call({ op: "pair" });
    const paired = await client.pair({
      pairingUri: buildUri({ ...fields, ep: [dead, broker.endpoint], rq: 3, seedB64 }),
      timeoutMs: 8000,
    });
    await peerPair;
    assert.equal(paired.route.provider, "broker");
    assert.equal(paired.route.hint, broker.endpoint);

    const confirmedPeerId = paired.device_id;
    await peer.call({ op: "confirm", peer_id: confirmedPeerId, sas: paired.sas });
    const grant = (await peer.call({ op: "mint", peer_id: confirmedPeerId, caps: ["fs.read"] })).grant;

    // Replace routes with dead + broker+ws:// and connect endpoint-free.
    await client.clearPeerRoutes(fields.id, "signed");
    await client.setPeerRoutes(fields.id, [dead, broker.endpoint]);
    const peerConn = peer.call({ op: "connect" });
    const sess = await client.connect({
      targetHostId: fields.id,
      grantJson: JSON.stringify(grant),
      timeoutMs: 8000,
    });
    await peerConn;
    assert.equal(sess.route.provider, "broker");
    assert.equal(sess.route.hint, broker.endpoint);
    await sess.sendData("hello-broker");
    assert.equal((await peer.call({ op: "recv", timeout_ms: 2000 })).data_utf8, "hello-broker");
    await sess.close(1000, "done");
    await peer.call({ op: "recv", timeout_ms: 2000 }).catch(() => {});

    // 2. Wire v2 pair + /v2/relay vs /v1/relay priority on connectV2.
    const v2Client = await TendrilWebClient.create({ hostId: "v2-priority-client" });
    try {
      const code2 = (await peer.call({ op: "issue_code", kind: "remote" })).code;
      const p2Accept = peer.call({ op: "pair_v2_accept" });
      const paired2 = await v2Client.pairV2({
        pairingUri: buildUri({ ...fields, code: code2, ep: [relay.wsUrl], rq: 4, seedB64 }),
        timeoutMs: 8000,
      });
      const hostP2 = await p2Accept;
      await peer.call({ op: "confirm", peer_id: hostP2.device_id, sas: hostP2.sas });
      const grant2 = (await peer.call({ op: "mint", peer_id: hostP2.device_id, caps: ["fs.read"] })).grant;

      const v2RelayUrl = relay.wsUrl.replace("/v1/relay", "/v2/relay");
      const deadV1 = `ws://127.0.0.1:${await deadPort()}/v1/relay`;
      await v2Client.setPeerRoutes(fields.id, [deadV1, v2RelayUrl, broker.endpoint]);
      await peer.call({ op: "serve_relay_v2", relay_url: v2RelayUrl, expected_host: "127.0.0.1" });
      const p2Conn = peer.call({ op: "accept_v2" });
      const sess2 = await v2Client.connectV2({
        targetHostId: fields.id,
        grantJson: JSON.stringify(grant2),
        timeoutMs: 8000,
      });
      await p2Conn;
      assert.equal(sess2.route.hint, v2RelayUrl);
      assert.equal(sess2.route.provider, "relay");
      await sess2.sendData("hello-v2-priority");
      assert.equal((await peer.call({ op: "recv", timeout_ms: 2000 })).data_utf8, "hello-v2-priority");
      await sess2.close(1000, "done");
      await peer.call({ op: "recv", timeout_ms: 2000 }).catch(() => {});
    } finally {
      v2Client.free();
    }
  } finally {
    client.free();
    host.close();
  }
});
