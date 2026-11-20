import { TendrilWebClient, b64urlDecode, benchmarkArgon2 } from "/src/index.js";

const IDENTITY_KEY = "tendril.demo.identity.v1";
const ROSTER_KEY = "tendril.demo.roster.v1";

const $ = (id) => document.getElementById(id);
const logEl = $("log");
const decoder = new TextDecoder();

function appendLog(msg) {
  const ts = new Date().toISOString().slice(11, 23);
  logEl.textContent += `[${ts}] ${msg}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

function defaultRelayUrl() {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/v1/relay`;
}

let client = null;
let session = null;
let polling = false;

async function initClient() {
  const identityJson = localStorage.getItem(IDENTITY_KEY);
  const rosterJson = localStorage.getItem(ROSTER_KEY);
  client = await TendrilWebClient.create({
    identityJson,
    rosterJson,
    onPersistRoster: (rj) => {
      localStorage.setItem(ROSTER_KEY, rj);
    },
  });
  localStorage.setItem(IDENTITY_KEY, client.exportIdentityJson());
  const info = client.info();
  $("status").textContent = "WASM core ready (Noise_XX_25519_ChaChaPoly_SHA256)";
  $("device-id").textContent = `device_id: ${info.device_id}`;
}

async function applyPreconfig() {
  $("relay-url").value = defaultRelayUrl();
  const params = new URLSearchParams(window.location.search);
  if (params.get("endpoint")) $("relay-url").value = params.get("endpoint");
  if (params.get("relay")) $("relay-url").value = params.get("relay");
  if (params.get("pub")) $("target-pub").value = params.get("pub");
  if (params.get("host")) $("target-host-id").value = params.get("host");
  if (params.get("code")) $("pair-code").value = params.get("code");
  try {
    const resp = await fetch("/demo-config.json", { cache: "no-store" });
    if (resp.ok) {
      const cfg = await resp.json();
      if (cfg.endpoint) $("relay-url").value = cfg.endpoint;
      else if (cfg.relayUrl) $("relay-url").value = cfg.relayUrl;
      if (cfg.targetPub && !$("target-pub").value) $("target-pub").value = cfg.targetPub;
      if (cfg.hostId) $("target-host-id").value = cfg.hostId;
      if (cfg.code && !$("pair-code").value) $("pair-code").value = cfg.code;
    }
  } catch {}
}

function transportArgsFromUi() {
  const target = $("relay-url").value.trim();
  if (target.startsWith("iroh://")) {
    return { endpoint: target, relayUrl: null, targetPub: null };
  }
  return { endpoint: null, relayUrl: target, targetPub: $("target-pub").value.trim() };
}

async function pollLoop(activeSession) {
  polling = true;
  try {
    while (polling && session === activeSession && !activeSession.isClosed()) {
      const ev = await activeSession.pollEvent(1500);
      if (ev.status === "would_block") continue;
      if (ev.status === "eof") {
        appendLog("Session EOF reached");
        break;
      }
      if (ev.event === "data") {
        const text = decoder.decode(b64urlDecode(ev.data_b64));
        appendLog(`RX DATA: ${text}`);
      } else {
        appendLog(`RX ${ev.event}: ${JSON.stringify(ev)}`);
      }
    }
  } catch (err) {
    appendLog(`Poll error: ${err.message || err}`);
  } finally {
    polling = false;
  }
}

async function connectSession() {
  if (session) {
    try {
      await session.close(1000, "reconnect");
    } catch {}
    session = null;
  }
  const { endpoint, relayUrl, targetPub } = transportArgsFromUi();
  const targetHostId = $("target-host-id").value.trim();
  const grantRaw = $("grant-json").value.trim();
  const t0 = performance.now();
  session = await client.connect({
    endpoint,
    relayUrl,
    targetPub,
    targetHostId,
    grantJson: grantRaw || null,
  });
  const elapsed = (performance.now() - t0).toFixed(1);
  appendLog(`Session established with ${targetHostId} in ${elapsed} ms`);
  pollLoop(session);
}

$("reset-btn").addEventListener("click", async () => {
  if (session) {
    await session.close(1000, "reset");
    session = null;
  }
  localStorage.removeItem(IDENTITY_KEY);
  localStorage.removeItem(ROSTER_KEY);
  client.free();
  await initClient();
  appendLog("Identity and roster reset.");
});

$("bench-main-btn").addEventListener("click", async () => {
  $("bench-out").textContent = "Running main-thread Argon2id x3...";
  const res = await benchmarkArgon2(3, { useWorker: false });
  $("bench-out").textContent = `Main thread: ${JSON.stringify(res, null, 2)}`;
});

$("bench-worker-btn").addEventListener("click", async () => {
  $("bench-out").textContent = "Running Web Worker Argon2id x3...";
  const res = await benchmarkArgon2(3, { useWorker: true });
  $("bench-out").textContent = `Web Worker: ${JSON.stringify(res, null, 2)}`;
});

$("pair-btn").addEventListener("click", async () => {
  const t0 = performance.now();
  try {
    const { endpoint, relayUrl, targetPub } = transportArgsFromUi();
    const res = await client.pair({
      endpoint,
      relayUrl,
      targetPub,
      code: $("pair-code").value.trim(),
      pairingUri: $("pair-uri").value.trim() || null,
      deviceName: $("device-name").value.trim() || "phone-browser",
      deviceKind: "web",
    });
    const elapsedSec = ((performance.now() - t0) / 1000).toFixed(2);
    $("sas-box").textContent = `SAS: ${res.sas}`;
    $("target-host-id").value = res.host_id;
    $("pair-meta").textContent =
      `Paired host=${res.host_id} in ${elapsedSec}s (awaiting host confirm)`;
    appendLog(`Pairing pending: host=${res.host_id} sas=${res.sas} elapsed=${elapsedSec}s`);
  } catch (err) {
    appendLog(`Pairing failed: ${err.message || err}`);
  }
});

$("connect-btn").addEventListener("click", async () => {
  try {
    await connectSession();
  } catch (err) {
    appendLog(`Connect failed: ${err.message || err}`);
  }
});

$("reconnect-btn").addEventListener("click", async () => {
  try {
    appendLog("Reconnecting session via relay...");
    await connectSession();
  } catch (err) {
    appendLog(`Reconnect failed: ${err.message || err}`);
  }
});

$("rekey-btn").addEventListener("click", async () => {
  if (!session) return;
  try {
    await session.rekey();
    appendLog("Sent 0x04 REKEY");
  } catch (err) {
    appendLog(`Rekey error: ${err.message || err}`);
  }
});

$("ping-btn").addEventListener("click", async () => {
  if (!session) return;
  try {
    const cookie = Math.floor(Math.random() * 100000);
    await session.ping(cookie);
    appendLog(`Sent 0x05 PING cookie=${cookie}`);
  } catch (err) {
    appendLog(`Ping error: ${err.message || err}`);
  }
});

$("send-btn").addEventListener("click", async () => {
  if (!session) return;
  const text = $("msg-input").value;
  try {
    await session.sendData(text);
    appendLog(`TX DATA: ${text}`);
  } catch (err) {
    appendLog(`Send error: ${err.message || err}`);
  }
});

$("close-btn").addEventListener("click", async () => {
  if (!session) return;
  await session.close(1000, "user-close");
  session = null;
  appendLog("Session closed.");
});

await applyPreconfig();
await initClient();
