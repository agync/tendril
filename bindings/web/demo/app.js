import {
  TendrilWebClient,
  b64urlDecode,
  benchmarkArgon2,
  createIndexedDbVault,
} from "/src/index.js";

const LEGACY_IDENTITY_KEY = "tendril.demo.identity.v1";
const LEGACY_ROSTER_KEY = "tendril.demo.roster.v1";
const IDENTITY_VAULT_ID = "identity";
const ROSTER_VAULT_ID = "roster";

const vault = createIndexedDbVault({
  dbName: "tendril-demo-vault-v1",
  storeName: "vault",
  wrappingKeyId: "wrapping-key",
  aadPrefix: "tendril.demo.vault.v1",
});

const $ = (id) => document.getElementById(id);
const logEl = $("log");
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function isLogRedacted() {
  const el = $("redact-log-toggle");
  return el ? el.checked : true;
}

function appendLog(msg) {
  const ts = new Date().toISOString().slice(11, 23);
  logEl.textContent += `[${ts}] ${msg}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

function defaultRelayUrl() {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/v1/relay`;
}

function scrubLegacyLocalStorage() {
  localStorage.removeItem(LEGACY_IDENTITY_KEY);
  localStorage.removeItem(LEGACY_ROSTER_KEY);
}

function isThirdPartyTarget(targetUrl) {
  if (!targetUrl) return false;
  if (targetUrl.startsWith("iroh://")) return true;
  try {
    const parsed = new URL(targetUrl, window.location.href);
    return parsed.host !== window.location.host;
  } catch {
    return true;
  }
}

let client = null;
let session = null;
let polling = false;
let pendingHostId = null;
let pendingHostSas = null;

async function initClient() {
  let identityBytes = await vault.readBytes(IDENTITY_VAULT_ID);
  let rosterBytes = await vault.readBytes(ROSTER_VAULT_ID);

  const legacyIdentity = localStorage.getItem(LEGACY_IDENTITY_KEY);
  const legacyRoster = localStorage.getItem(LEGACY_ROSTER_KEY);
  if (!identityBytes && legacyIdentity) {
    await vault.writeString(IDENTITY_VAULT_ID, legacyIdentity);
    identityBytes = await vault.readBytes(IDENTITY_VAULT_ID);
  }
  if (!rosterBytes && legacyRoster) {
    await vault.writeString(ROSTER_VAULT_ID, legacyRoster);
    rosterBytes = await vault.readBytes(ROSTER_VAULT_ID);
  }
  scrubLegacyLocalStorage();

  client = await TendrilWebClient.create({
    identityBytes,
    rosterBytes,
    onPersistRosterBytes: async (bytes) => {
      await vault.writeBytes(ROSTER_VAULT_ID, bytes);
    },
  });
  const exportedId = client.exportIdentityBytes();
  try {
    await vault.writeBytes(IDENTITY_VAULT_ID, exportedId);
  } finally {
    exportedId.fill(0);
  }
  const info = client.info();
  $("status").textContent = "WASM core ready (Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256)";
  $("device-id").textContent = `device_id: ${info.device_id}`;
}

async function applyPreconfig() {
  $("relay-url").value = defaultRelayUrl();
  const searchParams = new URLSearchParams(window.location.search);
  const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const urlParam = (name) => hashParams.get(name) ?? searchParams.get(name);

  const leakedQuerySecrets = searchParams.has("code") || searchParams.has("uri");

  const urlEndpoint = urlParam("endpoint") || urlParam("relay");
  if (urlEndpoint) $("relay-url").value = urlEndpoint;
  if (urlParam("pub")) $("target-pub").value = urlParam("pub");
  if (urlParam("host")) $("target-host-id").value = urlParam("host");
  // Secrets (code, uri) are ONLY accepted from the URL fragment (#), never query strings (?).
  if (hashParams.get("code")) $("pair-code").value = hashParams.get("code");
  if (hashParams.get("uri")) $("pair-uri").value = hashParams.get("uri");

  let serverConfigSetTarget = false;
  try {
    const resp = await fetch("/demo-config.json", { cache: "no-store" });
    if (resp.ok) {
      const cfg = await resp.json();
      if (cfg.endpoint) {
        $("relay-url").value = cfg.endpoint;
        serverConfigSetTarget = true;
      } else if (cfg.relayUrl) {
        $("relay-url").value = cfg.relayUrl;
        serverConfigSetTarget = true;
      }
      if (cfg.targetPub) $("target-pub").value = cfg.targetPub;
      if (cfg.hostId) $("target-host-id").value = cfg.hostId;
      if (cfg.code) $("pair-code").value = cfg.code;
    }
  } catch {}

  let urlChanged = false;
  for (const key of ["code", "uri", "pub"]) {
    if (searchParams.has(key)) {
      searchParams.delete(key);
      urlChanged = true;
    }
    if (hashParams.has(key)) {
      hashParams.delete(key);
      urlChanged = true;
    }
  }
  if (urlChanged) {
    const qs = searchParams.toString();
    const hs = hashParams.toString();
    const cleanUrl =
      window.location.pathname + (qs ? `?${qs}` : "") + (hs ? `#${hs}` : "");
    window.history.replaceState(null, "", cleanUrl);
  }

  const warnings = [];
  if (leakedQuerySecrets) {
    warnings.push(
      "Warning: pairing code/URI in URL query string was ignored and scrubbed; pass secrets only in the URL fragment (#code=... or #uri=...)."
    );
  }
  if (urlEndpoint && !serverConfigSetTarget && isThirdPartyTarget(urlEndpoint)) {
    warnings.push(
      `Warning: endpoint/relay overridden by URL parameters (${urlEndpoint}); verify destination before pairing or connecting.`
    );
  }
  const warningEl = $("url-warning");
  if (warnings.length > 0) {
    const msg = warnings.join(" ");
    warningEl.textContent = msg;
    warningEl.hidden = false;
    appendLog(msg);
  } else {
    warningEl.hidden = true;
    warningEl.textContent = "";
  }
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
        const rawBytes = b64urlDecode(ev.data_b64);
        if (isLogRedacted()) {
          appendLog(`RX DATA: [REDACTED (${rawBytes.byteLength} bytes)]`);
        } else {
          const text = decoder.decode(rawBytes);
          appendLog(`RX DATA: ${text}`);
        }
      } else if (isLogRedacted()) {
        appendLog(`RX ${ev.event}: [REDACTED]`);
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
  await vault.clear();
  scrubLegacyLocalStorage();
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
    if (res.host_confirmed) {
      pendingHostId = null;
      pendingHostSas = null;
      $("confirm-host-btn").hidden = true;
      $("pair-meta").textContent =
        `Paired & pinned host=${res.host_id} in ${elapsedSec}s (awaiting host confirm)`;
    } else {
      pendingHostId = res.host_id;
      pendingHostSas = res.sas;
      $("confirm-host-btn").hidden = false;
      $("pair-meta").textContent =
        `Paired host=${res.host_id} in ${elapsedSec}s: verify SAS match on host, then click Confirm Host SAS`;
    }
    const sasLog = isLogRedacted() ? "[REDACTED]" : res.sas;
    appendLog(`Pairing pending: host=${res.host_id} sas=${sasLog} elapsed=${elapsedSec}s`);
  } catch (err) {
    appendLog(`Pairing failed: ${err.message || err}`);
  }
});

$("confirm-host-btn").addEventListener("click", async () => {
  if (!client || !pendingHostId || !pendingHostSas) return;
  try {
    await client.confirmPeer(pendingHostId, pendingHostSas);
    appendLog(`Confirmed host pin ${pendingHostId} via SAS match.`);
    $("pair-meta").textContent = `Host ${pendingHostId} confirmed; ready to connect.`;
    pendingHostId = null;
    pendingHostSas = null;
    $("confirm-host-btn").hidden = true;
  } catch (err) {
    appendLog(`Confirm host failed: ${err.message || err}`);
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
    const { endpoint } = transportArgsFromUi();
    appendLog(`Reconnecting session via ${endpoint ? "iroh P2P" : "relay"}...`);
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
    if (isLogRedacted()) {
      appendLog(`TX DATA: [REDACTED (${encoder.encode(text).byteLength} bytes)]`);
    } else {
      appendLog(`TX DATA: ${text}`);
    }
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
