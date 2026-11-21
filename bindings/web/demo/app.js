import { TendrilWebClient, b64urlDecode, benchmarkArgon2 } from "/src/index.js";

const LEGACY_IDENTITY_KEY = "tendril.demo.identity.v1";
const LEGACY_ROSTER_KEY = "tendril.demo.roster.v1";
const VAULT_DB_NAME = "tendril-demo-vault-v1";
const VAULT_STORE = "vault";
const WRAPPING_KEY_ID = "wrapping-key";
const IDENTITY_VAULT_ID = "identity";
const ROSTER_VAULT_ID = "roster";

const $ = (id) => document.getElementById(id);
const logEl = $("log");
const encoder = new TextEncoder();
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

function requireSecureVaultSupport() {
  if (!window.isSecureContext || !globalThis.crypto?.subtle || !globalThis.indexedDB) {
    throw new Error(
      "Secure WebCrypto AES-GCM and IndexedDB context required for demo keystore"
    );
  }
}

function idbRequest(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("IndexedDB request failed"));
  });
}

function idbTransactionDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error || new Error("IndexedDB transaction failed"));
    tx.onabort = () => reject(tx.error || new Error("IndexedDB transaction aborted"));
  });
}

let vaultDbPromise = null;

function openVaultDb() {
  requireSecureVaultSupport();
  if (!vaultDbPromise) {
    vaultDbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(VAULT_DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(VAULT_STORE)) {
          db.createObjectStore(VAULT_STORE);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => {
        vaultDbPromise = null;
        reject(req.error || new Error("failed opening IndexedDB vault"));
      };
    });
  }
  return vaultDbPromise;
}

async function getOrCreateWrappingKey(db) {
  const readTx = db.transaction(VAULT_STORE, "readonly");
  const existing = await idbRequest(readTx.objectStore(VAULT_STORE).get(WRAPPING_KEY_ID));
  await idbTransactionDone(readTx);
  if (existing) {
    return existing;
  }
  const generated = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const writeTx = db.transaction(VAULT_STORE, "readwrite");
  const store = writeTx.objectStore(VAULT_STORE);
  const current = await idbRequest(store.get(WRAPPING_KEY_ID));
  if (current) {
    await idbTransactionDone(writeTx);
    return current;
  }
  store.put(generated, WRAPPING_KEY_ID);
  await idbTransactionDone(writeTx);
  return generated;
}

async function writeVaultString(entryId, value) {
  const db = await openVaultDb();
  const key = await getOrCreateWrappingKey(db);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(`tendril.demo.vault.v1:${entryId}`);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    key,
    encoder.encode(value)
  );
  const tx = db.transaction(VAULT_STORE, "readwrite");
  tx.objectStore(VAULT_STORE).put({ iv, ct: new Uint8Array(ct) }, entryId);
  await idbTransactionDone(tx);
}

async function readVaultString(entryId) {
  const db = await openVaultDb();
  const key = await getOrCreateWrappingKey(db);
  const tx = db.transaction(VAULT_STORE, "readonly");
  const record = await idbRequest(tx.objectStore(VAULT_STORE).get(entryId));
  await idbTransactionDone(tx);
  if (!record || !record.iv || !record.ct) {
    return null;
  }
  const aad = encoder.encode(`tendril.demo.vault.v1:${entryId}`);
  const ptBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: record.iv, additionalData: aad },
    key,
    record.ct
  );
  return decoder.decode(ptBuf);
}

async function clearVault() {
  const db = await openVaultDb();
  const tx = db.transaction(VAULT_STORE, "readwrite");
  tx.objectStore(VAULT_STORE).clear();
  await idbTransactionDone(tx);
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
  let identityJson = await readVaultString(IDENTITY_VAULT_ID);
  let rosterJson = await readVaultString(ROSTER_VAULT_ID);

  const legacyIdentity = localStorage.getItem(LEGACY_IDENTITY_KEY);
  const legacyRoster = localStorage.getItem(LEGACY_ROSTER_KEY);
  if (!identityJson && legacyIdentity) {
    identityJson = legacyIdentity;
    await writeVaultString(IDENTITY_VAULT_ID, identityJson);
  }
  if (!rosterJson && legacyRoster) {
    rosterJson = legacyRoster;
    await writeVaultString(ROSTER_VAULT_ID, rosterJson);
  }
  scrubLegacyLocalStorage();

  client = await TendrilWebClient.create({
    identityJson,
    rosterJson,
    onPersistRoster: async (rj) => {
      await writeVaultString(ROSTER_VAULT_ID, rj);
    },
  });
  await writeVaultString(IDENTITY_VAULT_ID, client.exportIdentityJson());
  const info = client.info();
  $("status").textContent = "WASM core ready (Noise_XX_25519_ChaChaPoly_SHA256)";
  $("device-id").textContent = `device_id: ${info.device_id}`;
}

async function applyPreconfig() {
  $("relay-url").value = defaultRelayUrl();
  const searchParams = new URLSearchParams(window.location.search);
  const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const urlParam = (name) => hashParams.get(name) ?? searchParams.get(name);

  const urlEndpoint = urlParam("endpoint") || urlParam("relay");
  if (urlEndpoint) $("relay-url").value = urlEndpoint;
  if (urlParam("pub")) $("target-pub").value = urlParam("pub");
  if (urlParam("host")) $("target-host-id").value = urlParam("host");
  if (urlParam("code")) $("pair-code").value = urlParam("code");
  if (urlParam("uri")) $("pair-uri").value = urlParam("uri");

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

  const warningEl = $("url-warning");
  if (urlEndpoint && !serverConfigSetTarget && isThirdPartyTarget(urlEndpoint)) {
    const msg = `Warning: endpoint/relay overridden by URL parameters (${urlEndpoint}); verify destination before pairing or connecting.`;
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
  await clearVault();
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
    appendLog(`Pairing pending: host=${res.host_id} sas=${res.sas} elapsed=${elapsedSec}s`);
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
