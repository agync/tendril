import initWasm, {
  WasmGroupBook,
  WasmIdentity,
  WasmPairInitiator,
  WasmPathPlanner,
  WasmRoster,
  WasmSessionClient,
  WasmV2PakePairInitiator,
  WasmV2SessionInitiator,
  canonical_relay_host,
  classify_pairing_code,
  compute_code_mac,
  compute_code_mac_bytes,
  compute_relay_auth_hmac_b64,
  derive_v2_relay_dial_json,
  device_id,
  fingerprint_device,
  fingerprint_host,
  pairing_sas,
  parse_pairing_uri_json,
  relay_auth_origin_allowed,
  v2_epoch_within_skew,
  verify_grant_json,
  verify_rotation_chain_json,
} from "../pkg/tendril_wasm.js";
import {
  MAX_QUEUED_BYTES,
  MAX_QUEUED_FRAMES,
  MAX_RELAY_FRAME_LEN,
  RelayStream,
  dialBrokerStream,
  dialRelayStream,
  dialRelayV2Stream,
  isLoopbackHost,
  validateBrokerWsUrl,
  validateRelayWsUrl,
} from "./relay.js";
import { TendrilWebGroup } from "./group.js";
import { redactHint } from "./redact.js";
import { createIndexedDbVault, openTendrilVault } from "./vault.js";
import {
  MAX_WT_FRAME_LEN,
  MAX_WT_QUEUED_BYTES,
  WtStream,
  dialWtStream,
  validateWtUrl,
} from "./webtransport.js";
import {
  MAX_WEBRTC_FRAME_LEN,
  MAX_WEBRTC_QUEUED_BYTES,
  WebRtcStream,
  dialWebRtcUpgrade,
  hasWebRtcSupport,
} from "./webrtc.js";

export {
  MAX_QUEUED_BYTES,
  MAX_QUEUED_FRAMES,
  MAX_RELAY_FRAME_LEN,
  MAX_WEBRTC_FRAME_LEN,
  MAX_WEBRTC_QUEUED_BYTES,
  MAX_WT_FRAME_LEN,
  MAX_WT_QUEUED_BYTES,
  RelayStream,
  TendrilWebGroup,
  WebRtcStream,
  WtStream,
  createIndexedDbVault,
  dialBrokerStream,
  dialRelayStream,
  dialRelayV2Stream,
  dialWtStream,
  hasWebRtcSupport,
  openTendrilVault,
  validateBrokerWsUrl,
  validateRelayWsUrl,
  validateWtUrl,
};

export async function initTendrilP2p(wasmUrl) {
  const { initTendrilP2p: init } = await import("./iroh.js");
  return init(wasmUrl);
}

export async function parseP2pEndpoint(endpoint) {
  const { parseP2pEndpoint: parse } = await import("./iroh.js");
  return parse(endpoint);
}

function makeAbortError(signal) {
  if (signal?.reason instanceof Error) {
    return signal.reason;
  }
  const err = new Error("dial aborted");
  err.name = "AbortError";
  return err;
}

export async function dialIrohStream(options) {
  const { signal = null } = options ?? {};
  if (signal?.aborted) {
    throw makeAbortError(signal);
  }
  const { dialIrohStream: dial } = await import("./iroh.js");
  if (signal?.aborted) {
    throw makeAbortError(signal);
  }
  return dial(options);
}

/** Resolves true when the opt-in `pkg-p2p` module loads, so `iroh://` hints are dialable. */
export async function hasP2pSupport() {
  try {
    await initTendrilP2p();
    return true;
  } catch {
    return false;
  }
}

const SESSION_TOKEN = Symbol("TendrilWebSession");
const CLIENT_TOKEN = Symbol("TendrilWebClient");
const encoder = new TextEncoder();

let wasmReadyPromise = null;

export async function initTendril(wasmUrl) {
  if (!wasmReadyPromise) {
    wasmReadyPromise = initWasm(wasmUrl).then(() => {});
  }
  return wasmReadyPromise;
}

function nowUnixSecs() {
  return Math.floor(Date.now() / 1000);
}

async function sendProtocolBytes(stream, bytes) {
  if (!bytes || bytes.length === 0) {
    return;
  }
  const maxFrame = stream.maxFrame();
  for (let offset = 0; offset < bytes.length; offset += maxFrame) {
    await stream.send(bytes.subarray(offset, offset + maxFrame));
  }
}

async function warmTargetTransport(endpoint, relayUrl) {
  const target = endpoint || relayUrl;
  if (target && target.startsWith("iroh://")) {
    await initTendrilP2p();
  }
}

async function dialWebStream({
  provider = null,
  endpoint = null,
  relayUrl = null,
  targetPub = null,
  expectedHost = null,
  relayUrlOverride = null,
  p2pRelayUrls = null,
  p2pRelayAuthToken = null,
  p2pApiSecret = null,
  relayAuthTicket = null,
  relayAuthSecret = null,
  useRelayV2 = false,
  deriveV2Dial = null,
  allowInsecureWs = false,
  irohHint = false,
  initFrame = null,
  timeoutMs,
  signal = null,
}) {
  if (p2pApiSecret) {
    throw new Error(
      "p2pApiSecret is not permitted in browser clients; pass a scoped p2pRelayAuthToken"
    );
  }
  const target = endpoint || relayUrl;
  if (provider === "p2p" || (target && target.startsWith("iroh://"))) {
    return dialIrohStream({
      endpoint: target,
      relayUrlOverride,
      p2pRelayUrls,
      p2pRelayAuthToken,
      p2pApiSecret,
      hint: irohHint,
      timeoutMs,
      signal,
    });
  }
  if (provider === "direct" || (target && target.startsWith("wt://"))) {
    return dialWtStream(target, {
      timeoutMs,
      signal,
    });
  }
  if (provider === "broker" || (target && /^broker\+/i.test(target))) {
    return dialBrokerStream(target, {
      allowInsecureWs,
      timeoutMs,
      signal,
    });
  }
  if (useRelayV2) {
    return dialRelayV2Stream({
      relayUrl: target,
      deriveV2Dial,
      expectedHost,
      allowInsecureWs,
      relayAuthTicket,
      relayAuthSecret,
      initFrame,
      timeoutMs,
      signal,
    });
  }
  return dialRelayStream({
    relayUrl: target,
    targetPub,
    expectedHost,
    allowInsecureWs,
    relayAuthTicket,
    relayAuthSecret,
    initFrame,
    timeoutMs,
    signal,
  });
}

function remainingBudgetMs(deadlineMs, label) {
  const remaining = Math.ceil(deadlineMs - performance.now());
  if (remaining <= 0) {
    throw new Error(label);
  }
  return remaining;
}

const PROVIDER_RANK = { local: 0, direct: 1, overlay: 2, p2p: 3, relay: 4, broker: 5 };
const RUNG_BUDGET_MS = 4000;
const ROSTER_LOCK_WARN_MS = 5000;
const CLIENT_ROUTE_SET_INTERVAL_MS = 10000;
const NO_BROWSER_ENDPOINTS =
  "pairing URI contains no browser-compatible endpoints (need wt://, iroh:// or wss://)";
const DAY2_RECOVERY_GUIDANCE =
  "advertise a configured relay as a stable route, or scan a fresh signed pairing URI and apply it or connect with it as a recovery URI";
const PAIR_V2_RELAY_REJECTED =
  "/v2/relay is not used for pairing; pair over another route, then use connectV2";
const RELAY_OFFLINE_ROTATED =
  "relay mailbox offline for pinned key; host may have rotated: reconnect over another route or supply a fresh pairing URI";
const ROUTE_POLICIES = {
  allSigned: "all_signed",
  all_signed: "all_signed",
  committedOnly: "committed_only",
  committed_only: "committed_only",
  none: "none",
};

function toError(err) {
  return err instanceof Error ? err : new Error(String(err));
}

function errorText(err) {
  return err instanceof Error ? err.message : String(err);
}

function noop() {}

function bytesEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function normalizeRoutePolicy(policy) {
  if (policy === null || policy === undefined) {
    return "all_signed";
  }
  const value = ROUTE_POLICIES[policy];
  if (!value) {
    throw new Error(`invalid routePolicy '${policy}': expected allSigned, committedOnly or none`);
  }
  return value;
}

function normalizeOrigins(origins) {
  if (origins === null || origins === undefined) {
    return [];
  }
  if (!Array.isArray(origins) || origins.some((o) => typeof o !== "string")) {
    throw new TypeError("relayAuthOrigins must be an array of origin strings");
  }
  return origins;
}

/** `ws://` or `wss://` in any letter case (URL schemes are case-insensitive). */
function isWsUrl(url) {
  return /^wss?:\/\//i.test(url);
}

function isV2RelayUrl(url) {
  try {
    return new URL(url).pathname === "/v2/relay";
  } catch {
    return false;
  }
}

function isIrohHint(hint) {
  return typeof hint === "string" && (hint.startsWith("iroh://") || hint.startsWith("p2p:iroh://"));
}

function isRelayTarget(target) {
  return !(
    target &&
    (target.startsWith("iroh://") ||
      target.startsWith("p2p:iroh://") ||
      target.startsWith("wt://") ||
      /^broker\+/i.test(target))
  );
}

function stripIrohRelayParams(endpoint) {
  const q = endpoint.indexOf("?");
  if (q < 0) {
    return endpoint;
  }
  const kept = endpoint
    .slice(q + 1)
    .split("&")
    .filter((pair) => pair && !pair.startsWith("relay="));
  return kept.length > 0 ? `${endpoint.slice(0, q)}?${kept.join("&")}` : endpoint.slice(0, q);
}

/**
 * Splits a relay `URL#<key>` into the URL, with its scheme lower-cased, and the operator relay key
 * (none for `/v2/relay`).
 */
function splitRelayKey(url) {
  if (typeof url !== "string" || !isWsUrl(url)) {
    return { url, relayKey: null };
  }
  url = url.replace(/^wss?/i, (scheme) => scheme.toLowerCase());
  if (!url.includes("#")) {
    return { url, relayKey: null };
  }
  const idx = url.indexOf("#");
  const base = url.slice(0, idx);
  if (isV2RelayUrl(base)) {
    return { url: base, relayKey: null };
  }
  const key = url.slice(idx + 1);
  if (!/^[A-Za-z0-9_-]{43}$/.test(key)) {
    throw new Error("invalid relay key in endpoint fragment");
  }
  return { url: base, relayKey: key };
}

function copySecret(secret) {
  return secret instanceof Uint8Array ? new Uint8Array(secret) : secret;
}

/** An Error with a stable `code`: a WASM core code or one of this binding's own. */
function codedError(code, message, options) {
  const err = new Error(message, options);
  if (code) {
    err.code = code;
  }
  return err;
}

function isFatalUpgradeError(err, persistFailedErr = null) {
  if (persistFailedErr) {
    return true;
  }
  if (!err) {
    return false;
  }
  if (err.name === "AbortError" || err instanceof TypeError || err instanceof RangeError) {
    return true;
  }
  const code = err.code;
  if (
    code === "rotation_fork_detected" ||
    code === "peer_revoked" ||
    code === "version_downgrade" ||
    code === "host_key_unverified" ||
    code === "crl_revoked"
  ) {
    return true;
  }
  return /locked after roster persistence failure|failed to persist|host key could not be verified|rotation_fork_detected|peer_revoked/i.test(
    errorText(err)
  );
}

/** Severity by stable error code; uncoded errors rank last. */
const ERROR_SEVERITY = {
  rotation_fork_detected: 6,
  peer_revoked: 5,
  version_downgrade: 4,
  host_key_unverified: 3,
  invalid_pairing_uri: 2,
};

function errorSeverity(err) {
  return ERROR_SEVERITY[err?.code] ?? 1;
}

/** The most severe error, the earliest among equals. */
function mostSevere(errors) {
  let best = null;
  for (const err of errors) {
    if (best === null || errorSeverity(err) > errorSeverity(best)) {
      best = err;
    }
  }
  return best;
}

function attemptError(err, { committed = false, skipped = [], failures = [] } = {}) {
  const out = toError(err);
  out.committed = committed;
  out.skipped = skipped;
  out.failures = failures;
  return out;
}

class FatalAttemptError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/**
 * Splits pairing URI hints into the candidates a browser can dial, in provider order, and the
 * skipped rest. `wt://` needs `webtransport`; `iroh://` needs `p2p` (see `hasP2pSupport()`)
 * and loses its `relay=` parameters; `wss://` and `broker+wss://` are kept, `ws://` and
 * `broker+ws://` only on loopback or with `allowInsecureWs`. IPC, `direct:`, `overlay://`
 * and `/v2/relay` are skipped.
 */
export function filterWebCompatibleEndpoints(
  endpoints,
  { p2p = false, allowInsecureWs = false, webtransport = false } = {}
) {
  if (!Array.isArray(endpoints)) {
    throw new TypeError("endpoints must be an array of strings");
  }
  const candidates = [];
  const skipped = [];
  const skip = (hint, reason) => skipped.push({ hint: String(hint), reason });
  for (const hint of endpoints) {
    if (typeof hint !== "string" || hint.length === 0 || hint.includes("#")) {
      skip(hint, "invalid");
      continue;
    }
    if (hint.startsWith("local:") || hint.startsWith("unix://")) {
      skip(hint, "ipc_from_uri");
      continue;
    }
    let bare = hint;
    let isBroker = false;
    if (hint.startsWith("p2p:")) {
      bare = hint.slice(4);
    } else if (hint.startsWith("relay:")) {
      bare = hint.slice(6);
    } else if (hint.startsWith("broker+")) {
      bare = hint.slice(7);
      isBroker = true;
    }
    if (bare === hint && bare.startsWith("wt://")) {
      try {
        validateWtUrl(bare);
      } catch (err) {
        skip(hint, err?.blocked ? "blocked_address" : "invalid");
        continue;
      }
      if (!webtransport) {
        skip(hint, "webtransport_feature_disabled");
        continue;
      }
      candidates.push({ hint, endpoint: bare, provider: "direct" });
      continue;
    }
    if (!isBroker && bare.startsWith("iroh://")) {
      if (!p2p) {
        skip(hint, "p2p_feature_disabled");
        continue;
      }
      candidates.push({ hint, endpoint: stripIrohRelayParams(bare), provider: "p2p" });
      continue;
    }
    if (bare.startsWith("wss://") || bare.startsWith("ws://")) {
      if (!isBroker && isV2RelayUrl(bare)) {
        skip(hint, "relay_v2_not_authorized");
        continue;
      }
      let checked;
      try {
        checked = validateRelayWsUrl(bare, true);
      } catch (err) {
        skip(hint, /metadata|link-local/.test(errorText(err)) ? "blocked_address" : "invalid");
        continue;
      }
      if (bare.startsWith("ws://") && !allowInsecureWs && !isLoopbackHost(checked.bareHost)) {
        skip(hint, "insecure_ws");
        continue;
      }
      candidates.push({ hint, endpoint: bare, provider: isBroker ? "broker" : "relay" });
      continue;
    }
    skip(hint, "browser_unsupported");
  }
  candidates.sort((a, b) => PROVIDER_RANK[a.provider] - PROVIDER_RANK[b.provider]);
  if (candidates.length === 0) {
    throw attemptError(new Error(NO_BROWSER_ENDPOINTS), { skipped });
  }
  return { candidates, skipped };
}

/** Classifies a pairing code: `lan2_group` or `remote3_group`; a malformed code throws. */
export function classifyPairingCode(code) {
  try {
    return classify_pairing_code(String(code));
  } catch (err) {
    throw toError(err);
  }
}

/** Whether relay admission material may be sent to `url`. */
export function relayAuthOriginAllowed(url, origins) {
  try {
    return relay_auth_origin_allowed(String(url), JSON.stringify(normalizeOrigins(origins)));
  } catch (err) {
    throw toError(err);
  }
}

function relayCredsFor(url, explicitUrl, origins, ticket, secret) {
  if (ticket === null && secret === null) {
    return { relayAuthTicket: null, relayAuthSecret: null };
  }
  const allowed =
    (explicitUrl !== null && url === explicitUrl) ||
    (origins.length > 0 && relayAuthOriginAllowed(url, origins));
  if (!allowed) {
    return { relayAuthTicket: null, relayAuthSecret: null, withheld: true };
  }
  return { relayAuthTicket: ticket, relayAuthSecret: copySecret(secret) };
}

/** A relay that demanded credentials the origin rule withheld fails `relay_auth_unconfigured`. */
function candidateError(err, creds) {
  const out = toError(err);
  if (creds && creds.withheld && /relay requires dial authentication/.test(out.message)) {
    return codedError("relay_auth_unconfigured", `relay_auth_unconfigured: ${out.message}`);
  }
  return out;
}

export function b64urlEncode(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(str) {
  if (!str) {
    return new Uint8Array(0);
  }
  const pad = "=".repeat((4 - (str.length % 4)) % 4);
  const b64 = (str + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export function deviceId(staticPub) {
  return device_id(staticPub);
}

export function fingerprintHost(staticPub) {
  return fingerprint_host(staticPub);
}

export function fingerprintDevice(staticPub) {
  return fingerprint_device(staticPub);
}

export function pairingSas(handshakeHash) {
  return pairing_sas(handshakeHash);
}

export function computeCodeMac(code, handshakeHash) {
  return compute_code_mac(code, handshakeHash);
}

export function computeCodeMacBytes(codeBytes, handshakeHash) {
  if (!(codeBytes instanceof Uint8Array)) {
    throw new TypeError("codeBytes must be a Uint8Array");
  }
  try {
    return compute_code_mac_bytes(codeBytes, handshakeHash);
  } finally {
    codeBytes.fill(0);
  }
}

export async function computeCodeMacWorker(code, handshakeHash, { timeoutMs = 15000 } = {}) {
  await initTendril();
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
    const id = 1;
    let settled = false;
    let timer = null;
    const finish = (err, val) => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer !== null) {
        clearTimeout(timer);
      }
      worker.terminate();
      if (err) {
        reject(err);
      } else {
        resolve(val);
      }
    };
    if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
      timer = setTimeout(() => {
        finish(new Error(`computeCodeMacWorker timed out after ${timeoutMs} ms`));
      }, timeoutMs);
    }
    worker.addEventListener("message", (ev) => {
      if (ev.data && ev.data.ok) {
        finish(null, new Uint8Array(ev.data.mac));
      } else {
        finish(new Error(ev.data ? ev.data.error : "worker failed"));
      }
    });
    worker.addEventListener("error", (ev) => {
      finish(new Error(ev.message || "worker error"));
    });
    worker.addEventListener("messageerror", () => {
      finish(new Error("worker message deserialization failed"));
    });
    let payloadBytes = null;
    try {
      if (code instanceof Uint8Array) {
        payloadBytes = new Uint8Array(code);
        code.fill(0);
      } else {
        payloadBytes = encoder.encode(String(code));
      }
      worker.postMessage(
        { id, op: "compute_code_mac", codeBytes: payloadBytes, handshakeHash },
        [payloadBytes.buffer]
      );
    } catch (err) {
      if (payloadBytes) {
        payloadBytes.fill(0);
      }
      finish(err);
    }
  });
}

export async function benchmarkArgon2(runs = 3, { useWorker = false } = {}) {
  await initTendril();
  const durationsMs = [];
  for (let i = 0; i < runs; i += 1) {
    const hh = new Uint8Array(32).fill(i + 1);
    const t0 = performance.now();
    if (useWorker) {
      await computeCodeMacWorker("4829-1704", hh);
    } else {
      compute_code_mac("4829-1704", hh);
    }
    durationsMs.push(Number((performance.now() - t0).toFixed(2)));
  }
  const sorted = [...durationsMs].sort((a, b) => a - b);
  return {
    runs,
    durationsMs,
    minMs: sorted[0],
    medianMs: sorted[Math.floor(sorted.length / 2)],
    maxMs: sorted[sorted.length - 1],
  };
}

export function verifyRotationChainJson(
  pinnedSigningB64,
  pinnedStaticB64,
  pinnedSeq,
  chainJson,
  curStaticB64,
  curSigningB64
) {
  return verify_rotation_chain_json(
    pinnedSigningB64,
    pinnedStaticB64,
    pinnedSeq,
    chainJson,
    curStaticB64,
    curSigningB64
  );
}

export function verifyGrantJson(
  grantJson,
  issuerKeysJson,
  expectedSubject,
  expectedRootIssuer,
  requestedCap,
  nowUnix,
  crlJson = null
) {
  return verify_grant_json(
    grantJson,
    issuerKeysJson,
    expectedSubject,
    expectedRootIssuer,
    requestedCap,
    nowUnix,
    crlJson
  );
}

export function parsePairingUri(uri) {
  try {
    return JSON.parse(parse_pairing_uri_json(uri));
  } catch (err) {
    throw toError(err);
  }
}

export function computeRelayAuthHmacB64(secretBytes, op, relayHost, nonce, pubOrTarget) {
  if (!(secretBytes instanceof Uint8Array)) {
    throw new TypeError("secretBytes must be a Uint8Array");
  }
  try {
    return compute_relay_auth_hmac_b64(secretBytes, op, relayHost, nonce, pubOrTarget);
  } finally {
    secretBytes.fill(0);
  }
}

export function deriveV2RelayDial(mailboxSecret, relayHost, unixSecs, dialNonce, connId) {
  return JSON.parse(derive_v2_relay_dial_json(mailboxSecret, relayHost, unixSecs, dialNonce, connId));
}

export function v2EpochWithinSkew(serverEpoch, claimedEpoch) {
  return v2_epoch_within_skew(serverEpoch, claimedEpoch);
}

export function canonicalRelayHost(host) {
  return canonical_relay_host(host);
}

export { WasmV2PakePairInitiator, WasmV2SessionInitiator };

export class TendrilWebClient {
  #identity;
  #roster;
  #groups;
  #onPersistRoster;
  #onPersistRosterBytes;
  #onPersistGroupBook;
  #onPersistGroupBookBytes;
  #openGroups = new Set();
  #groupPersistChain = Promise.resolve();
  #groupMutationLock = Promise.resolve();
  #freed = false;
  #wasmFreed = false;
  #holders = 0;
  #activeSessions = new Set();
  #persistChain = Promise.resolve();
  #rosterLock = Promise.resolve();
  #rosterPending = 0;
  #inPersistCallback = 0;
  #rosterFailedErr = null;

  constructor(
    token,
    identity,
    roster,
    onPersistRoster,
    onPersistRosterBytes = null,
    groups = null,
    onPersistGroupBook = null,
    onPersistGroupBookBytes = null
  ) {
    if (token !== CLIENT_TOKEN) {
      throw new Error("Use TendrilWebClient.create()");
    }
    this.#identity = identity;
    this.#roster = roster;
    this.#groups = groups;
    this.#onPersistRoster = onPersistRoster;
    this.#onPersistRosterBytes = onPersistRosterBytes;
    this.#onPersistGroupBook = onPersistGroupBook;
    this.#onPersistGroupBookBytes = onPersistGroupBookBytes;
  }

  static async create({
    hostId = null,
    identityJson = null,
    identityBytes = null,
    rosterJson = null,
    rosterBytes = null,
    onPersistRoster = null,
    onPersistRosterBytes = null,
    groupBookJson = null,
    groupBookBytes = null,
    onPersistGroupBook = null,
    onPersistGroupBookBytes = null,
  } = {}) {
    try {
      await initTendril();
      let identity;
      if (identityBytes !== null && identityBytes !== undefined) {
        if (!(identityBytes instanceof Uint8Array)) {
          throw new TypeError("identityBytes must be a Uint8Array");
        }
        identity = WasmIdentity.from_json_bytes(identityBytes);
      } else if (identityJson) {
        identity = WasmIdentity.from_json(identityJson);
      } else {
        identity = WasmIdentity.generate(hostId);
      }
      let roster;
      try {
        if (rosterBytes !== null && rosterBytes !== undefined) {
          if (!(rosterBytes instanceof Uint8Array)) {
            throw new TypeError("rosterBytes must be a Uint8Array");
          }
          roster = WasmRoster.from_json_bytes(rosterBytes);
        } else if (rosterJson) {
          roster = WasmRoster.from_json(rosterJson);
        } else {
          roster = new WasmRoster();
        }
      } catch (err) {
        identity.free();
        throw err;
      }
      let groups;
      try {
        if (groupBookBytes !== null && groupBookBytes !== undefined) {
          if (!(groupBookBytes instanceof Uint8Array)) {
            throw new TypeError("groupBookBytes must be a Uint8Array");
          }
          groups = WasmGroupBook.from_json_bytes(identity, groupBookBytes);
        } else if (groupBookJson) {
          groups = WasmGroupBook.from_json(identity, groupBookJson);
        } else {
          groups = new WasmGroupBook(identity);
        }
      } catch (err) {
        identity.free();
        roster.free();
        throw err;
      }
      return new TendrilWebClient(
        CLIENT_TOKEN,
        identity,
        roster,
        onPersistRoster,
        onPersistRosterBytes,
        groups,
        onPersistGroupBook,
        onPersistGroupBookBytes
      );
    } finally {
      if (identityBytes instanceof Uint8Array) {
        identityBytes.fill(0);
      }
      if (rosterBytes instanceof Uint8Array) {
        rosterBytes.fill(0);
      }
      if (groupBookBytes instanceof Uint8Array) {
        groupBookBytes.fill(0);
      }
    }
  }

  #ensureOpen() {
    if (this.#freed || this.#wasmFreed) {
      throw new Error("TendrilWebClient has been freed");
    }
  }

  #retain() {
    this.#ensureOpen();
    this.#holders += 1;
  }

  #release() {
    if (this.#holders > 0) {
      this.#holders -= 1;
    }
    this.#maybeFreeWasm();
  }

  #maybeFreeWasm() {
    if (this.#freed && !this.#wasmFreed && this.#holders === 0) {
      this.#wasmFreed = true;
      this.#identity.free();
      this.#roster.free();
      this.#groups.free();
    }
  }

  async #withHold(fn) {
    this.#retain();
    try {
      return await fn();
    } finally {
      this.#release();
    }
  }

  #attachSession(sess) {
    this.#retain();
    this.#activeSessions.add(sess);
    return () => {
      if (this.#activeSessions.delete(sess)) {
        this.#release();
      }
    };
  }

  info() {
    this.#ensureOpen();
    return JSON.parse(this.#identity.info_json());
  }

  exportIdentityJson() {
    this.#ensureOpen();
    return this.#identity.to_json();
  }

  exportIdentityBytes() {
    this.#ensureOpen();
    return this.#identity.to_json_bytes();
  }

  exportRosterJson() {
    this.#ensureOpen();
    return this.#roster.to_json();
  }

  exportRosterBytes() {
    this.#ensureOpen();
    return this.#roster.to_json_bytes();
  }

  /**
   * Locks the client after authenticated evidence could not be persisted: every later roster
   * section and group call fails, and every open session fails and closes, since each one
   * authorizes against the unpersisted roster.
   */
  #lockClient(persistErr) {
    if (this.#rosterFailedErr) {
      return;
    }
    this.#rosterFailedErr = persistErr;
    for (const sess of [...this.#activeSessions]) {
      sess._failFromClientLock(persistErr);
    }
  }

  #lockedError() {
    return new Error(
      `client locked after roster persistence failure: ${errorText(this.#rosterFailedErr)}`,
      { cause: this.#rosterFailedErr }
    );
  }

  #ensureUnlocked() {
    this.#ensureOpen();
    if (this.#rosterFailedErr) {
      throw this.#lockedError();
    }
  }

  /** `true` when the roster no longer serializes to `prev` (null: nothing to compare, no). */
  #rosterChangedSince(prev) {
    if (!prev) {
      return false;
    }
    const now = this.#roster.to_json_bytes();
    try {
      return !bytesEqual(prev, now);
    } finally {
      now.fill(0);
    }
  }

  #hasPersistCallback() {
    return (
      typeof this.#onPersistRosterBytes === "function" ||
      typeof this.#onPersistRoster === "function"
    );
  }

  #snapshotRosterBytes() {
    return this.#hasPersistCallback() ? this.#roster.to_json_bytes() : null;
  }

  #restoreRosterBytes(prevBytes) {
    if (prevBytes && !this.#wasmFreed) {
      try {
        this.#roster.replace_from_json_bytes(prevBytes);
      } catch {}
    }
  }

  /**
   * Runs one roster critical section behind the FIFO roster lock: an optional rollback snapshot,
   * the synchronous WASM mutation(s) in `fn`, and `await tx.persist()`. Nothing else may run
   * inside: no socket I/O, no stream reads, no group hooks, no application callbacks other than
   * the persist callback. A client call made from inside a persist callback is queued behind the
   * current holder; awaiting it from the callback deadlocks, so a debug warning is logged when a
   * waiter has waited 5 s while the holder is inside a persist callback.
   */
  #withRoster(fn, { readOnly = false, snapshot = true } = {}) {
    const busy = this.#rosterPending > 0;
    this.#rosterPending += 1;
    let acquired = false;
    let warnTimer = null;
    const armWarning = () => {
      warnTimer = setTimeout(() => {
        if (acquired) {
          return;
        }
        if (this.#inPersistCallback > 0) {
          console.warn(
            "TendrilWebClient: roster lock wait exceeded 5 s while a persist callback holds it; persist callbacks must not await client methods"
          );
          return;
        }
        armWarning();
      }, ROSTER_LOCK_WARN_MS);
      if (warnTimer && typeof warnTimer.unref === "function") {
        warnTimer.unref();
      }
    };
    if (busy) {
      armWarning();
    }
    const run = this.#rosterLock.then(() => {
      acquired = true;
      if (warnTimer !== null) {
        clearTimeout(warnTimer);
      }
      return this.#rosterCritical(fn, readOnly, snapshot);
    });
    this.#rosterLock = run.then(noop, noop).then(() => {
      this.#rosterPending -= 1;
    });
    return run;
  }

  async #rosterCritical(fn, readOnly, snapshot) {
    if (this.#wasmFreed) {
      throw new Error("TendrilWebClient has been freed");
    }
    if (this.#rosterFailedErr) {
      throw this.#lockedError();
    }
    if (readOnly) {
      return fn();
    }
    const prev = snapshot ? this.#snapshotRosterBytes() : null;
    // Evidence persisted with `rollback: false` stays in memory even when `fn` then throws.
    let keep = false;
    let restored = false;
    const restore = () => {
      if (!restored && !keep) {
        restored = true;
        this.#restoreRosterBytes(prev);
      }
    };
    const tx = {
      persist: async ({ rollback = true } = {}) => {
        if (!rollback) {
          keep = true;
        }
        try {
          await this.#persistRoster();
        } catch (err) {
          if (rollback) {
            restore();
          }
          throw err;
        }
      },
    };
    try {
      return await fn(tx);
    } catch (err) {
      if (prev) {
        restore();
      }
      throw err;
    } finally {
      if (prev) {
        prev.fill(0);
      }
    }
  }

  /** One rollback-protected roster mutation plus its persist. */
  #mutateRoster(mutate, changed = () => true) {
    return this.#withHold(() =>
      this.#withRoster(async (tx) => {
        let result;
        try {
          result = mutate();
        } catch (err) {
          throw toError(err);
        }
        if (changed(result)) {
          await tx.persist();
        }
        return result;
      })
    );
  }

  getPeer(peerId) {
    this.#ensureOpen();
    const raw = this.#roster.get_peer_json(peerId);
    if (!raw) {
      return null;
    }
    const peer = JSON.parse(raw);
    peer.routes = peer.routes ?? [];
    peer.route_meta = peer.route_meta ?? null;
    return peer;
  }

  async confirmPeer(peerId, sas = null) {
    await this.#mutateRoster(() => this.#roster.confirm_peer(peerId, sas));
  }

  async removePendingPeer(peerId) {
    await this.#mutateRoster(() => this.#roster.remove_pending_peer(peerId));
  }

  async addTrustAnchor(anchorId, signingPubB64) {
    await this.#mutateRoster(() => this.#roster.add_trust_anchor(anchorId, signingPubB64));
  }

  async revokeTrustAnchor(anchorId) {
    await this.#mutateRoster(() => this.#roster.revoke_trust_anchor(anchorId));
  }

  /** The routes, route metadata and legacy relay hints stored for `peerId`. */
  peerRoutes(peerId) {
    const peer = this.getPeer(peerId);
    if (!peer) {
      throw new Error(`peer not found in roster: ${peerId}`);
    }
    return {
      peer_id: peerId,
      routes: peer.routes,
      route_meta: peer.route_meta,
      legacy_relay_hints: peer.relay_hints ?? [],
    };
  }

  /** Replaces the `operator` routes of an active peer (at most six; empty clears them). */
  async setPeerRoutes(peerId, routes) {
    if (!Array.isArray(routes) || routes.some((r) => typeof r !== "string")) {
      throw new TypeError("routes must be an array of endpoint strings");
    }
    return this.#mutateRoster(() =>
      JSON.parse(this.#roster.set_routes(peerId, JSON.stringify(routes)))
    );
  }

  /** Removes the routes of one source (`operator` by default, `signed`, `committed`), or `all`. */
  async clearPeerRoutes(peerId, source = null) {
    await this.#mutateRoster(() => this.#roster.clear_routes(peerId, source ?? undefined));
  }

  /**
   * Applies a fresh host-signed pairing URI to the matching paired host offline: no network, no
   * code use. Signed routes replace older ones under `allSigned`; `replaceRoutes` approves an
   * equal or older route set explicitly.
   */
  async applyRouteUri(uri, { routePolicy = "allSigned", replaceRoutes = false } = {}) {
    const policy = normalizeRoutePolicy(routePolicy);
    return this.#mutateRoster(
      () =>
        JSON.parse(
          this.#roster.apply_signed_route_uri(
            uri,
            JSON.stringify({ route_policy: policy, replace_routes: Boolean(replaceRoutes) })
          )
        ),
      (result) => result.applied
    );
  }

  mintEnrollmentToken({ targetHostId, subject = null, ttlSecs = 900 }) {
    this.#ensureOpen();
    return this.#identity.mint_enrollment_token(targetHostId, subject, nowUnixSecs(), ttlSecs);
  }

  mintRelayTicket(relayHost, role = "dial", targetPubOrWildcard = "*", ttlSecs = 900) {
    this.#ensureOpen();
    return this.#identity.mint_relay_ticket_json(
      relayHost,
      role,
      targetPubOrWildcard,
      nowUnixSecs(),
      ttlSecs
    );
  }

  pairingFloor(staticPub) {
    this.#ensureOpen();
    const bytes = typeof staticPub === "string" ? b64urlDecode(staticPub) : staticPub;
    return this.#roster.pairing_floor(bytes);
  }

  peerV2Summary(peerId) {
    this.#ensureOpen();
    return JSON.parse(this.#roster.peer_v2_summary(peerId));
  }

  exportGroupBookJson() {
    this.#ensureOpen();
    return this.#groups.to_json();
  }

  exportGroupBookBytes() {
    this.#ensureOpen();
    return this.#groups.to_json_bytes();
  }

  #hasGroupPersistCallback() {
    return (
      typeof this.#onPersistGroupBookBytes === "function" ||
      typeof this.#onPersistGroupBook === "function"
    );
  }

  #snapshotGroupBytes() {
    return this.#hasGroupPersistCallback() ? this.#groups.to_json_bytes() : null;
  }

  #restoreGroupBytes(prevBytes) {
    if (prevBytes && !this.#wasmFreed) {
      try {
        this.#groups.replace_from_json_bytes(prevBytes);
      } catch {}
    }
  }

  #persistGroupBook() {
    const fnBytes = this.#onPersistGroupBookBytes;
    const fnStr = this.#onPersistGroupBook;
    if (typeof fnBytes !== "function" && typeof fnStr !== "function") {
      return Promise.resolve();
    }
    const run = this.#groupPersistChain.then(async () => {
      if (this.#wasmFreed) {
        throw new Error("TendrilWebClient has been freed");
      }
      if (typeof fnBytes === "function") {
        const bytes = this.#groups.to_json_bytes();
        try {
          await fnBytes(bytes);
        } finally {
          bytes.fill(0);
        }
        return;
      }
      await fnStr(this.#groups.to_json());
    });
    this.#groupPersistChain = run.catch(() => {});
    return run;
  }

  /**
   * Serializes every group book mutation (snapshot, apply, persist, restore on failure) so a
   * failed persist can never restore a snapshot that erases a concurrent mutation.
   */
  #mutateGroupBook(fn) {
    const run = this.#groupMutationLock.then(() => this.#mutateGroupBookLocked(fn));
    this.#groupMutationLock = run.then(
      () => {},
      () => {}
    );
    return run;
  }

  /** Runs `fn` against the group book and persists the result, restoring state on failure. */
  async #mutateGroupBookLocked(fn) {
    if (this.#wasmFreed) {
      throw new Error("TendrilWebClient has been freed");
    }
    if (this.#rosterFailedErr) {
      throw this.#lockedError();
    }
    const prev = this.#snapshotGroupBytes();
    try {
      const result = fn();
      try {
        await this.#persistGroupBook();
      } catch (err) {
        this.#restoreGroupBytes(prev);
        throw err;
      }
      return result;
    } catch (err) {
      this.#restoreGroupBytes(prev);
      throw err;
    } finally {
      if (prev) {
        prev.fill(0);
      }
    }
  }

  groupIds() {
    this.#ensureOpen();
    return JSON.parse(this.#groups.group_ids_json());
  }

  groupMembers(groupId) {
    this.#ensureOpen();
    return JSON.parse(this.#groups.members(groupId));
  }

  groupAuthorizePeer(groupId, peerId, cap) {
    this.#ensureUnlocked();
    this.#groups.authorize_peer(this.#roster, groupId, peerId, cap, nowUnixSecs());
    return true;
  }

  /**
   * Hands a manifest, or a `group_manifest_unverified` session event, received on `session` to the
   * WASM group book. The group book verifies it and applies the first-contact pinning rules
   * against the authenticated peer of `session`; gossip never pins a group.
   */
  async ingestGroupManifest(manifestOrEvent, session) {
    return this.#withHold(async () => {
      this.#ensureUnlocked();
      const sender = session?.peerDeviceId;
      if (typeof sender !== "string" || sender.length === 0) {
        throw new Error("manifest must arrive on an established authenticated session");
      }
      const isEvent =
        typeof manifestOrEvent === "object" &&
        manifestOrEvent !== null &&
        manifestOrEvent.event === "group_manifest_unverified";
      const text =
        typeof manifestOrEvent === "string" ? manifestOrEvent : JSON.stringify(manifestOrEvent);
      const outcome = await this.#mutateGroupBook(() =>
        JSON.parse(
          isEvent
            ? this.#groups.ingest_manifest_event(this.#roster, sender, text, nowUnixSecs())
            : this.#groups.ingest_manifest(this.#roster, sender, text, nowUnixSecs())
        )
      );
      for (const group of [...this.#openGroups]) {
        group._onManifestOutcome(outcome);
      }
      return outcome;
    });
  }

  /** Opens fan-out and inbound delivery for a group whose manifest is already ingested. */
  openGroup(groupId, options = {}) {
    this.#ensureUnlocked();
    this.#groups.check_local_member(this.#roster, groupId);
    const roster = this.#roster;
    const book = this.#groups;
    const targets = (cap) => {
      this.#ensureUnlocked();
      return JSON.parse(book.broadcast_targets(roster, groupId, cap ?? null, nowUnixSecs()));
    };
    const backend = {
      members: () => this.groupMembers(groupId),
      authorize: (peerId, cap) => this.groupAuthorizePeer(groupId, peerId, cap),
      authorizeInbound: (peerId, cap) => {
        this.#ensureUnlocked();
        return book.authorize_inbound(roster, groupId, peerId, cap, nowUnixSecs());
      },
      checkLocal: () => {
        this.#ensureUnlocked();
        return book.check_local_member(roster, groupId);
      },
      localDeviceId: () => book.local_device_id(),
      targets,
      canSend: (peerId, cap) => {
        if (!targets(cap).includes(peerId)) {
          throw new Error("recipient is no longer authorized");
        }
      },
      ingestManifest: (session, event) => this.ingestGroupManifest(event, session),
    };
    const group = TendrilWebGroup._create(groupId, backend, options, (g) =>
      this.#openGroups.delete(g)
    );
    this.#openGroups.add(group);
    return group;
  }

  async #applyGroupRendezvous(wasmSession) {
    return this.#withHold(() => {
      this.#ensureUnlocked();
      return this.#mutateGroupBook(() =>
        JSON.parse(wasmSession.apply_group_rendezvous(this.#groups, this.#roster, nowUnixSecs()))
      );
    });
  }

  #groupHook() {
    return { applyRendezvous: (wasmSession) => this.#applyGroupRendezvous(wasmSession) };
  }

  async enroll({
    endpoint = null,
    relayUrl = null,
    targetPub = null,
    expectedHost = null,
    relayUrlOverride = null,
    p2pRelayUrls = null,
    p2pRelayAuthToken = null,
    p2pApiSecret = null,
    relayAuthTicket = null,
    relayAuthSecret = null,
    allowInsecureWs = false,
    hostId,
    hostStaticPubB64,
    hostSigningPubB64,
    hostRotationSeq = 0,
    tokenJson,
    deviceName = "web-machine",
    deviceKind = "machine",
    timeoutMs = 15000,
  }) {
    if (p2pApiSecret) {
      throw new Error(
        "p2pApiSecret is not permitted in browser clients; pass a scoped p2pRelayAuthToken"
      );
    }
    return this.#withHold(async () => {
      await warmTargetTransport(endpoint, relayUrl);
      this.#ensureOpen();
      const deadlineMs = performance.now() + timeoutMs;
      const initiator = await this.#withRoster(
        () =>
          WasmPairInitiator.new_m2m_with_roster(
            this.#identity,
            deviceName,
            deviceKind,
            hostId,
            hostStaticPubB64,
            hostSigningPubB64,
            hostRotationSeq,
            tokenJson,
            this.#roster
          ),
        { readOnly: true }
      );
      let stream = null;
      try {
        const target = endpoint || relayUrl;
        const isRelay = isRelayTarget(target);
        const startBytes = initiator.start();
        stream = await dialWebStream({
          endpoint,
          relayUrl,
          targetPub,
          expectedHost,
          relayUrlOverride,
          p2pRelayUrls,
          p2pRelayAuthToken,
          p2pApiSecret,
          relayAuthTicket,
          relayAuthSecret,
          allowInsecureWs,
          initFrame: isRelay ? startBytes : null,
          timeoutMs: remainingBudgetMs(
            deadlineMs,
            "m2m enrollment timed out connecting to transport"
          ),
        });
        this.#ensureOpen();
        if (!stream.fastOpenSent) {
          await sendProtocolBytes(stream, startBytes);
        }
        while (true) {
          const waitMs = remainingBudgetMs(
            deadlineMs,
            "m2m enrollment timed out waiting for host response"
          );
          const frame = await stream.recv(waitMs);
          this.#ensureOpen();
          if (frame.status === "would_block") {
            throw new Error("m2m enrollment timed out waiting for host response");
          }
          if (frame.status === "eof") {
            throw new Error("m2m enrollment stream closed before completion");
          }
          const res = await this.#withRoster(async (tx) => {
            const step = JSON.parse(initiator.feed_bytes(frame.bytes, this.#roster));
            if (step.outcome && step.outcome.status === "active") {
              await tx.persist();
            }
            return step;
          });
          if (res.write_b64) {
            await sendProtocolBytes(stream, b64urlDecode(res.write_b64));
          }
          if (res.outcome) {
            if (res.outcome.status === "active") {
              return {
                device_id: res.outcome.device_id,
                host_id: res.outcome.host_id,
                status: "active",
                host_rotation_seq: res.outcome.host_rotation_seq,
                token_nonce: res.outcome.token_nonce,
              };
            }
            if (res.outcome.status === "rejected") {
              throw new Error(`m2m enrollment rejected: ${res.outcome.error}`);
            }
            throw new Error(`unexpected enrollment outcome: ${JSON.stringify(res.outcome)}`);
          }
        }
      } finally {
        initiator.free();
        if (stream) {
          await stream.close();
        }
      }
    });
  }

  #persistRoster() {
    const fnBytes = this.#onPersistRosterBytes;
    const fnStr = this.#onPersistRoster;
    if (typeof fnBytes !== "function" && typeof fnStr !== "function") {
      return Promise.resolve();
    }
    const run = this.#persistChain.then(async () => {
      if (this.#wasmFreed) {
        throw new Error("TendrilWebClient has been freed");
      }
      this.#inPersistCallback += 1;
      try {
        if (typeof fnBytes === "function") {
          const bytes = this.#roster.to_json_bytes();
          try {
            await fnBytes(bytes);
          } finally {
            bytes.fill(0);
          }
          return;
        }
        await fnStr(this.#roster.to_json());
      } finally {
        this.#inPersistCallback -= 1;
      }
    });
    this.#persistChain = run.catch(() => {});
    return run;
  }

  async pair(options = {}) {
    if (options.p2pApiSecret) {
      throw new Error(
        "p2pApiSecret is not permitted in browser clients; pass a scoped p2pRelayAuthToken"
      );
    }
    return this.#withHold(() => this.#pairWithPolicy(1, options));
  }

  async pairV2(options = {}) {
    if (options.p2pApiSecret) {
      throw new Error(
        "p2pApiSecret is not permitted in browser clients; pass a scoped p2pRelayAuthToken"
      );
    }
    return this.#withHold(() => this.#pairWithPolicy(2, options));
  }

  /**
   * Multi-route pairing: classify the code before any dial; for Wire v1 race browser-compatible
   * candidates via Happy Eyeballs up to `msg2` verification behind a single-winner latch (for
   * Wire v2 `pairV2`, try candidates strictly sequentially); check `rp` and `rs` on verified
   * `msg2`, commit `msg3` on exactly one stream, and persist the outcome with its route plan in
   * one roster critical section.
   */
  async #pairWithPolicy(wire, opts) {
    const {
      endpoint = null,
      relayUrl = null,
      targetPub = null,
      expectedHost = null,
      relayUrlOverride = null,
      p2pRelayUrls = null,
      p2pRelayAuthToken = null,
      relayAuthTicket = null,
      relayAuthSecret = null,
      relayAuthOrigins = null,
      allowInsecureWs = false,
      code = "",
      pairingUri = null,
      pinnedHost = null,
      deviceName = "web-device",
      deviceKind = "web",
      timeoutMs = 15000,
      routePolicy = "allSigned",
      saveRoute = false,
    } = opts;
    const label = wire === 2 ? "v2 pairing" : "pairing";
    const secretMaster = copySecret(relayAuthSecret);
    const tokenMaster = copySecret(p2pRelayAuthToken);
    let codeBytes = null;
    try {
      const origins = normalizeOrigins(relayAuthOrigins);
      const policy = normalizeRoutePolicy(routePolicy);
      if (saveRoute && policy === "none") {
        throw new Error("saveRoute conflicts with routePolicy none");
      }
      const parsed = pairingUri ? parsePairingUri(pairingUri) : null;
      const explicitCode = code instanceof Uint8Array ? code.length > 0 : Boolean(code);
      let codeStr;
      if (explicitCode && code instanceof Uint8Array) {
        if (wire !== 2) {
          throw new TypeError("pair() takes a string code; use pairV2() for a byte code");
        }
        codeBytes = new Uint8Array(code);
        code.fill(0);
        codeStr = new TextDecoder().decode(codeBytes);
      } else if (explicitCode) {
        codeStr = String(code);
      } else if (parsed) {
        codeStr = parsed.code;
      } else {
        throw new Error("pairing code or pairingUri is required");
      }
      if (wire === 2 && codeBytes === null) {
        codeBytes = encoder.encode(codeStr);
      }
      const codeKind = classifyPairingCode(codeStr);

      // An operator relay `URL#key` dials the URL with the key as the mailbox; `/v2/relay` is
      // never a pairing route.
      const { url: explicitUrl, relayKey: explicitKey } = splitRelayKey(
        endpoint || relayUrl || null
      );
      if (explicitUrl && isWsUrl(explicitUrl) && isV2RelayUrl(explicitUrl)) {
        throw new Error(PAIR_V2_RELAY_REJECTED);
      }
      const explicitTargetPub = explicitKey ?? targetPub ?? parsed?.relay_pub_b64 ?? null;
      let candidates;
      let skipped = [];
      if (explicitUrl) {
        const explicitProvider =
          explicitUrl.startsWith("iroh://") || explicitUrl.startsWith("p2p:iroh://")
            ? "p2p"
            : explicitUrl.startsWith("wt://")
              ? "direct"
              : /^broker\+/i.test(explicitUrl)
                ? "broker"
                : "relay";
        const normalizedExplicit =
          explicitProvider === "p2p"
            ? explicitUrl.replace(/^p2p:/, "")
            : explicitProvider === "broker"
              ? explicitUrl.replace(/^broker\+/i, "")
              : explicitUrl;
        if (codeKind === "lan2_group") {
          let lanOk = false;
          if (explicitProvider === "direct") {
            try {
              lanOk = validateWtUrl(normalizedExplicit).isLanOrLoopback;
            } catch {}
          }
          if (!lanOk) {
            throw codedError(
              "pairing_path_disallowed",
              "pairing path disallowed: 2-group code disallowed on remote path"
            );
          }
        }
        candidates = [
          {
            hint: null,
            endpoint: normalizedExplicit,
            provider: explicitProvider,
            explicit: true,
          },
        ];
      } else if (parsed) {
        const p2p = parsed.endpoints.some(isIrohHint) ? await hasP2pSupport() : false;
        const webtransport = typeof globalThis.WebTransport === "function";
        try {
          ({ candidates, skipped } = filterWebCompatibleEndpoints(parsed.endpoints, {
            p2p,
            allowInsecureWs,
            webtransport,
          }));
        } catch (err) {
          if (codeKind === "lan2_group") {
            throw codedError(
              "pairing_path_disallowed",
              "pairing path disallowed: 2-group code disallowed on remote path"
            );
          }
          throw err;
        }
        if (codeKind === "lan2_group") {
          const lanCandidates = [];
          for (const cand of candidates) {
            let lanOk = false;
            if (cand.provider === "direct") {
              try {
                lanOk = validateWtUrl(cand.endpoint).isLanOrLoopback;
              } catch {}
            }
            if (lanOk) {
              lanCandidates.push(cand);
            } else {
              skipped.push({
                hint: String(cand.hint ?? cand.endpoint),
                reason: "lan_code_remote_hint",
              });
            }
          }
          if (lanCandidates.length === 0) {
            throw attemptError(
              codedError(
                "pairing_path_disallowed",
                "pairing path disallowed: 2-group code disallowed on remote path"
              ),
              { skipped }
            );
          }
          candidates = lanCandidates;
        }
      } else {
        throw new Error("endpoint, relayUrl or pairingUri is required");
      }

      let operatorEndpoint = null;
      if (explicitUrl) {
        const normalizedOp = explicitUrl.replace(/^broker\+/i, "broker+");
        operatorEndpoint =
          explicitTargetPub && isWsUrl(normalizedOp)
            ? `${normalizedOp}#${explicitTargetPub}`
            : normalizedOp;
      }
      let pinnedJson = null;
      if (wire === 2) {
        if (parsed) {
          pinnedJson = JSON.stringify({
            host_id: parsed.host_id ?? null,
            static_pub_b64: parsed.host_static_pub_b64,
            signing_pub_b64: parsed.host_signing_pub_hash_b64,
            rotation_seq: parsed.rotation_seq ?? 0,
            min_wire_version: 2,
          });
        } else if (pinnedHost) {
          pinnedJson = typeof pinnedHost === "string" ? pinnedHost : JSON.stringify(pinnedHost);
        }
      }
      const ctx = {
        wire,
        label,
        codeStr,
        codeBytes,
        parsed,
        pairingUri,
        pinnedJson,
        deviceName,
        deviceKind,
        persistOptions: {
          route_policy: policy,
          operator_endpoint: operatorEndpoint,
          save_committed: Boolean(saveRoute),
        },
        dial: {
          explicitUrl,
          targetPub: explicitUrl ? explicitTargetPub : parsed?.relay_pub_b64,
          expectedHost: explicitUrl ? expectedHost : null,
          relayUrlOverride: explicitUrl ? relayUrlOverride : null,
          p2pRelayUrls,
          tokenMaster,
          relayAuthTicket,
          secretMaster,
          origins,
          allowInsecureWs,
        },
      };

      if (candidates.some((c) => c.provider === "p2p")) {
        await initTendrilP2p();
      }
      this.#ensureOpen();
      const deadlineMs = performance.now() + timeoutMs;
      if (wire === 2) {
        const failures = [];
        const errors = [];
        for (let i = 0; i < candidates.length; i += 1) {
          const cand = candidates[i];
          const remaining = deadlineMs - performance.now();
          if (remaining <= 0) {
            errors.push(new Error(`${label} timed out`));
            failures.push({
              hint: cand.hint ?? cand.endpoint,
              provider: cand.provider,
              error: `${label} timed out`,
            });
            break;
          }
          const rungMs =
            i === candidates.length - 1 ? remaining : Math.min(remaining, RUNG_BUDGET_MS);
          const outcome = await this.#pairCandidate(
            ctx,
            cand,
            performance.now() + rungMs,
            deadlineMs
          );
          if (outcome.result) {
            return { ...outcome.result, skipped, failures };
          }
          if (outcome.committed || outcome.fatal) {
            throw attemptError(outcome.error, { committed: outcome.committed, skipped, failures });
          }
          errors.push(outcome.error);
          failures.push({
            hint: cand.hint ?? cand.endpoint,
            provider: cand.provider,
            error: errorText(outcome.error),
          });
        }
        throw attemptError(
          mostSevere(errors) ?? new Error(`${label} failed: all candidates exhausted`),
          {
            skipped,
            failures,
          }
        );
      }

      const race = await this.#raceCandidatesWithPlanner({
        candidates,
        timeoutMs,
        label,
        runCandidate: ({ cand, attemptDeadlineMs, signal, claimWin }) =>
          this.#pairCandidate(ctx, cand, attemptDeadlineMs, deadlineMs, { signal, claimWin }),
      });
      if (race.fatal) {
        throw attemptError(race.fatal.error, {
          committed: Boolean(race.fatal.committed),
          skipped,
          failures: race.failures,
        });
      }
      if (race.winner?.result) {
        return { ...race.winner.result, skipped, failures: race.failures };
      }
      throw attemptError(
        mostSevere(race.errors) ?? new Error(`${label} failed: all candidates exhausted`),
        {
          skipped,
          failures: race.failures,
        }
      );
    } finally {
      if (codeBytes) {
        codeBytes.fill(0);
      }
      if (secretMaster instanceof Uint8Array) {
        secretMaster.fill(0);
      }
      if (tokenMaster instanceof Uint8Array) {
        tokenMaster.fill(0);
      }
      if (relayAuthSecret instanceof Uint8Array) {
        relayAuthSecret.fill(0);
      }
      if (p2pRelayAuthToken instanceof Uint8Array) {
        p2pRelayAuthToken.fill(0);
      }
    }
  }

  /** Dials one pairing candidate. Returns `{result}`, `{cancelledByWinner}`, or `{error, committed, fatal}`. */
  async #pairCandidate(
    ctx,
    cand,
    rungDeadlineMs,
    deadlineMs,
    { signal = null, claimWin = null } = {}
  ) {
    const { wire, label } = ctx;
    let initiator = null;
    let scratch = null;
    let stream = null;
    let committed = false;
    let creds = null;
    let rungDeadline = rungDeadlineMs;
    const onAbort = () => {
      if (stream) {
        try {
          void Promise.resolve(stream.close()).catch(() => {});
        } catch {}
      }
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
      if (signal?.aborted) {
        throw makeAbortError(signal);
      }
      ({ initiator, scratch } = await this.#withRoster(
        () => {
          const scratchRoster = this.#roster.clone_roster();
          try {
            let machine;
            if (wire === 2) {
              machine = WasmV2PakePairInitiator.new_bytes(
                this.#identity,
                ctx.deviceName,
                ctx.deviceKind,
                new Uint8Array(ctx.codeBytes),
                ctx.pinnedJson
              );
            } else {
              machine = WasmPairInitiator.new_with_roster(
                this.#identity,
                ctx.deviceName,
                ctx.deviceKind,
                ctx.codeStr,
                ctx.parsed?.host_static_pub_b64 ?? null,
                ctx.parsed?.host_signing_pub_hash_b64 ?? null,
                ctx.parsed?.host_id ?? null,
                ctx.parsed?.rotation_seq ?? null,
                this.#roster
              );
            }
            return { initiator: machine, scratch: scratchRoster };
          } catch (err) {
            scratchRoster.free();
            throw err;
          }
        },
        { readOnly: true }
      ));
      initiator.enable_deferred_claim();
      if (ctx.pairingUri) {
        initiator.set_pairing_uri(ctx.pairingUri);
      }
      initiator.set_persist_options(
        JSON.stringify({ ...ctx.persistOptions, winner_hint: cand.hint ?? null })
      );
      const d = ctx.dial;
      creds =
        cand.provider === "relay"
          ? relayCredsFor(
              cand.endpoint,
              d.explicitUrl,
              d.origins,
              d.relayAuthTicket,
              d.secretMaster
            )
          : { relayAuthTicket: null, relayAuthSecret: null };
      let preStart = null;
      if (cand.provider === "relay") {
        const startedAt = performance.now();
        preStart = initiator.start();
        rungDeadline += performance.now() - startedAt;
      }
      stream = await dialWebStream({
        provider: cand.provider,
        endpoint:
          cand.provider === "p2p" || cand.provider === "broker" || cand.provider === "direct"
            ? cand.endpoint
            : null,
        relayUrl: cand.provider === "relay" ? cand.endpoint : null,
        targetPub: d.targetPub,
        expectedHost: d.expectedHost,
        relayUrlOverride: d.relayUrlOverride,
        p2pRelayUrls: d.p2pRelayUrls,
        p2pRelayAuthToken: copySecret(d.tokenMaster),
        relayAuthTicket: creds.relayAuthTicket,
        relayAuthSecret: creds.relayAuthSecret,
        allowInsecureWs: d.allowInsecureWs,
        irohHint: !cand.explicit,
        initFrame: preStart,
        timeoutMs: remainingBudgetMs(rungDeadline, `${label} timed out connecting to transport`),
        signal,
      });
      this.#ensureOpen();
      if (!preStart) {
        const startedAt = performance.now();
        preStart = initiator.start();
        rungDeadline += performance.now() - startedAt;
      }
      if (!stream.fastOpenSent) {
        await sendProtocolBytes(stream, preStart);
      }
      let verified = null;
      while (verified === null) {
        if (signal?.aborted) {
          throw makeAbortError(signal);
        }
        const frame = await stream.recv(
          remainingBudgetMs(rungDeadline, `${label} timed out waiting for host response`)
        );
        this.#ensureOpen();
        if (signal?.aborted) {
          throw makeAbortError(signal);
        }
        if (frame.status === "would_block") {
          throw new Error(`${label} timed out waiting for host response`);
        }
        if (frame.status === "eof") {
          throw new Error(`${label} stream closed before completion`);
        }
        const res = JSON.parse(initiator.feed_bytes(frame.bytes, scratch));
        if (res.host_verified) {
          verified = res;
          break;
        }
        if (res.write_b64) {
          await sendProtocolBytes(stream, b64urlDecode(res.write_b64));
        }
        if (res.outcome) {
          if (res.outcome.status === "rejected") {
            throw new Error(`${label} rejected: ${res.outcome.error}`);
          }
          throw new Error(`unexpected ${label} outcome: ${JSON.stringify(res.outcome)}`);
        }
      }
      if (!verified.relay_pub_ok) {
        throw codedError(
          "host_key_unverified",
          "relay key does not match the verified host signing key"
        );
      }
      if (verified.route_check === "invalid") {
        throw new FatalAttemptError(
          "invalid_pairing_uri",
          "invalid pairing URI: route statement does not verify"
        );
      }
      if (claimWin && !claimWin()) {
        return { cancelledByWinner: true };
      }
      const claim = initiator.commit_claim();
      committed = true;
      await sendProtocolBytes(stream, claim);
      while (true) {
        const frame = await stream.recv(
          remainingBudgetMs(deadlineMs, `${label} timed out waiting for host response`)
        );
        this.#ensureOpen();
        if (frame.status === "would_block") {
          throw new Error(`${label} timed out waiting for host response`);
        }
        if (frame.status === "eof") {
          throw new Error(`${label} stream closed before completion`);
        }
        const res = await this.#withRoster(async (tx) => {
          const step = JSON.parse(initiator.feed_bytes(frame.bytes, this.#roster));
          if (step.outcome && step.outcome.status === "pending") {
            await tx.persist();
          }
          return step;
        });
        if (res.write_b64) {
          await sendProtocolBytes(stream, b64urlDecode(res.write_b64));
        }
        if (res.outcome) {
          if (res.outcome.status === "pending") {
            return {
              result: {
                device_id: res.outcome.device_id,
                host_id: res.outcome.host_id,
                sas: res.outcome.sas,
                host_confirmed: Boolean(res.outcome.host_confirmed),
                route_check: res.outcome.route_check ?? verified.route_check,
                routes_persisted: res.outcome.routes ?? [],
                routes_reason: res.outcome.routes_reason ?? null,
                route: { hint: cand.hint, endpoint: cand.endpoint, provider: cand.provider },
              },
            };
          }
          if (res.outcome.status === "rejected") {
            throw new Error(`${label} rejected: ${res.outcome.error}`);
          }
          throw new Error(`unexpected ${label} outcome: ${JSON.stringify(res.outcome)}`);
        }
      }
    } catch (err) {
      if (!committed && signal?.aborted) {
        if (signal.reason?.cancelledByWinner) {
          return { cancelledByWinner: true };
        }
        return {
          error: candidateError(makeAbortError(signal), creds),
          committed: false,
          fatal: this.#freed || this.#wasmFreed,
        };
      }
      if (err?.cancelledByWinner) {
        return { cancelledByWinner: true };
      }
      const fatal =
        committed || err instanceof FatalAttemptError || this.#freed || this.#wasmFreed;
      return {
        error:
          err instanceof FatalAttemptError
            ? codedError(err.code, err.message)
            : candidateError(err, creds),
        committed,
        fatal,
      };
    } finally {
      signal?.removeEventListener("abort", onAbort);
      if (initiator) {
        initiator.free();
      }
      if (scratch) {
        scratch.free();
      }
      if (stream) {
        try {
          await stream.close();
        } catch {}
      }
    }
  }

  async connect(options = {}) {
    if (options.p2pApiSecret) {
      throw new Error(
        "p2pApiSecret is not permitted in browser clients; pass a scoped p2pRelayAuthToken"
      );
    }
    return this.#withHold(() => this.#connectWithPolicy(1, options));
  }

  async connectV2(options = {}) {
    if (options.p2pApiSecret) {
      throw new Error(
        "p2pApiSecret is not permitted in browser clients; pass a scoped p2pRelayAuthToken"
      );
    }
    return this.#withHold(() => this.#connectWithPolicy(2, options));
  }

  async #connectWithPolicy(wire, opts) {
    const {
      endpoint = null,
      relayUrl = null,
      targetPub = null,
      expectedHost = null,
      relayUrlOverride = null,
      p2pRelayUrls = null,
      p2pRelayAuthToken = null,
      relayAuthTicket = null,
      relayAuthSecret = null,
      relayAuthOrigins = null,
      useRelayV2 = false,
      allowInsecureWs = false,
      targetHostId,
      grantJson = null,
      crlSeq = null,
      timeoutMs = 15000,
      recoveryUri = null,
      replaceRoutes = false,
      routePolicy = "allSigned",
      webrtcUpgrade = true,
      autoUpgradeWebRtc = false,
      iceServers = [],
    } = opts;
    if (!Array.isArray(iceServers)) {
      throw new TypeError("iceServers must be an array");
    }
    const secretMaster = copySecret(relayAuthSecret);
    const tokenMaster = copySecret(p2pRelayAuthToken);
    try {
      const ctx = {
        wire,
        base: wire === 2 ? "v2 session" : "session",
        peer: targetHostId,
        grantJson,
        crlSeq,
        timeoutMs,
        recoveryUri: recoveryUri || null,
        replaceRoutes: Boolean(replaceRoutes),
        policy: normalizeRoutePolicy(routePolicy),
        origins: normalizeOrigins(relayAuthOrigins),
        p2pRelayUrls,
        tokenMaster,
        relayAuthTicket,
        secretMaster,
        allowInsecureWs,
        webrtcUpgrade: Boolean(webrtcUpgrade),
        autoUpgradeWebRtc: Boolean(autoUpgradeWebRtc),
        iceServers: [...iceServers],
      };
      if (endpoint || relayUrl) {
        return await this.#connectExplicit(ctx, {
          endpoint,
          relayUrl,
          targetPub,
          expectedHost,
          relayUrlOverride,
          useRelayV2: wire === 2 && Boolean(useRelayV2),
        });
      }
      return await this.#connectStored(ctx);
    } finally {
      if (secretMaster instanceof Uint8Array) {
        secretMaster.fill(0);
      }
      if (tokenMaster instanceof Uint8Array) {
        tokenMaster.fill(0);
      }
      if (relayAuthSecret instanceof Uint8Array) {
        relayAuthSecret.fill(0);
      }
      if (p2pRelayAuthToken instanceof Uint8Array) {
        p2pRelayAuthToken.fill(0);
      }
    }
  }

  /** `SessionHello.route_seq` for a stored peer under `policy`, or null. */
  #helloRouteSeq(peer, wire, policy) {
    try {
      const plan = JSON.parse(
        this.#roster.session_candidates(peer, JSON.stringify({ wire, route_policy: policy }))
      );
      return plan.route_seq ?? null;
    } catch {
      return null;
    }
  }

  #newSession(ctx, roster, routeSeq, operatorKey, upgradeCaps = null) {
    const seq = ctx.crlSeq ?? roster.crl_seq(ctx.peer);
    const session =
      ctx.wire === 2
        ? new WasmV2SessionInitiator(this.#identity, ctx.peer, roster, ctx.grantJson, seq ?? null)
        : WasmSessionClient.new_with_roster(
            this.#identity,
            ctx.peer,
            roster,
            ctx.grantJson,
            seq ?? null
          );
    try {
      if (routeSeq !== null && routeSeq !== undefined) {
        session.with_route_seq(routeSeq);
      }
      if (ctx.recoveryUri || operatorKey) {
        session.with_route_expectation(ctx.peer, ctx.recoveryUri, operatorKey ?? null);
      }
      if (Array.isArray(upgradeCaps) && upgradeCaps.length > 0) {
        session.with_upgrade_caps(JSON.stringify(upgradeCaps));
      }
    } catch (err) {
      session.free();
      throw err;
    }
    return session;
  }

  /**
   * Runs the session handshake on `stream`, feeding `roster`. With `locked`, `roster` is the
   * client roster and each feed is one roster critical section that persists any evidence it
   * changed, whether the feed failed, established or closed; a failed evidence persist locks the
   * client. Writes happen after the section releases.
   */
  async #driveHandshake(ctx, session, stream, roster, deadlineMs, startedMs, locked, preStart = null) {
    const { wire, base } = ctx;
    const m1 = preStart?.bytes ?? (wire === 2 ? session.start(nowUnixSecs()) : session.start());
    if (!preStart?.fastOpenSent) {
      await sendProtocolBytes(stream, m1);
    }
    while (true) {
      const frame = await stream.recv(remainingBudgetMs(deadlineMs, `${base} handshake timed out`));
      this.#ensureOpen();
      if (frame.status === "would_block") {
        throw new Error(`${base} handshake timed out`);
      }
      if (frame.status === "eof") {
        throw new Error(`${base} stream closed during handshake`);
      }
      const elapsedMs = Math.max(0, Math.floor(performance.now() - startedMs));
      const feed = () => {
        const step = JSON.parse(session.feed_bytes(frame.bytes, nowUnixSecs(), elapsedMs, roster));
        if (wire === 2) {
          return {
            step,
            out: session.poll_write(),
            events: JSON.parse(session.drain_events_json()),
          };
        }
        return {
          step,
          out: step.write_b64 ? b64urlDecode(step.write_b64) : null,
          events: step.events || [],
        };
      };
      let res;
      if (locked) {
        res = await this.#withRoster(
          async (tx) => {
            const prev = this.#snapshotRosterBytes();
            try {
              let r;
              try {
                r = feed();
              } catch (err) {
                if (this.#rosterChangedSince(prev)) {
                  try {
                    await tx.persist({ rollback: false });
                  } catch (persistErr) {
                    this.#lockClient(persistErr);
                    throw codedError(
                      toError(err).code,
                      `${base} handshake failed (${errorText(err)}); failed to persist roster update: ${errorText(persistErr)}`,
                      { cause: persistErr }
                    );
                  }
                }
                throw err;
              }
              if (this.#rosterChangedSince(prev)) {
                try {
                  await tx.persist({ rollback: false });
                } catch (persistErr) {
                  this.#lockClient(persistErr);
                  throw new Error(`failed to persist roster update: ${errorText(persistErr)}`, {
                    cause: persistErr,
                  });
                }
              }
              return r;
            } finally {
              if (prev) {
                prev.fill(0);
              }
            }
          },
          { snapshot: false }
        );
      } else {
        res = feed();
      }
      if (res.out && res.out.length > 0) {
        await sendProtocolBytes(stream, res.out);
      }
      if (res.step.established) {
        return res.events;
      }
    }
  }

  /** Final authorization of a winner, inside a roster critical section. */
  #checkWinner(ctx, session, applyRotation) {
    if (applyRotation) {
      const rotation = session.presented_rotation_json();
      if (rotation && rotation !== "[]") {
        this.#roster.apply_verified_rotation_json(ctx.peer, rotation);
      }
    }
    const keysRaw = session.presented_host_keys_json();
    if (!keysRaw) {
      throw codedError(
        "host_key_unverified",
        "host key could not be verified against pin or rotation chain"
      );
    }
    const keys = JSON.parse(keysRaw);
    this.#roster.check_established_session(
      ctx.peer,
      keys.static_pub_b64,
      keys.signing_pub_b64,
      ctx.wire
    );
  }

  /** Applies a verified recovery URI's routes; only after the final checkpassed. */
  #applyRecoveryRoutes(ctx, session) {
    if (!ctx.recoveryUri || !session.verified_recovery_statement_json()) {
      return null;
    }
    try {
      return JSON.parse(
        this.#roster.apply_signed_route_uri(
          ctx.recoveryUri,
          JSON.stringify({ route_policy: ctx.policy, replace_routes: ctx.replaceRoutes })
        )
      );
    } catch (err) {
      return { applied: false, reason: "invalid_routes", error: errorText(err) };
    }
  }

  #handOff(ctx, session, stream, startedMs, initialEvents, recoveryRoutes, routeProvider = null) {
    let releaseSession = null;
    const webSession = new TendrilWebSession(
      SESSION_TOKEN,
      session,
      stream,
      this.#roster,
      startedMs,
      {
        withRoster: (fn, options) => this.#withRoster(fn, options),
        lockClient: (persistErr) => this.#lockClient(persistErr),
        snapshotRoster: () => this.#snapshotRosterBytes(),
        rosterChangedSince: (prev) => this.#rosterChangedSince(prev),
        peerId: ctx.peer,
        routePolicy: ctx.policy,
        recoveryRoutes: recoveryRoutes ?? null,
        routeProvider,
        grantJson: ctx.grantJson ?? null,
        dialUpgradeSession: async (newStream, deadlineMs, expectedPeerDeviceId) => {
          this.#ensureOpen();
          const upgradeCtx = {
            ...ctx,
            crlSeq: null,
            recoveryUri: null,
            grantJson: webSession._currentGrantJson(),
            webrtcUpgrade: false,
          };
          const newSession = await this.#withRoster(
            () => this.#newSession(upgradeCtx, this.#roster, null, null, null),
            { readOnly: true }
          );
          let committed = false;
          try {
            const newStartedMs = performance.now();
            const newInitialEvents = await this.#driveHandshake(
              upgradeCtx,
              newSession,
              newStream,
              this.#roster,
              deadlineMs,
              newStartedMs,
              true,
              null
            );
            await this.#withRoster(
              async (tx) => {
                const prev = this.#snapshotRosterBytes();
                let checkErr = null;
                try {
                  this.#checkWinner(upgradeCtx, newSession, true);
                  const newPeerDevId =
                    typeof newSession.peer_device_id === "function"
                      ? (newSession.peer_device_id() ?? null)
                      : null;
                  if (
                    typeof expectedPeerDeviceId !== "string" ||
                    expectedPeerDeviceId.length === 0 ||
                    typeof newPeerDevId !== "string" ||
                    newPeerDevId.length === 0 ||
                    newPeerDevId !== expectedPeerDeviceId
                  ) {
                    throw codedError(
                      "host_key_unverified",
                      "upgraded WebRTC peer device identity mismatch"
                    );
                  }
                } catch (err) {
                  checkErr = err;
                }
                if (this.#rosterChangedSince(prev)) {
                  try {
                    await tx.persist({ rollback: false });
                  } catch (persistErr) {
                    this.#lockClient(persistErr);
                    prev?.fill(0);
                    throw codedError(
                      checkErr?.code,
                      checkErr
                        ? `${errorText(checkErr)}; failed to persist roster update: ${errorText(persistErr)}`
                        : `failed to persist roster update: ${errorText(persistErr)}`,
                      { cause: persistErr }
                    );
                  }
                }
                prev?.fill(0);
                if (checkErr) {
                  throw checkErr;
                }
              },
              { snapshot: false }
            );
            committed = true;
            return { newSession, newStartedMs, newInitialEvents };
          } finally {
            if (!committed) {
              newSession.free();
            }
          }
        },
      },
      initialEvents,
      () => {
        if (releaseSession) {
          releaseSession();
          releaseSession = null;
        }
      },
      ctx.wire === 2,
      this.#groupHook()
    );
    releaseSession = this.#attachSession(webSession);
    return webSession;
  }

  async #connectExplicit(ctx, t) {
    const { wire, base, peer } = ctx;
    const relaySplit = splitRelayKey(t.relayUrl);
    const endpointSplit = splitRelayKey(t.endpoint);
    const endpoint = endpointSplit.url;
    const relayUrl = relaySplit.url;
    const operatorKey = relaySplit.relayKey ?? endpointSplit.relayKey;
    // The mailbox key is the expectation's relay key: the operator `URL#key`, else the recovery
    // URI's `rp` (a conflict between them fails pre-dial in `with_route_expectation`), else the
    // caller's `targetPub`.
    const recoveryRp = ctx.recoveryUri
      ? (parsePairingUri(ctx.recoveryUri).relay_pub_b64 ?? null)
      : null;
    const targetPub = operatorKey ?? recoveryRp ?? t.targetPub;
    await warmTargetTransport(endpoint, relayUrl);
    this.#ensureOpen();
    const target = endpoint || relayUrl;
    const isRelay = isRelayTarget(target);
    const explicitProvider = isRelay
      ? "relay"
      : target?.startsWith("wt://")
        ? "direct"
        : target?.startsWith("iroh://")
          ? "p2p"
          : "broker";
    const upgradeCaps =
      ctx.webrtcUpgrade &&
      hasWebRtcSupport() &&
      explicitProvider !== "p2p" &&
      explicitProvider !== "direct"
        ? ["webrtc/v1"]
        : null;
    const deadlineMs = performance.now() + ctx.timeoutMs;
    const session = await this.#withRoster(
      () =>
        this.#newSession(
          ctx,
          this.#roster,
          this.#helloRouteSeq(peer, wire, ctx.policy),
          operatorKey,
          upgradeCaps
        ),
      { readOnly: true }
    );
    let stream = null;
    let handedOff = false;
    try {
      const { relayAuthTicket: ticket, relayAuthSecret: secret } = relayCredsFor(
        target,
        target,
        ctx.origins,
        ctx.relayAuthTicket,
        ctx.secretMaster
      );
      const explicitCreds = { relayAuthTicket: ticket, relayAuthSecret: secret };
      const deriveV2Dial = t.useRelayV2
        ? ({ relayHost, nonceBytes, connIdBytes }) =>
            JSON.parse(
              this.#roster.derive_v2_relay_dial_for_peer_json(
                peer,
                relayHost,
                nowUnixSecs(),
                nonceBytes,
                connIdBytes
              )
            )
        : null;
      const isRelay = isRelayTarget(target);
      const startedMs = performance.now();
      const preBytes = isRelay
        ? wire === 2
          ? session.start(nowUnixSecs())
          : session.start()
        : null;
      stream = await dialWebStream({
        endpoint,
        relayUrl,
        targetPub,
        expectedHost: t.expectedHost,
        relayUrlOverride: t.relayUrlOverride,
        p2pRelayUrls: ctx.p2pRelayUrls,
        p2pRelayAuthToken: copySecret(ctx.tokenMaster),
        ...explicitCreds,
        useRelayV2: t.useRelayV2,
        deriveV2Dial,
        allowInsecureWs: ctx.allowInsecureWs,
        initFrame: preBytes,
        timeoutMs: remainingBudgetMs(
          deadlineMs,
          `${base} handshake timed out connecting to transport`
        ),
      });
      this.#ensureOpen();
      const initialEvents = await this.#driveHandshake(
        ctx,
        session,
        stream,
        this.#roster,
        deadlineMs,
        isRelay ? startedMs : performance.now(),
        true,
        preBytes ? { bytes: preBytes, fastOpenSent: Boolean(stream.fastOpenSent) } : null
      );
      let recoveryRoutes = null;
      if (ctx.recoveryUri) {
        // A route-only change: a failed persist rolls it back to the snapshot.
        recoveryRoutes = await this.#withRoster(async (tx) => {
          this.#checkWinner(ctx, session, false);
          const applied = this.#applyRecoveryRoutes(ctx, session);
          if (applied && applied.applied) {
            try {
              await tx.persist();
            } catch (persistErr) {
              throw new Error(`failed to persist recovery routes: ${errorText(persistErr)}`, {
                cause: persistErr,
              });
            }
          }
          return applied;
        });
      }
      this.#ensureUnlocked();
      const webSession = this.#handOff(
        ctx,
        session,
        stream,
        startedMs,
        initialEvents,
        recoveryRoutes,
        explicitProvider
      );
      handedOff = true;
      if (
        ctx.autoUpgradeWebRtc &&
        explicitProvider !== "p2p" &&
        explicitProvider !== "direct" &&
        webSession.canSendPathUpgrade() &&
        webSession.negotiatedUpgradeCaps().includes("webrtc/v1")
      ) {
        try {
          await webSession.upgradeToWebRtc({
            iceServers: ctx.iceServers,
            timeoutMs: remainingBudgetMs(deadlineMs, `${base} upgrade timed out`),
          });
        } catch (upgradeErr) {
          if (isFatalUpgradeError(upgradeErr)) {
            await webSession.close().catch(() => {});
            throw upgradeErr;
          }
        }
      }
      return webSession;
    } catch (err) {
      if (!handedOff) {
        session.free();
        if (stream) {
          await stream.close();
        }
      }
      throw err;
    }
  }

  /**
   * Drives concurrent Happy Eyeballs dialing over `WasmPathPlanner` (`250 ms` stagger, `500 ms`
   * P2P cold-start hold delay, `next_deadline_ms()` timer loop). `runCandidate` receives
   * `{ id, cand, attemptDeadlineMs, signal, claimWin }` and must never reject.
   */
  async #raceCandidatesWithPlanner({ candidates, timeoutMs, label, runCandidate, onDiscard }) {
    if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
      throw new RangeError("timeoutMs must be a finite non-negative number");
    }
    const safeTimeoutMs = Math.ceil(timeoutMs);
    const startMs = performance.now();
    const nowRel = () => Math.max(0, Math.floor(performance.now() - startMs));
    const planner = new WasmPathPlanner(
      JSON.stringify(
        candidates.map((cand, id) => ({
          id,
          addr: cand.hint ?? cand.endpoint,
          provider: cand.provider,
        }))
      ),
      JSON.stringify({
        attempt_stagger_ms: 250,
        p2p_cold_delay_ms: 500,
        exhaustion_timeout_ms: safeTimeoutMs,
      })
    );
    const controllers = new Map();
    const inFlight = new Map();
    const pendingResults = [];
    const failures = [];
    const errors = [];
    let winner = null;
    let winnerClaimed = false;
    let fatal = null;
    let exhausted = false;
    let timer = null;
    let wakeResolve = null;

    const wake = () => {
      if (wakeResolve) {
        const resolve = wakeResolve;
        wakeResolve = null;
        resolve();
      }
    };
    const abortReasonWinner = () => {
      const err = new Error("aborted by winning route");
      err.name = "AbortError";
      err.cancelledByWinner = true;
      return err;
    };
    const abortAllOthers = (keepId, reason) => {
      for (const [id, ac] of controllers) {
        if (id !== keepId && !ac.signal.aborted) {
          ac.abort(reason);
        }
      }
    };
    const waitUntilWakeOrDeadline = (deadlineRelMs) => {
      if (pendingResults.length > 0 || winner || fatal || exhausted) {
        return Promise.resolve();
      }
      return new Promise((resolve) => {
        wakeResolve = () => {
          if (timer !== null) {
            clearTimeout(timer);
            timer = null;
          }
          resolve();
        };
        if (deadlineRelMs !== null && deadlineRelMs !== undefined) {
          const delayMs = Math.max(0, deadlineRelMs - nowRel());
          timer = setTimeout(() => {
            timer = null;
            if (wakeResolve) {
              const r = wakeResolve;
              wakeResolve = null;
              r();
            }
          }, delayMs);
        }
      });
    };

    let processedFailure = false;
    const ingestPendingResults = async () => {
      processedFailure = false;
      while (pendingResults.length > 0) {
        const { id, cand, res } = pendingResults.shift();
        controllers.delete(id);
        if (res.cancelledByWinner) {
          continue;
        }
        if (res.fatal) {
          if (!fatal) {
            fatal = res;
            abortAllOthers(id, new Error(`${label} aborted`));
          }
          continue;
        }
        if (res.winner || res.result) {
          if (!winner && !fatal && !exhausted) {
            winner = res;
            if (!winnerClaimed) {
              winnerClaimed = true;
              abortAllOthers(id, abortReasonWinner());
              planner.on_dial_succeeded(id, nowRel());
            }
          } else if (onDiscard) {
            await onDiscard(res);
          }
          continue;
        }
        if (this.#freed || this.#wasmFreed) {
          if (!fatal) {
            fatal = { error: res.error, committed: Boolean(res.committed) };
            abortAllOthers(id, new Error(`${label} aborted`));
          }
          continue;
        }
        errors.push(res.error);
        failures.push({
          hint: cand.hint ?? cand.endpoint,
          provider: cand.provider,
          error: errorText(res.error),
        });
        if (!winnerClaimed && !exhausted && !fatal) {
          planner.on_dial_failed(id, errorText(res.error), nowRel());
          processedFailure = true;
        }
      }
    };

    try {
      planner.start(0);
      while (!winner && !fatal && !exhausted) {
        const actions = JSON.parse(planner.drain_actions());
        for (const action of actions) {
          if (action.action === "dial_candidate") {
            const id = action.candidate.id;
            const cand = candidates[id];
            const ac = new AbortController();
            controllers.set(id, ac);
            const attemptDeadlineMs = startMs + safeTimeoutMs;
            const claimWin = () => {
              if (winnerClaimed || winner || fatal || exhausted || ac.signal.aborted) {
                return false;
              }
              winnerClaimed = true;
              abortAllOthers(id, abortReasonWinner());
              planner.on_dial_succeeded(id, nowRel());
              return true;
            };
            const job = Promise.resolve()
              .then(() =>
                runCandidate({
                  id,
                  cand,
                  attemptDeadlineMs,
                  signal: ac.signal,
                  claimWin,
                })
              )
              .then(
                (res) => ({ id, cand, res }),
                (err) => ({ id, cand, res: { error: toError(err) } })
              )
              .then((entry) => {
                pendingResults.push(entry);
                wake();
              });
            inFlight.set(id, job);
          } else if (action.action === "cancel_candidate") {
            const ac = controllers.get(action.id);
            if (ac && !ac.signal.aborted) {
              ac.abort(
                winnerClaimed || winner ? abortReasonWinner() : new Error(`${label} timed out`)
              );
            }
          } else if (action.action === "all_candidates_exhausted") {
            exhausted = true;
          }
        }
        if (winner || fatal || exhausted) {
          break;
        }
        await ingestPendingResults();
        if (winner || fatal || exhausted) {
          break;
        }
        if (processedFailure) {
          continue;
        }
        const nextDeadline = planner.next_deadline_ms();
        if (nextDeadline !== undefined && nextDeadline !== null) {
          const cur = nowRel();
          if (cur >= nextDeadline) {
            planner.tick(cur);
          } else {
            await waitUntilWakeOrDeadline(nextDeadline);
            if (pendingResults.length === 0) {
              planner.tick(nowRel());
            }
          }
        } else if (pendingResults.length === 0) {
          if (controllers.size === 0) {
            exhausted = true;
            break;
          }
          await waitUntilWakeOrDeadline(null);
        }
      }
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      abortAllOthers(
        -1,
        winnerClaimed || winner
          ? abortReasonWinner()
          : fatal
            ? new Error(`${label} aborted`)
            : new Error(`${label} timed out`)
      );
      await Promise.allSettled([...inFlight.values()]);
      await ingestPendingResults();
      return { winner, fatal, failures, errors };
    } finally {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      abortAllOthers(
        -1,
        winnerClaimed || winner ? abortReasonWinner() : new Error(`${label} aborted`)
      );
      planner.free();
    }
  }

  /**
   * Endpoint-free Day-2 connect: plan under a read-only roster
   * section, dial each stored or recovery candidate against its own roster clone, reconcile the
   * evidence and run the final check in one roster section, then hand the winner over.
   */
  async #connectStored(ctx) {
    const { wire, peer, base } = ctx;
    let p2p = false;
    const view = this.getPeer(peer);
    let recoveryHasIroh = false;
    if (ctx.recoveryUri) {
      recoveryHasIroh = parsePairingUri(ctx.recoveryUri).endpoints.some(isIrohHint);
    }
    if (recoveryHasIroh || (view && view.routes.some((r) => isIrohHint(r.hint)))) {
      p2p = await hasP2pSupport();
    }
    const webtransport = typeof globalThis.WebTransport === "function";
    this.#ensureOpen();
    let plan;
    try {
      plan = await this.#withRoster(
        () => {
          if (wire === 1) {
            this.#roster.check_allows_wire_v1(peer);
          }
          const snap = this.#roster.pin_snapshot(peer);
          try {
            const cands = JSON.parse(
              this.#roster.session_candidates(
                peer,
                JSON.stringify({
                  recovery_uri: ctx.recoveryUri,
                  wire,
                  route_policy: ctx.policy,
                  p2p,
                  webtransport,
                  allow_insecure_ws: Boolean(ctx.allowInsecureWs),
                })
              )
            );
            return { snap, snapBytes: this.#roster.to_json_bytes(), cands };
          } catch (err) {
            snap.free();
            throw err;
          }
        },
        { readOnly: true }
      );
    } catch (err) {
      throw toError(err);
    }
    const { snap, snapBytes, cands } = plan;
    const skipped = cands.skipped ?? [];
    try {
      if (cands.candidates.length === 0) {
        let msg = `no dialable stored routes for ${peer}`;
        if (skipped.length > 0) {
          const reasons = skipped.map((s) => `${redactHint(s.hint)} [${s.reason}]`);
          msg += ` (skipped: ${reasons.join(", ")})`;
        }
        if (cands.legacy_relay_hints) {
          msg +=
            "; legacy relay hints are never dialed automatically: re-pair, apply a fresh signed pairing URI, or connect with an explicit endpoint";
        }
        msg += `; ${DAY2_RECOVERY_GUIDANCE}`;
        throw attemptError(new Error(msg), { skipped });
      }
      if (cands.candidates.some((c) => c.provider === "p2p")) {
        await initTendrilP2p();
      }
      const evidence = { records: [], recordKeys: new Set(), crls: [] };
      const race = await this.#raceCandidatesWithPlanner({
        candidates: cands.candidates,
        timeoutMs: ctx.timeoutMs,
        label: `${base} handshake`,
        runCandidate: ({ cand, attemptDeadlineMs, signal }) =>
          this.#connectCandidate(ctx, cands, cand, snapBytes, attemptDeadlineMs, evidence, signal),
        onDiscard: async (res) => {
          if (res?.winner) {
            await this.#discardWinner(res.winner);
          }
        },
      });
      if (race.fatal) {
        throw race.fatal.error;
      }
      const winner = race.winner?.winner ?? null;
      const failures = race.failures;
      const errors = race.errors;
      let fin;
      try {
        fin = await this.#finalizeConnect(ctx, snap, evidence, winner);
      } catch (err) {
        fin = { error: toError(err) };
      }
      if (fin.error) {
        if (winner) {
          await this.#discardWinner(winner);
        }
        throw attemptError(fin.error, { skipped, failures });
      }
      if (!winner) {
        const relayOffline =
          !ctx.recoveryUri &&
          failures.length > 0 &&
          failures.every((f) => f.provider === "relay" && f.error.includes("offline"));
        const err = relayOffline
          ? new Error(RELAY_OFFLINE_ROTATED)
          : (mostSevere(errors) ?? new Error("all candidates exhausted"));
        throw attemptError(err, { skipped, failures });
      }
      try {
        this.#ensureUnlocked();
      } catch (err) {
        await this.#discardWinner(winner);
        throw err;
      }
      winner.clone.free();
      const webSession = this.#handOff(
        ctx,
        winner.session,
        winner.stream,
        winner.startedMs,
        winner.initialEvents,
        fin.recovery,
        winner.cand.provider
      );
      webSession.route = {
        hint: winner.cand.hint,
        endpoint: winner.cand.endpoint,
        provider: winner.cand.provider,
      };
      webSession.skipped = skipped;
      webSession.failures = failures;
      if (
        ctx.autoUpgradeWebRtc &&
        winner.cand.provider !== "p2p" &&
        winner.cand.provider !== "direct" &&
        webSession.canSendPathUpgrade() &&
        webSession.negotiatedUpgradeCaps().includes("webrtc/v1")
      ) {
        try {
          await webSession.upgradeToWebRtc({
            iceServers: ctx.iceServers,
            timeoutMs: ctx.timeoutMs,
          });
        } catch (upgradeErr) {
          if (isFatalUpgradeError(upgradeErr)) {
            await webSession.close().catch(() => {});
            throw upgradeErr;
          }
        }
      }
      return webSession;
    } finally {
      snap.free();
      snapBytes.fill(0);
    }
  }

  /** Dials one Day-2 candidate against its own roster clone and records its evidence. */
  async #connectCandidate(ctx, cands, cand, snapBytes, rungDeadline, evidence, signal = null) {
    const { peer, base } = ctx;
    let clone = null;
    let session = null;
    let stream = null;
    let won = false;
    let creds = null;
    const onAbort = () => {
      if (stream) {
        try {
          void Promise.resolve(stream.close()).catch(() => {});
        } catch {}
      }
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
      if (signal?.aborted) {
        throw makeAbortError(signal);
      }
      clone = WasmRoster.from_json_bytes(snapBytes.slice());
      const upgradeCaps =
        ctx.webrtcUpgrade &&
        hasWebRtcSupport() &&
        cand.provider !== "p2p" &&
        cand.provider !== "direct"
          ? ["webrtc/v1"]
          : null;
      session = this.#newSession(ctx, clone, cands.route_seq, null, upgradeCaps);
      const isRelay = cand.provider === "relay";
      const v2Relay = isRelay && isV2RelayUrl(cand.endpoint);
      const dialClone = clone;
      const startedMs = performance.now();
      const preBytes = isRelay
        ? ctx.wire === 2
          ? session.start(nowUnixSecs())
          : session.start()
        : null;
      creds = isRelay
        ? relayCredsFor(cand.endpoint, null, ctx.origins, ctx.relayAuthTicket, ctx.secretMaster)
        : { relayAuthTicket: null, relayAuthSecret: null };
      stream = await dialWebStream({
        provider: cand.provider,
        endpoint:
          cand.provider === "p2p" || cand.provider === "broker" || cand.provider === "direct"
            ? cand.endpoint
            : null,
        relayUrl: isRelay ? cand.endpoint : null,
        targetPub: cands.relay_key_b64,
        p2pRelayUrls: ctx.p2pRelayUrls,
        p2pRelayAuthToken: copySecret(ctx.tokenMaster),
        relayAuthTicket: creds.relayAuthTicket,
        relayAuthSecret: creds.relayAuthSecret,
        useRelayV2: v2Relay,
        deriveV2Dial: v2Relay
          ? ({ relayHost, nonceBytes, connIdBytes }) =>
              JSON.parse(
                dialClone.derive_v2_relay_dial_for_peer_json(
                  peer,
                  relayHost,
                  nowUnixSecs(),
                  nonceBytes,
                  connIdBytes
                )
              )
          : null,
        allowInsecureWs: ctx.allowInsecureWs,
        irohHint: cand.source !== "operator",
        initFrame: preBytes,
        timeoutMs: remainingBudgetMs(
          rungDeadline,
          `${base} handshake timed out connecting to transport`
        ),
        signal,
      });
      this.#ensureOpen();
      if (signal?.aborted) {
        throw makeAbortError(signal);
      }
      const handshakeStartedMs = isRelay ? startedMs : performance.now();
      const initialEvents = await this.#driveHandshake(
        ctx,
        session,
        stream,
        clone,
        rungDeadline,
        handshakeStartedMs,
        false,
        preBytes ? { bytes: preBytes, fastOpenSent: Boolean(stream.fastOpenSent) } : null
      );
      if (signal?.aborted) {
        throw makeAbortError(signal);
      }
      won = true;
      return { winner: { session, stream, clone, startedMs: handshakeStartedMs, initialEvents, cand } };
    } catch (err) {
      if (signal?.aborted) {
        if (signal.reason?.cancelledByWinner) {
          return { cancelledByWinner: true };
        }
        return { error: candidateError(makeAbortError(signal), creds) };
      }
      if (err?.cancelledByWinner) {
        return { cancelledByWinner: true };
      }
      return { error: candidateError(err, creds) };
    } finally {
      signal?.removeEventListener("abort", onAbort);
      if (session) {
        try {
          for (const record of JSON.parse(session.presented_rotation_json())) {
            const key = JSON.stringify(record);
            if (!evidence.recordKeys.has(key)) {
              evidence.recordKeys.add(key);
              evidence.records.push(record);
            }
          }
        } catch {}
      }
      if (clone) {
        try {
          evidence.crls.push(...JSON.parse(clone.export_crls_json()));
        } catch {}
      }
      if (!won) {
        if (session) {
          session.free();
        }
        if (clone) {
          clone.free();
        }
        if (stream) {
          try {
            await stream.close();
          } catch {}
        }
      }
    }
  }

  async #discardWinner(winner) {
    winner.session.free();
    winner.clone.free();
    try {
      await winner.stream.close();
    } catch {}
  }

  /**
   * The final checks in one roster critical section: merge candidate CRLs, reconcile
   * every presented rotation against the snapshot (a fork revokes and is persisted first), then
   * for a winner apply its rotation, run the final check, and only then apply recovery routes.
   * Changed evidence is persisted whatever the outcome and a failed evidence persist locks the
   * client; an unchanged roster is not persisted. Recovery routes are a route-only change: a
   * failed persist rolls them back and fails the connect without locking the client.
   */
  async #finalizeConnect(ctx, snap, evidence, winner) {
    const { peer } = ctx;
    return this.#withRoster(
      async (tx) => {
        const before = this.#snapshotRosterBytes();
        let afterEvidence = null;
        try {
          const persistEvidence = async () => {
            if (!this.#rosterChangedSince(before)) {
              return null;
            }
            try {
              await tx.persist({ rollback: false });
              return null;
            } catch (persistErr) {
              this.#lockClient(persistErr);
              return persistErr;
            }
          };
          const withCause = (err, persistErr) =>
            persistErr ? codedError(err.code, errorText(err), { cause: persistErr }) : err;
          this.#roster.merge_crl_evidence(JSON.stringify(evidence.crls));
          try {
            this.#roster.reconcile_rotation_evidence(peer, snap, JSON.stringify(evidence.records));
          } catch (forkErr) {
            return { error: withCause(toError(forkErr), await persistEvidence()) };
          }
          if (!winner) {
            const persistErr = await persistEvidence();
            if (persistErr) {
              return {
                error: new Error(`failed to persist connect evidence: ${errorText(persistErr)}`, {
                  cause: persistErr,
                }),
              };
            }
            return { error: null };
          }
          let finalErr = null;
          try {
            this.#checkWinner(ctx, winner.session, true);
          } catch (err) {
            finalErr = toError(err);
          }
          if (finalErr) {
            return { error: withCause(finalErr, await persistEvidence()) };
          }
          const persistErr = await persistEvidence();
          if (persistErr) {
            return {
              error: new Error(`failed to persist roster update: ${errorText(persistErr)}`, {
                cause: persistErr,
              }),
            };
          }
          afterEvidence = this.#snapshotRosterBytes();
          const recovery = this.#applyRecoveryRoutes(ctx, winner.session);
          if (this.#rosterChangedSince(afterEvidence)) {
            try {
              await tx.persist({ rollback: false });
            } catch (routesErr) {
              this.#restoreRosterBytes(afterEvidence);
              return {
                error: new Error(`failed to persist recovery routes: ${errorText(routesErr)}`, {
                  cause: routesErr,
                }),
              };
            }
          }
          return { error: null, recovery };
        } finally {
          if (before) {
            before.fill(0);
          }
          if (afterEvidence) {
            afterEvidence.fill(0);
          }
        }
      },
      { snapshot: false }
    );
  }

  free() {
    if (this.#freed) {
      return;
    }
    this.#freed = true;
    for (const group of [...this.#openGroups]) {
      group.close();
    }
    for (const sess of [...this.#activeSessions]) {
      sess._abortFromClientFree();
    }
    this.#maybeFreeWasm();
  }
}

class UpgradeDeclinedError extends Error {
  constructor(reason) {
    super(`webrtc upgrade declined: ${reason}`);
    this.reason = reason;
  }
}

export class TendrilWebSession {
  #session;
  #stream;
  #roster;
  #startedMs;
  #withRoster;
  #lockClient;
  #snapshotRoster;
  #rosterChangedSince;
  #peerId;
  #routePolicy;
  #recoveryRoutes;
  #routeProvider;
  #dialUpgradeSession;
  #grantJson;
  #lastRouteSet = null;
  #lastRouteSetMs = null;
  #onRelease;
  #queue;
  #isV2;
  #peerDeviceId;
  #groupHook;
  #sendChain = Promise.resolve();
  #recvChain = Promise.resolve();
  #epoch = 0;
  #nextUpgradeId = 0;
  #upgradePromise = null;
  #pendingUpgrade = null;
  #closing = false;
  #freed = false;
  #closePromise = null;
  #persistFailedErr = null;
  #failureClosed = false;

  constructor(
    token,
    session,
    stream,
    roster,
    startedMs,
    rosterOps,
    initialEvents = [],
    onRelease = null,
    isV2 = false,
    groupHook = null
  ) {
    if (token !== SESSION_TOKEN) {
      throw new Error("Use TendrilWebClient.connect()");
    }
    this.#session = session;
    this.#stream = stream;
    this.#roster = roster;
    this.#startedMs = startedMs;
    this.#withRoster = rosterOps.withRoster;
    this.#lockClient = rosterOps.lockClient ?? noop;
    this.#snapshotRoster = rosterOps.snapshotRoster ?? (() => null);
    this.#rosterChangedSince = rosterOps.rosterChangedSince ?? (() => false);
    this.#peerId = rosterOps.peerId;
    this.#routePolicy = rosterOps.routePolicy ?? "all_signed";
    this.#recoveryRoutes = rosterOps.recoveryRoutes ?? null;
    this.#routeProvider = rosterOps.routeProvider ?? null;
    this.#dialUpgradeSession = rosterOps.dialUpgradeSession ?? null;
    this.#grantJson = rosterOps.grantJson ?? null;
    this.#onRelease = onRelease;
    this.#queue = [...initialEvents];
    this.#isV2 = Boolean(isV2);
    this.#groupHook = groupHook;
    this.#peerDeviceId =
      typeof session.peer_device_id === "function" ? (session.peer_device_id() ?? null) : null;
  }

  /** Device id derived from the static key authenticated by the handshake. */
  get peerDeviceId() {
    return this.#peerDeviceId;
  }

  /** What a recovery URI given to `connect` did to the stored routes, or null. */
  get recoveryRoutes() {
    return this.#recoveryRoutes;
  }

  /** Outcome of the last host route set (`0x0C`) this session received, or null. */
  get lastRouteSet() {
    return this.#lastRouteSet;
  }

  /**
   * One roster critical section on the client lock. An evidence persist failure inside marks the
   * session and the client failed there; the stream is closed only after the section released.
   */
  async #rosterSection(fn, { snapshot = false, readOnly = false } = {}) {
    try {
      return await this.#withRoster(fn, { snapshot, readOnly });
    } finally {
      if (this.#persistFailedErr && !this.#failureClosed) {
        this.#failureClosed = true;
        try {
          void Promise.resolve(this.#stream.close()).catch(() => {});
        } catch {}
      }
    }
  }

  _currentGrantJson() {
    return this.#grantJson;
  }

  #rejectPendingUpgrade(err) {
    if (this.#pendingUpgrade) {
      const pu = this.#pendingUpgrade;
      this.#pendingUpgrade = null;
      pu.reject(err);
    }
  }

  /** Authenticated evidence could not be persisted: fail this session and lock the client. */
  #markPersistFailed(persistErr) {
    this.#persistFailedErr = persistErr;
    this.#closing = true;
    this.#rejectPendingUpgrade(persistErr);
    this.#lockClient(persistErr);
  }

  #drainRouteSets() {
    try {
      return JSON.parse(this.#session.take_route_sets());
    } catch {
      return [];
    }
  }

  /**
   * Applies host route sets under `allSigned`, at most one per 10 s per session. A set is a
   * route-only change: a failed persist rolls it back and reports `persist_failed`; the session
   * and the client stay usable.
   */
  async #ingestRouteSets(sets) {
    if (!sets || sets.length === 0 || this.#routePolicy !== "all_signed") {
      return;
    }
    for (const payloadB64 of sets) {
      // Checked and stamped inside the critical section: time spent waiting for the lock never
      // counts toward the interval.
      this.#lastRouteSet = await this.#rosterSection(
        async (tx) => {
          const nowMs = performance.now();
          if (
            this.#lastRouteSetMs !== null &&
            nowMs < this.#lastRouteSetMs + CLIENT_ROUTE_SET_INTERVAL_MS
          ) {
            return { outcome: "ignored", reason: "rate_limited" };
          }
          this.#lastRouteSetMs = nowMs;
          let res;
          try {
            res = JSON.parse(
              this.#roster.apply_route_announcement(
                this.#peerId,
                b64urlDecode(payloadB64),
                nowUnixSecs()
              )
            );
          } catch (err) {
            return { outcome: "ignored", reason: errorText(err) };
          }
          if (res.outcome === "applied") {
            try {
              await tx.persist();
            } catch {
              return { outcome: "ignored", reason: "persist_failed" };
            }
          }
          return res;
        },
        { snapshot: true }
      );
    }
  }

  async #applyGroupEvents(events) {
    if (!this.#groupHook || !events.some((ev) => ev.event === "group_rendezvous_unverified")) {
      return;
    }
    let result;
    try {
      result = await this.#groupHook.applyRendezvous(this.#session);
    } catch (err) {
      this.#failPersistAndClose(err);
      throw new Error(`failed to persist group update: ${err.message || err}`, { cause: err });
    }
    for (const ev of events) {
      if (ev.event !== "group_rendezvous_unverified") {
        continue;
      }
      const match = (r) => r.group_id === ev.group_id && r.seq === ev.seq;
      const rejected = result.rejected.find(match);
      ev.applied = !rejected && result.applied.some(match);
      if (rejected) {
        ev.error = rejected.error;
      }
    }
  }

  #elapsedMs() {
    return Math.max(0, Math.floor(performance.now() - this.#startedMs));
  }

  #ensureOpen() {
    if (this.#persistFailedErr) {
      throw new Error(
        `session locked after roster persistence failure: ${this.#persistFailedErr.message || this.#persistFailedErr}`,
        { cause: this.#persistFailedErr }
      );
    }
    if (this.#closing || this.#freed) {
      throw new Error("session has been freed");
    }
  }

  #enqueueSend(fn) {
    const run = this.#sendChain.then(fn, fn);
    this.#sendChain = run.catch(() => {});
    return run;
  }

  #failPersistAndClose(persistErr) {
    this.#persistFailedErr = persistErr;
    this.#closing = true;
    try {
      void this.#stream.close();
    } catch {}
  }

  /** The client locked on a roster persist failure: fail this session and close it. */
  _failFromClientLock(persistErr) {
    if (!this.#persistFailedErr) {
      this.#persistFailedErr = persistErr;
    }
    this.#closing = true;
    void this.close(1011, "roster persistence failure").catch(() => {});
  }

  _abortFromClientFree() {
    this.#closing = true;
    void this.close(1000, "client freed").catch(() => {});
  }

  isEstablished() {
    return !this.#closing && !this.#freed && this.#session.is_established();
  }

  isClosed() {
    return this.#closing || this.#freed || this.#session.is_closed();
  }

  sendData(payload) {
    this.#ensureOpen();
    const bytes = typeof payload === "string" ? encoder.encode(payload) : payload;
    return this.#enqueueSend(async () => {
      this.#ensureOpen();
      const out = this.#session.send_data(bytes, this.#elapsedMs());
      await sendProtocolBytes(this.#stream, out);
    });
  }

  sendDummyCover(bucketSize = 256) {
    this.#ensureOpen();
    if (!this.#isV2) {
      throw new Error("sendDummyCover requires a v2 session");
    }
    return this.#enqueueSend(async () => {
      this.#ensureOpen();
      const out = this.#session.send_dummy_cover(bucketSize, this.#elapsedMs());
      await sendProtocolBytes(this.#stream, out);
    });
  }

  nextPingDelayMs() {
    this.#ensureOpen();
    if (!this.#isV2) {
      throw new Error("nextPingDelayMs requires a v2 session");
    }
    return this.#session.next_ping_delay_ms();
  }

  rekey() {
    this.#ensureOpen();
    return this.#enqueueSend(async () => {
      this.#ensureOpen();
      const out = this.#isV2
        ? this.#session.rekey(this.#elapsedMs())
        : this.#session.send_rekey(this.#elapsedMs());
      await sendProtocolBytes(this.#stream, out);
    });
  }

  ping(cookie = 1) {
    this.#ensureOpen();
    return this.#enqueueSend(async () => {
      this.#ensureOpen();
      const out = this.#session.send_ping(cookie, this.#elapsedMs());
      await sendProtocolBytes(this.#stream, out);
    });
  }

  tick() {
    this.#ensureOpen();
    return this.#enqueueSend(async () => {
      this.#ensureOpen();
      // `tick` reads the roster and never changes it.
      const out = await this.#rosterSection(
        () => this.#session.tick(nowUnixSecs(), this.#elapsedMs(), this.#roster),
        { readOnly: true }
      );
      await sendProtocolBytes(this.#stream, out);
    });
  }

  authorize(requestedCap) {
    this.#ensureOpen();
    return this.#session.authorize(requestedCap, nowUnixSecs(), this.#roster);
  }

  negotiatedUpgradeCaps() {
    if (this.#closing || this.#freed || this.#session.is_closed()) {
      return [];
    }
    try {
      const caps = JSON.parse(this.#session.negotiated_upgrade_caps_json());
      return Array.isArray(caps) ? caps : [];
    } catch {
      return [];
    }
  }

  canSendPathUpgrade() {
    if (this.#closing || this.#freed || this.#session.is_closed()) {
      return false;
    }
    if (typeof this.#session.can_send_path_upgrade === "function") {
      return Boolean(this.#session.can_send_path_upgrade());
    }
    return this.negotiatedUpgradeCaps().length > 0;
  }

  upgradeToWebRtc(options = {}) {
    if (this.#upgradePromise) {
      return this.#upgradePromise;
    }
    const run = this.#upgradeToWebRtcImpl(options).finally(() => {
      if (this.#upgradePromise === run) {
        this.#upgradePromise = null;
      }
    });
    this.#upgradePromise = run;
    return run;
  }

  async #upgradeToWebRtcImpl(options = {}) {
    this.#ensureOpen();
    const {
      timeoutMs = 15000,
      signal = null,
      iceServers = [],
      rtcPeerConnectionImpl = globalThis.RTCPeerConnection,
    } = options ?? {};

    if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new RangeError("upgradeToWebRtc timeoutMs must be a positive finite number");
    }
    if (!Array.isArray(iceServers)) {
      throw new TypeError("iceServers must be an array");
    }
    if (signal?.aborted) {
      throw makeAbortError(signal);
    }

    const currentRoute = this.route ?? null;
    const currentProvider = currentRoute?.provider ?? this.#routeProvider;
    if (currentProvider === "p2p" || currentProvider === "direct") {
      return { upgraded: false, reason: "already_direct", route: currentRoute };
    }
    if (!this.negotiatedUpgradeCaps().includes("webrtc/v1") || !this.canSendPathUpgrade()) {
      return { upgraded: false, reason: "not_negotiated", route: currentRoute };
    }
    if (typeof rtcPeerConnectionImpl !== "function") {
      return { upgraded: false, reason: "webrtc_unsupported", route: currentRoute };
    }
    if (typeof this.#dialUpgradeSession !== "function") {
      return { upgraded: false, reason: "upgrade_unavailable", route: currentRoute };
    }
    if (this.#nextUpgradeId >= 4) {
      return { upgraded: false, reason: "upgrade_limit_reached", route: currentRoute };
    }

    const deadlineMs = performance.now() + timeoutMs;
    const remaining = () => Math.max(0, Math.ceil(deadlineMs - performance.now()));

    let upgradeSettled = false;
    let pumpLoop = null;
    const sendOfferAndWaitAnswer = async (offerSdp, budgetMs, offerSignal = null) => {
      let upgradeId = null;
      let timer = null;
      let onAbort = null;
      let resolveAnswer;
      let rejectAnswer;
      const answerPromise = new Promise((resolve, reject) => {
        resolveAnswer = resolve;
        rejectAnswer = reject;
      });
      answerPromise.catch(() => {});
      const linkSignal = offerSignal ?? signal;
      const settle = (fn, val) => {
        if (timer !== null) {
          clearTimeout(timer);
          timer = null;
        }
        if (linkSignal && onAbort) {
          linkSignal.removeEventListener("abort", onAbort);
          onAbort = null;
        }
        if (upgradeId !== null && this.#pendingUpgrade?.upgradeId === upgradeId) {
          this.#pendingUpgrade = null;
        }
        fn(val);
      };
      if (linkSignal) {
        if (linkSignal.aborted) {
          throw makeAbortError(linkSignal);
        }
        onAbort = () => settle(rejectAnswer, makeAbortError(linkSignal));
        linkSignal.addEventListener("abort", onAbort, { once: true });
      }
      const waitMs = Math.max(1, Math.min(budgetMs, remaining() || 1));
      timer = setTimeout(() => {
        settle(rejectAnswer, new UpgradeDeclinedError("upgrade_timeout"));
      }, waitMs);

      try {
        await this.#enqueueSend(async () => {
          this.#ensureOpen();
          if (!this.canSendPathUpgrade()) {
            throw new UpgradeDeclinedError("not_negotiated");
          }
          if (this.#nextUpgradeId >= 4) {
            throw new UpgradeDeclinedError("upgrade_limit_reached");
          }
          if (linkSignal?.aborted) {
            throw makeAbortError(linkSignal);
          }
          const candidateId = this.#nextUpgradeId + 1;
          const offerMsg = {
            type: "offer",
            upgrade_id: candidateId,
            protocol: "webrtc/v1",
            sdp: offerSdp,
          };
          const out = this.#session.send_path_upgrade(
            JSON.stringify(offerMsg),
            this.#elapsedMs()
          );
          this.#nextUpgradeId = candidateId;
          upgradeId = candidateId;
          this.#pendingUpgrade = {
            upgradeId,
            resolve: (msg) => settle(resolveAnswer, msg),
            reject: (err) => settle(rejectAnswer, err),
          };
          await sendProtocolBytes(this.#stream, out);
        });

        pumpLoop = (async () => {
          while (!upgradeSettled && !this.#closing && !this.#freed && remaining() > 0) {
            const sliceMs = Math.max(1, Math.min(200, remaining()));
            const run = this.#recvChain.then(
              () =>
                this.#pollEventImpl(sliceMs, {
                  upgradePump: true,
                  isSettled: () => upgradeSettled,
                }),
              () =>
                this.#pollEventImpl(sliceMs, {
                  upgradePump: true,
                  isSettled: () => upgradeSettled,
                })
            );
            this.#recvChain = run.catch(() => {});
            const stepRes = await run.catch(() => ({ status: "eof" }));
            if (upgradeSettled || stepRes?.status === "eof") {
              break;
            }
          }
        })().catch(() => {});

        const msg = await answerPromise;
        if (msg?.type === "answer" && typeof msg.sdp === "string" && msg.sdp.length > 0) {
          return msg.sdp;
        }
        if (msg?.type === "reject") {
          throw new UpgradeDeclinedError(msg.reason || "rejected");
        }
        throw new UpgradeDeclinedError("invalid_upgrade_response");
      } finally {
        upgradeSettled = true;
        if (timer !== null) {
          clearTimeout(timer);
        }
        if (linkSignal && onAbort) {
          linkSignal.removeEventListener("abort", onAbort);
        }
        if (upgradeId !== null && this.#pendingUpgrade?.upgradeId === upgradeId) {
          this.#pendingUpgrade = null;
        }
      }
    };

    let newStream = null;
    try {
      const dialTimeoutMs = Math.max(1, remaining());
      newStream = await dialWebRtcUpgrade({
        signal,
        timeoutMs: dialTimeoutMs,
        iceServers,
        rtcPeerConnectionImpl,
        sendOfferAndWaitAnswer,
      });
    } catch (err) {
      if (
        this.#persistFailedErr ||
        this.#closing ||
        this.#freed ||
        signal?.aborted ||
        isFatalUpgradeError(err, this.#persistFailedErr)
      ) {
        throw signal?.aborted ? makeAbortError(signal) : err;
      }
      const reason =
        err instanceof UpgradeDeclinedError
          ? err.reason
          : err?.code || errorText(err) || "webrtc_dial_failed";
      return { upgraded: false, reason, route: this.route ?? null };
    }

    let handoff;
    try {
      const handshakeBudgetMs = Math.max(1, remaining());
      handoff = await this.#dialUpgradeSession(
        newStream,
        performance.now() + handshakeBudgetMs,
        this.#peerDeviceId
      );
    } catch (err) {
      try {
        await newStream.close();
      } catch {}
      if (
        this.#persistFailedErr ||
        this.#closing ||
        this.#freed ||
        signal?.aborted ||
        isFatalUpgradeError(err, this.#persistFailedErr)
      ) {
        throw signal?.aborted ? makeAbortError(signal) : err;
      }
      const reason = err?.code || errorText(err) || "webrtc_handshake_failed";
      return { upgraded: false, reason, route: this.route ?? null };
    }

    let cutoverDone = false;
    let oldStream = null;
    let oldSession = null;
    try {
      await this.#enqueueSend(async () => {
        this.#ensureOpen();
        oldStream = this.#stream;
        oldSession = this.#session;
        const oldElapsedMs = this.#elapsedMs();
        this.#epoch += 1;
        this.#session = handoff.newSession;
        this.#stream = newStream;
        this.#startedMs = handoff.newStartedMs;
        this.#routeProvider = "p2p";
        const filteredEvents = (handoff.newInitialEvents ?? []).filter(
          (ev) => ev?.event !== "established"
        );
        if (filteredEvents.length > 0) {
          this.#queue.push(...filteredEvents);
        }
        this.route = { hint: null, endpoint: "webrtc://tendril/v1", provider: "p2p" };
        cutoverDone = true;
        try {
          const closeOut = this.#isV2
            ? oldSession.close(1000, "path_upgrade", oldElapsedMs)
            : oldSession.send_close(1000, "path_upgrade");
          if (closeOut && closeOut.length > 0) {
            await sendProtocolBytes(oldStream, closeOut);
          }
        } catch {}
      });
      return { upgraded: true, route: this.route };
    } finally {
      if (oldStream) {
        try {
          await oldStream.close();
        } catch {}
      }
      if (oldSession) {
        try {
          oldSession.free();
        } catch {}
      }
      if (!cutoverDone) {
        try {
          handoff.newSession.free();
        } catch {}
        try {
          await newStream.close();
        } catch {}
      }
    }
  }

  poll(timeoutMs = 5000) {
    return this.pollEvent(timeoutMs);
  }

  pollEvent(timeoutMs = 5000) {
    this.#ensureOpen();
    const run = this.#recvChain.then(
      () => this.#pollEventImpl(timeoutMs),
      () => this.#pollEventImpl(timeoutMs)
    );
    this.#recvChain = run.catch(() => {});
    return run;
  }

  async #pollEventImpl(timeoutMs, opts = null) {
    const upgradePump = Boolean(opts?.upgradePump);
    const isSettled = opts?.isSettled ?? null;
    while (true) {
      if (upgradePump && isSettled?.()) {
        return { status: "would_block" };
      }
      if (this.#persistFailedErr) {
        throw new Error(
          `session locked after roster persistence failure: ${this.#persistFailedErr.message || this.#persistFailedErr}`,
          { cause: this.#persistFailedErr }
        );
      }
      if (!upgradePump && this.#queue.length > 0) {
        const ev = this.#queue.shift();
        return { status: "event", ...ev };
      }
      if (this.#closing || this.#freed || this.#session.is_closed()) {
        this.#rejectPendingUpgrade(new Error("session closed before upgrade response"));
        return { status: "eof" };
      }
      const pollEpoch = this.#epoch;
      let frame;
      try {
        frame = await this.#stream.recv(timeoutMs);
      } catch (recvErr) {
        if (!upgradePump && this.#upgradePromise) {
          try {
            await this.#upgradePromise;
          } catch {}
        }
        if (this.#epoch !== pollEpoch) {
          if (upgradePump) {
            return { status: "would_block" };
          }
          continue;
        }
        this.#rejectPendingUpgrade(recvErr);
        throw recvErr;
      }
      if (this.#persistFailedErr) {
        throw new Error(
          `session locked after roster persistence failure: ${this.#persistFailedErr.message || this.#persistFailedErr}`,
          { cause: this.#persistFailedErr }
        );
      }
      if (this.#closing || this.#freed) {
        this.#rejectPendingUpgrade(new Error("session closed before upgrade response"));
        return { status: "eof" };
      }
      if (this.#epoch !== pollEpoch) {
        if (upgradePump) {
          return { status: "would_block" };
        }
        continue;
      }
      if (frame.status === "would_block") {
        return { status: "would_block" };
      }
      if (frame.status === "eof") {
        if (!upgradePump && this.#upgradePromise) {
          try {
            await this.#upgradePromise;
          } catch {}
          if (!this.#closing && !this.#freed && this.#epoch !== pollEpoch) {
            continue;
          }
        }
        this.#rejectPendingUpgrade(new Error("stream reached EOF before upgrade response"));
        return { status: "eof" };
      }
      const outcome = await this.#enqueueSend(async () => {
        if (this.#persistFailedErr) {
          throw new Error(
            `session locked after roster persistence failure: ${this.#persistFailedErr.message || this.#persistFailedErr}`,
            { cause: this.#persistFailedErr }
          );
        }
        if (this.#closing || this.#freed) {
          return { eof: true };
        }
        if (this.#epoch !== pollEpoch) {
          return { epochChanged: true };
        }
        const step = await this.#rosterSection(async (tx) => {
          let res;
          const prev = this.#snapshotRoster();
          try {
            res = JSON.parse(
              this.#session.feed_bytes(frame.bytes, nowUnixSecs(), this.#elapsedMs(), this.#roster)
            );
          } catch (feedErr) {
            const changed = this.#rosterChangedSince(prev);
            prev?.fill(0);
            if (!changed) {
              throw feedErr;
            }
            try {
              await tx.persist({ rollback: false });
            } catch (persistErr) {
              this.#markPersistFailed(persistErr);
              throw new Error(
                `protocol error (${errorText(feedErr)}); failed to persist roster update: ${errorText(persistErr)}`,
                { cause: persistErr }
              );
            }
            throw feedErr;
          }
          prev?.fill(0);
          let out;
          let events;
          if (this.#isV2) {
            out = this.#session.poll_write();
            events = JSON.parse(this.#session.drain_events_json()) || [];
          } else {
            out = res.write_b64 ? b64urlDecode(res.write_b64) : null;
            events = res.events || [];
          }
          const routeSets = this.#drainRouteSets();
          if (events.some((ev) => ev.event === "revocation_updated")) {
            try {
              await tx.persist({ rollback: false });
            } catch (persistErr) {
              this.#markPersistFailed(persistErr);
              throw new Error(`failed to persist revocation update: ${errorText(persistErr)}`, {
                cause: persistErr,
              });
            }
          }
          return { closed: Boolean(res.closed), out, events, routeSets };
        });
        if (step.out && step.out.length > 0) {
          await sendProtocolBytes(this.#stream, step.out);
        }
        const keptEvents = [];
        let matchedUpgradeMsg = null;
        for (const ev of step.events) {
          if (ev.event === "grant_updated" && ev.grant) {
            try {
              this.#grantJson = JSON.stringify(ev.grant);
            } catch {}
          }
          const upgradePayload = ev.upgrade ?? ev.msg;
          if (
            ev.event === "path_upgrade" &&
            this.#pendingUpgrade &&
            upgradePayload &&
            upgradePayload.upgrade_id === this.#pendingUpgrade.upgradeId
          ) {
            matchedUpgradeMsg = upgradePayload;
            continue;
          }
          keptEvents.push(ev);
        }
        if (matchedUpgradeMsg && this.#pendingUpgrade) {
          const pu = this.#pendingUpgrade;
          this.#pendingUpgrade = null;
          pu.resolve(matchedUpgradeMsg);
        }
        if (keptEvents.length > 0) {
          await this.#applyGroupEvents(keptEvents);
          this.#queue.push(...keptEvents);
        }
        await this.#ingestRouteSets(step.routeSets);
        return { eof: Boolean(step.closed && this.#queue.length === 0) };
      });
      if (outcome.epochChanged) {
        if (upgradePump) {
          return { status: "would_block" };
        }
        continue;
      }
      if (outcome.eof) {
        if (!upgradePump && this.#upgradePromise) {
          try {
            await this.#upgradePromise;
          } catch {}
          if (!this.#closing && !this.#freed && this.#epoch !== pollEpoch) {
            continue;
          }
        }
        this.#rejectPendingUpgrade(new Error("session closed before upgrade response"));
        return { status: "eof" };
      }
      if (upgradePump) {
        return { status: "would_block" };
      }
    }
  }

  close(code = 1000, reason = "normal") {
    if (this.#closePromise) {
      return this.#closePromise;
    }
    this.#closing = true;
    this.#rejectPendingUpgrade(new Error("session closed before upgrade response"));
    this.#closePromise = (async () => {
      try {
        await this.#enqueueSend(async () => {
          if (!this.#persistFailedErr && !this.#freed && !this.#session.is_closed()) {
            const out = this.#isV2
              ? this.#session.close(code, reason, this.#elapsedMs())
              : this.#session.send_close(code, reason);
            await sendProtocolBytes(this.#stream, out);
          }
        }).catch(() => {});
      } finally {
        try {
          await this.#stream.close();
        } catch {}
        try {
          await this.#recvChain.catch(() => {});
        } catch {}
        if (!this.#freed) {
          this.#freed = true;
          this.#session.free();
        }
        if (typeof this.#onRelease === "function") {
          const rel = this.#onRelease;
          this.#onRelease = null;
          rel();
        }
      }
    })();
    return this.#closePromise;
  }
}
