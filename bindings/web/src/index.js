import initWasm, {
  WasmIdentity,
  WasmPairInitiator,
  WasmRoster,
  WasmSessionClient,
  WasmV2PakePairInitiator,
  WasmV2SessionInitiator,
  canonical_relay_host,
  compute_code_mac,
  compute_code_mac_bytes,
  compute_relay_auth_hmac_b64,
  derive_v2_relay_dial_json,
  device_id,
  fingerprint_device,
  fingerprint_host,
  pairing_sas,
  parse_pairing_uri_json,
  v2_epoch_within_skew,
  verify_grant_json,
  verify_rotation_chain_json,
} from "../pkg/tendril_wasm.js";
import {
  MAX_QUEUED_BYTES,
  MAX_QUEUED_FRAMES,
  MAX_RELAY_FRAME_LEN,
  RelayStream,
  dialRelayStream,
  dialRelayV2Stream,
  validateRelayWsUrl,
} from "./relay.js";
import { createIndexedDbVault, openTendrilVault } from "./vault.js";

export {
  MAX_QUEUED_BYTES,
  MAX_QUEUED_FRAMES,
  MAX_RELAY_FRAME_LEN,
  RelayStream,
  createIndexedDbVault,
  dialRelayStream,
  dialRelayV2Stream,
  openTendrilVault,
  validateRelayWsUrl,
};

export async function initTendrilP2p(wasmUrl) {
  const { initTendrilP2p: init } = await import("./iroh.js");
  return init(wasmUrl);
}

export async function parseP2pEndpoint(endpoint) {
  const { parseP2pEndpoint: parse } = await import("./iroh.js");
  return parse(endpoint);
}

export async function dialIrohStream(options) {
  const { dialIrohStream: dial } = await import("./iroh.js");
  return dial(options);
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
  timeoutMs,
}) {
  if (p2pApiSecret) {
    throw new Error(
      "p2pApiSecret is not permitted in browser clients; pass a scoped p2pRelayAuthToken"
    );
  }
  const target = endpoint || relayUrl;
  if (target && target.startsWith("iroh://")) {
    return dialIrohStream({
      endpoint: target,
      relayUrlOverride,
      p2pRelayUrls,
      p2pRelayAuthToken,
      p2pApiSecret,
      timeoutMs,
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
      timeoutMs,
    });
  }
  return dialRelayStream({
    relayUrl: target,
    targetPub,
    expectedHost,
    allowInsecureWs,
    relayAuthTicket,
    relayAuthSecret,
    timeoutMs,
  });
}

function remainingBudgetMs(deadlineMs, label) {
  const remaining = Math.ceil(deadlineMs - performance.now());
  if (remaining <= 0) {
    throw new Error(label);
  }
  return remaining;
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
  return JSON.parse(parse_pairing_uri_json(uri));
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
  #onPersistRoster;
  #freed = false;
  #wasmFreed = false;
  #holders = 0;
  #activeSessions = new Set();
  #persistChain = Promise.resolve();

  constructor(token, identity, roster, onPersistRoster) {
    if (token !== CLIENT_TOKEN) {
      throw new Error("Use TendrilWebClient.create()");
    }
    this.#identity = identity;
    this.#roster = roster;
    this.#onPersistRoster = onPersistRoster;
  }

  static async create({
    hostId = null,
    identityJson = null,
    identityBytes = null,
    rosterJson = null,
    rosterBytes = null,
    onPersistRoster = null,
  } = {}) {
    await initTendril();
    let identity;
    if (identityBytes !== null && identityBytes !== undefined) {
      if (!(identityBytes instanceof Uint8Array)) {
        throw new TypeError("identityBytes must be a Uint8Array");
      }
      try {
        identity = WasmIdentity.from_json_bytes(identityBytes);
      } finally {
        identityBytes.fill(0);
      }
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
        try {
          roster = WasmRoster.from_json_bytes(rosterBytes);
        } finally {
          rosterBytes.fill(0);
        }
      } else if (rosterJson) {
        roster = WasmRoster.from_json(rosterJson);
      } else {
        roster = new WasmRoster();
      }
    } catch (err) {
      identity.free();
      throw err;
    }
    return new TendrilWebClient(CLIENT_TOKEN, identity, roster, onPersistRoster);
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

  #snapshotRosterBytes() {
    return typeof this.#onPersistRoster === "function" ? this.#roster.to_json_bytes() : null;
  }

  #restoreRosterBytes(prevBytes) {
    if (prevBytes && !this.#wasmFreed) {
      try {
        this.#roster.replace_from_json_bytes(prevBytes);
      } catch {}
    }
  }

  getPeer(peerId) {
    this.#ensureOpen();
    const raw = this.#roster.get_peer_json(peerId);
    return raw ? JSON.parse(raw) : null;
  }

  async confirmPeer(peerId, sas = null) {
    return this.#withHold(async () => {
      const prevRoster = this.#snapshotRosterBytes();
      try {
        this.#roster.confirm_peer(peerId, sas);
        try {
          await this.#persistRoster();
        } catch (err) {
          this.#restoreRosterBytes(prevRoster);
          throw err;
        }
      } finally {
        if (prevRoster) {
          prevRoster.fill(0);
        }
      }
    });
  }

  async removePendingPeer(peerId) {
    return this.#withHold(async () => {
      const prevRoster = this.#snapshotRosterBytes();
      try {
        this.#roster.remove_pending_peer(peerId);
        try {
          await this.#persistRoster();
        } catch (err) {
          this.#restoreRosterBytes(prevRoster);
          throw err;
        }
      } finally {
        if (prevRoster) {
          prevRoster.fill(0);
        }
      }
    });
  }

  async addTrustAnchor(anchorId, signingPubB64) {
    return this.#withHold(async () => {
      const prevRoster = this.#snapshotRosterBytes();
      try {
        this.#roster.add_trust_anchor(anchorId, signingPubB64);
        try {
          await this.#persistRoster();
        } catch (err) {
          this.#restoreRosterBytes(prevRoster);
          throw err;
        }
      } finally {
        if (prevRoster) {
          prevRoster.fill(0);
        }
      }
    });
  }

  async revokeTrustAnchor(anchorId) {
    return this.#withHold(async () => {
      const prevRoster = this.#snapshotRosterBytes();
      try {
        this.#roster.revoke_trust_anchor(anchorId);
        try {
          await this.#persistRoster();
        } catch (err) {
          this.#restoreRosterBytes(prevRoster);
          throw err;
        }
      } finally {
        if (prevRoster) {
          prevRoster.fill(0);
        }
      }
    });
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
      const initiator = WasmPairInitiator.new_m2m_with_roster(
        this.#identity,
        deviceName,
        deviceKind,
        hostId,
        hostStaticPubB64,
        hostSigningPubB64,
        hostRotationSeq,
        tokenJson,
        this.#roster
      );
      let stream = null;
      try {
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
          timeoutMs: remainingBudgetMs(
            deadlineMs,
            "m2m enrollment timed out connecting to transport"
          ),
        });
        this.#ensureOpen();
        const startBytes = initiator.start();
        await sendProtocolBytes(stream, startBytes);
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
          const prevRoster = this.#snapshotRosterBytes();
          let res;
          try {
            res = JSON.parse(initiator.feed_bytes(frame.bytes, this.#roster));
            if (res.write_b64) {
              await sendProtocolBytes(stream, b64urlDecode(res.write_b64));
            }
            if (res.outcome) {
              if (res.outcome.status === "active") {
                try {
                  await this.#persistRoster();
                } catch (err) {
                  this.#restoreRosterBytes(prevRoster);
                  throw err;
                }
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
          } finally {
            if (prevRoster) {
              prevRoster.fill(0);
            }
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
    const fn = this.#onPersistRoster;
    if (typeof fn !== "function") {
      return Promise.resolve();
    }
    const run = this.#persistChain.then(async () => {
      if (this.#wasmFreed) {
        throw new Error("TendrilWebClient has been freed");
      }
      await fn(this.#roster.to_json());
    });
    this.#persistChain = run.catch(() => {});
    return run;
  }

  async pair({
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
    code = "",
    pairingUri = null,
    deviceName = "web-device",
    deviceKind = "web",
    timeoutMs = 15000,
  }) {
    if (p2pApiSecret) {
      throw new Error(
        "p2pApiSecret is not permitted in browser clients; pass a scoped p2pRelayAuthToken"
      );
    }
    return this.#withHold(async () => {
      let pairCode = code;
      let hostStaticPin = null;
      let hostSigningPin = null;
      let hostIdPin = null;
      let hostRotationSeqPin = null;
      if (pairingUri) {
        const parsed = parsePairingUri(pairingUri);
        pairCode = parsed.code;
        hostStaticPin = parsed.host_static_pub_b64;
        hostSigningPin = parsed.host_signing_pub_hash_b64;
        hostIdPin = parsed.host_id ?? null;
        hostRotationSeqPin = parsed.rotation_seq ?? null;
      }
      if (!pairCode) {
        throw new Error("pairing code or pairingUri is required");
      }

      await warmTargetTransport(endpoint, relayUrl);
      this.#ensureOpen();
      const deadlineMs = performance.now() + timeoutMs;
      const initiator = WasmPairInitiator.new_with_roster(
        this.#identity,
        deviceName,
        deviceKind,
        pairCode,
        hostStaticPin,
        hostSigningPin,
        hostIdPin,
        hostRotationSeqPin,
        this.#roster
      );
      let stream = null;
      try {
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
          timeoutMs: remainingBudgetMs(deadlineMs, "pairing timed out connecting to transport"),
        });
        this.#ensureOpen();
        const startBytes = initiator.start();
        await sendProtocolBytes(stream, startBytes);
        while (true) {
          const waitMs = remainingBudgetMs(
            deadlineMs,
            "pairing timed out waiting for host response"
          );
          const frame = await stream.recv(waitMs);
          this.#ensureOpen();
          if (frame.status === "would_block") {
            throw new Error("pairing timed out waiting for host response");
          }
          if (frame.status === "eof") {
            throw new Error("pairing stream closed before completion");
          }
          const prevRoster = this.#snapshotRosterBytes();
          try {
            const res = JSON.parse(initiator.feed_bytes(frame.bytes, this.#roster));
            if (res.write_b64) {
              await sendProtocolBytes(stream, b64urlDecode(res.write_b64));
            }
            if (res.outcome) {
              if (res.outcome.status === "pending") {
                try {
                  await this.#persistRoster();
                } catch (err) {
                  this.#restoreRosterBytes(prevRoster);
                  throw err;
                }
                return {
                  device_id: res.outcome.device_id,
                  host_id: res.outcome.host_id,
                  sas: res.outcome.sas,
                  host_confirmed: Boolean(res.outcome.host_confirmed),
                };
              }
              if (res.outcome.status === "rejected") {
                throw new Error(`pairing rejected: ${res.outcome.error}`);
              }
              throw new Error(`unexpected pairing outcome: ${JSON.stringify(res.outcome)}`);
            }
          } finally {
            if (prevRoster) {
              prevRoster.fill(0);
            }
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

  async pairV2({
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
    code = "",
    pairingUri = null,
    pinnedHost = null,
    deviceName = "web-device",
    deviceKind = "web",
    timeoutMs = 15000,
  }) {
    if (p2pApiSecret) {
      throw new Error(
        "p2pApiSecret is not permitted in browser clients; pass a scoped p2pRelayAuthToken"
      );
    }
    return this.#withHold(async () => {
      let pairCode = code;
      let pinnedJson = null;
      if (pairingUri) {
        const parsed = parsePairingUri(pairingUri);
        pairCode = parsed.code;
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
      if (!pairCode || (pairCode instanceof Uint8Array && pairCode.length === 0)) {
        throw new Error("pairing code or pairingUri is required");
      }

      await warmTargetTransport(endpoint, relayUrl);
      this.#ensureOpen();
      const deadlineMs = performance.now() + timeoutMs;
      const codeBytes =
        pairCode instanceof Uint8Array ? pairCode : encoder.encode(String(pairCode));
      let initiator;
      try {
        initiator = WasmV2PakePairInitiator.new_bytes(
          this.#identity,
          deviceName,
          deviceKind,
          codeBytes,
          pinnedJson
        );
      } finally {
        codeBytes.fill(0);
      }
      let stream = null;
      try {
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
          timeoutMs: remainingBudgetMs(deadlineMs, "v2 pairing timed out connecting to transport"),
        });
        this.#ensureOpen();
        const startBytes = initiator.start();
        await sendProtocolBytes(stream, startBytes);
        while (true) {
          const waitMs = remainingBudgetMs(
            deadlineMs,
            "v2 pairing timed out waiting for host response"
          );
          const frame = await stream.recv(waitMs);
          this.#ensureOpen();
          if (frame.status === "would_block") {
            throw new Error("v2 pairing timed out waiting for host response");
          }
          if (frame.status === "eof") {
            throw new Error("v2 pairing stream closed before completion");
          }
          const prevRoster = this.#snapshotRosterBytes();
          try {
            const res = JSON.parse(initiator.feed_bytes(frame.bytes, this.#roster));
            if (res.write_b64) {
              await sendProtocolBytes(stream, b64urlDecode(res.write_b64));
            }
            if (res.outcome) {
              if (res.outcome.status === "pending") {
                try {
                  await this.#persistRoster();
                } catch (err) {
                  this.#restoreRosterBytes(prevRoster);
                  throw err;
                }
                return {
                  device_id: res.outcome.device_id,
                  host_id: res.outcome.host_id,
                  sas: res.outcome.sas,
                  host_confirmed: Boolean(res.outcome.host_confirmed),
                };
              }
              if (res.outcome.status === "rejected") {
                throw new Error(`v2 pairing rejected: ${res.outcome.error}`);
              }
              throw new Error(`unexpected v2 pairing outcome: ${JSON.stringify(res.outcome)}`);
            }
          } finally {
            if (prevRoster) {
              prevRoster.fill(0);
            }
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

  async connect({
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
    targetHostId,
    grantJson = null,
    crlSeq = null,
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
      const seq = crlSeq ?? this.#roster.crl_seq(targetHostId);
      const session = WasmSessionClient.new_with_roster(
        this.#identity,
        targetHostId,
        this.#roster,
        grantJson,
        seq ?? null
      );
      let stream = null;
      let handedOff = false;
      try {
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
          timeoutMs: remainingBudgetMs(
            deadlineMs,
            "session handshake timed out connecting to transport"
          ),
        });
        this.#ensureOpen();
        const startedMs = performance.now();
        const m1 = session.start();
        await sendProtocolBytes(stream, m1);
        let initialEvents = [];
        while (!session.is_established()) {
          const waitMs = remainingBudgetMs(deadlineMs, "session handshake timed out");
          const frame = await stream.recv(waitMs);
          this.#ensureOpen();
          if (frame.status === "would_block") {
            throw new Error("session handshake timed out");
          }
          if (frame.status === "eof") {
            throw new Error("session stream closed during handshake");
          }
          const elapsedMs = Math.max(0, Math.floor(performance.now() - startedMs));
          let step;
          try {
            step = JSON.parse(
              session.feed_bytes(frame.bytes, nowUnixSecs(), elapsedMs, this.#roster)
            );
          } catch (err) {
            try {
              await this.#persistRoster();
            } catch (persistErr) {
              throw new Error(
                `session handshake failed (${err.message || err}); failed to persist roster update: ${persistErr.message || persistErr}`,
                { cause: persistErr }
              );
            }
            throw err;
          }
          if (step.write_b64) {
            await sendProtocolBytes(stream, b64urlDecode(step.write_b64));
          }
          if (step.established) {
            initialEvents = step.events || [];
            break;
          }
        }
        await this.#persistRoster();
        this.#ensureOpen();
        let releaseSession = null;
        const webSession = new TendrilWebSession(
          SESSION_TOKEN,
          session,
          stream,
          this.#roster,
          startedMs,
          () => this.#persistRoster(),
          initialEvents,
          () => {
            if (releaseSession) {
              releaseSession();
              releaseSession = null;
            }
          }
        );
        releaseSession = this.#attachSession(webSession);
        handedOff = true;
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
    });
  }

  async connectV2({
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
    allowInsecureWs = false,
    targetHostId,
    grantJson = null,
    crlSeq = null,
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
      const seq = crlSeq ?? this.#roster.crl_seq(targetHostId);
      const session = new WasmV2SessionInitiator(
        this.#identity,
        targetHostId,
        this.#roster,
        grantJson,
        seq ?? null
      );
      let stream = null;
      let handedOff = false;
      try {
        const deriveV2Dial = useRelayV2
          ? ({ relayHost, nonceBytes, connIdBytes }) =>
              JSON.parse(
                this.#roster.derive_v2_relay_dial_for_peer_json(
                  targetHostId,
                  relayHost,
                  nowUnixSecs(),
                  nonceBytes,
                  connIdBytes
                )
              )
          : null;
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
          useRelayV2,
          deriveV2Dial,
          allowInsecureWs,
          timeoutMs: remainingBudgetMs(
            deadlineMs,
            "v2 session handshake timed out connecting to transport"
          ),
        });
        this.#ensureOpen();
        const startedMs = performance.now();
        const m1 = session.start(nowUnixSecs());
        await sendProtocolBytes(stream, m1);
        let initialEvents = [];
        while (!session.is_established()) {
          const waitMs = remainingBudgetMs(deadlineMs, "v2 session handshake timed out");
          const frame = await stream.recv(waitMs);
          this.#ensureOpen();
          if (frame.status === "would_block") {
            throw new Error("v2 session handshake timed out");
          }
          if (frame.status === "eof") {
            throw new Error("v2 session stream closed during handshake");
          }
          const elapsedMs = Math.max(0, Math.floor(performance.now() - startedMs));
          let step;
          try {
            step = JSON.parse(
              session.feed_bytes(frame.bytes, nowUnixSecs(), elapsedMs, this.#roster)
            );
          } catch (err) {
            try {
              await this.#persistRoster();
            } catch (persistErr) {
              throw new Error(
                `v2 session handshake failed (${err.message || err}); failed to persist roster update: ${persistErr.message || persistErr}`,
                { cause: persistErr }
              );
            }
            throw err;
          }
          const outBytes = session.poll_write();
          if (outBytes && outBytes.length > 0) {
            await sendProtocolBytes(stream, outBytes);
          }
          const events = JSON.parse(session.drain_events_json());
          if (step.established) {
            initialEvents = events;
            break;
          }
        }
        await this.#persistRoster();
        this.#ensureOpen();
        let releaseSession = null;
        const webSession = new TendrilWebSession(
          SESSION_TOKEN,
          session,
          stream,
          this.#roster,
          startedMs,
          () => this.#persistRoster(),
          initialEvents,
          () => {
            if (releaseSession) {
              releaseSession();
              releaseSession = null;
            }
          },
          true
        );
        releaseSession = this.#attachSession(webSession);
        handedOff = true;
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
    });
  }

  free() {
    if (this.#freed) {
      return;
    }
    this.#freed = true;
    for (const sess of [...this.#activeSessions]) {
      sess._abortFromClientFree();
    }
    this.#maybeFreeWasm();
  }
}

export class TendrilWebSession {
  #session;
  #stream;
  #roster;
  #startedMs;
  #persist;
  #onRelease;
  #queue;
  #isV2;
  #sendChain = Promise.resolve();
  #recvChain = Promise.resolve();
  #closing = false;
  #freed = false;
  #closePromise = null;
  #persistFailedErr = null;

  constructor(
    token,
    session,
    stream,
    roster,
    startedMs,
    persistFn,
    initialEvents = [],
    onRelease = null,
    isV2 = false
  ) {
    if (token !== SESSION_TOKEN) {
      throw new Error("Use TendrilWebClient.connect()");
    }
    this.#session = session;
    this.#stream = stream;
    this.#roster = roster;
    this.#startedMs = startedMs;
    this.#persist = persistFn;
    this.#onRelease = onRelease;
    this.#queue = [...initialEvents];
    this.#isV2 = Boolean(isV2);
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
      let out;
      let tickErr = null;
      try {
        out = this.#session.tick(nowUnixSecs(), this.#elapsedMs(), this.#roster);
      } catch (err) {
        tickErr = err;
      }
      if (tickErr) {
        try {
          await this.#persist();
        } catch (persistErr) {
          this.#failPersistAndClose(persistErr);
          throw new Error(
            `session tick failed (${tickErr.message || tickErr}); failed to persist roster update: ${persistErr.message || persistErr}`,
            { cause: persistErr }
          );
        }
        throw tickErr;
      }
      await sendProtocolBytes(this.#stream, out);
    });
  }

  authorize(requestedCap) {
    this.#ensureOpen();
    return this.#session.authorize(requestedCap, nowUnixSecs(), this.#roster);
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

  async #pollEventImpl(timeoutMs) {
    while (true) {
      if (this.#persistFailedErr) {
        throw new Error(
          `session locked after roster persistence failure: ${this.#persistFailedErr.message || this.#persistFailedErr}`,
          { cause: this.#persistFailedErr }
        );
      }
      if (this.#queue.length > 0) {
        const ev = this.#queue.shift();
        return { status: "event", ...ev };
      }
      if (this.#closing || this.#freed || this.#session.is_closed()) {
        return { status: "eof" };
      }
      const frame = await this.#stream.recv(timeoutMs);
      if (this.#persistFailedErr) {
        throw new Error(
          `session locked after roster persistence failure: ${this.#persistFailedErr.message || this.#persistFailedErr}`,
          { cause: this.#persistFailedErr }
        );
      }
      if (this.#closing || this.#freed) {
        return { status: "eof" };
      }
      if (frame.status === "would_block") {
        return { status: "would_block" };
      }
      if (frame.status === "eof") {
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
        let step;
        let feedErr = null;
        try {
          step = JSON.parse(
            this.#session.feed_bytes(frame.bytes, nowUnixSecs(), this.#elapsedMs(), this.#roster)
          );
        } catch (err) {
          feedErr = err;
        }
        if (feedErr) {
          try {
            await this.#persist();
          } catch (persistErr) {
            this.#failPersistAndClose(persistErr);
            throw new Error(
              `protocol error (${feedErr.message || feedErr}); failed to persist roster update: ${persistErr.message || persistErr}`,
              { cause: persistErr }
            );
          }
          throw feedErr;
        }
        if (this.#isV2) {
          const outBytes = this.#session.poll_write();
          if (outBytes && outBytes.length > 0) {
            await sendProtocolBytes(this.#stream, outBytes);
          }
          const events = JSON.parse(this.#session.drain_events_json());
          if (events && events.length > 0) {
            if (events.some((ev) => ev.event === "revocation_updated")) {
              try {
                await this.#persist();
              } catch (persistErr) {
                this.#failPersistAndClose(persistErr);
                throw new Error(
                  `failed to persist revocation update: ${persistErr.message || persistErr}`,
                  { cause: persistErr }
                );
              }
            }
            this.#queue.push(...events);
          }
          return { eof: Boolean(step.closed && this.#queue.length === 0) };
        }
        if (step.write_b64) {
          await sendProtocolBytes(this.#stream, b64urlDecode(step.write_b64));
        }
        if (step.events && step.events.length > 0) {
          if (step.events.some((ev) => ev.event === "revocation_updated")) {
            try {
              await this.#persist();
            } catch (persistErr) {
              this.#failPersistAndClose(persistErr);
              throw new Error(
                `failed to persist revocation update: ${persistErr.message || persistErr}`,
                { cause: persistErr }
              );
            }
          }
          this.#queue.push(...step.events);
        }
        return { eof: Boolean(step.closed && this.#queue.length === 0) };
      });
      if (outcome.eof) {
        return { status: "eof" };
      }
    }
  }

  close(code = 1000, reason = "normal") {
    if (this.#closePromise) {
      return this.#closePromise;
    }
    this.#closing = true;
    this.#closePromise = (async () => {
      try {
        await this.#enqueueSend(async () => {
          if (!this.#freed && !this.#session.is_closed()) {
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
