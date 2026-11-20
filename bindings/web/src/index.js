import initWasm, {
  WasmIdentity,
  WasmPairInitiator,
  WasmRoster,
  WasmSessionClient,
  compute_code_mac,
  device_id,
  fingerprint_device,
  fingerprint_host,
  pairing_sas,
  parse_pairing_uri_json,
  verify_grant_json,
  verify_rotation_chain_json,
} from "../pkg/tendril_wasm.js";
import { dialRelayStream } from "./relay.js";

export { dialRelayStream };

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
  timeoutMs,
}) {
  const target = endpoint || relayUrl;
  if (target && target.startsWith("iroh://")) {
    return dialIrohStream({ endpoint: target, relayUrlOverride, timeoutMs });
  }
  return dialRelayStream({ relayUrl: target, targetPub, expectedHost, timeoutMs });
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

export async function computeCodeMacWorker(code, handshakeHash) {
  await initTendril();
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
    const id = 1;
    worker.addEventListener("message", (ev) => {
      worker.terminate();
      if (ev.data && ev.data.ok) {
        resolve(new Uint8Array(ev.data.mac));
      } else {
        reject(new Error(ev.data ? ev.data.error : "worker failed"));
      }
    });
    worker.addEventListener("error", (ev) => {
      worker.terminate();
      reject(new Error(ev.message || "worker error"));
    });
    worker.postMessage({ id, op: "compute_code_mac", code, handshakeHash });
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

export class TendrilWebClient {
  #identity;
  #roster;
  #onPersistRoster;

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
    rosterJson = null,
    onPersistRoster = null,
  } = {}) {
    await initTendril();
    const identity = identityJson
      ? WasmIdentity.from_json(identityJson)
      : WasmIdentity.generate(hostId);
    const roster = rosterJson ? WasmRoster.from_json(rosterJson) : new WasmRoster();
    return new TendrilWebClient(CLIENT_TOKEN, identity, roster, onPersistRoster);
  }

  info() {
    return JSON.parse(this.#identity.info_json());
  }

  exportIdentityJson() {
    return this.#identity.to_json();
  }

  exportRosterJson() {
    return this.#roster.to_json();
  }

  getPeer(peerId) {
    const raw = this.#roster.get_peer_json(peerId);
    return raw ? JSON.parse(raw) : null;
  }

  async #persistRoster() {
    if (typeof this.#onPersistRoster === "function") {
      await this.#onPersistRoster(this.#roster.to_json());
    }
  }

  async pair({
    endpoint = null,
    relayUrl = null,
    targetPub = null,
    expectedHost = null,
    relayUrlOverride = null,
    code = "",
    pairingUri = null,
    deviceName = "web-device",
    deviceKind = "web",
    timeoutMs = 15000,
  }) {
    let pairCode = code;
    let hostStaticPin = null;
    let hostSigningPin = null;
    let hostIdPin = null;
    let hostRotationSeqPin = null;
    if (pairingUri) {
      const parsed = parsePairingUri(pairingUri);
      pairCode = parsed.code;
      hostStaticPin = parsed.host_static_pub_b64;
      hostSigningPin = parsed.host_signing_pub_b64;
      hostIdPin = parsed.host_id ?? null;
      hostRotationSeqPin = parsed.rotation_seq ?? null;
    }
    if (!pairCode) {
      throw new Error("pairing code or pairingUri is required");
    }

    await warmTargetTransport(endpoint, relayUrl);
    const deadlineMs = performance.now() + timeoutMs;
    const initiator = new WasmPairInitiator(
      this.#identity,
      deviceName,
      deviceKind,
      pairCode,
      hostStaticPin,
      hostSigningPin,
      hostIdPin,
      hostRotationSeqPin
    );
    let stream = null;
    try {
      stream = await dialWebStream({
        endpoint,
        relayUrl,
        targetPub,
        expectedHost,
        relayUrlOverride,
        timeoutMs: remainingBudgetMs(deadlineMs, "pairing timed out connecting to transport"),
      });
      const startBytes = initiator.start();
      await sendProtocolBytes(stream, startBytes);
      while (true) {
        const waitMs = remainingBudgetMs(deadlineMs, "pairing timed out waiting for host response");
        const frame = await stream.recv(waitMs);
        if (frame.status === "would_block") {
          throw new Error("pairing timed out waiting for host response");
        }
        if (frame.status === "eof") {
          throw new Error("pairing stream closed before completion");
        }
        const res = JSON.parse(initiator.feed_bytes(frame.bytes, this.#roster));
        if (res.write_b64) {
          await sendProtocolBytes(stream, b64urlDecode(res.write_b64));
        }
        if (res.outcome) {
          if (res.outcome.status === "pending") {
            await this.#persistRoster();
            return {
              device_id: res.outcome.device_id,
              host_id: res.outcome.host_id,
              sas: res.outcome.sas,
            };
          }
          if (res.outcome.status === "rejected") {
            throw new Error(`pairing rejected: ${res.outcome.error}`);
          }
          throw new Error(`unexpected pairing outcome: ${JSON.stringify(res.outcome)}`);
        }
      }
    } finally {
      initiator.free();
      if (stream) {
        await stream.close();
      }
    }
  }

  async connect({
    endpoint = null,
    relayUrl = null,
    targetPub = null,
    expectedHost = null,
    relayUrlOverride = null,
    targetHostId,
    grantJson = null,
    crlSeq = null,
    timeoutMs = 15000,
  }) {
    await warmTargetTransport(endpoint, relayUrl);
    const deadlineMs = performance.now() + timeoutMs;
    const seq = crlSeq ?? this.#roster.crl_seq(targetHostId);
    const session = new WasmSessionClient(
      this.#identity,
      targetHostId,
      grantJson,
      seq ?? null
    );
    let stream = null;
    try {
      stream = await dialWebStream({
        endpoint,
        relayUrl,
        targetPub,
        expectedHost,
        relayUrlOverride,
        timeoutMs: remainingBudgetMs(deadlineMs, "session handshake timed out connecting to transport"),
      });
      const startedMs = performance.now();
      const m1 = session.start();
      await sendProtocolBytes(stream, m1);
      while (!session.is_established()) {
        const waitMs = remainingBudgetMs(deadlineMs, "session handshake timed out");
        const frame = await stream.recv(waitMs);
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
          } catch {}
          throw err;
        }
        if (step.write_b64) {
          await sendProtocolBytes(stream, b64urlDecode(step.write_b64));
        }
        if (step.established) {
          await this.#persistRoster();
          return new TendrilWebSession(
            SESSION_TOKEN,
            session,
            stream,
            this.#roster,
            startedMs,
            () => this.#persistRoster(),
            step.events || []
          );
        }
      }
      await this.#persistRoster();
      return new TendrilWebSession(
        SESSION_TOKEN,
        session,
        stream,
        this.#roster,
        startedMs,
        () => this.#persistRoster(),
        []
      );
    } catch (err) {
      session.free();
      if (stream) {
        await stream.close();
      }
      throw err;
    }
  }

  free() {
    this.#identity.free();
    this.#roster.free();
  }
}

export class TendrilWebSession {
  #session;
  #stream;
  #roster;
  #startedMs;
  #persist;
  #queue;
  #freed = false;

  constructor(token, session, stream, roster, startedMs, persistFn, initialEvents = []) {
    if (token !== SESSION_TOKEN) {
      throw new Error("Use TendrilWebClient.connect()");
    }
    this.#session = session;
    this.#stream = stream;
    this.#roster = roster;
    this.#startedMs = startedMs;
    this.#persist = persistFn;
    this.#queue = [...initialEvents];
  }

  #elapsedMs() {
    return Math.max(0, Math.floor(performance.now() - this.#startedMs));
  }

  #ensureOpen() {
    if (this.#freed) {
      throw new Error("session has been freed");
    }
  }

  isEstablished() {
    return !this.#freed && this.#session.is_established();
  }

  isClosed() {
    return this.#freed || this.#session.is_closed();
  }

  async sendData(payload) {
    this.#ensureOpen();
    const bytes = typeof payload === "string" ? encoder.encode(payload) : payload;
    const out = this.#session.send_data(bytes, this.#elapsedMs());
    await sendProtocolBytes(this.#stream, out);
  }

  async rekey() {
    this.#ensureOpen();
    const out = this.#session.send_rekey(this.#elapsedMs());
    await sendProtocolBytes(this.#stream, out);
  }

  async ping(cookie = 1) {
    this.#ensureOpen();
    const out = this.#session.send_ping(cookie, this.#elapsedMs());
    await sendProtocolBytes(this.#stream, out);
  }

  async tick() {
    this.#ensureOpen();
    let out;
    try {
      out = this.#session.tick(nowUnixSecs(), this.#elapsedMs(), this.#roster);
    } catch (err) {
      try {
        await this.#persist();
      } catch {}
      throw err;
    }
    await sendProtocolBytes(this.#stream, out);
  }

  authorize(requestedCap) {
    this.#ensureOpen();
    return this.#session.authorize(requestedCap, nowUnixSecs(), this.#roster);
  }

  async pollEvent(timeoutMs = 5000) {
    this.#ensureOpen();
    while (true) {
      if (this.#queue.length > 0) {
        const ev = this.#queue.shift();
        return { status: "event", ...ev };
      }
      if (this.#freed || this.#session.is_closed()) {
        return { status: "eof" };
      }
      const frame = await this.#stream.recv(timeoutMs);
      if (this.#freed) {
        return { status: "eof" };
      }
      if (frame.status === "would_block") {
        return { status: "would_block" };
      }
      if (frame.status === "eof") {
        return { status: "eof" };
      }
      let step;
      try {
        step = JSON.parse(
          this.#session.feed_bytes(frame.bytes, nowUnixSecs(), this.#elapsedMs(), this.#roster)
        );
      } catch (err) {
        try {
          await this.#persist();
        } catch {}
        throw err;
      }
      if (step.write_b64) {
        await sendProtocolBytes(this.#stream, b64urlDecode(step.write_b64));
      }
      if (step.events && step.events.length > 0) {
        if (step.events.some((ev) => ev.event === "revocation_updated")) {
          await this.#persist();
        }
        this.#queue.push(...step.events);
      }
      if (step.closed && this.#queue.length === 0) {
        return { status: "eof" };
      }
    }
  }

  async close(code = 1000, reason = "normal") {
    if (this.#freed) {
      return;
    }
    this.#freed = true;
    try {
      if (!this.#session.is_closed()) {
        const out = this.#session.send_close(code, reason);
        await sendProtocolBytes(this.#stream, out);
      }
    } catch {}
    await this.#stream.close();
    this.#session.free();
  }
}
