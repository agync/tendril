export interface BenchmarkResult {
  runs: number;
  durationsMs: number[];
  minMs: number;
  medianMs: number;
  maxMs: number;
}

export interface ParsedPairingUri {
  host_name: string;
  code: string;
  host_static_pub_b64: string;
  host_signing_pub_b64: string;
  endpoints: string[];
  host_id?: string | null;
  rotation_seq?: number | null;
}

export interface ParsedP2pEndpoint {
  endpoint_id: string;
  addrs: string[];
  relays: string[];
}

export type WebStreamRecvResult =
  | { status: "data"; bytes: Uint8Array }
  | { status: "would_block" }
  | { status: "eof" };

export interface TendrilStream {
  maxFrame(): number;
  send(bytes: Uint8Array): Promise<void> | void;
  recv(timeoutMs?: number): Promise<WebStreamRecvResult>;
  close(): Promise<void> | void;
}

export interface EndpointInfo {
  host_id: string;
  device_id: string;
  static_pub: string;
  signing_pub: string;
}

export interface PairResult {
  device_id: string;
  host_id: string;
  sas: string;
  host_confirmed: boolean;
}

export interface EnrollResult {
  device_id: string;
  host_id: string;
  status: "active";
  host_rotation_seq: number;
  token_nonce: string;
}

export interface PollEvent {
  status: "event" | "would_block" | "eof";
  event?: string;
  data_b64?: string;
  direction?: string;
  grant?: unknown;
  issuer?: string;
  seq?: number;
  cookie?: number;
  audit?: unknown;
  code?: number;
  reason?: string;
}

export function initTendril(wasmUrl?: string | URL | RequestInfo | BufferSource): Promise<void>;
export function initTendrilP2p(
  wasmUrl?: string | URL | RequestInfo | BufferSource
): Promise<void>;
export function parseP2pEndpoint(endpoint: string): Promise<ParsedP2pEndpoint>;
export const MAX_RELAY_FRAME_LEN: number;
export const MAX_QUEUED_BYTES: number;
export const MAX_QUEUED_FRAMES: number;

export class RelayStream implements TendrilStream {
  constructor(ws: WebSocket, maxQueuedBytes?: number, maxQueuedFrames?: number);
  maxFrame(): number;
  send(bytes: Uint8Array): void;
  recv(timeoutMs?: number): Promise<WebStreamRecvResult>;
  close(): void;
}

export function validateRelayWsUrl(
  relayUrl: string,
  allowInsecureWs?: boolean
): { url: string; bareHost: string };

export function dialRelayStream(options: {
  relayUrl: string;
  targetPub: string;
  expectedHost?: string | null;
  allowInsecureWs?: boolean;
  timeoutMs?: number;
}): Promise<TendrilStream>;
export function dialIrohStream(options: {
  endpoint: string;
  relayUrlOverride?: string | null;
  timeoutMs?: number;
}): Promise<TendrilStream>;
export function b64urlEncode(bytes: Uint8Array): string;
export function b64urlDecode(str: string): Uint8Array;
export function deviceId(staticPub: Uint8Array): string;
export function fingerprintHost(staticPub: Uint8Array): string;
export function fingerprintDevice(staticPub: Uint8Array): string;
export function pairingSas(handshakeHash: Uint8Array): string;
export function computeCodeMac(code: string, handshakeHash: Uint8Array): Uint8Array;
export function computeCodeMacBytes(codeBytes: Uint8Array, handshakeHash: Uint8Array): Uint8Array;
export function computeCodeMacWorker(
  code: string | Uint8Array,
  handshakeHash: Uint8Array,
  options?: { timeoutMs?: number }
): Promise<Uint8Array>;
export function benchmarkArgon2(
  runs?: number,
  options?: { useWorker?: boolean }
): Promise<BenchmarkResult>;
export function verifyRotationChainJson(
  pinnedSigningB64: string,
  pinnedStaticB64: string,
  pinnedSeq: number,
  chainJson: string,
  curStaticB64: string,
  curSigningB64: string
): number;
export function verifyGrantJson(
  grantJson: string,
  issuerKeysJson: string,
  expectedSubject: string,
  expectedRootIssuer: string,
  requestedCap: string,
  nowUnix: number,
  crlJson?: string | null
): boolean;
export function parsePairingUri(uri: string): ParsedPairingUri;

export interface TendrilWebClientOptions {
  hostId?: string | null;
  identityJson?: string | null;
  rosterJson?: string | null;
  onPersistRoster?: ((rosterJson: string) => void | Promise<void>) | null;
}

export class TendrilWebClient {
  private constructor();
  static create(options?: TendrilWebClientOptions): Promise<TendrilWebClient>;
  info(): EndpointInfo;
  exportIdentityJson(): string;
  exportRosterJson(): string;
  getPeer(peerId: string): unknown | null;
  confirmPeer(peerId: string, sas?: string | null): Promise<void>;
  removePendingPeer(peerId: string): Promise<void>;
  addTrustAnchor(anchorId: string, signingPubB64: string): Promise<void>;
  revokeTrustAnchor(anchorId: string): Promise<void>;
  mintEnrollmentToken(options: {
    targetHostId: string;
    subject?: string | null;
    ttlSecs?: number;
  }): string;
  enroll(options: {
    endpoint?: string | null;
    relayUrl?: string | null;
    targetPub?: string | null;
    expectedHost?: string | null;
    relayUrlOverride?: string | null;
    allowInsecureWs?: boolean;
    hostId: string;
    hostStaticPubB64: string;
    hostSigningPubB64: string;
    hostRotationSeq?: number;
    tokenJson: string;
    deviceName?: string;
    deviceKind?: string;
    timeoutMs?: number;
  }): Promise<EnrollResult>;
  pair(options: {
    endpoint?: string | null;
    relayUrl?: string | null;
    targetPub?: string | null;
    expectedHost?: string | null;
    relayUrlOverride?: string | null;
    allowInsecureWs?: boolean;
    code?: string;
    pairingUri?: string | null;
    deviceName?: string;
    deviceKind?: string;
    timeoutMs?: number;
  }): Promise<PairResult>;
  connect(options: {
    endpoint?: string | null;
    relayUrl?: string | null;
    targetPub?: string | null;
    expectedHost?: string | null;
    relayUrlOverride?: string | null;
    allowInsecureWs?: boolean;
    targetHostId: string;
    grantJson?: string | null;
    crlSeq?: number | null;
    timeoutMs?: number;
  }): Promise<TendrilWebSession>;
  free(): void;
}

export class TendrilWebSession {
  private constructor();
  isEstablished(): boolean;
  isClosed(): boolean;
  sendData(payload: Uint8Array | string): Promise<void>;
  pollEvent(timeoutMs?: number): Promise<PollEvent>;
  rekey(): Promise<void>;
  ping(cookie?: number): Promise<void>;
  tick(): Promise<void>;
  authorize(requestedCap: string): boolean;
  close(code?: number, reason?: string): Promise<void>;
}
