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
  host_signing_pub_hash_b64: string;
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
  signing_pub_hash: string;
  relay_pub: string;
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

export interface PeerV2Summary {
  min_wire_version: number;
  has_v2_secrets: boolean;
}

export interface V2RelayDialDerived {
  mailbox_id: string;
  epoch: number;
  dial_token: string;
}

export interface V2RelayDialContext {
  relayHost: string;
  nonceBytes: Uint8Array;
  connIdBytes: Uint8Array;
  connId: string;
  serverEpoch: number;
}

export interface V2PinnedHostInput {
  host_id?: string | null;
  static_pub_b64: string;
  signing_pub_b64: string;
  rotation_seq?: number | null;
  min_wire_version?: number | null;
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
  peer_device_id?: string;
}

export interface IndexedDbVaultOptions {
  dbName?: string;
  storeName?: string;
  wrappingKeyId?: string;
  aadPrefix?: string;
  isSecureContext?: boolean;
  cryptoSubtle?: SubtleCrypto;
  getRandomValues?: <T extends ArrayBufferView>(array: T) => T;
  indexedDB?: IDBFactory;
}

export interface TendrilIndexedDbVault {
  readString(entryId: string): Promise<string | null>;
  writeString(entryId: string, value: string): Promise<void>;
  readBytes(entryId: string): Promise<Uint8Array | null>;
  writeBytes(entryId: string, bytes: Uint8Array): Promise<void>;
  delete(entryId: string): Promise<void>;
  clear(): Promise<void>;
  close(): Promise<void>;
}

export function createIndexedDbVault(options?: IndexedDbVaultOptions): TendrilIndexedDbVault;
export const openTendrilVault: typeof createIndexedDbVault;

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
): { url: string; bareHost: string; host: string };

export function canonicalRelayHost(host: string): string;

export function dialRelayStream(options: {
  relayUrl: string;
  targetPub: string;
  expectedHost?: string | null;
  allowInsecureWs?: boolean;
  relayAuthTicket?: string | Record<string, unknown> | null;
  relayAuthSecret?: string | Uint8Array | null;
  timeoutMs?: number;
}): Promise<TendrilStream>;

export function dialRelayV2Stream(options: {
  relayUrl: string;
  deriveV2Dial: (ctx: V2RelayDialContext) => V2RelayDialDerived | Promise<V2RelayDialDerived>;
  expectedHost?: string | null;
  allowInsecureWs?: boolean;
  relayAuthTicket?: string | Record<string, unknown> | null;
  relayAuthSecret?: string | Uint8Array | null;
  timeoutMs?: number;
}): Promise<TendrilStream>;

export function dialIrohStream(options: {
  endpoint: string;
  relayUrlOverride?: string | null;
  p2pRelayUrls?: string[] | null;
  p2pRelayAuthToken?: string | Uint8Array | null;
  p2pApiSecret?: never | null;
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
export function computeRelayAuthHmacB64(
  secretBytes: Uint8Array,
  op: "register" | "dial",
  relayHost: string,
  nonce: Uint8Array,
  pubOrTarget: Uint8Array
): string;
export function deriveV2RelayDial(
  mailboxSecret: Uint8Array,
  relayHost: string,
  unixSecs: number,
  dialNonce: Uint8Array,
  connId: Uint8Array
): V2RelayDialDerived;
export function v2EpochWithinSkew(serverEpoch: number, claimedEpoch: number): boolean;

export class WasmV2PakePairInitiator {
  constructor(
    identity: unknown,
    device_name: string,
    device_kind: string,
    code: string,
    pinned_host_json?: string | null
  );
  static new_bytes(
    identity: unknown,
    device_name: string,
    device_kind: string,
    code: Uint8Array,
    pinned_host_json?: string | null
  ): WasmV2PakePairInitiator;
  start(): Uint8Array;
  feed_bytes(bytes: Uint8Array, roster: unknown): string;
  drain_events_json(): string;
  free(): void;
}

export class WasmV2SessionInitiator {
  constructor(
    identity: unknown,
    target_host_id: string,
    roster: unknown,
    grant_json?: string | null,
    crl_seq?: number | null
  );
  start(now_unix: number): Uint8Array;
  feed_bytes(chunk: Uint8Array, now_unix: number, now_ms: number, roster: unknown): string;
  poll_write(): Uint8Array;
  drain_events_json(): string;
  send_data(payload: Uint8Array, now_ms: number): Uint8Array;
  send_dummy_cover(bucket_size: number, now_ms: number): Uint8Array;
  next_ping_delay_ms(): number;
  send_ping(cookie: number, now_ms: number): Uint8Array;
  authorize(requested_cap: string, now_unix: number, roster: unknown): boolean;
  rekey(now_ms: number): Uint8Array;
  close(code: number, reason: string, now_ms: number): Uint8Array;
  tick(now_unix: number, now_ms: number, roster: unknown): Uint8Array;
  is_established(): boolean;
  is_closed(): boolean;
  free(): void;
}

export interface TendrilWebClientOptions {
  hostId?: string | null;
  identityJson?: string | null;
  identityBytes?: Uint8Array | null;
  rosterJson?: string | null;
  rosterBytes?: Uint8Array | null;
  onPersistRoster?: ((rosterJson: string) => void | Promise<void>) | null;
}

export interface WebTransportDialOptions {
  endpoint?: string | null;
  relayUrl?: string | null;
  targetPub?: string | null;
  expectedHost?: string | null;
  relayUrlOverride?: string | null;
  p2pRelayUrls?: string[] | null;
  p2pRelayAuthToken?: string | Uint8Array | null;
  p2pApiSecret?: never | null;
  relayAuthTicket?: string | Record<string, unknown> | null;
  relayAuthSecret?: string | Uint8Array | null;
  allowInsecureWs?: boolean;
  timeoutMs?: number;
}

export class TendrilWebClient {
  private constructor();
  static create(options?: TendrilWebClientOptions): Promise<TendrilWebClient>;
  info(): EndpointInfo;
  exportIdentityJson(): string;
  exportIdentityBytes(): Uint8Array;
  exportRosterJson(): string;
  exportRosterBytes(): Uint8Array;
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
  mintRelayTicket(
    relayHost: string,
    role?: "register" | "dial" | "any",
    targetPubOrWildcard?: string,
    ttlSecs?: number
  ): string;
  pairingFloor(staticPub: Uint8Array | string): number;
  peerV2Summary(peerId: string): PeerV2Summary;
  enroll(
    options: WebTransportDialOptions & {
      hostId: string;
      hostStaticPubB64: string;
      hostSigningPubB64: string;
      hostRotationSeq?: number;
      tokenJson: string;
      deviceName?: string;
      deviceKind?: string;
    }
  ): Promise<EnrollResult>;
  pair(
    options: WebTransportDialOptions & {
      code?: string;
      pairingUri?: string | null;
      deviceName?: string;
      deviceKind?: string;
    }
  ): Promise<PairResult>;
  pairV2(
    options: WebTransportDialOptions & {
      code?: string | Uint8Array;
      pairingUri?: string | null;
      pinnedHost?: string | V2PinnedHostInput | null;
      deviceName?: string;
      deviceKind?: string;
    }
  ): Promise<PairResult>;
  connect(
    options: WebTransportDialOptions & {
      targetHostId: string;
      grantJson?: string | null;
      crlSeq?: number | null;
    }
  ): Promise<TendrilWebSession>;
  connectV2(
    options: WebTransportDialOptions & {
      useRelayV2?: boolean;
      targetHostId: string;
      grantJson?: string | null;
      crlSeq?: number | null;
    }
  ): Promise<TendrilWebSession>;
  free(): void;
}

export class TendrilWebSession {
  private constructor();
  isEstablished(): boolean;
  isClosed(): boolean;
  sendData(payload: Uint8Array | string): Promise<void>;
  sendDummyCover(bucketSize?: number): Promise<void>;
  nextPingDelayMs(): number;
  poll(timeoutMs?: number): Promise<PollEvent>;
  pollEvent(timeoutMs?: number): Promise<PollEvent>;
  rekey(): Promise<void>;
  ping(cookie?: number): Promise<void>;
  tick(): Promise<void>;
  authorize(requestedCap: string): boolean;
  close(code?: number, reason?: string): Promise<void>;
}
