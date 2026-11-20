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
export function b64urlEncode(bytes: Uint8Array): string;
export function b64urlDecode(str: string): Uint8Array;
export function deviceId(staticPub: Uint8Array): string;
export function fingerprintHost(staticPub: Uint8Array): string;
export function fingerprintDevice(staticPub: Uint8Array): string;
export function pairingSas(handshakeHash: Uint8Array): string;
export function computeCodeMac(code: string, handshakeHash: Uint8Array): Uint8Array;
export function computeCodeMacWorker(code: string, handshakeHash: Uint8Array): Promise<Uint8Array>;
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
  pair(options: {
    relayUrl: string;
    targetPub: string;
    expectedHost?: string | null;
    code?: string;
    pairingUri?: string | null;
    deviceName?: string;
    deviceKind?: string;
    timeoutMs?: number;
  }): Promise<PairResult>;
  connect(options: {
    relayUrl: string;
    targetPub: string;
    expectedHost?: string | null;
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
