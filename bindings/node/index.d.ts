export function deviceId(staticPub: Buffer): string;
export function fingerprintHost(staticPub: Buffer): string;
export function fingerprintDevice(staticPub: Buffer): string;
export function pairingSas(handshakeHash: Buffer): string;
export function computeCodeMac(code: string, handshakeHash: Buffer): Promise<Buffer>;
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
  nowUnixSecs: number,
  crlJson?: string | null
): boolean;

export class Endpoint {
  constructor(stateDir?: string | null, hostId?: string | null);
  infoJson(): string;
  serveDirect(listenAddr?: string | null): Promise<string>;
  serveRelay(relayUrl: string, expectedHost?: string | null): Promise<string>;
  serveP2p(relayMode?: string | null): Promise<string>;
  issueCode(kind?: string | null): string;
  pairInitiate(
    endpoint: string,
    code: string,
    relayHost?: string | null,
    name?: string | null,
    kind?: string | null
  ): Promise<string>;
  pairAccept(timeoutMs?: number | null): Promise<string>;
  confirmPeer(peerId: string, sas?: string | null): void;
  mintGrant(peerId: string, caps: string[], ttlSecs?: number | null): string;
  revokePeer(peerId: string): void;
  addTrustAnchor(anchorId: string, signingPub: Buffer): void;
  revokeTrustAnchor(anchorId: string): void;
  mintEnrollmentToken(
    targetHostId: string,
    subject?: string | null,
    ttlSecs?: number | null
  ): string;
  enrollInitiate(
    endpoint: string,
    hostId: string,
    hostStaticPub: Buffer,
    hostSigningPub: Buffer,
    tokenJson: string,
    relayHost?: string | null,
    hostRotationSeq?: number | null,
    name?: string | null,
    kind?: string | null
  ): Promise<string>;
  connect(
    endpoint: string,
    targetHostId: string,
    grantJson?: string | null,
    relayHost?: string | null
  ): Promise<Session>;
  acceptSession(timeoutMs?: number | null): Promise<Session>;
  close(): void;
}

export class Session {
  private constructor();
  sendData(payload: Buffer): Promise<void>;
  pollEvent(timeoutMs?: number | null): Promise<string>;
  authorize(requestedCap: string): Promise<boolean>;
  rekey(): Promise<void>;
  close(code?: number | null, reason?: string | null): Promise<void>;
}
