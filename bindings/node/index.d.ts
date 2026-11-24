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
  /** An empty or null `endpoint` dials the target's stored routes. */
  connect(
    endpoint: string | null | undefined,
    targetHostId: string,
    grantJson?: string | null,
    relayHost?: string | null
  ): Promise<Session>;
  acceptSession(timeoutMs?: number | null): Promise<Session>;
  /**
   * Every key is accepted in snake_case (`relay_auth_secret`, `wake_pre_wake`,
   * `relay_auth_origins`, ...) and in camelCase (`relayAuthSecret`, `wakePreWake`,
   * `relayAuthOrigins`, ...). Besides the relay, p2p and wake keys: `relay_auth_origins`
   * (string[] of scheme://host[:port]), `advertise` ("auto" | "explicit"),
   * `advertised_endpoints` (string[]), `route_policy` ("all_signed" | "committed_only" |
   * "none") and `sign_routes` (boolean). A changed advertise set is published off the calling
   * thread, and the next `issuePairingUri` or `refreshRoutes` waits for that publish; a
   * publish error is not an error of this call (the issuance or refresh reports it).
   */
  configureTransportsJson(transportConfigJson: string): void;
  mintRelayTicket(
    relayHost: string,
    role?: string | null,
    targetPubOrWildcard?: string | null,
    ttlSecs?: number | null
  ): string;
  serveRelayV2(
    relayUrl: string,
    expectedHost?: string | null,
    peerId?: string | null
  ): Promise<string>;
  pairV2Initiate(
    endpoint: string,
    code: string,
    relayHost?: string | null,
    name?: string | null,
    kind?: string | null,
    pinnedHostJson?: string | null
  ): Promise<string>;
  pairV2Accept(timeoutMs?: number | null): Promise<string>;
  /** An empty or null `endpoint` dials the target's stored routes. */
  connectV2(
    endpoint: string | null | undefined,
    targetHostId: string,
    grantJson?: string | null,
    relayHost?: string | null
  ): Promise<Session>;
  /**
   * Day-2 connect with every option in one JSON object: `{"wire": 1 | 2, "grant": object,
   * "endpoint": string, "recovery_uri": string, "replace_routes": boolean,
   * "route_policy": string, "relay_host": string}`.
   */
  connectWithOptions(targetHostId: string, optionsJson: string): Promise<Session>;
  /**
   * Issues a pairing URI from the announced route set. Options
   * `{"kind": "auto" | "lan" | "remote", "host_name": string, "sign_routes": boolean}`.
   * Resolves to JSON `{"uri", "code_kind", "dropped", "uri_len", "qr_version_m", "route_seq"}`.
   */
  issuePairingUri(optionsJson?: string | null): Promise<string>;
  /**
   * Pairs over Wire v1 from a scanned pairing URI. Options
   * `{"route_policy": "all_signed" | "committed_only" | "none", "save_route": boolean,
   * "endpoint": string, "code": string}`. Resolves to the pairing outcome JSON plus
   * `provider`, `endpoint`, `committed`, `route_check`, `routes_persisted`, `routes_reason`
   * and `skipped`.
   */
  pairUri(
    pairingUri: string,
    name?: string | null,
    kind?: string | null,
    optionsJson?: string | null
  ): Promise<string>;
  /** As `pairUri` over Wire v2 PAKE; the outcome adds `"wire_version": 2`. */
  pairV2Uri(
    pairingUri: string,
    name?: string | null,
    kind?: string | null,
    optionsJson?: string | null
  ): Promise<string>;
  /**
   * Replaces the peer's operator routes. `routesJson` is a JSON array of endpoint strings
   * (at most six; an empty array clears them). Resolves to the peer's routes as JSON
   * `[{"hint", "source"}]`.
   */
  setPeerRoutes(peerId: string, routesJson: string): Promise<string>;
  /**
   * Resolves to JSON `{"routes": [{"hint", "source"}], "route_meta": {"seq", "issued_at",
   * "origin"} | null, "last_route_set": {"outcome", "seq"} | null}`.
   */
  peerRoutes(peerId: string): Promise<string>;
  /** Removes routes of `source`: "operator" (default), "signed", "committed" or "all". */
  clearPeerRoutes(peerId: string, source?: string | null): Promise<void>;
  /**
   * Applies a fresh signed pairing URI to the matching paired host offline. Options
   * `{"replace_routes": boolean, "route_policy": string}`. Resolves to JSON
   * `{"peer_id", "applied", "reason", "route_seq"}`.
   */
  applyRouteUri(pairingUri: string, optionsJson?: string | null): Promise<string>;
  /**
   * Re-scans the host's addresses and publishes the announced route set. `snapshotJson` is the
   * complete network snapshot `{"networks": [{"id", "iface", "if_index", "transports", "addrs"}]}`;
   * null re-enumerates natively or reuses the retained snapshot. Resolves to JSON
   * `{"route_seq", "changed"}`.
   */
  refreshRoutes(snapshotJson?: string | null): Promise<string>;
  acceptV2(timeoutMs?: number | null): Promise<Session>;
  groupCreate(
    name: string,
    minWireVersion: number,
    endpoints?: string[] | null
  ): Promise<string>;
  groupAddMember(
    groupId: string,
    peerId: string,
    caps?: string[] | null,
    endpoints?: string[] | null
  ): Promise<string>;
  groupRemoveMember(groupId: string, peerId: string): Promise<string>;
  groupIngestManifest(manifestJson: string, senderPeerId: string): Promise<string>;
  groupOpen(
    groupId: string,
    listenAddr?: string | null,
    relayListen?: boolean | null
  ): Promise<Group>;
  close(): void;
}

export class Group {
  private constructor();
  readonly groupId: string;
  readonly localEndpoint: string | null;
  broadcast(data: Buffer, requiredCap?: string | null): Promise<string>;
  sync(): Promise<string>;
  pollEvent(timeoutMs?: number | null): Promise<string | null>;
  authorizePeer(peerId: string, cap: string): boolean;
  close(): Promise<void>;
}

export class Session {
  private constructor();
  sendData(payload: Buffer): Promise<void>;
  pollEvent(timeoutMs?: number | null): Promise<string>;
  authorize(requestedCap: string): Promise<boolean>;
  rekey(): Promise<void>;
  close(code?: number | null, reason?: string | null): Promise<void>;
}
