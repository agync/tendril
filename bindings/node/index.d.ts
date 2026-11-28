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
export function verifyWakeTag(
  wakeSecret: Buffer,
  wakeTagB64: string,
  nowUnixSecs: number
): boolean;

/**
 * Decodes a `0x0C ROUTE_SET` payload and verifies its hybrid signature against the 1984-byte
 * `signingPub`. Returns JSON `{"seq","issued_at","routes"}` only when both succeed. Throws an
 * `Error` whose message is `signing key invalid`, `route set decode failed` or
 * `route set signature invalid`. There is no unverified decode.
 */
export function verifyRouteSet(payload: Buffer, signingPub: Buffer): string;

/**
 * The error of a session the host refused over an authenticated channel. Rejected by a refused
 * Wire v2 `connectV2` (or `connectWithOptions` with `wire: 2`), and by `sendData`, `rekey` and
 * `close` on a session the host ended with a refusal. A Wire v1 connect resolves before the
 * refusal arrives and never rejects with it: the session then reports a `closed` event whose
 * `refusal` is set, and the next `sendData`, `rekey` or `close` rejects. `pollEvent` never
 * rejects with it.
 *
 * - `refused_revoked` (`closeCode` 4001): the host blocks this device key permanently. Re-pairing
 *   needs a new device identity, so offer to forget the host.
 * - `refused_pending` (`closeCode` 4004): the host has not confirmed this device yet. Retry with
 *   backoff.
 * - `refused` (`closeCode` 4400 to 4499): a reserved admission refusal.
 *
 * A host sends at most one notice per peer in a short window, so a rapid retry can fail with a
 * plain `Error` instead. Test with `isRefusedError`.
 */
export interface RefusedError extends Error {
  code: "refused_revoked" | "refused_pending" | "refused";
  closeCode: number;
}

/** `true` when `err` is a [`RefusedError`](#refusederror). */
export function isRefusedError(err: unknown): err is RefusedError;

/**
 * The `closed` event of `Session.pollEvent`, as parsed JSON. `refusal` is `"revoked"`,
 * `"pending"`, `"other"` or `null`; it is set only on a session this endpoint dialed.
 */
export interface ClosedEvent {
  status: "event";
  event: "closed";
  code: number;
  reason: string;
  refusal: "revoked" | "pending" | "other" | null;
}

export class Endpoint {
  constructor(stateDir?: string | null, hostId?: string | null);
  infoJson(): string;
  serveDirect(listenAddr?: string | null): Promise<string>;
  serveRelay(relayUrl: string, expectedHost?: string | null): Promise<string>;
  serveP2p(relayMode?: string | null): Promise<string>;
  serveP2pV2(relayMode?: string | null, peerId?: string | null): Promise<string>;
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
  /**
   * Revokes `peerId` and clears its grants. `notify` unset follows the refusal policy, which
   * records a notice unless `revokedNoticeTtlSecs` is `0`; `false` revokes silently and clears an
   * earlier notice. Throws for an unknown peer.
   */
  revokePeer(peerId: string, notify?: boolean | null): void;
  /**
   * Sets the host refusal policy and persists it with the roster. `pending` refuses unconfirmed
   * peers with close code 4004 (default `true`). `revokedNoticeTtlSecs` is the lifetime of a notice
   * recorded at revocation (default 30 days); `0` records none. Notices already recorded keep their
   * expiry.
   */
  setRefusalPolicy(pending?: boolean | null, revokedNoticeTtlSecs?: number | null): void;
  /** Drops the refusal notice of `peerId`, which stays revoked. Throws for an unknown peer. */
  clearRefusalNotice(peerId: string): void;
  /**
   * Resolves to the unconfirmed host claims left by unpinned pairing, oldest first, as a JSON
   * array of `{"host_id", "device_id", "name", "static_pub", "signing_pub_hash", "rotation_seq",
   * "min_wire_version", "pairing_sas"}`. `host_id` is the unauthenticated label a claim names and
   * `device_id` the id derived from its static key in the handshake.
   */
  pendingHosts(): Promise<string>;
  /** Drops every unconfirmed host claim naming `hostId` and revokes nothing. */
  removePendingHost(hostId: string): void;
  /**
   * Revokes the keys of the claims whose handshake-derived `deviceId` matches; a claimed
   * `host_id` never matches.
   */
  revokePendingHost(deviceId: string): void;
  addTrustAnchor(anchorId: string, signingPub: Buffer): void;
  revokeTrustAnchor(anchorId: string): void;
  mintEnrollmentToken(
    targetHostId: string,
    subject?: string | null,
    ttlSecs?: number | null
  ): string;
  /**
   * Enrols as a machine under the endpoint's `route_policy` (default `all_signed`). With a state
   * directory the host is pinned and its Day-2 routes are stored in one transaction: the host's
   * signed set and the endpoint dialed as the `committed` route (`committed_only` keeps the
   * endpoint alone, `none` requests and stores nothing). The result JSON adds `routes_persisted`
   * (stored routes, `[]` under `none`), `route_warnings` (reasons a route was not stored; the
   * enrolment still succeeded) and `routes_reason` (`null`, or `"no_state_dir"` on a memory-only
   * endpoint, which stores no route). A host that predates route sets rejects `all_signed` as a
   * protocol error before it spends the token: configure `route_policy` `"committed_only"` or
   * `"none"` for it.
   */
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
   * Every key is accepted in snake_case (`relay_auth_secret`, `wake_pre_wake`, `wake_coalesce_secs`,
   * `wake_apns_mode`, `wake_apns_topic`, `wake_apns_loc_key`, `wake_apns_team_id`,
   * `wake_apns_key_id`, `wake_apns_p8_pem`, `wake_apns_client_cert_pem`,
   * `wake_apns_client_key_pem`, `relay_auth_origins`, ...) and in camelCase (`relayAuthSecret`,
   * `wakePreWake`, `wakeCoalesceSecs`, `wakeApnsMode`, `wakeApnsTopic`, `wakeApnsLocKey`,
   * `wakeApnsTeamId`, `wakeApnsKeyId`, `wakeApnsP8Pem`, `wakeApnsClientCertPem`,
   * `wakeApnsClientKeyPem`, `relayAuthOrigins`, ...). Besides the relay, p2p and wake keys:
   * `relay_auth_origins` (string[] of scheme://host[:port]), `advertise` ("auto" | "explicit"),
   * `advertised_endpoints` (string[]), `p2p_port_mapping` (boolean, defaults to `true` on desktop
   * listeners and `false` on mobile or `low_power` listeners and all dialers; false stops P2P
   * endpoints from probing the router), `p2p_ephemeral` (boolean; uses an ephemeral key and
   * disables `Pkarr` publishing on Day-1 `serveP2p` unless `p2p_pkarr` overrides), `p2p_bind_addrs`
   * (string[] of at most one IPv4 and one IPv6 address such as "0.0.0.0:0"; camelCase
   * `p2pPortMapping`, `p2pEphemeral`, `p2pBindAddrs`), `route_policy` ("all_signed" |
   * "committed_only" | "none"), `sign_routes` (boolean), `power_profile` ("standard" | "low_power",
   * camelCase `powerProfile`), and `wake_retry_max_delay_ms` (number, camelCase
   * `wakeRetryMaxDelayMs`). A changed advertise set is published off the calling thread, and the
   * next `issuePairingUri` or `refreshRoutes` waits for that publish; a publish error is not an
   * error of this call (the issuance or refresh reports it).
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
   * "route_policy": string, "relay_host": string, "idle_timeout_ms" | "idleTimeoutMs": number}`.
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
  /**
   * Notifies the route announcer whether an external OS path monitor owns interface-change
   * refreshes, suppressing periodic background polling while active.
   */
  setExternalPathMonitor(active: boolean): void;
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
  readonly peerId: string;
  sendData(payload: Buffer): Promise<void>;
  pollEvent(timeoutMs?: number | null): Promise<string>;
  authorize(requestedCap: string): Promise<boolean>;
  rekey(): Promise<void>;
  close(code?: number | null, reason?: string | null): Promise<void>;
}
