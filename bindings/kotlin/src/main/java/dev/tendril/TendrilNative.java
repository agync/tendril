package dev.tendril;

final class TendrilNative {
  static {
    System.loadLibrary("tendril_jni");
  }

  private TendrilNative() {}

  public static native String deviceId(byte[] staticPub);

  public static native String fingerprintHost(byte[] staticPub);

  public static native String fingerprintDevice(byte[] staticPub);

  public static native String pairingSas(byte[] handshakeHash);

  public static native byte[] computeCodeMac(String code, byte[] handshakeHash);

  public static native long verifyRotationChainJson(
      String pinnedSigningB64,
      String pinnedStaticB64,
      long pinnedSeq,
      String chainJson,
      String curStaticB64,
      String curSigningB64);

  public static native boolean verifyGrantJson(
      String grantJson,
      String issuerKeysJson,
      String expectedSubject,
      String expectedRootIssuer,
      String requestedCap,
      long nowUnix,
      String crlJson);

  public static native long endpointNew(String stateDir, String hostId);

  public static native long endpointNewFromState(
      String identityJson, String rosterJson, String hostId);

  public static native long endpointNewSealed(
      String stateDir, String identityJson, String rosterJson, String hostId);

  public static native void endpointClose(long ptr);

  public static native void endpointFree(long ptr);

  public static native String endpointExportIdentityJson(long ptr);

  public static native String endpointExportRosterJson(long ptr);

  public static native String endpointInfoJson(long ptr);

  public static native String endpointServeDirect(long ptr, String listenAddr);

  public static native String endpointServeRelay(
      long ptr, String relayUrl, String expectedHost);

  public static native void endpointConfigureTransportsJson(
      long ptr, String transportConfigJson);

  public static native String endpointMintRelayTicket(
      long ptr, String relayHost, String role, String targetPubOrWildcard, long ttlSecs);

  public static native String endpointServeRelayV2(
      long ptr, String relayUrl, String expectedHost, String peerIdOpt);

  public static native String endpointServeP2p(long ptr, String relayMode);

  public static native String endpointIssueCode(long ptr, String kind);

  public static native String endpointPairInitiate(
      long ptr, String endpoint, String relayHost, String code, String name, String kind);

  public static native String endpointPairAccept(long ptr, long timeoutMs);

  public static native String endpointPairV2Initiate(
      long ptr,
      String endpoint,
      String relayHost,
      String code,
      String name,
      String kind,
      String pinnedHostJson);

  public static native String endpointPairV2Accept(long ptr, long timeoutMs);

  public static native void endpointConfirmPeer(long ptr, String peerId, String sas);

  public static native String endpointMintGrant(
      long ptr, String peerId, String capsJson, long ttlSecs);

  public static native void endpointRevokePeer(long ptr, String peerId);

  public static native void endpointAddTrustAnchor(
      long ptr, String anchorId, byte[] signingPub);

  public static native void endpointRevokeTrustAnchor(long ptr, String anchorId);

  public static native String endpointMintEnrollmentToken(
      long ptr, String targetHostId, String subject, long ttlSecs);

  public static native String endpointEnrollInitiate(
      long ptr,
      String endpoint,
      String relayHost,
      String hostId,
      byte[] hostStaticPub,
      byte[] hostSigningPub,
      long hostRotationSeq,
      String tokenJson,
      String name,
      String kind);

  public static native String endpointIssuePairingUri(long ptr, String optionsJson);

  public static native String endpointPairUri(
      long ptr, String pairingUri, String name, String kind, String optionsJson);

  public static native String endpointPairV2Uri(
      long ptr, String pairingUri, String name, String kind, String optionsJson);

  public static native void endpointSetPeerRoutes(long ptr, String peerId, String routesJson);

  public static native String endpointPeerRoutes(long ptr, String peerId);

  public static native void endpointClearPeerRoutes(long ptr, String peerId, String source);

  public static native String endpointApplyRouteUri(long ptr, String pairingUri, String optionsJson);

  public static native String endpointRefreshRoutes(long ptr, String snapshotJson);

  public static native long sessionConnectWithOptions(
      long epPtr, String targetHostId, String optionsJson);

  public static native long sessionConnect(
      long epPtr, String endpoint, String relayHost, String targetHostId, String grantJson);

  public static native long sessionAccept(long epPtr, long timeoutMs);

  public static native long sessionConnectV2(
      long epPtr, String endpoint, String relayHost, String targetHostId, String grantJson);

  public static native long sessionAcceptV2(long epPtr, long timeoutMs);

  public static native void sessionShutdown(long ptr);

  public static native String sessionExportRosterJson(long ptr);

  public static native String sessionPeerId(long ptr);

  public static native void sessionFree(long ptr);

  public static native void sessionSendData(long ptr, byte[] data);

  public static native String sessionPollEvent(long ptr, long timeoutMs);

  public static native boolean sessionAuthorize(long ptr, String cap);

  public static native void sessionRekey(long ptr);

  public static native void sessionClose(long ptr, int code, String reason);

  public static native String groupCreate(
      long epPtr, String name, int minWireVersion, String endpointsJson);

  public static native String groupAddMember(
      long epPtr, String groupId, String peerId, String capsJson, String endpointsJson);

  public static native String groupRemoveMember(long epPtr, String groupId, String peerId);

  public static native String groupIngestManifest(
      long epPtr, String manifestJson, String senderPeerId);

  public static native long groupOpen(long epPtr, String groupId, String listenAddr);

  public static native String groupLocalEndpoint(long ptr);

  public static native String groupSync(long ptr);

  public static native String groupBroadcast(long ptr, String requiredCap, byte[] data);

  public static native String groupPollEvent(long ptr, long timeoutMs);

  public static native void groupAuthorizePeer(long ptr, String peerId, String cap);

  public static native void groupClose(long ptr);

  public static native void groupFree(long ptr);
}
