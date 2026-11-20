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

  public static native void endpointClose(long ptr);

  public static native void endpointFree(long ptr);

  public static native String endpointExportIdentityJson(long ptr);

  public static native String endpointExportRosterJson(long ptr);

  public static native String endpointInfoJson(long ptr);

  public static native String endpointServeDirect(long ptr, String listenAddr);

  public static native String endpointServeRelay(
      long ptr, String relayUrl, String expectedHost);

  public static native String endpointServeP2p(long ptr, String relayMode);

  public static native String endpointIssueCode(long ptr, String kind);

  public static native String endpointPairInitiate(
      long ptr, String endpoint, String relayHost, String code, String name, String kind);

  public static native String endpointPairAccept(long ptr, long timeoutMs);

  public static native void endpointConfirmPeer(long ptr, String peerId, String sas);

  public static native String endpointMintGrant(
      long ptr, String peerId, String capsJson, long ttlSecs);

  public static native void endpointRevokePeer(long ptr, String peerId);

  public static native long sessionConnect(
      long epPtr, String endpoint, String relayHost, String targetHostId, String grantJson);

  public static native long sessionAccept(long epPtr, long timeoutMs);

  public static native void sessionShutdown(long ptr);

  public static native String sessionExportRosterJson(long ptr);

  public static native void sessionFree(long ptr);

  public static native void sessionSendData(long ptr, byte[] data);

  public static native String sessionPollEvent(long ptr, long timeoutMs);

  public static native boolean sessionAuthorize(long ptr, String cap);

  public static native void sessionRekey(long ptr);

  public static native void sessionClose(long ptr, int code, String reason);
}
