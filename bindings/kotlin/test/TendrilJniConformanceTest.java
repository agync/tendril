package dev.tendril;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class TendrilJniConformanceTest {
  private static void check(boolean cond, String msg) {
    if (!cond) {
      throw new AssertionError(msg);
    }
  }

  private static byte[] hexDecode(String hex) {
    int n = hex.length();
    byte[] out = new byte[n / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  private static String hexEncode(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(String.format("%02x", b & 0xff));
    }
    return sb.toString();
  }

  private static String b64Url(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static byte[] b64UrlDecode(String s) {
    return Base64.getUrlDecoder().decode(s);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> asObj(Object v) {
    return (Map<String, Object>) v;
  }

  @SuppressWarnings("unchecked")
  private static List<Object> asArr(Object v) {
    return (List<Object>) v;
  }

  private static String asStr(Object v) {
    return (String) v;
  }

  private static final class Json {
    private final String src;
    private int pos;

    private Json(String src) {
      this.src = src;
    }

    static Object parse(String s) {
      Json j = new Json(s);
      Object v = j.readValue();
      j.skipWs();
      if (j.pos != j.src.length()) {
        throw new IllegalArgumentException("trailing json chars at " + j.pos);
      }
      return v;
    }

    static String stringify(Object v) {
      StringBuilder sb = new StringBuilder();
      writeJson(sb, v);
      return sb.toString();
    }

    private static void writeJson(StringBuilder sb, Object v) {
      if (v == null) {
        sb.append("null");
      } else if (v instanceof Boolean || v instanceof Number) {
        sb.append(v);
      } else if (v instanceof String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
          char c = s.charAt(i);
          if (c == '"' || c == '\\') {
            sb.append('\\').append(c);
          } else if (c == '\n') {
            sb.append("\\n");
          } else if (c == '\r') {
            sb.append("\\r");
          } else if (c == '\t') {
            sb.append("\\t");
          } else if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
        }
        sb.append('"');
      } else if (v instanceof List<?> list) {
        sb.append('[');
        for (int i = 0; i < list.size(); i++) {
          if (i > 0) sb.append(',');
          writeJson(sb, list.get(i));
        }
        sb.append(']');
      } else if (v instanceof Map<?, ?> map) {
        sb.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> e : map.entrySet()) {
          if (!first) sb.append(',');
          first = false;
          writeJson(sb, String.valueOf(e.getKey()));
          sb.append(':');
          writeJson(sb, e.getValue());
        }
        sb.append('}');
      } else {
        throw new IllegalArgumentException("unsupported json type: " + v.getClass());
      }
    }

    private void skipWs() {
      while (pos < src.length()) {
        char c = src.charAt(pos);
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
          pos++;
        } else {
          break;
        }
      }
    }

    private Object readValue() {
      skipWs();
      char c = src.charAt(pos);
      if (c == '{') return readObject();
      if (c == '[') return readArray();
      if (c == '"') return readString();
      if (c == 't') {
        pos += 4;
        return Boolean.TRUE;
      }
      if (c == 'f') {
        pos += 5;
        return Boolean.FALSE;
      }
      if (c == 'n') {
        pos += 4;
        return null;
      }
      return readNumber();
    }

    private Map<String, Object> readObject() {
      pos++;
      Map<String, Object> map = new LinkedHashMap<>();
      skipWs();
      if (src.charAt(pos) == '}') {
        pos++;
        return map;
      }
      while (true) {
        skipWs();
        String key = readString();
        skipWs();
        if (src.charAt(pos++) != ':') {
          throw new IllegalArgumentException("expected ':' at " + pos);
        }
        Object val = readValue();
        map.put(key, val);
        skipWs();
        char next = src.charAt(pos++);
        if (next == '}') break;
        if (next != ',') {
          throw new IllegalArgumentException("expected ',' or '}' at " + (pos - 1));
        }
      }
      return map;
    }

    private List<Object> readArray() {
      pos++;
      List<Object> list = new ArrayList<>();
      skipWs();
      if (src.charAt(pos) == ']') {
        pos++;
        return list;
      }
      while (true) {
        list.add(readValue());
        skipWs();
        char next = src.charAt(pos++);
        if (next == ']') break;
        if (next != ',') {
          throw new IllegalArgumentException("expected ',' or ']' at " + (pos - 1));
        }
      }
      return list;
    }

    private String readString() {
      pos++;
      StringBuilder sb = new StringBuilder();
      while (pos < src.length()) {
        char c = src.charAt(pos++);
        if (c == '"') {
          return sb.toString();
        }
        if (c == '\\') {
          char esc = src.charAt(pos++);
          switch (esc) {
            case '"', '\\', '/' -> sb.append(esc);
            case 'b' -> sb.append('\b');
            case 'f' -> sb.append('\f');
            case 'n' -> sb.append('\n');
            case 'r' -> sb.append('\r');
            case 't' -> sb.append('\t');
            case 'u' -> {
              int cp = Integer.parseInt(src.substring(pos, pos + 4), 16);
              pos += 4;
              sb.append((char) cp);
            }
            default -> throw new IllegalArgumentException("bad escape: \\" + esc);
          }
        } else {
          sb.append(c);
        }
      }
      throw new IllegalArgumentException("unterminated string");
    }

    private Number readNumber() {
      int start = pos;
      boolean isFloat = false;
      while (pos < src.length()) {
        char c = src.charAt(pos);
        if ((c >= '0' && c <= '9') || c == '-' || c == '+') {
          pos++;
        } else if (c == '.' || c == 'e' || c == 'E') {
          isFloat = true;
          pos++;
        } else {
          break;
        }
      }
      String raw = src.substring(start, pos);
      if (isFloat) {
        return Double.parseDouble(raw);
      }
      return Long.parseLong(raw);
    }
  }

  private static final class PeerDriver implements AutoCloseable {
    private final Process proc;
    private final BufferedWriter stdin;
    private final BufferedReader stdout;

    PeerDriver(Path binary) throws IOException {
      ProcessBuilder pb = new ProcessBuilder(binary.toString());
      pb.redirectError(ProcessBuilder.Redirect.INHERIT);
      this.proc = pb.start();
      this.stdin = new BufferedWriter(new OutputStreamWriter(proc.getOutputStream(), StandardCharsets.UTF_8));
      this.stdout = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8));
    }

    void send(Map<String, Object> msg) throws IOException {
      stdin.write(Json.stringify(msg));
      stdin.write('\n');
      stdin.flush();
    }

    Map<String, Object> recv() throws IOException {
      String line = stdout.readLine();
      check(line != null, "conformance peer EOF");
      return asObj(Json.parse(line));
    }

    Map<String, Object> call(Map<String, Object> msg) throws IOException {
      send(msg);
      Map<String, Object> resp = recv();
      check(Boolean.TRUE.equals(resp.get("ok")), "peer cmd failed: " + msg.get("op") + " -> " + resp);
      return resp;
    }

    @Override
    public void close() {
      proc.destroyForcibly();
    }
  }

  private static Map<String, Object> loadVector(Path root, String name) throws IOException {
    String raw = Files.readString(root.resolve("spec").resolve("vectors").resolve(name));
    return asObj(Json.parse(raw));
  }

  private static void verifyVectors(Path root) throws IOException {
    Map<String, Object> fp = loadVector(root, "fingerprints.json");
    byte[] rawPub = hexDecode(asStr(fp.get("raw_pubkey_hex")));
    byte[] hh = hexDecode(asStr(fp.get("handshake_hash_hex")));
    check(asStr(fp.get("raw_device_id")).equals(TendrilNative.deviceId(rawPub)), "deviceId mismatch");
    check(
        asStr(fp.get("raw_host_fingerprint")).equals(TendrilNative.fingerprintHost(rawPub)),
        "fingerprintHost mismatch");
    check(
        asStr(fp.get("raw_device_fingerprint")).equals(TendrilNative.fingerprintDevice(rawPub)),
        "fingerprintDevice mismatch");
    check(asStr(fp.get("pairing_sas")).equals(TendrilNative.pairingSas(hh)), "pairingSas mismatch");

    Map<String, Object> pm = loadVector(root, "pairing_mac.json");
    byte[] pmHh = hexDecode(asStr(pm.get("handshake_hash_hex")));
    Map<String, Object> r3 = asObj(pm.get("remote_3group"));
    check(
        asStr(r3.get("code_mac_hex"))
            .equals(hexEncode(TendrilNative.computeCodeMac(asStr(r3.get("code")), pmHh))),
        "remote_3group mac mismatch");
    Map<String, Object> l2 = asObj(pm.get("lan_2group"));
    check(
        asStr(l2.get("code_mac_hex"))
            .equals(hexEncode(TendrilNative.computeCodeMac(asStr(l2.get("code")), pmHh))),
        "lan_2group mac mismatch");

    Map<String, Object> rot = loadVector(root, "rotation.json");
    String pSig = b64Url(hexDecode(asStr(rot.get("pinned_signing_pub_hex"))));
    String pStat = b64Url(hexDecode(asStr(rot.get("pinned_static_pub_hex"))));
    List<Object> chain = asArr(rot.get("chain"));
    List<Object> records = new ArrayList<>();
    for (Object item : chain) {
      records.add(asObj(item).get("record"));
    }
    Map<String, Object> lastRec = asObj(records.get(records.size() - 1));
    long finalSeq =
        TendrilNative.verifyRotationChainJson(
            pSig,
            pStat,
            0L,
            Json.stringify(records),
            asStr(lastRec.get("new_static_pub")),
            asStr(lastRec.get("new_signing_pub")));
    check(finalSeq == 2L, "expected rotation seq 2, got " + finalSeq);

    boolean forkRejected = false;
    List<Object> forkRecords = List.of(records.get(0), asObj(rot.get("fork_record")).get("record"));
    try {
      TendrilNative.verifyRotationChainJson(
          pSig,
          pStat,
          0L,
          Json.stringify(forkRecords),
          asStr(lastRec.get("new_static_pub")),
          asStr(lastRec.get("new_signing_pub")));
    } catch (IllegalStateException expected) {
      forkRejected = true;
    }
    check(forkRejected, "fork rotation chain was not rejected");

    Map<String, Object> gv = loadVector(root, "grants.json");
    Map<String, Object> keysMap = new LinkedHashMap<>();
    keysMap.put(asStr(gv.get("root_issuer_id")), b64Url(hexDecode(asStr(gv.get("root_signing_pub_hex")))));
    keysMap.put(asStr(gv.get("delegate_id")), b64Url(hexDecode(asStr(gv.get("delegate_signing_pub_hex")))));
    String keysJson = Json.stringify(keysMap);
    long now = 1795564800L;
    check(
        TendrilNative.verifyGrantJson(
            Json.stringify(gv.get("delegated_valid")),
            keysJson,
            asStr(gv.get("leaf_id")),
            asStr(gv.get("root_issuer_id")),
            "fs.read:/photos/2026/a.jpg",
            now,
            null),
        "delegated_valid was denied");
    check(
        !TendrilNative.verifyGrantJson(
            Json.stringify(gv.get("delegated_widened")),
            keysJson,
            asStr(gv.get("leaf_id")),
            asStr(gv.get("root_issuer_id")),
            "fs.read:/photos/2026/a.jpg",
            now,
            null),
        "delegated_widened was allowed");
  }

  private static void verifyLiveInterop(Path peerBin) throws IOException {
    // Direction 1: Rust conformance peer serves, JNI client connects and exchanges data + rekeys.
    try (PeerDriver peer = new PeerDriver(peerBin)) {
      long cliEp = TendrilNative.endpointNew(null, "jni-client");
      try {
        peer.call(Map.of("op", "init", "host_id", "rust-peer"));
        String epAddr = asStr(peer.call(Map.of("op", "serve_direct")).get("endpoint"));
        String code = asStr(peer.call(Map.of("op", "issue_code", "kind", "lan")).get("code"));

        peer.send(Map.of("op", "pair"));
        String emojiName = "jni-\uD83D\uDE80";
        Map<String, Object> cliPair =
            asObj(Json.parse(TendrilNative.endpointPairInitiate(cliEp, epAddr, null, code, emojiName, "android")));
        Map<String, Object> peerPair = peer.recv();
        check(Boolean.TRUE.equals(peerPair.get("ok")), "peer pair failed");
        check(emojiName.equals(asStr(peerPair.get("name"))), "non-BMP UTF-8 name mismatch: " + peerPair);
        check(asStr(peerPair.get("sas")).equals(asStr(cliPair.get("sas"))), "SAS mismatch dir1");
        String cliDevId = asStr(peerPair.get("device_id"));

        peer.call(Map.of("op", "confirm", "peer_id", cliDevId, "sas", asStr(peerPair.get("sas"))));
        TendrilNative.endpointConfirmPeer(cliEp, "rust-peer", asStr(cliPair.get("sas")));
        Object grantObj =
            peer.call(Map.of("op", "mint", "peer_id", cliDevId, "caps", List.of("fs.read"))).get("grant");

        peer.send(Map.of("op", "connect"));
        long sess = TendrilNative.sessionConnect(cliEp, epAddr, null, "rust-peer", Json.stringify(grantObj));
        try {
          check(Boolean.TRUE.equals(peer.recv().get("ok")), "peer connect failed");
          boolean freedRejected = false;
          try {
            TendrilNative.sessionPeerId(0L);
          } catch (IllegalStateException expected) {
            freedRejected = true;
          }
          check(freedRejected, "sessionPeerId(0L) must throw IllegalStateException");
          check("rust-peer".equals(TendrilNative.sessionPeerId(sess)), "expected rust-peer peerId on JNI client");

          TendrilNative.sessionSendData(sess, "hello-from-jni".getBytes(StandardCharsets.UTF_8));
          Map<String, Object> ev1 = peer.call(Map.of("op", "recv", "timeout_ms", 2000));
          check("hello-from-jni".equals(ev1.get("data_utf8")), "peer recv mismatch: " + ev1);

          check(Boolean.TRUE.equals(peer.call(Map.of("op", "authorize", "cap", "fs.read")).get("allowed")),
              "expected fs.read allowed on peer");
          check(Boolean.FALSE.equals(peer.call(Map.of("op", "authorize", "cap", "shell.exec")).get("allowed")),
              "expected shell.exec denied on peer");

          TendrilNative.sessionRekey(sess);
          Map<String, Object> evRk = peer.call(Map.of("op", "recv", "timeout_ms", 2000));
          check("rekeyed".equals(evRk.get("event")), "expected rekeyed event: " + evRk);
          Map<String, Object> selfRk = asObj(Json.parse(TendrilNative.sessionPollEvent(sess, 2000)));
          check("rekeyed".equals(selfRk.get("event")), "expected local rekeyed event: " + selfRk);

          peer.call(Map.of("op", "send", "data_utf8", "reply-from-rust"));
          Map<String, Object> jniEv = asObj(Json.parse(TendrilNative.sessionPollEvent(sess, 2000)));
          check("data".equals(jniEv.get("event")), "expected data event on JNI: " + jniEv);
          String reply = new String(b64UrlDecode(asStr(jniEv.get("data_b64"))), StandardCharsets.UTF_8);
          check("reply-from-rust".equals(reply), "reply mismatch: " + reply);

          TendrilNative.sessionClose(sess, 1000, "done");
          peer.call(Map.of("op", "revoke", "peer_id", cliDevId));
          peer.call(Map.of("op", "shutdown"));
        } finally {
          TendrilNative.sessionFree(sess);
        }
      } finally {
        TendrilNative.endpointFree(cliEp);
      }
    }

    // Direction 2: JNI endpoint serves, Rust conformance peer pairs/connects, and JNI revokes.
    try (PeerDriver peer2 = new PeerDriver(peerBin)) {
      long hostEp = TendrilNative.endpointNew(null, "jni-host");
      try {
        Map<String, Object> hostInfo = asObj(Json.parse(TendrilNative.endpointInfoJson(hostEp)));
        check("jni-host".equals(hostInfo.get("host_id")), "unexpected host info");
        Map<String, Object> wb = asObj(Json.parse(TendrilNative.endpointPairAccept(hostEp, 0)));
        check("would_block".equals(wb.get("status")), "expected would_block on PairAccept(0)");
        boolean negRejected = false;
        try {
          TendrilNative.endpointPairAccept(hostEp, -1L);
        } catch (IllegalArgumentException expected) {
          negRejected = true;
        }
        check(negRejected, "negative timeout_ms was not rejected");

        String hostAddr = TendrilNative.endpointServeDirect(hostEp, "127.0.0.1:0");
        String code2 = TendrilNative.endpointIssueCode(hostEp, "lan");

        peer2.call(Map.of("op", "init", "host_id", "rust-client"));
        peer2.send(Map.of("op", "pair", "endpoint", hostAddr, "code", code2));
        Map<String, Object> acc = asObj(Json.parse(TendrilNative.endpointPairAccept(hostEp, 5000)));
        Map<String, Object> p2Pair = peer2.recv();
        check(asStr(acc.get("sas")).equals(asStr(p2Pair.get("sas"))), "SAS mismatch dir2");
        String accId = asStr(acc.get("device_id"));

        TendrilNative.endpointConfirmPeer(hostEp, accId, asStr(acc.get("sas")));
        peer2.call(Map.of("op", "confirm", "peer_id", "jni-host", "sas", asStr(acc.get("sas"))));
        String grantJson = TendrilNative.endpointMintGrant(hostEp, accId, Json.stringify(List.of("fs.read")), 3600);

        peer2.send(
            Map.of(
                "op",
                "connect",
                "endpoint",
                hostAddr,
                "target_host_id",
                "jni-host",
                "grant",
                Json.parse(grantJson)));
        long hostSess = TendrilNative.sessionAccept(hostEp, 5000);
        try {
          check(Boolean.TRUE.equals(peer2.recv().get("ok")), "peer2 connect failed");
          check(accId.equals(TendrilNative.sessionPeerId(hostSess)), "expected accId peerId on JNI host");
          check(TendrilNative.sessionAuthorize(hostSess, "fs.read"), "expected fs.read allowed on JNI host");
          check(!TendrilNative.sessionAuthorize(hostSess, "shell.exec"), "expected shell.exec denied on JNI host");
          TendrilNative.endpointRevokePeer(hostEp, accId);
          check(accId.equals(TendrilNative.sessionPeerId(hostSess)), "expected accId peerId after revoke");
          check(!TendrilNative.sessionAuthorize(hostSess, "fs.read"), "expected fs.read denied after revoke");
          TendrilNative.sessionClose(hostSess, 1000, "revoked");
          peer2.call(Map.of("op", "shutdown"));
        } finally {
          TendrilNative.sessionFree(hostSess);
        }
      } finally {
        TendrilNative.endpointFree(hostEp);
      }
    }
  }

  private static void verifyServeP2pLoopback() throws Exception {
    long hostEp = TendrilNative.endpointNew(null, "jni-p2p-host");
    long cliEp = TendrilNative.endpointNew(null, "jni-p2p-cli");
    try {
      String p2pEp = TendrilNative.endpointServeP2p(hostEp, "disabled");
      check(p2pEp.startsWith("iroh://"), "expected iroh:// endpoint, got " + p2pEp);
      String code = TendrilNative.endpointIssueCode(hostEp, "remote");

      final Map<String, Object>[] accepted = new Map[1];
      final Throwable[] acceptErr = new Throwable[1];
      Thread pairThread =
          new Thread(
              () -> {
                try {
                  accepted[0] = asObj(Json.parse(TendrilNative.endpointPairAccept(hostEp, 8000)));
                } catch (Throwable t) {
                  acceptErr[0] = t;
                }
              });
      pairThread.start();

      Map<String, Object> cliPair =
          asObj(
              Json.parse(
                  TendrilNative.endpointPairInitiate(
                      cliEp, p2pEp, "disabled", code, "jni-p2p-dev", "android")));
      pairThread.join(10000);
      check(acceptErr[0] == null && accepted[0] != null, "p2p pair accept failed: " + acceptErr[0]);
      check(asStr(cliPair.get("sas")).equals(asStr(accepted[0].get("sas"))), "p2p SAS mismatch");

      String devId = asStr(accepted[0].get("device_id"));
      TendrilNative.endpointConfirmPeer(hostEp, devId, asStr(cliPair.get("sas")));
      TendrilNative.endpointConfirmPeer(cliEp, "jni-p2p-host", asStr(cliPair.get("sas")));
      String grant =
          TendrilNative.endpointMintGrant(hostEp, devId, Json.stringify(List.of("fs.read")), 3600);

      final long[] hostSessHolder = new long[1];
      final Throwable[] sessErr = new Throwable[1];
      Thread sessThread =
          new Thread(
              () -> {
                try {
                  hostSessHolder[0] = TendrilNative.sessionAccept(hostEp, 8000);
                } catch (Throwable t) {
                  sessErr[0] = t;
                }
              });
      sessThread.start();

      long cliSess =
          TendrilNative.sessionConnect(cliEp, p2pEp, "disabled", "jni-p2p-host", grant);
      try {
        sessThread.join(10000);
        check(
            sessErr[0] == null && hostSessHolder[0] != 0,
            "p2p session accept failed: " + sessErr[0]);
        long hostSess = hostSessHolder[0];
        try {
          TendrilNative.sessionSendData(
              cliSess, "hello-jni-p2p".getBytes(StandardCharsets.UTF_8));
          Map<String, Object> ev =
              asObj(Json.parse(TendrilNative.sessionPollEvent(hostSess, 2000)));
          check("data".equals(ev.get("event")), "expected p2p data event: " + ev);
          String got =
              new String(b64UrlDecode(asStr(ev.get("data_b64"))), StandardCharsets.UTF_8);
          check("hello-jni-p2p".equals(got), "p2p data mismatch: " + got);
          TendrilNative.sessionClose(cliSess, 1000, "done");
        } finally {
          TendrilNative.sessionFree(hostSess);
        }
      } finally {
        TendrilNative.sessionFree(cliSess);
      }
    } finally {
      TendrilNative.endpointFree(cliEp);
      TendrilNative.endpointFree(hostEp);
    }
  }

  private static void verifyJniSecurityHardening() throws Exception {
    // SEC-16: reject interior NUL bytes across JNI strings.
    boolean nulRejected = false;
    try {
      TendrilNative.computeCodeMac("4829-1704\u0000EXTRA", new byte[32]);
    } catch (IllegalArgumentException e) {
      nulRejected = true;
    }
    check(nulRejected, "computeCodeMac must reject interior NUL");

    // SEC-08: endpointNewFromState + export roundtrip creates zero files.
    long memEp = TendrilNative.endpointNewFromState(null, null, "jni-state-host");
    try {
      String idJson = TendrilNative.endpointExportIdentityJson(memEp);
      String rstJson = TendrilNative.endpointExportRosterJson(memEp);
      String infoOrig = TendrilNative.endpointInfoJson(memEp);
      long restored = TendrilNative.endpointNewFromState(idJson, rstJson, null);
      try {
        check(
            infoOrig.equals(TendrilNative.endpointInfoJson(restored)),
            "restored endpoint info mismatch");
      } finally {
        TendrilNative.endpointFree(restored);
      }

      // SEC-37: non-BMP emoji and long (> 512-byte) errors preserve UTF-8 verbatim under -Xcheck:jni.
      String emojiPeer = "peer_\uD83D\uDE00_" + "x".repeat(600);
      String caughtMsg = null;
      try {
        TendrilNative.endpointRevokePeer(memEp, emojiPeer);
      } catch (IllegalStateException e) {
        caughtMsg = e.getMessage();
      }
      check(caughtMsg != null && caughtMsg.contains(emojiPeer), "emoji/long error corrupted: " + caughtMsg);
    } finally {
      TendrilNative.endpointFree(memEp);
    }

    // SEC-17: endpointClose unblocks parked sessionAccept(5000) and sessionPollEvent(5000) does not stall ops.
    long hostEp = TendrilNative.endpointNewFromState(null, null, "jni-sec17-host");
    long cliEp = TendrilNative.endpointNewFromState(null, null, "jni-sec17-cli");
    try {
      String ep = TendrilNative.endpointServeDirect(hostEp, "127.0.0.1:0");
      String code = TendrilNative.endpointIssueCode(hostEp, "lan");
      final String[] acc = new String[1];
      Thread pt =
          new Thread(
              () -> {
                acc[0] = TendrilNative.endpointPairAccept(hostEp, 5000);
              });
      pt.start();
      Map<String, Object> cliPair =
          asObj(Json.parse(TendrilNative.endpointPairInitiate(cliEp, ep, null, code, "j", "android")));
      pt.join(5000);
      String devId = asStr(asObj(Json.parse(acc[0])).get("device_id"));
      TendrilNative.endpointConfirmPeer(hostEp, devId, asStr(cliPair.get("sas")));
      TendrilNative.endpointConfirmPeer(cliEp, "jni-sec17-host", asStr(cliPair.get("sas")));
      String grant =
          TendrilNative.endpointMintGrant(hostEp, devId, Json.stringify(List.of("fs.read")), 3600);

      final long[] hostSessHolder = new long[1];
      Thread st =
          new Thread(
              () -> {
                hostSessHolder[0] = TendrilNative.sessionAccept(hostEp, 5000);
              });
      st.start();
      long cliSess = TendrilNative.sessionConnect(cliEp, ep, null, "jni-sec17-host", grant);
      st.join(5000);
      long hostSess = hostSessHolder[0];
      check(hostSess != 0, "session accept failed");
      String sessRoster = TendrilNative.sessionExportRosterJson(hostSess);
      check(sessRoster.contains(devId), "sessionExportRosterJson missing peer");

      long t0 = System.nanoTime();
      final String[] pollOut = new String[1];
      Thread pollT =
          new Thread(
              () -> {
                pollOut[0] = TendrilNative.sessionPollEvent(hostSess, 5000);
              });
      pollT.start();
      Thread.sleep(60);
      check(TendrilNative.sessionAuthorize(hostSess, "fs.read"), "authorize failed while polling");
      check(devId.equals(TendrilNative.sessionPeerId(hostSess)), "hostSess.peerId while polling");
      check("jni-sec17-host".equals(TendrilNative.sessionPeerId(cliSess)), "cliSess.peerId while polling");
      TendrilNative.sessionSendData(hostSess, "jni-duplex".getBytes(StandardCharsets.UTF_8));
      Map<String, Object> cliEv = asObj(Json.parse(TendrilNative.sessionPollEvent(cliSess, 2000)));
      check("data".equals(cliEv.get("event")), "expected duplex data event: " + cliEv);
      TendrilNative.sessionShutdown(hostSess);
      pollT.join(2000);
      check(pollOut[0].contains("\"eof\""), "expected eof on sessionShutdown: " + pollOut[0]);
      long elapsedMs = (System.nanoTime() - t0) / 1_000_000L;
      check(elapsedMs < 1500, "full-duplex JNI ops stalled: " + elapsedMs + "ms");

      TendrilNative.sessionFree(cliSess);
      TendrilNative.sessionFree(hostSess);

      long closeT0 = System.nanoTime();
      Thread blockedAcc =
          new Thread(
              () -> {
                try {
                  TendrilNative.sessionAccept(hostEp, 5000);
                } catch (IllegalStateException ignored) {
                }
              });
      blockedAcc.start();
      Thread.sleep(60);
      TendrilNative.endpointClose(hostEp);
      blockedAcc.join(2000);
      long closeMs = (System.nanoTime() - closeT0) / 1_000_000L;
      check(closeMs < 1500, "endpointClose stalled: " + closeMs + "ms");
    } finally {
      TendrilNative.endpointFree(cliEp);
      TendrilNative.endpointFree(hostEp);
    }
  }

  private static void verifyM2mEnrollment() throws Exception {
    long hostEp = TendrilNative.endpointNewFromState(null, null, "jni-m2m-host");
    long anchorEp = TendrilNative.endpointNewFromState(null, null, "jni-m2m-anchor");
    long cliEp = TendrilNative.endpointNewFromState(null, null, "jni-m2m-cli");
    long cli2Ep = TendrilNative.endpointNewFromState(null, null, "jni-m2m-cli2");
    final Thread[] activeBg = new Thread[1];
    try {
      Map<String, Object> hostInfo = asObj(Json.parse(TendrilNative.endpointInfoJson(hostEp)));
      Map<String, Object> anchorInfo = asObj(Json.parse(TendrilNative.endpointInfoJson(anchorEp)));
      byte[] hostStatic = b64UrlDecode(asStr(hostInfo.get("static_pub")));
      byte[] hostSigning = b64UrlDecode(asStr(hostInfo.get("signing_pub")));
      byte[] hostSigningHash = b64UrlDecode(asStr(hostInfo.get("signing_pub_hash")));
      byte[] anchorSigning = b64UrlDecode(asStr(anchorInfo.get("signing_pub")));
      check(hostSigning.length == 1984, "expected 1984-byte hybrid signing key");
      check(hostSigningHash.length == 32, "expected 32-byte signing pub hash");
      check(anchorSigning.length == 1984, "expected 1984-byte anchor hybrid signing key");

      TendrilNative.endpointAddTrustAnchor(hostEp, "jni-m2m-anchor", anchorSigning);
      String ep = TendrilNative.endpointServeDirect(hostEp, "127.0.0.1:0");
      String tokJson =
          TendrilNative.endpointMintEnrollmentToken(anchorEp, "jni-m2m-host", null, 900);

      final String[] acc = new String[1];
      Thread pt =
          new Thread(
              () -> {
                acc[0] = TendrilNative.endpointPairAccept(hostEp, 5000);
              });
      activeBg[0] = pt;
      pt.start();
      Map<String, Object> initRes =
          asObj(
              Json.parse(
                  TendrilNative.endpointEnrollInitiate(
                      cliEp,
                      ep,
                      null,
                      "jni-m2m-host",
                      hostStatic,
                      hostSigning,
                      0,
                      tokJson,
                      "jni-worker",
                      "machine")));
      pt.join(5000);
      activeBg[0] = null;
      Map<String, Object> accRes = asObj(Json.parse(acc[0]));
      check("active".equals(initRes.get("status")), "expected active init status: " + initRes);
      check(
          "no_state_dir".equals(initRes.get("routes_reason")),
          "a memory-only enrolment stores no route: " + initRes);
      check("active".equals(accRes.get("status")), "expected active acc status: " + accRes);
      check(
          asStr(initRes.get("device_id")).equals(asStr(accRes.get("device_id"))),
          "device_id mismatch");

      Thread repPt =
          new Thread(
              () -> {
                try {
                  TendrilNative.endpointPairAccept(hostEp, 5000);
                } catch (IllegalStateException ignored) {
                }
              });
      activeBg[0] = repPt;
      repPt.start();
      boolean replayRejected = false;
      try {
        TendrilNative.endpointEnrollInitiate(
            cliEp, ep, null, "jni-m2m-host", hostStatic, hostSigning, 0, tokJson, "r", "machine");
      } catch (IllegalStateException e) {
        replayRejected = e.getMessage() != null && e.getMessage().contains("token_replayed");
      }
      repPt.join(5000);
      activeBg[0] = null;
      check(replayRejected, "replayed M2M token must fail closed with token_replayed");

      String grant =
          TendrilNative.endpointMintGrant(
              hostEp, asStr(initRes.get("device_id")), Json.stringify(List.of("fs.read")), 3600);
      final long[] hostSessHolder = new long[1];
      Thread st =
          new Thread(
              () -> {
                hostSessHolder[0] = TendrilNative.sessionAccept(hostEp, 5000);
              });
      activeBg[0] = st;
      st.start();
      long cliSess = TendrilNative.sessionConnect(cliEp, ep, null, "jni-m2m-host", grant);
      st.join(5000);
      activeBg[0] = null;
      long hostSess = hostSessHolder[0];
      check(hostSess != 0, "post-M2M session accept failed");
      try {
        check(TendrilNative.sessionAuthorize(hostSess, "fs.read"), "post-M2M authorize fs.read");
        check(!TendrilNative.sessionAuthorize(hostSess, "shell.exec"), "post-M2M deny shell.exec");
        check("jni-m2m-host".equals(TendrilNative.sessionPeerId(cliSess)), "M2M cliSess.peerId mismatch");
        check(
            asStr(initRes.get("device_id")).equals(TendrilNative.sessionPeerId(hostSess)),
            "M2M hostSess.peerId mismatch");
      } finally {
        TendrilNative.sessionFree(cliSess);
        TendrilNative.sessionFree(hostSess);
      }

      TendrilNative.endpointRevokeTrustAnchor(hostEp, "jni-m2m-anchor");
      String freshTok =
          TendrilNative.endpointMintEnrollmentToken(anchorEp, "jni-m2m-host", null, 900);
      Thread revPt =
          new Thread(
              () -> {
                try {
                  TendrilNative.endpointPairAccept(hostEp, 5000);
                } catch (IllegalStateException ignored) {
                }
              });
      activeBg[0] = revPt;
      revPt.start();
      boolean soleAnchorDisabled = false;
      try {
        TendrilNative.endpointEnrollInitiate(
            cli2Ep, ep, null, "jni-m2m-host", hostStatic, hostSigning, 0, freshTok, "r2", "machine");
      } catch (IllegalStateException e) {
        soleAnchorDisabled = e.getMessage() != null && e.getMessage().contains("unauthorized");
      }
      revPt.join(5000);
      activeBg[0] = null;
      check(soleAnchorDisabled, "revoking sole anchor must disable M2M (unauthorized)");

      String selfTok =
          TendrilNative.endpointMintEnrollmentToken(hostEp, "jni-m2m-host", null, 900);
      Thread revPt2 =
          new Thread(
              () -> {
                try {
                  TendrilNative.endpointPairAccept(hostEp, 5000);
                } catch (IllegalStateException ignored) {
                }
              });
      activeBg[0] = revPt2;
      revPt2.start();
      boolean revokedRejected = false;
      try {
        TendrilNative.endpointEnrollInitiate(
            cli2Ep, ep, null, "jni-m2m-host", hostStatic, hostSigning, 0, freshTok, "r2", "machine");
      } catch (IllegalStateException e) {
        revokedRejected = e.getMessage() != null && e.getMessage().contains("untrusted_anchor");
      }
      revPt2.join(5000);
      activeBg[0] = null;
      check(revokedRejected, "revoked trust anchor token must fail with untrusted_anchor");

      final String[] selfAcc = new String[1];
      Thread selfPt =
          new Thread(
              () -> {
                selfAcc[0] = TendrilNative.endpointPairAccept(hostEp, 5000);
              });
      activeBg[0] = selfPt;
      selfPt.start();
      Map<String, Object> selfInit =
          asObj(
              Json.parse(
                  TendrilNative.endpointEnrollInitiate(
                      cli2Ep,
                      ep,
                      null,
                      "jni-m2m-host",
                      hostStatic,
                      hostSigningHash,
                      0,
                      selfTok,
                      "jni-worker-2",
                      "machine")));
      selfPt.join(5000);
      activeBg[0] = null;
      check("active".equals(selfInit.get("status")), "self-issued M2M init must succeed");
      check(
          "active".equals(asObj(Json.parse(selfAcc[0])).get("status")),
          "self-issued M2M accept must succeed");
    } finally {
      TendrilNative.endpointClose(hostEp);
      if (activeBg[0] != null) {
        try {
          activeBg[0].join(5000);
        } catch (InterruptedException ignored) {
          Thread.currentThread().interrupt();
        }
      }
      TendrilNative.endpointFree(cli2Ep);
      TendrilNative.endpointFree(cliEp);
      TendrilNative.endpointFree(anchorEp);
      TendrilNative.endpointFree(hostEp);
    }
  }

  private static Path ensureRelayBinary(Path root) throws Exception {
    Path bin = root.resolve("target").resolve("debug").resolve("tendril-relay");
    if (Files.isExecutable(bin)) {
      return bin;
    }
    Process p =
        new ProcessBuilder("cargo", "build", "-p", "tendril-relay", "--bin", "tendril-relay")
            .directory(root.toFile())
            .redirectErrorStream(true)
            .start();
    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    int code = p.waitFor();
    check(code == 0, "failed to build tendril-relay: " + out);
    return bin;
  }

  private static final class RelayProcess implements AutoCloseable {
    final Process proc;
    final String v1Url;
    final String v2Url;

    RelayProcess(Path bin, Map<String, String> extraEnv, String... extraArgs) throws Exception {
      List<String> cmd = new ArrayList<>();
      cmd.add(bin.toString());
      cmd.add("--listen");
      cmd.add("127.0.0.1:0");
      cmd.add("--host");
      cmd.add("127.0.0.1");
      for (String a : extraArgs) {
        cmd.add(a);
      }
      ProcessBuilder pb = new ProcessBuilder(cmd);
      pb.redirectErrorStream(true);
      pb.environment().put("RUST_LOG", "info");
      if (extraEnv != null) {
        pb.environment().putAll(extraEnv);
      }
      this.proc = pb.start();
      BufferedReader br =
          new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8));
      StringBuilder logs = new StringBuilder();
      String found = null;
      long deadline = System.currentTimeMillis() + 10_000L;
      while (System.currentTimeMillis() < deadline) {
        if (!br.ready()) {
          if (!proc.isAlive()) {
            break;
          }
          Thread.sleep(20);
          continue;
        }
        String line = br.readLine();
        if (line == null) {
          break;
        }
        String clean = line.replaceAll("\u001b\\[[0-9;]*m", "");
        logs.append(clean).append('\n');
        int idx = clean.indexOf("ws://127.0.0.1:");
        if (idx >= 0) {
          String rest = clean.substring(idx);
          int end = rest.length();
          for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"') {
              end = i;
              break;
            }
          }
          String cand = rest.substring(0, end);
          if (cand.endsWith("/v1/relay")) {
            found = cand;
            break;
          }
        }
      }
      if (found == null) {
        proc.destroyForcibly();
        throw new AssertionError("tendril-relay startup failed:\n" + logs);
      }
      this.v1Url = found;
      this.v2Url = found.substring(0, found.length() - "/v1/relay".length()) + "/v2/relay";
      Thread drain =
          new Thread(
              () -> {
                try {
                  while (br.readLine() != null) {}
                } catch (IOException ignored) {
                }
              });
      drain.setDaemon(true);
      drain.start();
    }

    @Override
    public void close() {
      proc.destroyForcibly();
      try {
        proc.waitFor();
      } catch (InterruptedException ignored) {
        Thread.currentThread().interrupt();
      }
    }
  }

  private static void verifyConfigureTransportsAndRelayAdmission(Path root) throws Exception {
    long cfgEp = TendrilNative.endpointNew(null, "jni-cfg-ep");
    try {
      TendrilNative.endpointConfigureTransportsJson(cfgEp, "{}");
      String secretSentinel = "jni-secret-sentinel-777";
      boolean unknownRejected = false;
      try {
        TendrilNative.endpointConfigureTransportsJson(
            cfgEp, "{\"relay_auth_secret\":\"" + secretSentinel + "\",\"unknown_field\":true}");
      } catch (IllegalStateException e) {
        unknownRejected = true;
        check(
            e.getMessage() == null || !e.getMessage().contains(secretSentinel),
            "configureTransportsJson leaked secret scalar");
      }
      check(unknownRejected, "unknown_field must be rejected");

      boolean scalarRejected = false;
      try {
        TendrilNative.endpointConfigureTransportsJson(cfgEp, "{\"relay_auth_secret\":98765}");
      } catch (IllegalStateException e) {
        scalarRejected = true;
        check(
            e.getMessage() == null || !e.getMessage().contains("98765"),
            "configureTransportsJson leaked scalar value");
      }
      check(scalarRejected, "scalar type mismatch must be rejected");
    } finally {
      TendrilNative.endpointFree(cfgEp);
    }

    Path relayBin = ensureRelayBinary(root);

    // 1. HMAC-gated relay (/v1/relay and /v2/relay)
    String hmacSecret = "jni-shared-relay-hmac-secret";
    try (RelayProcess relay =
        new RelayProcess(
            relayBin, Map.of("TENDRIL_RELAY_AUTH_SECRET", hmacSecret), "--auth-scope", "all")) {
      long hostEp = TendrilNative.endpointNew(null, "jni-hmac-host");
      long cliEp = TendrilNative.endpointNew(null, "jni-hmac-cli");
      try {
        boolean unauthRejected = false;
        try {
          TendrilNative.endpointServeRelay(hostEp, relay.v1Url, "127.0.0.1");
        } catch (IllegalStateException e) {
          unauthRejected = true;
        }
        check(unauthRejected, "unconfigured serveRelay must fail on HMAC relay");

        TendrilNative.endpointConfigureTransportsJson(
            hostEp, "{\"relay_auth_secret\":\"wrong-secret\"}");
        boolean wrongRejected = false;
        try {
          TendrilNative.endpointServeRelay(hostEp, relay.v1Url, "127.0.0.1");
        } catch (IllegalStateException e) {
          wrongRejected = true;
        }
        check(wrongRejected, "wrong-secret serveRelay must fail on HMAC relay");

        String okCfg = "{\"relay_auth_secret\":\"" + hmacSecret + "\"}";
        TendrilNative.endpointConfigureTransportsJson(hostEp, okCfg);
        String v1Ep = TendrilNative.endpointServeRelay(hostEp, relay.v1Url, "127.0.0.1");
        String code = TendrilNative.endpointIssueCode(hostEp, "remote");

        boolean cliUnauthRejected = false;
        try {
          TendrilNative.endpointPairV2Initiate(cliEp, v1Ep, "127.0.0.1", code, "c", "jni", null);
        } catch (IllegalStateException e) {
          cliUnauthRejected = true;
        }
        check(cliUnauthRejected, "unconfigured client pairV2Initiate must fail on HMAC relay");

        TendrilNative.endpointConfigureTransportsJson(cliEp, okCfg);
        final String[] accJson = new String[1];
        Thread accThread =
            new Thread(() -> accJson[0] = TendrilNative.endpointPairV2Accept(hostEp, 5000));
        accThread.start();
        Map<String, Object> initRes =
            asObj(
                Json.parse(
                    TendrilNative.endpointPairV2Initiate(
                        cliEp, v1Ep, "127.0.0.1", code, "jni-hmac-dev", "jni", null)));
        accThread.join(5000);
        Map<String, Object> accRes = asObj(Json.parse(accJson[0]));
        check(initRes.get("sas").equals(accRes.get("sas")), "HMAC v2 pair SAS mismatch");

        TendrilNative.endpointConfirmPeer(
            hostEp, asStr(accRes.get("device_id")), asStr(accRes.get("sas")));
        TendrilNative.endpointConfirmPeer(cliEp, "jni-hmac-host", asStr(initRes.get("sas")));
        String grantJson =
            TendrilNative.endpointMintGrant(
                hostEp, asStr(accRes.get("device_id")), "[\"fs.read\"]", 300);

        String v2Ep = TendrilNative.endpointServeRelayV2(hostEp, relay.v2Url, "127.0.0.1", null);
        TendrilNative.endpointConfigureTransportsJson(
            cliEp, "{\"relay_auth_secret\":\"wrong-secret\"}");
        boolean wrongV2Rejected = false;
        try {
          TendrilNative.sessionConnectV2(cliEp, v2Ep, "127.0.0.1", "jni-hmac-host", grantJson);
        } catch (IllegalStateException e) {
          wrongV2Rejected = true;
        }
        check(wrongV2Rejected, "wrong-secret sessionConnectV2 must fail on /v2/relay");
        TendrilNative.endpointConfigureTransportsJson(cliEp, okCfg);

        final long[] hostSess = new long[1];
        Thread sAccThread =
            new Thread(() -> hostSess[0] = TendrilNative.sessionAcceptV2(hostEp, 5000));
        sAccThread.start();
        long cliSess =
            TendrilNative.sessionConnectV2(cliEp, v2Ep, "127.0.0.1", "jni-hmac-host", grantJson);
        sAccThread.join(5000);
        try {
          check(
              "jni-hmac-host".equals(TendrilNative.sessionPeerId(cliSess)),
              "HMAC cliSess.peerId mismatch");
          check(
              asStr(accRes.get("device_id")).equals(TendrilNative.sessionPeerId(hostSess[0])),
              "HMAC hostSess.peerId mismatch");
          TendrilNative.sessionSendData(cliSess, "jni-hmac-v2".getBytes(StandardCharsets.UTF_8));
          Map<String, Object> ev =
              asObj(Json.parse(TendrilNative.sessionPollEvent(hostSess[0], 3000)));
          check("data".equals(ev.get("event")), "expected data event on HMAC v2 session");
          String payload =
              new String(b64UrlDecode(asStr(ev.get("data_b64"))), StandardCharsets.UTF_8);
          check("jni-hmac-v2".equals(payload), "unexpected HMAC v2 payload: " + payload);
          TendrilNative.sessionClose(cliSess, 1000, "done");
        } finally {
          TendrilNative.sessionFree(cliSess);
          if (hostSess[0] != 0) {
            TendrilNative.sessionFree(hostSess[0]);
          }
        }
      } finally {
        TendrilNative.endpointClose(hostEp);
        TendrilNative.endpointFree(cliEp);
        TendrilNative.endpointFree(hostEp);
      }
    }

    // 2. Ticket-gated relay (/v1/relay and /v2/relay)
    long issuerEp = TendrilNative.endpointNew(null, "jni-ticket-issuer");
    try {
      Map<String, Object> issuerInfo = asObj(Json.parse(TendrilNative.endpointInfoJson(issuerEp)));
      String issuerPub = asStr(issuerInfo.get("relay_pub"));
      String regTicket =
          TendrilNative.endpointMintRelayTicket(issuerEp, "127.0.0.1", "register", "*", 300);
      String dialTicket =
          TendrilNative.endpointMintRelayTicket(issuerEp, "127.0.0.1", "dial", "*", 300);

      try (RelayProcess tRelay =
          new RelayProcess(relayBin, null, "--issuer-pub", issuerPub, "--auth-scope", "all")) {
        long tHost = TendrilNative.endpointNew(null, "jni-ticket-host");
        long tCli = TendrilNative.endpointNew(null, "jni-ticket-cli");
        try {
          TendrilNative.endpointConfigureTransportsJson(tHost, "{\"relay_ticket\":" + dialTicket + "}");
          boolean wrongRoleReg = false;
          try {
            TendrilNative.endpointServeRelay(tHost, tRelay.v1Url, "127.0.0.1");
          } catch (IllegalStateException e) {
            wrongRoleReg = true;
          }
          check(wrongRoleReg, "dial-role ticket must be rejected for serveRelay");

          TendrilNative.endpointConfigureTransportsJson(tHost, "{\"relay_ticket\":" + regTicket + "}");
          String tV1Ep = TendrilNative.endpointServeRelay(tHost, tRelay.v1Url, "127.0.0.1");
          String tCode = TendrilNative.endpointIssueCode(tHost, "remote");

          TendrilNative.endpointConfigureTransportsJson(tCli, "{\"relay_ticket\":" + regTicket + "}");
          boolean wrongRoleDial = false;
          try {
            TendrilNative.endpointPairV2Initiate(
                tCli, tV1Ep, "127.0.0.1", tCode, "tc", "jni", null);
          } catch (IllegalStateException e) {
            wrongRoleDial = true;
          }
          check(wrongRoleDial, "register-role ticket must be rejected for pairV2Initiate");

          TendrilNative.endpointConfigureTransportsJson(tCli, "{\"relay_ticket\":" + dialTicket + "}");
          final String[] tAccJson = new String[1];
          Thread tAccThread =
              new Thread(() -> tAccJson[0] = TendrilNative.endpointPairV2Accept(tHost, 5000));
          tAccThread.start();
          Map<String, Object> tInit =
              asObj(
                  Json.parse(
                      TendrilNative.endpointPairV2Initiate(
                          tCli, tV1Ep, "127.0.0.1", tCode, "tc", "jni", null)));
          tAccThread.join(5000);
          Map<String, Object> tAcc = asObj(Json.parse(tAccJson[0]));
          check(tInit.get("sas").equals(tAcc.get("sas")), "ticket v2 pair SAS mismatch");
          TendrilNative.endpointConfirmPeer(
              tHost, asStr(tAcc.get("device_id")), asStr(tAcc.get("sas")));
          TendrilNative.endpointConfirmPeer(tCli, "jni-ticket-host", asStr(tInit.get("sas")));
          String tGrant =
              TendrilNative.endpointMintGrant(
                  tHost, asStr(tAcc.get("device_id")), "[\"fs.read\"]", 300);

          String tV2Ep = TendrilNative.endpointServeRelayV2(tHost, tRelay.v2Url, "127.0.0.1", null);
          final long[] tHostSess = new long[1];
          Thread tsAcc =
              new Thread(() -> tHostSess[0] = TendrilNative.sessionAcceptV2(tHost, 5000));
          tsAcc.start();
          long tCliSess =
              TendrilNative.sessionConnectV2(tCli, tV2Ep, "127.0.0.1", "jni-ticket-host", tGrant);
          tsAcc.join(5000);
          try {
            check(
                "jni-ticket-host".equals(TendrilNative.sessionPeerId(tCliSess)),
                "ticket cliSess.peerId mismatch");
            check(
                asStr(tAcc.get("device_id")).equals(TendrilNative.sessionPeerId(tHostSess[0])),
                "ticket hostSess.peerId mismatch");
            TendrilNative.sessionSendData(
                tCliSess, "jni-ticket-v2".getBytes(StandardCharsets.UTF_8));
            Map<String, Object> tev =
                asObj(Json.parse(TendrilNative.sessionPollEvent(tHostSess[0], 3000)));
            check("data".equals(tev.get("event")), "expected data event on ticket v2 session");
            String tp =
                new String(b64UrlDecode(asStr(tev.get("data_b64"))), StandardCharsets.UTF_8);
            check("jni-ticket-v2".equals(tp), "unexpected ticket v2 payload: " + tp);
            TendrilNative.sessionClose(tCliSess, 1000, "done");
          } finally {
            TendrilNative.sessionFree(tCliSess);
            if (tHostSess[0] != 0) {
              TendrilNative.sessionFree(tHostSess[0]);
            }
          }
        } finally {
          TendrilNative.endpointClose(tHost);
          TendrilNative.endpointFree(tCli);
          TendrilNative.endpointFree(tHost);
        }
      }
    } finally {
      TendrilNative.endpointFree(issuerEp);
    }
  }

  private static void verifyWireV2ConformancePeer(Path peerBin) throws Exception {
    try (PeerDriver peer = new PeerDriver(peerBin)) {
      long cliEp = TendrilNative.endpointNew(null, "jni-v2-cli");
      try {
        peer.call(Map.of("op", "init", "host_id", "rust-jni-v2"));
        String ep = asStr(peer.call(Map.of("op", "serve_direct")).get("endpoint"));
        String code = asStr(peer.call(Map.of("op", "issue_code", "kind", "lan")).get("code"));

        peer.send(Map.of("op", "pair_v2_accept", "timeout_ms", 5000));
        Map<String, Object> initRes =
            asObj(
                Json.parse(
                    TendrilNative.endpointPairV2Initiate(
                        cliEp, ep, null, code, "jni-v2-dev", "jni", null)));
        Map<String, Object> peerPair = peer.recv();
        check(Boolean.TRUE.equals(peerPair.get("ok")), "peer pair_v2_accept failed");
        check(initRes.get("sas").equals(peerPair.get("sas")), "v2 SAS mismatch");
        String cliDevId = asStr(peerPair.get("device_id"));

        peer.call(Map.of("op", "confirm", "peer_id", cliDevId, "sas", asStr(initRes.get("sas"))));
        Object grantObj =
            peer.call(Map.of("op", "mint", "peer_id", cliDevId, "caps", List.of("fs.read")))
                .get("grant");
        String grantJson = Json.stringify(grantObj);
        TendrilNative.endpointConfirmPeer(cliEp, "rust-jni-v2", asStr(initRes.get("sas")));

        peer.send(Map.of("op", "accept_v2", "timeout_ms", 5000));
        long sess = TendrilNative.sessionConnectV2(cliEp, ep, null, "rust-jni-v2", grantJson);
        try {
          check(Boolean.TRUE.equals(peer.recv().get("ok")), "peer accept_v2 failed");
          check("rust-jni-v2".equals(TendrilNative.sessionPeerId(sess)), "expected rust-jni-v2 peerId on v2 session");
          TendrilNative.sessionSendData(sess, "jni-v2-hello".getBytes(StandardCharsets.UTF_8));
          Map<String, Object> ev = peer.call(Map.of("op", "recv", "timeout_ms", 2000));
          check(
              "data".equals(ev.get("event")) && "jni-v2-hello".equals(ev.get("data_utf8")),
              "unexpected v2 recv: " + ev);
          TendrilNative.sessionRekey(sess);
          peer.call(Map.of("op", "send", "data_utf8", "rust-v2-reply"));
          String got = null;
          for (int i = 0; i < 4; i++) {
            Map<String, Object> jev =
                asObj(Json.parse(TendrilNative.sessionPollEvent(sess, 2000)));
            if ("data".equals(jev.get("event"))) {
              got = new String(b64UrlDecode(asStr(jev.get("data_b64"))), StandardCharsets.UTF_8);
              break;
            }
          }
          check("rust-v2-reply".equals(got), "unexpected rust v2 reply: " + got);
          check(TendrilNative.sessionAuthorize(sess, "fs.read"), "fs.read should be allowed");
          check(!TendrilNative.sessionAuthorize(sess, "shell.exec"), "shell.exec should be denied");

          // SEC-21 regression: exercise sessionSendData large-frame heap path (>4096 bytes)
          // and utf8_to_jstring decoding on pollEvent.
          byte[] largePayload = new byte[8192];
          byte[] marker = "SEC21_LARGE_FRAME_SECRET_".getBytes(StandardCharsets.UTF_8);
          for (int i = 0; i < largePayload.length; i++) {
            largePayload[i] = marker[i % marker.length];
          }
          TendrilNative.sessionSendData(sess, largePayload);
          String largeGot = null;
          for (int i = 0; i < 4; i++) {
            Map<String, Object> largeEv = peer.call(Map.of("op", "recv", "timeout_ms", 2000));
            if ("data".equals(largeEv.get("event"))) {
              largeGot = asStr(largeEv.get("data_utf8"));
              break;
            }
          }
          check(
              new String(largePayload, StandardCharsets.UTF_8).equals(largeGot),
              "unexpected large-frame recv");

          peer.call(Map.of("op", "send", "data_utf8", "SEC21_POLL_SECRET_UTF8"));
          String pollGot = null;
          for (int i = 0; i < 4; i++) {
            Map<String, Object> jev =
                asObj(Json.parse(TendrilNative.sessionPollEvent(sess, 2000)));
            if ("data".equals(jev.get("event"))) {
              pollGot =
                  new String(b64UrlDecode(asStr(jev.get("data_b64"))), StandardCharsets.UTF_8);
              break;
            }
          }
          check("SEC21_POLL_SECRET_UTF8".equals(pollGot), "unexpected poll secret: " + pollGot);

          // SEC-21 regression: exercise endpointNewFromState roster zeroization path.
          String idJson = TendrilNative.endpointExportIdentityJson(cliEp);
          try {
            TendrilNative.endpointNewFromState(idJson, "{\"SEC21_ROSTER_SECRET\":true}", "h");
            throw new AssertionError("expected invalid roster json to fail");
          } catch (IllegalStateException expected) {
            // Expected: c_roster is zeroized before free on return.
          }

          TendrilNative.sessionClose(sess, 1000, "done");
        } finally {
          TendrilNative.sessionFree(sess);
        }
        peer.call(Map.of("op", "shutdown"));
      } finally {
        TendrilNative.endpointFree(cliEp);
      }
    }
  }


  private static String tempStateDir(String prefix) throws IOException {
    Path dir = Files.createTempDirectory(prefix);
    dir.toFile().deleteOnExit();
    return dir.toString();
  }

  private static void groupEnroll(long host, Map<String, Object> hostInfo, String hostAddr, long peer, String peerId)
      throws Exception {
    byte[] hostStatic = b64UrlDecode(asStr(hostInfo.get("static_pub")));
    byte[] hostSigning = b64UrlDecode(asStr(hostInfo.get("signing_pub")));
    String hostId = asStr(hostInfo.get("host_id"));
    String token = TendrilNative.endpointMintEnrollmentToken(host, hostId, peerId, 900);
    final Throwable[] failure = new Throwable[1];
    Thread accept =
        new Thread(
            () -> {
              try {
                TendrilNative.endpointPairAccept(host, 10000);
              } catch (Throwable t) {
                failure[0] = t;
              }
            });
    accept.start();
    Map<String, Object> res =
        asObj(
            Json.parse(
                TendrilNative.endpointEnrollInitiate(
                    peer, hostAddr, null, hostId, hostStatic, hostSigning, 0, token, "peer", "machine")));
    accept.join(10000);
    check(failure[0] == null, "enroll accept failed: " + failure[0]);
    check("active".equals(res.get("status")), "expected active enrollment: " + res);
  }

  private static Map<String, Object> waitGroupEvent(long group, String want) {
    long deadline = System.nanoTime() + 15_000_000_000L;
    while (System.nanoTime() < deadline) {
      String raw = TendrilNative.groupPollEvent(group, 500);
      if (raw == null) {
        continue;
      }
      Map<String, Object> ev = asObj(Json.parse(raw));
      if (want.equals(ev.get("event"))) {
        return ev;
      }
    }
    throw new AssertionError("no " + want + " event in time");
  }

  private static String freeLoopbackAddr() throws Exception {
    try (java.net.ServerSocket probe =
        new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
      return "127.0.0.1:" + probe.getLocalPort();
    }
  }

  private static void verifyGroupMesh() throws Exception {
    long a = TendrilNative.endpointNew(tempStateDir("tendril-jni-ga-"), null);
    long b = TendrilNative.endpointNew(tempStateDir("tendril-jni-gb-"), null);
    long c = TendrilNative.endpointNew(tempStateDir("tendril-jni-gc-"), null);
    long mem = TendrilNative.endpointNewFromState(null, null, null);
    long ga = 0;
    long gb = 0;
    long gc = 0;
    try {
      Map<String, Object> aInfo = asObj(Json.parse(TendrilNative.endpointInfoJson(a)));
      Map<String, Object> bInfo = asObj(Json.parse(TendrilNative.endpointInfoJson(b)));
      Map<String, Object> cInfo = asObj(Json.parse(TendrilNative.endpointInfoJson(c)));
      String aId = asStr(aInfo.get("device_id"));
      String bId = asStr(bInfo.get("device_id"));
      String cId = asStr(cInfo.get("device_id"));
      String aAddr = TendrilNative.endpointServeDirect(a, "127.0.0.1:0");
      String bAddr = freeLoopbackAddr();
      String cAddr = freeLoopbackAddr();
      groupEnroll(a, aInfo, aAddr, b, bId);
      groupEnroll(a, aInfo, aAddr, c, cId);

      String created =
          TendrilNative.groupCreate(a, "jni-mesh", 1, Json.stringify(List.of(aAddr)));
      String gid = asStr(asObj(Json.parse(created)).get("group_id"));
      check(!created.contains("rendezvous_key"), "manifest must not carry the rendezvous key");
      TendrilNative.groupAddMember(a, gid, bId, null, Json.stringify(List.of(bAddr)));
      String manifest =
          TendrilNative.groupAddMember(a, gid, cId, null, Json.stringify(List.of(cAddr)));
      check(gid.equals(TendrilNative.groupIngestManifest(b, manifest, aId)), "ingest b");
      check(gid.equals(TendrilNative.groupIngestManifest(c, manifest, aId)), "ingest c");

      ga = TendrilNative.groupOpen(a, gid, "127.0.0.1:0");
      gb = TendrilNative.groupOpen(b, gid, bAddr);
      gc = TendrilNative.groupOpen(c, gid, cAddr);

      String bound = TendrilNative.groupLocalEndpoint(ga);
      check(bound != null && bound.contains("127.0.0.1:"), "listener endpoint: " + bound);
      check(bAddr.equals(TendrilNative.groupLocalEndpoint(gb)), "member listener endpoint");
      check(TendrilNative.groupPollEvent(gb, 0) == null, "idle poll returns null");
      Map<String, Object> synced = asObj(Json.parse(TendrilNative.groupSync(ga)));
      check(asArr(synced.get("delivered")).size() == 2, "sync reaches both members: " + synced);

      byte[] payload = "hello-jni-group".getBytes(StandardCharsets.UTF_8);
      Map<String, Object> report =
          asObj(Json.parse(TendrilNative.groupBroadcast(ga, null, payload)));
      check(asArr(report.get("delivered")).size() == 2, "expected two deliveries: " + report);
      check(asArr(report.get("failed")).isEmpty(), "unexpected failures: " + report);
      for (long g : new long[] {gb, gc}) {
        Map<String, Object> ev = waitGroupEvent(g, "app_data");
        check(aId.equals(ev.get("sender_device_id")), "sender mismatch: " + ev);
        check(!ev.containsKey("group_id"), "canonical event shape: " + ev);
        check(
            "hello-jni-group"
                .equals(new String(b64UrlDecode(asStr(ev.get("payload_b64"))), StandardCharsets.UTF_8)),
            "payload mismatch: " + ev);
      }

      TendrilNative.groupAuthorizePeer(ga, bId, "group.send:" + gid);
      boolean adminRefused = false;
      try {
        TendrilNative.groupAuthorizePeer(ga, bId, "group.admin:" + gid);
      } catch (IllegalStateException e) {
        adminRefused = true;
      }
      check(adminRefused, "authorizePeer must refuse a missing capability");

      String revoked = TendrilNative.groupRemoveMember(a, gid, cId);
      check(gid.equals(TendrilNative.groupIngestManifest(b, revoked, aId)), "ingest revocation");
      check(cId.equals(waitGroupEvent(gb, "member_revoked").get("device_id")), "revoked device");

      boolean memEndpointRefused = false;
      try {
        TendrilNative.groupIngestManifest(mem, manifest, aId);
      } catch (IllegalStateException e) {
        memEndpointRefused = e.getMessage() != null && e.getMessage().contains("state directory");
      }
      check(memEndpointRefused, "in-memory endpoint must refuse group operations");

      boolean unknownRefused = false;
      try {
        TendrilNative.groupOpen(a, "no-such-group", null);
      } catch (IllegalStateException e) {
        unknownRefused = e.getMessage() != null && e.getMessage().contains("(-2)");
      }
      check(unknownRefused, "unknown group must map to not-found");

      TendrilNative.groupClose(ga);
      TendrilNative.groupClose(ga);
      boolean closedRefused = false;
      try {
        TendrilNative.groupBroadcast(ga, null, payload);
      } catch (IllegalStateException e) {
        closedRefused = e.getMessage() != null && e.getMessage().contains("(-5)");
      }
      check(closedRefused, "broadcast after close must map to closed");
      TendrilNative.groupFree(ga);
      ga = 0;
      TendrilNative.groupFree(0);
      TendrilNative.groupClose(0);
    } finally {
      for (long g : new long[] {ga, gb, gc}) {
        if (g != 0) {
          TendrilNative.groupFree(g);
        }
      }
      for (long ep : new long[] {a, b, c, mem}) {
        TendrilNative.endpointClose(ep);
        TendrilNative.endpointFree(ep);
      }
    }
  }

  private static Map<String, Object> broadcastUntilDelivered(long group, byte[] payload, int want)
      throws Exception {
    long deadline = System.nanoTime() + 15_000_000_000L;
    while (true) {
      Map<String, Object> report =
          asObj(Json.parse(TendrilNative.groupBroadcast(group, null, payload)));
      if (asArr(report.get("delivered")).size() == want || System.nanoTime() > deadline) {
        return report;
      }
      Thread.sleep(200);
    }
  }

  private static void verifySealedGroupState() throws Exception {
    long a = TendrilNative.endpointNew(tempStateDir("tendril-jni-sa-"), null);
    String bDir = tempStateDir("tendril-jni-sb-");
    long b = TendrilNative.endpointNewSealed(bDir, null, null, null);
    long ga = 0;
    long gb = 0;
    try {
      Map<String, Object> aInfo = asObj(Json.parse(TendrilNative.endpointInfoJson(a)));
      String aId = asStr(aInfo.get("device_id"));
      String bId = asStr(asObj(Json.parse(TendrilNative.endpointInfoJson(b))).get("device_id"));
      String bIdentity = TendrilNative.endpointExportIdentityJson(b);
      String aAddr = TendrilNative.endpointServeDirect(a, "127.0.0.1:0");
      String bAddr = freeLoopbackAddr();
      groupEnroll(a, aInfo, aAddr, b, bId);

      String created =
          TendrilNative.groupCreate(a, "jni-sealed", 1, Json.stringify(List.of(aAddr)));
      String gid = asStr(asObj(Json.parse(created)).get("group_id"));
      String manifest =
          TendrilNative.groupAddMember(a, gid, bId, null, Json.stringify(List.of(bAddr)));
      check(gid.equals(TendrilNative.groupIngestManifest(b, manifest, aId)), "sealed ingest");

      ga = TendrilNative.groupOpen(a, gid, null);
      gb = TendrilNative.groupOpen(b, gid, bAddr);
      byte[] first = "sealed-before".getBytes(StandardCharsets.UTF_8);
      Map<String, Object> report = broadcastUntilDelivered(ga, first, 1);
      check(asArr(report.get("delivered")).size() == 1, "sealed delivery: " + report);
      waitGroupEvent(gb, "app_data");
      TendrilNative.groupFree(gb);
      gb = 0;
      TendrilNative.endpointClose(b);
      TendrilNative.endpointFree(b);
      b = 0;

      Path dir = Paths.get(bDir);
      check(Files.isRegularFile(dir.resolve("rt-groups.sealed")), "rt-groups.sealed missing");
      check(Files.isRegularFile(dir.resolve("rt-roster.sealed")), "rt-roster.sealed missing");
      for (String plain : new String[] {"identity.json", "roster.json", "groups.json"}) {
        check(!Files.exists(dir.resolve(plain)), "plaintext state written: " + plain);
      }
      String noIdentityErr = null;
      try {
        TendrilNative.endpointNewSealed(bDir, null, null, null);
      } catch (RuntimeException e) {
        noIdentityErr = e.getMessage();
      }
      check(
          noIdentityErr != null && noIdentityErr.contains("no identity was supplied"),
          "existing sealed state without identity must refuse: " + noIdentityErr);

      b = TendrilNative.endpointNewSealed(bDir, bIdentity, null, null);
      gb = TendrilNative.groupOpen(b, gid, bAddr);
      byte[] second = "sealed-after".getBytes(StandardCharsets.UTF_8);
      report = broadcastUntilDelivered(ga, second, 1);
      check(asArr(report.get("delivered")).size() == 1, "delivery after restart: " + report);
      Map<String, Object> ev = waitGroupEvent(gb, "app_data");
      check(
          "sealed-after"
              .equals(new String(b64UrlDecode(asStr(ev.get("payload_b64"))), StandardCharsets.UTF_8)),
          "payload after restart: " + ev);
    } finally {
      for (long g : new long[] {ga, gb}) {
        if (g != 0) {
          TendrilNative.groupFree(g);
        }
      }
      for (long ep : new long[] {a, b}) {
        if (ep != 0) {
          TendrilNative.endpointClose(ep);
          TendrilNative.endpointFree(ep);
        }
      }
    }
  }

  // ---- Pairing URIs and routes -------------------------------------------------------------

  private static long newEp(String prefix, String hostId) throws IOException {
    return TendrilNative.endpointNew(tempStateDir(prefix), hostId);
  }

  private static String deviceIdOf(long ep) {
    return asStr(asObj(Json.parse(TendrilNative.endpointInfoJson(ep))).get("device_id"));
  }

  private static String hostIdOf(long ep) {
    return asStr(asObj(Json.parse(TendrilNative.endpointInfoJson(ep))).get("host_id"));
  }

  private static Map<String, Object> issue(long host, String optionsJson) {
    return asObj(Json.parse(TendrilNative.endpointIssuePairingUri(host, optionsJson)));
  }

  private static long seqOf(Map<String, Object> m, String key) {
    return ((Number) m.get(key)).longValue();
  }

  /** Pairs [client] with [host] over a scanned URI and confirms on the host; returns the client result. */
  private static Map<String, Object> pairViaUri(long host, long client, String uri, boolean v2)
      throws Exception {
    final String[] hostRes = new String[1];
    final Throwable[] failure = new Throwable[1];
    Thread accept =
        new Thread(
            () -> {
              try {
                hostRes[0] =
                    v2
                        ? TendrilNative.endpointPairV2Accept(host, 15000)
                        : TendrilNative.endpointPairAccept(host, 15000);
              } catch (Throwable t) {
                failure[0] = t;
              }
            });
    accept.start();
    Map<String, Object> res;
    try {
      res =
          asObj(
              Json.parse(
                  v2
                      ? TendrilNative.endpointPairV2Uri(client, uri, "jni-client", "machine", null)
                      : TendrilNative.endpointPairUri(client, uri, "jni-client", "machine", null)));
    } finally {
      accept.join(20000);
    }
    check(failure[0] == null, "host accept failed: " + failure[0]);
    Map<String, Object> hostMap = asObj(Json.parse(hostRes[0]));
    check(asStr(res.get("sas")).equals(asStr(hostMap.get("sas"))), "sas mismatch");
    TendrilNative.endpointConfirmPeer(host, asStr(hostMap.get("device_id")), asStr(hostMap.get("sas")));
    return res;
  }

  /** Runs [connect] on this thread while [host] accepts; returns {client, host} session handles. */
  private static long[] connectAndAccept(
      long host, boolean v2, long acceptMs, java.util.function.LongSupplier connect) throws Exception {
    final long[] hostSess = new long[1];
    final Throwable[] failure = new Throwable[1];
    Thread accept =
        new Thread(
            () -> {
              try {
                hostSess[0] =
                    v2 ? TendrilNative.sessionAcceptV2(host, acceptMs) : TendrilNative.sessionAccept(host, acceptMs);
              } catch (Throwable t) {
                failure[0] = t;
              }
            });
    accept.start();
    long client = 0;
    RuntimeException connectErr = null;
    try {
      client = connect.getAsLong();
    } catch (RuntimeException e) {
      connectErr = e;
    }
    accept.join(acceptMs + 5000);
    if (connectErr != null) {
      if (hostSess[0] != 0) {
        TendrilNative.sessionFree(hostSess[0]);
      }
      throw connectErr;
    }
    check(failure[0] == null && hostSess[0] != 0, "host accept failed: " + failure[0]);
    return new long[] {client, hostSess[0]};
  }

  private static long[] connectStored(long client, long host, String hostId, String grant, boolean v2)
      throws Exception {
    return connectStored(client, host, hostId, grant, v2, 10000);
  }

  private static long[] connectStored(
      long client, long host, String hostId, String grant, boolean v2, long acceptMs) throws Exception {
    return connectAndAccept(
        host,
        v2,
        acceptMs,
        () ->
            v2
                ? TendrilNative.sessionConnectV2(client, null, null, hostId, grant)
                : TendrilNative.sessionConnect(client, "", null, hostId, grant));
  }

  private static void expectData(long sess, String want) {
    long deadline = System.nanoTime() + 10_000_000_000L;
    while (System.nanoTime() < deadline) {
      Map<String, Object> ev = asObj(Json.parse(TendrilNative.sessionPollEvent(sess, 500)));
      if ("data".equals(ev.get("event"))) {
        String got = new String(b64UrlDecode(asStr(ev.get("data_b64"))), StandardCharsets.UTF_8);
        check(want.equals(got), "data mismatch: " + got);
        return;
      }
    }
    throw new AssertionError("no data event");
  }

  private static void roundTrip(long a, long b, String text) {
    TendrilNative.sessionSendData(a, text.getBytes(StandardCharsets.UTF_8));
    expectData(b, text);
  }

  private static List<String> routesOf(long ep, String peerId, String source) {
    Map<String, Object> view = asObj(Json.parse(TendrilNative.endpointPeerRoutes(ep, peerId)));
    List<String> out = new ArrayList<>();
    for (Object r : asArr(view.get("routes"))) {
      Map<String, Object> route = asObj(r);
      if (source.equals(route.get("source"))) {
        out.add(asStr(route.get("hint")));
      }
    }
    java.util.Collections.sort(out);
    return out;
  }

  private static String snapshot(String... networks) {
    return "{\"networks\":[" + String.join(",", networks) + "]}";
  }

  private static String network(String id, String iface, int ifIndex, String transports, String... addrs) {
    List<String> quoted = new ArrayList<>();
    for (String a : addrs) {
      quoted.add("\"" + a + "\"");
    }
    return "{\"id\":\"" + id + "\",\"iface\":\"" + iface + "\",\"if_index\":" + ifIndex
        + ",\"transports\":[" + transports + "],\"addrs\":[" + String.join(",", quoted) + "]}";
  }

  /** Polls the session (route sets never reach its stream) until the client records [seq] as applied. */
  private static void waitRouteSet(long client, long clientSess, String hostId, long seq) {
    long deadline = System.nanoTime() + 15_000_000_000L;
    while (System.nanoTime() < deadline) {
      Map<String, Object> ev = asObj(Json.parse(TendrilNative.sessionPollEvent(clientSess, 250)));
      check("would_block".equals(ev.get("status")), "route sets never reach the event stream: " + ev);
      Map<String, Object> view = asObj(Json.parse(TendrilNative.endpointPeerRoutes(client, hostId)));
      Object last = view.get("last_route_set");
      if (last != null) {
        Map<String, Object> lastMap = asObj(last);
        if ("applied".equals(lastMap.get("outcome")) && seqOf(lastMap, "seq") == seq) {
          return;
        }
      }
    }
    throw new AssertionError("route set " + seq + " not applied");
  }

  private static String recoveryOptions(boolean v2, String grant, String uri, boolean replace) {
    return "{\"wire\":" + (v2 ? 2 : 1) + ",\"grant\":" + grant + ",\"recovery_uri\":"
        + Json.stringify(uri) + (replace ? ",\"replace_routes\":true" : "") + "}";
  }

  private static void verifyPairingUriFlow(boolean v2) throws Exception {
    String label = v2 ? "v2" : "v1";
    long host = newEp("tendril-jni-ph-", "jni-routes-host-" + label);
    long client = newEp("tendril-jni-pc-", null);
    long[] sessions = null;
    try {
      String listen = TendrilNative.endpointServeDirect(host, "127.0.0.1:0");
      Map<String, Object> issued = issue(host, null);
      String uri = asStr(issued.get("uri"));
      check(uri.contains("&rq=") && uri.contains("&rs="), label + " URI is signed: " + uri);
      check(seqOf(issued, "route_seq") >= 1, label + " route_seq");
      check(seqOf(issued, "uri_len") == uri.length(), label + " uri_len");
      check(seqOf(issued, "qr_version_m") >= 1, label + " qr_version_m");
      check(asArr(issued.get("dropped")).isEmpty(), label + " dropped: " + issued.get("dropped"));
      check(new java.net.URI(uri).toString().equals(uri), label + " builder URI is a java.net.URI fixpoint");

      Map<String, Object> res = pairViaUri(host, client, uri, v2);
      check("active".equals(res.get("status")), label + " status: " + res);
      check("verified".equals(res.get("route_check")), label + " route_check: " + res);
      check(Boolean.TRUE.equals(res.get("committed")), label + " committed: " + res);
      String hostId = hostIdOf(host);
      check(hostId.equals(res.get("host_id")), label + " host_id");
      check(routesOf(client, hostId, "signed").equals(List.of("direct:" + listen)), label + " signed routes");
      Map<String, Object> view = asObj(Json.parse(TendrilNative.endpointPeerRoutes(client, hostId)));
      check(seqOf(asObj(view.get("route_meta")), "seq") == seqOf(issued, "route_seq"), label + " route_meta");

      String grant =
          TendrilNative.endpointMintGrant(
              host, deviceIdOf(client), Json.stringify(List.of("fs.read")), 3600);
      sessions = connectStored(client, host, hostId, grant, v2);
      roundTrip(sessions[0], sessions[1], "stored-" + label);
      TendrilNative.sessionFree(sessions[0]);
      TendrilNative.sessionFree(sessions[1]);
      sessions = null;

      // Route setter: atomic, operator-only.
      TendrilNative.endpointSetPeerRoutes(client, hostId, Json.stringify(List.of("127.0.0.1:1", "127.0.0.1:2")));
      TendrilNative.endpointSetPeerRoutes(client, hostId, Json.stringify(List.of("127.0.0.1:3")));
      check(routesOf(client, hostId, "operator").equals(List.of("direct:127.0.0.1:3")), label + " operator");
      boolean rejected = false;
      try {
        TendrilNative.endpointSetPeerRoutes(client, hostId, Json.stringify(List.of("127.0.0.1:4", "host#frag")));
      } catch (IllegalStateException e) {
        rejected = true;
      }
      check(rejected, label + " bad entry rejects the list");
      check(routesOf(client, hostId, "operator").equals(List.of("direct:127.0.0.1:3")), label + " atomic");
      TendrilNative.endpointClearPeerRoutes(client, hostId, null);
      check(routesOf(client, hostId, "operator").isEmpty(), label + " operator cleared");
      check(routesOf(client, hostId, "signed").size() == 1, label + " signed kept");

      // Recovery with an equal rq: the URI's hints are dialed, the stored routes stay untouched.
      TendrilNative.endpointClearPeerRoutes(client, hostId, "signed");
      Map<String, Object> same = issue(host, null);
      String sameOptions = recoveryOptions(v2, grant, asStr(same.get("uri")), false);
      sessions =
          connectAndAccept(
              host, v2, 10000, () -> TendrilNative.sessionConnectWithOptions(client, hostId, sameOptions));
      roundTrip(sessions[0], sessions[1], "recovery-" + label);
      TendrilNative.sessionFree(sessions[0]);
      TendrilNative.sessionFree(sessions[1]);
      sessions = null;
      check(routesOf(client, hostId, "signed").isEmpty(), label + " equal rq leaves routes untouched");

      // Offline apply of a fresh signed URI after the host's set changes.
      TendrilNative.endpointServeDirect(host, "127.0.0.1:0");
      Map<String, Object> fresh = issue(host, null);
      check(seqOf(fresh, "route_seq") == seqOf(same, "route_seq") + 1, label + " set change bumps seq");
      Map<String, Object> applied =
          asObj(Json.parse(TendrilNative.endpointApplyRouteUri(client, asStr(fresh.get("uri")), null)));
      check(Boolean.TRUE.equals(applied.get("applied")), label + " apply: " + applied);
      check(routesOf(client, hostId, "signed").size() == 2, label + " applied routes");

      // With every route cleared, a connect has nothing to dial; a recovery URI approved with
      // replace_routes dials its hints and restores the signed routes.
      TendrilNative.endpointClearPeerRoutes(client, hostId, "all");
      boolean noRoutes = false;
      try {
        connectStored(client, host, hostId, grant, v2, 1500);
      } catch (IllegalStateException e) {
        noRoutes = e.getMessage() != null && e.getMessage().contains("no dialable stored routes");
      }
      check(noRoutes, label + " cleared routes cannot connect");
      String replaceOptions = recoveryOptions(v2, grant, asStr(fresh.get("uri")), true);
      sessions =
          connectAndAccept(
              host, v2, 10000, () -> TendrilNative.sessionConnectWithOptions(client, hostId, replaceOptions));
      roundTrip(sessions[0], sessions[1], "replace-" + label);
      check(routesOf(client, hostId, "signed").size() == 2, label + " recovery replaced routes");

      boolean badOption = false;
      try {
        TendrilNative.sessionConnectWithOptions(client, hostId, "{\"wire\":3}");
      } catch (IllegalStateException e) {
        badOption = true;
      }
      check(badOption, label + " bad options are refused");
    } finally {
      if (sessions != null) {
        TendrilNative.sessionFree(sessions[0]);
        TendrilNative.sessionFree(sessions[1]);
      }
      TendrilNative.endpointClose(host);
      TendrilNative.endpointClose(client);
      TendrilNative.endpointFree(host);
      TendrilNative.endpointFree(client);
    }
  }

  /** Multi-network snapshots through refreshRoutes: seq bumps, retention across NULL, delivery to live sessions. */
  private static void verifyRefreshRoutes() throws Exception {
    long host = newEp("tendril-jni-rh-", "jni-refresh-host");
    long client = newEp("tendril-jni-rc-", null);
    long[] sessions = null;
    try {
      String loopback = TendrilNative.endpointServeDirect(host, "127.0.0.1:0");
      String any = TendrilNative.endpointServeDirect(host, "0.0.0.0:0");
      String port = any.substring(any.lastIndexOf(':') + 1);
      String wifi = network("n1", "wlan0", 3, "\"wifi\"", "10.255.77.20/24");
      String tun = network("n2", "tun0", 4, "\"vpn\"", "100.101.1.2");
      String cell = network("n3", "rmnet0", 5, "\"cellular\"", "100.70.3.4", "203.0.113.7");

      Map<String, Object> first =
          asObj(Json.parse(TendrilNative.endpointRefreshRoutes(host, snapshot(wifi, tun, cell))));
      long seq0 = seqOf(first, "route_seq");
      Map<String, Object> issued = issue(host, null);
      check(seqOf(issued, "route_seq") == seq0, "issuance uses the refreshed set");
      String uri = asStr(issued.get("uri"));
      check(uri.contains("10.255.77.20"), "wifi LAN address advertised: " + uri);
      check(uri.contains("100.101.1.2"), "vpn address advertised: " + uri);
      check(!uri.contains("100.70.3.4") && !uri.contains("203.0.113.7"), "cellular addresses withheld: " + uri);
      check(uri.contains("overlay"), "vpn address is an overlay hint: " + uri);

      Map<String, Object> res = pairViaUri(host, client, uri, false);
      String hostId = hostIdOf(host);
      String grant =
          TendrilNative.endpointMintGrant(
              host, asStr(res.get("device_id")), Json.stringify(List.of("fs.read")), 3600);
      // A client that learned its routes from a URI reports route_seq 0, so the host's current set
      // is the first host-initiated frame of its first session.
      sessions = connectStored(client, host, hostId, grant, false);
      waitRouteSet(client, sessions[0], hostId, seq0);
      TendrilNative.sessionFree(sessions[0]);
      TendrilNative.sessionFree(sessions[1]);
      sessions = connectStored(client, host, hostId, grant, false);

      Map<String, Object> again =
          asObj(Json.parse(TendrilNative.endpointRefreshRoutes(host, snapshot(wifi, tun, cell))));
      check(Boolean.FALSE.equals(again.get("changed")) && seqOf(again, "route_seq") == seq0, "same snapshot: " + again);
      Map<String, Object> timer = asObj(Json.parse(TendrilNative.endpointRefreshRoutes(host, null)));
      check(Boolean.FALSE.equals(timer.get("changed")) && seqOf(timer, "route_seq") == seq0,
          "timer refresh reuses the retained snapshot: " + timer);

      Map<String, Object> noWifi =
          asObj(Json.parse(TendrilNative.endpointRefreshRoutes(host, snapshot(tun, cell))));
      check(Boolean.TRUE.equals(noWifi.get("changed")) && seqOf(noWifi, "route_seq") == seq0 + 1, "wifi lost: " + noWifi);
      waitRouteSet(client, sessions[0], hostId, seq0 + 1);
      List<String> signed = routesOf(client, hostId, "signed");
      check(!signed.contains("direct:10.255.77.20:" + port), "lost LAN route removed: " + signed);
      check(signed.contains("direct:" + loopback), "loopback route kept: " + signed);

      Map<String, Object> empty = asObj(Json.parse(TendrilNative.endpointRefreshRoutes(host, snapshot())));
      check(Boolean.FALSE.equals(empty.get("changed")), "an empty snapshot is debounced: " + empty);

      boolean badSnapshot = false;
      try {
        TendrilNative.endpointRefreshRoutes(host, "{\"networks\":1}");
      } catch (IllegalStateException e) {
        badSnapshot = true;
      }
      check(badSnapshot, "malformed snapshot is refused");
      roundTrip(sessions[1], sessions[0], "still-open");
    } finally {
      if (sessions != null) {
        TendrilNative.sessionFree(sessions[0]);
        TendrilNative.sessionFree(sessions[1]);
      }
      TendrilNative.endpointClose(host);
      TendrilNative.endpointClose(client);
      TendrilNative.endpointFree(host);
      TendrilNative.endpointFree(client);
    }
  }

  /** A sealed host keeps its route sequence across close and reopen; config keys are accepted. */
  private static void verifySealedRouteSeq() throws Exception {
    String dir = tempStateDir("tendril-jni-seq-");
    long first = TendrilNative.endpointNewSealed(dir, null, null, "jni-seq-host");
    String identity = TendrilNative.endpointExportIdentityJson(first);
    TendrilNative.endpointFree(first);
    long seqB;
    long ep = TendrilNative.endpointNewSealed(dir, identity, null, null);
    try {
      TendrilNative.endpointConfigureTransportsJson(
          ep,
          "{\"advertise\":\"explicit\",\"advertised_endpoints\":[\"192.168.40.1:4100\"],"
              + "\"relay_auth_origins\":[\"https://relay.example\"],\"route_policy\":\"all_signed\","
              + "\"sign_routes\":true}");
      long a = seqOf(issue(ep, null), "route_seq");
      TendrilNative.endpointConfigureTransportsJson(
          ep, "{\"advertise\":\"explicit\",\"advertised_endpoints\":[\"192.168.40.1:4101\"]}");
      seqB = seqOf(issue(ep, null), "route_seq");
      check(seqB == a + 1, "changed set bumps the sequence");
    } finally {
      TendrilNative.endpointClose(ep);
      TendrilNative.endpointFree(ep);
    }
    ep = TendrilNative.endpointNewSealed(dir, identity, null, null);
    try {
      TendrilNative.endpointConfigureTransportsJson(
          ep, "{\"advertise\":\"explicit\",\"advertised_endpoints\":[\"192.168.40.1:4101\"]}");
      check(seqOf(issue(ep, null), "route_seq") == seqB, "unchanged set keeps the persisted sequence");
      TendrilNative.endpointConfigureTransportsJson(
          ep, "{\"advertise\":\"explicit\",\"advertised_endpoints\":[\"192.168.40.1:4102\"]}");
      check(seqOf(issue(ep, null), "route_seq") == seqB + 1, "a changed set bumps from the persisted sequence");
    } finally {
      TendrilNative.endpointClose(ep);
      TendrilNative.endpointFree(ep);
    }
  }

  // ---- spec/vectors/routes.json replay ----------------------------------------------------

  private static final java.util.Set<String> ROUTES_COVERED_SECTIONS =
      java.util.Set.of("pairing_route_statement", "pairing_route_check");

  // Sections the Kotlin API cannot reach, with the reason.
  private static final Map<String, String> ROUTES_SKIPPED_SECTIONS =
      Map.of(
          "route_set",
          "verify_route_set is not in the C ABI, so the signed route set vectors cannot be replayed;"
              + " only its host keys pin the vector host here",
          "session_hello_route_seq",
          "SessionHello is built inside the core handshake; no binding exposes the wire JSON.");

  // URIs naming a host key the pinned vector host does not hold: the offline apply path can only
  // report that no paired host matches.
  private static final java.util.Set<String> ROUTES_NO_HOST_MATCH_CASES =
      java.util.Set.of("route_key_rotated", "route_key_rotated_stale_rs", "unchained_key");

  // Case fields the offline apply path does not model. A new field must fail the field check
  // until it is covered or listed here with a reason.
  private static final java.util.Set<String> ROUTES_COVERED_CASE_FIELDS =
      java.util.Set.of("name", "uri", "route_check");
  private static final Map<String, String> ROUTES_HANDSHAKE_ONLY_FIELDS =
      Map.ofEntries(
          Map.entry("pin_ok", "outcome of the host key pin check in the pairing handshake"),
          Map.entry("commit_error", "error raised when the handshake commits the pairing"),
          Map.entry("relay_pub_ok", "rp relay key check, made by the pairing initiator"),
          Map.entry("operator_relay_key_hex", "operator relay key given to the pairing initiator"),
          Map.entry("responder", "which identity answers the handshake in the replay"),
          Map.entry("wires", "wire versions the handshake replay runs on"),
          Map.entry("presented_static_pub_hex", "key material the responder presents"),
          Map.entry("presented_ed25519_pub_hex", "key material the responder presents"),
          Map.entry("presented_signing_pub_sha256_hex", "key material the responder presents"),
          Map.entry("presented_rotation_seq", "rotation chain length the responder presents"));

  private static String queryParam(String uri, String name) {
    String query = uri.substring(uri.indexOf('?') + 1);
    for (String pair : query.split("&")) {
      if (pair.startsWith(name + "=")) {
        return pair.substring(name.length() + 1);
      }
    }
    throw new AssertionError("no " + name + " in " + uri);
  }

  /** A fresh endpoint pinned to the vector host through a hand-written roster.json. */
  private static long vectorClient(Map<String, Object> routeSet, String hostId) throws IOException {
    byte[] staticPub = hexDecode(asStr(routeSet.get("static_pub_hex")));
    List<Object> staticList = new ArrayList<>();
    for (byte b : staticPub) {
      staticList.add(b & 0xff);
    }
    Map<String, Object> entry = new LinkedHashMap<>();
    entry.put("device_id", hostId);
    entry.put("name", "vector-host");
    entry.put("kind", "host");
    entry.put("static_pub", staticList);
    entry.put("signing_pub", b64Url(hexDecode(asStr(routeSet.get("signing_pub_hex")))));
    entry.put("rotation_seq", 0);
    entry.put("state", "active");
    entry.put("min_wire_version", 1);
    Map<String, Object> roster = new LinkedHashMap<>();
    roster.put("entries", Map.of(hostId, entry));
    roster.put("crls", Map.of());
    Path dir = Paths.get(tempStateDir("tendril-jni-rv-"));
    Path file = dir.resolve("roster.json");
    Files.writeString(file, Json.stringify(roster));
    Files.setPosixFilePermissions(file, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
    return TendrilNative.endpointNew(dir.toString(), "jni-routes-vectors");
  }

  private static String applyError(long ep, String uri) {
    try {
      TendrilNative.endpointApplyRouteUri(ep, uri, null);
    } catch (IllegalStateException e) {
      return e.getMessage();
    }
    throw new AssertionError("apply_route_uri accepted " + uri);
  }

  private static void verifyRoutesVectorCoverage(Map<String, Object> vectors) {
    java.util.Set<String> expected = new java.util.TreeSet<>(ROUTES_COVERED_SECTIONS);
    expected.addAll(ROUTES_SKIPPED_SECTIONS.keySet());
    check(
        expected.equals(new java.util.TreeSet<>(vectors.keySet())),
        "routes.json sections must be covered or skipped: " + vectors.keySet());
    for (String reason : ROUTES_SKIPPED_SECTIONS.values()) {
      check(!reason.isEmpty(), "skipped section needs a reason");
    }
    for (String reason : ROUTES_HANDSHAKE_ONLY_FIELDS.values()) {
      check(!reason.isEmpty(), "handshake-only field needs a reason");
    }
    java.util.Set<String> known = new java.util.HashSet<>(ROUTES_COVERED_CASE_FIELDS);
    known.addAll(ROUTES_HANDSHAKE_ONLY_FIELDS.keySet());
    java.util.Set<String> names = new java.util.HashSet<>();
    for (Object c : asArr(asObj(vectors.get("pairing_route_check")).get("cases"))) {
      Map<String, Object> cs = asObj(c);
      names.add(asStr(cs.get("name")));
      check(known.containsAll(cs.keySet()), "unexpected case field in " + cs.get("name") + ": " + cs.keySet());
    }
    check(names.containsAll(ROUTES_NO_HOST_MATCH_CASES), "no-host-match cases must exist: " + names);
  }

  private static void verifyRoutesVectors(Path root) throws Exception {
    Map<String, Object> vectors = loadVector(root, "routes.json");
    verifyRoutesVectorCoverage(vectors);
    Map<String, Object> routeSet = asObj(vectors.get("route_set"));
    String hostId = TendrilNative.deviceId(hexDecode(asStr(routeSet.get("static_pub_hex"))));
    String hostK = b64Url(hexDecode(asStr(routeSet.get("static_pub_hex"))));
    Map<String, Object> stmt = asObj(vectors.get("pairing_route_statement"));
    check(
        b64Url(hexDecode(asStr(routeSet.get("sh_hex")))).equals(queryParam(asStr(stmt.get("uri")), "sh")),
        "statement sh matches the vector host");

    // Statement: every hint applies as a signed route.
    long ep = vectorClient(routeSet, hostId);
    try {
      Map<String, Object> applied =
          asObj(Json.parse(TendrilNative.endpointApplyRouteUri(ep, asStr(stmt.get("uri")), null)));
      check(hostId.equals(applied.get("peer_id")), "applied peer: " + applied);
      check(Boolean.TRUE.equals(applied.get("applied")), "applied: " + applied);
      check(applied.get("reason") == null, "reason: " + applied);
      check(seqOf(applied, "route_seq") == seqOf(stmt, "route_seq"), "route_seq: " + applied);
      List<String> want = new ArrayList<>();
      for (Object h : asArr(stmt.get("hints"))) {
        want.add(asStr(h));
      }
      java.util.Collections.sort(want);
      check(routesOf(ep, hostId, "signed").equals(want), "signed hints: " + routesOf(ep, hostId, "signed"));
    } finally {
      TendrilNative.endpointFree(ep);
    }

    // Statement with a tampered rq does not verify and stores nothing.
    String uri = asStr(stmt.get("uri"));
    String tampered = uri.replace("&rq=7", "&rq=8");
    check(!uri.equals(tampered), "rq=7 present in the statement URI");
    ep = vectorClient(routeSet, hostId);
    try {
      check(applyError(ep, tampered).contains("does not verify"), "tampered rq must not verify");
      check(routesOf(ep, hostId, "signed").isEmpty(), "tampered rq stored routes");
    } finally {
      TendrilNative.endpointFree(ep);
    }

    // Check cases.
    for (Object c : asArr(asObj(vectors.get("pairing_route_check")).get("cases"))) {
      Map<String, Object> cs = asObj(c);
      String name = asStr(cs.get("name"));
      String caseUri = asStr(cs.get("uri"));
      ep = vectorClient(routeSet, hostId);
      try {
        String uriK = queryParam(caseUri, "k");
        if (ROUTES_NO_HOST_MATCH_CASES.contains(name)) {
          check(!uriK.equals(hostK), name + " names another host key");
          check(applyError(ep, caseUri).contains("no paired host matches"), name + " host match");
          continue;
        }
        check(uriK.equals(hostK), name + " names the vector host key");
        String outcome = asStr(cs.get("route_check"));
        if ("verified".equals(outcome)) {
          Map<String, Object> res =
              asObj(Json.parse(TendrilNative.endpointApplyRouteUri(ep, caseUri, null)));
          check(Boolean.TRUE.equals(res.get("applied")), name + " applied: " + res);
          check(!routesOf(ep, hostId, "signed").isEmpty(), name + " stored signed routes");
        } else if ("unsigned".equals(outcome)) {
          check(applyError(ep, caseUri).contains("not host-signed"), name + " unsigned");
        } else {
          check("invalid".equals(outcome), name + " unknown outcome " + outcome);
          check(applyError(ep, caseUri).contains("does not verify"), name + " invalid");
        }
      } finally {
        TendrilNative.endpointFree(ep);
      }
    }
  }

  private static String failureOf(Runnable call) {
    try {
      call.run();
    } catch (IllegalStateException e) {
      return String.valueOf(e.getMessage());
    }
    throw new AssertionError("call did not fail");
  }

  /** relay_host reaches the dialer, routes_reason reports why a pairing wrote no route, unknown peers are NOT_FOUND. */
  private static void verifyRelayHostRoutesReasonAndUnknownPeer() throws Exception {
    long host = newEp("tendril-jni-rr-h-", "jni-rr-host");
    long stateful = newEp("tendril-jni-rr-c-", null);
    try {
      TendrilNative.endpointServeDirect(host, "127.0.0.1:0");
      String signed = asStr(issue(host, null).get("uri"));
      Map<String, Object> res = pairViaUri(host, stateful, signed, false);
      check(res.containsKey("routes_reason") && res.get("routes_reason") == null, "verified pairing routes_reason: " + res);
      String hostId = hostIdOf(host);

      // An unsigned URI persists nothing and says why.
      long unsignedClient = newEp("tendril-jni-rr-u-", null);
      try {
        String plain = asStr(issue(host, "{\"sign_routes\":false}").get("uri"));
        check(!plain.contains("&rs="), "sign_routes=false must not sign: " + plain);
        Map<String, Object> uns = pairViaUri(host, unsignedClient, plain, false);
        check("unsigned".equals(uns.get("route_check")), "unsigned route_check: " + uns);
        check("unsigned_uri".equals(uns.get("routes_reason")), "unsigned routes_reason: " + uns);
      } finally {
        TendrilNative.endpointFree(unsignedClient);
      }

      // relay_host reaches the iroh dialer, whose relay mode parser rejects the value. A dropped
      // key fails later (peer or route errors) and a misspelled one fails as invalid options.
      String grant =
          TendrilNative.endpointMintGrant(host, deviceIdOf(stateful), Json.stringify(List.of("fs.read")), 3600);
      String bad =
          "{\"grant\":" + grant + ",\"endpoint\":\"iroh://peer\",\"relay_host\":\"not-a-relay-mode\"}";
      String msg = failureOf(() -> TendrilNative.sessionConnectWithOptions(stateful, hostId, bad));
      check(msg.contains("invalid p2p relay mode"), "relay_host must reach the dialer: " + msg);
      check(!msg.contains("invalid options_json"), "relay_host must be a known option: " + msg);

      // An unknown peer is NOT_FOUND for the setter and the getter.
      for (String unknown : List.of("dev_unknown")) {
        String set =
            failureOf(() -> TendrilNative.endpointSetPeerRoutes(stateful, unknown, Json.stringify(List.of("127.0.0.1:5"))));
        check(set.contains("(-2)"), "setPeerRoutes unknown peer: " + set);
        String get = failureOf(() -> TendrilNative.endpointPeerRoutes(stateful, unknown));
        check(get.contains("(-2)"), "peerRoutes unknown peer: " + get);
      }
    } finally {
      TendrilNative.endpointFree(host);
      TendrilNative.endpointFree(stateful);
    }
  }

  /** p2p_port_mapping and p2p_bind_addrs reach the listener and are validated. */
  private static void verifyP2pNetOptions() {
    long ep = TendrilNative.endpointNew(null, "jni-p2p-net");
    try {
      TendrilNative.endpointConfigureTransportsJson(
          ep, "{\"p2p_port_mapping\":false,\"p2p_bind_addrs\":[\"127.0.0.1:0\"]}");
      String addr = TendrilNative.endpointServeP2p(ep, "disabled");
      java.util.regex.Matcher m = java.util.regex.Pattern.compile("[?&]addr=([^&]+)").matcher(addr);
      int hints = 0;
      while (m.find()) {
        hints++;
        check(m.group(1).startsWith("127.0.0.1:"), "p2p hint outside the bind address: " + addr);
      }
      check(hints > 0, "p2p endpoint carries address hints: " + addr);
      String v2Addr = TendrilNative.endpointServeP2pV2(ep, "disabled", null);
      check("iroh://v2".equals(v2Addr), "expected iroh://v2 from ServeP2pV2, got: " + v2Addr);
      TendrilNative.endpointConfigureTransportsJson(ep, "{\"p2p_ephemeral\":true,\"p2p_port_mapping\":false}");
      String eph1 = TendrilNative.endpointServeP2p(ep, "disabled");
      String eph2 = TendrilNative.endpointServeP2p(ep, "disabled");
      String id1 = eph1.split("\\?", 2)[0];
      String id2 = eph2.split("\\?", 2)[0];
      check(!id1.equals(id2), "ephemeral serveP2p should rotate EndpointId: " + id1 + " vs " + id2);
    } finally {
      TendrilNative.endpointFree(ep);
    }
    long bad = TendrilNative.endpointNew(null, "jni-p2p-net-bad");
    try {
      for (String addrs : List.of("[\"not-an-addr\"]", "[\"127.0.0.1:0\",\"127.0.0.2:0\"]")) {
        String msg =
            failureOf(
                () -> TendrilNative.endpointConfigureTransportsJson(bad, "{\"p2p_bind_addrs\":" + addrs + "}"));
        check(msg.contains("p2p_bind_addrs"), "bind addrs error names the key: " + msg);
      }
      failureOf(() -> TendrilNative.endpointConfigureTransportsJson(bad, "{\"p2p_port_mapping\":\"no\"}"));
      TendrilNative.endpointConfigureTransportsJson(bad, "{\"p2p_relay_mode\":\"n0\",\"p2p_port_mapping\":true}");
    } finally {
      TendrilNative.endpointFree(bad);
    }
  }

  private static void verifyLowPowerAndExternalMonitor() throws Exception {
    Path dir = Paths.get(tempStateDir("tendril-jni-lowpower-"));
    long host = 0;
    long cli = 0;
    long[] sessions = null;
    try {
      host =
          TendrilNative.endpointNewSealedWithOptions(
              dir.resolve("host").toString(),
              null,
              null,
              "jni-lp-host",
              "{\"power_profile\":\"low_power\"}");
      cli = TendrilNative.endpointNew(null, "jni-lp-cli");
      final long cliHandle = cli;
      TendrilNative.endpointConfigureTransportsJson(
          cliHandle, "{\"power_profile\":\"low_power\"}");
      String listen = TendrilNative.endpointServeDirect(host, "127.0.0.1:0");
      String uri = asStr(issue(host, null).get("uri"));
      Map<String, Object> paired = pairViaUri(host, cliHandle, uri, true);
      String hostId = hostIdOf(host);
      String grant =
          TendrilNative.endpointMintGrant(
              host, asStr(paired.get("device_id")), Json.stringify(List.of("fs.read")), 3600);

      String idleZeroErr =
          failureOf(
              () ->
                  TendrilNative.sessionConnectWithOptions(
                      cliHandle, hostId, "{\"wire\":2,\"idle_timeout_ms\":0}"));
      check(idleZeroErr.contains("idle_timeout_ms"), "expected idle_timeout_ms error: " + idleZeroErr);

      TendrilNative.endpointSetExternalPathMonitor(host, true);
      TendrilNative.endpointRefreshRoutes(host, null);
      TendrilNative.endpointSetExternalPathMonitor(host, false);

      String wakeErr =
          failureOf(
              () ->
                  TendrilNative.endpointConfigureTransportsJson(
                      cliHandle, "{\"wake_retry_max_delay_ms\":2000}"));
      check(wakeErr.contains("wake_url"), "expected wake_url error: " + wakeErr);

      sessions =
          connectAndAccept(
              host,
              true,
              10000,
              () ->
                  TendrilNative.sessionConnectWithOptions(
                      cliHandle,
                      hostId,
                      Json.stringify(
                          Map.of(
                              "wire",
                              2,
                              "grant",
                              Json.parse(grant),
                              "idle_timeout_ms",
                              5000))));
      roundTrip(sessions[0], sessions[1], "jni-low-power-" + listen);
    } finally {
      if (sessions != null) {
        TendrilNative.sessionFree(sessions[0]);
        TendrilNative.sessionFree(sessions[1]);
      }
      if (host != 0) {
        TendrilNative.endpointClose(host);
        long closedHost = host;
        failureOf(() -> TendrilNative.endpointSetExternalPathMonitor(closedHost, true));
        TendrilNative.endpointFree(host);
      }
      if (cli != 0) {
        TendrilNative.endpointClose(cli);
        TendrilNative.endpointFree(cli);
      }
    }
  }

  private static void verifyPairingUriRoutes(Path root) throws Exception {
    verifyPairingUriFlow(false);
    verifyPairingUriFlow(true);
    verifyRefreshRoutes();
    verifySealedRouteSeq();
    verifyRoutesVectors(root);
    verifyRelayHostRoutesReasonAndUnknownPeer();
    verifyP2pNetOptions();
    verifyLowPowerAndExternalMonitor();
  }

  /** A paired host and client; the host knows the client by [clientId] and mints [grant]. */
  private static final class RefusalFixture {
    long host;
    long client;
    String hostId;
    String clientId;
    String grant;
  }

  private static RefusalFixture refusalFixture(boolean v2) throws Exception {
    RefusalFixture f = new RefusalFixture();
    f.host = newEp("tendril-jni-rf-h-", "jni-refusal-host-" + (v2 ? "v2" : "v1"));
    f.client = newEp("tendril-jni-rf-c-", null);
    TendrilNative.endpointServeDirect(f.host, "127.0.0.1:0");
    String uri = asStr(issue(f.host, null).get("uri"));
    pairViaUri(f.host, f.client, uri, v2);
    f.hostId = hostIdOf(f.host);
    f.clientId = deviceIdOf(f.client);
    f.grant =
        TendrilNative.endpointMintGrant(f.host, f.clientId, Json.stringify(List.of("fs.read")), 3600);
    return f;
  }

  private static void closeFixture(RefusalFixture f) {
    TendrilNative.endpointClose(f.host);
    TendrilNative.endpointClose(f.client);
    TendrilNative.endpointFree(f.host);
    TendrilNative.endpointFree(f.client);
  }

  /** The failure of a v2 connect that the host refuses, or null when the connect fails another way. */
  private static TendrilRefusedException refusedV2Connect(RefusalFixture f) throws Exception {
    try {
      long[] s = connectStored(f.client, f.host, f.hostId, f.grant, true, 3000);
      TendrilNative.sessionFree(s[0]);
      TendrilNative.sessionFree(s[1]);
    } catch (TendrilRefusedException e) {
      return e;
    } catch (IllegalStateException e) {
      return null;
    }
    throw new AssertionError("a revoked peer connected");
  }

  private static void verifyRefusal() throws Exception {
    // v2: the refusal arrives at connect as a typed exception.
    RefusalFixture f = refusalFixture(true);
    try {
      TendrilNative.endpointRevokePeer(f.host, f.clientId);
      TendrilRefusedException e = refusedV2Connect(f);
      check(e != null, "v2 revoked connect must throw TendrilRefusedException");
      check(e instanceof IllegalStateException, "refusal stays an IllegalStateException");
      check(e.getReason() == TendrilRefusedException.Reason.REVOKED, "reason: " + e.getReason());
      check(e.getCloseCode() == 4001, "close code: " + e.getCloseCode());
      check("refused_revoked".equals(e.getCode()), "code: " + e.getCode());
      check(String.valueOf(e.getMessage()).contains("revoked"), "message: " + e.getMessage());
      check(
          String.valueOf(e.getMessage()).startsWith("tendril ffi error (-8):"),
          "a refused connect formats -8: " + e.getMessage());
      // The refusal code must not leak into the next failing call on this thread: a different,
      // non-refusal FFI failure is a plain IllegalStateException.
      try {
        TendrilNative.endpointClearRefusalNotice(f.host, "no-such-peer");
        throw new AssertionError("clearing an unknown peer succeeded");
      } catch (TendrilRefusedException leaked) {
        throw new AssertionError("a refusal code leaked into the next failure: " + leaked.getMessage());
      } catch (IllegalStateException plain) {
        check(
            plain.getClass() == IllegalStateException.class,
            "plain failure class: " + plain.getClass());
        check(!String.valueOf(plain.getMessage()).startsWith("tendril ffi error (-8)"), "plain rc");
      }
    } finally {
      closeFixture(f);
    }

    // v1: connect returns first; the closed event carries the refusal and later calls throw it.
    f = refusalFixture(false);
    long clientSess = 0;
    long[] hostSess = new long[1];
    Thread accept = null;
    try {
      TendrilNative.endpointRevokePeer(f.host, f.clientId);
      final long host = f.host;
      accept =
          new Thread(
              () -> {
                try {
                  hostSess[0] = TendrilNative.sessionAccept(host, 3000);
                } catch (RuntimeException ignored) {
                  // the host side of a refused session is not under test
                }
              });
      accept.start();
      clientSess = TendrilNative.sessionConnect(f.client, "", null, f.hostId, f.grant);
      Map<String, Object> closed = null;
      long deadline = System.nanoTime() + 10_000_000_000L;
      while (closed == null && System.nanoTime() < deadline) {
        Map<String, Object> ev = asObj(Json.parse(TendrilNative.sessionPollEvent(clientSess, 500)));
        if ("closed".equals(ev.get("event"))) {
          closed = ev;
        }
      }
      check(closed != null, "v1 refusal produced no closed event");
      check("revoked".equals(closed.get("refusal")), "closed refusal: " + closed);
      check(((Number) closed.get("code")).intValue() == 4001, "closed code: " + closed);
      check(
          "eof".equals(asObj(Json.parse(TendrilNative.sessionPollEvent(clientSess, 500))).get("status")),
          "closed is followed by eof");
      try {
        TendrilNative.sessionSendData(clientSess, new byte[] {'x'});
        throw new AssertionError("sendData after a refusal succeeded");
      } catch (TendrilRefusedException e) {
        check(e.getReason() == TendrilRefusedException.Reason.REVOKED, "sendData reason");
        check(e.getCloseCode() == 4001, "sendData close code");
      }
      try {
        TendrilNative.sessionRekey(clientSess);
        throw new AssertionError("rekey after a refusal succeeded");
      } catch (TendrilRefusedException e) {
        check("refused_revoked".equals(e.getCode()), "rekey code: " + e.getCode());
      }
      try {
        TendrilNative.sessionClose(clientSess, 1000, "");
        throw new AssertionError("close after a refusal succeeded");
      } catch (TendrilRefusedException e) {
        check(e.getCloseCode() == 4001, "close close code");
      }
    } finally {
      if (clientSess != 0) {
        TendrilNative.sessionShutdown(clientSess);
      }
      if (accept != null) {
        accept.join(8000);
      }
      if (clientSess != 0) {
        TendrilNative.sessionFree(clientSess);
      }
      if (hostSess[0] != 0) {
        TendrilNative.sessionFree(hostSess[0]);
      }
      closeFixture(f);
    }

    // Endpoint calls. Each case uses a fresh host: a host sends one notice per peer in a window.
    f = refusalFixture(true);
    try {
      TendrilNative.endpointRevokePeerWithOptions(f.host, f.clientId, "{\"notify\":false}");
      check(refusedV2Connect(f) == null, "a silent revoke must not refuse");
    } finally {
      closeFixture(f);
    }
    f = refusalFixture(true);
    try {
      TendrilNative.endpointSetRefusalPolicyJson(f.host, "{\"pending\":true,\"revoked_notice_ttl_secs\":0}");
      TendrilNative.endpointRevokePeerWithOptions(f.host, f.clientId, null);
      check(refusedV2Connect(f) == null, "ttl 0 records no notice");
    } finally {
      closeFixture(f);
    }
    f = refusalFixture(true);
    try {
      TendrilNative.endpointRevokePeerWithOptions(f.host, f.clientId, null);
      TendrilNative.endpointClearRefusalNotice(f.host, f.clientId);
      check(refusedV2Connect(f) == null, "a cleared notice must not refuse");
      boolean unknown = false;
      try {
        TendrilNative.endpointClearRefusalNotice(f.host, "no-such-peer");
      } catch (IllegalStateException e) {
        unknown = true;
      }
      check(unknown, "clearing an unknown peer must fail");
    } finally {
      closeFixture(f);
    }
    f = refusalFixture(true);
    try {
      TendrilNative.endpointSetRefusalPolicyJson(f.host, "{\"pending\":true,\"revoked_notice_ttl_secs\":60}");
      TendrilNative.endpointRevokePeerWithOptions(f.host, f.clientId, "{\"notify\":true}");
      check(refusedV2Connect(f) != null, "notify true refuses");
    } finally {
      closeFixture(f);
    }
  }

  public static void main(String[] args) throws Exception {
    Path root = Paths.get("").toAbsolutePath().normalize();
    Path peerBin = root.resolve("target").resolve("debug").resolve("tendril-conformance-peer");
    if (args.length == 1 && args[0].equals("refusal")) {
      verifyRefusal();
      System.out.println("JNI_REFUSAL_OK=true");
      return;
    }
    verifyVectors(root);
    System.out.println("JNI_VECTORS_OK=true");
    verifyLiveInterop(peerBin);
    verifyServeP2pLoopback();
    verifyJniSecurityHardening();
    System.out.println("JNI_LIVE_INTEROP_OK=true");
    verifyM2mEnrollment();
    System.out.println("JNI_M2M_OK=true");
    verifyConfigureTransportsAndRelayAdmission(root);
    verifyWireV2ConformancePeer(peerBin);
    System.out.println("JNI_V2_RELAY_OK=true");
    verifyGroupMesh();
    System.out.println("JNI_GROUP_OK=true");
    verifySealedGroupState();
    System.out.println("JNI_SEALED_GROUP_OK=true");
    verifyPairingUriRoutes(root);
    System.out.println("JNI_PAIRING_URI_ROUTES_OK=true");
    verifyRefusal();
    System.out.println("JNI_REFUSAL_OK=true");
  }
}
