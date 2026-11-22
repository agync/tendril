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
          check(TendrilNative.sessionAuthorize(hostSess, "fs.read"), "expected fs.read allowed on JNI host");
          check(!TendrilNative.sessionAuthorize(hostSess, "shell.exec"), "expected shell.exec denied on JNI host");
          TendrilNative.endpointRevokePeer(hostEp, accId);
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

  public static void main(String[] args) throws Exception {
    Path root = Paths.get("").toAbsolutePath().normalize();
    Path peerBin = root.resolve("target").resolve("debug").resolve("tendril-conformance-peer");
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
  }
}
