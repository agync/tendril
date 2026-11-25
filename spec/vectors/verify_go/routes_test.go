package verify_go_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/curve25519"
)

const (
	routeSetDomain     = "tendril-route-set-v1\x00"
	routeSetVersion    = 0x01
	routeSetMinBody    = 1 + 32 + 32 + 8 + 8 + 1
	routeSetSigLen     = 64 + mldsa65.SignatureSize
	routeSetMinPayload = routeSetMinBody + routeSetSigLen
	routeSetMaxPayload = 5003
	routeSetMaxRoutes  = 6
	routeSetMaxHintLen = 256
	routeSetMaxSeq     = uint64(1)<<53 - 1
)

func encodeRouteSetBody(staticPub, sh []byte, seq, issuedAt uint64, routes []string) []byte {
	var buf bytes.Buffer
	buf.WriteByte(routeSetVersion)
	buf.Write(staticPub)
	buf.Write(sh)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], seq)
	buf.Write(u64[:])
	binary.BigEndian.PutUint64(u64[:], issuedAt)
	buf.Write(u64[:])
	buf.WriteByte(byte(len(routes)))
	for _, r := range routes {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(r)))
		buf.Write(l[:])
		buf.WriteString(r)
	}
	return buf.Bytes()
}

// decodeRouteSetStructure applies the structural rules of the 0x0C payload that do not depend on
// the full endpoint hint grammar (bounds, version, seq, count, lengths, UTF-8, duplicates, `#`,
// IPC hints, trailing bytes).
func decodeRouteSetStructure(payload []byte) ([]string, error) {
	if len(payload) < routeSetMinPayload || len(payload) > routeSetMaxPayload {
		return nil, fmt.Errorf("payload length %d out of range", len(payload))
	}
	if payload[0] != routeSetVersion {
		return nil, fmt.Errorf("bad version")
	}
	seq := binary.BigEndian.Uint64(payload[65:73])
	if seq == 0 || seq > routeSetMaxSeq {
		return nil, fmt.Errorf("seq out of range")
	}
	count := int(payload[81])
	if count > routeSetMaxRoutes {
		return nil, fmt.Errorf("count %d", count)
	}
	off := routeSetMinBody
	seen := map[string]bool{}
	var routes []string
	for range count {
		if off+2 > len(payload) {
			return nil, fmt.Errorf("truncated hint length")
		}
		l := int(binary.BigEndian.Uint16(payload[off : off+2]))
		off += 2
		if l == 0 || l > routeSetMaxHintLen || off+l > len(payload) {
			return nil, fmt.Errorf("bad hint length %d", l)
		}
		h := payload[off : off+l]
		off += l
		s := string(h)
		if !utf8.Valid(h) || seen[s] || strings.Contains(s, "#") ||
			strings.HasPrefix(s, "local:") || strings.HasPrefix(s, "unix://") {
			return nil, fmt.Errorf("bad hint %q", s)
		}
		seen[s] = true
		routes = append(routes, s)
	}
	if len(payload)-off != routeSetSigLen {
		return nil, fmt.Errorf("signature length %d", len(payload)-off)
	}
	return routes, nil
}

func TestRoutes(t *testing.T) {
	type signCase struct {
		Name           string   `json:"name"`
		Seq            uint64   `json:"seq"`
		IssuedAt       uint64   `json:"issued_at"`
		Routes         []string `json:"routes"`
		BodyHex        string   `json:"body_hex"`
		SignedBytesHex string   `json:"signed_bytes_hex"`
		SigHex         string   `json:"sig_hex"`
	}
	var v struct {
		RouteSet struct {
			DomainHex           string     `json:"domain_hex"`
			StaticScalarHex     string     `json:"static_scalar_hex"`
			StaticPubHex        string     `json:"static_pub_hex"`
			SigningSeedHex      string     `json:"signing_seed_hex"`
			SigningMLDSASeedHex string     `json:"signing_mldsa_seed_hex"`
			SigningPubHex       string     `json:"signing_pub_hex"`
			SHHex               string     `json:"sh_hex"`
			SignDeterministic   []signCase `json:"sign_deterministic"`
			DecodeRejections    []struct {
				Name          string `json:"name"`
				BodyHex       string `json:"body_hex"`
				ZeroFillerLen int    `json:"zero_filler_len"`
			} `json:"decode_rejections"`
		} `json:"route_set"`
		SessionHelloRouteSeq struct {
			RouteSeq uint64 `json:"route_seq"`
			JSON     string `json:"json"`
		} `json:"session_hello_route_seq"`
	}
	loadVector(t, "routes.json", &v)
	rs := v.RouteSet

	if string(mustHex(t, rs.DomainHex)) != routeSetDomain {
		t.Fatalf("route set domain mismatch")
	}
	staticPub, err := curve25519.X25519(mustHex(t, rs.StaticScalarHex), curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(staticPub) != rs.StaticPubHex {
		t.Fatalf("static pub mismatch")
	}
	edKey := ed25519.NewKeyFromSeed(mustHex(t, rs.SigningSeedHex))
	var mldsaSeed [mldsa65.SeedSize]byte
	copy(mldsaSeed[:], mustHex(t, rs.SigningMLDSASeedHex))
	mldsaPK, mldsaSK := mldsa65.NewKeyFromSeed(&mldsaSeed)
	signPub := append([]byte{}, edKey.Public().(ed25519.PublicKey)...)
	signPub = append(signPub, mldsaPK.Bytes()...)
	if hex.EncodeToString(signPub) != rs.SigningPubHex {
		t.Fatalf("hybrid signing pub mismatch")
	}
	sh := sha256.Sum256(signPub)
	if hex.EncodeToString(sh[:]) != rs.SHHex {
		t.Fatalf("sh mismatch")
	}

	if len(rs.SignDeterministic) < 2 {
		t.Fatalf("expected at least two sign cases")
	}
	for _, c := range rs.SignDeterministic {
		body := encodeRouteSetBody(staticPub, sh[:], c.Seq, c.IssuedAt, c.Routes)
		if hex.EncodeToString(body) != c.BodyHex {
			t.Fatalf("%s: body mismatch", c.Name)
		}
		signed := append([]byte(routeSetDomain), body...)
		if len(signed) > 1651 {
			t.Fatalf("%s: signed bytes too long", c.Name)
		}
		if hex.EncodeToString(signed) != c.SignedBytesHex {
			t.Fatalf("%s: signed bytes mismatch", c.Name)
		}
		sig := make([]byte, routeSetSigLen)
		copy(sig, ed25519.Sign(edKey, signed))
		if err := mldsa65.SignTo(mldsaSK, signed, hybridMLDSACtx, false, sig[64:]); err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(sig) != c.SigHex {
			t.Fatalf("%s: deterministic hybrid signature mismatch", c.Name)
		}
		if err := verifyHybridSig(signPub, signed, sig); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		payload := append(append([]byte{}, body...), sig...)
		routes, err := decodeRouteSetStructure(payload)
		if err != nil {
			t.Fatalf("%s: decode: %v", c.Name, err)
		}
		if strings.Join(routes, "\n") != strings.Join(c.Routes, "\n") {
			t.Fatalf("%s: decoded routes mismatch", c.Name)
		}
	}

	if len(rs.DecodeRejections) == 0 {
		t.Fatalf("expected decode rejection cases")
	}
	for _, r := range rs.DecodeRejections {
		payload := append(mustHex(t, r.BodyHex), make([]byte, r.ZeroFillerLen)...)
		if _, err := decodeRouteSetStructure(payload); err == nil {
			t.Fatalf("%s: expected structural rejection", r.Name)
		}
	}

	var hello map[string]json.RawMessage
	if err := json.Unmarshal([]byte(v.SessionHelloRouteSeq.JSON), &hello); err != nil {
		t.Fatal(err)
	}
	if string(hello["route_seq"]) != fmt.Sprint(v.SessionHelloRouteSeq.RouteSeq) {
		t.Fatalf("SessionHello.route_seq mismatch")
	}
}

const pairingRoutesDomain = "tendril-pairing-routes-v1\x00"

func TestPairingRouteStatement(t *testing.T) {
	var v struct {
		RouteSet struct {
			SigningSeedHex string `json:"signing_seed_hex"`
		} `json:"route_set"`
		Statement struct {
			DomainHex        string   `json:"domain_hex"`
			Ed25519PubHex    string   `json:"ed25519_pub_hex"`
			RouteSeq         uint64   `json:"route_seq"`
			Hints            []string `json:"hints"`
			UriBytesBeforeRs string   `json:"uri_bytes_before_rs"`
			RsInputHex       string   `json:"rs_input_hex"`
			RsHex            string   `json:"rs_hex"`
			URI              string   `json:"uri"`
		} `json:"pairing_route_statement"`
	}
	loadVector(t, "routes.json", &v)
	st := v.Statement

	if string(mustHex(t, st.DomainHex)) != pairingRoutesDomain || len(pairingRoutesDomain) != 26 {
		t.Fatalf("pairing routes domain mismatch")
	}
	edKey := ed25519.NewKeyFromSeed(mustHex(t, v.RouteSet.SigningSeedHex))
	edPub := edKey.Public().(ed25519.PublicKey)
	if hex.EncodeToString(edPub) != st.Ed25519PubHex {
		t.Fatalf("ed25519 pub mismatch")
	}

	input := append([]byte(pairingRoutesDomain), st.UriBytesBeforeRs...)
	if hex.EncodeToString(input) != st.RsInputHex {
		t.Fatalf("rs input mismatch")
	}
	sig := ed25519.Sign(edKey, input)
	if hex.EncodeToString(sig) != st.RsHex {
		t.Fatalf("rs signature mismatch")
	}
	if !ed25519.Verify(edPub, input, sig) {
		t.Fatalf("rs does not verify")
	}

	suffix := "&rs=" + base64.RawURLEncoding.EncodeToString(sig)
	if len(suffix) != 90 || st.URI != st.UriBytesBeforeRs+suffix {
		t.Fatalf("uri is not prefix || &rs=<sig>")
	}
	prefix := st.URI[:len(st.URI)-90]
	if !strings.HasSuffix(prefix, fmt.Sprintf("&rq=%d", st.RouteSeq)) {
		t.Fatalf("rq must immediately precede rs")
	}
	query, ok := strings.CutPrefix(prefix, "tendril://pair?")
	if !ok {
		t.Fatalf("missing tendril://pair? prefix")
	}
	var rp, ep string
	for _, pair := range strings.Split(query, "&") {
		k, val, _ := strings.Cut(pair, "=")
		switch k {
		case "rp":
			rp = val
		case "ep":
			ep = val
		}
	}
	if rp != base64.RawURLEncoding.EncodeToString(edPub) {
		t.Fatalf("rp is not the signing key's Ed25519 half")
	}
	var hints []string
	for _, part := range strings.Split(ep, ",") {
		h, err := url.PathUnescape(part)
		if err != nil {
			t.Fatal(err)
		}
		hints = append(hints, h)
	}
	if strings.Join(hints, "\n") != strings.Join(st.Hints, "\n") {
		t.Fatalf("ep hints mismatch")
	}
}

// classifyPairingRoute recomputes spec/pairing-v1.md Section 6.5 steps 2-3 for one presented
// host key: the relay key agreement, then the route statement result.
func classifyPairingRoute(t *testing.T, uri string, edPub, sh, operator []byte) (bool, string) {
	t.Helper()
	query, ok := strings.CutPrefix(uri, "tendril://pair?")
	if !ok {
		t.Fatalf("missing tendril://pair? prefix")
	}
	prefix, sigB64, signed := "", "", false
	if i := strings.LastIndex(uri, "&rs="); i >= 0 && len(uri)-i == 90 {
		prefix, sigB64, signed = uri[:i], uri[i+4:], true
		query = strings.TrimPrefix(prefix, "tendril://pair?")
	}
	var rp, uriSh []byte
	for _, pair := range strings.Split(query, "&") {
		k, val, _ := strings.Cut(pair, "=")
		var err error
		switch k {
		case "rp":
			rp, err = base64.RawURLEncoding.DecodeString(val)
		case "sh":
			uriSh, err = base64.RawURLEncoding.DecodeString(val)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	relayOK := (rp == nil || bytes.Equal(rp, edPub)) &&
		(operator == nil || bytes.Equal(operator, edPub))
	switch {
	case !signed:
		return relayOK, "unsigned"
	case !bytes.Equal(uriSh, sh):
		return relayOK, "route_key_rotated"
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte(pairingRoutesDomain), prefix...)
	if ed25519.Verify(ed25519.PublicKey(edPub), input, sig) {
		return relayOK, "verified"
	}
	return relayOK, "invalid"
}

// uriParam returns the base64url-decoded value of `key` in a pairing URI, or nil.
func uriParam(t *testing.T, uri, key string) []byte {
	t.Helper()
	query, _ := strings.CutPrefix(uri, "tendril://pair?")
	for _, pair := range strings.Split(query, "&") {
		k, val, _ := strings.Cut(pair, "=")
		if k == key {
			b, err := base64.RawURLEncoding.DecodeString(val)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	return nil
}

// TestPairingRouteCheck recomputes steps 2-3 (relay keys, route statement) and the refusal from
// the bytes. Step 1 (the host pin) is checked only for the `uri_key` responder, whose presented
// keys must equal the URI's `k` and `sh`. Go does not verify hybrid rotation chains: for
// `rotated_from_uri_key` and `unrelated_key` it checks that the presented key is not the URI's
// key and takes `pin_ok` from the Rust handshake replay.
func TestPairingRouteCheck(t *testing.T) {
	var v struct {
		RouteSet struct {
			StaticPubHex   string `json:"static_pub_hex"`
			SigningSeedHex string `json:"signing_seed_hex"`
			ShHex          string `json:"sh_hex"`
		} `json:"route_set"`
		Check struct {
			Cases []struct {
				Name                         string   `json:"name"`
				URI                          string   `json:"uri"`
				Responder                    string   `json:"responder"`
				PresentedStaticPubHex        string   `json:"presented_static_pub_hex"`
				PresentedEd25519PubHex       string   `json:"presented_ed25519_pub_hex"`
				PresentedSigningPubSha256Hex string   `json:"presented_signing_pub_sha256_hex"`
				PresentedRotationSeq         uint64   `json:"presented_rotation_seq"`
				OperatorRelayKeyHex          string   `json:"operator_relay_key_hex"`
				PinOk                        bool     `json:"pin_ok"`
				RelayPubOk                   *bool    `json:"relay_pub_ok"`
				RouteCheck                   *string  `json:"route_check"`
				CommitError                  *string  `json:"commit_error"`
				Wires                        []string `json:"wires"`
			} `json:"cases"`
		} `json:"pairing_route_check"`
	}
	loadVector(t, "routes.json", &v)
	edKey := ed25519.NewKeyFromSeed(mustHex(t, v.RouteSet.SigningSeedHex))
	edPub := []byte(edKey.Public().(ed25519.PublicKey))
	sh := mustHex(t, v.RouteSet.ShHex)
	staticPub := mustHex(t, v.RouteSet.StaticPubHex)
	if len(v.Check.Cases) != 9 {
		t.Fatalf("expected 9 pairing route check cases, got %d", len(v.Check.Cases))
	}
	for _, c := range v.Check.Cases {
		if !bytes.Equal(mustHex(t, c.PresentedEd25519PubHex), edPub) ||
			!bytes.Equal(mustHex(t, c.PresentedSigningPubSha256Hex), sh) ||
			!bytes.Equal(mustHex(t, c.PresentedStaticPubHex), staticPub) {
			t.Fatalf("%s: presented key is not the fixed host key", c.Name)
		}
		if strings.Join(c.Wires, ",") != "v1,v2" {
			t.Fatalf("%s: wires %v", c.Name, c.Wires)
		}
		uriIsPresented := bytes.Equal(uriParam(t, c.URI, "k"), staticPub) &&
			bytes.Equal(uriParam(t, c.URI, "sh"), sh)
		switch c.Responder {
		case "uri_key":
			if !uriIsPresented || c.PresentedRotationSeq != 0 || !c.PinOk {
				t.Fatalf("%s: uri_key responder must match the URI pin", c.Name)
			}
		case "rotated_from_uri_key":
			if uriIsPresented || c.PresentedRotationSeq == 0 || !c.PinOk {
				t.Fatalf("%s: rotated responder must present a chain from the URI key", c.Name)
			}
		case "unrelated_key":
			if uriIsPresented || c.PresentedRotationSeq != 0 || c.PinOk {
				t.Fatalf("%s: unrelated key without a chain must fail the pin", c.Name)
			}
		default:
			t.Fatalf("%s: unknown responder %q", c.Name, c.Responder)
		}
		got := ""
		if c.CommitError != nil {
			got = *c.CommitError
		}
		if !c.PinOk {
			if c.RelayPubOk != nil || c.RouteCheck != nil || got != "host_key_unverified" {
				t.Fatalf("%s: a failed pin has no verdict and refuses with host_key_unverified", c.Name)
			}
			continue
		}
		var operator []byte
		if c.OperatorRelayKeyHex != "" {
			operator = mustHex(t, c.OperatorRelayKeyHex)
		}
		relayOK, check := classifyPairingRoute(t, c.URI, edPub, sh, operator)
		if c.RelayPubOk == nil || c.RouteCheck == nil ||
			relayOK != *c.RelayPubOk || check != *c.RouteCheck {
			t.Fatalf("%s: got (%v, %s), want (%v, %v)", c.Name, relayOK, check, c.RelayPubOk, c.RouteCheck)
		}
		var want string
		switch {
		case !relayOK:
			want = "host_key_unverified"
		case check == "invalid":
			want = "invalid_pairing_uri"
		}
		if got != want {
			t.Fatalf("%s: commit_error %q, want %q", c.Name, got, want)
		}
	}
}
