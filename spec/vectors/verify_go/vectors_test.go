package verify_go_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/flynn/noise"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
)

func loadVector(t *testing.T, name string, dst any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

func mustB64URL(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode b64url %q: %v", s, err)
	}
	return b
}

func group4First16(s string) string {
	return s[0:4] + " " + s[4:8] + " " + s[8:12] + " " + s[12:16]
}

func goDeviceID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "dev_" + hex.EncodeToString(sum[:8])
}

func goHostFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	enc := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))
	return group4First16(enc)
}

func goDeviceFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return group4First16(strings.ToUpper(hex.EncodeToString(sum[:])))
}

func goPairingSAS(h []byte) string {
	mac := sha256.New()
	mac.Write([]byte("tendril-sas-v1"))
	mac.Write(h)
	sum := mac.Sum(nil)
	enc := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum))
	return group4First16(enc)
}

func decodeFrame(t *testing.T, framed []byte) []byte {
	t.Helper()
	if len(framed) < 2 {
		t.Fatalf("frame too short: %d", len(framed))
	}
	n := int(binary.BigEndian.Uint16(framed[:2]))
	if n > 65519 || len(framed) != 2+n {
		t.Fatalf("frame length mismatch: declared %d, total %d", n, len(framed))
	}
	return framed[2:]
}

func encodeFrame(body []byte) []byte {
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[:2], uint16(len(body)))
	copy(out[2:], body)
	return out
}

func parseStrictUTC(s string) (time.Time, error) {
	if len(s) != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != 'Z' {
		return time.Time{}, fmt.Errorf("timestamp %q must be whole-second YYYY-MM-DDTHH:MM:SSZ", s)
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", s)
	if err != nil {
		return time.Time{}, err
	}
	if parsed.Unix() < 0 {
		return time.Time{}, fmt.Errorf("pre-epoch timestamp %q", s)
	}
	return parsed, nil
}

func TestFingerprints(t *testing.T) {
	var v struct {
		HostStaticScalarHex   string `json:"host_static_scalar_hex"`
		HostStaticPubHex      string `json:"host_static_pub_hex"`
		HostDeviceID          string `json:"host_device_id"`
		HostFingerprint       string `json:"host_fingerprint"`
		DeviceStaticScalarHex string `json:"device_static_scalar_hex"`
		DeviceStaticPubHex    string `json:"device_static_pub_hex"`
		DeviceID              string `json:"device_id"`
		DeviceFingerprint     string `json:"device_fingerprint"`
		RawPubkeyHex          string `json:"raw_pubkey_hex"`
		RawHostFingerprint    string `json:"raw_host_fingerprint"`
		RawDeviceFingerprint  string `json:"raw_device_fingerprint"`
		RawDeviceID           string `json:"raw_device_id"`
		HandshakeHashHex      string `json:"handshake_hash_hex"`
		SASDigestHex          string `json:"sas_digest_hex"`
		PairingSAS            string `json:"pairing_sas"`
	}
	loadVector(t, "fingerprints.json", &v)

	hostPub, err := curve25519.X25519(mustHex(t, v.HostStaticScalarHex), curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(hostPub) != v.HostStaticPubHex {
		t.Fatalf("host pub mismatch")
	}
	if got := goDeviceID(hostPub); got != v.HostDeviceID {
		t.Fatalf("host device_id = %s, want %s", got, v.HostDeviceID)
	}
	if got := goHostFingerprint(hostPub); got != v.HostFingerprint {
		t.Fatalf("host fingerprint = %s, want %s", got, v.HostFingerprint)
	}

	devPub, err := curve25519.X25519(mustHex(t, v.DeviceStaticScalarHex), curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(devPub) != v.DeviceStaticPubHex {
		t.Fatalf("device pub mismatch")
	}
	if got := goDeviceID(devPub); got != v.DeviceID {
		t.Fatalf("device id = %s, want %s", got, v.DeviceID)
	}
	if got := goDeviceFingerprint(devPub); got != v.DeviceFingerprint {
		t.Fatalf("device fingerprint = %s, want %s", got, v.DeviceFingerprint)
	}

	rawPub := mustHex(t, v.RawPubkeyHex)
	if len(hostPub) != 32 || len(devPub) != 32 || len(rawPub) != 32 {
		t.Fatalf("expected 32-byte X25519 keys, got %d/%d/%d", len(hostPub), len(devPub), len(rawPub))
	}
	if got := goHostFingerprint(rawPub); got != v.RawHostFingerprint {
		t.Fatalf("raw host fingerprint = %s, want %s", got, v.RawHostFingerprint)
	}
	if got := goDeviceFingerprint(rawPub); got != v.RawDeviceFingerprint {
		t.Fatalf("raw device fingerprint = %s, want %s", got, v.RawDeviceFingerprint)
	}
	if got := goDeviceID(rawPub); got != v.RawDeviceID {
		t.Fatalf("raw device id = %s, want %s", got, v.RawDeviceID)
	}

	h := mustHex(t, v.HandshakeHashHex)
	d := sha256.New()
	d.Write([]byte("tendril-sas-v1"))
	d.Write(h)
	if got := hex.EncodeToString(d.Sum(nil)); got != v.SASDigestHex {
		t.Fatalf("sas digest mismatch: %s != %s", got, v.SASDigestHex)
	}
	if got := goPairingSAS(h); got != v.PairingSAS {
		t.Fatalf("pairing sas = %s, want %s", got, v.PairingSAS)
	}
}

func TestPairingMAC(t *testing.T) {
	type macCase struct {
		Code           string `json:"code"`
		CodeNormalized string `json:"code_normalized"`
		KDFHex         string `json:"kdf_hex"`
		CodeMACHex     string `json:"code_mac_hex"`
		CodeMACB64URL  string `json:"code_mac_b64url"`
	}
	var v struct {
		HandshakeHashHex string  `json:"handshake_hash_hex"`
		SaltHex          string  `json:"salt_hex"`
		MACLabel         string  `json:"mac_label"`
		Remote3Group     macCase `json:"remote_3group"`
		LAN2Group        macCase `json:"lan_2group"`
	}
	loadVector(t, "pairing_mac.json", &v)

	h := mustHex(t, v.HandshakeHashHex)
	salt := h[:16]
	if hex.EncodeToString(salt) != v.SaltHex {
		t.Fatalf("salt mismatch")
	}

	for _, c := range []macCase{v.Remote3Group, v.LAN2Group} {
		norm := strings.ReplaceAll(strings.ToUpper(c.Code), "-", "")
		if norm != c.CodeNormalized {
			t.Fatalf("normalized = %s, want %s", norm, c.CodeNormalized)
		}
		kdf := argon2.IDKey([]byte(norm), salt, 3, 64*1024, 1, 32)
		if hex.EncodeToString(kdf) != c.KDFHex {
			t.Fatalf("kdf mismatch for %s: got %x want %s", c.Code, kdf, c.KDFHex)
		}
		m := hmac.New(sha256.New, kdf)
		m.Write([]byte(v.MACLabel))
		m.Write(h)
		sum := m.Sum(nil)
		if hex.EncodeToString(sum) != c.CodeMACHex {
			t.Fatalf("code_mac hex mismatch for %s", c.Code)
		}
		if base64.RawURLEncoding.EncodeToString(sum) != c.CodeMACB64URL {
			t.Fatalf("code_mac b64url mismatch for %s", c.Code)
		}
		wrongKDF := argon2.IDKey([]byte("TNDWRONGCODE"), salt, 3, 64*1024, 1, 32)
		wm := hmac.New(sha256.New, wrongKDF)
		wm.Write([]byte(v.MACLabel))
		wm.Write(h)
		if hmac.Equal(wm.Sum(nil), sum) {
			t.Fatalf("wrong pairing code unexpectedly matched MAC for %s", c.Code)
		}
	}
}

func TestRotation(t *testing.T) {
	type rotRecord struct {
		Seq            uint64 `json:"seq"`
		PrevSigningPub string `json:"prev_signing_pub"`
		NewSigningPub  string `json:"new_signing_pub"`
		NewStaticPub   string `json:"new_static_pub"`
		TS             string `json:"ts"`
		Sig            string `json:"sig"`
	}
	type rotStep struct {
		SignedBytesHex string    `json:"signed_bytes_hex"`
		Record         rotRecord `json:"record"`
	}
	var v struct {
		PinnedSigningSeedHex string    `json:"pinned_signing_seed_hex"`
		PinnedSigningPubHex  string    `json:"pinned_signing_pub_hex"`
		Chain                []rotStep `json:"chain"`
		ForkRecord           rotStep   `json:"fork_record"`
	}
	loadVector(t, "rotation.json", &v)

	seed0 := mustHex(t, v.PinnedSigningSeedHex)
	key0 := ed25519.NewKeyFromSeed(seed0)
	if hex.EncodeToString(key0.Public().(ed25519.PublicKey)) != v.PinnedSigningPubHex {
		t.Fatalf("pinned signing pub mismatch")
	}

	verifyStep := func(step rotStep) {
		prevPub := mustB64URL(t, step.Record.PrevSigningPub)
		newSigPub := mustB64URL(t, step.Record.NewSigningPub)
		newStatPub := mustB64URL(t, step.Record.NewStaticPub)
		sig := mustB64URL(t, step.Record.Sig)
		parsedTS, err := parseStrictUTC(step.Record.TS)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		buf.WriteString("tendril-rot-v1\x00")
		var seqB [8]byte
		binary.BigEndian.PutUint64(seqB[:], step.Record.Seq)
		buf.Write(seqB[:])
		buf.Write(prevPub)
		buf.Write(newSigPub)
		buf.Write(newStatPub)
		var tsB [8]byte
		binary.BigEndian.PutUint64(tsB[:], uint64(parsedTS.Unix()))
		buf.Write(tsB[:])

		if hex.EncodeToString(buf.Bytes()) != step.SignedBytesHex {
			t.Fatalf("rotation signed bytes mismatch at seq %d", step.Record.Seq)
		}
		if !ed25519.Verify(ed25519.PublicKey(prevPub), buf.Bytes(), sig) {
			t.Fatalf("rotation signature invalid at seq %d", step.Record.Seq)
		}
	}

	seenSeq := map[uint64]rotRecord{}
	pinnedPubB64 := base64.RawURLEncoding.EncodeToString(key0.Public().(ed25519.PublicKey))
	for i, step := range v.Chain {
		verifyStep(step)
		if i == 0 {
			if step.Record.Seq != 1 || step.Record.PrevSigningPub != pinnedPubB64 {
				t.Fatalf("chain root mismatch at seq %d", step.Record.Seq)
			}
		} else {
			prev := v.Chain[i-1].Record
			if step.Record.Seq != prev.Seq+1 || step.Record.PrevSigningPub != prev.NewSigningPub {
				t.Fatalf("non-contiguous chain at index %d (seq %d -> %d)", i, prev.Seq, step.Record.Seq)
			}
		}
		seenSeq[step.Record.Seq] = step.Record
	}

	verifyStep(v.ForkRecord)
	if prev, ok := seenSeq[v.ForkRecord.Record.Seq]; !ok || prev == v.ForkRecord.Record {
		t.Fatalf("expected distinct conflicting record at seq %d", v.ForkRecord.Record.Seq)
	}
}

func TestGrants(t *testing.T) {
	type grantObj struct {
		V             uint8      `json:"v"`
		Issuer        string     `json:"issuer"`
		Subject       string     `json:"subject"`
		Caps          []string   `json:"caps"`
		NotBefore     string     `json:"not_before"`
		NotAfter      string     `json:"not_after"`
		Nonce         string     `json:"nonce"`
		DelegatedFrom []grantObj `json:"delegated_from,omitempty"`
		Uses          *uint64    `json:"uses,omitempty"`
		Machine       *bool      `json:"machine,omitempty"`
		Sig           string     `json:"sig"`
	}
	type crlObj struct {
		V              uint8    `json:"v"`
		Issuer         string   `json:"issuer"`
		Seq            uint64   `json:"seq"`
		RevokedDevices []string `json:"revoked_devices"`
		RevokedNonces  []string `json:"revoked_nonces"`
		TS             string   `json:"ts"`
		Sig            string   `json:"sig"`
	}
	var v struct {
		RootIssuerID          string   `json:"root_issuer_id"`
		RootSigningPubHex     string   `json:"root_signing_pub_hex"`
		DelegateSigningPubHex string   `json:"delegate_signing_pub_hex"`
		RootUnsortedJSON      string   `json:"root_unsorted_json"`
		RootJCSJSON           string   `json:"root_jcs_json"`
		RootSignedBytesHex    string   `json:"root_signed_bytes_hex"`
		RootGrant             grantObj `json:"root_grant"`
		DelegatedValid        grantObj `json:"delegated_valid"`
		DelegatedWidened      grantObj `json:"delegated_widened"`
		CRLJCSJSON            string   `json:"crl_jcs_json"`
		CRLSignedBytesHex     string   `json:"crl_signed_bytes_hex"`
		RevocationList        crlObj   `json:"revocation_list"`
	}
	loadVector(t, "grants.json", &v)

	if v.RootGrant.Issuer != v.RootIssuerID {
		t.Fatalf("root grant issuer = %s, want %s", v.RootGrant.Issuer, v.RootIssuerID)
	}

	jcsBytes, err := jsoncanonicalizer.Transform([]byte(v.RootUnsortedJSON))
	if err != nil {
		t.Fatal(err)
	}
	if string(jcsBytes) != v.RootJCSJSON {
		t.Fatalf("JCS mismatch:\ngot:  %s\nwant: %s", string(jcsBytes), v.RootJCSJSON)
	}
	signedRoot := append([]byte("tendril-grant-v1\x00"), jcsBytes...)
	if hex.EncodeToString(signedRoot) != v.RootSignedBytesHex {
		t.Fatalf("root signed bytes mismatch")
	}
	rootPub := ed25519.PublicKey(mustHex(t, v.RootSigningPubHex))
	if !ed25519.Verify(rootPub, signedRoot, mustB64URL(t, v.RootGrant.Sig)) {
		t.Fatalf("root grant signature invalid")
	}

	verifyGrant := func(g grantObj, pub ed25519.PublicKey) {
		raw, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		delete(m, "sig")
		unsignedRaw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		jcs, err := jsoncanonicalizer.Transform(unsignedRaw)
		if err != nil {
			t.Fatal(err)
		}
		msg := append([]byte("tendril-grant-v1\x00"), jcs...)
		if !ed25519.Verify(pub, msg, mustB64URL(t, g.Sig)) {
			t.Fatalf("grant signature invalid for nonce %s", g.Nonce)
		}
	}

	delPub := ed25519.PublicKey(mustHex(t, v.DelegateSigningPubHex))
	verifyGrant(v.DelegatedValid, delPub)
	verifyGrant(v.DelegatedWidened, delPub)

	type parsedCap struct {
		ns       string
		verb     string
		resource *string
	}
	validIdent := func(s string) bool {
		if len(s) == 0 || len(s) > 32 {
			return false
		}
		if s[0] < 'a' || s[0] > 'z' {
			return false
		}
		for i := 1; i < len(s); i++ {
			c := s[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
		return true
	}
	parseCap := func(raw string) (parsedCap, error) {
		action, res, hasRes := strings.Cut(raw, ":")
		ns, verb, hasDot := strings.Cut(action, ".")
		if !hasDot || !validIdent(ns) || !validIdent(verb) {
			return parsedCap{}, fmt.Errorf("invalid cap action %q", raw)
		}
		if hasRes {
			if len(res) == 0 {
				return parsedCap{}, fmt.Errorf("empty resource %q", raw)
			}
			for i := 0; i < len(res); i++ {
				if res[i] < 0x21 || res[i] > 0x7E {
					return parsedCap{}, fmt.Errorf("invalid resource byte in %q", raw)
				}
			}
			if idx := strings.IndexByte(res, '*'); idx >= 0 && idx != len(res)-1 {
				return parsedCap{}, fmt.Errorf("non-trailing wildcard in %q", raw)
			}
			return parsedCap{ns: ns, verb: verb, resource: &res}, nil
		}
		return parsedCap{ns: ns, verb: verb}, nil
	}
	capCovers := func(grantedRaw, reqRaw string) bool {
		granted, err := parseCap(grantedRaw)
		if err != nil {
			return false
		}
		req, err := parseCap(reqRaw)
		if err != nil {
			return false
		}
		if granted.ns != req.ns || granted.verb != req.verb {
			return false
		}
		if granted.resource == nil && req.resource == nil {
			return true
		}
		if granted.resource != nil && req.resource != nil {
			gRes := *granted.resource
			rRes := *req.resource
			if strings.HasSuffix(gRes, "*") {
				gPrefix := strings.TrimSuffix(gRes, "*")
				rTarget := strings.TrimSuffix(rRes, "*")
				return strings.HasPrefix(rTarget, gPrefix)
			}
			return !strings.HasSuffix(rRes, "*") && gRes == rRes
		}
		return false
	}
	verifyDelegationSubset := func(child, parent grantObj) error {
		if child.V != 1 || parent.V != 1 {
			return fmt.Errorf("unsupported grant version")
		}
		if child.Issuer != parent.Subject {
			return fmt.Errorf("issuer %s != parent subject %s", child.Issuer, parent.Subject)
		}
		hasMint := false
		for _, pc := range parent.Caps {
			if capCovers(pc, "pair.mint") {
				hasMint = true
				break
			}
		}
		if !hasMint {
			return fmt.Errorf("parent lacks pair.mint")
		}
		childNB, err := parseStrictUTC(child.NotBefore)
		if err != nil {
			return err
		}
		childNA, err := parseStrictUTC(child.NotAfter)
		if err != nil {
			return err
		}
		parentNB, err := parseStrictUTC(parent.NotBefore)
		if err != nil {
			return err
		}
		parentNA, err := parseStrictUTC(parent.NotAfter)
		if err != nil {
			return err
		}
		if childNB.Before(parentNB) || childNA.After(parentNA) || !childNB.Before(childNA) {
			return fmt.Errorf("child validity window exceeds parent")
		}
		for _, cc := range child.Caps {
			if _, err := parseCap(cc); err != nil {
				return err
			}
			covered := false
			for _, pc := range parent.Caps {
				if capCovers(pc, cc) {
					covered = true
					break
				}
			}
			if !covered {
				return fmt.Errorf("capability %s not covered by parent", cc)
			}
		}
		return nil
	}

	if err := verifyDelegationSubset(v.DelegatedValid, v.RootGrant); err != nil {
		t.Fatalf("delegated_valid failed subset check: %v", err)
	}
	if err := verifyDelegationSubset(v.DelegatedWidened, v.RootGrant); err == nil {
		t.Fatalf("delegated_widened unexpectedly passed subset check")
	}
	if _, err := parseStrictUTC("2026-11-20T00:00:00.500Z"); err == nil {
		t.Fatalf("expected fractional-second timestamp to be rejected")
	}
	if _, err := parseStrictUTC(v.RevocationList.TS); err != nil {
		t.Fatalf("CRL ts invalid: %v", err)
	}

	// Verify CRL canonicalization and signature
	crlRaw, err := json.Marshal(v.RevocationList)
	if err != nil {
		t.Fatal(err)
	}
	var crlMap map[string]any
	if err := json.Unmarshal(crlRaw, &crlMap); err != nil {
		t.Fatal(err)
	}
	delete(crlMap, "sig")
	crlUnsignedRaw, err := json.Marshal(crlMap)
	if err != nil {
		t.Fatal(err)
	}
	crlJCS, err := jsoncanonicalizer.Transform(crlUnsignedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if string(crlJCS) != v.CRLJCSJSON {
		t.Fatalf("CRL JCS mismatch:\ngot:  %s\nwant: %s", string(crlJCS), v.CRLJCSJSON)
	}
	crlMsg := append([]byte("tendril-crl-v1\x00"), crlJCS...)
	if hex.EncodeToString(crlMsg) != v.CRLSignedBytesHex {
		t.Fatalf("CRL signed bytes mismatch")
	}
	if !ed25519.Verify(rootPub, crlMsg, mustB64URL(t, v.RevocationList.Sig)) {
		t.Fatalf("CRL signature invalid")
	}
}

func TestHandshake(t *testing.T) {
	var v struct {
		NoisePattern   string `json:"noise_pattern"`
		PairTranscript struct {
			PreambleHex              string `json:"preamble_hex"`
			InitiatorStaticScalarHex string `json:"initiator_static_scalar_hex"`
			InitiatorStaticPubHex    string `json:"initiator_static_pub_hex"`
			InitiatorEphemScalarHex  string `json:"initiator_ephem_scalar_hex"`
			ResponderStaticScalarHex string `json:"responder_static_scalar_hex"`
			ResponderStaticPubHex    string `json:"responder_static_pub_hex"`
			ResponderEphemScalarHex  string `json:"responder_ephem_scalar_hex"`
			HostHelloJSON            string `json:"host_hello_json"`
			Msg1FrameHex             string `json:"msg1_frame_hex"`
			Msg2FrameHex             string `json:"msg2_frame_hex"`
			PostMsg2HandshakeHashHex string `json:"post_msg2_handshake_hash_hex"`
			PairingCode              string `json:"pairing_code"`
			PairingSAS               string `json:"pairing_sas"`
			CodeMACB64URL            string `json:"code_mac_b64url"`
			PairClaimJSON            string `json:"pair_claim_json"`
			Msg3FrameHex             string `json:"msg3_frame_hex"`
			FinalHandshakeHashHex    string `json:"final_handshake_hash_hex"`
			PairResponseJSON         string `json:"pair_response_json"`
			PairResponseFrameHex     string `json:"pair_response_frame_hex"`
		} `json:"pair_transcript"`
		SessionTranscript struct {
			PreambleHex              string `json:"preamble_hex"`
			InitiatorStaticScalarHex string `json:"initiator_static_scalar_hex"`
			InitiatorEphemScalarHex  string `json:"initiator_ephem_scalar_hex"`
			ResponderStaticScalarHex string `json:"responder_static_scalar_hex"`
			ResponderEphemScalarHex  string `json:"responder_ephem_scalar_hex"`
			HostHelloJSON            string `json:"host_hello_json"`
			Msg1FrameHex             string `json:"msg1_frame_hex"`
			Msg2FrameHex             string `json:"msg2_frame_hex"`
			PostMsg2HandshakeHashHex string `json:"post_msg2_handshake_hash_hex"`
			SessionHelloJSON         string `json:"session_hello_json"`
			Msg3FrameHex             string `json:"msg3_frame_hex"`
			FinalHandshakeHashHex    string `json:"final_handshake_hash_hex"`
			DataInnerHex             string `json:"data_inner_hex"`
			DataFrameHex             string `json:"data_frame_hex"`
			RekeyInnerHex            string `json:"rekey_inner_hex"`
			RekeyFrameHex            string `json:"rekey_frame_hex"`
			PostRekeyDataInnerHex    string `json:"post_rekey_data_inner_hex"`
			PostRekeyDataFrameHex    string `json:"post_rekey_data_frame_hex"`
		} `json:"session_transcript"`
	}
	loadVector(t, "handshake.json", &v)

	if v.NoisePattern != "Noise_XX_25519_ChaChaPoly_SHA256" {
		t.Fatalf("unexpected pattern %s", v.NoisePattern)
	}
	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	// 1. Pair transcript
	p := v.PairTranscript
	preamble := mustHex(t, p.PreambleHex)
	initS := noise.DHKey{
		Private: mustHex(t, p.InitiatorStaticScalarHex),
		Public:  mustHex(t, p.InitiatorStaticPubHex),
	}
	respS := noise.DHKey{
		Private: mustHex(t, p.ResponderStaticScalarHex),
		Public:  mustHex(t, p.ResponderStaticPubHex),
	}

	initHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		Prologue:      preamble,
		StaticKeypair: initS,
		Random:        bytes.NewReader(mustHex(t, p.InitiatorEphemScalarHex)),
	})
	if err != nil {
		t.Fatal(err)
	}
	respHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		Prologue:      preamble,
		StaticKeypair: respS,
		Random:        bytes.NewReader(mustHex(t, p.ResponderEphemScalarHex)),
	})
	if err != nil {
		t.Fatal(err)
	}

	msg1, _, _, err := initHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(msg1)) != p.Msg1FrameHex {
		t.Fatalf("pair msg1 mismatch:\ngot:  %x\nwant: %s", encodeFrame(msg1), p.Msg1FrameHex)
	}
	if _, _, _, err := respHS.ReadMessage(nil, decodeFrame(t, mustHex(t, p.Msg1FrameHex))); err != nil {
		t.Fatal(err)
	}

	msg2, _, _, err := respHS.WriteMessage(nil, []byte(p.HostHelloJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(msg2)) != p.Msg2FrameHex {
		t.Fatalf("pair msg2 mismatch:\ngot:  %x\nwant: %s", encodeFrame(msg2), p.Msg2FrameHex)
	}
	pt2, _, _, err := initHS.ReadMessage(nil, decodeFrame(t, mustHex(t, p.Msg2FrameHex)))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt2) != p.HostHelloJSON {
		t.Fatalf("pair msg2 payload mismatch")
	}
	h := initHS.ChannelBinding()
	if hex.EncodeToString(h) != p.PostMsg2HandshakeHashHex {
		t.Fatalf("pair post-msg2 h mismatch: %x != %s", h, p.PostMsg2HandshakeHashHex)
	}
	if got := goPairingSAS(h); got != p.PairingSAS {
		t.Fatalf("pair sas = %s, want %s", got, p.PairingSAS)
	}

	norm := strings.ReplaceAll(strings.ToUpper(p.PairingCode), "-", "")
	k := argon2.IDKey([]byte(norm), h[:16], 3, 64*1024, 1, 32)
	hm := hmac.New(sha256.New, k)
	hm.Write([]byte("tendril-pair-v1"))
	hm.Write(h)
	if base64.RawURLEncoding.EncodeToString(hm.Sum(nil)) != p.CodeMACB64URL {
		t.Fatalf("pair code_mac mismatch")
	}

	msg3, initCS0, initCS1, err := initHS.WriteMessage(nil, []byte(p.PairClaimJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(msg3)) != p.Msg3FrameHex {
		t.Fatalf("pair msg3 mismatch")
	}
	pt3, respCS0, respCS1, err := respHS.ReadMessage(nil, decodeFrame(t, mustHex(t, p.Msg3FrameHex)))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt3) != p.PairClaimJSON {
		t.Fatalf("pair msg3 payload mismatch")
	}
	if hex.EncodeToString(initHS.ChannelBinding()) != p.FinalHandshakeHashHex {
		t.Fatalf("pair final hash mismatch")
	}

	// Responder writes PairResponse on respCS1; initiator decrypts on initCS1
	pairRespCT, err := respCS1.Encrypt(nil, nil, []byte(p.PairResponseJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(pairRespCT)) != p.PairResponseFrameHex {
		t.Fatalf("pair response frame mismatch")
	}
	pairRespPT, err := initCS1.Decrypt(nil, nil, decodeFrame(t, mustHex(t, p.PairResponseFrameHex)))
	if err != nil {
		t.Fatal(err)
	}
	if string(pairRespPT) != p.PairResponseJSON {
		t.Fatalf("pair response plaintext mismatch")
	}
	_ = initCS0
	_ = respCS0

	// 2. Session transcript + REKEY
	s := v.SessionTranscript
	sPre := mustHex(t, s.PreambleHex)
	sInitPub, _ := curve25519.X25519(mustHex(t, s.InitiatorStaticScalarHex), curve25519.Basepoint)
	sRespPub, _ := curve25519.X25519(mustHex(t, s.ResponderStaticScalarHex), curve25519.Basepoint)
	sInitHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		Prologue:      sPre,
		StaticKeypair: noise.DHKey{Private: mustHex(t, s.InitiatorStaticScalarHex), Public: sInitPub},
		Random:        bytes.NewReader(mustHex(t, s.InitiatorEphemScalarHex)),
	})
	if err != nil {
		t.Fatal(err)
	}
	sRespHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		Prologue:      sPre,
		StaticKeypair: noise.DHKey{Private: mustHex(t, s.ResponderStaticScalarHex), Public: sRespPub},
		Random:        bytes.NewReader(mustHex(t, s.ResponderEphemScalarHex)),
	})
	if err != nil {
		t.Fatal(err)
	}

	sm1, _, _, err := sInitHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(sm1)) != s.Msg1FrameHex {
		t.Fatalf("session msg1 mismatch")
	}
	if _, _, _, err := sRespHS.ReadMessage(nil, decodeFrame(t, mustHex(t, s.Msg1FrameHex))); err != nil {
		t.Fatal(err)
	}

	sm2, _, _, err := sRespHS.WriteMessage(nil, []byte(s.HostHelloJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(sm2)) != s.Msg2FrameHex {
		t.Fatalf("session msg2 mismatch")
	}
	if _, _, _, err := sInitHS.ReadMessage(nil, decodeFrame(t, mustHex(t, s.Msg2FrameHex))); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sInitHS.ChannelBinding()) != s.PostMsg2HandshakeHashHex {
		t.Fatalf("session post-msg2 h mismatch")
	}

	sm3, sInitWrite, _, err := sInitHS.WriteMessage(nil, []byte(s.SessionHelloJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(sm3)) != s.Msg3FrameHex {
		t.Fatalf("session msg3 mismatch")
	}
	_, sRespRead, _, err := sRespHS.ReadMessage(nil, decodeFrame(t, mustHex(t, s.Msg3FrameHex)))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sInitHS.ChannelBinding()) != s.FinalHandshakeHashHex {
		t.Fatalf("session final hash mismatch")
	}

	dataCT, err := sInitWrite.Encrypt(nil, nil, mustHex(t, s.DataInnerHex))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(dataCT)) != s.DataFrameHex {
		t.Fatalf("session data frame mismatch")
	}
	dataPT, err := sRespRead.Decrypt(nil, nil, decodeFrame(t, mustHex(t, s.DataFrameHex)))
	if err != nil || hex.EncodeToString(dataPT) != s.DataInnerHex {
		t.Fatalf("session data decrypt mismatch: %v", err)
	}

	rekeyCT, err := sInitWrite.Encrypt(nil, nil, mustHex(t, s.RekeyInnerHex))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(rekeyCT)) != s.RekeyFrameHex {
		t.Fatalf("session rekey frame mismatch")
	}
	sInitWrite.Rekey()
	rekeyPT, err := sRespRead.Decrypt(nil, nil, decodeFrame(t, mustHex(t, s.RekeyFrameHex)))
	if err != nil || hex.EncodeToString(rekeyPT) != s.RekeyInnerHex {
		t.Fatalf("session rekey decrypt mismatch: %v", err)
	}
	sRespRead.Rekey()

	postCT, err := sInitWrite.Encrypt(nil, nil, mustHex(t, s.PostRekeyDataInnerHex))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(postCT)) != s.PostRekeyDataFrameHex {
		t.Fatalf("post-rekey data frame mismatch:\ngot:  %x\nwant: %s", encodeFrame(postCT), s.PostRekeyDataFrameHex)
	}
	postPT, err := sRespRead.Decrypt(nil, nil, decodeFrame(t, mustHex(t, s.PostRekeyDataFrameHex)))
	if err != nil || hex.EncodeToString(postPT) != s.PostRekeyDataInnerHex {
		t.Fatalf("post-rekey data decrypt mismatch: %v", err)
	}
}
