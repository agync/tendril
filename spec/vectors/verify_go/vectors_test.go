package verify_go_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const hfsPattern = "Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256"

var hybridMLDSACtx = []byte("tendril-hybrid-v1")

func verifyHybridSig(pub, msg, sig []byte) error {
	if len(pub) != 32+mldsa65.PublicKeySize {
		return fmt.Errorf("hybrid pub length = %d, want %d", len(pub), 32+mldsa65.PublicKeySize)
	}
	if len(sig) != 64+mldsa65.SignatureSize {
		return fmt.Errorf("hybrid sig length = %d, want %d", len(sig), 64+mldsa65.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub[:32]), msg, sig[:64]) {
		return fmt.Errorf("ed25519 verification failed")
	}
	var mldsaPub mldsa65.PublicKey
	if err := mldsaPub.UnmarshalBinary(pub[32:]); err != nil {
		return fmt.Errorf("mldsa65 pub unmarshal: %w", err)
	}
	if !mldsa65.Verify(&mldsaPub, msg, hybridMLDSACtx, sig[64:]) {
		return fmt.Errorf("mldsa65 verification failed")
	}
	return nil
}

type hfsCipher struct {
	hasKey bool
	key    [32]byte
	n      uint64
}

func makeHfsNonce(n uint64) []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return nonce[:]
}

func (c *hfsCipher) initKey(k []byte) {
	copy(c.key[:], k)
	c.n = 0
	c.hasKey = true
}

func (c *hfsCipher) encryptWithAD(ad, pt []byte) ([]byte, error) {
	if !c.hasKey {
		out := make([]byte, len(pt))
		copy(out, pt)
		return out, nil
	}
	if c.n == math.MaxUint64 {
		return nil, fmt.Errorf("nonce exhausted")
	}
	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, makeHfsNonce(c.n), pt, ad)
	c.n++
	return ct, nil
}

func (c *hfsCipher) decryptWithAD(ad, ct []byte) ([]byte, error) {
	if !c.hasKey {
		out := make([]byte, len(ct))
		copy(out, ct)
		return out, nil
	}
	if c.n == math.MaxUint64 {
		return nil, fmt.Errorf("nonce exhausted")
	}
	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, makeHfsNonce(c.n), ct, ad)
	if err != nil {
		return nil, err
	}
	c.n++
	return pt, nil
}

func (c *hfsCipher) rekey() error {
	if !c.hasKey {
		return fmt.Errorf("rekey before init")
	}
	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return err
	}
	ct := aead.Seal(nil, makeHfsNonce(math.MaxUint64), make([]byte, 32), nil)
	copy(c.key[:], ct[:32])
	return nil
}

type hfsHandshake struct {
	initiator   bool
	localStatic []byte
	localPub    []byte
	ephem       []byte
	mlkemSeed   []byte // 64B d||z for initiator, 32B m for responder
	dk          *mlkem.DecapsulationKey768
	remoteEk    *mlkem.EncapsulationKey768
	re          []byte
	rs          []byte
	ck          [32]byte
	h           [32]byte
	cipher      hfsCipher
}

func newHfsHandshake(initiator bool, prologue, localPriv, ephem, mlkemSeed []byte) (*hfsHandshake, error) {
	localPub, err := curve25519.X25519(localPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(hfsPattern))
	hs := &hfsHandshake{
		initiator:   initiator,
		localStatic: localPriv,
		localPub:    localPub,
		ephem:       ephem,
		mlkemSeed:   mlkemSeed,
		ck:          sum,
		h:           sum,
	}
	hs.mixHash(prologue)
	return hs, nil
}

func (hs *hfsHandshake) mixHash(data []byte) {
	d := sha256.New()
	d.Write(hs.h[:])
	d.Write(data)
	copy(hs.h[:], d.Sum(nil))
}

func hkdfNoise2(ck, ikm []byte) ([32]byte, [32]byte) {
	m0 := hmac.New(sha256.New, ck)
	m0.Write(ikm)
	temp := m0.Sum(nil)

	m1 := hmac.New(sha256.New, temp)
	m1.Write([]byte{0x01})
	var o1 [32]byte
	copy(o1[:], m1.Sum(nil))

	m2 := hmac.New(sha256.New, temp)
	m2.Write(o1[:])
	m2.Write([]byte{0x02})
	var o2 [32]byte
	copy(o2[:], m2.Sum(nil))
	return o1, o2
}

func (hs *hfsHandshake) mixKey(ikm []byte) {
	ck, k := hkdfNoise2(hs.ck[:], ikm)
	hs.ck = ck
	hs.cipher.initKey(k[:])
}

func (hs *hfsHandshake) encryptAndHash(pt []byte) ([]byte, error) {
	ct, err := hs.cipher.encryptWithAD(hs.h[:], pt)
	if err != nil {
		return nil, err
	}
	hs.mixHash(ct)
	return ct, nil
}

func (hs *hfsHandshake) decryptAndHash(ct []byte) ([]byte, error) {
	pt, err := hs.cipher.decryptWithAD(hs.h[:], ct)
	if err != nil {
		return nil, err
	}
	hs.mixHash(ct)
	return pt, nil
}

func (hs *hfsHandshake) writeMsg1(payload []byte) ([]byte, error) {
	ePub, err := curve25519.X25519(hs.ephem, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	hs.mixHash(ePub)
	dk, err := mlkem.NewDecapsulationKey768(hs.mlkemSeed)
	if err != nil {
		return nil, err
	}
	hs.dk = dk
	ekBytes := dk.EncapsulationKey().Bytes()
	hs.mixHash(ekBytes)
	encPayload, err := hs.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(ePub)+len(ekBytes)+len(encPayload))
	out = append(out, ePub...)
	out = append(out, ekBytes...)
	out = append(out, encPayload...)
	return out, nil
}

func (hs *hfsHandshake) readMsg1(msg []byte) ([]byte, error) {
	if len(msg) < 32+mlkem.EncapsulationKeySize768 {
		return nil, fmt.Errorf("short msg1: %d", len(msg))
	}
	hs.re = msg[:32]
	hs.mixHash(hs.re)
	ekBytes := msg[32 : 32+mlkem.EncapsulationKeySize768]
	ek, err := mlkem.NewEncapsulationKey768(ekBytes)
	if err != nil {
		return nil, err
	}
	hs.remoteEk = ek
	hs.mixHash(ekBytes)
	return hs.decryptAndHash(msg[32+mlkem.EncapsulationKeySize768:])
}

func (hs *hfsHandshake) writeMsg2(payload []byte) ([]byte, error) {
	ePub, err := curve25519.X25519(hs.ephem, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	hs.mixHash(ePub)
	ee, err := curve25519.X25519(hs.ephem, hs.re)
	if err != nil {
		return nil, err
	}
	hs.mixKey(ee)
	ss, ct, err := mlkemtest.Encapsulate768(hs.remoteEk, hs.mlkemSeed)
	if err != nil {
		return nil, err
	}
	ctEnc, err := hs.encryptAndHash(ct)
	if err != nil {
		return nil, err
	}
	hs.mixKey(ss)
	sEnc, err := hs.encryptAndHash(hs.localPub)
	if err != nil {
		return nil, err
	}
	es, err := curve25519.X25519(hs.localStatic, hs.re)
	if err != nil {
		return nil, err
	}
	hs.mixKey(es)
	payloadEnc, err := hs.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(ePub)+len(ctEnc)+len(sEnc)+len(payloadEnc))
	out = append(out, ePub...)
	out = append(out, ctEnc...)
	out = append(out, sEnc...)
	out = append(out, payloadEnc...)
	return out, nil
}

func (hs *hfsHandshake) readMsg2(msg []byte) ([]byte, error) {
	const encCTLen = mlkem.CiphertextSize768 + 16
	const encStaticLen = 32 + 16
	if len(msg) < 32+encCTLen+encStaticLen+16 {
		return nil, fmt.Errorf("short msg2: %d", len(msg))
	}
	pos := 0
	hs.re = msg[pos : pos+32]
	pos += 32
	hs.mixHash(hs.re)
	ee, err := curve25519.X25519(hs.ephem, hs.re)
	if err != nil {
		return nil, err
	}
	hs.mixKey(ee)
	ctBytes, err := hs.decryptAndHash(msg[pos : pos+encCTLen])
	pos += encCTLen
	if err != nil {
		return nil, err
	}
	ss, err := hs.dk.Decapsulate(ctBytes)
	if err != nil {
		return nil, err
	}
	hs.mixKey(ss)
	rs, err := hs.decryptAndHash(msg[pos : pos+encStaticLen])
	pos += encStaticLen
	if err != nil {
		return nil, err
	}
	hs.rs = rs
	es, err := curve25519.X25519(hs.ephem, hs.rs)
	if err != nil {
		return nil, err
	}
	hs.mixKey(es)
	return hs.decryptAndHash(msg[pos:])
}

func (hs *hfsHandshake) writeMsg3(payload []byte) ([]byte, *hfsCipher, *hfsCipher, error) {
	sEnc, err := hs.encryptAndHash(hs.localPub)
	if err != nil {
		return nil, nil, nil, err
	}
	se, err := curve25519.X25519(hs.localStatic, hs.re)
	if err != nil {
		return nil, nil, nil, err
	}
	hs.mixKey(se)
	payloadEnc, err := hs.encryptAndHash(payload)
	if err != nil {
		return nil, nil, nil, err
	}
	out := make([]byte, 0, len(sEnc)+len(payloadEnc))
	out = append(out, sEnc...)
	out = append(out, payloadEnc...)
	c1, c2 := hkdfNoise2(hs.ck[:], nil)
	cs1 := &hfsCipher{}
	cs1.initKey(c1[:])
	cs2 := &hfsCipher{}
	cs2.initKey(c2[:])
	return out, cs1, cs2, nil
}

func (hs *hfsHandshake) readMsg3(msg []byte) ([]byte, *hfsCipher, *hfsCipher, error) {
	const encStaticLen = 32 + 16
	if len(msg) < encStaticLen+16 {
		return nil, nil, nil, fmt.Errorf("short msg3: %d", len(msg))
	}
	rs, err := hs.decryptAndHash(msg[:encStaticLen])
	if err != nil {
		return nil, nil, nil, err
	}
	hs.rs = rs
	se, err := curve25519.X25519(hs.ephem, rs)
	if err != nil {
		return nil, nil, nil, err
	}
	hs.mixKey(se)
	pt, err := hs.decryptAndHash(msg[encStaticLen:])
	if err != nil {
		return nil, nil, nil, err
	}
	c1, c2 := hkdfNoise2(hs.ck[:], nil)
	cs1 := &hfsCipher{}
	cs1.initKey(c1[:])
	cs2 := &hfsCipher{}
	cs2.initKey(c2[:])
	return pt, cs1, cs2, nil
}

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
		PinnedSigningSeedHex      string    `json:"pinned_signing_seed_hex"`
		PinnedSigningMLDSASeedHex string    `json:"pinned_signing_mldsa_seed_hex"`
		PinnedSigningPubHex       string    `json:"pinned_signing_pub_hex"`
		Chain                     []rotStep `json:"chain"`
		ForkRecord                rotStep   `json:"fork_record"`
	}
	loadVector(t, "rotation.json", &v)

	seed0 := mustHex(t, v.PinnedSigningSeedHex)
	key0 := ed25519.NewKeyFromSeed(seed0)
	var mldsaSeed0 [mldsa65.SeedSize]byte
	copy(mldsaSeed0[:], mustHex(t, v.PinnedSigningMLDSASeedHex))
	mldsaPK0, _ := mldsa65.NewKeyFromSeed(&mldsaSeed0)
	pinnedPubBytes := append([]byte{}, key0.Public().(ed25519.PublicKey)...)
	pinnedPubBytes = append(pinnedPubBytes, mldsaPK0.Bytes()...)
	if hex.EncodeToString(pinnedPubBytes) != v.PinnedSigningPubHex {
		t.Fatalf("pinned hybrid signing pub mismatch")
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

		if buf.Len() != 4031 {
			t.Fatalf("rotation signed bytes len = %d, want 4031", buf.Len())
		}
		if hex.EncodeToString(buf.Bytes()) != step.SignedBytesHex {
			t.Fatalf("rotation signed bytes mismatch at seq %d", step.Record.Seq)
		}
		if err := verifyHybridSig(prevPub, buf.Bytes(), sig); err != nil {
			t.Fatalf("rotation signature invalid at seq %d: %v", step.Record.Seq, err)
		}
	}

	seenSeq := map[uint64]rotRecord{}
	pinnedPubB64 := base64.RawURLEncoding.EncodeToString(pinnedPubBytes)
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
	rootPub := mustHex(t, v.RootSigningPubHex)
	if err := verifyHybridSig(rootPub, signedRoot, mustB64URL(t, v.RootGrant.Sig)); err != nil {
		t.Fatalf("root grant signature invalid: %v", err)
	}

	verifyGrant := func(g grantObj, pub []byte) {
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
		if err := verifyHybridSig(pub, msg, mustB64URL(t, g.Sig)); err != nil {
			t.Fatalf("grant signature invalid for nonce %s: %v", g.Nonce, err)
		}
	}

	delPub := mustHex(t, v.DelegateSigningPubHex)
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
	if err := verifyHybridSig(rootPub, crlMsg, mustB64URL(t, v.RevocationList.Sig)); err != nil {
		t.Fatalf("CRL signature invalid: %v", err)
	}
}

func TestHandshake(t *testing.T) {
	var v struct {
		NoisePattern   string `json:"noise_pattern"`
		PairTranscript struct {
			PreambleHex                string `json:"preamble_hex"`
			InitiatorStaticScalarHex   string `json:"initiator_static_scalar_hex"`
			InitiatorStaticPubHex      string `json:"initiator_static_pub_hex"`
			InitiatorEphemScalarHex    string `json:"initiator_ephem_scalar_hex"`
			InitiatorMLKEM768KeygenHex string `json:"initiator_mlkem768_keygen_seed_hex"`
			ResponderStaticScalarHex   string `json:"responder_static_scalar_hex"`
			ResponderStaticPubHex      string `json:"responder_static_pub_hex"`
			ResponderEphemScalarHex    string `json:"responder_ephem_scalar_hex"`
			ResponderMLKEM768EncapsHex string `json:"responder_mlkem768_encaps_seed_hex"`
			HostHelloJSON              string `json:"host_hello_json"`
			Msg1FrameHex               string `json:"msg1_frame_hex"`
			Msg2FrameHex               string `json:"msg2_frame_hex"`
			PostMsg2HandshakeHashHex   string `json:"post_msg2_handshake_hash_hex"`
			PairingCode                string `json:"pairing_code"`
			PairingSAS                 string `json:"pairing_sas"`
			CodeMACB64URL              string `json:"code_mac_b64url"`
			PairClaimJSON              string `json:"pair_claim_json"`
			Msg3FrameHex               string `json:"msg3_frame_hex"`
			FinalHandshakeHashHex      string `json:"final_handshake_hash_hex"`
			PairResponseJSON           string `json:"pair_response_json"`
			PairResponseFrameHex       string `json:"pair_response_frame_hex"`
		} `json:"pair_transcript"`
		SessionTranscript struct {
			PreambleHex                string `json:"preamble_hex"`
			InitiatorStaticScalarHex   string `json:"initiator_static_scalar_hex"`
			InitiatorEphemScalarHex    string `json:"initiator_ephem_scalar_hex"`
			InitiatorMLKEM768KeygenHex string `json:"initiator_mlkem768_keygen_seed_hex"`
			ResponderStaticScalarHex   string `json:"responder_static_scalar_hex"`
			ResponderEphemScalarHex    string `json:"responder_ephem_scalar_hex"`
			ResponderMLKEM768EncapsHex string `json:"responder_mlkem768_encaps_seed_hex"`
			HostHelloJSON              string `json:"host_hello_json"`
			Msg1FrameHex               string `json:"msg1_frame_hex"`
			Msg2FrameHex               string `json:"msg2_frame_hex"`
			PostMsg2HandshakeHashHex   string `json:"post_msg2_handshake_hash_hex"`
			SessionHelloJSON           string `json:"session_hello_json"`
			Msg3FrameHex               string `json:"msg3_frame_hex"`
			FinalHandshakeHashHex      string `json:"final_handshake_hash_hex"`
			DataInnerHex               string `json:"data_inner_hex"`
			DataFrameHex               string `json:"data_frame_hex"`
			RekeyInnerHex              string `json:"rekey_inner_hex"`
			RekeyFrameHex              string `json:"rekey_frame_hex"`
			PostRekeyDataInnerHex      string `json:"post_rekey_data_inner_hex"`
			PostRekeyDataFrameHex      string `json:"post_rekey_data_frame_hex"`
		} `json:"session_transcript"`
	}
	loadVector(t, "handshake.json", &v)

	if v.NoisePattern != hfsPattern {
		t.Fatalf("unexpected pattern %s", v.NoisePattern)
	}

	// 1. Pair transcript
	p := v.PairTranscript
	preamble := mustHex(t, p.PreambleHex)
	initHS, err := newHfsHandshake(
		true,
		preamble,
		mustHex(t, p.InitiatorStaticScalarHex),
		mustHex(t, p.InitiatorEphemScalarHex),
		mustHex(t, p.InitiatorMLKEM768KeygenHex),
	)
	if err != nil {
		t.Fatal(err)
	}
	respHS, err := newHfsHandshake(
		false,
		preamble,
		mustHex(t, p.ResponderStaticScalarHex),
		mustHex(t, p.ResponderEphemScalarHex),
		mustHex(t, p.ResponderMLKEM768EncapsHex),
	)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(initHS.localPub) != p.InitiatorStaticPubHex || hex.EncodeToString(respHS.localPub) != p.ResponderStaticPubHex {
		t.Fatalf("static pub mismatch")
	}

	msg1, err := initHS.writeMsg1(nil)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(msg1)) != p.Msg1FrameHex {
		t.Fatalf("pair msg1 mismatch:\ngot:  %x\nwant: %s", encodeFrame(msg1), p.Msg1FrameHex)
	}
	if _, err := respHS.readMsg1(decodeFrame(t, mustHex(t, p.Msg1FrameHex))); err != nil {
		t.Fatal(err)
	}

	msg2, err := respHS.writeMsg2([]byte(p.HostHelloJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(msg2)) != p.Msg2FrameHex {
		t.Fatalf("pair msg2 mismatch:\ngot:  %x\nwant: %s", encodeFrame(msg2), p.Msg2FrameHex)
	}
	pt2, err := initHS.readMsg2(decodeFrame(t, mustHex(t, p.Msg2FrameHex)))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt2) != p.HostHelloJSON {
		t.Fatalf("pair msg2 payload mismatch")
	}
	var hostHello struct {
		SigningPub string `json:"signing_pub"`
	}
	if err := json.Unmarshal(pt2, &hostHello); err != nil {
		t.Fatal(err)
	}
	if len(mustB64URL(t, hostHello.SigningPub)) != 1984 {
		t.Fatalf("expected 1984-byte hybrid signing_pub in HostHello")
	}
	h := initHS.h[:]
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

	msg3, initCS0, initCS1, err := initHS.writeMsg3([]byte(p.PairClaimJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(msg3)) != p.Msg3FrameHex {
		t.Fatalf("pair msg3 mismatch")
	}
	pt3, respCS0, respCS1, err := respHS.readMsg3(decodeFrame(t, mustHex(t, p.Msg3FrameHex)))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt3) != p.PairClaimJSON {
		t.Fatalf("pair msg3 payload mismatch")
	}
	if hex.EncodeToString(initHS.h[:]) != p.FinalHandshakeHashHex {
		t.Fatalf("pair final hash mismatch")
	}

	// Responder writes PairResponse on respCS1; initiator decrypts on initCS1
	pairRespCT, err := respCS1.encryptWithAD(nil, []byte(p.PairResponseJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(pairRespCT)) != p.PairResponseFrameHex {
		t.Fatalf("pair response frame mismatch")
	}
	pairRespPT, err := initCS1.decryptWithAD(nil, decodeFrame(t, mustHex(t, p.PairResponseFrameHex)))
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
	sInitHS, err := newHfsHandshake(
		true,
		sPre,
		mustHex(t, s.InitiatorStaticScalarHex),
		mustHex(t, s.InitiatorEphemScalarHex),
		mustHex(t, s.InitiatorMLKEM768KeygenHex),
	)
	if err != nil {
		t.Fatal(err)
	}
	sRespHS, err := newHfsHandshake(
		false,
		sPre,
		mustHex(t, s.ResponderStaticScalarHex),
		mustHex(t, s.ResponderEphemScalarHex),
		mustHex(t, s.ResponderMLKEM768EncapsHex),
	)
	if err != nil {
		t.Fatal(err)
	}

	sm1, err := sInitHS.writeMsg1(nil)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(sm1)) != s.Msg1FrameHex {
		t.Fatalf("session msg1 mismatch")
	}
	if _, err := sRespHS.readMsg1(decodeFrame(t, mustHex(t, s.Msg1FrameHex))); err != nil {
		t.Fatal(err)
	}

	sm2, err := sRespHS.writeMsg2([]byte(s.HostHelloJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(sm2)) != s.Msg2FrameHex {
		t.Fatalf("session msg2 mismatch")
	}
	if _, err := sInitHS.readMsg2(decodeFrame(t, mustHex(t, s.Msg2FrameHex))); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sInitHS.h[:]) != s.PostMsg2HandshakeHashHex {
		t.Fatalf("session post-msg2 h mismatch")
	}

	sm3, sInitWrite, _, err := sInitHS.writeMsg3([]byte(s.SessionHelloJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(sm3)) != s.Msg3FrameHex {
		t.Fatalf("session msg3 mismatch")
	}
	_, sRespRead, _, err := sRespHS.readMsg3(decodeFrame(t, mustHex(t, s.Msg3FrameHex)))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sInitHS.h[:]) != s.FinalHandshakeHashHex {
		t.Fatalf("session final hash mismatch")
	}

	dataCT, err := sInitWrite.encryptWithAD(nil, mustHex(t, s.DataInnerHex))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(dataCT)) != s.DataFrameHex {
		t.Fatalf("session data frame mismatch")
	}
	dataPT, err := sRespRead.decryptWithAD(nil, decodeFrame(t, mustHex(t, s.DataFrameHex)))
	if err != nil || hex.EncodeToString(dataPT) != s.DataInnerHex {
		t.Fatalf("session data decrypt mismatch: %v", err)
	}

	rekeyCT, err := sInitWrite.encryptWithAD(nil, mustHex(t, s.RekeyInnerHex))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(rekeyCT)) != s.RekeyFrameHex {
		t.Fatalf("session rekey frame mismatch")
	}
	if err := sInitWrite.rekey(); err != nil {
		t.Fatal(err)
	}
	rekeyPT, err := sRespRead.decryptWithAD(nil, decodeFrame(t, mustHex(t, s.RekeyFrameHex)))
	if err != nil || hex.EncodeToString(rekeyPT) != s.RekeyInnerHex {
		t.Fatalf("session rekey decrypt mismatch: %v", err)
	}
	if err := sRespRead.rekey(); err != nil {
		t.Fatal(err)
	}

	postCT, err := sInitWrite.encryptWithAD(nil, mustHex(t, s.PostRekeyDataInnerHex))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(postCT)) != s.PostRekeyDataFrameHex {
		t.Fatalf("post-rekey data frame mismatch:\ngot:  %x\nwant: %s", encodeFrame(postCT), s.PostRekeyDataFrameHex)
	}
	postPT, err := sRespRead.decryptWithAD(nil, decodeFrame(t, mustHex(t, s.PostRekeyDataFrameHex)))
	if err != nil || hex.EncodeToString(postPT) != s.PostRekeyDataInnerHex {
		t.Fatalf("post-rekey data decrypt mismatch: %v", err)
	}
}

func TestM2mEnrollment(t *testing.T) {
	type enrollGrantObj struct {
		V         uint8    `json:"v"`
		Issuer    string   `json:"issuer"`
		Subject   string   `json:"subject"`
		Caps      []string `json:"caps"`
		NotBefore string   `json:"not_before"`
		NotAfter  string   `json:"not_after"`
		Nonce     string   `json:"nonce"`
		Uses      *uint64  `json:"uses,omitempty"`
		Machine   *bool    `json:"machine,omitempty"`
		Sig       string   `json:"sig"`
	}
	var v struct {
		NoisePattern               string         `json:"noise_pattern"`
		PreambleHex                string         `json:"preamble_hex"`
		NowUnix                    uint64         `json:"now_unix"`
		AnchorID                   string         `json:"anchor_id"`
		AnchorSigningPubHex        string         `json:"anchor_signing_pub_hex"`
		ResponderHostID            string         `json:"responder_host_id"`
		ResponderStaticScalarHex   string         `json:"responder_static_scalar_hex"`
		ResponderStaticPubHex      string         `json:"responder_static_pub_hex"`
		ResponderEphemScalarHex    string         `json:"responder_ephem_scalar_hex"`
		ResponderMLKEM768EncapsHex string         `json:"responder_mlkem768_encaps_seed_hex"`
		ResponderSigningPubHex     string         `json:"responder_signing_pub_hex"`
		InitiatorStaticScalarHex   string         `json:"initiator_static_scalar_hex"`
		InitiatorStaticPubHex      string         `json:"initiator_static_pub_hex"`
		InitiatorDeviceID          string         `json:"initiator_device_id"`
		InitiatorEphemScalarHex    string         `json:"initiator_ephem_scalar_hex"`
		InitiatorMLKEM768KeygenHex string         `json:"initiator_mlkem768_keygen_seed_hex"`
		InitiatorSigningPubHex     string         `json:"initiator_signing_pub_hex"`
		TokenJCSJSON               string         `json:"token_jcs_json"`
		TokenSignedBytesHex        string         `json:"token_signed_bytes_hex"`
		EnrollmentToken            enrollGrantObj `json:"enrollment_token"`
		HostHelloJSON              string         `json:"host_hello_json"`
		Msg1FrameHex               string         `json:"msg1_frame_hex"`
		Msg2FrameHex               string         `json:"msg2_frame_hex"`
		PostMsg2HandshakeHashHex   string         `json:"post_msg2_handshake_hash_hex"`
		EnrollProofDomainHex       string         `json:"enroll_proof_domain_hex"`
		EnrollProofBytesHex        string         `json:"enroll_proof_bytes_hex"`
		EnrollProofB64URL          string         `json:"enroll_proof_b64url"`
		PairClaimJSON              string         `json:"pair_claim_json"`
		Msg3FrameHex               string         `json:"msg3_frame_hex"`
		FinalHandshakeHashHex      string         `json:"final_handshake_hash_hex"`
		PairResponseJSON           string         `json:"pair_response_json"`
		PairResponseFrameHex       string         `json:"pair_response_frame_hex"`
		ReplayedResponseJSON       string         `json:"replayed_response_json"`
	}
	loadVector(t, "m2m_enrollment.json", &v)

	if v.NoisePattern != hfsPattern {
		t.Fatalf("unexpected noise pattern %s", v.NoisePattern)
	}
	pre := mustHex(t, v.PreambleHex)
	if !bytes.Equal(pre, []byte{'T', 'N', 'D', 0x01, 0x02, 0x00}) {
		t.Fatalf("unexpected preamble %x", pre)
	}
	if v.EnrollmentToken.Uses == nil || *v.EnrollmentToken.Uses != 1 {
		t.Fatalf("enrollment token uses must be 1")
	}
	if v.EnrollmentToken.Machine == nil || !*v.EnrollmentToken.Machine {
		t.Fatalf("enrollment token machine must be true")
	}

	rawTok, err := json.Marshal(v.EnrollmentToken)
	if err != nil {
		t.Fatal(err)
	}
	var tokMap map[string]any
	if err := json.Unmarshal(rawTok, &tokMap); err != nil {
		t.Fatal(err)
	}
	delete(tokMap, "sig")
	unsignedBytes, err := json.Marshal(tokMap)
	if err != nil {
		t.Fatal(err)
	}
	jcsTok, err := jsoncanonicalizer.Transform(unsignedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(jcsTok) != v.TokenJCSJSON {
		t.Fatalf("token JCS mismatch:\ngot:  %s\nwant: %s", string(jcsTok), v.TokenJCSJSON)
	}
	signedTok := append([]byte("tendril-grant-v1\x00"), jcsTok...)
	if hex.EncodeToString(signedTok) != v.TokenSignedBytesHex {
		t.Fatalf("token signed bytes mismatch")
	}
	anchorPub := mustHex(t, v.AnchorSigningPubHex)
	if err := verifyHybridSig(anchorPub, signedTok, mustB64URL(t, v.EnrollmentToken.Sig)); err != nil {
		t.Fatalf("enrollment token signature invalid: %v", err)
	}

	initPub := mustHex(t, v.InitiatorStaticPubHex)
	respPub := mustHex(t, v.ResponderStaticPubHex)
	if goDeviceID(initPub) != v.InitiatorDeviceID {
		t.Fatalf("initiator device_id mismatch")
	}
	if goDeviceID(respPub) != v.ResponderHostID {
		t.Fatalf("responder host_id mismatch")
	}

	initHS, err := newHfsHandshake(
		true,
		pre,
		mustHex(t, v.InitiatorStaticScalarHex),
		mustHex(t, v.InitiatorEphemScalarHex),
		mustHex(t, v.InitiatorMLKEM768KeygenHex),
	)
	if err != nil {
		t.Fatal(err)
	}
	respHS, err := newHfsHandshake(
		false,
		pre,
		mustHex(t, v.ResponderStaticScalarHex),
		mustHex(t, v.ResponderEphemScalarHex),
		mustHex(t, v.ResponderMLKEM768EncapsHex),
	)
	if err != nil {
		t.Fatal(err)
	}

	m1, err := initHS.writeMsg1(nil)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(m1)) != v.Msg1FrameHex {
		t.Fatalf("m2m msg1 frame mismatch")
	}
	if _, err := respHS.readMsg1(decodeFrame(t, mustHex(t, v.Msg1FrameHex))); err != nil {
		t.Fatal(err)
	}

	m2, err := respHS.writeMsg2([]byte(v.HostHelloJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(m2)) != v.Msg2FrameHex {
		t.Fatalf("m2m msg2 frame mismatch")
	}
	pt2, err := initHS.readMsg2(decodeFrame(t, mustHex(t, v.Msg2FrameHex)))
	if err != nil || string(pt2) != v.HostHelloJSON {
		t.Fatalf("m2m msg2 decrypt mismatch: %v", err)
	}

	h := initHS.h[:]
	if hex.EncodeToString(h) != v.PostMsg2HandshakeHashHex {
		t.Fatalf("m2m post-msg2 h mismatch")
	}
	domain := []byte("tendril-enroll-v1\x00")
	if hex.EncodeToString(domain) != v.EnrollProofDomainHex {
		t.Fatalf("enroll proof domain mismatch")
	}
	var proofInput []byte
	proofInput = append(proofInput, domain...)
	proofInput = append(proofInput, h...)
	proofInput = append(proofInput, initPub...)
	proofInput = append(proofInput, []byte(v.EnrollmentToken.Nonce)...)
	if hex.EncodeToString(proofInput) != v.EnrollProofBytesHex {
		t.Fatalf("enroll proof bytes mismatch")
	}
	initSignPub := mustHex(t, v.InitiatorSigningPubHex)
	if err := verifyHybridSig(initSignPub, proofInput, mustB64URL(t, v.EnrollProofB64URL)); err != nil {
		t.Fatalf("enroll proof hybrid signature invalid: %v", err)
	}

	m3, initCS0, initCS1, err := initHS.writeMsg3([]byte(v.PairClaimJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(m3)) != v.Msg3FrameHex {
		t.Fatalf("m2m msg3 frame mismatch")
	}
	pt3, respCS0, respCS1, err := respHS.readMsg3(decodeFrame(t, mustHex(t, v.Msg3FrameHex)))
	if err != nil || string(pt3) != v.PairClaimJSON {
		t.Fatalf("m2m msg3 decrypt mismatch: %v", err)
	}
	if hex.EncodeToString(initHS.h[:]) != v.FinalHandshakeHashHex {
		t.Fatalf("m2m final hash mismatch")
	}
	_ = initCS0
	_ = respCS0

	ct4, err := respCS1.encryptWithAD(nil, []byte(v.PairResponseJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(ct4)) != v.PairResponseFrameHex {
		t.Fatalf("m2m pair_response frame mismatch")
	}
	pt4, err := initCS1.decryptWithAD(nil, decodeFrame(t, mustHex(t, v.PairResponseFrameHex)))
	if err != nil || string(pt4) != v.PairResponseJSON {
		t.Fatalf("m2m pair_response decrypt mismatch: %v", err)
	}
	var respObj map[string]string
	if err := json.Unmarshal(pt4, &respObj); err != nil {
		t.Fatal(err)
	}
	if respObj["status"] != "active" {
		t.Fatalf("m2m pair response status = %q, want active", respObj["status"])
	}
	if respObj["host_signing_pub"] != base64.RawURLEncoding.EncodeToString(mustHex(t, v.ResponderSigningPubHex)) {
		t.Fatalf("m2m pair response host_signing_pub mismatch")
	}
	var repObj map[string]string
	if err := json.Unmarshal([]byte(v.ReplayedResponseJSON), &repObj); err != nil {
		t.Fatal(err)
	}
	if repObj["error"] != "token_replayed" {
		t.Fatalf("replayed error = %q, want token_replayed", repObj["error"])
	}
}
