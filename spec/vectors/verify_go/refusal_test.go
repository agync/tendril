package verify_go_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// TestSessionRefusalV1 replays the Wire v1 refusal transcript over the independent Noise
// implementation and decrypts the responder's 21-byte 0x07 CLOSE (spec/wire-v1.md Section 5.4).
func TestSessionRefusalV1(t *testing.T) {
	var v struct {
		SessionRefusalV1 struct {
			PreambleHex                string `json:"preamble_hex"`
			InitiatorStaticScalarHex   string `json:"initiator_static_scalar_hex"`
			InitiatorStaticPubHex      string `json:"initiator_static_pub_hex"`
			InitiatorEphemScalarHex    string `json:"initiator_ephem_scalar_hex"`
			InitiatorMLKEM768KeygenHex string `json:"initiator_mlkem768_keygen_seed_hex"`
			ResponderStaticScalarHex   string `json:"responder_static_scalar_hex"`
			ResponderStaticPubHex      string `json:"responder_static_pub_hex"`
			ResponderEphemScalarHex    string `json:"responder_ephem_scalar_hex"`
			ResponderMLKEM768EncapsHex string `json:"responder_mlkem768_encaps_seed_hex"`
			RevokedDeviceID            string `json:"revoked_device_id"`
			HostHelloJSON              string `json:"host_hello_json"`
			Msg1FrameHex               string `json:"msg1_frame_hex"`
			Msg2FrameHex               string `json:"msg2_frame_hex"`
			SessionHelloJSON           string `json:"session_hello_json"`
			Msg3FrameHex               string `json:"msg3_frame_hex"`
			FinalHandshakeHashHex      string `json:"final_handshake_hash_hex"`
			CloseCode                  uint16 `json:"close_code"`
			CloseInnerHex              string `json:"close_inner_hex"`
			CloseFrameHex              string `json:"close_frame_hex"`
		} `json:"session_refusal_v1"`
	}
	loadVector(t, "handshake.json", &v)
	r := v.SessionRefusalV1
	if r.PreambleHex == "" {
		t.Fatal("handshake.json lacks session_refusal_v1")
	}

	pre := mustHex(t, r.PreambleHex)
	initHS, err := newHfsHandshake(true, pre, mustHex(t, r.InitiatorStaticScalarHex),
		mustHex(t, r.InitiatorEphemScalarHex), mustHex(t, r.InitiatorMLKEM768KeygenHex))
	if err != nil {
		t.Fatal(err)
	}
	respHS, err := newHfsHandshake(false, pre, mustHex(t, r.ResponderStaticScalarHex),
		mustHex(t, r.ResponderEphemScalarHex), mustHex(t, r.ResponderMLKEM768EncapsHex))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(initHS.localPub) != r.InitiatorStaticPubHex ||
		hex.EncodeToString(respHS.localPub) != r.ResponderStaticPubHex {
		t.Fatal("static pub mismatch")
	}
	if goDeviceID(initHS.localPub) != r.RevokedDeviceID {
		t.Fatalf("revoked device_id mismatch: %s", goDeviceID(initHS.localPub))
	}

	m1, err := initHS.writeMsg1(nil)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(m1)) != r.Msg1FrameHex {
		t.Fatal("refusal msg1 mismatch")
	}
	if _, err := respHS.readMsg1(m1); err != nil {
		t.Fatal(err)
	}
	m2, err := respHS.writeMsg2([]byte(r.HostHelloJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(m2)) != r.Msg2FrameHex {
		t.Fatal("refusal msg2 mismatch")
	}
	if _, err := initHS.readMsg2(m2); err != nil {
		t.Fatal(err)
	}
	m3, _, initRead, err := initHS.writeMsg3([]byte(r.SessionHelloJSON))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encodeFrame(m3)) != r.Msg3FrameHex {
		t.Fatal("refusal msg3 mismatch")
	}
	_, _, respWrite, err := respHS.readMsg3(m3)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(initHS.h[:]) != r.FinalHandshakeHashHex {
		t.Fatal("refusal final hash mismatch")
	}

	inner := []byte{0x07, 0, 0}
	binary.BigEndian.PutUint16(inner[1:], r.CloseCode)
	if r.CloseCode != 4001 || hex.EncodeToString(inner) != r.CloseInnerHex {
		t.Fatalf("close inner mismatch: %x", inner)
	}
	ct, err := respWrite.encryptWithAD(nil, inner)
	if err != nil {
		t.Fatal(err)
	}
	frame := encodeFrame(ct)
	if len(frame) != 21 || hex.EncodeToString(frame) != r.CloseFrameHex {
		t.Fatalf("close frame mismatch: %d bytes %x", len(frame), frame)
	}
	pt, err := initRead.decryptWithAD(nil, decodeFrame(t, mustHex(t, r.CloseFrameHex)))
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 3 || pt[0] != 0x07 || binary.BigEndian.Uint16(pt[1:]) != 4001 {
		t.Fatalf("decrypted close mismatch: %x", pt)
	}
}

var (
	errRefusalAEAD      = errors.New("host_key_unverified")
	errRefusalMalformed = errors.New("protocol_violation")
)

var v2HandshakeBuckets = []int{4096, 16384, 32768, 63488}

// lowOrderX25519 reports a public key whose shared secret with any scalar is all zero;
// curve25519.X25519 rejects that output (RFC 7748 Section 6.1).
func lowOrderX25519(pub []byte) bool {
	_, err := curve25519.X25519(bytes.Repeat([]byte{0x42}, 32), pub)
	return err != nil
}

// goOpenRefusal implements spec/wire-v2.md Section 3.1.4 step 2 independently of the core.
func goOpenRefusal(key, hPre, envelope, remoteStatic []byte) (uint16, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return 0, err
	}
	pt, err := aead.Open(nil, make([]byte, 12), envelope, hPre)
	if err != nil {
		return 0, errRefusalAEAD
	}
	inBucket := false
	for _, b := range v2HandshakeBuckets {
		inBucket = inBucket || len(envelope) == b
	}
	if !inBucket || lowOrderX25519(remoteStatic) || len(pt) < 5 || binary.BigEndian.Uint16(pt) != 3 {
		return 0, errRefusalMalformed
	}
	var pad byte
	for _, b := range pt[5:] {
		pad |= b
	}
	code := binary.BigEndian.Uint16(pt[3:5])
	refusal := code == 4001 || code == 4004 || (code >= 4400 && code <= 4499)
	if pad != 0 || pt[2] != 0x01 || !refusal {
		return 0, errRefusalMalformed
	}
	return code, nil
}

func goOpenHello(key, hPre, envelope []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	if _, err := aead.Open(nil, make([]byte, 12), envelope, hPre); err != nil {
		return errRefusalAEAD
	}
	return nil
}

// TestV2Refusal derives refusal_seal_key, re-seals and opens each sealed refusal, and checks
// that every negative envelope is rejected for the expected reason (spec/wire-v2.md Section 3.1.5).
func TestV2Refusal(t *testing.T) {
	var v struct {
		V2Refusal struct {
			ReconnectSecretHex string `json:"reconnect_secret_hex"`
			RendezvousNonceHex string `json:"rendezvous_nonce_hex"`
			HPreHex            string `json:"h_pre_hex"`
			Bucket             int    `json:"bucket"`
			RefusalSealInfo    string `json:"refusal_seal_info"`
			RefusalSealKeyHex  string `json:"refusal_seal_key_hex"`
			HelloSealKeyHex    string `json:"hello_seal_key_hex"`
			RemoteStaticPubHex string `json:"remote_static_pub_hex"`
			Cases              []struct {
				Code             uint16 `json:"code"`
				Reason           string `json:"reason"`
				RefusalPtHex     string `json:"refusal_pt_hex"`
				SealedRefusalHex string `json:"sealed_refusal_hex"`
			} `json:"cases"`
			Negatives []struct {
				Name          string `json:"name"`
				OpenWith      string `json:"open_with"`
				EnvelopeHex   string `json:"envelope_hex"`
				ExpectedError string `json:"expected_error"`
			} `json:"negatives"`
		} `json:"v2_refusal"`
	}
	loadVector(t, "wire_v2.json", &v)
	r := v.V2Refusal
	if r.RefusalSealInfo != "tendril-v2-refusal-seal" {
		t.Fatalf("refusal info %q", r.RefusalSealInfo)
	}
	secret := mustHex(t, r.ReconnectSecretHex)
	nonce := mustHex(t, r.RendezvousNonceHex)
	hPre := mustHex(t, r.HPreHex)
	remote := mustHex(t, r.RemoteStaticPubHex)
	refusalKey := hkdf32(t, secret, nonce, []byte(r.RefusalSealInfo))
	helloKey := hkdf32(t, secret, nonce, []byte("tendril-v2-hello-seal"))
	if hex.EncodeToString(refusalKey) != r.RefusalSealKeyHex || hex.EncodeToString(helloKey) != r.HelloSealKeyHex {
		t.Fatal("seal key mismatch")
	}
	if len(r.Cases) != 2 {
		t.Fatalf("want 2 cases, got %d", len(r.Cases))
	}
	for _, c := range r.Cases {
		pt := make([]byte, r.Bucket-16)
		binary.BigEndian.PutUint16(pt, 3)
		pt[2] = 0x01
		binary.BigEndian.PutUint16(pt[3:], c.Code)
		if hex.EncodeToString(pt) != c.RefusalPtHex {
			t.Fatalf("%s: plaintext mismatch", c.Reason)
		}
		aead, err := chacha20poly1305.New(refusalKey)
		if err != nil {
			t.Fatal(err)
		}
		sealed := aead.Seal(nil, make([]byte, 12), pt, hPre)
		if len(sealed) != r.Bucket || hex.EncodeToString(sealed) != c.SealedRefusalHex {
			t.Fatalf("%s: sealed refusal mismatch", c.Reason)
		}
		code, err := goOpenRefusal(refusalKey, hPre, sealed, remote)
		if err != nil || code != c.Code {
			t.Fatalf("%s: open = %d, %v", c.Reason, code, err)
		}
		if goOpenHello(helloKey, hPre, sealed) == nil {
			t.Fatalf("%s: a refusal opened under hello_seal_key", c.Reason)
		}
		if _, err := goOpenRefusal(refusalKey, hPre, sealed, make([]byte, 32)); err != errRefusalMalformed {
			t.Fatalf("%s: low-order remote static accepted: %v", c.Reason, err)
		}
	}
	if len(r.Negatives) != 5 {
		t.Fatalf("want 5 negatives, got %d", len(r.Negatives))
	}
	for _, n := range r.Negatives {
		env := mustHex(t, n.EnvelopeHex)
		var err error
		if n.OpenWith == "hello" {
			err = goOpenHello(helloKey, hPre, env)
		} else {
			_, err = goOpenRefusal(refusalKey, hPre, env, remote)
		}
		if err == nil || err.Error() != n.ExpectedError {
			t.Fatalf("%s: got %v, want %s", n.Name, err, n.ExpectedError)
		}
	}
}
