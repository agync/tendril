package verify_go_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/crypto/curve25519"
)

const (
	groupMaxMembers     = 32
	groupMaxManifestLen = 32768
	groupMaxEndpoints   = 8
	groupMaxEndpointLen = 256
	groupMaxCaps        = 16
	groupMaxRevoked     = 256
	groupMaxValidity    = 90 * 86400
	groupSkew           = 30
	groupMaxSeq         = uint64(1)<<53 - 1
	groupMaxSeqJump     = 1024
)

type groupMember struct {
	DeviceID       string   `json:"device_id"`
	Name           string   `json:"name"`
	StaticPub      string   `json:"static_pub"`
	SigningPubHash string   `json:"signing_pub_hash"`
	RelayPub       string   `json:"relay_pub"`
	Endpoints      []string `json:"endpoints"`
	Caps           []string `json:"caps"`
}

type groupManifest struct {
	V                int             `json:"v"`
	GroupID          string          `json:"group_id"`
	Name             string          `json:"name"`
	Seq              uint64          `json:"seq"`
	MinWireVersion   int             `json:"min_wire_version"`
	TS               string          `json:"ts"`
	ExpiresAt        string          `json:"expires_at"`
	RootSigningPub   string          `json:"root_signing_pub"`
	SignerDeviceID   string          `json:"signer_device_id"`
	SignerSigningPub *string         `json:"signer_signing_pub"`
	AdminGrant       json.RawMessage `json:"admin_grant"`
	Members          []groupMember   `json:"members"`
	RevokedMembers   []string        `json:"revoked_members"`
	Sig              string          `json:"sig"`
}

type groupGrant struct {
	V             int             `json:"v"`
	Issuer        string          `json:"issuer"`
	Subject       string          `json:"subject"`
	Caps          []string        `json:"caps"`
	NotBefore     string          `json:"not_before"`
	NotAfter      string          `json:"not_after"`
	Nonce         string          `json:"nonce"`
	DelegatedFrom json.RawMessage `json:"delegated_from"`
	Sig           string          `json:"sig"`
}

func base64RawURL(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func base64RawURLEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func isLowerHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validGroupID(s string) bool {
	return len(s) == 20 && strings.HasPrefix(s, "grp_") && isLowerHex(s[4:])
}

func validDeviceID(s string) bool {
	return len(s) == 20 && strings.HasPrefix(s, "dev_") && isLowerHex(s[4:])
}

func jcsWithoutSig(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	delete(m, "sig")
	unsigned, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(unsigned)
}

func groupScopeOK(cap, gid string) error {
	action, resource, hasRes := strings.Cut(cap, ":")
	ns, verb, ok := strings.Cut(action, ".")
	if !ok || ns == "" || verb == "" {
		return fmt.Errorf("InvalidCapability")
	}
	if ns == "group" && verb == "admin" {
		return fmt.Errorf("InvalidGroupCapabilityScope")
	}
	if !hasRes {
		return fmt.Errorf("InvalidGroupCapabilityScope")
	}
	if strings.ContainsAny(resource, "%\\") {
		return fmt.Errorf("InvalidGroupCapabilityScope")
	}
	if resource == gid {
		return nil
	}
	rest, found := strings.CutPrefix(resource, gid+"/")
	if !found {
		return fmt.Errorf("InvalidGroupCapabilityScope")
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("InvalidGroupCapabilityScope")
		}
	}
	return nil
}

func decodeB64Len(s string, n int) ([]byte, bool) {
	b, err := base64RawURL(s)
	if err != nil || len(b) != n {
		return nil, false
	}
	return b, true
}

// checkGroupManifest mirrors the ordered verification algorithm in spec/groups-v1.md and
// returns the Rust error name ("" when valid) plus the signed bytes.
func checkGroupManifest(t *testing.T, raw []byte, now int64) (*groupManifest, []byte, string) {
	t.Helper()
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatal(err)
	}
	if compact.Len() > groupMaxManifestLen {
		return nil, nil, "GroupManifestTooLarge"
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, nil, "InvalidGroupManifest"
	}
	for _, optional := range []string{"signer_signing_pub", "admin_grant"} {
		if string(bytes.TrimSpace(fields[optional])) == "null" {
			return nil, nil, "InvalidGroupManifest"
		}
	}
	var m groupManifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, nil, "InvalidGroupManifest"
	}
	bad := func() (*groupManifest, []byte, string) { return &m, nil, "InvalidGroupManifest" }
	if m.V != 1 || !validGroupID(m.GroupID) || m.Seq == 0 || m.Seq > groupMaxSeq || (m.MinWireVersion != 1 && m.MinWireVersion != 2) {
		return bad()
	}
	nameOK := func(n string) bool {
		c := utf8.RuneCountInString(n)
		if c == 0 || c > 64 {
			return false
		}
		for _, r := range n {
			if unicode.IsControl(r) {
				return false
			}
		}
		return true
	}
	if !nameOK(m.Name) {
		return bad()
	}
	rootPub, ok := decodeB64Len(m.RootSigningPub, 1984)
	if !ok {
		return bad()
	}
	rootHash := sha256.Sum256(rootPub)
	if m.GroupID != "grp_"+hex.EncodeToString(rootHash[:8]) {
		return bad()
	}
	ts, err1 := parseStrictUTC(m.TS)
	exp, err2 := parseStrictUTC(m.ExpiresAt)
	if err1 != nil || err2 != nil {
		return bad()
	}
	if !exp.After(ts) || exp.Unix()-ts.Unix() > groupMaxValidity || now >= exp.Unix() || ts.Unix() > now+groupSkew {
		return bad()
	}
	if len(m.Members) == 0 || len(m.Members) > groupMaxMembers {
		return bad()
	}
	ids := map[string]bool{}
	hashes := map[string]bool{}
	byID := map[string]groupMember{}
	for _, mem := range m.Members {
		if !nameOK(mem.Name) {
			return bad()
		}
		sp, ok := decodeB64Len(mem.StaticPub, 32)
		if !ok {
			return bad()
		}
		sum := sha256.Sum256(sp)
		if mem.DeviceID != "dev_"+hex.EncodeToString(sum[:8]) {
			return bad()
		}
		if _, ok := decodeB64Len(mem.SigningPubHash, 32); !ok {
			return bad()
		}
		if _, ok := decodeB64Len(mem.RelayPub, 32); !ok {
			return bad()
		}
		if len(mem.Endpoints) > groupMaxEndpoints {
			return bad()
		}
		for _, ep := range mem.Endpoints {
			if len(ep) > groupMaxEndpointLen || ep == "" {
				return bad()
			}
		}
		if len(mem.Caps) > groupMaxCaps {
			return bad()
		}
		for _, c := range mem.Caps {
			if err := groupScopeOK(c, m.GroupID); err != nil {
				if err.Error() == "InvalidCapability" {
					return bad()
				}
				return &m, nil, err.Error()
			}
		}
		if ids[mem.DeviceID] || hashes[mem.SigningPubHash] {
			return bad()
		}
		ids[mem.DeviceID] = true
		hashes[mem.SigningPubHash] = true
		byID[mem.DeviceID] = mem
	}
	if len(m.RevokedMembers) > groupMaxRevoked {
		return bad()
	}
	revoked := map[string]bool{}
	for _, r := range m.RevokedMembers {
		if !validDeviceID(r) || revoked[r] {
			return bad()
		}
		revoked[r] = true
	}
	for _, mem := range m.Members {
		if revoked[mem.DeviceID] {
			return &m, nil, "GroupMemberRevoked"
		}
	}
	wantHash := base64RawURLEncode(rootHash[:])
	wantRelay := base64RawURLEncode(rootPub[:32])
	var root *groupMember
	for i := range m.Members {
		if m.Members[i].SigningPubHash == wantHash {
			root = &m.Members[i]
		}
	}
	if root == nil || root.RelayPub != wantRelay {
		return bad()
	}

	signerPub := rootPub
	if m.SignerDeviceID == root.DeviceID {
		if m.SignerSigningPub != nil || len(m.AdminGrant) != 0 {
			return bad()
		}
	} else {
		mem, ok := byID[m.SignerDeviceID]
		if !ok || m.SignerSigningPub == nil {
			return bad()
		}
		sp, ok := decodeB64Len(*m.SignerSigningPub, 1984)
		if !ok {
			return bad()
		}
		sh := sha256.Sum256(sp)
		if mem.SigningPubHash != base64RawURLEncode(sh[:]) || mem.RelayPub != base64RawURLEncode(sp[:32]) {
			return bad()
		}
		if len(m.AdminGrant) == 0 {
			return &m, nil, "GroupUnauthorized"
		}
		if !checkAdminGrant(t, m.AdminGrant, m.SignerDeviceID, root.DeviceID, rootPub, sp, m.GroupID, now) {
			return &m, nil, "GroupUnauthorized"
		}
		signerPub = sp
	}

	jcs, err := jcsWithoutSig(raw)
	if err != nil {
		t.Fatal(err)
	}
	signed := append([]byte("tendril-group-v1\x00"), jcs...)
	sig, err := base64RawURL(m.Sig)
	if err != nil || verifyHybridSig(signerPub, signed, sig) != nil {
		return &m, signed, "InvalidSignature"
	}
	return &m, signed, ""
}

func checkAdminGrant(t *testing.T, raw json.RawMessage, signer, rootDevice string, rootPub, signerPub []byte, gid string, now int64) bool {
	t.Helper()
	var g groupGrant
	if err := json.Unmarshal(raw, &g); err != nil {
		return false
	}
	if g.V != 1 || g.Issuer != rootDevice || g.Subject != signer || len(g.DelegatedFrom) != 0 {
		return false
	}
	signerHash := sha256.Sum256(signerPub)
	keyed := "group.admin:" + gid + "/" + hex.EncodeToString(signerHash[:])
	covered := false
	for _, c := range g.Caps {
		if c == keyed {
			covered = true
		}
	}
	nb, err1 := parseStrictUTC(g.NotBefore)
	na, err2 := parseStrictUTC(g.NotAfter)
	if !covered || err1 != nil || err2 != nil || now < nb.Unix()-groupSkew || now >= na.Unix() {
		return false
	}
	jcs, err := jcsWithoutSig(raw)
	if err != nil {
		return false
	}
	msg := append([]byte("tendril-grant-v1\x00"), jcs...)
	sig, err := base64RawURL(g.Sig)
	return err == nil && verifyHybridSig(rootPub, msg, sig) == nil
}

func checkAgainstPrior(cur, prior *groupManifest, curSigned, priorSigned []byte) string {
	switch {
	case cur.Seq < prior.Seq:
		return "GroupSeqRollback"
	case cur.Seq == prior.Seq:
		if bytes.Equal(curSigned, priorSigned) {
			return ""
		}
		return "GroupManifestFork"
	case cur.Seq-prior.Seq > groupMaxSeqJump:
		return "InvalidGroupManifest"
	case cur.MinWireVersion < prior.MinWireVersion:
		return "GroupWireDowngrade"
	}
	now := map[string]bool{}
	for _, r := range cur.RevokedMembers {
		now[r] = true
	}
	for _, r := range prior.RevokedMembers {
		if !now[r] {
			for _, mem := range cur.Members {
				if mem.DeviceID == r {
					return "GroupMemberRevoked"
				}
			}
			return "InvalidGroupManifest"
		}
	}
	live := map[string]bool{}
	for _, mem := range cur.Members {
		live[mem.DeviceID] = true
	}
	for _, mem := range prior.Members {
		if !live[mem.DeviceID] && !now[mem.DeviceID] {
			return "InvalidGroupManifest"
		}
	}
	rootPub, err := base64RawURL(cur.RootSigningPub)
	if err != nil {
		return "InvalidGroupManifest"
	}
	rootHash := sha256.Sum256(rootPub)
	wantHash := base64RawURLEncode(rootHash[:])
	findRoot := func(m *groupManifest) *groupMember {
		for i := range m.Members {
			if m.Members[i].SigningPubHash == wantHash {
				return &m.Members[i]
			}
		}
		return nil
	}
	priorRoot, curRoot := findRoot(prior), findRoot(cur)
	if priorRoot == nil || curRoot == nil ||
		priorRoot.DeviceID != curRoot.DeviceID || priorRoot.StaticPub != curRoot.StaticPub {
		return "InvalidGroupManifest"
	}
	if cur.SignerSigningPub != nil && !reflect.DeepEqual(priorRoot, curRoot) {
		return "GroupUnauthorized"
	}
	return ""
}

func TestGroups(t *testing.T) {
	type keyEntry struct {
		DeviceID        string `json:"device_id"`
		StaticScalarHex string `json:"static_scalar_hex"`
		StaticPubHex    string `json:"static_pub_hex"`
		SigningPubHex   string `json:"signing_pub_hex"`
	}
	var v struct {
		NowUnix           int64               `json:"now_unix"`
		ManifestDomainHex string              `json:"manifest_domain_hex"`
		Keys              map[string]keyEntry `json:"keys"`
		GroupID           struct {
			RootSigningPubHex       string `json:"root_signing_pub_hex"`
			RootSigningPubSHA256Hex string `json:"root_signing_pub_sha256_hex"`
			GroupID                 string `json:"group_id"`
		} `json:"group_id"`
		Chain []struct {
			Label          string          `json:"label"`
			Manifest       json.RawMessage `json:"manifest"`
			SignedBytesHex string          `json:"signed_bytes_hex"`
			WireLen        int             `json:"wire_len"`
		} `json:"chain"`
		AdminGrant struct {
			Grant          json.RawMessage `json:"grant"`
			SignedBytesHex string          `json:"signed_bytes_hex"`
		} `json:"admin_grant"`
		Rejections []struct {
			Name          string          `json:"name"`
			ExpectedError string          `json:"expected_error"`
			Manifest      json.RawMessage `json:"manifest"`
			PriorIndex    *int            `json:"prior_index"`
		} `json:"rejections"`
		SameSeqReplays []struct {
			Name       string          `json:"name"`
			Manifest   json.RawMessage `json:"manifest"`
			PriorIndex int             `json:"prior_index"`
		} `json:"same_seq_replays"`
		ParseRejections []struct {
			Name     string          `json:"name"`
			Manifest json.RawMessage `json:"manifest"`
		} `json:"parse_rejections"`
		PairBootstrap struct {
			Key       string `json:"group_rendezvous_key_hex"`
			Seq       uint64 `json:"seq"`
			IDA       string `json:"id_a"`
			IDB       string `json:"id_b"`
			InfoHex   string `json:"info_hex"`
			OutputHex string `json:"output_hex"`
		} `json:"pair_bootstrap"`
		GroupMailbox struct {
			Key       string `json:"group_rendezvous_key_hex"`
			Seq       uint64 `json:"seq"`
			Member    string `json:"member_device_id"`
			InfoHex   string `json:"info_hex"`
			OutputHex string `json:"output_hex"`
		} `json:"group_mailbox"`
		RendezvousFrame struct {
			GroupID       string `json:"group_id"`
			Seq           uint64 `json:"seq"`
			Key           string `json:"group_rendezvous_key_hex"`
			FrameHex      string `json:"frame_hex"`
			InnerFrameHex string `json:"inner_frame_hex"`
		} `json:"rendezvous_frame"`
		SessionHelloGroups struct {
			JSON string `json:"json"`
		} `json:"session_hello_groups"`
	}
	loadVector(t, "groups.json", &v)

	if !bytes.Equal(mustHex(t, v.ManifestDomainHex), []byte("tendril-group-v1\x00")) {
		t.Fatal("manifest domain mismatch")
	}

	for name, k := range v.Keys {
		scalar := mustHex(t, k.StaticScalarHex)
		pub, err := curve25519.X25519(scalar, curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(pub) != k.StaticPubHex || goDeviceID(pub) != k.DeviceID {
			t.Fatalf("%s: static key or device_id mismatch", name)
		}
	}

	rootPub := mustHex(t, v.GroupID.RootSigningPubHex)
	sum := sha256.Sum256(rootPub)
	if hex.EncodeToString(sum[:]) != v.GroupID.RootSigningPubSHA256Hex {
		t.Fatal("root pub hash mismatch")
	}
	if "grp_"+hex.EncodeToString(sum[:8]) != v.GroupID.GroupID || len(v.GroupID.GroupID) != 20 {
		t.Fatalf("group_id derivation mismatch: %s", v.GroupID.GroupID)
	}

	var parsed []*groupManifest
	var parsedSigned [][]byte
	for i, entry := range v.Chain {
		m, signed, errName := checkGroupManifest(t, entry.Manifest, v.NowUnix)
		if errName != "" {
			t.Fatalf("chain[%d] %s rejected: %s", i, entry.Label, errName)
		}
		if hex.EncodeToString(signed) != entry.SignedBytesHex {
			t.Fatalf("chain[%d] signed bytes mismatch", i)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, entry.Manifest); err != nil {
			t.Fatal(err)
		}
		if compact.Len() != entry.WireLen || compact.Len() > groupMaxManifestLen {
			t.Fatalf("chain[%d] wire length %d != %d", i, compact.Len(), entry.WireLen)
		}
		if i > 0 {
			if got := checkAgainstPrior(m, parsed[i-1], signed, parsedSigned[i-1]); got != "" {
				t.Fatalf("chain[%d] fails prior check: %s", i, got)
			}
		}
		parsed = append(parsed, m)
		parsedSigned = append(parsedSigned, signed)
	}
	if parsed[0].SignerSigningPub != nil || parsed[4].SignerSigningPub == nil {
		t.Fatal("expected root-signed seq1 and co-admin-signed seq5")
	}

	jcsGrant, err := jcsWithoutSig(v.AdminGrant.Grant)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(append([]byte("tendril-grant-v1\x00"), jcsGrant...)) != v.AdminGrant.SignedBytesHex {
		t.Fatal("admin grant signed bytes mismatch")
	}

	for _, rej := range v.Rejections {
		m, signed, errName := checkGroupManifest(t, rej.Manifest, v.NowUnix)
		if errName == "" && rej.PriorIndex != nil {
			errName = checkAgainstPrior(m, parsed[*rej.PriorIndex], signed, parsedSigned[*rej.PriorIndex])
		}
		if errName != rej.ExpectedError {
			t.Fatalf("rejection %s: got %q, want %q", rej.Name, errName, rej.ExpectedError)
		}
	}

	if len(v.SameSeqReplays) == 0 {
		t.Fatal("missing same_seq_replays")
	}
	for _, rep := range v.SameSeqReplays {
		m, signed, errName := checkGroupManifest(t, rep.Manifest, v.NowUnix)
		if errName == "" {
			errName = checkAgainstPrior(m, parsed[rep.PriorIndex], signed, parsedSigned[rep.PriorIndex])
		}
		if errName != "" {
			t.Fatalf("same-seq replay %s: got %q, want unchanged", rep.Name, errName)
		}
	}

	if len(v.ParseRejections) == 0 {
		t.Fatal("missing parse_rejections")
	}
	for _, rej := range v.ParseRejections {
		if _, _, errName := checkGroupManifest(t, rej.Manifest, v.NowUnix); errName != "InvalidGroupManifest" {
			t.Fatalf("parse rejection %s: got %q", rej.Name, errName)
		}
	}

	pb := v.PairBootstrap
	lo, hi := pb.IDA, pb.IDB
	if lo > hi {
		lo, hi = hi, lo
	}
	info := []byte("tendril-group-v2-rendezvous\x00" + lo + "\x00" + hi)
	if hex.EncodeToString(info) != pb.InfoHex {
		t.Fatal("pair_bootstrap info mismatch")
	}
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], pb.Seq)
	if got := hex.EncodeToString(hkdf32(t, mustHex(t, pb.Key), seq[:], info)); got != pb.OutputHex {
		t.Fatalf("pair_bootstrap = %s, want %s", got, pb.OutputHex)
	}

	gm := v.GroupMailbox
	minfo := []byte("tendril-group-v2-mailbox" + gm.Member)
	if hex.EncodeToString(minfo) != gm.InfoHex {
		t.Fatal("group_mailbox info mismatch")
	}
	binary.BigEndian.PutUint64(seq[:], gm.Seq)
	if got := hex.EncodeToString(hkdf32(t, mustHex(t, gm.Key), seq[:], minfo)); got != gm.OutputHex {
		t.Fatalf("group_mailbox = %s, want %s", got, gm.OutputHex)
	}

	rf := v.RendezvousFrame
	frame := append([]byte(rf.GroupID), 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint64(frame[20:28], rf.Seq)
	frame = append(frame, mustHex(t, rf.Key)...)
	if len(frame) != 60 || hex.EncodeToString(frame) != rf.FrameHex {
		t.Fatal("rendezvous frame mismatch")
	}
	if hex.EncodeToString(append([]byte{0x0B}, frame...)) != rf.InnerFrameHex {
		t.Fatal("rendezvous inner frame mismatch")
	}

	var hello struct {
		DeviceID string `json:"device_id"`
		Groups   []struct {
			GroupID string `json:"group_id"`
			Seq     uint64 `json:"seq"`
		} `json:"groups"`
	}
	dec := json.NewDecoder(strings.NewReader(v.SessionHelloGroups.JSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&hello); err != nil {
		t.Fatal(err)
	}
	if len(hello.Groups) == 0 || len(hello.Groups) > 16 {
		t.Fatal("hello groups out of bounds")
	}
	for _, g := range hello.Groups {
		if !validGroupID(g.GroupID) || g.Seq == 0 || g.Seq > groupMaxSeq {
			t.Fatalf("malformed hello group entry %+v", g)
		}
	}
}
