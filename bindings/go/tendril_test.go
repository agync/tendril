package tendril_test

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	tendril "github.com/agync/tendril/bindings/go"
)

func readJSONFile(t *testing.T, rel string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", rel))
	if err != nil {
		t.Fatalf("read vector %s: %v", rel, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parse vector %s: %v", rel, err)
	}
	return out
}

func hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("invalid hex32 %q: %v", s, err)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func hexB64(t *testing.T, s string) string {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestConformanceVectors(t *testing.T) {
	// 1. Fingerprints + SAS
	fp := readJSONFile(t, "fingerprints.json")
	pub := hex32(t, fp["raw_pubkey_hex"].(string))
	devID, err := tendril.DeviceID(pub)
	if err != nil || devID != fp["raw_device_id"].(string) {
		t.Fatalf("DeviceID mismatch: got %q err=%v", devID, err)
	}
	hfp, err := tendril.FingerprintHost(pub)
	if err != nil || hfp != fp["raw_host_fingerprint"].(string) {
		t.Fatalf("FingerprintHost mismatch: got %q err=%v", hfp, err)
	}
	dfp, err := tendril.FingerprintDevice(pub)
	if err != nil || dfp != fp["raw_device_fingerprint"].(string) {
		t.Fatalf("FingerprintDevice mismatch: got %q err=%v", dfp, err)
	}
	hh := hex32(t, fp["handshake_hash_hex"].(string))
	sas, err := tendril.PairingSAS(hh)
	if err != nil || sas != fp["pairing_sas"].(string) {
		t.Fatalf("PairingSAS mismatch: got %q err=%v", sas, err)
	}

	// 2. Pairing MAC
	pm := readJSONFile(t, "pairing_mac.json")
	pmHH := hex32(t, pm["handshake_hash_hex"].(string))
	r3 := pm["remote_3group"].(map[string]any)
	mac, err := tendril.ComputeCodeMAC(r3["code"].(string), pmHH)
	if err != nil {
		t.Fatalf("ComputeCodeMAC: %v", err)
	}
	if hex.EncodeToString(mac[:]) != r3["code_mac_hex"].(string) {
		t.Fatalf("ComputeCodeMAC mismatch")
	}

	// 3. Rotation chain + fork rejection
	rot := readJSONFile(t, "rotation.json")
	psig := hexB64(t, rot["pinned_signing_pub_hex"].(string))
	pstat := hexB64(t, rot["pinned_static_pub_hex"].(string))
	chainArr := rot["chain"].([]any)
	var records []any
	for _, item := range chainArr {
		records = append(records, item.(map[string]any)["record"])
	}
	lastRec := records[len(records)-1].(map[string]any)
	chainBytes, _ := json.Marshal(records)
	finalSeq, err := tendril.VerifyRotationChainJSON(
		psig, pstat, 0,
		string(chainBytes),
		lastRec["new_static_pub"].(string),
		lastRec["new_signing_pub"].(string),
	)
	if err != nil || finalSeq != 2 {
		t.Fatalf("VerifyRotationChainJSON failed: seq=%d err=%v", finalSeq, err)
	}
	forkRec := rot["fork_record"].(map[string]any)["record"]
	forkChainBytes, _ := json.Marshal(append(records, forkRec))
	if _, err := tendril.VerifyRotationChainJSON(
		psig, pstat, 0,
		string(forkChainBytes),
		lastRec["new_static_pub"].(string),
		lastRec["new_signing_pub"].(string),
	); err == nil {
		t.Fatalf("expected rotation fork rejection")
	}

	// 4. Grants delegation allow / widened deny
	gv := readJSONFile(t, "grants.json")
	keysMap := map[string]string{
		gv["root_issuer_id"].(string): hexB64(t, gv["root_signing_pub_hex"].(string)),
		gv["delegate_id"].(string):    hexB64(t, gv["delegate_signing_pub_hex"].(string)),
	}
	keysJSON, _ := json.Marshal(keysMap)
	validGrant, _ := json.Marshal(gv["delegated_valid"])
	widenedGrant, _ := json.Marshal(gv["delegated_widened"])
	const nowUnix = 1795564800

	allowed, err := tendril.VerifyGrantJSON(
		string(validGrant),
		string(keysJSON),
		gv["leaf_id"].(string),
		gv["root_issuer_id"].(string),
		"fs.read:/photos/2026/a.jpg",
		nowUnix,
		"",
	)
	if err != nil || !allowed {
		t.Fatalf("expected delegated_valid allow: allowed=%v err=%v", allowed, err)
	}
	widenedAllowed, err := tendril.VerifyGrantJSON(
		string(widenedGrant),
		string(keysJSON),
		gv["leaf_id"].(string),
		gv["root_issuer_id"].(string),
		"fs.read:/photos/2026/a.jpg",
		nowUnix,
		"",
	)
	if err != nil || widenedAllowed {
		t.Fatalf("expected delegated_widened deny: allowed=%v err=%v", widenedAllowed, err)
	}
}

type peerDriver struct {
	cmd    *exec.Cmd
	stdin  *bufio.Writer
	stdout *bufio.Scanner
}

func spawnPeer(t *testing.T) *peerDriver {
	t.Helper()
	bin := filepath.Join("..", "..", "target", "debug", "tendril-conformance-peer")
	cmd := exec.Command(bin)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start conformance peer: %v", err)
	}
	p := &peerDriver{
		cmd:    cmd,
		stdin:  bufio.NewWriter(stdinPipe),
		stdout: bufio.NewScanner(stdoutPipe),
	}
	p.stdout.Buffer(make([]byte, 1024*1024), 1024*1024)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return p
}

func (p *peerDriver) send(t *testing.T, v map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(v)
	_, _ = p.stdin.Write(raw)
	_ = p.stdin.WriteByte('\n')
	_ = p.stdin.Flush()
}

func (p *peerDriver) recv(t *testing.T) map[string]any {
	t.Helper()
	if !p.stdout.Scan() {
		t.Fatalf("conformance peer eof: %v", p.stdout.Err())
	}
	var out map[string]any
	if err := json.Unmarshal(p.stdout.Bytes(), &out); err != nil {
		t.Fatalf("parse peer json: %v", err)
	}
	return out
}

func (p *peerDriver) call(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	p.send(t, v)
	resp := p.recv(t)
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("peer cmd %v failed: %v", v["op"], resp)
	}
	return resp
}

func TestLiveInteropWithConformancePeer(t *testing.T) {
	// Direction 1: Rust conformance peer listens, Go dials & pairs/connects/sends.
	peer := spawnPeer(t)
	goClient, err := tendril.NewEndpoint("", "go-client")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer goClient.Close()

	peerInit := peer.call(t, map[string]any{"op": "init", "host_id": "rust-peer"})
	_ = peerInit
	srv := peer.call(t, map[string]any{"op": "serve_direct"})
	ep := srv["endpoint"].(string)
	code := peer.call(t, map[string]any{"op": "issue_code", "kind": "lan"})["code"].(string)

	peer.send(t, map[string]any{"op": "pair"})
	pairRes, err := goClient.PairInitiate(ep, "", code, "go-dev", "go")
	if err != nil {
		t.Fatalf("Go PairInitiate: %v", err)
	}
	peerPair := peer.recv(t)
	if ok, _ := peerPair["ok"].(bool); !ok || peerPair["sas"] != pairRes.SAS {
		t.Fatalf("pair SAS mismatch: go=%s peer=%v", pairRes.SAS, peerPair)
	}
	cliDevID := peerPair["device_id"].(string)

	peer.call(t, map[string]any{"op": "confirm", "peer_id": cliDevID, "sas": pairRes.SAS})
	grantBytes, _ := json.Marshal(peer.call(t, map[string]any{
		"op": "mint", "peer_id": cliDevID, "caps": []string{"fs.read"},
	})["grant"])

	// Connecting before client-side ConfirmPeer must fail closed.
	peer.send(t, map[string]any{"op": "connect"})
	if _, err := goClient.Connect(ep, "", "rust-peer", string(grantBytes)); err == nil {
		t.Fatalf("Go Connect succeeded before client ConfirmPeer")
	}
	if ok, _ := peer.recv(t)["ok"].(bool); ok {
		t.Fatalf("expected peer connect to observe client pre-confirm abort")
	}
	if err := goClient.ConfirmPeer("rust-peer", pairRes.SAS); err != nil {
		t.Fatalf("Go client ConfirmPeer: %v", err)
	}

	peer.send(t, map[string]any{"op": "connect"})
	sess, err := goClient.Connect(ep, "", "rust-peer", string(grantBytes))
	if err != nil {
		t.Fatalf("Go Connect: %v", err)
	}
	defer sess.Close()
	if ok, _ := peer.recv(t)["ok"].(bool); !ok {
		t.Fatalf("peer connect failed")
	}
	if gotPeerID, err := sess.PeerID(); err != nil || gotPeerID != "rust-peer" {
		t.Fatalf("Go sess.PeerID() = %q err=%v, want %q", gotPeerID, err, "rust-peer")
	}

	if err := sess.SendData([]byte("hello-from-go")); err != nil {
		t.Fatalf("Go SendData: %v", err)
	}
	ev := peer.call(t, map[string]any{"op": "recv", "timeout_ms": 2000})
	if ev["event"] != "data" || ev["data_utf8"] != "hello-from-go" {
		t.Fatalf("unexpected peer recv: %v", ev)
	}

	if ok, _ := peer.call(t, map[string]any{"op": "authorize", "cap": "fs.read"})["allowed"].(bool); !ok {
		t.Fatalf("expected fs.read allowed")
	}
	if ok, _ := peer.call(t, map[string]any{"op": "authorize", "cap": "shell.exec"})["allowed"].(bool); ok {
		t.Fatalf("expected shell.exec denied")
	}

	peer.call(t, map[string]any{"op": "send", "data_utf8": "reply-from-rust"})
	goEv, err := sess.PollEvent(2000)
	if err != nil || goEv.Event != "data" {
		t.Fatalf("Go PollEvent failed: ev=%v err=%v", goEv, err)
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(goEv.DataB64)
	if string(decoded) != "reply-from-rust" {
		t.Fatalf("unexpected Go payload: %q", decoded)
	}

	_ = sess.CloseSession(1000, "done")
	peer.call(t, map[string]any{"op": "revoke", "peer_id": cliDevID})
	peer.call(t, map[string]any{"op": "shutdown"})

	// Direction 2: Go serves & enforces grants/revocation against Rust conformance peer client.
	peer2 := spawnPeer(t)
	goHost, err := tendril.NewEndpoint("", "go-host")
	if err != nil {
		t.Fatalf("NewEndpoint host: %v", err)
	}
	defer goHost.Close()
	hostEp, err := goHost.ServeDirect("")
	if err != nil {
		t.Fatalf("Go ServeDirect: %v", err)
	}
	code2, err := goHost.IssueCode("lan")
	if err != nil {
		t.Fatalf("Go IssueCode: %v", err)
	}
	peer2.call(t, map[string]any{"op": "init"})
	peer2.send(t, map[string]any{"op": "pair", "endpoint": hostEp, "code": code2})
	accPair, err := goHost.PairAccept(5000)
	if err != nil {
		t.Fatalf("Go PairAccept: %v", err)
	}
	p2Pair := peer2.recv(t)
	if p2Pair["sas"] != accPair.SAS {
		t.Fatalf("SAS mismatch: %s vs %v", accPair.SAS, p2Pair["sas"])
	}
	if err := goHost.ConfirmPeer(accPair.DeviceID, accPair.SAS); err != nil {
		t.Fatalf("Go ConfirmPeer: %v", err)
	}
	peer2.call(t, map[string]any{"op": "confirm", "peer_id": "go-host", "sas": accPair.SAS})
	grantJSON, err := goHost.MintGrant(accPair.DeviceID, []string{"fs.read"}, 3600)
	if err != nil {
		t.Fatalf("Go MintGrant: %v", err)
	}
	var grantVal any
	_ = json.Unmarshal([]byte(grantJSON), &grantVal)
	peer2.send(t, map[string]any{
		"op": "connect", "endpoint": hostEp, "target_host_id": "go-host", "grant": grantVal,
	})
	hostSess, err := goHost.AcceptSession(5000)
	if err != nil {
		t.Fatalf("Go AcceptSession: %v", err)
	}
	defer hostSess.Close()
	if ok, _ := peer2.recv(t)["ok"].(bool); !ok {
		t.Fatalf("peer2 connect failed")
	}
	if gotPeerID, err := hostSess.PeerID(); err != nil || gotPeerID != accPair.DeviceID {
		t.Fatalf("Go hostSess.PeerID() = %q err=%v, want %q", gotPeerID, err, accPair.DeviceID)
	}
	if allowed, err := hostSess.Authorize("fs.read"); err != nil || !allowed {
		t.Fatalf("Go Authorize fs.read failed: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := hostSess.Authorize("shell.exec"); err != nil || allowed {
		t.Fatalf("Go Authorize shell.exec expected false: allowed=%v err=%v", allowed, err)
	}
	if err := goHost.RevokePeer(accPair.DeviceID); err != nil {
		t.Fatalf("Go RevokePeer: %v", err)
	}
	if gotPeerID, err := hostSess.PeerID(); err != nil || gotPeerID != accPair.DeviceID {
		t.Fatalf("Go hostSess.PeerID() after revoke = %q err=%v, want %q", gotPeerID, err, accPair.DeviceID)
	}
	if allowed, err := hostSess.Authorize("fs.read"); err != nil || allowed {
		t.Fatalf("Go Authorize after revoke expected false: allowed=%v err=%v", allowed, err)
	}
	peer2.call(t, map[string]any{"op": "shutdown"})
}

func TestConcurrencyLifetimeRekeyAndWouldBlock(t *testing.T) {
	hostEp, err := tendril.NewEndpoint("", "go-race-host")
	if err != nil {
		t.Fatalf("NewEndpoint host: %v", err)
	}
	defer hostEp.Close()

	info, err := hostEp.Info()
	if err != nil || info.HostID != "go-race-host" || info.DeviceID == "" {
		t.Fatalf("unexpected Info: %+v err=%v", info, err)
	}

	addr, err := hostEp.ServeDirect("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	code, err := hostEp.IssueCode("lan")
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}

	if _, err := hostEp.PairAccept(0); !errors.Is(err, tendril.ErrWouldBlock) {
		t.Fatalf("expected ErrWouldBlock on PairAccept(0), got %v", err)
	}

	cliEp, err := tendril.NewEndpoint("", "go-race-cli")
	if err != nil {
		t.Fatalf("NewEndpoint cli: %v", err)
	}
	defer cliEp.Close()

	var wg sync.WaitGroup
	var key [32]byte
	key[0] = 0x11
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := tendril.DeviceID(key); err != nil {
				t.Errorf("concurrent DeviceID: %v", err)
			}
			if _, err := hostEp.Info(); err != nil {
				t.Errorf("concurrent Info: %v", err)
			}
		}()
	}

	pairCh := make(chan tendril.PairAcceptResult, 1)
	pairErrCh := make(chan error, 1)
	go func() {
		res, err := hostEp.PairAccept(5000)
		if err != nil {
			pairErrCh <- err
			return
		}
		pairCh <- res
	}()

	cliPair, err := cliEp.PairInitiate(addr, "", code, "go-dev", "go")
	if err != nil {
		t.Fatalf("PairInitiate: %v", err)
	}
	select {
	case err := <-pairErrCh:
		t.Fatalf("PairAccept failed: %v", err)
	case acc := <-pairCh:
		if acc.SAS != cliPair.SAS {
			t.Fatalf("SAS mismatch: %s vs %s", acc.SAS, cliPair.SAS)
		}
		if err := hostEp.ConfirmPeer(acc.DeviceID, acc.SAS); err != nil {
			t.Fatalf("ConfirmPeer: %v", err)
		}
		if err := cliEp.ConfirmPeer("go-race-host", cliPair.SAS); err != nil {
			t.Fatalf("client ConfirmPeer: %v", err)
		}
		grant, err := hostEp.MintGrant(acc.DeviceID, []string{"fs.read"}, 3600)
		if err != nil {
			t.Fatalf("MintGrant: %v", err)
		}
		sessCh := make(chan *tendril.Session, 1)
		sessErrCh := make(chan error, 1)
		go func() {
			s, err := hostEp.AcceptSession(5000)
			if err != nil {
				sessErrCh <- err
				return
			}
			sessCh <- s
		}()

		cliSess, err := cliEp.Connect(addr, "", "go-race-host", grant)
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		defer cliSess.Close()

		var hostSess *tendril.Session
		select {
		case err := <-sessErrCh:
			t.Fatalf("AcceptSession failed: %v", err)
		case hostSess = <-sessCh:
		}
		defer hostSess.Close()

		// Free client endpoint before using cliSess to confirm lifetime independence.
		_ = cliEp.Close()

		if _, err := hostSess.PollEvent(0); !errors.Is(err, tendril.ErrWouldBlock) {
			t.Fatalf("expected ErrWouldBlock on PollEvent(0), got %v", err)
		}
		if err := cliSess.Rekey(); err != nil {
			t.Fatalf("Rekey: %v", err)
		}
		ev, err := hostSess.PollEvent(2000)
		if err != nil || ev.Event != "rekeyed" {
			t.Fatalf("expected rekeyed event, got %+v err=%v", ev, err)
		}
		if err := cliSess.SendData([]byte("post-rekey-go")); err != nil {
			t.Fatalf("SendData after Rekey: %v", err)
		}
		ev2, err := hostSess.PollEvent(2000)
		if err != nil || ev2.Event != "data" {
			t.Fatalf("expected data event, got %+v err=%v", ev2, err)
		}

		pollDone := make(chan error, 1)
		go func() {
			_, perr := hostSess.PollEvent(350)
			pollDone <- perr
		}()
		time.Sleep(30 * time.Millisecond)
		if got, err := hostSess.PeerID(); err != nil || got != acc.DeviceID {
			t.Fatalf("concurrent hostSess.PeerID() = %q err=%v, want %q", got, err, acc.DeviceID)
		}
		if got, err := cliSess.PeerID(); err != nil || got != "go-race-host" {
			t.Fatalf("cliSess.PeerID() = %q err=%v, want %q", got, err, "go-race-host")
		}
		if perr := <-pollDone; !errors.Is(perr, tendril.ErrWouldBlock) {
			t.Fatalf("expected ErrWouldBlock after concurrent PollEvent, got %v", perr)
		}
		_ = cliSess.Close()
		if _, err := cliSess.PeerID(); err == nil {
			t.Fatalf("expected PeerID() after Close() to fail")
		}
	}
	wg.Wait()
}

func TestServeP2pV2ZeroPeersAndEphemeral(t *testing.T) {
	ep, err := tendril.NewEndpoint("", "go-p2p-v2")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer ep.Close()

	if err := ep.ConfigureTransportsJSON(`{"p2p_ephemeral":true,"p2p_port_mapping":false}`); err != nil {
		t.Fatalf("ConfigureTransportsJSON: %v", err)
	}
	v2Ep, err := ep.ServeP2pV2("disabled", "")
	if err != nil {
		t.Fatalf("ServeP2pV2: %v", err)
	}
	if v2Ep != "iroh://v2" {
		t.Fatalf("ServeP2pV2 = %q, want iroh://v2", v2Ep)
	}

	ep1, err := ep.ServeP2p("disabled")
	if err != nil {
		t.Fatalf("ServeP2p 1: %v", err)
	}
	ep2, err := ep.ServeP2p("disabled")
	if err != nil {
		t.Fatalf("ServeP2p 2: %v", err)
	}
	id1 := strings.TrimPrefix(strings.SplitN(ep1, "?", 2)[0], "iroh://")
	id2 := strings.TrimPrefix(strings.SplitN(ep2, "?", 2)[0], "iroh://")
	if id1 == "" || id2 == "" || id1 == id2 {
		t.Fatalf("expected distinct ephemeral EndpointIds, got %q and %q", id1, id2)
	}
}

func TestServeP2pDisabledLoopback(t *testing.T) {
	hostEp, err := tendril.NewEndpoint("", "go-p2p-host")
	if err != nil {
		t.Fatalf("NewEndpoint host: %v", err)
	}
	defer hostEp.Close()

	cliEp, err := tendril.NewEndpoint("", "go-p2p-cli")
	if err != nil {
		t.Fatalf("NewEndpoint cli: %v", err)
	}
	defer cliEp.Close()

	p2pAddr, err := hostEp.ServeP2p("disabled")
	if err != nil {
		t.Fatalf("ServeP2p: %v", err)
	}
	code, err := hostEp.IssueCode("remote")
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}

	pairCh := make(chan tendril.PairAcceptResult, 1)
	pairErrCh := make(chan error, 1)
	go func() {
		res, err := hostEp.PairAccept(8000)
		if err != nil {
			pairErrCh <- err
			return
		}
		pairCh <- res
	}()

	cliPair, err := cliEp.PairInitiate(p2pAddr, "disabled", code, "go-p2p-dev", "go")
	if err != nil {
		t.Fatalf("PairInitiate p2p: %v", err)
	}
	var acc tendril.PairAcceptResult
	select {
	case err := <-pairErrCh:
		t.Fatalf("PairAccept p2p: %v", err)
	case acc = <-pairCh:
	}
	if err := hostEp.ConfirmPeer(acc.DeviceID, cliPair.SAS); err != nil {
		t.Fatalf("ConfirmPeer: %v", err)
	}
	if err := cliEp.ConfirmPeer("go-p2p-host", cliPair.SAS); err != nil {
		t.Fatalf("client ConfirmPeer p2p: %v", err)
	}
	grant, err := hostEp.MintGrant(acc.DeviceID, []string{"fs.read"}, 3600)
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}

	sessCh := make(chan *tendril.Session, 1)
	sessErrCh := make(chan error, 1)
	go func() {
		s, err := hostEp.AcceptSession(8000)
		if err != nil {
			sessErrCh <- err
			return
		}
		sessCh <- s
	}()

	cliSess, err := cliEp.Connect(p2pAddr, "disabled", "go-p2p-host", grant)
	if err != nil {
		t.Fatalf("Connect p2p: %v", err)
	}
	defer cliSess.Close()
	var hostSess *tendril.Session
	select {
	case err := <-sessErrCh:
		t.Fatalf("AcceptSession p2p: %v", err)
	case hostSess = <-sessCh:
	}
	defer hostSess.Close()

	if err := cliSess.SendData([]byte("go-p2p-ok")); err != nil {
		t.Fatalf("SendData p2p: %v", err)
	}
	ev, err := hostSess.PollEvent(2000)
	if err != nil || ev.Event != "data" {
		t.Fatalf("expected p2p data event, got %+v err=%v", ev, err)
	}
}

func TestNulByteRejection(t *testing.T) {
	var hh [32]byte
	if _, err := tendril.ComputeCodeMAC("4829-1704\x00EXTRA", hh); err == nil {
		t.Fatal("ComputeCodeMAC must reject interior NUL")
	}
	if _, err := tendril.VerifyGrantJSON("{}\x00", "{}", "s", "r", "fs.read\x00.delete", 1, ""); err == nil {
		t.Fatal("VerifyGrantJSON must reject interior NUL")
	}
	if _, err := tendril.VerifyRotationChainJSON("a\x00b", "c", 0, "[]", "d", "e"); err == nil {
		t.Fatal("VerifyRotationChainJSON must reject interior NUL")
	}
	if _, err := tendril.NewEndpoint("", "host\x00bad"); err == nil {
		t.Fatal("NewEndpoint must reject interior NUL")
	}
	ep, err := tendril.NewEndpoint("", "go-nul-host")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer ep.Close()
	if _, err := ep.ServeDirect("127.0.0.1:0\x00bad"); err == nil {
		t.Fatal("ServeDirect must reject interior NUL")
	}
	if _, err := ep.IssueCode("lan\x00"); err == nil {
		t.Fatal("IssueCode must reject interior NUL")
	}
	if err := ep.RevokePeer("dev_1234\x005678"); err == nil {
		t.Fatal("RevokePeer must reject interior NUL")
	}
}

func TestConcurrentEndpointCloseAndFullDuplexSession(t *testing.T) {
	hostEp, err := tendril.NewEndpoint("", "go-sec17-host")
	if err != nil {
		t.Fatalf("NewEndpoint host: %v", err)
	}
	cliEp, err := tendril.NewEndpoint("", "go-sec17-cli")
	if err != nil {
		t.Fatalf("NewEndpoint cli: %v", err)
	}

	addr, err := hostEp.ServeDirect("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	code, err := hostEp.IssueCode("lan")
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	pairCh := make(chan tendril.PairAcceptResult, 1)
	go func() {
		res, _ := hostEp.PairAccept(5000)
		pairCh <- res
	}()
	cliPair, err := cliEp.PairInitiate(addr, "", code, "go-dev", "go")
	if err != nil {
		t.Fatalf("PairInitiate: %v", err)
	}
	acc := <-pairCh
	if err := hostEp.ConfirmPeer(acc.DeviceID, acc.SAS); err != nil {
		t.Fatalf("ConfirmPeer: %v", err)
	}
	if err := cliEp.ConfirmPeer("go-sec17-host", cliPair.SAS); err != nil {
		t.Fatalf("cli ConfirmPeer: %v", err)
	}
	grant, err := hostEp.MintGrant(acc.DeviceID, []string{"fs.read"}, 3600)
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}

	sessCh := make(chan *tendril.Session, 1)
	go func() {
		s, err := hostEp.AcceptSession(5000)
		if err == nil {
			sessCh <- s
		}
	}()
	cliSess, err := cliEp.Connect(addr, "", "go-sec17-host", grant)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	hostSess := <-sessCh

	pollDone := make(chan error, 1)
	go func() {
		_, err := hostSess.PollEvent(5000)
		pollDone <- err
	}()
	time.Sleep(60 * time.Millisecond)

	t0 := time.Now()
	if allowed, err := hostSess.Authorize("fs.read"); err != nil || !allowed {
		t.Fatalf("Authorize failed while polling: allowed=%v err=%v", allowed, err)
	}
	if _, err := hostSess.Authorize("fs.read\x00.delete"); err == nil {
		t.Fatal("Authorize must reject interior NUL")
	}
	if err := hostSess.SendData([]byte("go-duplex-ok")); err != nil {
		t.Fatalf("SendData failed while polling: %v", err)
	}

	ev, err := cliSess.PollEvent(2000)
	if err != nil || ev.Event != "data" {
		t.Fatalf("expected cli data event while host polling, got %+v err=%v", ev, err)
	}
	if err := hostSess.Close(); err != nil {
		t.Fatalf("hostSess Close: %v", err)
	}
	if err := <-pollDone; !errors.Is(err, errors.New("EOF")) && err.Error() != "EOF" {
		t.Fatalf("expected EOF unblocking PollEvent on Close, got %v", err)
	}
	if time.Since(t0) > time.Second {
		t.Fatalf("full-duplex Go ops took too long: %v", time.Since(t0))
	}
	_ = cliSess.Close()
	_ = cliEp.Close()

	// Endpoint.Close() must wake blocked AcceptSession(5000) promptly without blocking Info().
	accErrCh := make(chan error, 1)
	go func() {
		_, err := hostEp.AcceptSession(5000)
		accErrCh <- err
	}()
	time.Sleep(60 * time.Millisecond)
	closeT0 := time.Now()
	if info, err := hostEp.Info(); err != nil || info.HostID != "go-sec17-host" {
		t.Fatalf("Info while AcceptSession parked failed: %+v err=%v", info, err)
	}
	if err := hostEp.Close(); err != nil {
		t.Fatalf("hostEp Close: %v", err)
	}
	if err := <-accErrCh; err == nil {
		t.Fatal("expected AcceptSession error after Endpoint.Close()")
	}
	if time.Since(closeT0) > time.Second {
		t.Fatalf("Endpoint.Close took too long: %v", time.Since(closeT0))
	}
}

func BenchmarkFFIOverhead(b *testing.B) {
	var key [32]byte
	key[0] = 0x42
	for b.Loop() {
		if _, err := tendril.DeviceID(key); err != nil {
			b.Fatal(err)
		}
	}
}

func TestM2mEnrollmentAndReplay(t *testing.T) {
	hostEp, err := tendril.NewEndpoint("", "go-m2m-host")
	if err != nil {
		t.Fatalf("NewEndpoint host: %v", err)
	}
	defer hostEp.Close()
	anchorEp, err := tendril.NewEndpoint("", "go-m2m-anchor")
	if err != nil {
		t.Fatalf("NewEndpoint anchor: %v", err)
	}
	defer anchorEp.Close()
	cliEp, err := tendril.NewEndpoint("", "go-m2m-cli")
	if err != nil {
		t.Fatalf("NewEndpoint cli: %v", err)
	}
	defer cliEp.Close()
	cli2Ep, err := tendril.NewEndpoint("", "go-m2m-cli2")
	if err != nil {
		t.Fatalf("NewEndpoint cli2: %v", err)
	}
	defer cli2Ep.Close()

	hostInfo, err := hostEp.Info()
	if err != nil {
		t.Fatalf("host Info: %v", err)
	}
	hostStatic, err := base64.RawURLEncoding.DecodeString(hostInfo.StaticPub)
	if err != nil {
		t.Fatalf("decode static: %v", err)
	}
	hostSigning, err := base64.RawURLEncoding.DecodeString(hostInfo.SigningPub)
	if err != nil {
		t.Fatalf("decode signing: %v", err)
	}
	if len(hostSigning) != tendril.SigningPubLen {
		t.Fatalf("expected %d-byte hybrid signing pub, got %d", tendril.SigningPubLen, len(hostSigning))
	}
	hostSigningHash, err := base64.RawURLEncoding.DecodeString(hostInfo.SigningPubHash)
	if err != nil {
		t.Fatalf("decode signing hash: %v", err)
	}
	if len(hostSigningHash) != tendril.SigningHashLen {
		t.Fatalf("expected %d-byte signing pub hash, got %d", tendril.SigningHashLen, len(hostSigningHash))
	}
	anchorInfo, err := anchorEp.Info()
	if err != nil {
		t.Fatalf("anchor Info: %v", err)
	}
	anchorSigning, err := base64.RawURLEncoding.DecodeString(anchorInfo.SigningPub)
	if err != nil {
		t.Fatalf("decode anchor signing: %v", err)
	}
	if len(anchorSigning) != tendril.SigningPubLen {
		t.Fatalf("expected %d-byte anchor signing pub, got %d", tendril.SigningPubLen, len(anchorSigning))
	}

	if err := hostEp.AddTrustAnchor("go-m2m-anchor", anchorSigning); err != nil {
		t.Fatalf("AddTrustAnchor: %v", err)
	}
	addr, err := hostEp.ServeDirect("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}

	tokJSON, err := anchorEp.MintEnrollmentToken("go-m2m-host", "", 900)
	if err != nil {
		t.Fatalf("MintEnrollmentToken: %v", err)
	}

	type accOutcome struct {
		res tendril.PairAcceptResult
		err error
	}
	accCh := make(chan accOutcome, 1)
	go func() {
		r, e := hostEp.PairAccept(5000)
		accCh <- accOutcome{res: r, err: e}
	}()
	initRes, err := cliEp.EnrollInitiate(addr, "", "go-m2m-host", hostStatic, hostSigning, 0, tokJSON, "go-worker", "machine")
	if err != nil {
		t.Fatalf("EnrollInitiate: %v", err)
	}
	acc := <-accCh
	if acc.err != nil {
		t.Fatalf("PairAccept M2M: %v", acc.err)
	}
	if initRes.Status != "active" || acc.res.Status != "active" || initRes.DeviceID != acc.res.DeviceID {
		t.Fatalf("unexpected M2M outcome: init=%+v acc=%+v", initRes, acc.res)
	}

	// Single-use token replay must fail closed with token_replayed.
	go func() {
		_, _ = hostEp.PairAccept(5000)
	}()
	if _, err := cliEp.EnrollInitiate(addr, "", "go-m2m-host", hostStatic, hostSigning, 0, tokJSON, "go-worker", "machine"); err == nil {
		t.Fatal("replayed M2M token must fail")
	}

	// Enrolled machine enters Active state with default-deny grants; minting enables session auth.
	grantJSON, err := hostEp.MintGrant(initRes.DeviceID, []string{"fs.read"}, 3600)
	if err != nil {
		t.Fatalf("MintGrant post-M2M: %v", err)
	}
	sessCh := make(chan *tendril.Session, 1)
	go func() {
		s, e := hostEp.AcceptSession(5000)
		if e == nil {
			sessCh <- s
		}
	}()
	cliSess, err := cliEp.Connect(addr, "", "go-m2m-host", grantJSON)
	if err != nil {
		t.Fatalf("Connect post-M2M: %v", err)
	}
	defer cliSess.Close()
	srvSess := <-sessCh
	defer srvSess.Close()
	if gotPeerID, err := cliSess.PeerID(); err != nil || gotPeerID != "go-m2m-host" {
		t.Fatalf("M2M cliSess.PeerID() = %q err=%v, want %q", gotPeerID, err, "go-m2m-host")
	}
	if gotPeerID, err := srvSess.PeerID(); err != nil || gotPeerID != initRes.DeviceID {
		t.Fatalf("M2M srvSess.PeerID() = %q err=%v, want %q", gotPeerID, err, initRes.DeviceID)
	}
	if allowed, err := srvSess.Authorize("fs.read"); err != nil || !allowed {
		t.Fatalf("Authorize fs.read failed: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := srvSess.Authorize("shell.exec"); err != nil || allowed {
		t.Fatalf("Authorize shell.exec must deny: allowed=%v err=%v", allowed, err)
	}

	// Revoking the sole trust anchor disables M2M policy -> unauthorized.
	if err := hostEp.RevokeTrustAnchor("go-m2m-anchor"); err != nil {
		t.Fatalf("RevokeTrustAnchor: %v", err)
	}
	freshTok, err := anchorEp.MintEnrollmentToken("go-m2m-host", "", 900)
	if err != nil {
		t.Fatalf("MintEnrollmentToken 2: %v", err)
	}
	go func() {
		_, _ = hostEp.PairAccept(5000)
	}()
	if _, err := cli2Ep.EnrollInitiate(addr, "", "go-m2m-host", hostStatic, hostSigning, 0, freshTok, "go-worker-2", "machine"); err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("revoked sole trust anchor token must fail with unauthorized, got: %v", err)
	}

	// Self-issued token re-enables M2M on host while still rejecting revoked anchor with untrusted_anchor.
	selfTok, err := hostEp.MintEnrollmentToken("go-m2m-host", "", 900)
	if err != nil {
		t.Fatalf("MintEnrollmentToken self: %v", err)
	}
	go func() {
		_, _ = hostEp.PairAccept(5000)
	}()
	if _, err := cli2Ep.EnrollInitiate(addr, "", "go-m2m-host", hostStatic, hostSigning, 0, freshTok, "go-worker-2", "machine"); err == nil || !strings.Contains(err.Error(), "untrusted_anchor") {
		t.Fatalf("revoked trust anchor under active M2M must fail with untrusted_anchor, got: %v", err)
	}
	go func() {
		r, e := hostEp.PairAccept(5000)
		accCh <- accOutcome{res: r, err: e}
	}()
	selfInitRes, err := cli2Ep.EnrollInitiate(addr, "", "go-m2m-host", hostStatic, hostSigningHash, 0, selfTok, "go-worker-2", "machine")
	if err != nil {
		t.Fatalf("EnrollInitiate self: %v", err)
	}
	selfAcc := <-accCh
	if selfAcc.err != nil || selfInitRes.Status != "active" || selfAcc.res.Status != "active" {
		t.Fatalf("self-issued M2M failed: init=%+v acc=%+v err=%v", selfInitRes, selfAcc.res, selfAcc.err)
	}
}

func TestConfigureTransportsJSONValidation(t *testing.T) {
	ep, err := tendril.NewEndpoint("", "go-cfg-test")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer ep.Close()

	if err := ep.ConfigureTransportsJSON("{}"); err != nil {
		t.Fatalf("ConfigureTransportsJSON empty object: %v", err)
	}

	// Unknown field must be rejected and secret scalars must never be echoed.
	secretSentinel := "super-secret-value-999"
	err = ep.ConfigureTransportsJSON(`{"relay_auth_secret":"` + secretSentinel + `","unknown_field":true}`)
	if err == nil {
		t.Fatalf("expected error for unknown_field")
	}
	if strings.Contains(err.Error(), secretSentinel) {
		t.Fatalf("error leaked secret scalar: %v", err)
	}

	// Scalar type mismatch must be rejected without leaking scalar values.
	err = ep.ConfigureTransportsJSON(`{"relay_auth_secret":12345}`)
	if err == nil {
		t.Fatalf("expected error for scalar type mismatch")
	}
	if strings.Contains(err.Error(), "12345") {
		t.Fatalf("error leaked scalar value: %v", err)
	}

	// NUL byte must be rejected.
	if err := ep.ConfigureTransportsJSON("{\x00}"); err == nil {
		t.Fatalf("expected error for NUL byte in transportConfigJSON")
	}
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func ensureRelayBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join("..", "..", "target", "debug", "tendril-relay")
	if _, err := os.Stat(bin); err == nil {
		return bin
	}
	cmd := exec.Command("cargo", "build", "-p", "tendril-relay", "--bin", "tendril-relay")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build tendril-relay: %v\n%s", err, out)
	}
	return bin
}

func spawnRelay(t *testing.T, extraEnv []string, args ...string) (string, string) {
	t.Helper()
	bin := ensureRelayBinary(t)
	fullArgs := append([]string{"--listen", "127.0.0.1:0", "--host", "127.0.0.1"}, args...)
	cmd := exec.Command(bin, fullArgs...)
	cmd.Env = append(os.Environ(), append([]string{"RUST_LOG=info"}, extraEnv...)...)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("relay stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("relay stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start tendril-relay: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	urlCh := make(chan string, 1)
	var mu sync.Mutex
	var logs bytes.Buffer
	scan := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := ansiRe.ReplaceAllString(sc.Text(), "")
			mu.Lock()
			logs.WriteString(line)
			logs.WriteByte('\n')
			mu.Unlock()
			if idx := strings.Index(line, "ws://127.0.0.1:"); idx >= 0 {
				rest := line[idx:]
				if end := strings.IndexAny(rest, " \t\r\n\""); end >= 0 {
					rest = rest[:end]
				}
				if strings.HasSuffix(rest, "/v1/relay") {
					select {
					case urlCh <- rest:
					default:
					}
				}
			}
		}
	}
	go scan(stdoutPipe)
	go scan(stderrPipe)

	select {
	case v1URL := <-urlCh:
		v2URL := strings.TrimSuffix(v1URL, "/v1/relay") + "/v2/relay"
		return v1URL, v2URL
	case <-time.After(10 * time.Second):
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("timed out waiting for tendril-relay startup; logs:\n%s", logs.String())
		return "", ""
	}
}

func TestRelayAdmissionHMACAndTickets(t *testing.T) {
	// 1. HMAC-gated relay (/v1/relay and /v2/relay)
	const hmacSecret = "shared-relay-hmac-secret-123"
	v1URL, v2URL := spawnRelay(t, []string{"TENDRIL_RELAY_AUTH_SECRET=" + hmacSecret}, "--auth-scope", "all")

	hostEp, err := tendril.NewEndpoint("", "go-hmac-host")
	if err != nil {
		t.Fatalf("NewEndpoint host: %v", err)
	}
	defer hostEp.Close()
	cliEp, err := tendril.NewEndpoint("", "go-hmac-cli")
	if err != nil {
		t.Fatalf("NewEndpoint cli: %v", err)
	}
	defer cliEp.Close()

	// Negative control: unconfigured and wrong-secret ServeRelay rejected.
	if _, err := hostEp.ServeRelay(v1URL, "127.0.0.1"); err == nil {
		t.Fatalf("expected unconfigured ServeRelay to fail on HMAC-gated relay")
	}
	if err := hostEp.ConfigureTransportsJSON(`{"relay_auth_secret":"wrong-secret"}`); err != nil {
		t.Fatalf("ConfigureTransportsJSON wrong: %v", err)
	}
	if _, err := hostEp.ServeRelay(v1URL, "127.0.0.1"); err == nil {
		t.Fatalf("expected wrong-secret ServeRelay to fail")
	}

	// Positive control: matching HMAC secret succeeds on /v1/relay and /v2/relay.
	cfgJSON := `{"relay_auth_secret":"` + hmacSecret + `"}`
	if err := hostEp.ConfigureTransportsJSON(cfgJSON); err != nil {
		t.Fatalf("ConfigureTransportsJSON host: %v", err)
	}
	relayV1Ep, err := hostEp.ServeRelay(v1URL, "127.0.0.1")
	if err != nil {
		t.Fatalf("ServeRelay with HMAC: %v", err)
	}
	code, err := hostEp.IssueCode("remote")
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}

	// Negative control: unconfigured client rejected on /v1/relay pair.
	if _, err := cliEp.PairV2Initiate(relayV1Ep, "127.0.0.1", code, "cli", "go", ""); err == nil {
		t.Fatalf("expected unconfigured client PairV2Initiate to fail on HMAC-gated relay")
	}
	if err := cliEp.ConfigureTransportsJSON(cfgJSON); err != nil {
		t.Fatalf("ConfigureTransportsJSON cli: %v", err)
	}

	type accRes struct {
		r   tendril.PairAcceptResult
		err error
	}
	accCh := make(chan accRes, 1)
	go func() {
		r, e := hostEp.PairV2Accept(5000)
		accCh <- accRes{r, e}
	}()
	pInit, err := cliEp.PairV2Initiate(relayV1Ep, "127.0.0.1", code, "go-hmac-dev", "go", "")
	if err != nil {
		t.Fatalf("PairV2Initiate over HMAC relay: %v", err)
	}
	pAcc := <-accCh
	if pAcc.err != nil || pAcc.r.SAS != pInit.SAS {
		t.Fatalf("PairV2Accept failed: %+v", pAcc)
	}
	if err := hostEp.ConfirmPeer(pAcc.r.DeviceID, pAcc.r.SAS); err != nil {
		t.Fatalf("host ConfirmPeer: %v", err)
	}
	if err := cliEp.ConfirmPeer("go-hmac-host", pInit.SAS); err != nil {
		t.Fatalf("cli ConfirmPeer: %v", err)
	}
	grantJSON, err := hostEp.MintGrant(pAcc.r.DeviceID, []string{"fs.read"}, 300)
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}

	// ServeRelayV2 on /v2/relay and ConnectV2/AcceptV2.
	relayV2Ep, err := hostEp.ServeRelayV2(v2URL, "127.0.0.1", "")
	if err != nil {
		t.Fatalf("ServeRelayV2 with HMAC: %v", err)
	}
	// Negative control: wrong secret on client rejected on /v2/relay.
	if err := cliEp.ConfigureTransportsJSON(`{"relay_auth_secret":"wrong-secret"}`); err != nil {
		t.Fatalf("ConfigureTransportsJSON wrong cli: %v", err)
	}
	if _, err := cliEp.ConnectV2(relayV2Ep, "127.0.0.1", "go-hmac-host", grantJSON); err == nil {
		t.Fatalf("expected wrong-secret ConnectV2 to fail on HMAC /v2/relay")
	}
	if err := cliEp.ConfigureTransportsJSON(cfgJSON); err != nil {
		t.Fatalf("ConfigureTransportsJSON restore cli: %v", err)
	}

	sessCh := make(chan *tendril.Session, 1)
	go func() {
		s, e := hostEp.AcceptV2(5000)
		if e == nil {
			sessCh <- s
		}
	}()
	cliSess, err := cliEp.ConnectV2(relayV2Ep, "127.0.0.1", "go-hmac-host", grantJSON)
	if err != nil {
		t.Fatalf("ConnectV2 over HMAC /v2/relay: %v", err)
	}
	defer cliSess.Close()
	hostSess := <-sessCh
	defer hostSess.Close()

	if err := cliSess.SendData([]byte("hmac-v2-ok")); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	ev, err := hostSess.PollEvent(3000)
	if err != nil || ev.Event != "data" {
		t.Fatalf("PollEvent: ev=%+v err=%v", ev, err)
	}
	got, _ := base64.RawURLEncoding.DecodeString(ev.DataB64)
	if string(got) != "hmac-v2-ok" {
		t.Fatalf("unexpected payload: %q", got)
	}

	// 2. Ticket-gated relay (/v1/relay and /v2/relay)
	issuerEp, err := tendril.NewEndpoint("", "go-ticket-issuer")
	if err != nil {
		t.Fatalf("NewEndpoint issuer: %v", err)
	}
	defer issuerEp.Close()
	issuerInfo, err := issuerEp.Info()
	if err != nil {
		t.Fatalf("issuer Info: %v", err)
	}
	tv1URL, tv2URL := spawnRelay(t, nil, "--issuer-pub", issuerInfo.RelayPub, "--auth-scope", "all")

	regTicket, err := issuerEp.MintRelayTicket("127.0.0.1", "register", "*", 300)
	if err != nil {
		t.Fatalf("MintRelayTicket register: %v", err)
	}
	dialTicket, err := issuerEp.MintRelayTicket("127.0.0.1", "dial", "*", 300)
	if err != nil {
		t.Fatalf("MintRelayTicket dial: %v", err)
	}

	tHost, err := tendril.NewEndpoint("", "go-ticket-host")
	if err != nil {
		t.Fatalf("NewEndpoint tHost: %v", err)
	}
	defer tHost.Close()
	tCli, err := tendril.NewEndpoint("", "go-ticket-cli")
	if err != nil {
		t.Fatalf("NewEndpoint tCli: %v", err)
	}
	defer tCli.Close()

	// Wrong-role ticket (dial) rejected for register.
	if err := tHost.ConfigureTransportsJSON(`{"relay_ticket":` + dialTicket + `}`); err != nil {
		t.Fatalf("ConfigureTransportsJSON dial ticket on host: %v", err)
	}
	if _, err := tHost.ServeRelay(tv1URL, "127.0.0.1"); err == nil {
		t.Fatalf("expected dial-role ticket to be rejected for ServeRelay")
	}

	if err := tHost.ConfigureTransportsJSON(`{"relay_ticket":` + regTicket + `}`); err != nil {
		t.Fatalf("ConfigureTransportsJSON reg ticket on host: %v", err)
	}
	tV1Ep, err := tHost.ServeRelay(tv1URL, "127.0.0.1")
	if err != nil {
		t.Fatalf("ServeRelay with register ticket: %v", err)
	}
	tCode, err := tHost.IssueCode("remote")
	if err != nil {
		t.Fatalf("tHost IssueCode: %v", err)
	}

	// Wrong-role ticket (register) rejected for dial.
	if err := tCli.ConfigureTransportsJSON(`{"relay_ticket":` + regTicket + `}`); err != nil {
		t.Fatalf("ConfigureTransportsJSON reg ticket on cli: %v", err)
	}
	if _, err := tCli.PairV2Initiate(tV1Ep, "127.0.0.1", tCode, "tcli", "go", ""); err == nil {
		t.Fatalf("expected register-role ticket to be rejected for PairV2Initiate")
	}

	if err := tCli.ConfigureTransportsJSON(`{"relay_ticket":` + dialTicket + `}`); err != nil {
		t.Fatalf("ConfigureTransportsJSON dial ticket on cli: %v", err)
	}
	go func() {
		r, e := tHost.PairV2Accept(5000)
		accCh <- accRes{r, e}
	}()
	tpInit, err := tCli.PairV2Initiate(tV1Ep, "127.0.0.1", tCode, "tcli", "go", "")
	if err != nil {
		t.Fatalf("PairV2Initiate with dial ticket: %v", err)
	}
	tpAcc := <-accCh
	if tpAcc.err != nil || tpAcc.r.SAS != tpInit.SAS {
		t.Fatalf("PairV2Accept with ticket failed: %+v", tpAcc)
	}
	if err := tHost.ConfirmPeer(tpAcc.r.DeviceID, tpAcc.r.SAS); err != nil {
		t.Fatalf("tHost ConfirmPeer: %v", err)
	}
	if err := tCli.ConfirmPeer("go-ticket-host", tpInit.SAS); err != nil {
		t.Fatalf("tCli ConfirmPeer: %v", err)
	}
	tGrant, err := tHost.MintGrant(tpAcc.r.DeviceID, []string{"fs.read"}, 300)
	if err != nil {
		t.Fatalf("tHost MintGrant: %v", err)
	}

	tV2Ep, err := tHost.ServeRelayV2(tv2URL, "127.0.0.1", "")
	if err != nil {
		t.Fatalf("ServeRelayV2 with register ticket: %v", err)
	}
	go func() {
		s, e := tHost.AcceptV2(5000)
		if e == nil {
			sessCh <- s
		}
	}()
	tCliSess, err := tCli.ConnectV2(tV2Ep, "127.0.0.1", "go-ticket-host", tGrant)
	if err != nil {
		t.Fatalf("ConnectV2 with dial ticket: %v", err)
	}
	defer tCliSess.Close()
	tHostSess := <-sessCh
	defer tHostSess.Close()

	if err := tCliSess.SendData([]byte("ticket-v2-ok")); err != nil {
		t.Fatalf("tCliSess SendData: %v", err)
	}
	tev, err := tHostSess.PollEvent(3000)
	if err != nil || tev.Event != "data" {
		t.Fatalf("tHostSess PollEvent: ev=%+v err=%v", tev, err)
	}
	tGot, _ := base64.RawURLEncoding.DecodeString(tev.DataB64)
	if string(tGot) != "ticket-v2-ok" {
		t.Fatalf("unexpected ticket payload: %q", tGot)
	}
}

func TestWireV2ConformancePeerInterop(t *testing.T) {
	// Direction 1: Rust conformance_peer serves v2, Go dials PairV2Initiate + ConnectV2.
	peer := spawnPeer(t)
	goClient, err := tendril.NewEndpoint("", "go-v2-client")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer goClient.Close()

	peer.call(t, map[string]any{"op": "init", "host_id": "rust-v2-peer"})
	srv := peer.call(t, map[string]any{"op": "serve_direct"})
	ep := srv["endpoint"].(string)
	code := peer.call(t, map[string]any{"op": "issue_code", "kind": "lan"})["code"].(string)

	peer.send(t, map[string]any{"op": "pair_v2_accept", "timeout_ms": 5000})
	pairRes, err := goClient.PairV2Initiate(ep, "", code, "go-v2-dev", "go", "")
	if err != nil {
		t.Fatalf("Go PairV2Initiate: %v", err)
	}
	if pairRes.WireVersion != 2 {
		t.Fatalf("expected WireVersion=2, got %d", pairRes.WireVersion)
	}
	peerPair := peer.recv(t)
	if ok, _ := peerPair["ok"].(bool); !ok || peerPair["sas"] != pairRes.SAS {
		t.Fatalf("v2 pair SAS mismatch: go=%s peer=%v", pairRes.SAS, peerPair)
	}
	cliDevID := peerPair["device_id"].(string)

	peer.call(t, map[string]any{"op": "confirm", "peer_id": cliDevID, "sas": pairRes.SAS})
	grantBytes, _ := json.Marshal(peer.call(t, map[string]any{
		"op": "mint", "peer_id": cliDevID, "caps": []string{"fs.read"},
	})["grant"])
	if err := goClient.ConfirmPeer("rust-v2-peer", pairRes.SAS); err != nil {
		t.Fatalf("Go ConfirmPeer: %v", err)
	}

	peer.send(t, map[string]any{"op": "accept_v2", "timeout_ms": 5000})
	sess, err := goClient.ConnectV2(ep, "", "rust-v2-peer", string(grantBytes))
	if err != nil {
		t.Fatalf("Go ConnectV2: %v", err)
	}
	defer sess.Close()
	if ok, _ := peer.recv(t)["ok"].(bool); !ok {
		t.Fatalf("peer accept_v2 failed")
	}
	if gotPeerID, err := sess.PeerID(); err != nil || gotPeerID != "rust-v2-peer" {
		t.Fatalf("Go v2 sess.PeerID() = %q err=%v, want %q", gotPeerID, err, "rust-v2-peer")
	}

	if err := sess.SendData([]byte("v2-hello-from-go")); err != nil {
		t.Fatalf("Go SendData: %v", err)
	}
	ev := peer.call(t, map[string]any{"op": "recv", "timeout_ms": 2000})
	if ev["event"] != "data" || ev["data_utf8"] != "v2-hello-from-go" {
		t.Fatalf("unexpected peer recv: %v", ev)
	}
	if err := sess.Rekey(); err != nil {
		t.Fatalf("Go v2 Rekey: %v", err)
	}
	peer.call(t, map[string]any{"op": "send", "data_utf8": "v2-reply-from-rust"})
	// Drain rekey/data events.
	var gotData string
	for i := 0; i < 4; i++ {
		goEv, err := sess.PollEvent(2000)
		if err != nil {
			t.Fatalf("Go PollEvent: %v", err)
		}
		if goEv.Event == "data" {
			b, _ := base64.RawURLEncoding.DecodeString(goEv.DataB64)
			gotData = string(b)
			break
		}
	}
	if gotData != "v2-reply-from-rust" {
		t.Fatalf("unexpected Go v2 payload: %q", gotData)
	}
	if allowed, err := sess.Authorize("fs.read"); err != nil || !allowed {
		t.Fatalf("Go v2 Authorize fs.read: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := sess.Authorize("shell.exec"); err != nil || allowed {
		t.Fatalf("Go v2 Authorize shell.exec expected false: allowed=%v err=%v", allowed, err)
	}

	// Revoke peer on host side, close session, and verify subsequent ConnectV2 fails.
	peer.call(t, map[string]any{"op": "revoke", "peer_id": cliDevID})
	_ = sess.CloseSession(1000, "revoked")
	peer.send(t, map[string]any{"op": "accept_v2", "timeout_ms": 3000})
	if _, err := goClient.ConnectV2(ep, "", "rust-v2-peer", string(grantBytes)); err == nil {
		t.Fatalf("expected ConnectV2 after peer revocation to fail")
	}
	_ = peer.recv(t)
	peer.call(t, map[string]any{"op": "shutdown"})

	// Direction 2: Go serves PairV2Accept + ServeRelayV2 + AcceptV2 against conformance_peer.
	_, v2URL := spawnRelay(t, nil)
	goHost, err := tendril.NewEndpoint("", "go-v2-host")
	if err != nil {
		t.Fatalf("NewEndpoint goHost: %v", err)
	}
	defer goHost.Close()
	hostEp, err := goHost.ServeDirect("")
	if err != nil {
		t.Fatalf("Go ServeDirect: %v", err)
	}
	code2, err := goHost.IssueCode("lan")
	if err != nil {
		t.Fatalf("Go IssueCode: %v", err)
	}
	peer2 := spawnPeer(t)
	peer2.call(t, map[string]any{"op": "init", "host_id": "rust-v2-client"})
	peer2.send(t, map[string]any{"op": "pair_v2_initiate", "endpoint": hostEp, "code": code2})
	accPair, err := goHost.PairV2Accept(5000)
	if err != nil {
		t.Fatalf("Go PairV2Accept: %v", err)
	}
	if accPair.WireVersion != 2 {
		t.Fatalf("expected accPair WireVersion=2, got %d", accPair.WireVersion)
	}
	p2Pair := peer2.recv(t)
	if ok, _ := p2Pair["ok"].(bool); !ok || p2Pair["sas"] != accPair.SAS {
		t.Fatalf("PairV2Accept SAS mismatch: %s vs %v", accPair.SAS, p2Pair)
	}
	if err := goHost.ConfirmPeer(accPair.DeviceID, accPair.SAS); err != nil {
		t.Fatalf("Go ConfirmPeer: %v", err)
	}
	peer2.call(t, map[string]any{"op": "confirm", "peer_id": "go-v2-host", "sas": accPair.SAS})
	grantJSON2, err := goHost.MintGrant(accPair.DeviceID, []string{"fs.read"}, 300)
	if err != nil {
		t.Fatalf("Go MintGrant: %v", err)
	}
	var grantVal2 any
	_ = json.Unmarshal([]byte(grantJSON2), &grantVal2)

	relayV2Ep, err := goHost.ServeRelayV2(v2URL, "127.0.0.1", accPair.DeviceID)
	if err != nil {
		t.Fatalf("Go ServeRelayV2: %v", err)
	}
	peer2.send(t, map[string]any{
		"op": "connect_v2", "endpoint": relayV2Ep, "target_host_id": "go-v2-host", "grant": grantVal2,
	})
	hostSess, err := goHost.AcceptV2(5000)
	if err != nil {
		t.Fatalf("Go AcceptV2: %v", err)
	}
	defer hostSess.Close()
	if ok, _ := peer2.recv(t)["ok"].(bool); !ok {
		t.Fatalf("peer2 connect_v2 failed")
	}
	if gotPeerID, err := hostSess.PeerID(); err != nil || gotPeerID != accPair.DeviceID {
		t.Fatalf("Go AcceptV2 hostSess.PeerID() = %q err=%v, want %q", gotPeerID, err, accPair.DeviceID)
	}
	if allowed, err := hostSess.Authorize("fs.read"); err != nil || !allowed {
		t.Fatalf("Go AcceptV2 Authorize fs.read failed: allowed=%v err=%v", allowed, err)
	}
	if err := goHost.RevokePeer(accPair.DeviceID); err != nil {
		t.Fatalf("Go RevokePeer: %v", err)
	}
	if gotPeerID, err := hostSess.PeerID(); err != nil || gotPeerID != accPair.DeviceID {
		t.Fatalf("Go post-revoke PeerID() = %q err=%v, want %q", gotPeerID, err, accPair.DeviceID)
	}
	if allowed, err := hostSess.Authorize("fs.read"); err != nil || allowed {
		t.Fatalf("Go Authorize after RevokePeer expected false: allowed=%v err=%v", allowed, err)
	}
	_ = hostSess.CloseSession(1000, "done")
	peer2.call(t, map[string]any{"op": "shutdown"})
}

type rosterDoc struct {
	Entries map[string]struct {
		State  string            `json:"state"`
		Grants []json.RawMessage `json:"grants"`
	} `json:"entries"`
}

func parseRoster(t *testing.T, raw []byte) rosterDoc {
	t.Helper()
	var doc rosterDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse roster: %v", err)
	}
	return doc
}

func TestRevokePeerRacesPollEventAndAuthorize(t *testing.T) {
	hostDir := t.TempDir()
	cliDir := t.TempDir()
	hostEp, err := tendril.NewEndpoint(hostDir, "go-sec04-host")
	if err != nil {
		t.Fatalf("NewEndpoint host: %v", err)
	}
	defer hostEp.Close()
	cliEp, err := tendril.NewEndpoint(cliDir, "")
	if err != nil {
		t.Fatalf("NewEndpoint cli: %v", err)
	}
	defer cliEp.Close()

	addr, err := hostEp.ServeDirect("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	code, err := hostEp.IssueCode("lan")
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	pairCh := make(chan tendril.PairAcceptResult, 1)
	pairErr := make(chan error, 1)
	go func() {
		res, err := hostEp.PairAccept(5000)
		if err != nil {
			pairErr <- err
			return
		}
		pairCh <- res
	}()
	cliPair, err := cliEp.PairInitiate(addr, "", code, "go-dev", "go")
	if err != nil {
		t.Fatalf("PairInitiate: %v", err)
	}
	var acc tendril.PairAcceptResult
	select {
	case err := <-pairErr:
		t.Fatalf("PairAccept: %v", err)
	case acc = <-pairCh:
	}
	if err := hostEp.ConfirmPeer(acc.DeviceID, acc.SAS); err != nil {
		t.Fatalf("host ConfirmPeer: %v", err)
	}
	if err := cliEp.ConfirmPeer("go-sec04-host", cliPair.SAS); err != nil {
		t.Fatalf("cli ConfirmPeer: %v", err)
	}
	grant, err := hostEp.MintGrant(acc.DeviceID, []string{"fs.read"}, 3600)
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}

	sessCh := make(chan *tendril.Session, 1)
	sessErr := make(chan error, 1)
	go func() {
		s, err := hostEp.AcceptSession(5000)
		if err != nil {
			sessErr <- err
			return
		}
		sessCh <- s
	}()
	cliSess, err := cliEp.Connect(addr, "", "go-sec04-host", grant)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer cliSess.Close()
	var hostSess *tendril.Session
	select {
	case err := <-sessErr:
		t.Fatalf("AcceptSession: %v", err)
	case hostSess = <-sessCh:
	}
	defer hostSess.Close()

	if ok, err := hostSess.Authorize("fs.read"); err != nil || !ok {
		t.Fatalf("authorize before revoke: ok=%v err=%v", ok, err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					fn()
				}
			}
		}()
	}
	run(func() { _, _ = hostSess.PollEvent(5) })
	run(func() { _, _ = hostSess.Authorize("fs.read") })
	run(func() {
		_ = cliSess.SendData([]byte("x"))
		_ = cliSess.Rekey()
		time.Sleep(time.Millisecond)
	})
	run(func() {
		if s, err := hostEp.Connect("127.0.0.1:1", "", "nobody", ""); err == nil {
			_ = s.Close()
			t.Errorf("connect to a dead endpoint must fail")
		}
	})

	time.Sleep(30 * time.Millisecond)
	if err := hostEp.RevokePeer(acc.DeviceID); err != nil {
		t.Fatalf("RevokePeer: %v", err)
	}
	for range 200 {
		ok, err := hostSess.Authorize("fs.read")
		if err != nil {
			t.Fatalf("Authorize after revoke: %v", err)
		}
		if ok {
			t.Fatalf("authorize must deny immediately after RevokePeer")
		}
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()

	for name, export := range map[string]func() ([]byte, error){
		"endpoint": hostEp.ExportRosterJSON,
		"session":  hostSess.ExportRosterJSON,
	} {
		raw, err := export()
		if err != nil {
			t.Fatalf("%s ExportRosterJSON: %v", name, err)
		}
		doc := parseRoster(t, raw)
		for i := range raw {
			raw[i] = 0
		}
		entry, ok := doc.Entries[acc.DeviceID]
		if !ok || entry.State != "revoked" || len(entry.Grants) != 0 {
			t.Fatalf("%s roster resurrected revoked peer: %+v", name, entry)
		}
	}
	disk, err := os.ReadFile(filepath.Join(hostDir, "roster.json"))
	if err != nil {
		t.Fatalf("read roster.json: %v", err)
	}
	if entry := parseRoster(t, disk).Entries[acc.DeviceID]; entry.State != "revoked" {
		t.Fatalf("disk roster resurrected revoked peer: %+v", entry)
	}
}

func hexBytes(t *testing.T, m map[string]any, key string) []byte {
	t.Helper()
	s, ok := m[key].(string)
	if !ok {
		t.Fatalf("vector key %q missing", key)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("vector key %q: %v", key, err)
	}
	return b
}

// TestRoutesVectors checks spec/vectors/routes.json byte for byte with the Go standard library.
// The Ed25519 half of each signature, the URI bytes and the key material are verified here; the
// ML-DSA half and the 0x0C codec are core-only and covered by the Rust vector tests.
func TestRoutesVectors(t *testing.T) {
	doc := readJSONFile(t, "routes.json")
	keys := doc["route_set"].(map[string]any)

	seed := hexBytes(t, keys, "signing_seed_hex")
	signingPub := hexBytes(t, keys, "signing_pub_hex")
	edKey := ed25519.NewKeyFromSeed(seed)
	edPub := edKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(edPub, signingPub[:ed25519.PublicKeySize]) {
		t.Fatalf("Ed25519 half of signing_pub_hex does not derive from signing_seed_hex")
	}
	sh := sha256.Sum256(signingPub)
	if !bytes.Equal(sh[:], hexBytes(t, keys, "sh_hex")) {
		t.Fatalf("sh_hex is not SHA-256 of signing_pub_hex")
	}
	staticPriv, err := ecdh.X25519().NewPrivateKey(hexBytes(t, keys, "static_scalar_hex"))
	if err != nil {
		t.Fatalf("static scalar: %v", err)
	}
	if !bytes.Equal(staticPriv.PublicKey().Bytes(), hexBytes(t, keys, "static_pub_hex")) {
		t.Fatalf("static_pub_hex does not derive from static_scalar_hex")
	}

	// Pairing URI route statement (rs): exact input bytes, deterministic Ed25519 signature, URI text.
	rs := doc["pairing_route_statement"].(map[string]any)
	if !bytes.Equal(hexBytes(t, rs, "ed25519_pub_hex"), edPub) {
		t.Fatalf("ed25519_pub_hex mismatch")
	}
	domain := hexBytes(t, rs, "domain_hex")
	if string(domain) != "tendril-pairing-routes-v1\x00" {
		t.Fatalf("unexpected rs domain %q", domain)
	}
	prefix := rs["uri_bytes_before_rs"].(string)
	input := append(append([]byte{}, domain...), prefix...)
	if !bytes.Equal(input, hexBytes(t, rs, "rs_input_hex")) {
		t.Fatalf("rs_input_hex mismatch")
	}
	sig := ed25519.Sign(edKey, input)
	if !bytes.Equal(sig, hexBytes(t, rs, "rs_hex")) {
		t.Fatalf("rs signature mismatch: %x", sig)
	}
	if !ed25519.Verify(edPub, input, sig) {
		t.Fatalf("rs does not verify")
	}
	uri := rs["uri"].(string)
	if want := prefix + "&rs=" + base64.RawURLEncoding.EncodeToString(sig); uri != want {
		t.Fatalf("uri mismatch:\n got %s\nwant %s", uri, want)
	}
	hints := rs["hints"].([]any)
	var escaped []string
	for _, h := range hints {
		escaped = append(escaped, url.QueryEscape(h.(string)))
	}
	if !strings.Contains(uri, "&ep="+strings.Join(escaped, ",")+"&rq=") {
		t.Fatalf("uri ep does not carry the vector hints in order")
	}
	if want := "&rq=" + strconv.FormatUint(uint64(rs["route_seq"].(float64)), 10); !strings.HasSuffix(prefix, want) {
		t.Fatalf("uri prefix does not end with %s", want)
	}

	// The same URI is host-signed for a key this endpoint does not know: the FFI parses it and
	// reports an unknown host rather than a malformed URI.
	ep, err := tendril.NewEndpoint("", "go-vector-ep")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer ep.Close()
	if _, err := ep.ApplyRouteURI(uri, nil); err == nil || !strings.Contains(err.Error(), "(-2)") {
		t.Fatalf("expected not-found for the vector host, got %v", err)
	}

	// Route set: signed bytes are domain || body, the wire payload is body || sig, and the
	// Ed25519 half of the hybrid signature is deterministic.
	setDomain := hexBytes(t, keys, "domain_hex")
	if string(setDomain) != "tendril-route-set-v1\x00" {
		t.Fatalf("unexpected route set domain %q", setDomain)
	}
	cases := keys["sign_deterministic"].([]any)
	if len(cases) < 2 {
		t.Fatalf("expected at least two sign_deterministic cases")
	}
	for _, c := range cases {
		cm := c.(map[string]any)
		name := cm["name"].(string)
		body := hexBytes(t, cm, "body_hex")
		hsig := hexBytes(t, cm, "sig_hex")
		if len(hsig) != 3373 {
			t.Fatalf("%s: hybrid signature length %d", name, len(hsig))
		}
		signed := append(append([]byte{}, setDomain...), body...)
		if !bytes.Equal(signed, hexBytes(t, cm, "signed_bytes_hex")) {
			t.Fatalf("%s: signed_bytes_hex mismatch", name)
		}
		if got := ed25519.Sign(edKey, signed); !bytes.Equal(got, hsig[:ed25519.SignatureSize]) {
			t.Fatalf("%s: Ed25519 half mismatch", name)
		}
		if !ed25519.Verify(edPub, signed, hsig[:ed25519.SignatureSize]) {
			t.Fatalf("%s: Ed25519 half does not verify", name)
		}
		if !bytes.Contains(body, hexBytes(t, keys, "static_pub_hex")) || !bytes.Contains(body, hexBytes(t, keys, "sh_hex")) {
			t.Fatalf("%s: body lacks host static key or signing hash", name)
		}
		for _, r := range cm["routes"].([]any) {
			if !bytes.Contains(body, []byte(r.(string))) {
				t.Fatalf("%s: body lacks route %v", name, r)
			}
		}
	}
	// Fixture shape check only: the decoder rejections themselves are asserted by the Rust tests.
	for _, c := range keys["decode_rejections"].([]any) {
		cm := c.(map[string]any)
		hexBytes(t, cm, "body_hex")
		if cm["zero_filler_len"].(float64) < 0 {
			t.Fatalf("%s: negative filler", cm["name"])
		}
	}

	hello := doc["session_hello_route_seq"].(map[string]any)
	var parsed struct {
		DeviceID string `json:"device_id"`
		RouteSeq uint64 `json:"route_seq"`
	}
	if err := json.Unmarshal([]byte(hello["json"].(string)), &parsed); err != nil {
		t.Fatalf("session hello json: %v", err)
	}
	if float64(parsed.RouteSeq) != hello["route_seq"].(float64) {
		t.Fatalf("session hello route_seq mismatch")
	}
}

type routesHost struct {
	ep       *tendril.Endpoint
	hostID   string
	listen   string
	clientEp *tendril.Endpoint
	deviceID string
	grant    string
}

func hostIDOf(t *testing.T, ep *tendril.Endpoint) string {
	t.Helper()
	info, err := ep.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	return info.HostID
}

// acceptPairing waits for one real pairing on ep. A foreign loopback probe fails its handshake
// without consuming the code, so failures are retried until the deadline.
func acceptPairing(ep *tendril.Endpoint, v2 bool) (tendril.PairAcceptResult, error) {
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		var res tendril.PairAcceptResult
		var err error
		if v2 {
			res, err = ep.PairV2Accept(5000)
		} else {
			res, err = ep.PairAccept(5000)
		}
		if err == nil {
			return res, nil
		}
		last = err
		if strings.Contains(err.Error(), "closed") {
			break
		}
	}
	return tendril.PairAcceptResult{}, last
}

// pairThroughURI pairs client with host through uri and confirms on the host.
func pairThroughURI(t *testing.T, host, client *tendril.Endpoint, uri string, v2 bool, opts *tendril.PairURIOptions) tendril.PairURIResult {
	t.Helper()
	type accepted struct {
		res tendril.PairAcceptResult
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		res, err := acceptPairing(host, v2)
		ch <- accepted{res, err}
	}()
	var res tendril.PairURIResult
	var err error
	if v2 {
		res, err = client.PairV2URI(uri, "go-client", "go", opts)
	} else {
		res, err = client.PairURI(uri, "go-client", "go", opts)
	}
	if err != nil {
		t.Fatalf("pair (v2=%v): %v", v2, err)
	}
	acc := <-ch
	if acc.err != nil {
		t.Fatalf("pair accept: %v", acc.err)
	}
	if acc.res.SAS != res.SAS {
		t.Fatalf("SAS mismatch: %s vs %s", acc.res.SAS, res.SAS)
	}
	if err := host.ConfirmPeer(acc.res.DeviceID, acc.res.SAS); err != nil {
		t.Fatalf("host ConfirmPeer: %v", err)
	}
	return res
}

// connectPair connects client with connect while host accepts, retrying the accept past foreign probes.
// The accept loop stops when connect fails, when connect succeeds but the host returns no session
// within acceptGrace, and at a hard deadline, so a stuck handshake cannot hang the test.
func connectPair(t *testing.T, host *tendril.Endpoint, v2 bool, connect func() (*tendril.Session, error)) (*tendril.Session, *tendril.Session, error) {
	t.Helper()
	const acceptGrace = 15 * time.Second
	type accepted struct {
		sess *tendril.Session
		err  error
	}
	ch := make(chan accepted, 1)
	stop := make(chan struct{})
	deadline := time.Now().Add(60 * time.Second)
	go func() {
		for {
			var s *tendril.Session
			var err error
			if v2 {
				s, err = host.AcceptV2(3000)
			} else {
				s, err = host.AcceptSession(3000)
			}
			if err == nil {
				ch <- accepted{s, nil}
				return
			}
			select {
			case <-stop:
				ch <- accepted{nil, err}
				return
			default:
			}
			if time.Now().After(deadline) {
				ch <- accepted{nil, err}
				return
			}
		}
	}()
	cs, cerr := connect()
	if cerr != nil {
		close(stop)
		if a := <-ch; a.sess != nil {
			_ = a.sess.Close()
		}
		return nil, nil, cerr
	}
	var a accepted
	select {
	case a = <-ch:
	case <-time.After(acceptGrace):
		close(stop)
		a = <-ch
	}
	if a.err != nil {
		_ = cs.Close()
		return nil, nil, a.err
	}
	t.Cleanup(func() { _ = cs.Close(); _ = a.sess.Close() })
	return cs, a.sess, nil
}

func expectData(t *testing.T, s *tendril.Session, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ev, err := s.PollEvent(500)
		if errors.Is(err, tendril.ErrWouldBlock) {
			continue
		}
		if err != nil {
			t.Fatalf("PollEvent: %v", err)
		}
		if ev.Event == "data" {
			got, _ := base64.RawURLEncoding.DecodeString(ev.DataB64)
			if string(got) != want {
				t.Fatalf("data %q, want %q", got, want)
			}
			return
		}
	}
	t.Fatalf("no data event for %q", want)
}

func newRoutesHost(t *testing.T, stateDir string, v2 bool) routesHost {
	t.Helper()
	host, err := tendril.NewEndpoint(stateDir, "go-routes-host")
	if err != nil {
		t.Fatalf("NewEndpoint host: %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })
	client, err := tendril.NewEndpoint("", "")
	if err != nil {
		t.Fatalf("NewEndpoint client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	listen, err := host.ServeDirect("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	issued, err := host.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("IssuePairingURI: %v", err)
	}
	if !strings.Contains(issued.URI, "&rs=") {
		t.Fatalf("issued URI must be host-signed by default: %s", issued.URI)
	}
	res := pairThroughURI(t, host, client, issued.URI, v2, nil)
	grant, err := host.MintGrant(res.DeviceID, []string{"fs.read"}, 3600)
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}
	return routesHost{ep: host, hostID: hostIDOf(t, host), listen: listen, clientEp: client, deviceID: res.DeviceID, grant: grant}
}

func routesOf(t *testing.T, ep *tendril.Endpoint, peer, source string) []string {
	t.Helper()
	view, err := ep.PeerRoutes(peer)
	if err != nil {
		t.Fatalf("PeerRoutes: %v", err)
	}
	out := []string{}
	for _, r := range view.Routes {
		if r.Source == source {
			out = append(out, r.Hint)
		}
	}
	sort.Strings(out)
	return out
}

func TestIssueAndPairURIPersistsSignedRoutes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state func(*testing.T) string
	}{
		{"state_dir", func(t *testing.T) string { return t.TempDir() }},
		{"ephemeral", func(*testing.T) string { return "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, err := tendril.NewEndpoint(tc.state(t), "go-uri-host")
			if err != nil {
				t.Fatalf("NewEndpoint: %v", err)
			}
			defer host.Close()
			client, err := tendril.NewEndpoint("", "")
			if err != nil {
				t.Fatalf("NewEndpoint client: %v", err)
			}
			defer client.Close()
			listen, err := host.ServeDirect("127.0.0.1:0")
			if err != nil {
				t.Fatalf("ServeDirect: %v", err)
			}

			issued, err := host.IssuePairingURI(nil)
			if err != nil {
				t.Fatalf("IssuePairingURI: %v", err)
			}
			if !strings.Contains(issued.URI, "&rq=") || !strings.Contains(issued.URI, "&rs=") {
				t.Fatalf("expected a signed URI: %s", issued.URI)
			}
			if issued.CodeKind != "lan" || issued.URILen != len(issued.URI) || issued.QRVersionM < 1 {
				t.Fatalf("unexpected issue result: %+v", issued)
			}
			if issued.RouteSeq == nil || *issued.RouteSeq < 1 || issued.Dropped == nil {
				t.Fatalf("unexpected route_seq or dropped: %+v", issued)
			}

			res := pairThroughURI(t, host, client, issued.URI, false, nil)
			hostID := hostIDOf(t, host)
			if res.HostID != hostID || res.Status != "active" || !res.HostConfirmed || !res.Committed {
				t.Fatalf("unexpected pair result: %+v", res)
			}
			if res.RouteCheck != "verified" || res.Provider != "direct" || res.Endpoint != "direct:"+listen {
				t.Fatalf("unexpected route result: %+v", res)
			}
			wantRoutes := []tendril.Route{{Hint: "direct:" + listen, Source: "signed"}}
			if !reflect.DeepEqual(res.RoutesPersisted, wantRoutes) || len(res.Skipped) != 0 {
				t.Fatalf("routes_persisted=%+v skipped=%+v", res.RoutesPersisted, res.Skipped)
			}
			if res.RoutesReason != "" {
				t.Fatalf("routes_reason = %q for a verified pairing", res.RoutesReason)
			}

			view, err := client.PeerRoutes(hostID)
			if err != nil {
				t.Fatalf("PeerRoutes: %v", err)
			}
			if !reflect.DeepEqual(view.Routes, wantRoutes) || view.LastRouteSet != nil {
				t.Fatalf("unexpected view: %+v", view)
			}
			if view.RouteMeta == nil || view.RouteMeta.Seq != *issued.RouteSeq || view.RouteMeta.Origin != "uri" {
				t.Fatalf("unexpected route_meta: %+v", view.RouteMeta)
			}

			grant, err := host.MintGrant(res.DeviceID, []string{"fs.read"}, 3600)
			if err != nil {
				t.Fatalf("MintGrant: %v", err)
			}
			cs, hs, err := connectPair(t, host, false, func() (*tendril.Session, error) {
				return client.Connect("", "", hostID, grant)
			})
			if err != nil {
				t.Fatalf("endpoint-free Connect: %v", err)
			}
			if err := cs.SendData([]byte("over stored route")); err != nil {
				t.Fatalf("SendData: %v", err)
			}
			expectData(t, hs, "over stored route")
		})
	}
}

func TestV2URIPairingAndEndpointFreeConnectV2(t *testing.T) {
	p := newRoutesHost(t, t.TempDir(), true)
	if got := routesOf(t, p.clientEp, p.hostID, "signed"); !reflect.DeepEqual(got, []string{"direct:" + p.listen}) {
		t.Fatalf("signed routes after v2 pairing: %v", got)
	}
	cs, hs, err := connectPair(t, p.ep, true, func() (*tendril.Session, error) {
		return p.clientEp.ConnectV2("", "", p.hostID, p.grant)
	})
	if err != nil {
		t.Fatalf("endpoint-free ConnectV2: %v", err)
	}
	if err := cs.SendData([]byte("v2 stored")); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	expectData(t, hs, "v2 stored")
}

func TestIssueAndPairOptions(t *testing.T) {
	host, err := tendril.NewEndpoint(t.TempDir(), "go-opt-host")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer host.Close()
	listen, err := host.ServeDirect("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}

	remote, err := host.IssuePairingURI(&tendril.IssuePairingURIOptions{Kind: "remote", HostName: "Studio"})
	if err != nil {
		t.Fatalf("remote issue: %v", err)
	}
	if remote.CodeKind != "remote" || !strings.Contains(remote.URI, "Studio") {
		t.Fatalf("unexpected remote issue: %+v", remote)
	}
	if _, err := host.IssuePairingURI(&tendril.IssuePairingURIOptions{Kind: "bluetooth"}); err == nil {
		t.Fatalf("expected an unknown kind to be rejected")
	}

	unsigned := false
	issued, err := host.IssuePairingURI(&tendril.IssuePairingURIOptions{SignRoutes: &unsigned})
	if err != nil {
		t.Fatalf("unsigned issue: %v", err)
	}
	if strings.Contains(issued.URI, "&rs=") {
		t.Fatalf("sign_routes=false must not sign: %s", issued.URI)
	}
	client, err := tendril.NewEndpoint("", "")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer client.Close()
	res := pairThroughURI(t, host, client, issued.URI, false, nil)
	if res.RouteCheck != "unsigned" || len(res.RoutesPersisted) != 0 {
		t.Fatalf("unsigned URI must persist nothing by default: %+v", res)
	}
	if res.RoutesReason != "unsigned_uri" {
		t.Fatalf("routes_reason = %q, want unsigned_uri", res.RoutesReason)
	}

	issued, err = host.IssuePairingURI(&tendril.IssuePairingURIOptions{SignRoutes: &unsigned})
	if err != nil {
		t.Fatalf("unsigned issue: %v", err)
	}
	client2, err := tendril.NewEndpoint("", "")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer client2.Close()
	res = pairThroughURI(t, host, client2, issued.URI, false, &tendril.PairURIOptions{SaveRoute: true})
	if want := []tendril.Route{{Hint: "direct:" + listen, Source: "committed"}}; !reflect.DeepEqual(res.RoutesPersisted, want) {
		t.Fatalf("save_route persisted %+v", res.RoutesPersisted)
	}

	issued, err = host.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("signed issue: %v", err)
	}
	client3, err := tendril.NewEndpoint("", "")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer client3.Close()
	res = pairThroughURI(t, host, client3, issued.URI, false, &tendril.PairURIOptions{Endpoint: listen, RoutePolicy: "none"})
	if want := []tendril.Route{{Hint: "direct:" + listen, Source: "operator"}}; !reflect.DeepEqual(res.RoutesPersisted, want) {
		t.Fatalf("endpoint option persisted %+v", res.RoutesPersisted)
	}

	if _, err := client.PairURI("tendril://nope", "", "", nil); err == nil {
		t.Fatalf("expected a malformed URI to be rejected")
	}
	if _, err := client.PairURI(issued.URI, "", "", &tendril.PairURIOptions{RoutePolicy: "sometimes"}); err == nil {
		t.Fatalf("expected an unknown route policy to be rejected")
	}
	if _, err := client.PairURI("tendril://pair\x00", "", "", nil); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("expected NUL rejection, got %v", err)
	}
}

func strs(v ...string) *[]string { return &v }

func TestRouteConfigKeys(t *testing.T) {
	ep, err := tendril.NewEndpoint("", "go-config-ep")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer ep.Close()
	unsigned := false
	if err := ep.ConfigureRoutes(tendril.RouteConfig{
		RelayAuthOrigins:    strs("wss://relay.example", "ws://127.0.0.1:8080/"),
		AdvertisedEndpoints: strs("192.168.1.5:7000"),
		Advertise:           "explicit",
		RoutePolicy:         "committed_only",
		SignRoutes:          &unsigned,
	}); err != nil {
		t.Fatalf("ConfigureRoutes: %v", err)
	}
	for _, bad := range []tendril.RouteConfig{
		{RelayAuthOrigins: strs("relay.example")},
		{RelayAuthOrigins: strs("wss://relay.example/path")},
		{RelayAuthOrigins: strs("wss://user@relay.example")},
		{RoutePolicy: "sometimes"},
		{Advertise: "loud"},
	} {
		if err := ep.ConfigureRoutes(bad); err == nil {
			t.Fatalf("expected %+v to be rejected", bad)
		}
	}
}

func TestConfigureRoutesKeepsRelayTicket(t *testing.T) {
	issuer, err := tendril.NewEndpoint("", "go-routes-issuer")
	if err != nil {
		t.Fatalf("NewEndpoint issuer: %v", err)
	}
	defer issuer.Close()
	info, err := issuer.Info()
	if err != nil {
		t.Fatalf("issuer Info: %v", err)
	}
	v1URL, _ := spawnRelay(t, nil, "--issuer-pub", info.RelayPub, "--auth-scope", "all")
	regTicket, err := issuer.MintRelayTicket("127.0.0.1", "register", "*", 300)
	if err != nil {
		t.Fatalf("MintRelayTicket: %v", err)
	}
	host, err := tendril.NewEndpoint("", "go-routes-host")
	if err != nil {
		t.Fatalf("NewEndpoint host: %v", err)
	}
	defer host.Close()
	if err := host.ConfigureTransportsJSON(`{"relay_ticket":` + regTicket + `}`); err != nil {
		t.Fatalf("ConfigureTransportsJSON ticket: %v", err)
	}
	if err := host.ConfigureRoutes(tendril.RouteConfig{RoutePolicy: "committed_only"}); err != nil {
		t.Fatalf("ConfigureRoutes: %v", err)
	}
	if _, err := host.ServeRelay(v1URL, "127.0.0.1"); err != nil {
		t.Fatalf("authenticated relay dial after ConfigureRoutes lost the ticket: %v", err)
	}

	// A full replacement through ConfigureTransportsJSON updates the cache, so a later
	// ConfigureRoutes does not resurrect the replaced ticket.
	if err := host.ConfigureTransportsJSON("{}"); err != nil {
		t.Fatalf("ConfigureTransportsJSON empty: %v", err)
	}
	if err := host.ConfigureRoutes(tendril.RouteConfig{RoutePolicy: "all_signed"}); err != nil {
		t.Fatalf("ConfigureRoutes after reset: %v", err)
	}
	if _, err := host.ServeRelay(v1URL, "127.0.0.1"); err == nil {
		t.Fatalf("ServeRelay succeeded without a ticket after the config was replaced")
	}
}

func TestConfigureRoutesClearsLists(t *testing.T) {
	host, err := tendril.NewEndpoint(t.TempDir(), "")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer host.Close()
	unsigned := false
	if err := host.ConfigureRoutes(tendril.RouteConfig{
		Advertise:           "explicit",
		AdvertisedEndpoints: strs("192.168.1.5:7000"),
		SignRoutes:          &unsigned,
	}); err != nil {
		t.Fatalf("ConfigureRoutes: %v", err)
	}
	if _, err := host.ServeDirect("0.0.0.0:0"); err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	// nil leaves the list unchanged.
	if err := host.ConfigureRoutes(tendril.RouteConfig{RoutePolicy: "all_signed"}); err != nil {
		t.Fatalf("ConfigureRoutes: %v", err)
	}
	issued, err := host.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("IssuePairingURI: %v", err)
	}
	if !strings.Contains(issued.URI, "192.168.1.5") {
		t.Fatalf("nil list must keep the advertised hint: %s", issued.URI)
	}
	// A pointer to an empty slice clears it.
	if err := host.ConfigureRoutes(tendril.RouteConfig{AdvertisedEndpoints: strs()}); err != nil {
		t.Fatalf("ConfigureRoutes clear: %v", err)
	}
	issued, err = host.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("IssuePairingURI after clear: %v", err)
	}
	if strings.Contains(issued.URI, "192.168.1.5") {
		t.Fatalf("empty list must clear the advertised hint: %s", issued.URI)
	}
}

func TestExplicitAdvertisingDefaultsToUnsignedWhenConfigured(t *testing.T) {
	host, err := tendril.NewEndpoint(t.TempDir(), "")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer host.Close()
	unsigned := false
	if err := host.ConfigureRoutes(tendril.RouteConfig{
		Advertise:           "explicit",
		AdvertisedEndpoints: strs("192.168.1.5:7000"),
		SignRoutes:          &unsigned,
	}); err != nil {
		t.Fatalf("ConfigureRoutes: %v", err)
	}
	if _, err := host.ServeDirect("0.0.0.0:0"); err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	issued, err := host.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("IssuePairingURI: %v", err)
	}
	if strings.Contains(issued.URI, "&rs=") || !strings.Contains(issued.URI, "192.168.1.5") {
		t.Fatalf("expected an unsigned URI with the advertised hint: %s", issued.URI)
	}
	found := false
	for _, d := range issued.Dropped {
		if d.Reason == "unspecified_bind" {
			found = true
		}
	}
	if !found {
		t.Fatalf("explicit mode must report the dropped unspecified bind: %+v", issued.Dropped)
	}
}

func TestPeerRouteSettersAndStoredConnect(t *testing.T) {
	p := newRoutesHost(t, t.TempDir(), false)
	client, hostID := p.clientEp, p.hostID
	signed := []string{"direct:" + p.listen}

	if err := client.SetPeerRoutes(hostID, []string{"127.0.0.1:1", "127.0.0.1:2"}); err != nil {
		t.Fatalf("SetPeerRoutes: %v", err)
	}
	if err := client.SetPeerRoutes(hostID, []string{"127.0.0.1:3"}); err != nil {
		t.Fatalf("SetPeerRoutes replace: %v", err)
	}
	if got := routesOf(t, client, hostID, "operator"); !reflect.DeepEqual(got, []string{"direct:127.0.0.1:3"}) {
		t.Fatalf("operator routes: %v", got)
	}
	if got := routesOf(t, client, hostID, "signed"); !reflect.DeepEqual(got, signed) {
		t.Fatalf("signed routes disturbed: %v", got)
	}

	for _, bad := range [][]string{
		{"127.0.0.1:4", "host#frag"},
		{"a:1", "a:2", "a:3", "a:4", "a:5", "a:6", "a:7"},
	} {
		if err := client.SetPeerRoutes(hostID, bad); err == nil {
			t.Fatalf("expected %v to be rejected", bad)
		}
	}
	if got := routesOf(t, client, hostID, "operator"); !reflect.DeepEqual(got, []string{"direct:127.0.0.1:3"}) {
		t.Fatalf("a rejected list must change nothing: %v", got)
	}
	if err := client.SetPeerRoutes("dev_unknown", []string{"127.0.0.1:5"}); err == nil || !strings.Contains(err.Error(), "(-2)") {
		t.Fatalf("expected not-found for an unknown peer, got %v", err)
	}
	if _, err := client.PeerRoutes("dev_unknown"); err == nil || !strings.Contains(err.Error(), "(-2)") {
		t.Fatalf("expected not-found for an unknown peer, got %v", err)
	}

	if err := client.ClearPeerRoutes(hostID, ""); err != nil {
		t.Fatalf("ClearPeerRoutes default: %v", err)
	}
	if got := routesOf(t, client, hostID, "operator"); len(got) != 0 {
		t.Fatalf("operator routes after clear: %v", got)
	}
	if got := routesOf(t, client, hostID, "signed"); !reflect.DeepEqual(got, signed) {
		t.Fatalf("a default clear must keep signed routes: %v", got)
	}
	if err := client.ClearPeerRoutes(hostID, "bogus"); err == nil {
		t.Fatalf("expected an unknown source to be rejected")
	}
	if err := client.ClearPeerRoutes(hostID, "signed"); err != nil {
		t.Fatalf("ClearPeerRoutes signed: %v", err)
	}
	view, err := client.PeerRoutes(hostID)
	if err != nil {
		t.Fatalf("PeerRoutes: %v", err)
	}
	if len(view.Routes) != 0 || view.RouteMeta == nil {
		t.Fatalf("route_meta must outlive the routes: %+v", view)
	}

	_, _, err = connectPair(t, p.ep, false, func() (*tendril.Session, error) {
		return client.Connect("", "", hostID, p.grant)
	})
	if err == nil || !strings.Contains(err.Error(), "no dialable stored routes") {
		t.Fatalf("expected no dialable stored routes, got %v", err)
	}

	if err := client.SetPeerRoutes(hostID, []string{p.listen}); err != nil {
		t.Fatalf("SetPeerRoutes: %v", err)
	}
	cs, hs, err := connectPair(t, p.ep, false, func() (*tendril.Session, error) {
		return client.Connect("", "", hostID, p.grant)
	})
	if err != nil {
		t.Fatalf("operator route connect: %v", err)
	}
	if err := cs.SendData([]byte("operator")); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	expectData(t, hs, "operator")
}

func TestApplyRouteURIOffline(t *testing.T) {
	p := newRoutesHost(t, t.TempDir(), false)
	host, client, hostID := p.ep, p.clientEp, p.hostID
	view, err := client.PeerRoutes(hostID)
	if err != nil || view.RouteMeta == nil {
		t.Fatalf("PeerRoutes: %+v %v", view, err)
	}
	first := view.RouteMeta.Seq
	stale, err := host.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("issue stale: %v", err)
	}

	second, err := host.ServeDirect("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	fresh, err := host.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("issue fresh: %v", err)
	}
	if fresh.RouteSeq == nil || *fresh.RouteSeq != first+1 {
		t.Fatalf("fresh seq %v, want %d", fresh.RouteSeq, first+1)
	}

	res, err := client.ApplyRouteURI(fresh.URI, nil)
	if err != nil {
		t.Fatalf("apply fresh: %v", err)
	}
	if res.PeerID != hostID || !res.Applied || res.Reason != "" || res.RouteSeq == nil || *res.RouteSeq != first+1 {
		t.Fatalf("unexpected apply result: %+v", res)
	}
	want := []string{"direct:" + p.listen, "direct:" + second}
	sort.Strings(want)
	if got := routesOf(t, client, hostID, "signed"); !reflect.DeepEqual(got, want) {
		t.Fatalf("signed routes %v, want %v", got, want)
	}

	res, err = client.ApplyRouteURI(stale.URI, nil)
	if err != nil || res.Applied || res.Reason != "stale_route_seq" {
		t.Fatalf("stale apply: %+v %v", res, err)
	}
	res, err = client.ApplyRouteURI(stale.URI, &tendril.ApplyRouteURIOptions{ReplaceRoutes: true})
	if err != nil || !res.Applied {
		t.Fatalf("approved apply: %+v %v", res, err)
	}
	if got := routesOf(t, client, hostID, "signed"); !reflect.DeepEqual(got, []string{"direct:" + p.listen}) {
		t.Fatalf("approved replacement: %v", got)
	}
	if view, _ := client.PeerRoutes(hostID); view.RouteMeta == nil || view.RouteMeta.Origin != "approved" {
		t.Fatalf("expected approved origin: %+v", view.RouteMeta)
	}

	res, err = client.ApplyRouteURI(fresh.URI, &tendril.ApplyRouteURIOptions{RoutePolicy: "committed_only"})
	if err != nil || res.Applied || res.Reason != "route_policy" {
		t.Fatalf("policy apply: %+v %v", res, err)
	}

	unsigned := false
	plain, err := host.IssuePairingURI(&tendril.IssuePairingURIOptions{SignRoutes: &unsigned})
	if err != nil {
		t.Fatalf("issue unsigned: %v", err)
	}
	if _, err := client.ApplyRouteURI(plain.URI, nil); err == nil || !strings.Contains(err.Error(), "not host-signed") {
		t.Fatalf("expected an unsigned URI to be refused, got %v", err)
	}
	if _, err := client.ApplyRouteURI("not a uri", nil); err == nil || !strings.Contains(err.Error(), "(-1)") {
		t.Fatalf("expected an invalid-argument error, got %v", err)
	}
}

func TestConnectWithOptionsTakesRelayHost(t *testing.T) {
	p := newRoutesHost(t, t.TempDir(), false)
	_, err := p.clientEp.ConnectWithOptions(p.hostID, &tendril.ConnectOptions{
		Grant:     json.RawMessage(p.grant),
		Endpoint:  "iroh://peer",
		RelayHost: "not-a-relay-mode",
	})
	if err == nil || strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("relay_host must reach the dialer config and fail its parser, got %v", err)
	}
}

func TestConnectWithOptionsUsesAndAppliesRecoveryURI(t *testing.T) {
	p := newRoutesHost(t, t.TempDir(), false)
	host, client, hostID := p.ep, p.clientEp, p.hostID
	if err := client.ClearPeerRoutes(hostID, "all"); err != nil {
		t.Fatalf("ClearPeerRoutes: %v", err)
	}
	if _, _, err := connectPair(t, host, false, func() (*tendril.Session, error) {
		return client.Connect("", "", hostID, p.grant)
	}); err == nil {
		t.Fatalf("expected no stored routes to fail")
	}

	same, err := host.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	opts := &tendril.ConnectOptions{Wire: 1, Grant: json.RawMessage(p.grant), RecoveryURI: same.URI}
	cs, hs, err := connectPair(t, host, false, func() (*tendril.Session, error) {
		return client.ConnectWithOptions(hostID, opts)
	})
	if err != nil {
		t.Fatalf("recovery connect: %v", err)
	}
	if err := cs.SendData([]byte("recovered")); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	expectData(t, hs, "recovered")
	if view, _ := client.PeerRoutes(hostID); len(view.Routes) != 0 {
		t.Fatalf("an equal rq must not touch stored routes: %+v", view.Routes)
	}

	if _, err := host.ServeDirect("127.0.0.1:0"); err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	newer, err := host.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("issue newer: %v", err)
	}
	opts = &tendril.ConnectOptions{Grant: json.RawMessage(p.grant), RecoveryURI: newer.URI}
	if _, _, err := connectPair(t, host, false, func() (*tendril.Session, error) {
		return client.ConnectWithOptions(hostID, opts)
	}); err != nil {
		t.Fatalf("newer recovery connect: %v", err)
	}
	view, err := client.PeerRoutes(hostID)
	if err != nil {
		t.Fatalf("PeerRoutes: %v", err)
	}
	if len(routesOf(t, client, hostID, "signed")) != 2 || view.RouteMeta == nil || newer.RouteSeq == nil || view.RouteMeta.Seq != *newer.RouteSeq {
		t.Fatalf("a newer rq must replace the signed routes: %+v", view)
	}

	opts = &tendril.ConnectOptions{Grant: json.RawMessage(p.grant), Endpoint: p.listen, RecoveryURI: newer.URI}
	if _, _, err := connectPair(t, host, false, func() (*tendril.Session, error) {
		return client.ConnectWithOptions(hostID, opts)
	}); err != nil {
		t.Fatalf("explicit endpoint with recovery URI: %v", err)
	}

	stranger, err := tendril.NewEndpoint("", "")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer stranger.Close()
	if _, err := stranger.ServeDirect("127.0.0.1:0"); err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	foreign, err := stranger.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("issue foreign: %v", err)
	}
	if s, err := client.ConnectWithOptions(hostID, &tendril.ConnectOptions{Grant: json.RawMessage(p.grant), RecoveryURI: foreign.URI}); err == nil {
		_ = s.Close()
		t.Fatalf("a recovery URI of another host must be refused")
	}
	if s, err := client.ConnectWithOptions(hostID, &tendril.ConnectOptions{Wire: 3}); err == nil {
		_ = s.Close()
		t.Fatalf("wire 3 must be rejected")
	}
}

func snapshotOf(addr string) *tendril.NetworkSnapshot {
	return &tendril.NetworkSnapshot{Networks: []tendril.Network{{
		ID: "net-1", Iface: "wlan0", IfIndex: 3, Transports: []string{"wifi"}, Addrs: []string{addr},
	}}}
}

func waitRouteSet(t *testing.T, client *tendril.Endpoint, sess *tendril.Session, hostID string, seq uint64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		ev, err := sess.PollEvent(250)
		if err == nil {
			t.Fatalf("route sets never reach the event stream: %+v", ev)
		}
		if !errors.Is(err, tendril.ErrWouldBlock) {
			t.Fatalf("PollEvent: %v", err)
		}
		view, err := client.PeerRoutes(hostID)
		if err != nil {
			t.Fatalf("PeerRoutes: %v", err)
		}
		if view.LastRouteSet != nil && view.LastRouteSet.Outcome == "applied" && view.LastRouteSet.Seq == seq {
			if view.RouteMeta == nil || view.RouteMeta.Origin != "session" || view.RouteMeta.Seq != seq {
				t.Fatalf("unexpected route_meta: %+v", view.RouteMeta)
			}
			return
		}
	}
	t.Fatalf("route set %d not applied", seq)
}

func TestRefreshRoutesDeliversRouteSetToLiveSession(t *testing.T) {
	host, err := tendril.NewEndpoint(t.TempDir(), "go-refresh-host")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer host.Close()
	client, err := tendril.NewEndpoint("", "")
	if err != nil {
		t.Fatalf("NewEndpoint client: %v", err)
	}
	defer client.Close()
	loopback, err := host.ServeDirect("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	anyAddr, err := host.ServeDirect("0.0.0.0:0")
	if err != nil {
		t.Fatalf("ServeDirect any: %v", err)
	}
	lanPort := anyAddr[strings.LastIndex(anyAddr, ":")+1:]

	first, err := host.RefreshRoutes(snapshotOf("10.255.77.20"))
	if err != nil {
		t.Fatalf("RefreshRoutes: %v", err)
	}
	issued, err := host.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("IssuePairingURI: %v", err)
	}
	if issued.RouteSeq == nil || *issued.RouteSeq != first.RouteSeq || !strings.Contains(issued.URI, "10.255.77.20") {
		t.Fatalf("issue must carry the refreshed set: %+v first=%+v", issued, first)
	}
	res := pairThroughURI(t, host, client, issued.URI, false, nil)
	hostID := hostIDOf(t, host)
	lanA := "direct:10.255.77.20:" + lanPort
	want := []string{"direct:" + loopback, lanA}
	sort.Strings(want)
	if got := routesOf(t, client, hostID, "signed"); !reflect.DeepEqual(got, want) {
		t.Fatalf("signed routes %v, want %v", got, want)
	}
	grant, err := host.MintGrant(res.DeviceID, []string{"fs.read"}, 3600)
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}
	connect := func() (*tendril.Session, *tendril.Session) {
		cs, hs, err := connectPair(t, host, false, func() (*tendril.Session, error) {
			return client.Connect("", "", hostID, grant)
		})
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		return cs, hs
	}

	// A URI-paired client sends route_seq 0, so the current set is the first frame of its first session.
	cs, hs := connect()
	waitRouteSet(t, client, cs, hostID, first.RouteSeq)
	_ = cs.Close()
	_ = hs.Close()

	cs, hs = connect()
	again, err := host.RefreshRoutes(snapshotOf("10.255.77.20"))
	if err != nil || again.Changed || again.RouteSeq != first.RouteSeq {
		t.Fatalf("an unchanged snapshot must not bump: %+v %v", again, err)
	}
	moved, err := host.RefreshRoutes(snapshotOf("10.255.77.30"))
	if err != nil || !moved.Changed || moved.RouteSeq != first.RouteSeq+1 {
		t.Fatalf("a moved address must bump once: %+v %v", moved, err)
	}
	waitRouteSet(t, client, cs, hostID, moved.RouteSeq)
	signed := routesOf(t, client, hostID, "signed")
	lanB := "direct:10.255.77.30:" + lanPort
	has := func(h string) bool {
		for _, s := range signed {
			if s == h {
				return true
			}
		}
		return false
	}
	if !has(lanB) || has(lanA) || !has("direct:"+loopback) {
		t.Fatalf("signed routes after refresh: %v", signed)
	}
	if err := hs.SendData([]byte("still open")); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	expectData(t, cs, "still open")

	if _, err := host.RefreshRoutes(&tendril.NetworkSnapshot{}); err != nil {
		t.Fatalf("an empty snapshot is a valid snapshot: %v", err)
	}
	if _, err := host.RefreshRoutes(nil); err != nil {
		t.Fatalf("native refresh: %v", err)
	}
}

func deriveWakeTagB64(secret [32]byte, unixSecs uint64) string {
	var salt [8]byte
	binary.BigEndian.PutUint64(salt[:], unixSecs/3600)
	extract := hmac.New(sha256.New, salt[:])
	_, _ = extract.Write(secret[:])
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write([]byte("tendril/wake/epoch-tag/v1\x01"))
	okm := expand.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(okm[:16])
}

func TestVerifyWakeTagAndApnsWakeConfig(t *testing.T) {
	if tendril.MlDsa65PubLen != 1952 {
		t.Fatalf("MlDsa65PubLen = %d, want 1952", tendril.MlDsa65PubLen)
	}
	if tendril.MlDsa65SigLen != 3309 {
		t.Fatalf("MlDsa65SigLen = %d, want 3309", tendril.MlDsa65SigLen)
	}

	var secret [32]byte
	for i := range secret {
		secret[i] = byte(0x30 + i)
	}
	var wrong [32]byte
	wrong[0] = 0xff

	const nowUnix = uint64(1764115200)
	tagB64 := deriveWakeTagB64(secret, nowUnix)

	for _, checkNow := range []uint64{nowUnix - 3600, nowUnix, nowUnix + 3600} {
		ok, err := tendril.VerifyWakeTag(secret, tagB64, checkNow)
		if err != nil || !ok {
			t.Fatalf("VerifyWakeTag(%d) = (%v, %v), want (true, nil)", checkNow, ok, err)
		}
	}
	for _, checkNow := range []uint64{nowUnix - 7200, nowUnix + 7200} {
		ok, err := tendril.VerifyWakeTag(secret, tagB64, checkNow)
		if err != nil || ok {
			t.Fatalf("VerifyWakeTag(%d) = (%v, %v), want (false, nil)", checkNow, ok, err)
		}
	}
	if ok, err := tendril.VerifyWakeTag(wrong, tagB64, nowUnix); err != nil || ok {
		t.Fatalf("VerifyWakeTag(wrong) = (%v, %v), want (false, nil)", ok, err)
	}
	if _, err := tendril.VerifyWakeTag(secret, "bad-tag", nowUnix); err == nil {
		t.Fatal("VerifyWakeTag must fail on malformed wake_tag_b64")
	}
	if _, err := tendril.VerifyWakeTag(secret, tagB64+"\x00x", nowUnix); err == nil {
		t.Fatal("VerifyWakeTag must reject embedded NUL bytes")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	p8Pem := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	ep, err := tendril.NewEndpoint("", "go-apns-wake")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer ep.Close()

	deviceToken := strings.Repeat("a", 64)
	validCfg, err := json.Marshal(map[string]any{
		"wake_url":           "https://api.sandbox.push.apple.com/3/device/" + deviceToken,
		"wake_adapter":       "apns_h2",
		"wake_secret_b64":    base64.RawURLEncoding.EncodeToString(secret[:]),
		"wake_apns_mode":     "mutable_alert",
		"wake_apns_topic":    "app.tendril.go",
		"wake_apns_loc_key":  "TENDRIL_WAKE_GO",
		"wake_apns_team_id":  "TEAM123456",
		"wake_apns_key_id":   "KEY1234567",
		"wake_apns_p8_pem":   p8Pem,
		"wake_coalesce_secs": 15,
	})
	if err != nil {
		t.Fatalf("Marshal validCfg: %v", err)
	}
	if err := ep.ConfigureTransportsJSON(string(validCfg)); err != nil {
		t.Fatalf("ConfigureTransportsJSON(apns_h2): %v", err)
	}

	for _, bad := range []map[string]any{
		{
			"wake_url":        "http://127.0.0.1:8080/3/device/" + deviceToken,
			"wake_adapter":    "apns_h2",
			"wake_secret_b64": base64.RawURLEncoding.EncodeToString(secret[:]),
			"wake_auth_token": "tok",
			"wake_apns_topic": "app.tendril.go",
		},
		{
			"wake_url":        "https://api.push.apple.com/3/device/" + deviceToken,
			"wake_adapter":    "apns_h2",
			"wake_secret_b64": base64.RawURLEncoding.EncodeToString(secret[:]),
			"wake_auth_token": "tok",
		},
		{
			"wake_url":          "https://api.push.apple.com/3/device/" + deviceToken,
			"wake_adapter":      "apns_h2",
			"wake_secret_b64":   base64.RawURLEncoding.EncodeToString(secret[:]),
			"wake_auth_token":   "tok",
			"wake_apns_topic":   "app.tendril.go",
			"wake_apns_mode":    "mutable_alert",
			"wake_apns_loc_key": "BAD KEY",
		},
	} {
		raw, _ := json.Marshal(bad)
		if err := ep.ConfigureTransportsJSON(string(raw)); err == nil {
			t.Fatalf("expected failure for %v", bad)
		}
	}
}

func TestLowPowerRouteConfigIdleTimeoutAndExternalMonitor(t *testing.T) {
	host, err := tendril.NewEndpoint(t.TempDir(), "go-lp-host")
	if err != nil {
		t.Fatalf("NewEndpoint host: %v", err)
	}
	defer host.Close()
	client, err := tendril.NewEndpoint(t.TempDir(), "")
	if err != nil {
		t.Fatalf("NewEndpoint client: %v", err)
	}
	defer client.Close()

	if err := host.ConfigureRoutes(tendril.RouteConfig{PowerProfile: "low_power"}); err != nil {
		t.Fatalf("ConfigureRoutes host: %v", err)
	}
	if err := client.ConfigureRoutes(tendril.RouteConfig{PowerProfile: "low_power"}); err != nil {
		t.Fatalf("ConfigureRoutes client: %v", err)
	}
	if err := host.SetExternalPathMonitor(true); err != nil {
		t.Fatalf("SetExternalPathMonitor(true): %v", err)
	}
	if err := host.SetExternalPathMonitor(false); err != nil {
		t.Fatalf("SetExternalPathMonitor(false): %v", err)
	}
	if _, err := host.ServeDirect("127.0.0.1:0"); err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	issued, err := host.IssuePairingURI(nil)
	if err != nil {
		t.Fatalf("IssuePairingURI: %v", err)
	}
	res := pairThroughURI(t, host, client, issued.URI, true, nil)
	hostID := hostIDOf(t, host)
	grant, err := host.MintGrant(res.DeviceID, []string{"fs.read"}, 3600)
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}

	cs, hs, err := connectPair(t, host, true, func() (*tendril.Session, error) {
		return client.ConnectWithOptions(hostID, &tendril.ConnectOptions{
			Wire:          2,
			Grant:         json.RawMessage(grant),
			IdleTimeoutMs: 120,
		})
	})
	if err != nil {
		t.Fatalf("ConnectWithOptions: %v", err)
	}
	defer hs.Close()
	defer cs.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ev, err := cs.PollEvent(100)
		if errors.Is(err, tendril.ErrWouldBlock) {
			continue
		}
		if errors.Is(err, io.EOF) || (err == nil && ev != nil && ev.Event == "closed") {
			return
		}
		if err != nil {
			t.Fatalf("PollEvent: %v", err)
		}
	}
	t.Fatal("expected idle_timeout_ms session to close on idle")
}
