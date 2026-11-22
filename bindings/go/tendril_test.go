package tendril_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	if allowed, err := hostSess.Authorize("fs.read"); err != nil || !allowed {
		t.Fatalf("Go Authorize fs.read failed: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := hostSess.Authorize("shell.exec"); err != nil || allowed {
		t.Fatalf("Go Authorize shell.exec expected false: allowed=%v err=%v", allowed, err)
	}
	if err := goHost.RevokePeer(accPair.DeviceID); err != nil {
		t.Fatalf("Go RevokePeer: %v", err)
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
	}
	wg.Wait()
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
	if allowed, err := hostSess.Authorize("fs.read"); err != nil || !allowed {
		t.Fatalf("Go AcceptV2 Authorize fs.read failed: allowed=%v err=%v", allowed, err)
	}
	if err := goHost.RevokePeer(accPair.DeviceID); err != nil {
		t.Fatalf("Go RevokePeer: %v", err)
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
