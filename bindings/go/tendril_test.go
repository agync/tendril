package tendril_test

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	tendril "tendril.dev/bindings/go"
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

func BenchmarkFFIOverhead(b *testing.B) {
	var key [32]byte
	key[0] = 0x42
	for b.Loop() {
		if _, err := tendril.DeviceID(key); err != nil {
			b.Fatal(err)
		}
	}
}
