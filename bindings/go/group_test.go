package tendril_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	tendril "github.com/agync/tendril/bindings/go"
)

type groupNode struct {
	ep   *tendril.Endpoint
	info tendril.EndpointInfo
	addr string
}

func newGroupNode(t *testing.T) *groupNode {
	t.Helper()
	ep, err := tendril.NewEndpoint(t.TempDir(), "")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = ep.Close() })
	info, err := ep.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	addr, err := ep.ServeDirect("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ServeDirect: %v", err)
	}
	return &groupNode{ep: ep, info: info, addr: addr}
}

// enroll pins both full signing keys through the M2M flow, as group admin requires.
func enroll(t *testing.T, host, peer *groupNode) {
	t.Helper()
	static, err := base64.RawURLEncoding.DecodeString(host.info.StaticPub)
	if err != nil {
		t.Fatalf("decode static: %v", err)
	}
	signing, err := base64.RawURLEncoding.DecodeString(host.info.SigningPub)
	if err != nil {
		t.Fatalf("decode signing: %v", err)
	}
	token, err := host.ep.MintEnrollmentToken(host.info.HostID, peer.info.DeviceID, 900)
	if err != nil {
		t.Fatalf("MintEnrollmentToken: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, e := host.ep.PairAccept(10_000)
		done <- e
	}()
	res, err := peer.ep.EnrollInitiate(host.addr, "", host.info.HostID, static, signing, 0, token, "peer", "machine")
	if err != nil {
		t.Fatalf("EnrollInitiate: %v", err)
	}
	if res.Status != "active" {
		t.Fatalf("unexpected enroll status %q", res.Status)
	}
	if err := <-done; err != nil {
		t.Fatalf("PairAccept: %v", err)
	}
}

func manifestField(t *testing.T, manifest, key string) any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(manifest), &doc); err != nil {
		t.Fatalf("manifest json: %v", err)
	}
	return doc[key]
}

func waitGroupEvent(t *testing.T, g *tendril.Group, want string) *tendril.GroupEvent {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		ev, err := g.PollEvent(500)
		if err != nil {
			t.Fatalf("PollEvent: %v", err)
		}
		if ev == nil {
			continue
		}
		if ev.Event == want {
			return ev
		}
	}
	t.Fatalf("no %s event in time", want)
	return nil
}

func TestGroupMeshBroadcastAndRevoke(t *testing.T) {
	a, b, c := newGroupNode(t), newGroupNode(t), newGroupNode(t)
	enroll(t, a, b)
	enroll(t, a, c)

	m1, err := a.ep.GroupCreate("go-mesh", 1, []string{a.addr})
	if err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}
	gid, _ := manifestField(t, m1, "group_id").(string)
	if gid == "" {
		t.Fatal("manifest has no group_id")
	}
	if _, err := a.ep.GroupAddMember(gid, b.info.DeviceID, nil, []string{b.addr}); err != nil {
		t.Fatalf("GroupAddMember b: %v", err)
	}
	manifest, err := a.ep.GroupAddMember(gid, c.info.DeviceID, nil, []string{c.addr})
	if err != nil {
		t.Fatalf("GroupAddMember c: %v", err)
	}
	for _, n := range []*groupNode{b, c} {
		got, err := n.ep.GroupIngestManifest(manifest, a.info.DeviceID)
		if err != nil {
			t.Fatalf("GroupIngestManifest: %v", err)
		}
		if got != gid {
			t.Fatalf("ingested %q, want %q", got, gid)
		}
	}

	ga, err := a.ep.OpenGroup(gid, "")
	if err != nil {
		t.Fatalf("OpenGroup a: %v", err)
	}
	defer ga.Close()
	gb, err := b.ep.OpenGroup(gid, "")
	if err != nil {
		t.Fatalf("OpenGroup b: %v", err)
	}
	defer gb.Close()
	gc, err := c.ep.OpenGroup(gid, "")
	if err != nil {
		t.Fatalf("OpenGroup c: %v", err)
	}
	defer gc.Close()

	report, err := ga.Broadcast([]byte("hello-go"), "")
	if err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if len(report.Delivered) != 2 || len(report.Failed) != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
	for _, g := range []*tendril.Group{gb, gc} {
		ev := waitGroupEvent(t, g, "app_data")
		payload, err := ev.Payload()
		if err != nil || string(payload) != "hello-go" || ev.SenderDeviceID != a.info.DeviceID {
			t.Fatalf("unexpected app_data %+v payload=%q err=%v", ev, payload, err)
		}
	}

	if err := ga.AuthorizePeer(b.info.DeviceID, "group.send:"+gid); err != nil {
		t.Fatalf("AuthorizePeer: %v", err)
	}
	if err := ga.AuthorizePeer(b.info.DeviceID, "group.admin:"+gid); err == nil {
		t.Fatal("AuthorizePeer must refuse a capability the member lacks")
	}

	revoked, err := a.ep.GroupRemoveMember(gid, c.info.DeviceID)
	if err != nil {
		t.Fatalf("GroupRemoveMember: %v", err)
	}
	if _, err := b.ep.GroupIngestManifest(revoked, a.info.DeviceID); err != nil {
		t.Fatalf("ingest revocation: %v", err)
	}
	ev := waitGroupEvent(t, gb, "member_revoked")
	if ev.DeviceID != c.info.DeviceID {
		t.Fatalf("revoked %q, want %q", ev.DeviceID, c.info.DeviceID)
	}
}

func TestGroupIngestRefusalsAndErrors(t *testing.T) {
	a, b, d := newGroupNode(t), newGroupNode(t), newGroupNode(t)
	enroll(t, a, b)
	enroll(t, b, d)
	m1, err := a.ep.GroupCreate("go-refuse", 1, nil)
	if err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}
	gid, _ := manifestField(t, m1, "group_id").(string)
	manifest, err := a.ep.GroupAddMember(gid, b.info.DeviceID, nil, nil)
	if err != nil {
		t.Fatalf("GroupAddMember: %v", err)
	}
	if _, err := d.ep.GroupIngestManifest(manifest, b.info.DeviceID); err == nil {
		t.Fatal("first contact from a non-root peer must be refused")
	}
	if _, err := d.ep.GroupIngestManifest(manifest, "not-a-paired-peer"); err == nil {
		t.Fatal("unknown sender must be refused")
	}
	if _, err := d.ep.OpenGroup(gid, ""); err == nil || !strings.Contains(err.Error(), "-2") {
		t.Fatalf("OpenGroup of an unknown group must return not-found, got %v", err)
	}
	if _, err := b.ep.GroupAddMember(gid, d.info.DeviceID, nil, nil); err == nil {
		t.Fatal("only the root may add members")
	}
	if _, err := a.ep.GroupCreate("bad\x00name", 1, nil); err == nil {
		t.Fatal("interior NUL must be rejected")
	}

	mem, err := tendril.NewEndpoint("", "")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer mem.Close()
	if _, err := mem.GroupCreate("no-state", 1, nil); err == nil {
		t.Fatal("an in-memory endpoint has no group store")
	}
}

func TestGroupCloseIsIdempotentAndFinalizerSafe(t *testing.T) {
	a := newGroupNode(t)
	m1, err := a.ep.GroupCreate("go-close", 1, nil)
	if err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}
	gid, _ := manifestField(t, m1, "group_id").(string)
	g, err := a.ep.OpenGroup(gid, "")
	if err != nil {
		t.Fatalf("OpenGroup: %v", err)
	}
	if ev, err := g.PollEvent(0); ev != nil || err != nil {
		t.Fatalf("idle PollEvent must time out with (nil, nil), got %v, %v", ev, err)
	}
	if err := g.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := g.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := g.Broadcast([]byte("x"), ""); err == nil {
		t.Fatal("Broadcast after Close must fail")
	}
	if _, err := g.PollEvent(0); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("PollEvent after Close must fail, got %v", err)
	}
	if err := g.AuthorizePeer(a.info.DeviceID, "group.send:"+gid); err == nil {
		t.Fatal("AuthorizePeer after Close must fail")
	}

	// A dropped, unclosed handle is released by its finalizer without crashing.
	func() {
		dropped, err := a.ep.OpenGroup(gid, "")
		if err != nil {
			t.Fatalf("OpenGroup: %v", err)
		}
		_ = dropped
	}()
	for i := 0; i < 3; i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}

	// Closing concurrently with a polling goroutine is race-free.
	g2, err := a.ep.OpenGroup(gid, "")
	if err != nil {
		t.Fatalf("OpenGroup: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := g2.PollEvent(20); err != nil {
				return
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	_ = g2.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("poller did not stop after Close")
	}
}

func TestGroupCloseWakesParkedPoll(t *testing.T) {
	a := newGroupNode(t)
	m1, err := a.ep.GroupCreate("go-close-wake", 1, nil)
	if err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}
	gid, _ := manifestField(t, m1, "group_id").(string)
	g, err := a.ep.OpenGroup(gid, "")
	if err != nil {
		t.Fatalf("OpenGroup: %v", err)
	}
	type result struct {
		ev  *tendril.GroupEvent
		err error
	}
	polled := make(chan result, 1)
	go func() {
		ev, err := g.PollEvent(60_000)
		polled <- result{ev, err}
	}()
	time.Sleep(200 * time.Millisecond)
	closed := make(chan struct{})
	go func() {
		_ = g.Close()
		close(closed)
	}()
	select {
	case r := <-polled:
		if r.ev != nil || !errors.Is(r.err, io.EOF) {
			t.Fatalf("parked PollEvent must end with io.EOF, got %v, %v", r.ev, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("parked PollEvent did not return after Close")
	}
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close blocked behind the parked PollEvent")
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestGroupSyncAndListener(t *testing.T) {
	a, b := newGroupNode(t), newGroupNode(t)
	enroll(t, a, b)
	m1, err := a.ep.GroupCreate("go-sync", 1, []string{a.addr})
	if err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}
	gid, _ := manifestField(t, m1, "group_id").(string)
	addrB := freeAddr(t)
	manifest, err := a.ep.GroupAddMember(gid, b.info.DeviceID, nil, []string{addrB})
	if err != nil {
		t.Fatalf("GroupAddMember: %v", err)
	}
	if _, err := b.ep.GroupIngestManifest(manifest, a.info.DeviceID); err != nil {
		t.Fatalf("GroupIngestManifest: %v", err)
	}
	ga, err := a.ep.OpenGroup(gid, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("OpenGroup a: %v", err)
	}
	defer ga.Close()
	endpoint, err := ga.LocalEndpoint()
	if err != nil || !strings.Contains(endpoint, "127.0.0.1:") {
		t.Fatalf("LocalEndpoint = %q, %v", endpoint, err)
	}
	gb, err := b.ep.OpenGroup(gid, addrB)
	if err != nil {
		t.Fatalf("OpenGroup b: %v", err)
	}
	defer gb.Close()
	if endpoint, err := gb.LocalEndpoint(); err != nil || endpoint != addrB {
		t.Fatalf("member listener reported %q, %v", endpoint, err)
	}
	report, err := ga.Sync()
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(report.Delivered) != 1 || report.Delivered[0] != b.info.DeviceID {
		t.Fatalf("unexpected sync report: %+v", report)
	}
}
