package tendril_test

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	tendril "github.com/agync/tendril/bindings/go"
)

func asRefused(t *testing.T, err error) *tendril.RefusedError {
	t.Helper()
	var refused *tendril.RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("error %v is not a *RefusedError", err)
	}
	return refused
}

func TestRefusedV2ConnectIsATypedError(t *testing.T) {
	p := newRoutesHost(t, t.TempDir(), true)
	if err := p.ep.RevokePeer(p.deviceID); err != nil {
		t.Fatalf("RevokePeer: %v", err)
	}
	_, _, err := connectPair(t, p.ep, true, func() (*tendril.Session, error) {
		return p.clientEp.ConnectV2("", "", p.hostID, p.grant)
	})
	if err == nil {
		t.Fatal("a revoked peer connected")
	}
	refused := asRefused(t, err)
	if refused.Reason != tendril.RefusalRevoked || refused.CloseCode != tendril.CloseCodePeerRevoked {
		t.Fatalf("unexpected refusal: %+v", refused)
	}
	if refused.Code != "refused_revoked" || !strings.Contains(refused.Error(), "revoked") {
		t.Fatalf("unexpected code or text: %+v / %q", refused, refused.Error())
	}
}

func TestRefusedConnectWithOptionsV2IsATypedError(t *testing.T) {
	p := newRoutesHost(t, t.TempDir(), true)
	if err := p.ep.RevokePeer(p.deviceID); err != nil {
		t.Fatalf("RevokePeer: %v", err)
	}
	_, _, err := connectPair(t, p.ep, true, func() (*tendril.Session, error) {
		return p.clientEp.ConnectWithOptions(p.hostID, &tendril.ConnectOptions{
			Wire:  2,
			Grant: json.RawMessage(p.grant),
		})
	})
	if err == nil {
		t.Fatal("a revoked peer connected")
	}
	refused := asRefused(t, err)
	if refused.Reason != tendril.RefusalRevoked || refused.CloseCode != tendril.CloseCodePeerRevoked {
		t.Fatalf("unexpected refusal: %+v", refused)
	}
	if refused.Code != "refused_revoked" {
		t.Fatalf("unexpected code: %+v", refused)
	}
}

func TestRefusedV1RefusalSurfacesAfterConnect(t *testing.T) {
	p := newRoutesHost(t, t.TempDir(), false)
	if err := p.ep.RevokePeer(p.deviceID); err != nil {
		t.Fatalf("RevokePeer: %v", err)
	}
	accepting := make(chan struct{})
	go func() { // the host writes the notice while it accepts
		defer close(accepting)
		if s, err := p.ep.AcceptSession(3000); err == nil {
			_ = s.Close()
		}
	}()
	cs, err := p.clientEp.Connect("", "", p.hostID, p.grant)
	if err != nil {
		t.Fatalf("v1 connect returns before the refusal: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close(); <-accepting })
	var closed *tendril.SessionEvent
	deadline := time.Now().Add(10 * time.Second)
	for closed == nil && time.Now().Before(deadline) {
		ev, err := cs.PollEvent(500)
		if errors.Is(err, tendril.ErrWouldBlock) {
			continue
		}
		if err != nil {
			t.Fatalf("PollEvent: %v", err)
		}
		if ev.Event == "closed" {
			closed = ev
		}
	}
	if closed == nil {
		t.Fatal("no closed event")
	}
	if closed.Refusal != "revoked" || closed.Code != tendril.CloseCodePeerRevoked {
		t.Fatalf("unexpected closed event: %+v", closed)
	}
	if r := closed.Refused(); r == nil || r.Reason != tendril.RefusalRevoked {
		t.Fatalf("Refused() = %+v", r)
	}
	if r := (&tendril.SessionEvent{Event: "closed", Code: 1000}).Refused(); r != nil {
		t.Fatalf("a plain close is no refusal: %+v", r)
	}
	if got := asRefused(t, cs.SendData([]byte("x"))); got.Reason != tendril.RefusalRevoked {
		t.Fatalf("SendData refusal: %+v", got)
	}
	if err := cs.Rekey(); err == nil {
		t.Fatal("Rekey after a refusal succeeded")
	} else if got := asRefused(t, err); got.CloseCode != tendril.CloseCodePeerRevoked {
		t.Fatalf("Rekey refusal: %+v", got)
	}
}

func TestRefusalEndpointCalls(t *testing.T) {
	notify := false
	t.Run("silent revoke leaves no notice", func(t *testing.T) {
		p := newRoutesHost(t, t.TempDir(), true)
		if err := p.ep.RevokePeerWithOptions(p.deviceID, &tendril.RevokeOptions{Notify: &notify}); err != nil {
			t.Fatalf("RevokePeerWithOptions: %v", err)
		}
		_, _, err := connectPair(t, p.ep, true, func() (*tendril.Session, error) {
			return p.clientEp.ConnectV2("", "", p.hostID, p.grant)
		})
		if err == nil {
			t.Fatal("a revoked peer connected")
		}
		var refused *tendril.RefusedError
		if errors.As(err, &refused) {
			t.Fatalf("a silent revoke refused: %+v", refused)
		}
	})
	t.Run("policy without notices", func(t *testing.T) {
		p := newRoutesHost(t, t.TempDir(), true)
		if err := p.ep.SetRefusalPolicy(tendril.RefusalPolicy{Pending: true, RevokedNoticeTTLSecs: 0}); err != nil {
			t.Fatalf("SetRefusalPolicy: %v", err)
		}
		if err := p.ep.RevokePeerWithOptions(p.deviceID, nil); err != nil {
			t.Fatalf("RevokePeerWithOptions: %v", err)
		}
		_, _, err := connectPair(t, p.ep, true, func() (*tendril.Session, error) {
			return p.clientEp.ConnectV2("", "", p.hostID, p.grant)
		})
		var refused *tendril.RefusedError
		if err == nil || errors.As(err, &refused) {
			t.Fatalf("ttl 0 must record no notice, got %v", err)
		}
	})
	t.Run("clear notice", func(t *testing.T) {
		p := newRoutesHost(t, t.TempDir(), true)
		if err := p.ep.RevokePeer(p.deviceID); err != nil {
			t.Fatalf("RevokePeer: %v", err)
		}
		if err := p.ep.ClearRefusalNotice(p.deviceID); err != nil {
			t.Fatalf("ClearRefusalNotice: %v", err)
		}
		_, _, err := connectPair(t, p.ep, true, func() (*tendril.Session, error) {
			return p.clientEp.ConnectV2("", "", p.hostID, p.grant)
		})
		var refused *tendril.RefusedError
		if err == nil || errors.As(err, &refused) {
			t.Fatalf("a cleared notice must not refuse, got %v", err)
		}
		if err := p.ep.ClearRefusalNotice("no-such-peer"); err == nil {
			t.Fatal("clearing an unknown peer succeeded")
		}
	})
}

// A refused connect reads the message and the code on the thread of the failing call. Other
// goroutines issuing FFI calls at the same time must never see or clear them. The host limits
// refusal notices per peer, so each round uses a fresh host and a single refused connect.
func TestRefusedErrorSurvivesConcurrentFFICalls(t *testing.T) {
	for round := 0; round < 3; round++ {
		p := newRoutesHost(t, t.TempDir(), true)
		if err := p.ep.RevokePeer(p.deviceID); err != nil {
			t.Fatalf("RevokePeer: %v", err)
		}
		accepting := make(chan struct{})
		go func() {
			defer close(accepting)
			if s, err := p.ep.AcceptV2(3000); err == nil {
				_ = s.Close()
			}
		}()
		stop := make(chan struct{})
		var noise sync.WaitGroup
		for i := 0; i < 4; i++ {
			noise.Add(1)
			go func() {
				defer noise.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					_, _ = p.clientEp.Info()
					_, _ = tendril.DeviceID([32]byte{})
				}
			}()
		}
		_, err := p.clientEp.ConnectV2("", "", p.hostID, p.grant)
		close(stop)
		noise.Wait()
		<-accepting
		if err == nil {
			t.Fatal("a revoked peer connected")
		}
		if got := asRefused(t, err); got.Reason != tendril.RefusalRevoked {
			t.Fatalf("lost the typed refusal: %+v", got)
		}
	}
}
