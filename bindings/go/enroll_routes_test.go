package tendril_test

import (
	"encoding/base64"
	"testing"

	tendril "github.com/agync/tendril/bindings/go"
)

func enrollResult(t *testing.T, host *groupNode, peer *tendril.Endpoint, peerDeviceID string) tendril.EnrollInitiateResult {
	t.Helper()
	static, err := base64.RawURLEncoding.DecodeString(host.info.StaticPub)
	if err != nil {
		t.Fatalf("decode static: %v", err)
	}
	signing, err := base64.RawURLEncoding.DecodeString(host.info.SigningPub)
	if err != nil {
		t.Fatalf("decode signing: %v", err)
	}
	token, err := host.ep.MintEnrollmentToken(host.info.HostID, peerDeviceID, 900)
	if err != nil {
		t.Fatalf("MintEnrollmentToken: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, e := host.ep.PairAccept(10_000)
		done <- e
	}()
	res, err := peer.EnrollInitiate(host.addr, "", host.info.HostID, static, signing, 0, token, "peer", "machine")
	if err != nil {
		t.Fatalf("EnrollInitiate: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("PairAccept: %v", err)
	}
	return res
}

func TestEnrollInitiateReportsRouteFields(t *testing.T) {
	t.Run("memory only endpoint reports no_state_dir", func(t *testing.T) {
		host := newGroupNode(t)
		mem, err := tendril.NewEndpoint("", "")
		if err != nil {
			t.Fatalf("NewEndpoint: %v", err)
		}
		t.Cleanup(func() { _ = mem.Close() })
		info, err := mem.Info()
		if err != nil {
			t.Fatalf("Info: %v", err)
		}
		res := enrollResult(t, host, mem, info.DeviceID)
		if res.Status != "active" {
			t.Fatalf("status %q", res.Status)
		}
		if res.RoutesReason != "no_state_dir" {
			t.Fatalf("routes_reason %q", res.RoutesReason)
		}
		if len(res.RoutesPersisted) != 0 || len(res.RouteWarnings) != 0 {
			t.Fatalf("routes=%+v warnings=%+v", res.RoutesPersisted, res.RouteWarnings)
		}
	})
	t.Run("stateful endpoint has no reason", func(t *testing.T) {
		host := newGroupNode(t)
		peer := newGroupNode(t)
		res := enrollResult(t, host, peer.ep, peer.info.DeviceID)
		if res.Status != "active" {
			t.Fatalf("status %q", res.Status)
		}
		if res.RoutesReason != "" {
			t.Fatalf("routes_reason %q", res.RoutesReason)
		}
		want := tendril.Route{Hint: "direct:" + host.addr, Source: "committed"}
		found := false
		for _, r := range res.RoutesPersisted {
			found = found || r == want
		}
		if !found {
			t.Fatalf("routes_persisted %+v lacks %+v", res.RoutesPersisted, want)
		}
		if len(res.RouteWarnings) != 0 {
			t.Fatalf("route_warnings %+v", res.RouteWarnings)
		}
	})
}
