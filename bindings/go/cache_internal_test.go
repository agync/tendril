package tendril

import "testing"

func TestConfigCacheClearedOnCloseAndKeptOnFailure(t *testing.T) {
	ep, err := NewEndpoint("", "go-cache-ep")
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer ep.Close()
	if err := ep.ConfigureTransportsJSON(`{"route_policy":"committed_only"}`); err != nil {
		t.Fatalf("ConfigureTransportsJSON: %v", err)
	}
	if err := ep.ConfigureRoutes(RouteConfig{RoutePolicy: "sometimes"}); err == nil {
		t.Fatalf("expected invalid route policy to be rejected")
	}
	ep.cfgMu.Lock()
	got := string(ep.cfg["route_policy"])
	ep.cfgMu.Unlock()
	if got != `"committed_only"` {
		t.Fatalf("failed ConfigureRoutes changed the cache: %q", got)
	}
	if err := ep.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ep.cfgMu.Lock()
	cleared := ep.cfg == nil
	ep.cfgMu.Unlock()
	if !cleared {
		t.Fatalf("Close must clear the config cache")
	}
}
