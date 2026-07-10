package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #5439: routesHandler iterated ONLY cfg.RoutingOptions.StaticRoutes
// (inet.0), so the REST /routes view silently omitted every IPv6 static
// route AND every per-routing-instance (VRF) static route — not even their
// destination was rendered — while the CLI/gRPC `show route` iterate both
// families and every VRF. This test injects inet.0 + inet6.0 global routes
// AND per-VRF inet.0 + inet6.0 routes into the live ActiveConfig, drives
// routesHandler, and asserts each appears tagged with its family and Junos
// RIB table name, with the #5410 disposition labeling preserved across
// families. Reverting the handler to iterate only StaticRoutes drops every
// v6 and per-VRF route from the response — RED on revert.
func routesV6VRFStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
system {
    host-name xpf;
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	// Global inet.0 (v4): a normal next-hop route (regression check).
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.4.0.0/24", Preference: 7, NextHops: []config.NextHopEntry{
			{Address: "10.4.0.254", Interface: "ge-0-0-0"},
		}},
	}
	// Global inet6.0 (v6): a normal route, plus a reject and a discard route
	// so the disposition labeling is exercised on the v6 path (#5410 compose).
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{
		{Destination: "2001:db8:1::/48", Preference: 5, NextHops: []config.NextHopEntry{
			{Address: "2001:db8:1::1", Interface: "ge-0-0-1"},
		}},
		{Destination: "2001:db8:dead::/48", Reject: true, Preference: 5},
		{Destination: "2001:db8:beef::/48", Discard: true, Preference: 5},
	}
	// Per-VRF (routing-instance) static routes: one v4, one v6.
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name:         "Comcast",
			InstanceType: "vrf",
			StaticRoutes: []*config.StaticRoute{
				{Destination: "192.0.2.0/24", Preference: 5, NextHops: []config.NextHopEntry{
					{Address: "192.0.2.254"},
				}},
			},
			Inet6StaticRoutes: []*config.StaticRoute{
				{Destination: "2001:db8:c0::/48", Preference: 5, NextHops: []config.NextHopEntry{
					{Address: "2001:db8:c0::1"},
				}},
			},
		},
	}
	return store
}

func TestRoutesHandlerIPv6AndVRF(t *testing.T) {
	s := &Server{store: routesV6VRFStore(t)}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/routing/routes", nil)
	s.routesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Success bool        `json:"success"`
		Data    []RouteInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success=false; body: %s", rr.Body.String())
	}

	byDest := map[string]RouteInfo{}
	for _, r := range resp.Data {
		byDest[r.Destination] = r
	}

	// IPv4 inet.0 route still renders as before — no regression, and now
	// tagged with family/table additively.
	if got, ok := byDest["10.4.0.0/24"]; !ok {
		t.Errorf("inet.0 route 10.4.0.0/24 missing from response")
	} else if got.NextHop != "10.4.0.254" || got.Interface != "ge-0-0-0" ||
		got.Family != "inet" || got.Table != "inet.0" || got.Disposition != "" {
		t.Errorf("inet.0 route = %+v, want next-hop 10.4.0.254 via ge-0-0-0, family=inet, table=inet.0", got)
	}

	// IPv6 global route — WAS ABSENT before #5439.
	if got, ok := byDest["2001:db8:1::/48"]; !ok {
		t.Errorf("inet6.0 route 2001:db8:1::/48 missing (the #5439 bug: v6 omitted)")
	} else if got.NextHop != "2001:db8:1::1" || got.Family != "inet6" || got.Table != "inet6.0" {
		t.Errorf("inet6.0 route = %+v, want next-hop 2001:db8:1::1, family=inet6, table=inet6.0", got)
	}

	// IPv6 reject route — disposition labeling composes with #5410 on v6.
	if got, ok := byDest["2001:db8:dead::/48"]; !ok {
		t.Errorf("inet6.0 reject route missing (the #5439 bug)")
	} else if got.Disposition != "reject" || got.Family != "inet6" || got.Table != "inet6.0" {
		t.Errorf("inet6.0 reject route = %+v, want disposition=reject, family=inet6, table=inet6.0", got)
	}
	// IPv6 discard route.
	if got, ok := byDest["2001:db8:beef::/48"]; !ok {
		t.Errorf("inet6.0 discard route missing (the #5439 bug)")
	} else if got.Disposition != "discard" || got.Family != "inet6" {
		t.Errorf("inet6.0 discard route = %+v, want disposition=discard, family=inet6", got)
	}

	// Per-VRF IPv4 static route — WAS ABSENT before #5439, tagged with the
	// instance's Junos RIB name.
	if got, ok := byDest["192.0.2.0/24"]; !ok {
		t.Errorf("per-VRF inet route 192.0.2.0/24 missing (the #5439 bug: per-VRF omitted)")
	} else if got.NextHop != "192.0.2.254" || got.Family != "inet" || got.Table != "Comcast.inet.0" {
		t.Errorf("per-VRF inet route = %+v, want next-hop 192.0.2.254, family=inet, table=Comcast.inet.0", got)
	}

	// Per-VRF IPv6 static route.
	if got, ok := byDest["2001:db8:c0::/48"]; !ok {
		t.Errorf("per-VRF inet6 route 2001:db8:c0::/48 missing (the #5439 bug)")
	} else if got.NextHop != "2001:db8:c0::1" || got.Family != "inet6" || got.Table != "Comcast.inet6.0" {
		t.Errorf("per-VRF inet6 route = %+v, want next-hop 2001:db8:c0::1, family=inet6, table=Comcast.inet6.0", got)
	}
}
