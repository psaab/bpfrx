package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #5410: #5298 made static `reject` routes first-class (they install into
// the kernel FIB as RTN_UNREACHABLE via FRR), but the REST /routes handler
// lumped a reject route into the same no-next-hop branch as discard and
// emitted NO disposition label — so a reject and a discard route were
// indistinguishable, and a plain no-next-hop route carried no marker
// either. This test injects reject / discard / connected / normal /
// next-table static routes into the live ActiveConfig, drives
// routesHandler, and asserts each carries the right disposition (mirroring
// the CLI/gRPC `show route` reject/discard labels) while a real next-hop /
// next-table route leaks nothing new (backward-compatible, additive
// field). Reverting the routing.go disposition logic makes the reject
// route render with an empty disposition — RED on revert.
func routesDispositionStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	// Commit a minimal config so an ActiveConfig exists; then inject the
	// static routes post-commit so no recompile normalizes them away.
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
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.1.0.0/24", Reject: true, Preference: 5},
		{Destination: "10.2.0.0/24", Discard: true, Preference: 5},
		{Destination: "10.3.0.0/24", Preference: 5}, // no next-hop => connected
		{Destination: "10.4.0.0/24", Preference: 7, NextHops: []config.NextHopEntry{
			{Address: "10.4.0.254", Interface: "ge-0-0-0"},
		}},
		{Destination: "10.5.0.0/24", NextTable: "Comcast", Preference: 5},
	}
	return store
}

func TestRoutesHandlerRejectDiscardDisposition(t *testing.T) {
	s := &Server{store: routesDispositionStore(t)}

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

	// reject => labeled "reject", never lumped with discard, no phantom
	// next-hop/next-table.
	if got := byDest["10.1.0.0/24"]; got.Disposition != "reject" ||
		got.NextHop != "" || got.NextTable != "" {
		t.Errorf("reject route = %+v, want disposition=reject, no next-hop/next-table", got)
	}
	// discard => "discard".
	if got := byDest["10.2.0.0/24"]; got.Disposition != "discard" {
		t.Errorf("discard route = %+v, want disposition=discard", got)
	}
	// connected (no next-hop, not reject/discard) => "connected".
	if got := byDest["10.3.0.0/24"]; got.Disposition != "connected" {
		t.Errorf("no-next-hop route = %+v, want disposition=connected", got)
	}
	// A normal next-hop route is unchanged: real next-hop, empty
	// disposition (backward-compatible / additive field).
	if got := byDest["10.4.0.0/24"]; got.NextHop != "10.4.0.254" ||
		got.Interface != "ge-0-0-0" || got.Disposition != "" {
		t.Errorf("next-hop route = %+v, want next-hop 10.4.0.254 via ge-0-0-0, empty disposition", got)
	}
	// A next-table route is unchanged: next-table set, empty disposition.
	if got := byDest["10.5.0.0/24"]; got.NextTable != "Comcast" || got.Disposition != "" {
		t.Errorf("next-table route = %+v, want next-table Comcast, empty disposition", got)
	}
}
