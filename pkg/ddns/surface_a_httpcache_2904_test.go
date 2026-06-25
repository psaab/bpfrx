package ddns

import (
	"net/http"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// surface_a_httpcache_2904_test.go: FAIL-ON-REVERT coverage for #2904 — the
// Surface A reconcile path must REUSE the hardened *http.Client (and its
// keep-alive connection pool) across reconcile passes instead of rebuilding a
// fresh http.Transport every pass. The backend OBJECT is still rebuilt per pass
// (resolve-per-Reconcile, #2691); only the expensive transport is cached, keyed
// on the provider's source-binding inputs (source-address / dest-interface /
// routing-instance). These tests go RED if the per-binding cache is removed
// (every resolve allocates a new client) or if its invalidation key stops
// tracking the binding leaves.

// httpClientOf extracts the *http.Client a freshly resolved HTTP backend holds,
// so a test can assert the SAME client (transport/pool) is reused across passes.
func httpClientOf(t *testing.T, u DNSUpdater) *http.Client {
	t.Helper()
	switch b := u.(type) {
	case *genericBackend:
		return b.client
	case *dyndns2Backend:
		return b.client
	case *cloudflareBackend:
		return b.client
	case *route53Backend:
		return b.client
	default:
		t.Fatalf("resolved backend is %T, not an HTTP backend (cannot inspect client)", u)
		return nil
	}
}

// TestSurfaceAHTTPClientReusedAcrossPasses is the core FAIL-ON-REVERT: two
// successive backend resolutions (simulating two reconcile passes) for the SAME
// provider must hand the backend the SAME *http.Client — the cached transport
// and its keep-alive connection pool. Before #2904 each resolution called
// newProviderHTTPClient and built a brand-new http.Transport, so this assertion
// (identical pointers) FAILS without the cache.
func TestSurfaceAHTTPClientReusedAcrossPasses(t *testing.T) {
	m := NewSurfaceAManager()

	p := &config.DDNSProvider{
		Name:        "generic",
		Backend:     "generic",
		URLTemplate: "https://example.test/update?host=%h&ip=%i",
	}

	u1, err := m.resolveBackend(p, "host.example.test", 60)
	if err != nil {
		t.Fatalf("resolveBackend pass 1: %v", err)
	}
	u2, err := m.resolveBackend(p, "host.example.test", 60)
	if err != nil {
		t.Fatalf("resolveBackend pass 2: %v", err)
	}

	c1 := httpClientOf(t, u1)
	c2 := httpClientOf(t, u2)
	if c1 == nil || c2 == nil {
		t.Fatal("resolved HTTP backends have a nil client")
	}
	if c1 != c2 {
		t.Fatalf("Surface A rebuilt the HTTP client across reconcile passes "+
			"(pass1=%p pass2=%p) — the per-binding transport pool was NOT reused (#2904)", c1, c2)
	}
}

// TestSurfaceAHTTPClientReusedAcrossDifferentProvidersSameBinding proves the
// cache is keyed on the BINDING, not the provider name: two distinct providers
// with the same (empty) source binding share one transport. A transport's pool
// is keyed on the destination host:port, so cross-provider reuse only ever
// connects to the host the request targets — sharing is safe and is the whole
// point of pooling.
func TestSurfaceAHTTPClientReusedAcrossDifferentProvidersSameBinding(t *testing.T) {
	m := NewSurfaceAManager()

	pA := &config.DDNSProvider{Name: "a", Backend: "generic", URLTemplate: "https://a.test/u?ip=%i"}
	pB := &config.DDNSProvider{Name: "b", Backend: "generic", URLTemplate: "https://b.test/u?ip=%i"}

	uA, err := m.resolveBackend(pA, "a.test", 60)
	if err != nil {
		t.Fatalf("resolveBackend a: %v", err)
	}
	uB, err := m.resolveBackend(pB, "b.test", 60)
	if err != nil {
		t.Fatalf("resolveBackend b: %v", err)
	}
	if httpClientOf(t, uA) != httpClientOf(t, uB) {
		t.Fatal("same-binding providers must share one cached transport (#2904)")
	}
}

// TestSurfaceAHTTPClientRebuiltWhenBindingChanges proves the invalidation half:
// when an operator changes a binding leaf on commit, the next resolution gets a
// NEW client (a freshly bound transport), not the stale one. Each distinct
// binding input (source-address, dest-interface, routing-instance) must key a
// distinct client.
func TestSurfaceAHTTPClientRebuiltWhenBindingChanges(t *testing.T) {
	m := NewSurfaceAManager()

	base := config.DDNSProvider{
		Name:        "generic",
		Backend:     "generic",
		URLTemplate: "https://example.test/u?ip=%i",
	}

	// Unbound (default route).
	pUnbound := base
	uUnbound, err := m.resolveBackend(&pUnbound, "h.example.test", 60)
	if err != nil {
		t.Fatalf("resolveBackend unbound: %v", err)
	}
	cUnbound := httpClientOf(t, uUnbound)

	// Change source-address → must rebuild.
	pSrc := base
	pSrc.SourceAddress = "127.0.0.2"
	uSrc, err := m.resolveBackend(&pSrc, "h.example.test", 60)
	if err != nil {
		t.Fatalf("resolveBackend source-address: %v", err)
	}
	if httpClientOf(t, uSrc) == cUnbound {
		t.Fatal("changing source-address must rebuild the HTTP client (#2904 invalidation)")
	}

	// Change destination-interface → must rebuild (distinct from both above).
	pIf := base
	pIf.DestinationInterface = "ge-0-0-0"
	uIf, err := m.resolveBackend(&pIf, "h.example.test", 60)
	if err != nil {
		t.Fatalf("resolveBackend dest-interface: %v", err)
	}
	cIf := httpClientOf(t, uIf)
	if cIf == cUnbound || cIf == httpClientOf(t, uSrc) {
		t.Fatal("changing destination-interface must key a distinct HTTP client (#2904 invalidation)")
	}

	// Change routing-instance → must rebuild.
	pVRF := base
	pVRF.RoutingInstance = "vrf-blue"
	uVRF, err := m.resolveBackend(&pVRF, "h.example.test", 60)
	if err != nil {
		t.Fatalf("resolveBackend routing-instance: %v", err)
	}
	if httpClientOf(t, uVRF) == cUnbound {
		t.Fatal("changing routing-instance must rebuild the HTTP client (#2904 invalidation)")
	}

	// Re-resolving the original unbound provider must STILL hit the cache (the
	// entry was not evicted by the other bindings).
	uUnbound2, err := m.resolveBackend(&pUnbound, "h.example.test", 60)
	if err != nil {
		t.Fatalf("resolveBackend unbound (2): %v", err)
	}
	if httpClientOf(t, uUnbound2) != cUnbound {
		t.Fatal("re-resolving the original binding must reuse its cached client (#2904)")
	}
}

// TestSurfaceACheckIPClientReused proves the checkip-probe path (the other
// ~30s-per-pass HTTP caller named in #2904) also reuses the manager's cached
// per-binding client rather than rebuilding a transport every probe.
func TestSurfaceACheckIPClientReused(t *testing.T) {
	m := NewSurfaceAManager()
	p := &config.DDNSProvider{Name: "p", Backend: "generic"}

	c1, err := m.CheckIPClient(p)
	if err != nil {
		t.Fatalf("CheckIPClient 1: %v", err)
	}
	c2, err := m.CheckIPClient(p)
	if err != nil {
		t.Fatalf("CheckIPClient 2: %v", err)
	}
	if c1 != c2 {
		t.Fatalf("checkip probe rebuilt the HTTP client (%p vs %p) — not reusing the cached transport (#2904)", c1, c2)
	}

	// And it shares the SAME client the DNS-update backend uses for the same
	// binding (one pool for the provider's whole HTTP surface).
	u, err := m.resolveBackend(&config.DDNSProvider{Name: "p", Backend: "generic",
		URLTemplate: "https://example.test/u?ip=%i"}, "h.example.test", 60)
	if err != nil {
		t.Fatalf("resolveBackend: %v", err)
	}
	if httpClientOf(t, u) != c1 {
		t.Fatal("checkip and update path must share one cached transport for the same binding (#2904)")
	}
}
