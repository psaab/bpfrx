package ddns

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"net/http"
	"net/http/httptest"

	"github.com/psaab/xpf/pkg/config"
)

// surface_a_http_test.go: end-to-end engine-through-HTTP-backend tests (#2691
// P3). These drive the REAL SurfaceAManager (change-detection / forced-refresh /
// backoff / per-RG gate) through the REAL productionSurfaceABackend resolver and
// a REAL dyndns2 backend pointed at an httptest server — the full publish path,
// no fakeUpdater shortcut. This is the integration proof the plan requires: the
// engine drives the right HTTP calls, change-detection skips a no-change, and a
// backend error arms the engine backoff.

// httpScope builds a Surface A scope bound to a dyndns2 provider whose Server is
// the mock endpoint.
func httpScope(fqdn, serverURL string) SurfaceAScope {
	return SurfaceAScope{
		Key: ScopeKey{
			Family: FamilyV4, Interface: "ge-0-0-2", Unit: 50, RGOwner: 0,
			PolicyID: "dd2",
		},
		FQDN:   fqdn,
		TTL:    300,
		Source: AddressSourceInterface,
		Provider: &config.DDNSProvider{
			Name: "dd2", Backend: "dyndns2", Server: serverURL,
			Username: "u", Password: config.Secret("p"),
		},
	}
}

// newHTTPEngineManager builds a SurfaceAManager wired to the PRODUCTION backend
// factory (so the engine resolves a real dyndns2 backend per scope).
func newHTTPEngineManager(t *testing.T, now func() time.Time) *SurfaceAManager {
	t.Helper()
	st, _ := loadDDNSState(filepath.Join(t.TempDir(), "iface-ddns.json"))
	m := &SurfaceAManager{
		state:      st,
		runtime:    map[string]*surfaceAState{},
		newBackend: productionSurfaceABackend,
		now:        now,
	}
	m.seedFromStore()
	return m
}

type dyndns2Counter struct {
	mu     sync.Mutex
	calls  int
	lastIP string
	fail   bool
}

func (c *dyndns2Counter) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.calls++
		c.lastIP = r.URL.Query().Get("myip")
		fail := c.fail
		c.mu.Unlock()
		if fail {
			_, _ = w.Write([]byte("911\n"))
			return
		}
		_, _ = w.Write([]byte("good " + r.URL.Query().Get("myip") + "\n"))
	})
}

func TestEngineThroughDyndns2PublishAndSkip(t *testing.T) {
	cnt := &dyndns2Counter{}
	srv := httptest.NewServer(cnt.handler())
	defer srv.Close()
	now := time.Unix(1_700_000_000, 0)
	m := newHTTPEngineManager(t, func() time.Time { return now })
	sc := httpScope("wan.example.net", srv.URL)

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("publish: %v", err)
	}
	cnt.mu.Lock()
	calls, ip := cnt.calls, cnt.lastIP
	cnt.mu.Unlock()
	if calls != 1 || ip != "203.0.113.5" {
		t.Fatalf("expected one publish of 203.0.113.5, got calls=%d ip=%q", calls, ip)
	}
	// Second pass, unchanged, within forced-refresh: change-detection must SKIP
	// the wire call (no new HTTP request).
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("skip pass: %v", err)
	}
	cnt.mu.Lock()
	calls = cnt.calls
	cnt.mu.Unlock()
	if calls != 1 {
		t.Fatalf("unchanged address must not re-hit the provider; calls=%d", calls)
	}
	// Address change → a new wire publish.
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.9"), nil, nil); err != nil {
		t.Fatalf("change publish: %v", err)
	}
	cnt.mu.Lock()
	calls, ip = cnt.calls, cnt.lastIP
	cnt.mu.Unlock()
	if calls != 2 || ip != "203.0.113.9" {
		t.Fatalf("address change must republish; calls=%d ip=%q", calls, ip)
	}
}

func TestEngineThroughDyndns2BackoffOnError(t *testing.T) {
	cnt := &dyndns2Counter{fail: true}
	srv := httptest.NewServer(cnt.handler())
	defer srv.Close()
	now := time.Unix(1_700_000_000, 0)
	m := newHTTPEngineManager(t, func() time.Time { return now })
	sc := httpScope("wan.example.net", srv.URL)

	// First pass: the provider returns 911 → publish error → engine arms backoff.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err == nil {
		t.Fatal("expected a publish error from the 911 response")
	}
	cnt.mu.Lock()
	c1 := cnt.calls
	cnt.mu.Unlock()
	// Immediate retry inside the backoff window: the scope is skipped (no wire
	// call) — ban-avoidance.
	now = now.Add(time.Second)
	_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil)
	cnt.mu.Lock()
	c2 := cnt.calls
	cnt.mu.Unlock()
	if c2 != c1 {
		t.Fatalf("scope in backoff must not hit the provider again; calls %d -> %d", c1, c2)
	}
	if st := m.Stats(); st.BackedOff < 1 {
		t.Fatalf("expected a backed-off skip, got %+v", st)
	}
}

// TestEngineSecretsNeverLogged asserts the credential-handling invariant
// (plan §8.1): a provider's password/token is never present in the catalog
// entry's String() (used by %v/slog) nor in any error the publish path returns.
func TestEngineSecretsNeverLogged(t *testing.T) {
	const secret = "SUPER-SECRET-TOKEN-9f3a"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a hard auth failure so the publish errors — the error must not
		// echo the password.
		_, _ = w.Write([]byte("badauth\n"))
	}))
	defer srv.Close()

	prov := &config.DDNSProvider{
		Name: "dd2", Backend: "dyndns2", Server: srv.URL,
		Username: "u", Password: config.Secret(secret),
		APIToken: config.Secret(secret), AWSSecretAccessKey: config.Secret(secret),
		TSIGSecret: config.Secret(secret),
	}
	// String()/slog formatting must redact every secret.
	if s := prov.String(); strings.Contains(s, secret) {
		t.Fatalf("DDNSProvider.String() leaked a secret: %q", s)
	}

	now := time.Unix(1_700_000_000, 0)
	m := newHTTPEngineManager(t, func() time.Time { return now })
	sc := httpScope("wan.example.net", srv.URL)
	sc.Provider = prov
	sc.Key.PolicyID = "dd2"

	err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil)
	if err == nil {
		t.Fatal("expected a badauth publish error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("publish error leaked the secret: %q", err.Error())
	}
}
