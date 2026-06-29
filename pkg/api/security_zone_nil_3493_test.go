package api

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #3493: the REST interface/zone inventory and per-zone stats surfaces iterate
// cfg.Security.Zones (map[string]*ZoneConfig) and dereference the value
// (zone.Interfaces / zone.Description / zone.ScreenProfile). A nil map VALUE is
// reachable on the tolerant / HA-sync config path (#3474/#3476 premise) and the
// runtime walker (pkg/dataplane/userspace/zones.go) already skips it. These
// tests inject a nil zone value into the live ActiveConfig and drive each REST
// surface; reverting any of the api.go / interfaces.go / stats.go / security.go
// `if zone == nil { continue }` guards makes the matching call panic (RED on
// revert). Distinct from #3476, which covered nil zone-PAIR / rule / screen.

// nilZoneValueAPIStore commits a config with one real zone and then injects a
// nil zone map value (the strict compiler never emits one; the tolerant path
// can). The committed map is non-nil so the nil entry survives.
func nilZoneValueAPIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            screen sp;
        }
        security-zone untrust;
    }
    screen {
        ids-option sp {
            tcp { land; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		t.Fatalf("fixture missing zones")
	}
	cfg.Security.Zones["zz-nil-zone"] = nil
	return store
}

func TestAPIAllInterfaceNamesNilZoneNoPanic(t *testing.T) {
	cfg := nilZoneValueAPIStore(t).ActiveConfig()
	// Panics on revert of the api.go:allInterfaceNames `if zone == nil` guard.
	_ = allInterfaceNames(cfg)
}

func TestAPIZoneInventoryNilZoneNoPanic(t *testing.T) {
	s := &Server{
		store: nilZoneValueAPIStore(t),
		dp: &schedulerCounterAPIDP{
			Manager:  dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{},
		},
	}
	// zonesHandler builds ZoneInfo from each zone value (security.go).
	rr := httptest.NewRecorder()
	s.zonesHandler(rr, httptest.NewRequest("GET", "/api/v1/security/zones", nil))
	if rr.Code != 200 {
		t.Fatalf("zonesHandler status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	// interfaces.go terse + detail + stats.go iface->zone map builders.
	s.interfacesHandler(httptest.NewRecorder(),
		httptest.NewRequest("GET", "/api/v1/interfaces", nil))
	s.interfacesDetailHandler(httptest.NewRecorder(),
		httptest.NewRequest("GET", "/api/v1/interfaces/detail", nil))
	s.ifaceStatsHandler(httptest.NewRecorder(),
		httptest.NewRequest("GET", "/api/v1/stats/interfaces", nil))
}
