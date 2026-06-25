package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2008 M5: the application-identification catalog must reach the userspace
// dataplane via the snapshot wire so the dataplane can stamp app_id on sessions.
// These tests pin that the catalog is built into the snapshot and survives a
// JSON round-trip (the #1961-class wire-parity guard).

func appCatalogTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true
	cfg.Applications.Applications = map[string]*config.Application{
		"my-app": {Name: "my-app", Protocol: "tcp", DestinationPort: "8443"},
	}
	return cfg
}

func TestBuildSnapshotShipsAppCatalog_M5(t *testing.T) {
	cfg := appCatalogTestConfig()
	snap, _ := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.AppCatalog) == 0 {
		t.Fatal("snapshot AppCatalog is empty; catalog never ships to Rust (#2008 M5)")
	}
	// my-app must appear with the right protocol/port and a nonzero app_id.
	var found bool
	for _, e := range snap.AppCatalog {
		if e.Protocol == 6 && e.DstPortLow == 8443 && e.DstPortHigh == 8443 {
			found = true
			if e.AppID == 0 {
				t.Fatal("my-app catalog entry has app_id 0 (reserved unknown sentinel)")
			}
		}
	}
	if !found {
		t.Fatalf("my-app (tcp/8443) not in AppCatalog: %+v", snap.AppCatalog)
	}
}

func TestAppCatalogSnapshotJSONRoundTrip_M5(t *testing.T) {
	cfg := appCatalogTestConfig()
	snap, _ := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	// The wire field name MUST be app_catalog (matches the Rust serde rename).
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if _, ok := raw["app_catalog"]; !ok {
		t.Fatalf("snapshot JSON missing app_catalog field; keys=%v", keysOf(raw))
	}

	var back ConfigSnapshot
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if len(back.AppCatalog) != len(snap.AppCatalog) {
		t.Fatalf("AppCatalog round-trip size: got %d want %d",
			len(back.AppCatalog), len(snap.AppCatalog))
	}
	for i := range snap.AppCatalog {
		if back.AppCatalog[i] != snap.AppCatalog[i] {
			t.Fatalf("AppCatalog[%d] round-trip mismatch: %+v vs %+v",
				i, back.AppCatalog[i], snap.AppCatalog[i])
		}
	}
}

// An old Go binary that never sets AppCatalog (and the AppID-disabled case)
// must omit the field entirely so an old Rust helper decoding it is unaffected
// and a new Rust helper sees an empty catalog (every session keeps app_id 0).
func TestAppCatalogOmittedWhenEmpty_M5(t *testing.T) {
	cfg := &config.Config{} // no applications referenced, AppID off
	snap, _ := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.AppCatalog) != 0 {
		t.Fatalf("expected empty AppCatalog for bare config, got %+v", snap.AppCatalog)
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if _, ok := raw["app_catalog"]; ok {
		t.Fatal("empty AppCatalog must be omitted from the wire (omitempty), but it was present")
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
