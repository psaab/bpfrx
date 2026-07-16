// #5910: the local `show security zones detail` renderer (showZonesDisplay)
// carried the SAME present-but-nil InterfaceConfig/InterfaceUnit nil-deref class
// as #5813 that the #5068 pass missed. Its per-interface detail loop did
// `ifc, ok := cfg.Interfaces.Interfaces[base]; if !ok { continue }` then
// `range ifc.Units` — `ok` proves KEY presence, not a non-nil value, so a
// present-but-nil InterfaceConfig (tolerant load / HA config-sync path,
// #3494/#5068) nil-derefs, and a present-but-nil InterfaceUnit nil-derefs on
// `unit.Number`. It now guards `!ok || ifc == nil` and walks units via the
// shared config.RangeUnits nil-safe iterator.
//
// FAIL-ON-REVERT: restoring the raw `if !ok { continue }` + `range ifc.Units`
// makes the injected nil slot deref and panic; the recover turns that into a
// test FAILURE rather than a silent pass.
package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// zoneIfaceCLIStore commits a config binding lo.0 to zone trust so the
// showZonesDisplay(detail) per-interface loop runs. The CLI renderer splits the
// logical "lo.0" to its BASE "lo" and looks that up, so the nil slots are
// injected under the "lo" key.
func zoneIfaceCLIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set security zones security-zone trust interfaces ge-0/0/0.0
set security zones security-zone untrust`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatalf("fixture missing active config")
	}
	if z := cfg.Security.Zones["trust"]; z == nil || len(z.Interfaces) == 0 {
		t.Fatalf("fixture zone trust missing interface binding: %+v", z)
	}
	return store
}

// TestCLIShowZonesDisplayNilIfaceSlots5910 drives the REAL showZonesDisplay
// detail renderer (dp nil: counters skipped) against a zone binding lo.0, with
// a nil InterfaceConfig / nil InterfaceUnit injected under the base "lo" key.
// Without the guards a present-but-nil slot nil-derefs (`range ifc.Units` /
// `unit.Number`).
func TestCLIShowZonesDisplayNilIfaceSlots5910(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(cfg *config.Config)
		wantAddress bool
	}{
		{"nil-interface-config", func(cfg *config.Config) {
			// The CLI renderer splits "ge-0/0/0.0" to the BASE "ge-0/0/0" and
			// looks that up, so inject the present-but-nil slot under the base.
			cfg.Interfaces.Interfaces["ge-0/0/0"] = nil
		}, false},
		{"nil-interface-unit", func(cfg *config.Config) {
			cfg.Interfaces.Interfaces["ge-0/0/0"] = &config.InterfaceConfig{
				Name: "ge-0/0/0",
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"127.0.0.1/8"}},
					7: nil, // present-but-nil unit alongside a valid one
				},
			}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := zoneIfaceCLIStore(t)
			cfg := store.ActiveConfig()
			tc.mutate(cfg)
			c := &CLI{store: store} // dp nil: skip counters, run interface detail
			out := captureStdout(t, func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("showZonesDisplay %s panicked (nil-guard regression #5910): %v", tc.name, r)
					}
				}()
				if err := c.showZonesDisplay(cfg, true, ""); err != nil {
					t.Fatalf("showZonesDisplay: %v", err)
				}
			})
			if tc.wantAddress && !strings.Contains(out, "127.0.0.1/8") {
				t.Fatalf("valid unit address dropped by nil-unit skip:\n%s", out)
			}
		})
	}
}
