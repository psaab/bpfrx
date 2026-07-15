package monitoriface

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestTrafficSummaryInterfacesNilSlotNoPanic_5886 pins the #5886 fix in
// resolveConfiguredTrafficKernel (monitor.go): a PRESENT-but-nil
// InterfaceConfig slot — which a tolerant load / HA config-sync can leave
// (#3494/#5068) — must NOT panic the read-only traffic-summary path (the CLI
// `show interfaces` traffic summary and the gRPC MonitorInterface RPC both
// call TrafficSummaryInterfaces on the active config). Before the fix the raw
// `cfg.Interfaces.Interfaces[base]; ok && ifc.LocalFabricMember != ""` derefed
// the nil value and crashed xpfd.
//
// Fail-on-revert: restore the raw map-index deref at monitor.go:343 and this
// test PANICS (nil pointer dereference) → RED. No recover() is used — a panic
// unwinds through the test and fails it naturally.
func TestTrafficSummaryInterfacesNilSlotNoPanic_5886(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				// Present key, nil value — the exact #5886 hazard. Both the
				// `for name := range cfg.Interfaces.Interfaces` sweep in
				// configuredTrafficSummaryInterfaces and the direct resolver call
				// below drive this key into resolveConfiguredTrafficKernel.
				"zz-nil-ifc": nil,
				"ge-0-0-0":   {Name: "ge-0-0-0"},
			},
		},
	}

	// The public entry point used by both operator surfaces. Must complete
	// without panicking on the nil slot; the nil interface is simply omitted.
	names, kernels := TrafficSummaryInterfaces(cfg)
	if names == nil && kernels == nil {
		// A nil,nil return is acceptable (no configured summary interfaces); the
		// point of this test is that the call did not panic.
		return
	}
	for _, n := range names {
		if n == "zz-nil-ifc" {
			// A present-but-nil slot must not surface as a resolved summary
			// interface (it has no config to summarize).
			t.Fatalf("present-but-nil interface slot must be omitted from the traffic summary, got %v", names)
		}
	}

	// Direct hit on the fixed resolver for the nil-slot key — resolves to the
	// fallback (its own canonical name), never a phantom fabric member, and
	// never a nil deref.
	if got := resolveConfiguredTrafficKernel(cfg, "zz-nil-ifc", func(s string) string { return s }); got == "" {
		t.Fatalf("resolveConfiguredTrafficKernel on a present-but-nil slot returned empty; want the fallback name")
	}
}
