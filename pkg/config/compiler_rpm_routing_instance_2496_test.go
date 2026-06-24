package config

import (
	"strings"
	"testing"
)

// TestRPMRoutingInstanceStrictRejects pins the #2496 commit-time gate: an
// RPM test whose `routing-instance` names a nonexistent / typo'd instance
// is hard-rejected on the strict path (commit / commit-check). The runtime
// would bind the probe DATA socket to a synthesized vrf-<name> device
// (SO_BINDTODEVICE) that does not exist -> ENODEV -> the probe never sends
// a packet and the test silently HOLDS its state forever, starving any
// event-options / ip-monitoring policy keyed off it of a failover signal.
//
// The target is an IP literal so the scoped-hostname gate (#2493), which
// runs earlier and would also reject a hostname on a scoped test, does not
// fire first — this isolates the routing-instance cross-reference check.
//
// This FAILS against master, which has no routing-instance cross-reference
// gate and silently accepts the unprobeable test.
func TestRPMRoutingInstanceStrictRejects(t *testing.T) {
	lines := []string{
		"set routing-instances ISP-B instance-type forwarding",
		"set services rpm probe P test t routing-instance ISP-TYPO",
		"set services rpm probe P test t target 8.8.8.8",
	}
	tree := buildTree(t, lines)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an RPM test referencing a nonexistent routing-instance; want strict reject")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v, want substring %q", err, "does not exist")
	}
}

// TestRPMRoutingInstanceLenientWarns pins the no-brick contract (#1960
// doctrine): the nonexistent-instance the strict path rejects is TOLERATED
// on the lenient load / peer-sync path — downgraded to a warning so an
// already-persisted or peer-synced config still boots. The runtime VRF
// bind then returns ENODEV and the test holds state.
func TestRPMRoutingInstanceLenientWarns(t *testing.T) {
	lines := []string{
		"set routing-instances ISP-B instance-type forwarding",
		"set services rpm probe P test t routing-instance ISP-TYPO",
		"set services rpm probe P test t target 8.8.8.8",
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a bad rpm routing-instance (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "rpm routing-instance") {
		t.Fatalf("expected a downgraded rpm routing-instance warning, warnings=%v", cfg.Warnings)
	}
}

// TestRPMRoutingInstanceConfiguredAccepted confirms NO regression: an RPM
// test whose routing-instance names a CONFIGURED instance is accepted, and
// a test with an EMPTY routing-instance (default/master context — not
// scoped to any VRF device) is likewise accepted.
func TestRPMRoutingInstanceConfiguredAccepted(t *testing.T) {
	t.Run("configured instance accepted", func(t *testing.T) {
		lines := []string{
			"set routing-instances ISP-B instance-type forwarding",
			"set services rpm probe P test t routing-instance ISP-B",
			"set services rpm probe P test t target 8.8.8.8",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("RPM test naming a configured routing-instance must be accepted: %v", err)
		}
	})

	t.Run("empty routing-instance (default context) accepted", func(t *testing.T) {
		lines := []string{
			"set services rpm probe P test t target 8.8.8.8",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("RPM test with no routing-instance (default context) must be accepted: %v", err)
		}
	})
}
