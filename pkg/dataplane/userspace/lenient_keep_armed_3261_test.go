package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3261 — an unrepresentable-content config (e.g. a leniently-loaded or
// peer-synced protocol-less application that #3257's strict-commit reject
// cannot catch on the lenient path) must NOT disarm the userspace helper. The
// snapshot still publishes carrying the __unsupported__ sentinel, and the
// helper's integrity preflight rejects it while staying armed — keeping the
// previous-good policy state on a running node, or the default-deny PolicyState
// on a fresh boot. Disarming instead XDP_PASSes transit to the kernel and
// bypasses the reject (the system-level fail-OPEN this fixes). These tests pin
// the Go capability-gate / diagnostic half of the contract; policy_tests.rs and
// server/tests.rs pin the Rust reject + default-deny half.

// goodAndBadPolicyCfg builds a config with one fully-representable policy (a
// plain tcp application) AND one policy whose application is unrepresentable (a
// protocol-less app — the lenient/synced case). The GOOD policy proves the
// whole dataplane is not condemned by one BAD policy.
func goodAndBadPolicyCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Applications.Applications = map[string]*config.Application{
		"good-tcp": {Name: "good-tcp", Protocol: "tcp", DestinationPort: "443"},
		"bad-app":  {Name: "bad-app", Protocol: ""}, // protocol-less: unrepresentable
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{
			{
				Name: "permit-good",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"good-tcp"},
				},
				Action: config.PolicyPermit,
			},
			{
				Name: "deny-bad",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"bad-app"},
				},
				Action: config.PolicyDeny,
			},
		},
	}}
	return cfg
}

func TestDeriveCapabilitiesKeepsArmedForUnrepresentableContent(t *testing.T) {
	// THE #3261 repro / fail-on-revert anchor. Pre-fix this set
	// ForwardingSupported=false (disarm -> kernel fail-open). The fix keeps it
	// true and records the content as a non-disarming diagnostic. Reverting the
	// capabilities.go split flips ForwardingSupported back to false -> RED.
	caps := deriveUserspaceCapabilities(goodAndBadPolicyCfg())
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, want true: unrepresentable policy content must NOT disarm the helper (#3261). UnsupportedReasons=%v", caps.UnsupportedReasons)
	}
	if len(caps.PolicyContentRejected) == 0 {
		t.Fatal("PolicyContentRejected is empty, want a reason recorded for the unrepresentable content diagnostic")
	}
	if len(caps.UnsupportedReasons) != 0 {
		t.Fatalf("UnsupportedReasons = %v, want empty (content rejection is not a forwarding-unsupported semantic)", caps.UnsupportedReasons)
	}
}

func TestDeriveCapabilitiesDisarmsForGenuineSemanticGap(t *testing.T) {
	// Class (ii) non-regression: a genuinely-unsupported semantic (color-aware
	// three-color policer) still sets ForwardingSupported=false and is NOT
	// recorded as content rejection. Proves #3261 did not weaken the legitimate
	// disarm cases.
	caps := deriveUserspaceCapabilities(colorAwarePolicerCfg())
	if caps.ForwardingSupported {
		t.Fatal("ForwardingSupported = true, want false: a color-aware three-color policer is a genuine semantic gap (class ii) and must still disarm")
	}
	if len(caps.UnsupportedReasons) == 0 {
		t.Fatal("UnsupportedReasons is empty, want the three-color policer reason")
	}
	if len(caps.PolicyContentRejected) != 0 {
		t.Fatalf("PolicyContentRejected = %v, want empty for a class-(ii) semantic gap", caps.PolicyContentRejected)
	}
}

func TestPolicyContentRejectionDiagnosticTracksTransitions(t *testing.T) {
	m := New()
	// Representable -> nothing recorded.
	m.recordPolicyContentRejectionLocked(nil)
	if len(m.lastSnapshotRejectReasons) != 0 {
		t.Fatalf("lastSnapshotRejectReasons = %v, want empty after representable build", m.lastSnapshotRejectReasons)
	}
	// Becomes unrepresentable -> recorded.
	reasons := deriveUserspaceCapabilities(goodAndBadPolicyCfg()).PolicyContentRejected
	m.recordPolicyContentRejectionLocked(reasons)
	if len(m.lastSnapshotRejectReasons) == 0 {
		t.Fatal("lastSnapshotRejectReasons is empty after recording an unrepresentable build")
	}
	// Clears again -> recorded empty (so status / metric reflect recovery).
	m.recordPolicyContentRejectionLocked(nil)
	if len(m.lastSnapshotRejectReasons) != 0 {
		t.Fatalf("lastSnapshotRejectReasons = %v, want empty after recovery", m.lastSnapshotRejectReasons)
	}
}

// TestSnapshotKeepsArmedAndCarriesSentinelForUnrepresentableContent ties the
// two halves together at the snapshot level: the built snapshot for an
// unrepresentable-content config (1) reports ForwardingSupported=true (helper
// stays armed) and (2) carries the __unsupported__ sentinel term that the Rust
// integrity preflight rejects (previous-good retained). Both must hold for the
// fail-closed-without-fail-open property.
func TestSnapshotKeepsArmedAndCarriesSentinelForUnrepresentableContent(t *testing.T) {
	snap, err := buildSnapshot(goodAndBadPolicyCfg(), config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if !snap.Capabilities.ForwardingSupported {
		t.Fatal("snapshot Capabilities.ForwardingSupported = false, want true (#3261 keep-armed)")
	}
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Fatal("snapshot Capabilities.PolicyContentRejected empty, want the content diagnostic")
	}
	var sawSentinel bool
	for _, pol := range snap.Policies {
		for _, term := range pol.ApplicationTerms {
			if term.Protocol == unsupportedApplicationSentinel {
				sawSentinel = true
			}
		}
	}
	if !sawSentinel {
		t.Fatal("no __unsupported__ sentinel term in the published snapshot; the Rust integrity preflight would NOT reject it (fail-open)")
	}
}
