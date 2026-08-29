package config

import (
	"strings"
	"testing"
)

// #5804. `security flow gre-performance-acceleration` is typed, committed, and
// carried all the way to `ForwardingState.gre_acceleration` in the Rust
// dataplane — where nothing reads it. GRE is protocol 47 and has no L4 ports,
// so the shim stamps flow_src_port = flow_dst_port = 0 and `SessionKey` (a
// 5-tuple with no tunnel discriminator) is identical for every keyed tunnel
// sharing the outer addresses. Two GRE/PPTP tunnels between the same pair of
// outer endpoints alias one session.
//
// Enforcing the knob is a dataplane architecture (SessionKey schema change +
// a cross-language session-sync wire change), tracked separately. Until then
// the accepted-only doctrine (#2078/#4231) applies: an operator who sets it
// must be told it has no runtime effect, rather than discovering it from
// aliased sessions.
func TestGREPerformanceAccelerationAdvisory_5804(t *testing.T) {
	tree := buildTree(t, []string{"set security flow gre-performance-acceleration"})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("gre-performance-acceleration must still COMMIT (accepted-only, Junos-valid): %v", err)
	}
	if !cfg.Security.Flow.GREPerformanceAcceleration {
		t.Fatal("the knob did not compile; this test would be vacuous")
	}
	if !warn167Has(cfg, "gre-performance-acceleration") {
		t.Fatalf("no advisory names the knob; an operator is told nothing and believes "+
			"per-tunnel identity is in force. warnings=%v", cfg.Warnings)
	}
	// The cited issue MOVED with the work. #5804 is closed; #7188 is the
	// successor that carries the dataplane half, and it is the issue an
	// operator reading this advisory needs to find. Pinning the closed one
	// would send them to a thread whose Problem statement describes behaviour
	// that no longer exists.
	if !warn167Has(cfg, "#7188") {
		t.Fatalf("the advisory must cite #7188, the CURRENT tracking issue, so the operator "+
			"can find the remaining gap; warnings=%v", cfg.Warnings)
	}

	// The advisory must state the CONSEQUENCE, not just "not enforced". An
	// operator who reads "accepted-only" and nothing else does not learn that
	// two tunnels will share one session's policy and NAT state — which is the
	// only reason this knob's absence matters.
	var advisory string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "gre-performance-acceleration") {
			advisory = w
			break
		}
	}
	// #7188 cut 1 CHANGED WHAT IS TRUE HERE, and this assertion had to change
	// with it. It used to require the words "5-tuple" and "one session",
	// pinning #5804's claim that the knob was inert. That claim became false
	// the moment transit GRE started resolving a discriminator-keyed flow, and
	// the pin then actively defended the falsehood — a test written to hold
	// today's behaviour becomes a test demanding yesterday's.
	//
	// The property now asserted is the one that survives: the advisory must
	// name the REMAINING gap rather than the closed one. It must NOT claim the
	// knob is inert, and it MUST say per-tunnel identity does not cross HA
	// sync, because build_synced_session_key zeroes the discriminator on a
	// peer-synced key and an operator planning around a failover is the one
	// who gets hurt.
	for _, want := range []string{"discriminator", "HA session sync", "failover"} {
		if !strings.Contains(advisory, want) {
			t.Errorf("advisory does not say %q, so it does not tell an operator which half "+
				"of this feature is in force: %q", want, advisory)
		}
	}
	// The inverse, and the half a keyword check alone would miss: the advisory
	// must not still be asserting the pre-#7188 claim. A message that gained
	// the new words while keeping the old sentence reads as self-contradictory
	// and leaves the operator with the wrong model.
	for _, stale := range []string{"accepted-only", "no packet path", "still share one session"} {
		if strings.Contains(advisory, stale) {
			t.Errorf("advisory still carries the pre-#7188 claim %q, which stopped being "+
				"true when transit GRE became discriminator-keyed: %q", stale, advisory)
		}
	}
}

// TestGREAccelerationAdvisorySilentWhenUnset is the negative control. The
// advisory fires on PRESENCE of the knob; a config that never sets it must stay
// quiet, or every commit on every box carries a warning about a feature the
// operator never asked for.
func TestGREAccelerationAdvisorySilentWhenUnset(t *testing.T) {
	tree := buildTree(t, []string{"set security flow allow-dns-reply"})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if warn167Has(cfg, "gre-performance-acceleration") {
		t.Fatalf("a config that does not set the knob must not be warned about it; warnings=%v",
			cfg.Warnings)
	}
}
