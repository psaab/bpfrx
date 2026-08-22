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
	if !warn167Has(cfg, "#5804") {
		t.Fatalf("the advisory must cite #5804 so the operator can find the tracking issue; "+
			"warnings=%v", cfg.Warnings)
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
	for _, want := range []string{"5-tuple", "one session"} {
		if !strings.Contains(advisory, want) {
			t.Errorf("advisory does not say %q, so it states that the knob is inert without "+
				"stating what goes wrong: %q", want, advisory)
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
