package config

import (
	"strings"
	"testing"
)

// #4785 fold F2 + F3: the anchor-only advisory.
//
// F2 (a REGRESSION this PR introduced). The #4788 advisory it replaced walked
// UNITS as well as interfaces. The replacement examined only `iface.Tunnel`,
// while daemon collection (collectAppliedTunnels, pkg/daemon/daemon_run_routehelpers.go)
// applies EVERY non-nil `unit.Tunnel` with no completeness screen at all and
// routing then creates a mode-independent Tuntap anchor. So
//
//	set interfaces ip-0/0/0 unit 5 tunnel destination 10.0.0.2
//
// emitted nothing (the emitter suppresses a non-WireGuard endpoint missing
// either half), which is exactly why the strict gate is silent for it by
// design — and it also produced NO advisory, while still creating a visible
// `ip-0-0-0u5` device carrying nothing. Neither rejection nor alarm, which
// contradicts the reason the advisory is registered at all.
//
// F3 (wrong cause in a diagnostic). The advisory always said "no tunnel endpoint
// is emitted for the interface-level stanza (every unit overrides it)". For a
// source-only interface stanza with NO units that diagnosis is false and its
// per-unit remediation is the wrong advice.

// ipipWarningsFor compiles and returns the ValidateConfig warnings mentioning
// ipip — the REAL alarm entry point, not ipipAnchorOnlyWarnings directly. The
// alarm surfaces (`show system alarms`, gRPC, the two security-alarm views)
// recompute ValidateConfig from the ACTIVE config, so that is the path that has
// to carry the advisory.
func ipipWarningsFor(t *testing.T, cmds ...string) []string {
	t.Helper()
	cfg, err := CompileConfig(ipipTree(t, cmds...))
	if err != nil {
		t.Fatalf("compile must SUCCEED for these fixtures (nothing is emitted, so the "+
			"strict gate is silent by design): %v", err)
	}
	if got := len(EmitTunnelEndpointNames(cfg)); got != 0 {
		t.Fatalf("fixture emits %d endpoint(s); it must emit NONE, otherwise the strict "+
			"gate covers it and the advisory is not what is under test", got)
	}
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "ipip") {
			out = append(out, w)
		}
	}
	return out
}

// TestIpipUnitAnchorStillAlarms_4785 is the F2 fail-on-revert guard: a unit-level
// ipip record that emits nothing must still raise the standing alarm, because
// the daemon still builds it an anchor.
//
// RED-on-revert: drop the unit walk from ipipAnchorOnlyWarnings and this fails
// at "creates a kernel anchor ... but raised NO alarm".
func TestIpipUnitAnchorStillAlarms_4785(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
		want string
	}{
		{
			// The F2 shape verbatim: destination only, no source.
			name: "destination_only",
			cmds: []string{"set interfaces ip-0/0/0 unit 5 tunnel destination 10.0.0.2"},
			want: "no `tunnel source` is configured",
		},
		{
			// The mirror: source only. collectAppliedTunnels screens the
			// INTERFACE level on Source != "" but screens units on nothing, so
			// this is an anchor too.
			name: "source_only",
			cmds: []string{"set interfaces ip-0/0/1 unit 3 tunnel source 10.0.0.1"},
			want: "no `tunnel destination` is configured",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warns := ipipWarningsFor(t, tc.cmds...)
			if len(warns) == 0 {
				t.Fatalf("a unit-level ipip stanza creates a kernel anchor device the "+
					"operator can see, but raised NO alarm: it gets neither the strict "+
					"rejection (nothing is emitted) nor the standing advisory, so a dead "+
					"tunnel is invisible on a box already carrying it (#4785 F2). cmds=%v",
					tc.cmds)
			}
			joined := strings.Join(warns, "\n")
			if !strings.Contains(joined, "unit") {
				t.Errorf("the advisory must name the UNIT so the operator can find the "+
					"stanza; got %q", joined)
			}
			if !strings.Contains(joined, tc.want) {
				t.Errorf("advisory must give the real cause %q; got %q", tc.want, joined)
			}
		})
	}
}

// TestIpipIncompleteAnchorNamesTheRealCause_4785 is the F3 guard. A source-only
// interface stanza with NO units at all must not be diagnosed as "every unit
// overrides it" — there are no units.
//
// RED-on-revert: restore the single hard-coded cause string and this fails at
// "diagnosed as overridden-by-units".
func TestIpipIncompleteAnchorNamesTheRealCause_4785(t *testing.T) {
	warns := ipipWarningsFor(t, "set interfaces ip-0/0/2 tunnel source 10.0.0.1")
	if len(warns) != 1 {
		t.Fatalf("expected exactly 1 anchor advisory, got %d: %v", len(warns), warns)
	}
	w := warns[0]
	if strings.Contains(w, "every unit overrides it") {
		t.Errorf("a stanza with NO units was diagnosed as overridden-by-units, and the "+
			"remediation it gives (remove the interface-level stanza so the per-unit "+
			"tunnels win) is the wrong advice for a config that has none: %q", w)
	}
	if !strings.Contains(w, "no `tunnel destination` is configured") {
		t.Errorf("the advisory must name the real cause — the endpoint is incomplete, so "+
			"the emitter suppressed it: %q", w)
	}
}

// TestIpipOverriddenAnchorKeepsTheOverrideCause_4785 is the over-reach guard for
// F3: the genuine every-unit-overrides shape must KEEP its original diagnosis
// and its original remediation. Splitting the cause must not collapse both arms
// onto the new wording.
//
// Stays GREEN under the F3 revert (both arms said this before), and is what
// stops the F3 fix from being a blanket rewording.
func TestIpipOverriddenAnchorKeepsTheOverrideCause_4785(t *testing.T) {
	// The interface record is COMPLETE, so nothing about it is incomplete; it is
	// unemitted purely because the single unit carries its own tunnel.
	cfg, err := CompileConfig(ipipTree(t,
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces ip-0/0/0 unit 1 tunnel mode gre",
		"set interfaces ip-0/0/0 unit 1 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 unit 1 tunnel destination 10.0.0.3",
	))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	warns := ipipAnchorOnlyWarnings(cfg)
	if len(warns) != 1 {
		t.Fatalf("expected exactly 1 anchor advisory for the overridden interface "+
			"stanza, got %d: %v", len(warns), warns)
	}
	if !strings.Contains(warns[0], "every unit overrides it") {
		t.Errorf("the genuine override shape lost its diagnosis: %q", warns[0])
	}
	if !strings.Contains(warns[0], "Remove the interface-level `tunnel` stanza") {
		t.Errorf("the genuine override shape lost its remediation: %q", warns[0])
	}
}

// TestIpipAnchorAdvisoryIgnoresGre_4785 is the over-reach guard for the MODE.
// The unit walk added for F2 must not start alarming on working tunnels: a
// GRE unit record that emits nothing is not a #4785 dead tunnel.
//
// Stays GREEN under the revert.
func TestIpipAnchorAdvisoryIgnoresGre_4785(t *testing.T) {
	cfg, err := CompileConfig(ipipTree(t,
		"set interfaces gr-0/0/0 unit 5 tunnel destination 10.0.0.2",
	))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := len(EmitTunnelEndpointNames(cfg)); got != 0 {
		t.Fatalf("fixture must emit nothing, got %d", got)
	}
	if warns := ipipAnchorOnlyWarnings(cfg); len(warns) != 0 {
		t.Errorf("a GRE unit record raised an IPIP dead-tunnel advisory — the unit walk "+
			"must key on mode, not on being unemitted: %v", warns)
	}
}

// TestIpipEmittedUnitIsNotDoubleReported_4785 is the over-reach guard for the
// EMISSION screen. A unit whose endpoint IS emitted belongs to the strict gate;
// the anchor advisory must not also claim it, or every rejected config would
// carry a duplicate paragraph about the same tunnel.
//
// Stays GREEN under the revert.
func TestIpipEmittedUnitIsNotDoubleReported_4785(t *testing.T) {
	cfg, err := CompileConfigLenient(ipipTree(t,
		"set interfaces ip-0/0/0 unit 5 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 unit 5 tunnel destination 10.0.0.2",
	))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if got := len(EmitTunnelEndpointNames(cfg)); got != 1 {
		t.Fatalf("fixture must emit exactly 1 endpoint, got %d", got)
	}
	if warns := ipipAnchorOnlyWarnings(cfg); len(warns) != 0 {
		t.Errorf("an EMITTED unit endpoint was also reported as anchor-only; it is the "+
			"strict gate's (and the dead-endpoint advisory's) subject, not this one's: %v",
			warns)
	}
}
