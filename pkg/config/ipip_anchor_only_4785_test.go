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

// #6861 F1: the COMPLETE-but-unemitted fallback was shared between the
// interface and unit call sites, so a unit record was reported with the
// interface record's cause and remediation.
//
// The interface-level `tunnel mode wireguard` stanza short-circuits the
// emitter to ONE endpoint keyed by the lowest unit (#1910) and never visits
// the per-unit records, while collectAppliedTunnels applies EVERY non-nil
// unit.Tunnel with no screen at all — so a unit overriding to `mode ipip`
// with both endpoints set is complete, unemitted, and still gets a kernel
// anchor. It used to be told "no tunnel endpoint is emitted for the
// interface-level stanza (every unit overrides it)", which named a unit and
// then explained the interface, inverted the direction of the suppression, and
// pointed remediation at a stanza that is not the one to touch first.
//
// TestIpipOverriddenAnchorKeepsTheOverrideCause_4785 above is the reason this
// went unnoticed: it drives the INTERFACE branch, where that same default text
// is CORRECT. It stays green under the revert; this one does not.
func TestIpipUnitUnderWireguardNamesTheSlotCause_6861(t *testing.T) {
	// Fixture producibility: a WireGuard stanza only compiles with a
	// listen-port, a decodable private key, and at least one peer. The
	// endpoint-bearing unit is a genuine override — both halves set — so
	// ipipMissingEndpointHalves returns "" and the COMPLETE fallback is what
	// renders. `tunnel wireguard listen-port` is the real syntax; a bare
	// `tunnel listen-port` parses into a leaf nothing reads and would leave
	// the fixture unable to compile.
	cfg, err := CompileConfig(ipipTree(t,
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key "+
			"1111111111111111111111111111111111111111111111111111111111111111",
		"set interfaces wg0 tunnel wireguard peer "+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "+
			"allowed-ips 10.0.0.0/24",
		"set interfaces wg0 unit 3 tunnel mode ipip",
		"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
		"set interfaces wg0 unit 3 tunnel destination 10.0.0.2",
	))
	if err != nil {
		t.Fatalf("compile must SUCCEED — the ipip unit emits nothing, so the strict "+
			"gate is silent for it by design: %v", err)
	}

	// PRECONDITION, so a fixture that drifts into some other shape fails loudly
	// instead of passing for the wrong reason. Exactly one endpoint is emitted,
	// it is the interface-level WireGuard object keyed by the lowest unit, and
	// the unit's own ipip endpoint is NOT among them.
	eps := EmitTunnelEndpointNames(cfg)
	if len(eps) != 1 || eps[0].Name != "wg0.3" || eps[0].Tunnel.Mode != "wireguard" {
		t.Fatalf("fixture must emit exactly the interface-level WireGuard endpoint "+
			"keyed by the lowest unit; the unit's ipip endpoint being emitted would "+
			"make this the strict gate's subject, not the advisory's. got %d: %+v",
			len(eps), eps)
	}
	unit := cfg.Interfaces.Interfaces["wg0"].Units[3]
	if unit == nil || unit.Tunnel == nil || unit.Tunnel.Mode != "ipip" ||
		unit.Tunnel.Source == "" || unit.Tunnel.Destination == "" {
		t.Fatalf("fixture must leave unit 3 carrying a COMPLETE ipip override — an "+
			"incomplete one takes the missing-halves branch and this test would be "+
			"measuring the wrong arm: %+v", unit)
	}

	// Drive the REAL alarm entry point, not ipipAnchorOnlyWarnings, so the
	// ValidateConfig wiring is bound too.
	var warns []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "ipip") {
			warns = append(warns, w)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("expected exactly 1 ipip advisory for the anchor-only unit, got %d: %v",
			len(warns), warns)
	}
	got := warns[0]

	if !strings.Contains(got, `unit 3`) {
		t.Errorf("the advisory does not name the unit it is about: %q", got)
	}
	// The three ways the shared interface text was wrong here.
	if strings.Contains(got, "every unit overrides it") {
		t.Errorf("a UNIT record was given the INTERFACE record's cause: the "+
			"interface-level stanza suppressed this unit, not the units overriding "+
			"the interface — the direction is inverted (#6861 F1): %q", got)
	}
	if !strings.Contains(got, "interface-level `tunnel mode wireguard` stanza takes the") {
		t.Errorf("the advisory does not name the interface-level WireGuard stanza "+
			"that took the interface's single endpoint slot, which is the ACTUAL "+
			"reason this complete unit endpoint went unemitted (#6861 F1): %q", got)
	}
	if !strings.Contains(got, "Remove this unit's `tunnel` stanza") {
		t.Errorf("the advisory does not offer the remediation that actually drops "+
			"this dead anchor (#6861 F1): %q", got)
	}
	// The advisory must still carry what it always did: the anchor device name
	// and the #4785 reference.
	if !strings.Contains(got, `"wg0u3"`) || !strings.Contains(got, "#4785") {
		t.Errorf("the advisory lost the anchor device name or the issue "+
			"reference: %q", got)
	}
}

// TestIpipIncompleteUnitStillNamesTheMissingHalf_6861 pins the PRECEDENCE the
// isUnit branch must not disturb. A unit record that is ALSO incomplete has two
// true causes at once; the missing half is the one to report, because it keeps
// the endpoint unemitted even if the interface-level stanza went away.
//
// Stays GREEN under the revert — the incomplete branch is unchanged by this
// fold, and that is exactly what this asserts.
func TestIpipIncompleteUnitStillNamesTheMissingHalf_6861(t *testing.T) {
	cfg, err := CompileConfig(ipipTree(t,
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key "+
			"1111111111111111111111111111111111111111111111111111111111111111",
		"set interfaces wg0 tunnel wireguard peer "+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "+
			"allowed-ips 10.0.0.0/24",
		"set interfaces wg0 unit 3 tunnel mode ipip",
		"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
	))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	warns := ipipAnchorOnlyWarnings(cfg)
	if len(warns) != 1 {
		t.Fatalf("expected exactly 1 anchor advisory, got %d: %v", len(warns), warns)
	}
	if !strings.Contains(warns[0], "no `tunnel destination` is configured") {
		t.Errorf("an incomplete unit endpoint must still report the MISSING HALF, "+
			"which outlives the slot cause: %q", warns[0])
	}
	if strings.Contains(warns[0], "takes the") {
		t.Errorf("the slot cause displaced the missing-half cause; the incomplete "+
			"check must stay FIRST: %q", warns[0])
	}
}
