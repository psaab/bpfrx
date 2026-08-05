package config

import (
	"strings"
	"testing"
)

// #4785 half 1: `tunnel mode ipip` must be REJECTED at commit / commit-check.
//
// IPIP has no userspace dataplane primitive in either direction — an endpoint
// is entered into gre_decap_index only when tunnel_mode_kind() == TunnelKind::Gre,
// and TunnelKind::Unknown is the egress dispatcher's fail-closed drop arm — so
// the tunnel is created, comes UP, and passes no traffic at all. It previously
// committed green with only the #4788 advisory. This file replaces
// ipip_tunnel_dead_warn_4788_test.go: the advisory is now the gate's
// lenient-path warning, and the strict path errors.
//
// Both severities are pinned here, because a gate that rejects everywhere would
// brick the boot of a node whose ALREADY-COMMITTED config carries an IPIP
// stanza — the #1960 no-brick class covers a load that succeeds while revoking
// something, and it equally covers a load that refuses outright.

func ipipTree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestIpipTunnelRejectedAtCommit_4785 is the fail-on-revert guard for the strict
// path. It drives the REAL operator entry point (CompileConfig), not the gate
// function, so removing the wiring in compiler_tailgates.go fails it just as
// loudly as gutting the gate body.
func TestIpipTunnelRejectedAtCommit_4785(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{
			// The inference case: the operator never types "ipip". An `ip-*`
			// interface defaults to mode ipip in compileInterfaces, so this is
			// the shape a real vSRX config arrives in.
			name: "interface-level, mode inferred from ip- prefix",
			cmds: []string{
				"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
			},
		},
		{
			// Explicit mode on a gr-* interface: the name says GRE, the mode
			// says ipip. The mode is what the dataplane classifies on.
			name: "explicit mode ipip on a gr- interface",
			cmds: []string{
				"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
				"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces gr-0/0/0 tunnel mode ipip",
			},
		},
		{
			name: "unit-level tunnel",
			cmds: []string{
				"set interfaces ip-0/0/1 unit 5 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/1 unit 5 tunnel destination 10.0.0.2",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(ipipTree(t, tc.cmds...))
			if err == nil {
				t.Fatalf("CompileConfig ACCEPTED an ipip tunnel; the operator gets a "+
					"configured, UP interface that passes no traffic in either direction "+
					"and no error to act on (#4785). cmds: %v", tc.cmds)
			}
			if !strings.Contains(err.Error(), "#4785") {
				t.Errorf("rejection must cite the tracking issue so the operator can find "+
					"the status of the unimplemented feature; got: %v", err)
			}
			if !strings.Contains(err.Error(), "mode gre") {
				t.Errorf("rejection must name the working alternative; got: %v", err)
			}
		})
	}
}

// TestIpipTunnelWarnsOnTolerantPath_4785 is the #1960 no-brick half. A config an
// older binary already committed (it was only an advisory then) must still LOAD
// — Store.Load and Store.SyncApply compile through CompileConfigLenient. A gate
// that rejected here would blackout-boot the node or alarm-loop HA config sync,
// which is a worse failure than the dead tunnel it is complaining about.
func TestIpipTunnelWarnsOnTolerantPath_4785(t *testing.T) {
	tree := ipipTree(t,
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
	)

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant load / peer-sync path must NOT reject an ipip tunnel — a "+
			"node whose already-committed config carries one would fail to boot (#1960): %v", err)
	}
	if cfg == nil {
		t.Fatal("lenient compile returned a nil config")
	}

	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4785") && strings.Contains(w, `"ip-0/0/0"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("the tolerant path must still WARN — a silently tolerated dead tunnel is "+
			"the pre-#4785 behaviour this change exists to end. warnings: %v", cfg.Warnings)
	}

	// The interface must still compile: the tolerant path tolerates, it does not
	// drop. A node that silently lost the stanza would diverge from its peer.
	if ifc := cfg.Interfaces.Interfaces["ip-0/0/0"]; ifc == nil || ifc.Tunnel == nil ||
		ifc.Tunnel.Mode != "ipip" {
		t.Errorf("lenient compile must preserve the tunnel config, got %+v",
			cfg.Interfaces.Interfaces["ip-0/0/0"])
	}
}

// TestIpipTunnelRejectionDoesNotOverreach_4785 is the over-rejection guard. The
// gate keys on the compiled MODE, so every other tunnel kind — and an `ip-*`
// interface with no tunnel stanza at all — must still commit. A gate that
// rejected these would take working GRE and WireGuard tunnels down.
func TestIpipTunnelRejectionDoesNotOverreach_4785(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"gre by gr- prefix", []string{
			"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
		}},
		{"explicit mode gre on an ip- interface", []string{
			"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
			"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
			"set interfaces ip-0/0/0 tunnel mode gre",
		}},
		{"unit-level gre", []string{
			"set interfaces gr-0/0/1 unit 5 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/1 unit 5 tunnel destination 10.0.0.2",
		}},
		{"ip- interface with no tunnel stanza", []string{
			"set interfaces ip-0/0/0 unit 0 family inet address 10.10.10.1/30",
		}},
		{"no interfaces at all", []string{
			"set system host-name fw1",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(ipipTree(t, tc.cmds...)); err != nil {
				t.Fatalf("the ipip gate must key on the compiled tunnel MODE and reject "+
					"nothing else; this commit failed: %v", err)
			}
		})
	}
}

// TestIpipTunnelGateReportsDeterministically_4785 pins the ordering contract the
// gate shares with its neighbours: names are walked sorted, so the FIRST
// reported error is stable across runs (Go map order is randomized) and both HA
// nodes report identically on the same config.
func TestIpipTunnelGateReportsDeterministically_4785(t *testing.T) {
	cfg := &Config{}
	// Device names are set the way compileInterfaces sets them: each interface
	// owns a DISTINCT Linux device, so none shadows another. A fixture leaving
	// Name empty would collapse all three onto one device and test nothing.
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ip-0/0/9": {Name: "ip-0/0/9", Tunnel: &TunnelConfig{Name: "ip-0-0-9", Mode: "ipip"}},
		"ip-0/0/0": {Name: "ip-0/0/0", Tunnel: &TunnelConfig{Name: "ip-0-0-0", Mode: "ipip"}},
		"ip-0/0/5": {Name: "ip-0/0/5", Tunnel: &TunnelConfig{Name: "ip-0-0-5", Mode: "ipip"}},
	}

	for i := 0; i < 50; i++ {
		_, err := validateIpipTunnelUnimplementedStrict(cfg, false)
		if err == nil {
			t.Fatal("expected a rejection")
		}
		if !strings.Contains(err.Error(), `"ip-0/0/0"`) {
			t.Fatalf("first reported interface must be the lowest sorted name on every "+
				"run; iteration %d got: %v", i, err)
		}
	}

	// On the lenient path every offender is reported, not just the first — an
	// operator fixing a tolerated config should see the whole list at once.
	warnings, err := validateIpipTunnelUnimplementedStrict(cfg, true)
	if err != nil {
		t.Fatalf("lenient path must not error: %v", err)
	}
	if len(warnings) != 3 {
		t.Errorf("lenient path reported %d warnings, want 3 (one per offending "+
			"interface): %v", len(warnings), warnings)
	}
}

// TestIpipTunnelEffectiveGreStillCommits_4785 is the positive control the first
// round was missing, and the case that made the gate over-reject.
//
// An interface-level `tunnel` stanza on an `ip-*` interface compiles to mode
// ipip by default. A `unit 0 tunnel` stanza compiles to the SAME Linux device
// name (only unit N>0 gets a "uN" suffix), and the applier keys its desired set
// by that name with the unit record applied last — so when the unit resolves to
// gre, the realized device is a working GRE tunnel and the config must commit.
// Rejecting it is the same over-rejection keying on the interface NAME would
// have caused, reached one level in.
func TestIpipTunnelEffectiveGreStillCommits_4785(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{
			// Inherited parent: the interface names the mode, the unit inherits
			// it. Compiles to gre on both records.
			name: "unit inherits the parent's explicit gre",
			cmds: []string{
				"set interfaces ip-0/0/0 tunnel mode gre",
				"set interfaces ip-0/0/0 unit 0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 unit 0 tunnel destination 10.0.0.2",
			},
		},
		{
			// Unit override: the interface record defaults to ipip, and unit 0
			// overrides to gre on the SAME device. The device is GRE.
			name: "unit 0 overrides an ip- interface to gre",
			cmds: []string{
				"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces ip-0/0/0 unit 0 tunnel mode gre",
			},
		},
		{
			name: "unit 0 overrides with a full gre tunnel stanza",
			cmds: []string{
				"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces ip-0/0/0 unit 0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 unit 0 tunnel destination 10.0.0.2",
				"set interfaces ip-0/0/0 unit 0 tunnel mode gre",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(ipipTree(t, tc.cmds...)); err != nil {
				t.Fatalf("a config whose EFFECTIVE tunnel mode is gre was rejected — the "+
					"realized device is a working GRE tunnel and this is a new strict "+
					"failure on valid config (#4785): %v", err)
			}
		})
	}
}

// TestIpipTunnelUnitAboveZeroStillReported_4785 is the counter-case that keeps
// the shadowing rule honest. Unit N>0 is a SEPARATE Linux device ("uN" suffix),
// so it shadows nothing: an interface-level ipip stanza beside it is still a
// real device that is created and is dead, and must still be rejected. A
// shadowing rule that swallowed this would turn the over-rejection fix into an
// under-rejection.
func TestIpipTunnelUnitAboveZeroStillReported_4785(t *testing.T) {
	_, err := CompileConfig(ipipTree(t,
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces ip-0/0/0 unit 1 tunnel mode gre",
		"set interfaces ip-0/0/0 unit 1 tunnel source 10.0.0.1",
	))
	if err == nil {
		t.Fatal("unit 1 is a DIFFERENT device (ip-0-0-0u1), so it does not shadow the " +
			"interface-level ip-0-0-0 ipip device — that device is still created and " +
			"still dead, and must still be rejected (#4785)")
	}
}

// TestIpipTunnelWireguardStillCommits_4785 is the WireGuard positive control.
// The gate keys on the compiled mode, so the third tunnel kind must be
// unaffected — and WireGuard is the one the error message recommends, which
// would be a poor recommendation if the gate rejected it.
func TestIpipTunnelWireguardStillCommits_4785(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"interface-level wireguard", []string{
			"set interfaces wg0 tunnel mode wireguard",
			"set interfaces wg0 tunnel listen-port 51820",
		}},
		{"unit-level wireguard", []string{
			"set interfaces wg0 unit 0 tunnel mode wireguard",
			"set interfaces wg0 unit 0 tunnel listen-port 51820",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(ipipTree(t, tc.cmds...))
			if err != nil && strings.Contains(err.Error(), "#4785") {
				t.Fatalf("the ipip gate rejected a WireGuard tunnel — the very mode its own "+
					"error message recommends: %v", err)
			}
		})
	}
}

// TestIpipTunnelSurfacesOnAlarmPath_4785 is the alarm-surface registration pin.
//
// The strict gate covers the NEXT commit. It does not reach a box already
// carrying a dead tunnel: that generation was committed by an older build and
// loads leniently (#1960). The CLI and gRPC `show system alarms` views, and the
// two security-alarm views, all RECOMPUTE ValidateConfig from the ACTIVE config
// rather than reading cfg.Warnings — so an advisory that lives only in
// cfg.Warnings leaves those surfaces reporting "No alarms currently active"
// while the box forwards nothing. Removing the ValidateConfig registration is
// exactly that regression, and it is what this pins.
func TestIpipTunnelSurfacesOnAlarmPath_4785(t *testing.T) {
	cfg, err := CompileConfigLenient(ipipTree(t,
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
	))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}

	var found bool
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#4785") && strings.Contains(w, `"ip-0/0/0"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("ValidateConfig does not surface the ipip advisory, so `show system alarms` "+
			"reports no alarms on a box whose tunnel passes no traffic. warnings: %v",
			ValidateConfig(cfg))
	}

	// Negative control: a working GRE tunnel must not raise a standing alarm.
	greCfg, err := CompileConfigLenient(ipipTree(t,
		"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
	))
	if err != nil {
		t.Fatalf("tolerant compile (gre): %v", err)
	}
	for _, w := range ValidateConfig(greCfg) {
		if strings.Contains(w, "#4785") {
			t.Errorf("a working GRE tunnel raised the ipip alarm: %q", w)
		}
	}
}
