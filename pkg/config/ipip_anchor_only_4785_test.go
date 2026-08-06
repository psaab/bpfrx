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

// ipipWgIfaceStanza is the interface-level WireGuard stanza the slot-cause
// fixtures share. WireGuard only compiles with a listen-port, a decodable
// private key, and at least one peer; `tunnel wireguard listen-port` is the real
// syntax (a bare `tunnel listen-port` parses into a leaf nothing reads and would
// leave the fixture unable to compile).
func ipipWgIfaceStanza() []string {
	return []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " +
			"1111111111111111111111111111111111111111111111111111111111111111",
		"set interfaces wg0 tunnel wireguard peer " +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa " +
			"allowed-ips 10.0.0.0/24",
	}
}

// TestIpipUnitAnchorStillAlarms_4785 is the F2 fail-on-revert guard: a unit-level
// ipip record that emits nothing must still raise the standing alarm, because
// the daemon still builds it an anchor.
//
// RED-on-revert: drop the unit walk from ipipAnchorOnlyWarnings and this fails
// at "creates a kernel anchor ... but raised NO alarm".
//
// The unit number is asserted EXACTLY, not via the bare word "unit" (#6861 F2b).
// Production formats it (ipipAnchorOnlyWarnings: `interfaces %q unit %d`), and
// the bare-word form passed for any unit number at all — so a walk that reported
// the wrong unit, which is precisely the kind of off-by-one an operator cannot
// recover from because they would go edit a stanza that is not the dead one,
// scored green. The merge-base assertion this file's F2 work replaced did check
// the number; that strength is restored here.
func TestIpipUnitAnchorStillAlarms_4785(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cmds     []string
		wantUnit string
		want     string
	}{
		{
			// The F2 shape verbatim: destination only, no source.
			name:     "destination_only",
			cmds:     []string{"set interfaces ip-0/0/0 unit 5 tunnel destination 10.0.0.2"},
			wantUnit: `interfaces "ip-0/0/0" unit 5`,
			want:     "no `tunnel source` is configured",
		},
		{
			// The mirror: source only. collectAppliedTunnels screens the
			// INTERFACE level on Source != "" but screens units on nothing, so
			// this is an anchor too.
			name:     "source_only",
			cmds:     []string{"set interfaces ip-0/0/1 unit 3 tunnel source 10.0.0.1"},
			wantUnit: `interfaces "ip-0/0/1" unit 3`,
			want:     "no `tunnel destination` is configured",
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
			if !strings.Contains(joined, tc.wantUnit) {
				t.Errorf("the advisory must name the EXACT interface and unit the dead "+
					"anchor belongs to, want %q; an advisory naming some other unit sends "+
					"the operator to edit a stanza that is not the dead one. got %q",
					tc.wantUnit, joined)
			}
			if !strings.Contains(joined, tc.want) {
				t.Errorf("advisory must give the real cause %q; got %q", tc.want, joined)
			}
		})
	}
}

// TestIpipSharedDeviceWithEmittedEndpointIsNotAnchorOnly_6861 is the fail-on-revert
// guard for the F1b fix: the anchor determination keys on the RUNTIME DEVICE
// NAME, not on *TunnelConfig pointer identity.
//
// Pointer identity answers "is this record the object the emitter published".
// The advisory's claim is about a Linux device — "an interface an operator can
// see that carries no traffic" — and in both shapes below an UNEMITTED record
// names the SAME device an emitted endpoint binds to. Reported as dead, each is
// a false alarm against live, traffic-carrying infrastructure, and each carries
// a remediation telling the operator to delete it.
//
// RED-on-revert: restore the `emitted map[*TunnelConfig]bool` test and both
// sub-cases fail at "declared DEAD ... but that device carries the emitted".
func TestIpipSharedDeviceWithEmittedEndpointIsNotAnchorOnly_6861(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cmds       []string
		wantRef    string // the emitted endpoint ref
		wantDevice string // the device that ref resolves to
		why        string
	}{
		{
			// compiler_interfaces.go gives unit 0's per-unit tunnel the BASE
			// Linux name — identical to the interface-level record's — and
			// pkg/routing/tunnel.go keys its desired set by that name, so the
			// two records are ONE device. The emitter publishes the unit's GRE
			// pointer (#5635), leaving the interface pointer unemitted.
			name: "gre_unit0_shares_the_base_device",
			cmds: []string{
				"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
				"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces ip-0/0/0 unit 0 tunnel mode gre",
			},
			wantRef:    "ip-0/0/0.0",
			wantDevice: "ip-0-0-0",
			why: "the interface-level ipip record and unit 0's GRE record carry the " +
				"SAME Linux device name, and that device is the one the working GRE " +
				"tunnel runs on",
		},
		{
			// Interface-level WireGuard short-circuits the emitter to ONE
			// endpoint keyed by the lowest unit, carrying the INTERFACE-level
			// pointer (#1910) — but TunnelNameMap resolves that ref to the
			// UNIT's device, which is what snapshotLinuxName writes into
			// InterfaceSnapshot.LinuxName and therefore what the tunnel
			// endpoint (and the Rust WireGuard TUN behind it) binds to.
			name: "wireguard_endpoint_binds_the_units_device",
			cmds: append(ipipWgIfaceStanza(),
				"set interfaces wg0 unit 3 tunnel mode ipip",
				"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
				"set interfaces wg0 unit 3 tunnel destination 10.0.0.2",
			),
			wantRef:    "wg0.3",
			wantDevice: "wg0u3",
			why: "the sole unit is the lowest, so the emitted WireGuard endpoint is " +
				"keyed to it and resolves to the unit's own device — live WireGuard " +
				"infrastructure, not a dead IPIP anchor",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(ipipTree(t, tc.cmds...))
			if err != nil {
				t.Fatalf("compile must SUCCEED — the emitted endpoint is not ipip: %v", err)
			}

			// PRECONDITIONS. Without these a fixture that drifted into some
			// other shape would pass for the wrong reason: it must really emit
			// the endpoint, and that endpoint must really resolve to the device
			// the unemitted ipip record names.
			eps := EmitTunnelEndpointNames(cfg)
			if len(eps) != 1 || eps[0].Name != tc.wantRef {
				t.Fatalf("fixture must emit exactly one endpoint %q, got %d: %+v",
					tc.wantRef, len(eps), eps)
			}
			if eps[0].Tunnel.Mode == "ipip" {
				t.Fatalf("fixture's EMITTED endpoint is itself ipip; that makes this the "+
					"strict gate's subject, not the anchor advisory's: %+v", eps[0])
			}
			if got := cfg.TunnelNameMap()[tc.wantRef]; got != tc.wantDevice {
				t.Fatalf("fixture precondition: the emitted ref %q must resolve to device "+
					"%q (the same name the unemitted ipip record carries) or this test is "+
					"not exercising the shared-device collision at all; got %q",
					tc.wantRef, tc.wantDevice, got)
			}

			// Drive the REAL alarm entry point: `show system alarms` and the two
			// security-alarm views recompute ValidateConfig from the active config.
			var warns []string
			for _, w := range ValidateConfig(cfg) {
				if strings.Contains(w, "ipip") {
					warns = append(warns, w)
				}
			}
			if len(warns) != 0 {
				t.Errorf("device %q was declared DEAD (\"carries no traffic\") but that "+
					"device carries the emitted endpoint %q — %s. The advisory reaches the "+
					"boot/apply log and `show system alarms`, and its remediation tells the "+
					"operator to delete the stanza, so this is a false alarm aimed at live "+
					"config (#6861 F1b). advisories: %v",
					tc.wantDevice, tc.wantRef, tc.why, warns)
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
	if !strings.Contains(warns[0], "Removing the interface-level `tunnel` stanza") {
		t.Errorf("the genuine override shape lost its remediation: %q", warns[0])
	}
}

// TestIpipRemediationsNeverInstructTrafficLoss_6861 binds the #6861 F1b
// remediation rule: an advisory that reaches the boot/apply log and
// `show system alarms` must never tell an operator to delete config that is
// carrying traffic.
//
// Each arm asserts the corrected text AND separately PROVES the hazard by
// compiling the config the old remediation described — so the assertions are
// anchored to a demonstrated consequence rather than to a wording preference.
// Without the proofs an assertion on advisory text is only a restatement of
// whatever string production happens to hold.
//
// RED-on-revert: restore either old remediation and the matching arm fails at
// "still offers the deletion".
func TestIpipRemediationsNeverInstructTrafficLoss_6861(t *testing.T) {
	// ARM 1 — the INTERFACE-level branch. The old text was an unconditional
	// "Remove the interface-level `tunnel` stanza if the per-unit tunnels are
	// the intent." A unit tunnel is built by cloneForUnit FROM the interface
	// record and only then takes its own overrides, so a unit carrying just
	// `tunnel mode gre` holds INHERITED endpoints.
	t.Run("interface_branch_warns_about_inheritance", func(t *testing.T) {
		inheriting := []string{
			"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
			"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
			"set interfaces ip-0/0/0 unit 1 tunnel mode gre",
		}
		cfg, err := CompileConfig(ipipTree(t, inheriting...))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if got := len(EmitTunnelEndpointNames(cfg)); got != 1 {
			t.Fatalf("precondition: the inheriting unit must emit a working GRE "+
				"endpoint, got %d", got)
		}
		warns := ipipAnchorOnlyWarnings(cfg)
		if len(warns) != 1 {
			t.Fatalf("expected exactly 1 anchor advisory, got %d: %v", len(warns), warns)
		}
		if !strings.Contains(warns[0], "INHERITS them from this stanza") {
			t.Errorf("the remediation does not warn that removing the interface-level "+
				"stanza strips the endpoints inheriting units are built from, so an "+
				"operator who complies silently kills a working tunnel (#6861 F1b): %q",
				warns[0])
		}

		// THE PROOF. Compile exactly what the old remediation instructed —
		// the same config with the interface-level `tunnel` stanza removed.
		stripped, err := CompileConfig(ipipTree(t, inheriting[2]))
		if err != nil {
			t.Fatalf("compile without the interface-level stanza: %v", err)
		}
		if got := len(EmitTunnelEndpointNames(stripped)); got != 0 {
			t.Fatalf("this arm's premise is stale: removing the interface-level stanza "+
				"was expected to leave the unit with no endpoints and emit NOTHING, but "+
				"it emitted %d. Re-derive the hazard before trusting the assertion "+
				"above", got)
		}
	})

	// ARM 2 — the UNIT branch under interface-level WireGuard. The old text
	// offered "or remove the interface-level `tunnel` stanza if the per-unit
	// tunnels are the intent" as an alternative, and NOTHING tested that
	// branch. It is doubly unsafe: it deletes the working WireGuard tunnel and
	// it exposes the complete ipip unit underneath.
	t.Run("wireguard_unit_branch_refuses_the_parent_removal", func(t *testing.T) {
		unitStanza := []string{
			"set interfaces wg0 unit 1 family inet address 10.1.1.1/30",
			"set interfaces wg0 unit 3 tunnel mode ipip",
			"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
			"set interfaces wg0 unit 3 tunnel destination 10.0.0.2",
		}
		cfg, err := CompileConfig(ipipTree(t, append(ipipWgIfaceStanza(), unitStanza...)...))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		warns := ipipAnchorOnlyWarnings(cfg)
		if len(warns) != 1 {
			t.Fatalf("expected exactly 1 anchor advisory, got %d: %v", len(warns), warns)
		}
		if strings.Contains(warns[0], "remove the interface-level `tunnel` stanza if the") {
			t.Errorf("the advisory still offers the deletion of the interface-level "+
				"WireGuard stanza as an alternative remediation (#6861 F1b): %q", warns[0])
		}
		if !strings.Contains(warns[0], "Do NOT remove the interface-level") {
			t.Errorf("the advisory does not warn the operator off the parent removal, "+
				"leaving the more destructive of the two obvious moves unmarked: %q",
				warns[0])
		}

		// THE PROOF. Compile exactly what the old alternative instructed —
		// the same config with the interface-level WireGuard stanza removed.
		// The ipip unit is now the emitted endpoint, and the strict gate that
		// is the whole point of #4785 half 1 rejects it.
		_, err = CompileConfig(ipipTree(t, unitStanza...))
		if err == nil {
			t.Fatal("this arm's premise is stale: removing the interface-level " +
				"WireGuard stanza was expected to expose the complete ipip unit to the " +
				"strict gate, but the config compiled clean. Re-derive the hazard " +
				"before trusting the assertion above")
		}
		if !strings.Contains(err.Error(), `tunnel endpoint "wg0.3" has mode ipip`) {
			t.Errorf("the exposed endpoint must be the ipip unit the advisory is "+
				"about; a different rejection means the proof is not measuring the "+
				"hazard: %v", err)
		}
	})

	// ARM 3 — the incomplete-endpoint branch is SHARED by interface and unit
	// records, so its "or remove the `tunnel` stanza" was ambiguous at the
	// interface site in exactly the same way. The unit site scopes the
	// deletion to the unit; the interface site carries the inheritance caveat.
	t.Run("incomplete_branch_scopes_the_deletion", func(t *testing.T) {
		// Interface record, incomplete, with a unit that COMPLETES it by
		// inheriting the source — so the deletion really would cost traffic.
		completing := []string{
			"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
			"set interfaces ip-0/0/0 unit 1 tunnel destination 10.0.0.2",
		}
		if _, err := CompileConfig(ipipTree(t, completing...)); err == nil {
			t.Fatal("precondition: the inheriting unit resolves to a complete IPIP " +
				"endpoint, so the strict gate must reject this config")
		}
		lenientCfg, err := CompileConfigLenient(ipipTree(t, completing...))
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		if got := len(EmitTunnelEndpointNames(lenientCfg)); got != 1 {
			t.Fatalf("precondition: the unit must emit by inheriting the "+
				"interface-level source, got %d", got)
		}
		ifaceWarn := ipipAnchorOnlyWarnings(lenientCfg)
		if len(ifaceWarn) != 1 {
			t.Fatalf("expected exactly 1 anchor advisory, got %d: %v",
				len(ifaceWarn), ifaceWarn)
		}
		if !strings.Contains(ifaceWarn[0], "no `tunnel destination` is configured") {
			t.Fatalf("precondition: this must be the incomplete branch: %q", ifaceWarn[0])
		}
		if !strings.Contains(ifaceWarn[0], "INHERITS them from this stanza") {
			t.Errorf("the incomplete branch's interface-site remediation drops the "+
				"inheritance caveat, so it repeats the unsafe instruction the complete "+
				"branch was fixed for (#6861 F1b): %q", ifaceWarn[0])
		}

		// Unit record, incomplete: the deletion must be scoped to the unit.
		unitCfg, err := CompileConfig(ipipTree(t,
			"set interfaces ip-0/0/1 unit 3 tunnel source 10.0.0.1"))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		unitWarn := ipipAnchorOnlyWarnings(unitCfg)
		if len(unitWarn) != 1 {
			t.Fatalf("expected exactly 1 anchor advisory, got %d: %v",
				len(unitWarn), unitWarn)
		}
		if !strings.Contains(unitWarn[0], "remove THIS UNIT's `tunnel` stanza") {
			t.Errorf("a unit-site remediation must scope the deletion to the unit; the "+
				"bare \"remove the `tunnel` stanza\" reads as the interface-level one: %q",
				unitWarn[0])
		}
	})
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
	// Fixture: unit 1 carries no `tunnel` stanza of its own, so it is the LOWEST
	// unit AND resolves to the shared `wg0` device — which is what makes unit 3's
	// `wg0u3` a genuinely dead anchor rather than the device the WireGuard
	// endpoint binds to. The original single-unit-3 fixture is the shape #6861
	// F1b proved is NOT dead (the WG endpoint keys to the sole unit and resolves
	// to `wg0u3`); it now lives in
	// TestIpipSharedDeviceWithEmittedEndpointIsNotAnchorOnly_6861 as a must-be-
	// silent case. The endpoint-bearing unit here is a genuine override — both
	// halves set — so ipipMissingEndpointHalves returns "" and the COMPLETE
	// fallback is what renders.
	cfg, err := CompileConfig(ipipTree(t, append(ipipWgIfaceStanza(),
		"set interfaces wg0 unit 1 family inet address 10.1.1.1/30",
		"set interfaces wg0 unit 3 tunnel mode ipip",
		"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
		"set interfaces wg0 unit 3 tunnel destination 10.0.0.2",
	)...))
	if err != nil {
		t.Fatalf("compile must SUCCEED — the ipip unit emits nothing, so the strict "+
			"gate is silent for it by design: %v", err)
	}

	// PRECONDITION, so a fixture that drifts into some other shape fails loudly
	// instead of passing for the wrong reason. Exactly one endpoint is emitted,
	// it is the interface-level WireGuard object keyed by the lowest unit, and
	// the unit's own ipip endpoint is NOT among them.
	eps := EmitTunnelEndpointNames(cfg)
	if len(eps) != 1 || eps[0].Name != "wg0.1" || eps[0].Tunnel.Mode != "wireguard" {
		t.Fatalf("fixture must emit exactly the interface-level WireGuard endpoint "+
			"keyed by the lowest unit; the unit's ipip endpoint being emitted would "+
			"make this the strict gate's subject, not the advisory's. got %d: %+v",
			len(eps), eps)
	}
	// The dead anchor must be a DIFFERENT device from the one the emitted
	// WireGuard endpoint binds to; if they coincide, unit 3 is live and this
	// test is asserting an advisory that should not exist at all (#6861 F1b).
	names := cfg.TunnelNameMap()
	if names["wg0.1"] != "wg0" || names["wg0u3"] == "wg0" || names["wg0.3"] != "wg0u3" {
		t.Fatalf("fixture precondition: the emitted endpoint must resolve to `wg0` and "+
			"unit 3 to a SEPARATE `wg0u3` device, else the anchor is not dead: %v", names)
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
	if !strings.Contains(got, "Remove THIS UNIT's `tunnel` stanza") {
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
	// Same two-unit shape as the slot-cause test: unit 1 owns the emitted
	// endpoint's device, so unit 3's `wg0u3` really is dead.
	cfg, err := CompileConfig(ipipTree(t, append(ipipWgIfaceStanza(),
		"set interfaces wg0 unit 1 family inet address 10.1.1.1/30",
		"set interfaces wg0 unit 3 tunnel mode ipip",
		"set interfaces wg0 unit 3 tunnel source 10.0.0.1",
	)...))
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
