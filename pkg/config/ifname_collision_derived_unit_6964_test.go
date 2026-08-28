package config

import (
	"strings"
	"testing"
)

// #6964: the authored interface-name set is NOT the kernel device-name set. A
// logical unit carrying its own `tunnel` stanza gets its OWN Linux device, named
// by the compiler as the interface's canonical name plus "u<unit>" for unit > 0.
// So `gr-0/0/0 unit 1` needs the device `gr-0-0-0u1`, which is byte-identical to
// the canonical name of an interface an operator may author as `gr-0/0/0u1`.
// The two AUTHORED keys are distinct (`gr-0/0/0u1` vs `gr-0/0/0`), so the #5832
// authored-only walk never sees them touch and the config compiled clean.
//
// These tests pin BOTH halves of the widened gate: it must REJECT the derived
// collision, and it must not start rejecting the ordinary per-unit tunnel
// configs that share a base device by design.

// collidingDerivedUnitSets is the #6964 vector. The two colliding records are
// given DIFFERENT tunnel endpoints deliberately: if both sides carried the same
// source/destination the collapse onto one device would be invisible — the
// single surviving device would be indistinguishable from the intended one and
// a consequence assertion could not fail. The differing endpoints are what make
// "one device, two intents" observable.
func collidingDerivedUnitSets() []string {
	return []string{
		// Interface authored literally as the derived name of the unit below.
		"set interfaces gr-0/0/0u1 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0u1 tunnel destination 10.0.0.2",
		// Distinct authored interface whose unit 1 tunnel DERIVES gr-0-0-0u1.
		"set interfaces gr-0/0/0 unit 1 tunnel source 10.1.0.1",
		"set interfaces gr-0/0/0 unit 1 tunnel destination 10.1.0.2",
	}
}

// TestDerivedUnitDeviceCollisionStrictReject_6964 is the RED-on-revert guard:
// a strict commit of the pair must HARD-REJECT, naming the authored interface,
// the unit ref, and the shared Linux device.
//
// FAIL-ON-REVERT: dropping the derived-name pass from
// validateInterfaceNameCollisionStrict makes CompileConfig return nil here, so
// the reject assertion fires RED. The #5832 authored-only pass cannot cover
// this — `gr-0/0/0u1` and `gr-0/0/0` canonicalize to DIFFERENT names.
func TestDerivedUnitDeviceCollisionStrictReject_6964(t *testing.T) {
	tree := flatTreeFromSets(t, collidingDerivedUnitSets()...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict CompileConfig accepted an interface whose canonical name is the DERIVED per-unit tunnel device of another interface (#6964 silent shared device)")
	}
	for _, want := range []string{"gr-0/0/0u1", "gr-0/0/0.1", "gr-0-0-0u1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("collision error %q does not name %q", err, want)
		}
	}
}

// TestDerivedUnitDeviceCollisionLenientWarns_6964 pins the compatibility
// decision. The shape is reachable in an ALREADY-COMMITTED config (nothing ever
// rejected it), so the widened gate inherits the #5832 strict/lenient split: the
// tolerant load / peer-sync path WARNS instead of failing, and the warning names
// the collision so the shared device is visible rather than silent.
//
// FAIL-ON-REVERT: hard-rejecting on the lenient path (dropping the
// opts.lenientIfNameCollision downgrade, or gating outside it) makes the load
// error → RED, which is the brick this project refuses (#1960).
func TestDerivedUnitDeviceCollisionLenientWarns_6964(t *testing.T) {
	tree := flatTreeFromSets(t, collidingDerivedUnitSets()...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must NOT reject a grandfathered derived-device collision (brick-on-restart): %v", err)
	}
	for _, want := range []string{"gr-0/0/0u1", "gr-0/0/0.1", "gr-0-0-0u1"} {
		if !hasWarningSubstr(cfg.Warnings, want) {
			t.Errorf("tolerant load must warn naming %q, warnings=%v", want, cfg.Warnings)
		}
	}
}

// TestDerivedUnitDeviceCollisionConsequence_6964 is the SEVERITY statement, and
// it is what makes the reject worth having. The tolerant path does not repair
// the collision — it only makes it visible — so the compiled config still
// carries the damage, and this reads it directly out of the typed config.
//
// Two config objects, one device name, two DIFFERENT tunnel endpoints. pkg/
// routing keys its desired tunnel set by TunnelConfig.Name, so these are one
// kernel device with two independent intents.
func TestDerivedUnitDeviceCollisionConsequence_6964(t *testing.T) {
	tree := flatTreeFromSets(t, collidingDerivedUnitSets()...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load: %v", err)
	}
	ifTun := cfg.Interfaces.Interfaces["gr-0/0/0u1"]
	if ifTun == nil || ifTun.Tunnel == nil {
		t.Fatalf("fixture did not build the interface-level tunnel: %+v", cfg.Interfaces.Interfaces["gr-0/0/0u1"])
	}
	base := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if base == nil || base.Units[1] == nil || base.Units[1].Tunnel == nil {
		t.Fatalf("fixture did not build the per-unit tunnel: %+v", base)
	}
	unitTun := base.Units[1].Tunnel
	if ifTun.Tunnel.Name != unitTun.Name {
		t.Fatalf("fixture no longer collides: interface device %q vs unit device %q — the gate under test would be exercised on a non-colliding input",
			ifTun.Tunnel.Name, unitTun.Name)
	}
	if ifTun.Tunnel.Name != "gr-0-0-0u1" {
		t.Errorf("shared device name = %q, want %q", ifTun.Tunnel.Name, "gr-0-0-0u1")
	}
	// The endpoints MUST differ, or the collision would be unobservable and
	// every assertion above would hold just as well on a correct config.
	if ifTun.Tunnel.Source == unitTun.Source {
		t.Fatalf("fixture is blind: both records carry source %q, so one device serving two intents is indistinguishable from one correct record", ifTun.Tunnel.Source)
	}
}

// TestDerivedUnitDeviceOverlengthStrictReject_6964 covers the sibling hazard on
// the same derived name: an authored name whose canonical form FITS IFNAMSIZ but
// whose "u<unit>" derivative does not. The kernel cannot create that device, so
// the tunnel endpoint silently never materializes — the same failure the #5832
// authored-name length check exists to prevent, one derivation later.
//
// LinuxIfName("gr-0/0/1234567") == "gr-0-0-1234567" == 14 bytes (accepted), and
// the unit-1 device "gr-0-0-1234567u1" == 16 bytes (over the 15-byte limit), so
// ONLY the derived check can reject this config.
func TestDerivedUnitDeviceOverlengthStrictReject_6964(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set interfaces gr-0/0/1234567 unit 1 tunnel source 10.2.0.1",
		"set interfaces gr-0/0/1234567 unit 1 tunnel destination 10.2.0.2",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict CompileConfig accepted a per-unit tunnel whose derived device name is over IFNAMSIZ (#6964)")
	}
	if !strings.Contains(err.Error(), "gr-0-0-1234567u1") || !strings.Contains(err.Error(), "IFNAMSIZ") {
		t.Errorf("over-length error %q must name the derived device and the IFNAMSIZ limit", err)
	}
}

// --- OVER-REJECTION half ------------------------------------------------
//
// A gate that compares the effective device-name set must not start refusing
// the configs that share a device BY DESIGN. These three cells are the ones a
// too-broad implementation reddens.

// TestUnitZeroTunnelSharesBaseDeviceAccepted_6964 is the cell a naive
// implementation fails. `unit 0 { tunnel }` is assigned the interface's OWN base
// device name — deliberately, unit 0 collapses onto the base interface — so a
// derived-vs-authored comparison that does not exempt it would reject the single
// most ordinary tunnel config in the tree.
func TestUnitZeroTunnelSharesBaseDeviceAccepted_6964(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict CompileConfig must ACCEPT `unit 0 tunnel` — unit 0 shares the interface's own device by design: %v", err)
	}
	// Bind the premise the exemption rests on, so this cell cannot go vacuous
	// if the compiler ever stops assigning unit 0 the base device name.
	if got := cfg.Interfaces.Interfaces["gr-0/0/0"].Units[0].Tunnel.Name; got != "gr-0-0-0" {
		t.Fatalf("unit 0 tunnel device = %q, want the interface base %q — the exemption this test guards no longer describes the compiler", got, "gr-0-0-0")
	}
}

// TestOrdinaryPerUnitTunnelsAccepted_6964 is the broad over-rejection cell: a
// realistic multi-unit, multi-interface tunnel config whose derived device names
// are all distinct and none of which is authored anywhere must still compile.
func TestOrdinaryPerUnitTunnelsAccepted_6964(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 unit 1 tunnel source 10.0.1.1",
		"set interfaces gr-0/0/0 unit 1 tunnel destination 10.0.1.2",
		"set interfaces gr-0/0/0 unit 2 tunnel source 10.0.2.1",
		"set interfaces gr-0/0/0 unit 2 tunnel destination 10.0.2.2",
		"set interfaces gr-0/0/1 unit 1 tunnel source 10.0.3.1",
		"set interfaces gr-0/0/1 unit 1 tunnel destination 10.0.3.2",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict CompileConfig must ACCEPT ordinary per-unit tunnels with distinct derived devices: %v", err)
	}
	// The cell is only meaningful if the fixture actually produced the derived
	// "uN" devices the gate walks; assert the population it was screened on.
	for ref, want := range map[string]string{
		"gr-0/0/0#1": "gr-0-0-0u1",
		"gr-0/0/0#2": "gr-0-0-0u2",
		"gr-0/0/1#1": "gr-0-0-1u1",
	} {
		name, unit := ref[:len(ref)-2], int(ref[len(ref)-1]-'0')
		got := cfg.Interfaces.Interfaces[name].Units[unit].Tunnel.Name
		if got != want {
			t.Errorf("%s unit %d device = %q, want %q", name, unit, got, want)
		}
	}
}

// TestDerivedUnitDeviceAtIFNAMSIZBoundaryAccepted_6964 is the fencepost on the
// derived length check. "gr-0-0-123456" (13) + "u1" == "gr-0-0-123456u1" == 15
// bytes, EXACTLY the kernel limit, and must be accepted — a `>=` where the code
// needs `>` turns a working config into a failed commit with no workaround.
func TestDerivedUnitDeviceAtIFNAMSIZBoundaryAccepted_6964(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set interfaces gr-0/0/123456 unit 1 tunnel source 10.4.0.1",
		"set interfaces gr-0/0/123456 unit 1 tunnel destination 10.4.0.2",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict CompileConfig must ACCEPT a derived device name of exactly %d bytes: %v", maxLinuxIfNameLen, err)
	}
	got := cfg.Interfaces.Interfaces["gr-0/0/123456"].Units[1].Tunnel.Name
	if len(got) != maxLinuxIfNameLen {
		t.Fatalf("boundary fixture drifted: derived device %q is %d bytes, want exactly %d", got, len(got), maxLinuxIfNameLen)
	}
}
