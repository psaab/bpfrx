package config

import (
	"strings"
	"testing"
)

// #5832: LinuxIfName only replaces '/' with '-', so two DISTINCT authored
// interface names can canonicalize to the SAME Linux device name / ifindex. The
// Go snapshot emits both logical rows; the Rust forwarding-state builder keys by
// ifindex and OVERWRITES the earlier one, so the lexicographically later name
// silently wins — hijacking that device's security-zone / routing identity. The
// strict commit path must REJECT this; the lenient load / peer-sync path must
// WARN (no brick) so a grandfathered config still boots but the overwrite is
// visible.

// TestIfNameCollisionStrictReject_5832 is the RED-on-revert guard: a strict
// commit of `ge-0/0/0` AND `ge-0-0-0` (both → `ge-0-0-0`) is HARD-REJECTED,
// naming both authored names and the shared Linux device.
//
// FAIL-ON-REVERT: removing validateInterfaceNameCollisionStrict (or its
// runUniformGates call) makes CompileConfig accept the colliding config, so this
// reject assertion fires RED.
func TestIfNameCollisionStrictReject_5832(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.2.1/24",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict CompileConfig accepted two names that canonicalize to the same Linux device (#5832 silent zone hijack)")
	}
	for _, want := range []string{"ge-0/0/0", "ge-0-0-0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("collision error %q does not name %q", err, want)
		}
	}
}

// TestIfNameOverlengthStrictReject_5832 pins the companion IFNAMSIZ case: an
// authored name whose canonical Linux form exceeds the kernel 15-byte limit is
// rejected at commit (the device can never be created).
func TestIfNameOverlengthStrictReject_5832(t *testing.T) {
	// LinuxIfName("ge-0/0/1234567890") == "ge-0-0-1234567890" == 17 bytes > 15.
	tree := flatTreeFromSets(t,
		"set interfaces ge-0/0/1234567890 unit 0 family inet address 10.0.9.1/24",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict CompileConfig accepted an over-IFNAMSIZ interface name (#5832)")
	}
	if !strings.Contains(err.Error(), "ge-0-0-1234567890") || !strings.Contains(err.Error(), "IFNAMSIZ") {
		t.Errorf("over-length error %q must name the canonical device and the IFNAMSIZ limit", err)
	}
}

// TestIfNameCollisionLenientWarns_5832 proves the strict/tolerant split: the
// SAME colliding config LOADS (never hard-fails) on the tolerant path with a
// downgrade warning that names the collision, so an already-committed or
// peer-synced generation that predates this gate still boots (#1960 no-brick)
// rather than silently hijacking a device's zone.
//
// FAIL-ON-REVERT: dropping opts.lenientIfNameCollision (hard-rejecting in
// lenient) makes this load error → RED; dropping the warning makes it silent →
// the warning assertion fires RED.
func TestIfNameCollisionLenientWarns_5832(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.2.1/24",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must NOT reject a grandfathered interface-name collision (brick-on-restart): %v", err)
	}
	// The warning must surface the collision (both names appear in the wrapped
	// gate error) so the silent overwrite is visible.
	if !hasWarningSubstr(cfg.Warnings, "ge-0/0/0") || !hasWarningSubstr(cfg.Warnings, "ge-0-0-0") {
		t.Fatalf("tolerant load must record an interface-name collision warning naming both names, warnings=%v", cfg.Warnings)
	}
}

// TestIfNameDistinctNamesCompileClean_5832 confirms the gate does not
// over-reject: a normal config with distinct, non-colliding interface names
// (the standard ge-0/0/N case) still compiles clean.
func TestIfNameDistinctNamesCompileClean_5832(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.3.1/24",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("distinct non-colliding interface names must compile clean, got %v", err)
	}
}
