package config

import (
	"strings"
	"testing"
)

// #2387 (Track A.1): the userspace-dp session/flow identity is the bare 5-tuple
// with no routing-instance/VRF discriminator (userspace-dp/src/session/key.rs),
// so two flows in different routing-instances that share a 5-tuple collide in
// the conntrack map. The collision is LIVE under PBR `then routing-instance`.
// validateVRFOverlap emits a commit WARNING (never a reject) when two DISTINCT
// routing-instances carry overlapping L3 address space.
//
// These tests pin: (1) two RIs with overlapping addresses on their member
// interface units WARN, naming both RIs + the prefix; (2) non-overlapping RIs
// do NOT warn (no false positive); (3) a single RI / no RI does NOT warn;
// (4) the PBR-term source (`then routing-instance`) also feeds the overlap set.
//
// fail-on-revert: removing the validateVRFOverlap call (or its detection body)
// drops the warning, so TestVRFOverlapWarnsOnOverlappingRIs goes RED.

// vrf2387Warnings returns the compile warnings that mention #2387.
func vrf2387Warnings(t *testing.T, cmds []string) []string {
	t.Helper()
	tree := buildTree(t, cmds)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#2387") {
			out = append(out, w)
		}
	}
	return out
}

func TestVRFOverlapWarnsOnOverlappingRIs(t *testing.T) {
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(warns) != 1 {
		t.Fatalf("expected exactly one #2387 overlap warning, got %d: %v", len(warns), warns)
	}
	w := warns[0]
	for _, want := range []string{`"RI-A"`, `"RI-B"`, "10.0.0.0/24", "NOT session-isolated"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning missing %q: %s", want, w)
		}
	}
}

func TestVRFOverlapNoWarnNonOverlapping(t *testing.T) {
	// Distinct address space per VRF — the common multi-VRF deployment. No warn.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(warns) != 0 {
		t.Fatalf("non-overlapping RIs should not warn, got: %v", warns)
	}
}

func TestVRFOverlapNoWarnSingleRI(t *testing.T) {
	// A single RI cannot overlap another RI. No warn even with two interfaces
	// carrying the same subnet inside the SAME instance.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-A interface ge-0/0/2.0",
	})
	if len(warns) != 0 {
		t.Fatalf("single RI should not warn, got: %v", warns)
	}
}

func TestVRFOverlapNoWarnNoRI(t *testing.T) {
	// No routing-instances at all — plain master-table config. No warn.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
	})
	if len(warns) != 0 {
		t.Fatalf("no-RI config should not warn, got: %v", warns)
	}
}

func TestVRFOverlapWarnsViaPBRTerms(t *testing.T) {
	// The same destination prefix steered into two different routing-instances
	// by two PBR `then routing-instance` terms is the exact reachable-via-PBR
	// trigger — overlap detected from the filter-term source.
	warns := vrf2387Warnings(t, []string{
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-B instance-type virtual-router",
		"set firewall family inet filter fbf term to-a from destination-address 172.16.9.0/24",
		"set firewall family inet filter fbf term to-a then routing-instance RI-A",
		"set firewall family inet filter fbf term to-b from destination-address 172.16.9.0/24",
		"set firewall family inet filter fbf term to-b then routing-instance RI-B",
	})
	if len(warns) != 1 {
		t.Fatalf("expected one #2387 overlap warning from PBR terms, got %d: %v", len(warns), warns)
	}
	for _, want := range []string{`"RI-A"`, `"RI-B"`, "172.16.9.0/24"} {
		if !strings.Contains(warns[0], want) {
			t.Errorf("PBR warning missing %q: %s", want, warns[0])
		}
	}
}

func TestVRFOverlapV6NoCrossFamilyFalsePositive(t *testing.T) {
	// A v4 subnet in one RI and a v6 subnet in another never overlap. No warn.
	warns := vrf2387Warnings(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet6 address 2001:db8::1/64",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
	})
	if len(warns) != 0 {
		t.Fatalf("cross-family (v4 vs v6) must not warn, got: %v", warns)
	}
}
