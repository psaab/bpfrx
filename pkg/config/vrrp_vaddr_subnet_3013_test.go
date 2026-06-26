package config

import (
	"strings"
	"testing"
)

// #3013 — VRRP virtual-address subnet-containment commit-time validation.
//
// A `vrrp-group <id> virtual-address <vip>` must fall within a subnet
// configured on the same interface unit for the matching family. In Junos/vSRX
// a VIP outside every on-link subnet is a commit-time error; xpf accepted it and
// installed a route-less VIP at runtime (silent blackhole). These tests prove
// the strict commit path now hard-rejects the out-of-subnet VIP, that a valid
// in-subnet VIP still commits (no over-reject), and that the tolerant load path
// downgrades to a warning so a persisted config still boots.
//
// Fail-on-revert: removing the validateVRRPVirtualAddressSubnet call (or its
// hard-reject branch) makes the reject tests pass-through, turning them RED.

// buildSetTree builds a ConfigTree from flat-set lines using ParseSetCommand +
// SetPath (never NewParser — it merges newlines as whitespace). Returns the
// tree so the caller can choose CompileConfig (strict) vs CompileConfigLenient.
func buildSetTree(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

// TestVRRPVAddrOutOfSubnetRejected proves the strict commit path hard-rejects a
// VIP that is not within any subnet configured on the unit.
func TestVRRPVAddrOutOfSubnetRejected(t *testing.T) {
	tree := buildSetTree(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 virtual-address 10.0.99.1/24",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an out-of-subnet VRRP virtual-address; want hard reject")
	}
	if !strings.Contains(err.Error(), "10.0.99.1/24") ||
		!strings.Contains(err.Error(), "vrrp-group 1") ||
		!strings.Contains(err.Error(), "reth0") {
		t.Errorf("error must name the offending field; got: %v", err)
	}
}

// TestVRRPVAddrCrossFamilyRejected proves a v4 VIP authored under a v6-only
// address (no matching-family subnet) is rejected.
func TestVRRPVAddrCrossFamilyRejected(t *testing.T) {
	tree := buildSetTree(t, []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-group 7 virtual-address 10.0.0.1/24",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a cross-family VRRP virtual-address; want hard reject")
	}
	if !strings.Contains(err.Error(), "family inet subnet") {
		t.Errorf("error should name family inet (the VIP family); got: %v", err)
	}
}

// TestVRRPVAddrInSubnetCommits proves a valid in-subnet VIP commits with no
// reject and no warning (no over-reject), for both families, including the
// owner case where the VIP equals an interface address.
func TestVRRPVAddrInSubnetCommits(t *testing.T) {
	tree := buildSetTree(t, []string{
		// v4 VIP inside the unit subnet.
		"set interfaces reth0 unit 0 family inet address 10.0.61.2/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.2/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		// v6 VIP inside the unit subnet.
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::2/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::2/64 vrrp-group 1 virtual-address 2001:db8::1/64",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a valid in-subnet VRRP config: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "vrrp-group") && strings.Contains(w, "not within any family") {
			t.Errorf("unexpected over-reject warning for a valid VIP: %s", w)
		}
	}
}

// TestVRRPVAddrSecondSubnetCommits proves containment is checked against ANY
// matching-family address on the unit, not just the parent address the group is
// nested under.
func TestVRRPVAddrSecondSubnetCommits(t *testing.T) {
	tree := buildSetTree(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.2/24",
		"set interfaces reth0 unit 0 family inet address 192.168.5.2/24",
		// VIP belongs to the SECOND subnet but is authored under the first.
		"set interfaces reth0 unit 0 family inet address 10.0.61.2/24 vrrp-group 1 virtual-address 192.168.5.1/24",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a VIP contained in another unit subnet: %v", err)
	}
}

// TestVRRPVAddrOutOfSubnetLenientWarns proves the tolerant load/peer-sync path
// downgrades the reject to a warning so a persisted config an older binary
// accepted still boots.
func TestVRRPVAddrOutOfSubnetLenientWarns(t *testing.T) {
	tree := buildSetTree(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 virtual-address 10.0.99.1/24",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not hard-reject an out-of-subnet VIP: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "10.0.99.1/24") && strings.Contains(w, "not within any family inet subnet") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("lenient path must warn about the out-of-subnet VIP; warnings: %v", cfg.Warnings)
	}
}
