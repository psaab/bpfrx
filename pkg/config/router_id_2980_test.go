package config

import (
	"strings"
	"testing"
)

// #2980: an OSPF / OSPFv3 / BGP router-id that is not a valid 32-bit IPv4
// dotted-quad must be rejected at commit / commit-check. router-id is parsed
// as a raw string with no validation, so a malformed value (garbage, an
// out-of-range octet, or an IPv6 address) flowed verbatim into frr.conf.
// FRR/vtysh requires an IPv4 router-id for ALL routing protocols (including
// the IPv6 protocols OSPFv3 and BGP) and rejects anything else, failing the
// whole frr-reload — a commit-accepted config the routing daemon cannot load.
//
// These tests drive the real CompileConfig (strict) / CompileConfigLenient
// (tolerant) paths via buildTreeFromSet (the flat-set helper shared with the
// other validate-strict tests).

// FAIL-ON-REVERT anchor: strict commit rejects a non-IPv4 OSPF router-id.
// Without validateRouterIDStrict (or its call site) this config compiles clean
// and renders `ospf router-id not-an-ip`, so removing the fix turns this test
// RED.
func TestOSPFRouterIDInvalidRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols ospf router-id not-an-ip",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a non-IPv4 OSPF router-id; expected rejection (would break frr-reload)")
	}
	for _, want := range []string{"ospf", "router-id", "not-an-ip", "IPv4"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// An out-of-range octet is rejected (net.ParseIP fails on 300).
func TestOSPFRouterIDOutOfRangeRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols ospf router-id 300.1.2.3",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted an out-of-range OSPF router-id 300.1.2.3; expected rejection")
	}
}

// An IPv6 address is rejected — a router-id is the 32-bit dotted-quad form
// even for IPv6 protocols.
func TestOSPFRouterIDIPv6Rejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols ospf router-id 2001:db8::1",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted an IPv6 OSPF router-id; expected rejection (FRR needs a dotted-quad)")
	}
}

// A valid IPv4 router-id is accepted.
func TestOSPFRouterIDValidAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols ospf router-id 10.0.0.1",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a valid IPv4 OSPF router-id 10.0.0.1: %v", err)
	}
}

// An OSPFv3 (ospf3) router-id must also be a valid IPv4 dotted-quad — FRR's
// ospf6 router-id is still a 32-bit value.
func TestOSPFv3RouterIDInvalidRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols ospf3 router-id garbage",
		"set protocols ospf3 area 0.0.0.0 interface ge-0/0/0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a non-IPv4 OSPFv3 router-id; expected rejection")
	}
	for _, want := range []string{"ospf3", "router-id", "garbage"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// A BGP router-id must be a valid IPv4 dotted-quad.
func TestBGPRouterIDInvalidRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp router-id bogus.id",
		"set protocols bgp group EXT neighbor 10.0.2.1 peer-as 65002",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a non-IPv4 BGP router-id; expected rejection")
	}
	for _, want := range []string{"bgp", "router-id", "bogus.id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// A valid BGP router-id is accepted.
func TestBGPRouterIDValidAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp router-id 192.0.2.1",
		"set protocols bgp group EXT neighbor 10.0.2.1 peer-as 65002",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a valid IPv4 BGP router-id 192.0.2.1: %v", err)
	}
}

// The same gate fires for a per-routing-instance OSPF router-id and the error
// names the instance and protocol.
func TestRoutingInstanceRouterIDInvalidRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols ospf router-id nope",
		"set routing-instances VR1 protocols ospf area 0.0.0.0 interface ge-0/0/1",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an invalid routing-instance OSPF router-id; expected rejection")
	}
	for _, want := range []string{"routing-instance", "VR1", "router-id", "nope"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// An unset router-id is allowed at every scope — the renderer omits it and FRR
// auto-derives one.
func TestOSPFRouterIDUnsetAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected an OSPF config with no router-id: %v", err)
	}
}

// Tolerant load / peer-sync path: an already-persisted config carrying a bad
// router-id must still BOOT (warn, not hard-fail) — #1960 fail-closed-on-load
// doctrine. The render-path guard keeps the malformed value out of frr.conf.
func TestOSPFRouterIDInvalidLenientWarns(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set protocols ospf router-id not-an-ip",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on a bad router-id; expected warn-and-boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "router-id") && strings.Contains(w, "not-an-ip") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("lenient compile did not record a router-id warning; warnings=%v", cfg.Warnings)
	}
}
