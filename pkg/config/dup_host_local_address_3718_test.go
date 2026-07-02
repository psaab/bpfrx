package config

import (
	"strings"
	"testing"
)

// #3718 (Option B): a firewall-local address (interface address or VRRP VIP)
// that is host-inbound-reachable from more than one security zone with DIFFERING
// host-inbound service/protocol sets makes the kernel destination-address-only
// host-inbound verdict order-dependent (the earlier-sorting zone decides the
// packet) and can disagree with the ingress-scoped userspace-dp path. These
// tests pin the commit-time gate (validateDuplicateHostLocalAddressStrict) and
// are fail-on-revert: neuter the validator (return nil) and the reject cases go
// GREEN-then-RED here; the negatives guard against over-rejecting a deliberate
// identical-service duplicate.

// dupHostLocalZone builds a config with two static interface addresses. The two
// zones' host-inbound service sets are supplied by the caller so a single helper
// drives both the ambiguous (differing) and unambiguous (identical) cases.
func dupHostLocalZone(addrA, addrB string, svcA, svcB []string) *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{addrA}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{addrB}},
		}},
	}
	zoneA := &ZoneConfig{Name: "aaa", Interfaces: []string{"ge-0/0/0.0"}}
	if svcA != nil {
		zoneA.HostInboundTraffic = &HostInboundTraffic{SystemServices: svcA}
	}
	zoneB := &ZoneConfig{Name: "zzz", Interfaces: []string{"ge-0/0/1.0"}}
	if svcB != nil {
		zoneB.HostInboundTraffic = &HostInboundTraffic{SystemServices: svcB}
	}
	cfg.Security.Zones = map[string]*ZoneConfig{"aaa": zoneA, "zzz": zoneB}
	return cfg
}

// TestDupHostLocalV4DifferingServicesRejected is the core H01 fail-on-revert:
// the SAME IPv4 in two zones whose host-inbound sets differ (aaa default-deny,
// zzz ssh) must be rejected, naming the address and both zones.
func TestDupHostLocalV4DifferingServicesRejected(t *testing.T) {
	cfg := dupHostLocalZone("192.0.2.1/24", "192.0.2.1/24", nil, []string{"ssh"})
	err := validateDuplicateHostLocalAddressStrict(cfg)
	if err == nil {
		t.Fatal("expected rejection of a duplicate IPv4 host-local address across zones with differing host-inbound sets, got nil")
	}
	for _, want := range []string{"192.0.2.1", "aaa", "zzz"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err.Error(), want)
		}
	}
}

// TestDupHostLocalV4IdenticalServicesAllowed guards against a false positive on
// a deliberate duplicate: the same IPv4 in two zones with IDENTICAL host-inbound
// sets renders the same block twice (order-independent) and must be allowed.
func TestDupHostLocalV4IdenticalServicesAllowed(t *testing.T) {
	cfg := dupHostLocalZone("192.0.2.1/24", "192.0.2.1/24", []string{"ssh"}, []string{"ssh"})
	if err := validateDuplicateHostLocalAddressStrict(cfg); err != nil {
		t.Fatalf("identical-service duplicate must be allowed (no order-dependence), got: %v", err)
	}
}

// TestDupHostLocalDistinctAddressesAllowed: two DIFFERENT addresses, one per
// zone, is the ordinary case and must never be flagged.
func TestDupHostLocalDistinctAddressesAllowed(t *testing.T) {
	cfg := dupHostLocalZone("192.0.2.1/24", "192.0.2.2/24", nil, []string{"ssh"})
	if err := validateDuplicateHostLocalAddressStrict(cfg); err != nil {
		t.Fatalf("distinct addresses must be allowed, got: %v", err)
	}
}

// TestDupHostLocalV6DifferingServicesRejected covers M02 (IPv6 parity): the same
// IPv6 in two zones with differing host-inbound sets is rejected as IPv6.
func TestDupHostLocalV6DifferingServicesRejected(t *testing.T) {
	cfg := dupHostLocalZone("2001:db8::1/64", "2001:db8::1/64", nil, []string{"ssh"})
	err := validateDuplicateHostLocalAddressStrict(cfg)
	if err == nil {
		t.Fatal("expected rejection of a duplicate IPv6 host-local address across zones, got nil")
	}
	for _, want := range []string{"2001:db8::1", "IPv6", "aaa", "zzz"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err.Error(), want)
		}
	}
}

// TestDupHostLocalVRRPVIPDifferingServicesRejected covers M03: the SAME VRRP VIP
// configured under two units in two zones with differing host-inbound sets is
// rejected — the most realistic case (a copy-paste VIP error during HA setup).
func TestDupHostLocalVRRPVIPDifferingServicesRejected(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.2/24"}, VRRPGroups: map[string]*VRRPGroup{
				"10.0.0.2/24": {ID: 1, VirtualAddresses: []string{"10.0.0.1"}},
			}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.3/24"}, VRRPGroups: map[string]*VRRPGroup{
				"10.0.0.3/24": {ID: 2, VirtualAddresses: []string{"10.0.0.1"}},
			}},
		}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"aaa": {Name: "aaa", Interfaces: []string{"ge-0/0/0.0"}},
		"zzz": {Name: "zzz", Interfaces: []string{"ge-0/0/1.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	err := validateDuplicateHostLocalAddressStrict(cfg)
	if err == nil {
		t.Fatal("expected rejection of a duplicate VRRP VIP across zones with differing host-inbound sets, got nil")
	}
	if !strings.Contains(err.Error(), "10.0.0.1") {
		t.Fatalf("error %q does not name the VIP 10.0.0.1", err.Error())
	}
}

// TestDupHostLocalSameZoneNotFlagged: the same address on two interfaces in the
// SAME zone resolves to one effective host-inbound set (one block) — no
// order-dependence — so it must be allowed.
func TestDupHostLocalSameZoneNotFlagged(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0", "ge-0/0/1.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	if err := validateDuplicateHostLocalAddressStrict(cfg); err != nil {
		t.Fatalf("same-zone duplicate address must be allowed, got: %v", err)
	}
}

// TestDupHostLocalLifelineExcluded: a shared management address on lifeline
// interfaces (fxp0) is never host-inbound-denied, so it must not be flagged even
// across zones with differing sets.
func TestDupHostLocalLifelineExcluded(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"mgmt": {Name: "mgmt", Interfaces: []string{"fxp0.0"}},
		"zzz": {Name: "zzz", Interfaces: []string{"ge-0/0/1.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	// Only one non-lifeline zone contributes the address, so it maps to a single
	// scope — not ambiguous.
	if err := validateDuplicateHostLocalAddressStrict(cfg); err != nil {
		t.Fatalf("lifeline (fxp0) address must be excluded from the dup gate, got: %v", err)
	}
}

// TestDupHostLocalCommitRejectsAndLenientWarns proves the compiler wiring: the
// STRICT commit path hard-rejects an ambiguous duplicate, and the tolerant load
// path downgrades it to a warning so an already-persisted config still boots
// (#1960 no-brick). This is the end-to-end fail-on-revert for the dispatch in
// compiler.go.
func TestDupHostLocalCommitRejectsAndLenientWarns(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone aaa interfaces ge-0/0/0.0",
		"set security zones security-zone zzz interfaces ge-0/0/1.0",
		"set security zones security-zone zzz host-inbound-traffic system-services ssh",
	}
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict commit must reject a duplicate host-local address across zones with differing host-inbound sets")
	} else if !strings.Contains(err.Error(), "192.0.2.1") {
		t.Fatalf("strict error %q does not name the address", err.Error())
	}

	tree2 := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree2)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a duplicate host-local address: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "duplicate host-local address (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded duplicate-host-local-address warning, got warnings: %v", cfg.Warnings)
	}
}
