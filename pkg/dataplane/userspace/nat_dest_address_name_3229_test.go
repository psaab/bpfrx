package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3229: a DNAT rule scoped by `match destination-address-name <book-entry>` is
// an address-book reference, the destination twin of #2416's source path. The
// compiler parses it into NATMatch.DestinationAddressName but the snapshot
// builder must resolve it into the destination list the DNAT table is keyed on —
// otherwise a name-scoped DNAT installs NO table entry and is silently dropped.
// appendNATDestinationAddressName resolves the name to its concrete prefixes
// (reusing the policy-path address-book expander) and appends them so each
// resolved host installs its own snapshot entry.
//
// The compiler-side parse + commit-time reject are covered in pkg/config
// (compiler_nat_dest_address_name_3229_test.go).

func destAddressBookForNAT() *config.AddressBook {
	return &config.AddressBook{
		Addresses: map[string]*config.Address{
			"svc-a": {Name: "svc-a", Value: "203.0.113.20/32"},
			"svc-b": {Name: "svc-b", Value: "203.0.113.21/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"svc-net": {Name: "svc-net", Addresses: []string{"svc-a", "svc-b"}},
		},
	}
}

func dnatCfgWithDestName(name string, litDest string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.AddressBook = destAddressBookForNAT()
	match := config.NATMatch{
		DestinationAddressName: name,
		Protocol:               "tcp",
		DestinationPort:        443,
	}
	if litDest != "" {
		match.DestinationAddress = litDest
		match.DestinationAddresses = []string{litDest}
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "scoped", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "name-scoped",
					Match: match,
					Then:  config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}
	return cfg
}

// dnatDestinations returns the set of DestinationAddress values emitted for the
// name-scoped rule.
func dnatDestinations(snaps []DestinationNATRuleSnapshot) []string {
	var got []string
	for _, s := range snaps {
		if s.Name == "name-scoped" {
			got = append(got, s.DestinationAddress)
		}
	}
	return got
}

// TestBuildDestinationNATSnapshotsResolvesDestinationAddressName is the core
// fail-on-revert pin: a DNAT rule with `match destination-address-name svc-net`
// must install one table entry per expanded address-set host. Reverting
// appendNATDestinationAddressName leaves the destination list empty so the rule
// is `continue`-skipped (no snapshot row) and this test FAILS.
func TestBuildDestinationNATSnapshotsResolvesDestinationAddressName(t *testing.T) {
	cfg := dnatCfgWithDestName("svc-net", "")
	snaps := buildDestinationNATSnapshots(cfg, nil)
	got := dnatDestinations(snaps)
	want := []string{"203.0.113.20", "203.0.113.21"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("name-scoped DNAT destinations = %+v, want resolved book hosts %+v "+
			"(empty => destination-address-name not resolved => rule dropped #3229)", got, want)
	}
}

// TestBuildDestinationNATSnapshotsDestinationNameAndLiteralUnion: a rule can mix
// a literal destination with a name; both install entries.
func TestBuildDestinationNATSnapshotsDestinationNameAndLiteralUnion(t *testing.T) {
	cfg := dnatCfgWithDestName("svc-a", "198.51.100.9")
	snaps := buildDestinationNATSnapshots(cfg, nil)
	got := dnatDestinations(snaps)
	want := []string{"198.51.100.9", "203.0.113.20"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("union DNAT destinations = %+v, want literal+resolved %+v", got, want)
	}
}

// TestBuildDestinationNATSnapshotsUnknownDestinationNameFailsClosed: an unknown
// name resolves to the raw token, which is not a valid IP and is skipped in the
// emit loop, so the rule installs NO entry (matches nothing) rather than
// broadening to match-any.
func TestBuildDestinationNATSnapshotsUnknownDestinationNameFailsClosed(t *testing.T) {
	cfg := dnatCfgWithDestName("does-not-exist", "")
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if got := dnatDestinations(snaps); len(got) != 0 {
		t.Fatalf("unknown destination-address-name must install no entry (fail-closed), got %+v", got)
	}
}

// TestBuildSourceNATSnapshotsResolvesDestinationAddressName: the source NAT
// builder carries the destination constraint too, so destination-address-name
// must resolve there as well (else the source NAT destination scope is lost =
// fail-open). Reverting the source-builder resolution call leaves
// DestinationAddresses empty and this FAILS.
func TestBuildSourceNATSnapshotsResolvesDestinationAddressName(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = destAddressBookForNAT()
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "scoped", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
			{
				Name: "name-scoped",
				Match: config.NATMatch{
					DestinationAddressName: "svc-net",
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			},
		}},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	var got []string
	for _, s := range snaps {
		if s.Name == "name-scoped" {
			got = s.DestinationAddresses
		}
	}
	want := []string{"203.0.113.20/32", "203.0.113.21/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("name-scoped SNAT DestinationAddresses = %+v, want resolved book prefixes %+v "+
			"(empty => destination-address-name not resolved => fail-open #3229)", got, want)
	}
}
