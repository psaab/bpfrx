package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2506: the firewall-filter compiler parses `from source-prefix-list` /
// `destination-prefix-list` (with optional `except`) into
// config.FirewallFilterTerm, but the userspace snapshot builder previously
// dropped the references entirely — a term scoped by a prefix-list reached the
// dataplane with NO source/destination address constraint. These tests fail on
// the pre-fix builder (the resolved prefixes never reach FirewallTermSnapshot
// and the except flag never inverts) and pass after the resolve-in-Go fix.

// prefixListCfg builds a config with a policy-options prefix-list and a single
// inet filter whose one term references it as configured.
func prefixListCfg(srcRefs, dstRefs []config.PrefixListRef, prefixes map[string][]string) *config.Config {
	cfg := &config.Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{}
	for name, p := range prefixes {
		cfg.PolicyOptions.PrefixLists[name] = &config.PrefixList{Name: name, Prefixes: p}
	}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {
			Name: "edge",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:              "t",
					SourcePrefixLists: srcRefs,
					DestPrefixLists:   dstRefs,
					ICMPType:          -1,
					ICMPCode:          -1,
					Action:            "discard",
				},
			},
		},
	}
	return cfg
}

// A plain `source-prefix-list` reference resolves to its CIDRs in the snapshot
// with the except flag clear.
func TestFilterSnapshotSourcePrefixListResolved(t *testing.T) {
	cfg := prefixListCfg(
		[]config.PrefixListRef{{Name: "mgmt"}},
		nil,
		map[string][]string{"mgmt": {"10.0.0.0/24", "10.0.1.0/24"}},
	)
	snaps := buildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	term := snaps[0].Terms[0]
	want := []string{"10.0.0.0/24", "10.0.1.0/24"}
	if !reflect.DeepEqual(term.SourceAddresses, want) {
		t.Fatalf("source addresses = %v, want %v (prefix-list dropped? #2506)", term.SourceAddresses, want)
	}
	if term.SourceExcept {
		t.Error("source_except set for a plain (non-except) prefix-list reference")
	}
}

// Literal source-addresses are OR'd with positive prefix-list prefixes.
func TestFilterSnapshotLiteralPlusPositivePrefixList(t *testing.T) {
	cfg := prefixListCfg(
		[]config.PrefixListRef{{Name: "mgmt"}},
		nil,
		map[string][]string{"mgmt": {"10.0.0.0/24"}},
	)
	cfg.Firewall.FiltersInet["edge"].Terms[0].SourceAddresses = []string{"192.168.0.0/16"}
	snaps := buildFirewallFilterSnapshots(cfg)
	term := snaps[0].Terms[0]
	want := []string{"192.168.0.0/16", "10.0.0.0/24"}
	if !reflect.DeepEqual(term.SourceAddresses, want) {
		t.Fatalf("source addresses = %v, want %v (literal+prefix-list union)", term.SourceAddresses, want)
	}
	if term.SourceExcept {
		t.Error("source_except set for a positive prefix-list")
	}
}

// A `destination-prefix-list NAME except` as the sole address source sets the
// destination_except inversion flag and carries the prefixes.
func TestFilterSnapshotDestPrefixListExcept(t *testing.T) {
	cfg := prefixListCfg(
		nil,
		[]config.PrefixListRef{{Name: "internal", Except: true}},
		map[string][]string{"internal": {"10.0.0.0/8"}},
	)
	snaps := buildFirewallFilterSnapshots(cfg)
	term := snaps[0].Terms[0]
	want := []string{"10.0.0.0/8"}
	if !reflect.DeepEqual(term.DestAddresses, want) {
		t.Fatalf("dest addresses = %v, want %v", term.DestAddresses, want)
	}
	if !term.DestExcept {
		t.Fatal("destination_except NOT set for `destination-prefix-list except` — the term would match the listed prefixes instead of excluding them (#2506)")
	}
}

// The mixed case (literal addresses + an except prefix-list in ONE direction)
// is out of scope: the except modifier is dropped (folded to a positive set)
// rather than silently mis-inverting.
func TestFilterSnapshotMixedLiteralAndExceptFoldsPositive(t *testing.T) {
	cfg := prefixListCfg(
		[]config.PrefixListRef{{Name: "internal", Except: true}},
		nil,
		map[string][]string{"internal": {"10.0.0.0/8"}},
	)
	cfg.Firewall.FiltersInet["edge"].Terms[0].SourceAddresses = []string{"192.168.0.0/16"}
	snaps := buildFirewallFilterSnapshots(cfg)
	term := snaps[0].Terms[0]
	if term.SourceExcept {
		t.Fatal("mixed literal+except must NOT set source_except (ambiguous, scoped out)")
	}
	want := []string{"192.168.0.0/16", "10.0.0.0/8"}
	if !reflect.DeepEqual(term.SourceAddresses, want) {
		t.Fatalf("source addresses = %v, want %v (mixed folds to positive)", term.SourceAddresses, want)
	}
}

// An undefined prefix-list reference contributes no prefixes (the strict commit
// gate, tested separately in pkg/config, is what rejects it; here we confirm
// the tolerant-path resolver does not crash and yields no scope from the
// dangling ref).
func TestFilterSnapshotUndefinedPrefixListContributesNothing(t *testing.T) {
	cfg := prefixListCfg(
		[]config.PrefixListRef{{Name: "missing"}},
		nil,
		map[string][]string{},
	)
	snaps := buildFirewallFilterSnapshots(cfg)
	term := snaps[0].Terms[0]
	if len(term.SourceAddresses) != 0 {
		t.Fatalf("undefined prefix-list contributed %v, want none", term.SourceAddresses)
	}
	if term.SourceExcept {
		t.Error("source_except set for an unresolved reference")
	}
}
