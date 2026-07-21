package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6143 (follow-up to #4925): a NAT `match {source,destination}-address-name`
// reference to an address-SET that mixes a RESOLVABLE STATIC member with a
// genuinely-UNRESOLVABLE NON-FEED token must PARTIALLY resolve on the lenient /
// peer-sync runtime path — it carries the static member's prefixes while the
// unresolvable token is silently dropped. This is the SSOT expander's behavior
// (expandBookNameRecursive, adopted by resolveNATAddressNamePrefixes in #4925),
// and it matches the security-policy runtime path.
//
// This is SAFE: the constraint stays NON-EMPTY (the static prefix), so the rule
// never widens to match-any; the strict commit gate
// (validateNATSourceAddressNameReferencesStrict / policyMatchAddressBookResolves)
// still rejects such a config at commit. The existing dead_set_fails_closed pin
// (nat_feed_nested_set_4925_test.go) only covers the ALL-unresolvable case; this
// pins the MIXED static+unresolvable case #4925 changed as a side effect.
//
// Fail-on-revert: reverting resolveNATAddressNamePrefixes to the old static
// resolveUserspaceAddressBookEntry resolver makes the mixed set POISON on the
// unresolvable "ghost" member — the whole set resolves to nothing, the append
// helper falls back to the raw set-name token, and the "static member 10.20.0.0/16
// is present" assertions below go RED.

// mixedStaticGhostAddressBook builds an address book with two sets, each mixing
// one resolvable static member with the unresolvable non-feed token "ghost":
//   - "mixed-static-ghost": { static-a = 10.20.0.0/16, ghost } — CIDR member for
//     the SNAT source/destination + DNAT source-constraint cases.
//   - "mixed-host-ghost":   { host-a  = 10.30.0.9/32,  ghost } — host member for
//     the DNAT destination-translation case (one table row per host).
//
// "ghost" is neither a static address, nor a set, nor a feed binding — the
// genuinely-unresolvable member that the OLD static resolver poisoned the whole
// set on.
func mixedStaticGhostAddressBook() *config.AddressBook {
	return &config.AddressBook{
		Addresses: map[string]*config.Address{
			"static-a": {Name: "static-a", Value: "10.20.0.0/16"},
			"host-a":   {Name: "host-a", Value: "10.30.0.9/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"mixed-static-ghost": {Name: "mixed-static-ghost", Addresses: []string{"static-a", "ghost"}},
			"mixed-host-ghost":   {Name: "mixed-host-ghost", Addresses: []string{"host-a", "ghost"}},
		},
	}
}

func Test_nat_mixed_static_and_unresolvable_set_partial_resolves_6143(t *testing.T) {
	// A live overlay for an UNRELATED feed, so the resolver's overlay path is
	// exercised but has nothing to contribute to either mixed set (neither
	// references "bad-feed"). Assertions below confirm the unrelated feed does
	// not leak into these sets.
	overlay := map[string][]string{"bad-feed": {"198.51.100.0/24"}}

	// --- SNAT source-address-name -> mixed static+ghost set ---
	t.Run("snat_source_mixed_static_ghost", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = mixedStaticGhostAddressBook()
		cfg.Security.NAT.Source = []*config.NATRuleSet{
			{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "mixed-src",
					Match: config.NATMatch{SourceAddressName: "mixed-static-ghost"},
					Then:  config.NATThen{Type: config.NATSource, Interface: true},
				},
			}},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		got := snatSourceAddrs(snap, "mixed-src")
		if !contains(got, "10.20.0.0/16") {
			t.Fatalf("mixed static+unresolvable SET must PARTIALLY resolve to the static "+
				"member's prefix, got %v (missing => whole set poisoned by the "+
				"unresolvable member => static-resolver revert / #6143 regression)", got)
		}
		if len(got) == 0 {
			t.Fatal("source list collapsed to empty (match-any) — fail-OPEN; a partially " +
				"resolvable set must stay non-empty (#6143)")
		}
		if contains(got, "0.0.0.0/0") || contains(got, "::/0") {
			t.Fatalf("partial resolution must not widen to match-any, got %v", got)
		}
		if contains(got, "mixed-static-ghost") || contains(got, "ghost") {
			t.Fatalf("partial resolution must not carry the raw set-name / unresolvable "+
				"token (that is the poisoned static-resolver fallback), got %v", got)
		}
		if contains(got, "198.51.100.0/24") {
			t.Fatalf("an unrelated feed's prefixes must not leak into this set, got %v", got)
		}
	})

	// --- SNAT destination-address-name -> mixed static+ghost set ---
	t.Run("snat_dest_mixed_static_ghost", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = mixedStaticGhostAddressBook()
		cfg.Security.NAT.Source = []*config.NATRuleSet{
			{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "mixed-dst",
					Match: config.NATMatch{DestinationAddressName: "mixed-static-ghost"},
					Then:  config.NATThen{Type: config.NATSource, Interface: true},
				},
			}},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		got := snatDestAddrs(snap, "mixed-dst")
		if !contains(got, "10.20.0.0/16") {
			t.Fatalf("SNAT destination-address-name mixed static+unresolvable SET must "+
				"PARTIALLY resolve to the static member's prefix, got %v (#6143)", got)
		}
		if len(got) == 0 {
			t.Fatal("destination list collapsed to empty (match-any) — fail-OPEN (#6143)")
		}
		if contains(got, "0.0.0.0/0") || contains(got, "::/0") {
			t.Fatalf("partial resolution must not widen to match-any, got %v", got)
		}
		if contains(got, "mixed-static-ghost") || contains(got, "ghost") {
			t.Fatalf("partial resolution must not carry the raw set-name / unresolvable "+
				"token, got %v", got)
		}
	})

	// --- DNAT source-address-name (the #2394 source constraint on a
	// destination-translation rule) -> mixed static+ghost set ---
	t.Run("dnat_source_mixed_static_ghost", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = mixedStaticGhostAddressBook()
		cfg.Security.NAT.Destination = &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
			RuleSets: []*config.NATRuleSet{
				{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
					{
						Name: "mixed-src-dnat",
						Match: config.NATMatch{
							SourceAddressName:  "mixed-static-ghost",
							DestinationAddress: "198.51.100.9",
							Protocol:           "tcp",
							DestinationPort:    443,
						},
						Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
					},
				}},
			},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		var got []string
		for _, s := range snap.DestinationNAT {
			if s.Name == "mixed-src-dnat" {
				got = s.SourceAddresses
				break
			}
		}
		if !contains(got, "10.20.0.0/16") {
			t.Fatalf("DNAT source-address-name mixed static+unresolvable SET must PARTIALLY "+
				"resolve to the static member's prefix, got %v (#6143)", got)
		}
		if len(got) == 0 {
			t.Fatal("DNAT source constraint collapsed to empty (match-any) — fail-OPEN (#6143)")
		}
		if contains(got, "mixed-static-ghost") || contains(got, "ghost") {
			t.Fatalf("partial resolution must not carry the raw set-name / unresolvable "+
				"token, got %v", got)
		}
	})

	// --- DNAT destination-address-name -> mixed static+ghost set ---
	// The static host row must still install (one table row per resolvable host);
	// the rule must NOT be continue-skipped and must NOT widen.
	t.Run("dnat_dest_mixed_static_ghost", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = mixedStaticGhostAddressBook()
		cfg.Security.NAT.Destination = &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
			RuleSets: []*config.NATRuleSet{
				{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
					{
						Name: "mixed-dst-dnat",
						Match: config.NATMatch{
							DestinationAddressName: "mixed-host-ghost",
							Protocol:               "tcp",
							DestinationPort:        443,
						},
						Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
					},
				}},
			},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		var got []string
		for _, s := range snap.DestinationNAT {
			if s.Name == "mixed-dst-dnat" {
				got = append(got, s.DestinationAddress)
			}
		}
		if !contains(got, "10.30.0.9") {
			t.Fatalf("DNAT destination-address-name mixed static+unresolvable SET must "+
				"install the static host row (partial resolution), got %v (empty => whole "+
				"set poisoned => rule dropped => static-resolver revert / #6143 regression)", got)
		}
		if len(got) == 0 {
			t.Fatal("DNAT destination mixed set installed NO row — the partially resolvable " +
				"set must keep the static host (#6143)")
		}
	})
}
