// feed_static_alias_failclosed_5645_test.go: #5645 residual (codex-182). The
// #5665 first-fetch fix OMITS an unresolved feed binding from the overlay so a
// direct feed-bound deny fails closed. But when the SAME name ALSO exists as a
// STATIC address-book entry, buildAddressBookTableWithFeeds still builds that
// static name/ID from the static book, so a `deny <name>` would enforce only the
// partial static subset while the unready feed's prefixes stay silently
// unmatched — a residual deny fail-OPEN. The fix: addrRepresentable treats a
// DECLARED dynamic-address binding that is ABSENT from the overlay as UNRESOLVED
// (fail closed) regardless of a static alias.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// denyStaticAliasCfg builds a config where "denylist" is BOTH a declared
// feed-backed dynamic-address binding AND a static address-book entry, and a
// policy DENIES it. This is the static+unready acceptance case codex-182
// requires added to #5645.
func denyStaticAliasCfg() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			AddressBook: &config.AddressBook{
				Addresses: map[string]*config.Address{
					"denylist": {Name: "denylist", Value: "10.0.0.0/8"},
				},
			},
			DynamicAddress: config.DynamicAddressConfig{
				AddressBindings: map[string]*config.AddressBinding{
					"denylist": {Name: "denylist", FeedNames: []string{"threat"}},
				},
			},
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "untrust",
					ToZone:   "trust",
					Policies: []*config.Policy{
						{
							Name: "block-threats",
							Match: config.PolicyMatch{
								SourceAddresses:      []string{"denylist"},
								DestinationAddresses: []string{"any"},
							},
							Action: config.PolicyDeny,
						},
					},
				},
			},
		},
	}
}

// TestUnresolvedFeedBindingWithStaticAliasFailsClosed is the static-alias
// fail-on-revert. With the feed UNRESOLVED (overlay omits "denylist", exactly
// what SnapshotForBindings emits before the first successful fetch), a
// `deny denylist` must fail CLOSED: the source side routes to the #3261 address
// sentinel and carries NO book reference to the static-only 10.0.0.0/8 row.
// Reverting the addrRepresentable declared-binding guard lets the static alias
// resurrect the name as a representable book reference (SourceBookIDs non-empty,
// no sentinel) — a partial-static deny fail-open — turning the assertions RED.
func TestUnresolvedFeedBindingWithStaticAliasFailsClosed(t *testing.T) {
	cfg := denyStaticAliasCfg()

	// UNRESOLVED: the feed has not completed its first fetch, so the daemon's
	// SnapshotForBindings OMITS "denylist" (empty overlay here).
	overlay := map[string][]string{}

	// Precondition: the static alias DID create a name/ID — this is what makes
	// the residual reachable (overlay omission alone cannot suppress it).
	_, nameToID, err := buildAddressBookTableWithFeeds(cfg, overlay)
	if err != nil {
		t.Fatalf("buildAddressBookTableWithFeeds error: %v", err)
	}
	if _, ok := nameToID["denylist"]; !ok {
		t.Fatalf("precondition: the static address-book alias must create a name/ID "+
			"for denylist; nameToID=%v", nameToID)
	}

	snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if err != nil {
		t.Fatalf("buildPolicySnapshots error: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("expected 1 policy rule, got %d", len(snaps))
	}
	rule := snaps[0]

	// THE FAIL-OPEN SURFACE: the deny source must NOT resolve to a book reference
	// (the static-only 10.0.0.0/8 row). That would enforce a partial deny while
	// the unready feed's prefixes are unmatched.
	if len(rule.SourceBookIDs) != 0 {
		t.Fatalf("fail-open: an unresolved feed binding with a static alias routed as "+
			"a book reference (partial static deny); SourceBookIDs=%v", rule.SourceBookIDs)
	}
	// It must route to the #3261 address sentinel so the Rust preflight rejects
	// the whole snapshot (previous-good retained / fresh-boot default-deny).
	if !addressListHasSentinel(rule.SourceLiterals) {
		t.Fatalf("an unresolved feed binding with a static alias must fail CLOSED via "+
			"the __unsupported_address__ sentinel; SourceLiterals=%v", rule.SourceLiterals)
	}
}

// TestResolvedFeedBindingWithStaticAliasEnforcesUnion is the non-tautological
// companion: once the feed IS ready (overlay carries its prefixes), the same
// name resolves normally and the deny enforces the UNION of the feed prefixes
// and the static alias. Proves the fail-closed guard is scoped to the
// unresolved window and does not suppress a resolved composite name.
func TestResolvedFeedBindingWithStaticAliasEnforcesUnion(t *testing.T) {
	cfg := denyStaticAliasCfg()
	overlay := map[string][]string{
		"denylist": {"198.51.100.0/24"},
	}

	_, nameToID, _ := buildAddressBookTableWithFeeds(cfg, overlay)
	wantID := nameToID["denylist"]
	if wantID == 0 {
		t.Fatalf("precondition: resolved feed name must have an ID")
	}
	snaps, _ := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	rule := snaps[0]
	if !containsID(rule.SourceBookIDs, wantID) {
		t.Fatalf("a resolved feed binding must route as a book reference; "+
			"SourceBookIDs=%v want %d", rule.SourceBookIDs, wantID)
	}
	if addressListHasSentinel(rule.SourceLiterals) {
		t.Fatalf("a resolved feed binding must NOT fail closed; SourceLiterals=%v",
			rule.SourceLiterals)
	}

	// The book row carries BOTH the feed prefix and the static alias (the union).
	books, _, _ := buildAddressBookTableWithFeeds(cfg, overlay)
	row := findBookByName(books, "denylist")
	if row == nil {
		t.Fatalf("resolved denylist produced no book row")
	}
	if !contains(row.PrefixesV4, "198.51.100.0/24") || !contains(row.PrefixesV4, "10.0.0.0/8") {
		t.Fatalf("resolved row must union feed + static prefixes; PrefixesV4=%v",
			row.PrefixesV4)
	}
}
