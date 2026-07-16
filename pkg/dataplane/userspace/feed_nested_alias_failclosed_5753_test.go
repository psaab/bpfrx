// feed_nested_alias_failclosed_5753_test.go: #5753 residual (codex-182 M38).
// PR #5751 (#5645) closed the TOP-LEVEL and composite partial-deny fail-opens
// for dynamic-address feed bindings: a DECLARED binding ABSENT from the resolved
// overlay (feed unready) fails closed even when a STATIC address-book alias of
// the same name exists. But #5751 threaded that guard ONLY into the top-level
// addrRepresentable branch, NOT into the nested nameRepresentability recursion.
//
// The residual: a dynamic-address binding name nested INSIDE an address-set that
// ALSO has a static alias of that name, with an UNREADY feed, in a `deny`
// policy, stayed fail-OPEN. The nameRepresentability walk did not receive
// cfg.Security.DynamicAddress.AddressBindings, so when it recursed into the set
// member it resolved the STATIC alias (representable) instead of recognizing a
// declared-but-unresolved dynamic binding — the set compiled to a book row
// carrying only the partial static subset while the unready feed's prefixes went
// unmatched. For a `deny`, under-matching = fail-OPEN.
//
// The fix threads AddressBindings into nameRepresentable/nameRepresentability so
// the nested walk applies the SAME declared-but-unresolved guard the top level
// has: an unready declared binding taints the enclosing set -> the source side
// routes to the #3261 __unsupported_address__ sentinel -> the Rust preflight
// rejects the whole snapshot (previous-good retained / fresh-boot default-deny).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// denyNestedStaticAliasCfg builds a config where the address-set "blocklist-set"
// nests two members: a concrete sibling "corp-net" and "denylist", where
// "denylist" is BOTH a static address-book entry (10.0.0.0/8) AND — when
// withBinding is true — a declared feed-backed dynamic-address binding. A `deny`
// policy references the SET (not the member directly), which is what routes the
// declared binding through the NESTED nameRepresentability recursion rather than
// the top-level addrRepresentable guard #5751 already covers.
func denyNestedStaticAliasCfg(withBinding bool) *config.Config {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			AddressBook: &config.AddressBook{
				Addresses: map[string]*config.Address{
					// Static alias of the SAME name as the dynamic binding.
					"denylist": {Name: "denylist", Value: "10.0.0.0/8"},
					// A concrete sibling so the set is neither empty nor pure-feed
					// (isolates the residual from the #3261 empty-set reject).
					"corp-net": {Name: "corp-net", Value: "192.168.0.0/16"},
				},
				AddressSets: map[string]*config.AddressSet{
					"blocklist-set": {
						Name:      "blocklist-set",
						Addresses: []string{"corp-net", "denylist"},
					},
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
								SourceAddresses:      []string{"blocklist-set"},
								DestinationAddresses: []string{"any"},
							},
							Action: config.PolicyDeny,
						},
					},
				},
			},
		},
	}
	if withBinding {
		cfg.Security.DynamicAddress = config.DynamicAddressConfig{
			AddressBindings: map[string]*config.AddressBinding{
				"denylist": {Name: "denylist", FeedNames: []string{"threat"}},
			},
		}
	}
	return cfg
}

// TestNestedFeedBindingWithStaticAliasFailsClosed is the #5753 fail-on-revert.
// With the feed UNRESOLVED (overlay omits "denylist", exactly what
// SnapshotForBindings emits before the first successful fetch) and "denylist"
// declared as a dynamic-address binding nested inside "blocklist-set", a
// `deny blocklist-set` MUST fail CLOSED: the source side routes to the #3261
// address sentinel and carries NO book reference to the partial static-subset
// row. Neutralizing the fix (stop threading AddressBindings into the nested
// nameRepresentability walk) lets the static alias resolve the member normally,
// so the set is representable, SourceBookIDs is non-empty, and no sentinel is
// emitted — a partial-static deny fail-open — turning the assertions RED.
func TestNestedFeedBindingWithStaticAliasFailsClosed(t *testing.T) {
	cfg := denyNestedStaticAliasCfg(true)

	// UNRESOLVED: the feed has not completed its first fetch, so the daemon's
	// SnapshotForBindings OMITS "denylist" (empty overlay here).
	overlay := map[string][]string{}

	// Precondition: the static alias DID create a name/ID for BOTH the member
	// and the enclosing set — this is what makes the residual reachable (overlay
	// omission alone cannot suppress the set's book reference).
	_, nameToID, err := buildAddressBookTableWithFeeds(cfg, overlay)
	if err != nil {
		t.Fatalf("buildAddressBookTableWithFeeds error: %v", err)
	}
	if _, ok := nameToID["blocklist-set"]; !ok {
		t.Fatalf("precondition: the nesting address-set must create a name/ID; nameToID=%v", nameToID)
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
	// (the set's partial static-subset row). That would enforce a partial deny
	// while the unready feed's prefixes are unmatched.
	if len(rule.SourceBookIDs) != 0 {
		t.Fatalf("fail-open: a nested unresolved feed binding with a static alias routed as "+
			"a book reference (partial static deny); SourceBookIDs=%v", rule.SourceBookIDs)
	}
	// It must route to the #3261 address sentinel so the Rust preflight rejects
	// the whole snapshot (previous-good retained / fresh-boot default-deny).
	if !addressListHasSentinel(rule.SourceLiterals) {
		t.Fatalf("a nested unresolved feed binding with a static alias must fail CLOSED via "+
			"the __unsupported_address__ sentinel; SourceLiterals=%v", rule.SourceLiterals)
	}
}

// TestNestedStaticAliasNoBindingResolvesNormally is regression guard (i): a
// nested static alias with NO declared dynamic binding of that name must still
// resolve normally (no over-block). The fix must be scoped to DECLARED bindings
// only — a plain static member of a set is unaffected.
func TestNestedStaticAliasNoBindingResolvesNormally(t *testing.T) {
	cfg := denyNestedStaticAliasCfg(false) // no AddressBindings entry
	overlay := map[string][]string{}

	_, nameToID, err := buildAddressBookTableWithFeeds(cfg, overlay)
	if err != nil {
		t.Fatalf("buildAddressBookTableWithFeeds error: %v", err)
	}
	wantID, ok := nameToID["blocklist-set"]
	if !ok || wantID == 0 {
		t.Fatalf("precondition: the address-set must have a book ID; nameToID=%v", nameToID)
	}

	snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if err != nil {
		t.Fatalf("buildPolicySnapshots error: %v", err)
	}
	rule := snaps[0]

	if !containsID(rule.SourceBookIDs, wantID) {
		t.Fatalf("a nested static-only set (no dynamic binding) must route as a book reference; "+
			"SourceBookIDs=%v want %d", rule.SourceBookIDs, wantID)
	}
	if addressListHasSentinel(rule.SourceLiterals) {
		t.Fatalf("a nested static-only set must NOT fail closed (no over-block); SourceLiterals=%v",
			rule.SourceLiterals)
	}
	// The compiled row carries the concrete static prefixes — real disposition,
	// not just an internal flag.
	books, _, _ := buildAddressBookTableWithFeeds(cfg, overlay)
	row := findBookByName(books, "blocklist-set")
	if row == nil {
		t.Fatalf("static-only blocklist-set produced no book row")
	}
	if !contains(row.PrefixesV4, "192.168.0.0/16") || !contains(row.PrefixesV4, "10.0.0.0/8") {
		t.Fatalf("static-only set row must carry both static members; PrefixesV4=%v", row.PrefixesV4)
	}
}

// TestNestedFeedBindingWithStaticAliasReadyEnforcesUnion is regression guard
// (ii): once the nested binding's feed IS ready (overlay carries its prefixes),
// the same name resolves normally and the deny enforces the UNION of the feed
// prefixes, the static alias, and the concrete sibling. Proves the fail-closed
// guard is scoped to the unresolved window and does not suppress a resolved
// nested feed binding (no regression on feed prefix compilation).
func TestNestedFeedBindingWithStaticAliasReadyEnforcesUnion(t *testing.T) {
	cfg := denyNestedStaticAliasCfg(true)
	overlay := map[string][]string{
		"denylist": {"198.51.100.0/24"},
	}

	_, nameToID, _ := buildAddressBookTableWithFeeds(cfg, overlay)
	wantID := nameToID["blocklist-set"]
	if wantID == 0 {
		t.Fatalf("precondition: resolved nesting set must have an ID; nameToID=%v", nameToID)
	}

	snaps, _ := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	rule := snaps[0]
	if !containsID(rule.SourceBookIDs, wantID) {
		t.Fatalf("a resolved nested feed binding must route as a book reference; "+
			"SourceBookIDs=%v want %d", rule.SourceBookIDs, wantID)
	}
	if addressListHasSentinel(rule.SourceLiterals) {
		t.Fatalf("a resolved nested feed binding must NOT fail closed; SourceLiterals=%v",
			rule.SourceLiterals)
	}

	// The set row unions the feed prefix, the static alias, and the concrete
	// sibling — the resolved deny enforces the full set (feed prefixes compiled
	// normally).
	books, _, _ := buildAddressBookTableWithFeeds(cfg, overlay)
	row := findBookByName(books, "blocklist-set")
	if row == nil {
		t.Fatalf("resolved blocklist-set produced no book row")
	}
	if !contains(row.PrefixesV4, "198.51.100.0/24") {
		t.Fatalf("resolved nested feed binding must compile its feed prefix; PrefixesV4=%v", row.PrefixesV4)
	}
	if !contains(row.PrefixesV4, "192.168.0.0/16") || !contains(row.PrefixesV4, "10.0.0.0/8") {
		t.Fatalf("resolved set row must union feed + static + sibling prefixes; PrefixesV4=%v",
			row.PrefixesV4)
	}
}
