// #2049: tests proving dynamic-address feed prefixes are ENFORCED — they
// reach the published userspace snapshot's AddressBookSnapshot rows and the
// referencing policy routes them through SourceBookIDs/DestinationBookIDs
// (book references), not as no-match literals. Asserts against the published
// snapshot, NOT the retired eBPF compiler's result.AddrIDs.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// feedPolicyCfg builds a config with a single from->to policy whose source
// (and optionally destination) reference a feed-backed address-name. The name
// is NOT in the static AddressBook — it is purely feed-backed, which is the
// case #2049 fixes (before the overlay the token was a no-match literal).
func feedPolicyCfg(srcName, dstName string) *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			// AddressBook intentionally nil: the feed-backed name exists only
			// via the binding, exercising the "build from overlay alone" path.
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "untrust",
					ToZone:   "trust",
					Policies: []*config.Policy{
						{
							Name: "block-threats",
							Match: config.PolicyMatch{
								SourceAddresses:      []string{srcName},
								DestinationAddresses: []string{dstName},
							},
							Action: config.PolicyDeny,
						},
					},
				},
			},
		},
	}
}

func findBookByName(books []AddressBookSnapshot, name string) *AddressBookSnapshot {
	for i := range books {
		if books[i].Name == name {
			return &books[i]
		}
	}
	return nil
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func containsID(ids []uint32, want uint32) bool {
	for _, v := range ids {
		if v == want {
			return true
		}
	}
	return false
}

// TestFeedOverlayEmitsBookRowAndPopulatesNameToID is the core enforcement
// proof: a feed-backed name with v4 AND v6 feed prefixes produces an
// AddressBookSnapshot row carrying those prefixes, and nameToID[name] is set
// (non-zero). NON-TAUTOLOGICAL: the same build WITHOUT the overlay must NOT
// emit the row and must NOT set nameToID — if the overlay merge is removed
// from buildAddressBookTableWithFeeds, this test fails.
func TestFeedOverlayEmitsBookRowAndPopulatesNameToID(t *testing.T) {
	cfg := feedPolicyCfg("bad-actors", "any")
	overlay := map[string][]string{
		"bad-actors": {"198.51.100.0/24", "2001:db8:bad::/48"},
	}

	books, nameToID := buildAddressBookTableWithFeeds(cfg, overlay)

	row := findBookByName(books, "bad-actors")
	if row == nil {
		t.Fatalf("feed-backed name produced no AddressBookSnapshot row; books=%+v", books)
	}
	if !contains(row.PrefixesV4, "198.51.100.0/24") {
		t.Fatalf("v4 feed prefix not enforced; PrefixesV4=%v", row.PrefixesV4)
	}
	if !contains(row.PrefixesV6, "2001:db8:bad::/48") {
		t.Fatalf("v6 feed prefix not enforced; PrefixesV6=%v", row.PrefixesV6)
	}
	id, ok := nameToID["bad-actors"]
	if !ok || id == 0 {
		t.Fatalf("nameToID not populated for feed-backed name (ok=%v id=%d)", ok, id)
	}

	// NON-TAUTOLOGICAL guard: with no overlay the name is unknown — the table
	// is empty and nameToID has no entry. Proves the row/ID come from the
	// overlay, not from anywhere else.
	booksNoOverlay, nameToIDNoOverlay := buildAddressBookTableWithFeeds(cfg, nil)
	if findBookByName(booksNoOverlay, "bad-actors") != nil {
		t.Fatalf("without the overlay, bad-actors must NOT emit a book row (tautology check)")
	}
	if _, ok := nameToIDNoOverlay["bad-actors"]; ok {
		t.Fatalf("without the overlay, nameToID must NOT contain bad-actors (tautology check)")
	}
}

// TestFeedBackedPolicyRoutesAsBookReference proves the policy snapshot routes
// the feed-backed token into SourceBookIDs (a book reference), not
// SourceLiterals (a no-match literal) — the actual enforcement behaviour.
func TestFeedBackedPolicyRoutesAsBookReference(t *testing.T) {
	cfg := feedPolicyCfg("bad-actors", "any")
	overlay := map[string][]string{
		"bad-actors": {"198.51.100.0/24"},
	}

	_, nameToID := buildAddressBookTableWithFeeds(cfg, overlay)
	wantID := nameToID["bad-actors"]
	if wantID == 0 {
		t.Fatalf("precondition: feed name must have an ID")
	}

	snaps := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if len(snaps) != 1 {
		t.Fatalf("expected 1 policy rule, got %d", len(snaps))
	}
	rule := snaps[0]
	if !containsID(rule.SourceBookIDs, wantID) {
		t.Fatalf("feed-backed source must be a book reference; SourceBookIDs=%v want id %d", rule.SourceBookIDs, wantID)
	}
	if contains(rule.SourceLiterals, "bad-actors") {
		t.Fatalf("feed-backed source must NOT fall through to a no-match literal; SourceLiterals=%v", rule.SourceLiterals)
	}

	// NON-TAUTOLOGICAL: without the overlay the SAME token IS a no-match
	// literal (the pre-#2049 broken behaviour). This proves the difference is
	// the overlay.
	snapsNoOverlay := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if len(snapsNoOverlay) != 1 {
		t.Fatalf("expected 1 rule without overlay, got %d", len(snapsNoOverlay))
	}
	if len(snapsNoOverlay[0].SourceBookIDs) != 0 {
		t.Fatalf("without overlay the feed name must NOT be a book reference; got %v", snapsNoOverlay[0].SourceBookIDs)
	}
	if !contains(snapsNoOverlay[0].SourceLiterals, "bad-actors") {
		t.Fatalf("without overlay the feed name must be an (unmatched) literal; got %v", snapsNoOverlay[0].SourceLiterals)
	}
}

// TestFeedBackedPolicyDestinationRoutesAsBookReference is the destination-side
// analogue (v4+v6 parity flows through expandBookNameToCIDRs automatically).
func TestFeedBackedPolicyDestinationRoutesAsBookReference(t *testing.T) {
	cfg := feedPolicyCfg("any", "blocklist")
	overlay := map[string][]string{
		"blocklist": {"203.0.113.0/24", "2001:db8:dead::/48"},
	}
	_, nameToID := buildAddressBookTableWithFeeds(cfg, overlay)
	wantID := nameToID["blocklist"]
	if wantID == 0 {
		t.Fatalf("precondition: feed name must have an ID")
	}
	snaps := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if !containsID(snaps[0].DestinationBookIDs, wantID) {
		t.Fatalf("feed-backed destination must be a book reference; DestinationBookIDs=%v want %d", snaps[0].DestinationBookIDs, wantID)
	}
}

// TestEmptyFeedSnapshotYieldsNoPrefixes is the documented empty-feed case
// (#2049 §3a): an overlay entry with no prefixes (startup before first fetch /
// operator hold-interval drop) produces a row with no concrete prefixes — the
// rule matches nothing (fail-closed for an allowlist; the documented
// operator-opted fail-open for a denylist). No panic, no compile error.
func TestEmptyFeedSnapshotYieldsNoPrefixes(t *testing.T) {
	cfg := feedPolicyCfg("bad-actors", "any")
	overlay := map[string][]string{
		"bad-actors": {}, // bound but empty (no snapshot yet)
	}
	books, nameToID := buildAddressBookTableWithFeeds(cfg, overlay)
	row := findBookByName(books, "bad-actors")
	if row != nil {
		if len(row.PrefixesV4) != 0 || len(row.PrefixesV6) != 0 {
			t.Fatalf("empty feed must yield no concrete prefixes, got v4=%v v6=%v", row.PrefixesV4, row.PrefixesV6)
		}
	}
	// The name is still classifiable (present in nameToID with an empty book)
	// so the policy snapshot builds without error.
	if _, ok := nameToID["bad-actors"]; !ok {
		t.Fatalf("empty feed-backed name must still be in nameToID (book reference to an empty set)")
	}
	snaps := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if len(snaps) != 1 {
		t.Fatalf("policy must still build with an empty feed; got %d rules", len(snaps))
	}
}

// TestFeedContentChangeReshapesPublishedSnapshot proves a feed content change
// reshapes the FULL published snapshot AND shifts its content hash, so
// Manager.Apply's duplicate-publish gate (snapshotContentHash) lets the
// refresh through. Both snapshots are built from the SAME *config.Config — the
// only difference is the overlay — which is exactly the feed onUpdate path
// (the typed config is byte-identical across a feed refresh).
func TestFeedContentChangeReshapesPublishedSnapshot(t *testing.T) {
	cfg := feedPolicyCfg("bad-actors", "any")
	ucfg := config.UserspaceConfig{}

	overlayP1 := map[string][]string{"bad-actors": {"198.51.100.0/24"}}
	overlayP2 := map[string][]string{"bad-actors": {"203.0.113.0/24"}}

	s1 := buildSnapshotWithSchedulerState(cfg, ucfg, 1, 0, nil, nil, overlayP1)
	s2 := buildSnapshotWithSchedulerState(cfg, ucfg, 1, 0, nil, nil, overlayP2)

	// The published address-book row follows the new content.
	row1 := findBookByName(s1.AddressBooks, "bad-actors")
	row2 := findBookByName(s2.AddressBooks, "bad-actors")
	if row1 == nil || row2 == nil {
		t.Fatalf("both snapshots must carry the feed-backed book row")
	}
	if !contains(row1.PrefixesV4, "198.51.100.0/24") {
		t.Fatalf("S1 must carry P1; got %v", row1.PrefixesV4)
	}
	if !contains(row2.PrefixesV4, "203.0.113.0/24") || contains(row2.PrefixesV4, "198.51.100.0/24") {
		t.Fatalf("S2 must carry P2 and not P1; got %v", row2.PrefixesV4)
	}

	// The content hash MUST differ so the duplicate-publish gate republishes.
	h1, ok1 := snapshotContentHash(s1)
	h2, ok2 := snapshotContentHash(s2)
	if !ok1 || !ok2 {
		t.Fatalf("content hash failed (ok1=%v ok2=%v)", ok1, ok2)
	}
	if h1 == h2 {
		t.Fatalf("feed content change must shift the snapshot content hash (else the refresh is silently dropped)")
	}

	// Conversely: identical overlay content yields an identical hash (the skip
	// is correct — no wasted round-trip).
	s1b := buildSnapshotWithSchedulerState(cfg, ucfg, 9, 7, nil, nil, overlayP1)
	h1b, _ := snapshotContentHash(s1b)
	if h1 != h1b {
		t.Fatalf("identical feed content must yield identical content hash; %x != %x", h1, h1b)
	}
}

// TestFeedOverlayMergesWithStaticBook proves a feed-backed name that ALSO has
// static members merges both sets into one book row (the overlay is additive,
// not a replacement).
func TestFeedOverlayMergesWithStaticBook(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			AddressBook: &config.AddressBook{
				Addresses: map[string]*config.Address{
					"mixed": {Name: "mixed", Value: "10.0.0.0/8"},
				},
			},
		},
	}
	overlay := map[string][]string{"mixed": {"198.51.100.0/24"}}
	books, _ := buildAddressBookTableWithFeeds(cfg, overlay)
	row := findBookByName(books, "mixed")
	if row == nil {
		t.Fatalf("mixed book row missing")
	}
	if !contains(row.PrefixesV4, "10.0.0.0/8") || !contains(row.PrefixesV4, "198.51.100.0/24") {
		t.Fatalf("mixed row must carry BOTH static and feed prefixes; got %v", row.PrefixesV4)
	}
}
