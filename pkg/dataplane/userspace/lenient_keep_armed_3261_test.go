package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3261 — an unrepresentable-content config (e.g. a leniently-loaded or
// peer-synced protocol-less application that #3257's strict-commit reject
// cannot catch on the lenient path) must NOT disarm the userspace helper. The
// snapshot still publishes carrying the __unsupported__ sentinel, and the
// helper's integrity preflight rejects it while staying armed — keeping the
// previous-good policy state on a running node, or the default-deny PolicyState
// on a fresh boot. Disarming instead XDP_PASSes transit to the kernel and
// bypasses the reject (the system-level fail-OPEN this fixes). These tests pin
// the Go capability-gate / diagnostic half of the contract; policy_tests.rs and
// server/tests.rs pin the Rust reject + default-deny half.

// goodAndBadPolicyCfg builds a config with one fully-representable policy (a
// plain tcp application) AND one policy whose application is unrepresentable (a
// protocol-less app — the lenient/synced case). The GOOD policy proves the
// whole dataplane is not condemned by one BAD policy.
func goodAndBadPolicyCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Applications.Applications = map[string]*config.Application{
		"good-tcp": {Name: "good-tcp", Protocol: "tcp", DestinationPort: "443"},
		"bad-app":  {Name: "bad-app", Protocol: ""}, // protocol-less: unrepresentable
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{
			{
				Name: "permit-good",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"good-tcp"},
				},
				Action: config.PolicyPermit,
			},
			{
				Name: "deny-bad",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"bad-app"},
				},
				Action: config.PolicyDeny,
			},
		},
	}}
	return cfg
}

func TestDeriveCapabilitiesKeepsArmedForUnrepresentableContent(t *testing.T) {
	// THE #3261 repro / fail-on-revert anchor. Pre-fix this set
	// ForwardingSupported=false (disarm -> kernel fail-open). The fix keeps it
	// true and records the content as a non-disarming diagnostic. Reverting the
	// capabilities.go split flips ForwardingSupported back to false -> RED.
	cfg := goodAndBadPolicyCfg()
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, want true: unrepresentable policy content must NOT disarm the helper (#3261). UnsupportedReasons=%v", caps.UnsupportedReasons)
	}
	if len(caps.UnsupportedReasons) != 0 {
		t.Fatalf("UnsupportedReasons = %v, want empty (content rejection is not a forwarding-unsupported semantic)", caps.UnsupportedReasons)
	}
	// The content-rejection diagnostic is computed from the ACTUAL built
	// snapshot (feed-aware), not the cfg-only gate.
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Fatal("snap.Capabilities.PolicyContentRejected is empty, want a reason recorded for the unrepresentable content diagnostic")
	}
}

func TestDeriveCapabilitiesDisarmsForGenuineSemanticGap(t *testing.T) {
	// Class (ii) non-regression: a genuinely-unsupported semantic (color-aware
	// three-color policer) still sets ForwardingSupported=false and is NOT
	// recorded as content rejection. Proves #3261 did not weaken the legitimate
	// disarm cases.
	caps := deriveUserspaceCapabilities(colorAwarePolicerCfg())
	if caps.ForwardingSupported {
		t.Fatal("ForwardingSupported = true, want false: a color-aware three-color policer is a genuine semantic gap (class ii) and must still disarm")
	}
	if len(caps.UnsupportedReasons) == 0 {
		t.Fatal("UnsupportedReasons is empty, want the three-color policer reason")
	}
	if len(caps.PolicyContentRejected) != 0 {
		t.Fatalf("PolicyContentRejected = %v, want empty for a class-(ii) semantic gap", caps.PolicyContentRejected)
	}
}

func TestPolicyContentRejectionDiagnosticTracksTransitions(t *testing.T) {
	m := New()
	// Representable -> nothing recorded.
	m.recordPolicyContentRejectionLocked(nil)
	if len(m.lastSnapshotRejectReasons) != 0 {
		t.Fatalf("lastSnapshotRejectReasons = %v, want empty after representable build", m.lastSnapshotRejectReasons)
	}
	// Becomes unrepresentable -> recorded.
	snap, err := buildSnapshot(goodAndBadPolicyCfg(), config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	reasons := snap.Capabilities.PolicyContentRejected
	m.recordPolicyContentRejectionLocked(reasons)
	if len(m.lastSnapshotRejectReasons) == 0 {
		t.Fatal("lastSnapshotRejectReasons is empty after recording an unrepresentable build")
	}
	// Clears again -> recorded empty (so status / metric reflect recovery).
	m.recordPolicyContentRejectionLocked(nil)
	if len(m.lastSnapshotRejectReasons) != 0 {
		t.Fatalf("lastSnapshotRejectReasons = %v, want empty after recovery", m.lastSnapshotRejectReasons)
	}
}

// TestSnapshotKeepsArmedAndCarriesSentinelForUnrepresentableContent ties the
// two halves together at the snapshot level: the built snapshot for an
// unrepresentable-content config (1) reports ForwardingSupported=true (helper
// stays armed) and (2) carries the __unsupported__ sentinel term that the Rust
// integrity preflight rejects (previous-good retained). Both must hold for the
// fail-closed-without-fail-open property.
func TestSnapshotKeepsArmedAndCarriesSentinelForUnrepresentableContent(t *testing.T) {
	snap, err := buildSnapshot(goodAndBadPolicyCfg(), config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if !snap.Capabilities.ForwardingSupported {
		t.Fatal("snapshot Capabilities.ForwardingSupported = false, want true (#3261 keep-armed)")
	}
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Fatal("snapshot Capabilities.PolicyContentRejected empty, want the content diagnostic")
	}
	var sawSentinel bool
	for _, pol := range snap.Policies {
		for _, term := range pol.ApplicationTerms {
			if term.Protocol == unsupportedApplicationSentinel {
				sawSentinel = true
			}
		}
	}
	if !sawSentinel {
		t.Fatal("no __unsupported__ sentinel term in the published snapshot; the Rust integrity preflight would NOT reject it (fail-open)")
	}
}

// TestFeedBackedAddressIsRepresentableNoSentinel guards the #3261 feed-aware
// boundary: a healthy dynamic-address feed policy resolves through the snapshot
// overlay to a book reference and must NOT be flagged unrepresentable — no
// address sentinel, no PolicyContentRejected, stays armed. (The cfg-only
// capability gate cannot see the overlay, so a naive content check would
// false-positive a permanent "policy content rejected" alarm on every feed
// deployment.)
func TestFeedBackedAddressIsRepresentableNoSentinel(t *testing.T) {
	cfg := feedPolicyCfg("bad-actors", "any")
	overlay := map[string][]string{"bad-actors": {"198.51.100.0/24", "2001:db8:bad::/48"}}
	snap, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 0, nil, nil, overlay)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if !snap.Capabilities.ForwardingSupported {
		t.Fatal("ForwardingSupported = false, want true for a healthy feed policy")
	}
	if len(snap.Capabilities.PolicyContentRejected) != 0 {
		t.Fatalf("PolicyContentRejected = %v, want empty: a feed-backed address is representable (#3261 feed false-positive guard)", snap.Capabilities.PolicyContentRejected)
	}
	for _, rule := range snap.Policies {
		if addressListHasSentinel(rule.SourceLiterals) || addressListHasSentinel(rule.SourceAddresses) {
			t.Fatalf("rule %q carries the address sentinel for a representable feed: src_lit=%v src_addr=%v", rule.Name, rule.SourceLiterals, rule.SourceAddresses)
		}
		if len(rule.SourceBookIDs) == 0 {
			t.Fatalf("rule %q feed-backed source must route through a book ID, got none", rule.Name)
		}
	}
}

// unrepresentableAddressCfg builds a config whose deny rule (over a
// default-PERMIT, so a silently-dropped deny is a real fail-open) names an
// unrepresentable DESTINATION address. kind selects the sub-case:
//   - "undefined": an UNDEFINED address-book name.
//   - "empty-value": a DEFINED book whose value is EMPTY — the REAL compiled
//     shape of a Junos dns-name / wildcard-address / range-address sub-stanza
//     (compiler_validate_warn.go). This is the path Codex caught: pre-fix
//     expandBookNameToCIDRs widened "" to 0.0.0.0/0 match-any (overbroad
//     deny-all / permit-any), so it was NOT rejected.
//   - "unparseable-value": a DEFINED book whose value is a non-CIDR token.
//   - "partial-set": an address-set MIXING a valid literal AND an empty-value
//     (dns-name) member — pre-fix the literal gave the row content so the book
//     looked representable while the dns-name member was silently dropped
//     (deny narrowing). The whole set must be unrepresentable.
//   - "empty-set": an address-set with ZERO members. Pre-(convergent-fix) the
//     structural nameRepresentable's AddressSet branch returned VACUOUSLY true
//     (no member to taint it), so no sentinel was emitted; the empty row decodes
//     to MatchNone and the deny falls through (fail-open).
//   - "cycle-set": a PURE self-cycle (X -> X) with no concrete member. The
//     cycle-guard returns representable on revisit, so pre-fix the set was
//     vacuously representable yet compiles to an empty row (fail-open).
//   - "feed-only-set": an address-set whose ONLY member is a feed-bound name.
//     Feed prefixes are merged only for the TOP-LEVEL overlay name, never into
//     a set member's row (#2049 / Codex MAJOR 1), so the set row is empty —
//     pre-fix it was deemed representable (the member is a representable feed
//     name) yet decodes to MatchNone (fail-open).
//
// All must make the snapshot carry the __unsupported_address__ sentinel and
// stay armed (#3261). overlay carries the feed binding for "feed-only-set".
func unrepresentableAddressCfg(kind string) (*config.Config, map[string][]string) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyPermit
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	dstName := "undefined-book"
	var overlay map[string][]string
	switch kind {
	case "empty-value":
		dstName = "dns-book"
		cfg.Security.AddressBook = &config.AddressBook{
			Addresses: map[string]*config.Address{
				// REAL compiled shape: a dns-name/wildcard/range sub-stanza
				// leaves Value=="" (no CIDR prefix).
				"dns-book": {Name: "dns-book", Value: ""},
			},
		}
	case "unparseable-value":
		dstName = "dns-book"
		cfg.Security.AddressBook = &config.AddressBook{
			Addresses: map[string]*config.Address{
				"dns-book": {Name: "dns-book", Value: "www.example.com"},
			},
		}
	case "partial-set":
		dstName = "mixed-set"
		cfg.Security.AddressBook = &config.AddressBook{
			Addresses: map[string]*config.Address{
				"good-host":  {Name: "good-host", Value: "172.16.80.200/32"},
				"dns-member": {Name: "dns-member", Value: ""}, // dns-name member
			},
			AddressSets: map[string]*config.AddressSet{
				"mixed-set": {Name: "mixed-set", Addresses: []string{"good-host", "dns-member"}},
			},
		}
	case "empty-set":
		dstName = "empty-set"
		cfg.Security.AddressBook = &config.AddressBook{
			// An address-set with ZERO members — vacuously "representable"
			// pre-(convergent-fix), but an empty row -> MatchNone -> fail-open.
			AddressSets: map[string]*config.AddressSet{
				"empty-set": {Name: "empty-set"},
			},
		}
	case "cycle-set":
		dstName = "cycle-set"
		cfg.Security.AddressBook = &config.AddressBook{
			// Pure self-cycle with no concrete member.
			AddressSets: map[string]*config.AddressSet{
				"cycle-set": {Name: "cycle-set", AddressSets: []string{"cycle-set"}},
			},
		}
	case "feed-only-set":
		dstName = "feed-only-set"
		cfg.Security.AddressBook = &config.AddressBook{
			// The set's ONLY member is a feed-bound name. The feed prefixes are
			// NOT merged into the set row (#2049), so the row is empty.
			AddressSets: map[string]*config.AddressSet{
				"feed-only-set": {Name: "feed-only-set", Addresses: []string{"bad-actors"}},
			},
		}
		overlay = map[string][]string{"bad-actors": {"198.51.100.0/24", "2001:db8:bad::/48"}}
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "deny-bad-addr",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{dstName},
				Applications:         []string{"any"},
			},
			Action: config.PolicyDeny,
		}},
	}}
	return cfg, overlay
}

func TestUnrepresentableAddressKeepsArmedAndCarriesSentinel(t *testing.T) {
	for _, kind := range []string{
		"undefined", "empty-value", "unparseable-value", "partial-set",
		"empty-set", "cycle-set", "feed-only-set",
	} {
		t.Run(kind, func(t *testing.T) {
			cfg, overlay := unrepresentableAddressCfg(kind)
			caps := deriveUserspaceCapabilities(cfg)
			if !caps.ForwardingSupported {
				t.Fatalf("ForwardingSupported = false, want true: an unrepresentable address must NOT disarm (#3261). UnsupportedReasons=%v", caps.UnsupportedReasons)
			}
			snap, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 0, nil, nil, overlay)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			if len(snap.Capabilities.PolicyContentRejected) == 0 {
				t.Fatal("snap.Capabilities.PolicyContentRejected empty, want the content diagnostic for an unrepresentable address")
			}
			if len(snap.Policies) != 1 {
				t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
			}
			rule := snap.Policies[0]
			has := func(list []string) bool {
				for _, a := range list {
					if a == unsupportedAddressSentinel {
						return true
					}
				}
				return false
			}
			// The failed side (destination) must carry the sentinel in BOTH the
			// v3 literal and legacy shapes, and its book IDs must be cleared, so
			// the Rust preflight rejects no matter which shape it reads. This is
			// the fail-on-revert anchor: drop the address-sentinel override and
			// the destination collapses to MatchNone with no sentinel -> the
			// deny silently drops and falls through to default-permit.
			if !has(rule.DestinationLiterals) {
				t.Fatalf("DestinationLiterals = %v, want the __unsupported_address__ sentinel", rule.DestinationLiterals)
			}
			if !has(rule.DestinationAddresses) {
				t.Fatalf("DestinationAddresses = %v, want the __unsupported_address__ sentinel", rule.DestinationAddresses)
			}
			if len(rule.DestinationBookIDs) != 0 {
				t.Fatalf("DestinationBookIDs = %v, want empty (sentinel override clears book IDs)", rule.DestinationBookIDs)
			}
		})
	}
}

// TestExpandBookNameToCIDRsEmptyValueContributesNothing pins the root data bug
// Codex caught (#3261 Part A): an address-book entry with an EMPTY value (the
// compiled shape of a dns-name/wildcard/range sub-stanza) must contribute NO
// prefix — it must NOT widen to 0.0.0.0/0 + ::/0 (match-any). Reverting the
// expandBookNameToCIDRs fix makes this RED (the empty value becomes 0.0.0.0/0).
func TestExpandBookNameToCIDRsEmptyValueContributesNothing(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"dns-book": {Name: "dns-book", Value: ""},
		},
	}
	v4, v6 := expandBookNameToCIDRs(cfg, "dns-book")
	if len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("empty-value book expanded to v4=%v v6=%v, want both empty (must NOT widen to 0.0.0.0/0 match-any)", v4, v6)
	}
	// Explicit `any` must still widen to the full prefixes (no regression).
	cfg.Security.AddressBook.Addresses["any-book"] = &config.Address{Name: "any-book", Value: "any"}
	a4, a6 := expandBookNameToCIDRs(cfg, "any-book")
	if len(a4) != 1 || a4[0] != "0.0.0.0/0" || len(a6) != 1 || a6[0] != "::/0" {
		t.Fatalf("explicit `any` book expanded to v4=%v v6=%v, want [0.0.0.0/0] / [::/0]", a4, a6)
	}
}

// TestExplicitAnyAddressBookIsMatchAnyNotRejected guards the Part-A boundary:
// an address-book entry whose value is the explicit `any` keyword is legitimate
// match-any (0.0.0.0/0 + ::/0), NOT unrepresentable. It must build a normal
// expanded rule with no sentinel — only an EMPTY value (no prefix) is the
// fail-open #3261 closes.
func TestExplicitAnyAddressBookIsMatchAnyNotRejected(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"any-book": {Name: "any-book", Value: "any"},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "permit-any-book",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any-book"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Capabilities.PolicyContentRejected) != 0 {
		t.Fatalf("PolicyContentRejected = %v, want empty: an explicit `any` book is match-any, not unrepresentable", snap.Capabilities.PolicyContentRejected)
	}
	rule := snap.Policies[0]
	if addressListHasSentinel(rule.DestinationLiterals) || addressListHasSentinel(rule.DestinationAddresses) {
		t.Fatalf("explicit `any` book must NOT carry the address sentinel: lit=%v addr=%v", rule.DestinationLiterals, rule.DestinationAddresses)
	}
	if len(rule.DestinationBookIDs) == 0 {
		t.Fatal("explicit `any` book must route through a book ID (the 0.0.0.0/0 + ::/0 row)")
	}
}

// TestFeedPlusConcreteAddressSetIsRepresentable is the convergent-MAJOR POSITIVE
// control: an address-set with a feed-bound member ALONGSIDE a concrete CIDR
// member keeps >=1 concrete contribution, so it stays representable — NO address
// sentinel, NO content rejection, stays armed. This documents the deferred #2049
// residual: the feed prefixes are NOT merged into the set row, so a deny over
// this set under-denies the feed portion; that partial-under-deny is the
// pre-existing feed-prefixes-not-merged-into-sets limitation and is explicitly
// OUT OF SCOPE for #3261. Only a set with ZERO concrete members (empty / pure
// cycle / feed-only) is rejected — see TestUnrepresentableAddressKeepsArmedAndCarriesSentinel.
func TestFeedPlusConcreteAddressSetIsRepresentable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyPermit
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"good-host": {Name: "good-host", Value: "172.16.80.200/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			// feed member + concrete member -> >=1 concrete -> representable.
			"mixed-feed-set": {Name: "mixed-feed-set", Addresses: []string{"bad-actors", "good-host"}},
		},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "deny-mixed",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"mixed-feed-set"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyDeny,
		}},
	}}
	overlay := map[string][]string{"bad-actors": {"198.51.100.0/24"}}
	snap, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 0, nil, nil, overlay)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Capabilities.PolicyContentRejected) != 0 {
		t.Fatalf("PolicyContentRejected = %v, want empty: a {feed + concrete} set keeps a concrete prefix and stays representable (#2049 under-deny residual is out of scope)", snap.Capabilities.PolicyContentRejected)
	}
	rule := snap.Policies[0]
	if addressListHasSentinel(rule.DestinationLiterals) || addressListHasSentinel(rule.DestinationAddresses) {
		t.Fatalf("{feed + concrete} set must NOT carry the address sentinel: lit=%v addr=%v", rule.DestinationLiterals, rule.DestinationAddresses)
	}
	if len(rule.DestinationBookIDs) == 0 {
		t.Fatal("{feed + concrete} set must route through a book ID (carries the concrete-member prefix)")
	}
}

// TestMutualCycleWithConcreteAddressSetIsRepresentable is the Codex
// MERGE-NEEDS-MAJOR POSITIVE control: a MUTUAL cycle whose entry set ALSO has
// its own concrete member —
//
//	address-set A { address <concrete>; address-set B; }
//	address-set B { address-set A; }
//
// — is COMMIT-VALID (the strict validator policyMatchAddressBookResolves accepts
// it: the cycle revisit of A inside B returns true, B contributes no concrete,
// A's own `<concrete>` gives count=1, count!=0 so no reject). The dataplane's
// representability decision MUST EXACTLY equal strict's, so this config must
// stay representable: NO sentinel, NO PolicyContentRejected, a real book ID.
//
// This test is RED on the pre-fix head: the old `return anyConcrete, anyConcrete`
// COUPLED structural-resolvability with concrete-ness, so when A is the entry, B
// (whose only member is the now-visited A) had anyConcrete=false and returned
// (false,false), which poisoned A via `if !r { return false, false }` and
// DISCARDED A's own concrete -> A returned (false,false) -> __unsupported_address__
// sentinel -> the whole snapshot over-rejected and a legitimate deny dropped.
// The decoupled `return hasMember, anyConcrete` + top-level `r && c` gate fixes
// it: B is (true,false) structurally resolvable, A is (true,true), accepted.
func TestMutualCycleWithConcreteAddressSetIsRepresentable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyPermit
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"concrete-host": {Name: "concrete-host", Value: "172.16.80.200/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			// A has a concrete member AND references B; B references back to A.
			"set-a": {Name: "set-a", Addresses: []string{"concrete-host"}, AddressSets: []string{"set-b"}},
			"set-b": {Name: "set-b", AddressSets: []string{"set-a"}},
		},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "deny-mutual-cycle",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"set-a"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyDeny,
		}},
	}}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Capabilities.PolicyContentRejected) != 0 {
		t.Fatalf("PolicyContentRejected = %v, want empty: a mutual cycle with a concrete member is commit-valid (strict accepts) and must stay representable (Codex over-reject)", snap.Capabilities.PolicyContentRejected)
	}
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	rule := snap.Policies[0]
	if addressListHasSentinel(rule.DestinationLiterals) || addressListHasSentinel(rule.DestinationAddresses) {
		t.Fatalf("mutual-cycle-with-concrete set must NOT carry the address sentinel: lit=%v addr=%v", rule.DestinationLiterals, rule.DestinationAddresses)
	}
	if len(rule.DestinationBookIDs) == 0 {
		t.Fatal("mutual-cycle-with-concrete set must route through a book ID (carries the concrete-member prefix)")
	}
}

// TestAddressSetWithEmptyNestedSetIsRejected is the parity NEGATIVE for the
// decouple: a set with a concrete member AND an EMPTY nested set —
//
//	address-set outer { address <concrete>; address-set inner-empty; }
//	address-set inner-empty { }
//
// — must STILL be rejected, because strict aborts (resolve(inner-empty) hits
// resolvedAny==false). The decoupled dataplane matches: the empty nested set
// returns hasMember=false -> (false,false), which poisons `outer` via
// `if !r { return false, false }` even though `outer` has its own concrete. Both
// validators reject -> parity preserved.
func TestAddressSetWithEmptyNestedSetIsRejected(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyPermit
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"concrete-host": {Name: "concrete-host", Value: "172.16.80.200/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"outer":       {Name: "outer", Addresses: []string{"concrete-host"}, AddressSets: []string{"inner-empty"}},
			"inner-empty": {Name: "inner-empty"},
		},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "deny-empty-nested",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"outer"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyDeny,
		}},
	}}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Fatal("PolicyContentRejected empty, want a reason: a set with an EMPTY nested set is rejected by strict and must be rejected by the dataplane (parity)")
	}
	rule := snap.Policies[0]
	if !addressListHasSentinel(rule.DestinationLiterals) || !addressListHasSentinel(rule.DestinationAddresses) {
		t.Fatalf("empty-nested-set must carry the __unsupported_address__ sentinel: lit=%v addr=%v", rule.DestinationLiterals, rule.DestinationAddresses)
	}
}
