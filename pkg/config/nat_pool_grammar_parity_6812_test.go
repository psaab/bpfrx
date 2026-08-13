package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// #6812 F1 round 3 — the Go half of the source-NAT pool address GRAMMAR parity
// guard.
//
// sourceNATPoolAddressReason claims to be "the exact per-member mirror of
// expand_pool_address". Round 2 established that claim by SHARING the predicate
// between the snapshot builder and the aggregate budget walk — but sharing a
// predicate between two Go call sites makes the two GO sites agree; it says
// nothing about whether the Go parser and the Rust parser agree. A measured
// differential over both real parsers found six inputs where they did not, in
// both directions (see the doc comment on sourceNATPoolAddressReason).
//
// The fix for that CLASS, rather than for those six inputs, is this fixture:
// userspace-dp/tests/fixtures/snat_pool_grammar_v1.json is the ONE table, read
// here and by nat_pool_grammar_parity_fixture (userspace-dp/src/nat/
// tests_aggregate_budget.rs) through the real expand_pool_address. Neither side
// keeps a copy, so the two grammars cannot drift apart unnoticed — the next
// divergence reds a test instead of surviving to a review round. Same shared-
// fixture convention as the #3612 AppID parity guard (pkg/appid/
// precedence_parity_test.go).
type snatPoolGrammarFixture struct {
	Version     int                   `json:"version"`
	Description string                `json:"description"`
	Cases       []snatPoolGrammarCase `json:"cases"`
}

type snatPoolGrammarCase struct {
	Addr  string `json:"addr"`
	OK    bool   `json:"ok"`
	Hosts uint64 `json:"hosts"`
	Note  string `json:"note"`
	// #6812 B2: WHICH addresses the member expands to. Asserted on the RUST
	// side, where the expansion happens (Go only counts). Carried here so this
	// side can keep the row self-consistent — a fixture row that disagrees with
	// itself would weaken the Rust assertion silently.
	First    string   `json:"first"`
	Last     string   `json:"last"`
	Expanded []string `json:"expanded"`
}

func loadSNATPoolGrammarFixture(t *testing.T) snatPoolGrammarFixture {
	t.Helper()
	path := filepath.Join("..", "..", "userspace-dp", "tests", "fixtures", "snat_pool_grammar_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var fx snatPoolGrammarFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fx.Cases) == 0 {
		t.Fatal("fixture carries no cases")
	}
	return fx
}

// TestPoolAddressGrammarMatchesDataplane_6812 asserts the Go predicate reaches
// the fixture verdict for every member.
//
// FAIL-ON-REVERT: dropping the zone check in sourceNATPoolAddressReason turns
// `fe80::1%eth0` from REJECT to ACCEPT and reds this test.
func TestPoolAddressGrammarMatchesDataplane_6812(t *testing.T) {
	fx := loadSNATPoolGrammarFixture(t)
	accepted := 0
	for _, c := range fx.Cases {
		reason, ok := sourceNATPoolAddressReason(c.Addr)
		if ok != c.OK {
			t.Errorf("sourceNATPoolAddressReason(%q) ok = %v, want %v (reason %q; fixture note: %s)",
				c.Addr, ok, c.OK, reason, c.Note)
			continue
		}
		if ok {
			accepted++
			if reason != "" {
				t.Errorf("sourceNATPoolAddressReason(%q) accepted but returned reason %q", c.Addr, reason)
			}
			continue
		}
		if reason == "" {
			t.Errorf("sourceNATPoolAddressReason(%q) rejected with an EMPTY reason", c.Addr)
		}
	}
	// Non-vacuity: a fixture of only-rejects would pass against a predicate
	// that rejects everything.
	if accepted < 10 {
		t.Fatalf("fixture exercises only %d accepted members; the table must carry both verdicts", accepted)
	}
}

// TestPoolAddressHostCountMatchesDataplane_6812 asserts the expansion
// CARDINALITY of every accepted member — the quantity the aggregate budget
// charges and the quantity the dataplane sizes an occupancy bitmap for.
//
// CORRECTION (#6812 B2). An earlier revision of this comment claimed a
// cardinality assertion "would catch a masking or off-by-one drift". It does
// not, and that was measured: deleting BOTH network-base masks from
// expand_pool_address left the entire crate green, because a missing mask
// changes WHICH addresses are produced and never HOW MANY. The claim was
// carried only by `note` strings that no assertion read. The address SET is
// pinned by the fixture's first/last/expanded fields, asserted Rust-side in
// nat_pool_grammar_parity_fixture; this test covers the count alone.
func TestPoolAddressHostCountMatchesDataplane_6812(t *testing.T) {
	fx := loadSNATPoolGrammarFixture(t)
	for _, c := range fx.Cases {
		if !c.OK {
			// A rejected member is never charged: SourceNATPoolUnusableReason
			// is all-or-nothing, so the walk skips its whole pool.
			continue
		}
		if got := sourceNATPoolMemberHostCount(c.Addr); got != c.Hosts {
			t.Errorf("sourceNATPoolMemberHostCount(%q) = %d, want %d", c.Addr, got, c.Hosts)
		}
	}
}

// TestZoneScopedBarePoolAddressKeepsItsSpecificReason_6812 pins the precedence
// the round-3 zone check must NOT disturb. `fe80::1%eth0` now fails the
// membership-grammar clause too, but the pool's wire reason stays the specific
// #5875 zone_scoped_pool_address, because SourceNATPoolUnusableReason writes
// the zone clause AFTER the grammar clause.
func TestZoneScopedBarePoolAddressKeepsItsSpecificReason_6812(t *testing.T) {
	pool := &NATPool{
		Name:      "p",
		Addresses: []string{"fe80::1%eth0"},
		PortLow:   1024,
		PortHigh:  65535,
	}
	if got := SourceNATPoolUnusableReason(pool); got != "zone_scoped_pool_address" {
		t.Fatalf("SourceNATPoolUnusableReason = %q, want zone_scoped_pool_address", got)
	}
}

// TestPoolGrammarFixtureRowsAreSelfConsistent_6812 keeps the shared fixture
// honest for the assertions the OTHER side runs (#6812 B2).
//
// The Rust address-set assertions are conditional on a row carrying first /
// last / expanded, so a row whose annotation disagrees with its own `hosts`
// would still pass there while pinning the wrong thing. Go cannot expand a
// member, but it can refuse to let the table contradict itself.
func TestPoolGrammarFixtureRowsAreSelfConsistent_6812(t *testing.T) {
	fx := loadSNATPoolGrammarFixture(t)
	annotated := 0
	for _, c := range fx.Cases {
		hasRange := c.First != "" || c.Last != ""
		if !hasRange && len(c.Expanded) == 0 {
			continue
		}
		annotated++
		if !c.OK {
			t.Errorf("%q is a REJECTED row but carries an expansion annotation; a refused "+
				"member expands to nothing", c.Addr)
			continue
		}
		if len(c.Expanded) > 0 && uint64(len(c.Expanded)) != c.Hosts {
			t.Errorf("%q lists %d expanded addresses but declares hosts=%d — the row "+
				"contradicts itself, so the Rust assertion pins the wrong set",
				c.Addr, len(c.Expanded), c.Hosts)
		}
		if len(c.Expanded) > 0 {
			if c.First != "" && c.Expanded[0] != c.First {
				t.Errorf("%q: first=%q but expanded[0]=%q", c.Addr, c.First, c.Expanded[0])
			}
			if c.Last != "" && c.Expanded[len(c.Expanded)-1] != c.Last {
				t.Errorf("%q: last=%q but expanded[last]=%q", c.Addr, c.Last,
					c.Expanded[len(c.Expanded)-1])
			}
		}
		if c.Hosts == 1 && c.First != "" && c.Last != "" && c.First != c.Last {
			t.Errorf("%q expands to one host but declares first=%q last=%q",
				c.Addr, c.First, c.Last)
		}
	}
	if annotated < 8 {
		t.Fatalf("only %d fixture rows pin an expanded address set; the network-base "+
			"mask loses its witness below that", annotated)
	}
}

// TestLeadingZeroHintIsBoundInThisPackage_6812 closes a package-scoping hole
// (#6812 B3): the leading-zero diagnostic is PRODUCED here
// (sourceNATPoolAddressReason -> canonicalPoolAddressHint,
// compiler_validate_strict_nat.go) but every test that binds it lives in
// pkg/dataplane/userspace. Deleting both hint branches therefore left
// `go test ./pkg/config/ -run '6812|LeadingZero'` GREEN — a full-tree run
// catches it, a package-scoped one cannot, and a package-scoped run is what a
// maintainer touching this file will do.
//
// FAIL-ON-REVERT: drop either canonicalPoolAddressHint branch and this reds.
func TestLeadingZeroHintIsBoundInThisPackage_6812(t *testing.T) {
	for _, tc := range []struct {
		addr      string
		canonical string
	}{
		{"010.0.0.0/24", "10.0.0.0/24"},
		{"192.168.001.1/32", "192.168.1.1/32"},
		{"010.0.0.1", "10.0.0.1"},
		{"::ffff:010.0.0.0/120", "::ffff:10.0.0.0/120"},
	} {
		reason, ok := sourceNATPoolAddressReason(tc.addr)
		if ok {
			t.Errorf("%q must be rejected", tc.addr)
			continue
		}
		if !strings.Contains(reason, "leading zero") {
			t.Errorf("%q: reason does not name the cause: %s", tc.addr, reason)
		}
		if !strings.Contains(reason, strconv.Quote(tc.canonical)) {
			t.Errorf("%q: reason does not name the canonical spelling %q, so the operator "+
				"cannot see the fix is one character: %s", tc.addr, tc.canonical, reason)
		}
	}

	// The hint must never fire for an address that already works, nor invent a
	// suggestion for an unrelated malformation — it would be telling the
	// operator to make a change that does not help.
	for _, addr := range []string{
		"10.0.0.0/24", "198.51.100.1", "2001:db8::1", // already valid
		"not-an-ip", "10.0.0.256/24", "203.0.113.1/garbage", "10.0.0.0/33",
	} {
		if hint := canonicalPoolAddressHint(addr); hint != "" {
			t.Errorf("canonicalPoolAddressHint(%q) = %q, want no suggestion", addr, hint)
		}
	}
}
