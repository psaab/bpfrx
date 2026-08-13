package config

import (
	"encoding/json"
	"os"
	"path/filepath"
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
// charges and the quantity the dataplane sizes an occupancy bitmap for. A
// verdict-only table would not catch a masking or off-by-one drift on either
// side (the round-3 Rust rewrite replaced IpNet::network() with its own mask).
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
