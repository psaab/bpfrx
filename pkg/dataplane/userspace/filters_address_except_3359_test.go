package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3359: a firewall-filter term mixing a positive address match (a literal
// source/destination-address or a non-except prefix-list) with an `except`
// prefix-list in the same direction has no faithful boolean-inversion form. The
// commit gate (config.validateFilterAddressExceptStrict) rejects the shape, but
// an already-persisted / peer-synced config can still reach the userspace
// lowering on the tolerant path. resolvePrefixListAddrs MUST be fail-safe there:
// POSITIVE-WINS — the except prefixes are ignored (NOT folded into the positive
// set). The earlier code did `positive = append(positive, exceptPrefixes...)`,
// which was fail-OPEN: a discard/reject term no longer dropped the excepted
// traffic and an accept term admitted the prefixes the operator wrote to
// exclude.
//
// FAIL-ON-REVERT: restore the fold and `except` (10.1.0.0/16) appears in the
// returned positive set — this test goes RED.
func TestResolvePrefixListAddrsMixedPositiveExceptFailsSafe_3359(t *testing.T) {
	cfg := &config.Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"trusted": {Name: "trusted", Prefixes: []string{"10.1.0.0/16"}},
	}

	// Positive literal 10.0.0.0/8 + except prefix-list trusted (10.1.0.0/16) in
	// the same (source) direction.
	addrs, except, constrained := resolvePrefixListAddrs(
		[]string{"10.0.0.0/8"},
		[]config.PrefixListRef{{Name: "trusted", Except: true}},
		cfg, "f", "t", "source",
	)

	if except {
		t.Fatalf("mixed positive+except must resolve except=false (positive-wins), got except=true")
	}
	if !constrained {
		t.Fatalf("a term with a written address scope must stay constrained")
	}
	// The positive set must be EXACTLY the operator's positive scope — the
	// except prefixes must NOT be folded in (the #3359 fail-open).
	for _, a := range addrs {
		if a == "10.1.0.0/16" {
			t.Fatalf("except prefix 10.1.0.0/16 was folded into the positive set "+
				"(fail-OPEN #3359); positive-wins must drop it. addrs=%v", addrs)
		}
	}
	if len(addrs) != 1 || addrs[0] != "10.0.0.0/8" {
		t.Fatalf("positive set = %v, want exactly [10.0.0.0/8] (positive-wins)", addrs)
	}
}

// The clean except case (an except prefix-list as the SOLE address source for
// the direction) is unchanged and must still produce except=true so the matcher
// evaluates "match everything NOT in the list".
func TestResolvePrefixListAddrsCleanExceptUnchanged_3359(t *testing.T) {
	cfg := &config.Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"trusted": {Name: "trusted", Prefixes: []string{"10.1.0.0/16"}},
	}
	addrs, except, constrained := resolvePrefixListAddrs(
		nil,
		[]config.PrefixListRef{{Name: "trusted", Except: true}},
		cfg, "f", "t", "source",
	)
	if !except {
		t.Fatalf("clean except case must resolve except=true, got false")
	}
	if !constrained {
		t.Fatalf("clean except case must stay constrained")
	}
	if len(addrs) != 1 || addrs[0] != "10.1.0.0/16" {
		t.Fatalf("clean except prefixes = %v, want [10.1.0.0/16]", addrs)
	}
}
