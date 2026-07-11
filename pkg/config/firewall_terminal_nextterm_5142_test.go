package config

import (
	"strings"
	"testing"
)

// #5142 (security, filter fail-open): a firewall-filter term with a terminating
// action (discard/reject/accept) co-located with `then next term` is a
// contradiction. A terminating deny MUST terminate and apply the deny; a
// fall-through / next-term bit must NEVER suppress it (vSRX filter semantics).
// Before #5142, validateFilterTerminalConflictStrict skipped any term with fewer
// than two terminals, so a SINGLE terminal + `then next term` committed cleanly
// and (on the runtime) fell through — leaving the implicit Accept in place, i.e.
// the deny was silently dropped (fail-OPEN). This is distinct from #4375 (two
// DISTINCT terminals) and #2544 (empty-action modifier-only next-term).
//
// FAIL-ON-REVERT: restore the `then next term` reject to the pre-#5142
// `len(term.TerminalActions) < 2 { continue }` skip and TestFilterDiscard*Next*
// go RED — CompileConfig accepts the discard+next-term contradiction.

func TestFilterDiscardPlusNextTerm_5142(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t then discard",
		"set firewall family inet filter f term t then next term",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("term with `then discard` AND `then next term` must be rejected " +
			"at commit (#5142 — a terminating deny cannot fall through)")
	}
	if !strings.Contains(err.Error(), "discard") ||
		!strings.Contains(err.Error(), "next term") {
		t.Fatalf("error %q must name the discard action and `next term`", err)
	}
	if !strings.Contains(err.Error(), `filter "f"`) ||
		!strings.Contains(err.Error(), `term "t"`) {
		t.Fatalf("error %q must name the offending filter and term", err)
	}
	// Tolerant load / peer-sync path must not brick (#1960 no-brick): the
	// last-wins Action still drives the dataplane, but the operator never
	// reaches this state through a commit.
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the discard+next-term contradiction: %v", lerr)
	}
}

func TestFilterRejectPlusNextTerm_5142(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t then reject",
		"set firewall family inet filter f term t then next term",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("term with `then reject` AND `then next term` must be rejected at commit (#5142)")
	}
	if !strings.Contains(err.Error(), "reject") ||
		!strings.Contains(err.Error(), "next term") {
		t.Fatalf("error %q must name the reject action and `next term`", err)
	}
}

// An `accept` terminal + next-term is equally contradictory (a terminal always
// terminates); reject it too so the invariant is symmetric.
func TestFilterAcceptPlusNextTerm_5142(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t then accept",
		"set firewall family inet filter f term t then next term",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("term with `then accept` AND `then next term` must be rejected at commit (#5142)")
	}
}

// inet6 must be gated identically (the validator walks both families).
func TestFilterDiscardPlusNextTermV6_5142(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet6 filter f6 term t then discard",
		"set firewall family inet6 filter f6 term t then next term",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("inet6 term with discard + next-term must be rejected (#5142)")
	}
	if !strings.Contains(err.Error(), "inet6") {
		t.Fatalf("error %q must name the inet6 family", err)
	}
}

// A modifier-only next-term term (count/log + `then next term`, NO terminating
// action) is a VALID fall-through (#2544/#3427) and must compile cleanly — the
// #5142 gate must NOT reject a legitimate fall-through.
func TestFilterModifierOnlyNextTermAllowed_5142(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter ok term t1 then count c1",
		"set firewall family inet filter ok term t1 then log",
		"set firewall family inet filter ok term t1 then next term",
		"set firewall family inet filter ok term t2 then discard",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("modifier-only `then next term` (no terminating action) must compile: %v", err)
	}
}

// A bare `then next term` with no other action is a valid fall-through.
func TestFilterBareNextTermAllowed_5142(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter ok term t1 then next term",
		"set firewall family inet filter ok term t2 then accept",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("bare `then next term` fall-through must compile: %v", err)
	}
}

// A single terminating action WITHOUT next-term remains the ordinary case and
// must compile (no regression on the common path).
func TestFilterSingleTerminalNoNextTermAllowed_5142(t *testing.T) {
	for _, action := range []string{"accept", "reject", "discard"} {
		tree := buildFilterTree(t,
			"set firewall family inet filter ok term t then "+action,
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("single terminal %q (no next-term) must compile: %v", action, err)
		}
	}
}
