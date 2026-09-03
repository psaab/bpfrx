package frr

// policy_chain_narrowed_eval_8363_test.go — #8363, the #7625 remainder.
//
// #7625 fixed the EMPTIED half (every authored chain member undefined -> bounded
// deny, PR #8362) and deliberately left the NARROWED half (some members survive)
// at today's behaviour, pending the measurement these cells record.
//
// THE QUESTION. Extending the synthesized deny to a narrowed chain was argued to
// be wrong because the deny becomes an ORDERED MEMBER of the chain, so routes
// passing the surviving member would reach it and be dropped — taking a
// works-but-narrowed config to deny-all.
//
// THE ANSWER, measured rather than argued:
//
//  1. That objection is REFUTED. An accepting member TERMINATES evaluation. xpf
//     emits `on-match next` only for NON-terminating terms, so a `then accept`
//     term is a bare `permit` and FRR stops there. A route the surviving member
//     accepts never reaches a later deny.
//
//  2. But POSITION is a hazard the objection did not name, and it is worse. A
//     synthesized deny is a chain member with a terminating DEFAULT action, and
//     renderComposedRouteMap BREAKS on the first such member — so every member
//     after it is never emitted at all. A deny at a non-final ghost position
//     does not merely shadow the rest of the chain, it DELETES it:
//     `[GHOST, REAL]` renders as a lone `deny 10`. That IS the deny-all outcome
//     the objection feared, reached by a mechanism nobody had named.
//
// CONSEQUENCE. A synthesized deny is safe in a narrowed chain IFF the undefined
// members form a SUFFIX of the authored chain. Ghost-last (the common shape — a
// policy appended and never defined, or since removed) is safe. Ghost-first or
// ghost-middle must keep the surviving subset, because the "fix" there is a
// routing outage.
//
// These cells exist so that any future attempt at the narrowed fix trips over
// fact 2 instead of rediscovering it in production.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func policyOptions8363() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			// Accepts what it matches: a TERMINATING term.
			"ACCEPTER": {Name: "ACCEPTER", Terms: []*config.PolicyTerm{
				{Name: "t1", PrefixList: []string{"PL"}, Action: "accept"},
			}},
			// Modifies and falls through: a NON-terminating term.
			"TAGGER": {Name: "TAGGER", Terms: []*config.PolicyTerm{
				{Name: "t1", PrefixList: []string{"PL"}, Community: "COMM"},
			}},
			// Stand-in for the deny a narrowed fix would synthesize for the
			// undefined member: a chain member whose DEFAULT action denies.
			"SYNTH-DENY": {Name: "SYNTH-DENY", DefaultAction: "reject"},
		},
		PrefixLists: map[string]*config.PrefixList{"PL": {Name: "PL", Prefixes: []string{"10.0.0.0/8"}}},
		Communities: map[string]*config.CommunityDef{"COMM": {Name: "COMM", Members: []string{"65001:100"}}},
		ASPaths:     map[string]*config.ASPathDef{},
	}
}

// seqAction8363 returns the action word of the route-map sequence at seq, and
// whether that sequence carries `on-match next`.
func seqAction8363(t *testing.T, section, name string, seq int) (action string, continues bool) {
	t.Helper()
	lines := strings.Split(section, "\n")
	header := ""
	for i, ln := range lines {
		if strings.HasPrefix(ln, "route-map "+name+" ") && strings.HasSuffix(ln, " "+itoa8363(seq)) {
			header = ln
			for _, rest := range lines[i+1:] {
				if strings.HasPrefix(rest, "route-map ") {
					break
				}
				if strings.TrimSpace(rest) == "on-match next" {
					continues = true
				}
				if strings.TrimSpace(rest) == "exit" {
					break
				}
			}
			break
		}
	}
	if header == "" {
		t.Fatalf("no sequence %d under route-map %q in:\n%s", seq, name, section)
	}
	f := strings.Fields(header)
	return f[2], continues
}

func itoa8363(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// FACT 1 — the objection is refuted. An accepting member terminates, so the
// trailing deny catches only the fall-through.
func TestAcceptingChainMemberTerminatesEvaluation8363(t *testing.T) {
	po := policyOptions8363()
	got := New().renderComposedRouteMap(po, "C-xpf-chain", []string{"ACCEPTER", "SYNTH-DENY"})

	action, continues := seqAction8363(t, got, "C-xpf-chain", 10)
	if action != "permit" {
		t.Errorf("the accepting member's sequence is %q, want permit", action)
	}
	if continues {
		t.Errorf("the accepting member carries `on-match next`, so FRR would fall into the "+
			"deny and the #8363 objection would stand:\n%s", got)
	}
	if action, _ := seqAction8363(t, got, "C-xpf-chain", 20); action != "deny" {
		t.Errorf("the fall-through sequence is %q, want deny", action)
	}
}

// FACT 1b — the CONTROL. A non-terminating member DOES continue into the deny.
// Without this, "no on-match next" above could just mean the renderer never
// emits it, and fact 1 would be measuring nothing.
func TestNonTerminatingChainMemberContinuesIntoTheDeny8363(t *testing.T) {
	po := policyOptions8363()
	got := New().renderComposedRouteMap(po, "C2-xpf-chain", []string{"TAGGER", "SYNTH-DENY"})

	action, continues := seqAction8363(t, got, "C2-xpf-chain", 10)
	if action != "permit" {
		t.Errorf("the non-terminating member's sequence is %q, want permit", action)
	}
	if !continues {
		t.Fatalf("a non-terminating member must carry `on-match next` (Junos fall-through); "+
			"without it the renderer never continues and fact 1 proves nothing:\n%s", got)
	}
	if action, _ := seqAction8363(t, got, "C2-xpf-chain", 20); action != "deny" {
		t.Errorf("the fall-through sequence is %q, want deny", action)
	}
}

// FACT 2 — THE HAZARD. A chain member with a terminating default action ends the
// composed render, so every member AFTER it is never emitted. A deny synthesized
// at a non-final ghost position therefore deletes the rest of the chain.
//
// This is the cell that constrains any future narrowed fix: the deny is safe
// only when the undefined members form a SUFFIX of the authored chain.
func TestDenyBeforeASurvivingMemberDeletesTheRestOfTheChain8363(t *testing.T) {
	po := policyOptions8363()
	got := New().renderComposedRouteMap(po, "C3-xpf-chain", []string{"SYNTH-DENY", "ACCEPTER"})

	if action, _ := seqAction8363(t, got, "C3-xpf-chain", 10); action != "deny" {
		t.Errorf("first sequence is %q, want deny", action)
	}
	// The surviving member must be ABSENT — that is the hazard, stated as the
	// property rather than as a line count.
	if strings.Contains(got, "match ip address prefix-list PL") {
		t.Errorf("ACCEPTER's match survived a preceding terminating deny; if this now "+
			"passes, renderComposedRouteMap stopped breaking on a terminating member and "+
			"the #8363 position constraint must be re-derived:\n%s", got)
	}
	// ...and the whole route-map is exactly one deny: a ghost-first chain would
	// render as deny-all.
	if n := strings.Count(got, "route-map C3-xpf-chain "); n != 1 {
		t.Errorf("ghost-first chain rendered %d sequences, want exactly 1 (deny-all):\n%s", n, got)
	}
}
