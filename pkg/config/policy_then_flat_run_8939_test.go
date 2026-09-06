package config

import "testing"

// #8939 on `policy-options policy-statement … then`. TWO census rows, and they
// are NOT equally interesting -- a distinction the census cannot draw, because
// it synthesizes the alphabetically-first eligible leaves and cannot know
// whether the pair it built is a command anyone writes.
//
//	policy-statement <p> then       declares exactly  accept | reject
//	policy-statement <p> term <t> then   declares TEN, including
//	  load-balance, local-preference, metric, next-hop, origin,
//	  as-path-prepend, community
//
// `accept` and `reject` are MUTUALLY EXCLUSIVE, so the policy-level row is the
// only pair that exists there and is not an operator command. It is still
// fixed -- the two spellings disagreed about which action won (split
// last-wins `reject`, packed `accept`), and a spelling difference on a
// contradictory input is still a spelling difference -- but the severity is
// "the spellings disagree", not "a control was lost".
//
// THE TERM-LEVEL ROW IS THE ONE WITH AN OPERATOR BEHIND IT:
//
//	set … term t1 then accept load-balance per-packet local-preference 200
//	  -> action="accept"  load-balance=""  local-preference=0
//
// `then { local-preference 200; load-balance per-packet; accept; }` is
// ordinary Junos. And `accept` is alphabetically FIRST, so it is the token
// that survives: the route is still accepted and installed WITHOUT the
// attributes the operator attached to it -- default local-preference, no
// ECMP. Not a fail-open; a route present with the wrong attributes, which
// `show configuration` renders exactly as authored.
//
// Both spellings commit clean through the strict pair (`OPERATOR` rows).
func TestPolicyThenFlatRunKeepsEveryLeaf8939(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *PolicyStatement {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			p, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("compile: %v", err)
		}
		ps := cfg.PolicyOptions.PolicyStatements["p1"]
		if ps == nil {
			t.Fatal("the command produced no policy-statement p1 (#8939)")
		}
		return ps
	}

	t.Run("term then", func(t *testing.T) {
		b := "set policy-options policy-statement p1 term t1 then "
		termOf := func(ps *PolicyStatement) *PolicyTerm {
			if len(ps.Terms) == 0 {
				t.Fatal("no term (#8939)")
			}
			return ps.Terms[0]
		}
		ref := termOf(build(t, b+"accept", b+"load-balance per-packet",
			b+"local-preference 200"))
		if ref.Action == "" || ref.LoadBalance == "" || ref.LocalPreference == 0 {
			t.Fatalf("the split reference arm is incomplete (%+v) -- every comparison "+
				"below would pass against a term that carries nothing (#8939)", ref)
		}
		for _, tc := range []struct{ name, cmd string }{
			{"two leaves", b + "accept load-balance per-packet"},
			// THE WIDTH A RECURSIVE DESCENT FAILS (#9079).
			{"three leaves", b + "accept load-balance per-packet local-preference 200"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := termOf(build(t, tc.cmd))
				if got.Action != ref.Action {
					t.Errorf("action = %q, want %q (#8939)", got.Action, ref.Action)
				}
				if got.LoadBalance != ref.LoadBalance {
					t.Errorf("load-balance = %q, want %q -- the route is accepted "+
						"without the ECMP the operator attached to it (#8939)",
						got.LoadBalance, ref.LoadBalance)
				}
				if tc.name == "three leaves" && got.LocalPreference != ref.LocalPreference {
					t.Errorf("local-preference = %d, want %d -- the leaf a recursive "+
						"descent drops, and the one that decides which path traffic "+
						"takes (#8939)", got.LocalPreference, ref.LocalPreference)
				}
			})
		}
	})

	t.Run("policy then", func(t *testing.T) {
		// The contradictory pair, asserted for SPELLING AGREEMENT only. The
		// claim is "both spellings resolve it the same way", NOT that either
		// answer is meaningful -- see the file comment.
		b := "set policy-options policy-statement p1 then "
		ref := build(t, b+"accept", b+"reject").DefaultAction
		if ref == "" {
			t.Fatalf("the split reference arm produced no default action (#8939)")
		}
		if got := build(t, b+"accept reject").DefaultAction; got != ref {
			t.Errorf("packed default-action = %q, want %q -- the packed and split "+
				"spellings of the same contradictory input must resolve it "+
				"identically (#8939)", got, ref)
		}
	})
}
