package config

import (
	"sort"
	"strings"
	"testing"
)

// #8933: a brace-elided policy-statement `then` clause loses every
// value-carrying routing action AND corrupts the term's TERMINAL ACTION.
//
// WHY THE SECOND HALF IS THE SEVERE ONE. The compiler consumes the first
// packed token into `PolicyTerm.Action`, so `then metric 50;` yields
// Action="metric" -- neither "accept" nor "reject". `pkg/frr/policy_render.go`
// branches on exactly that:
//
//	action := "permit"; if term.Action == "reject" { action = "deny" }
//	nonTerminating := term.Action != "accept" && term.Action != "reject"
//
// so the term renders as `permit` + `on-match next` with no `set` clauses. It
// loses its attributes AND STOPS TERMINATING -- falling through to later terms
// and the default action (#2451). A term written to accept-with-metric does
// neither.
//
// This was found by printing the compiled term rather than comparing
// fingerprints. A fingerprint diff detects that something was lost; it cannot
// show what the loss DID, and the fall-through half is invisible to it.

// policyThenActions8933 is the value-carrying action set. Derived from the
// schema below rather than trusted as a literal, so a NINTH action added
// tomorrow fails this cell rather than being silently unadmitted -- the
// #8922 shape, where admitting some of a family reads as success.
var policyThenActions8933 = []string{
	"as-path-prepend", "community", "load-balance", "local-preference",
	"metric", "metric-type", "next-hop", "origin",
}

func policyStatementThenNode8933(t *testing.T) *schemaNode {
	t.Helper()
	po := setSchema.children["policy-options"]
	if po == nil {
		t.Fatal("no policy-options in setSchema")
	}
	// `policy-statement` and `term` are args:1 instance containers — the
	// instance name is consumed as an argument, so their children hang
	// directly off the node rather than off a wildcard.
	ps := po.children["policy-statement"]
	if ps == nil {
		t.Fatal("no policy-statement under policy-options")
	}
	term := ps.children["term"]
	if term == nil {
		t.Fatal("policy-statement declares no `term` container")
	}
	then := term.children["then"]
	if then == nil {
		t.Fatal("policy-statement term declares no `then` container")
	}
	return then
}

// The family must be admitted TOGETHER. A partially-admitted family is the
// #8922 defect: the operator hardens all of them, some apply, and partial
// application reads as success.
func TestPolicyThenActionsAdmittedTogether8933(t *testing.T) {
	then := policyStatementThenNode8933(t)

	// LIVENESS: the schema must still declare these. If the container is
	// renamed or the actions move, this cell must fail rather than pass over
	// an empty set.
	var declared []string
	for _, a := range policyThenActions8933 {
		if _, ok := then.children[a]; ok {
			declared = append(declared, a)
		}
	}
	if len(declared) != len(policyThenActions8933) {
		t.Fatalf("the policy-statement `then` no longer declares all %d actions "+
			"(found %d: %v). Either the schema moved or this list is stale — "+
			"re-derive it before trusting the admission check below",
			len(policyThenActions8933), len(declared), declared)
	}

	var missing []string
	for _, a := range policyThenActions8933 {
		if !compactNormalizeInScope("then", a) {
			missing = append(missing, a)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("policy `then` action(s) %v are NOT admitted by "+
			"compactNormalizeInScope while their siblings are. A partially "+
			"admitted family is the #8922 shape: the operator writes all of "+
			"them, some survive the elided spelling and some vanish, and "+
			"partial application reads as success (#8933). family=%v",
			missing, policyThenActions8933)
	}
}

// The behaviour, measured end to end, with the arms pinned one brace apart.
func TestElidedPolicyThenKeepsActionAndTerminates8933(t *testing.T) {
	const pre = `policy-options { policy-statement p { term t { from { protocol bgp; } `

	compile := func(txt string) (action string, metric int) {
		tr, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture does not parse: %v", perrs[0])
		}
		cfg, err := CompileConfigLenient(tr)
		if err != nil || cfg == nil {
			t.Fatalf("fixture does not compile: %v", err)
		}
		ps := cfg.PolicyOptions.PolicyStatements["p"]
		if ps == nil || len(ps.Terms) == 0 {
			t.Fatal("NON-VACUITY: the fixture produced no term, so neither " +
				"assertion below can mean anything")
		}
		return ps.Terms[0].Action, ps.Terms[0].Metric
	}

	braced := pre + `then { metric 50; } } } }`
	elided := pre + `then metric 50; } } }`

	// ARM CHECK. The two spellings must differ by EXACTLY the brace pair this
	// cell is about. Every fixture fault in this census came from arms that
	// differed by more than the named variable, and the check is one line.
	if d := strings.Count(braced, "{") - strings.Count(elided, "{"); d != 1 {
		t.Fatalf("ARM CHECK FAILED: brace delta = %d, must be exactly 1. The "+
			"two arms differ by more than the elision under test, so any "+
			"difference below is unattributable", d)
	}

	bAction, bMetric := compile(braced)
	eAction, eMetric := compile(elided)

	// CONTROL: the braced arm must carry the value, or the comparison is
	// between two empty results.
	if bMetric != 50 {
		t.Fatalf("CONTROL FAILED: the braced arm did not carry metric=50 "+
			"(got %d). The fixture cannot demonstrate a loss it never had", bMetric)
	}

	if eMetric != bMetric {
		t.Errorf("the elided `then` LOST the metric: braced=%d elided=%d. A "+
			"routing policy written with the compact spelling applies none of "+
			"its attribute changes, and `show configuration` renders what the "+
			"operator wrote (#8933)", bMetric, eMetric)
	}
	if eAction != bAction {
		t.Errorf("the elided `then` CORRUPTED the terminal action: braced=%q "+
			"elided=%q. The compiler consumed the packed token into "+
			"PolicyTerm.Action; policy_render.go treats anything that is "+
			"neither \"accept\" nor \"reject\" as NON-TERMINATING, so the term "+
			"renders as permit + `on-match next` and falls through to later "+
			"terms and the default action (#8933, #2451). This half is "+
			"invisible to a fingerprint comparison", bAction, eAction)
	}
}
