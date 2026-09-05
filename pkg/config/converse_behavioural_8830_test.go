package config

import (
	"fmt"
	"reflect"
	"testing"
)

// #8830: the #8807 converse predicate answers "unread at P" by asking whether
// any `.Name()` clause at that container names the head. That is a question
// about the SOURCE, and it admits a false negative shaped exactly like the
// class the predicate exists to find:
//
//	no clause at P                      -> reported          (#8785)
//	clause at P, value reaches a field  -> not reported       (correct)
//	clause at P, value reaches NOTHING  -> NOT reported       (FALSE NEGATIVE)
//
// Per-hit adjudication cannot close that gap. Adjudication iterates the hits
// the predicate reported, so a head it never reported is never adjudicated —
// adjudication is a PRECISION discipline and this is a RECALL defect.
//
// This cell answers the question BEHAVIOURALLY instead: compile the fixture
// with and without the statement and compare the whole *Config. If adding the
// statement changes nothing, the value reaches nothing, whatever the source
// looks like.
//
// THE ACCEPTANCE MUTATION, run by hand and recorded because it cannot be
// shipped. Adding to the IKE proposal compiler
//
//	case "description":
//	        _ = v          // reads the value into nothing
//
// makes the AST predicate go QUIET — converseHits8807 stops reporting
// "proposal / description" — while this cell still reports UNREAD. That is the
// false negative demonstrated and killed: the source now contains a clause, and
// the compiled result is still unchanged.
//
// WARNINGS ARE PART OF THE COMPARISON and that is not incidental. A keyword
// whose only visible effect is an advisory IS read; nulling cfg.Warnings before
// comparing once made a keyword look silently dropped when the proof it was
// read was an advisory appearing. TestConverseComparisonSeesWarnings8830 pins
// the comparison's sensitivity directly, so the property does not depend on
// some real keyword happening to have a warnings-only effect.
//
// COVERAGE IS DELIBERATELY NARROW. A behavioural predicate needs a compilable
// fixture per container, so this is not a census; it is the instrument plus the
// containers it has been given fixtures for. Within them no LIVE false negative
// was found — every head carrying a clause is behaviourally read — so the class
// is proven by mutation rather than observed in the wild. Widening it means
// adding fixtures, and a fixture that compiles to an empty config measures
// nothing, which is why the liveness check below is fatal rather than skipped.
type converseFixture8830 struct {
	key        string // "container / head", matching converseHits8807's key
	base       string // fixture text with one %s slot
	stmt       string // the statement under test
	wantUnread bool
	why        string
}

func converseFixtures8830() []converseFixture8830 {
	const ikeProposal = `security { ike { proposal P { %s } } }`
	const ikePolicy = `security { ike { policy PL { %s } } }`
	const ipsecVPN = `security { ipsec { vpn V { %s } } }`
	return []converseFixture8830{
		{"proposal / description", ikeProposal, "description hello;", true,
			"#8785: declared, no field, no read. The motivating case, and the " +
				"one the AST predicate finds only because NO clause exists."},
		{"policy / description", ikePolicy, "description hi;", true,
			"was carried as NOT MEASURED in converseAdjudicated8807; measured " +
				"here and it is genuinely unread."},

		// Heads at the SAME containers that ARE read. These make the positives
		// above mean something: a predicate that called everything unread
		// would satisfy the two rows above and fail every row below.
		{"proposal / authentication-algorithm", ikeProposal, "authentication-algorithm sha1;", false, ""},
		{"proposal / authentication-method", ikeProposal, "authentication-method pre-shared-keys;", false, ""},
		{"proposal / encryption-algorithm", ikeProposal, "encryption-algorithm aes-128-cbc;", false, ""},
		{"proposal / dh-group", ikeProposal, "dh-group group14;", false, ""},
		{"proposal / lifetime-seconds", ikeProposal, "lifetime-seconds 3600;", false, ""},
		{"policy / mode", ikePolicy, "mode main;", false, ""},
		{"policy / proposals", ikePolicy, "proposals P;", false, ""},
		{"policy / pre-shared-key", ikePolicy, `pre-shared-key ascii-text "s3cret";`, false, ""},
		{"vpn / bind-interface", ipsecVPN, "bind-interface st0.1;", false, ""},
		{"vpn / df-bit", ipsecVPN, "df-bit copy;", false, ""},
		{"vpn / establish-tunnels", ipsecVPN, "establish-tunnels immediately;", false, ""},
	}
}

func compileForConverse8830(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture does not parse (%q): %v", text, perrs[0])
	}
	cfg, err := CompileConfigLenient(tree)
	if cfg == nil {
		t.Fatalf("fixture did not compile (%q): %v", text, err)
	}
	return cfg
}

func TestConverseBehaviouralPredicate8830(t *testing.T) {
	empty := compileForConverse8830(t, "")
	for _, f := range converseFixtures8830() {
		t.Run(f.key, func(t *testing.T) {
			without := compileForConverse8830(t, fmt.Sprintf(f.base, ""))
			with := compileForConverse8830(t, fmt.Sprintf(f.base, f.stmt))

			// LIVENESS, and it is FATAL rather than a skip. If the with-arm
			// compiles to an empty config the two arms are being compared as
			// two empty results, and "identical" means the fixture delivered
			// nothing rather than that the value is unread. A census that
			// skipped this scored 126 of 130 links clean while 102 of them
			// compiled to nothing in both arms.
			if reflect.DeepEqual(empty, with) {
				t.Fatalf("fixture compiles to an EMPTY config, so the comparison "+
					"is vacuous — it would report UNREAD for a statement that was "+
					"never modelled at all (%q)", f.stmt)
			}

			unread := reflect.DeepEqual(without, with)
			switch {
			case f.wantUnread && !unread:
				t.Errorf("%s is expected to be UNREAD but adding %q changed the "+
					"compiled config. Either the value now lands somewhere — in "+
					"which case the defect is fixed and this row should move — or "+
					"the fixture changed. %s", f.key, f.stmt, f.why)
			case !f.wantUnread && unread:
				t.Errorf("%s is READ, but adding %q left the compiled config "+
					"IDENTICAL, warnings included. The value reaches nothing: "+
					"either a compiler clause was lost, or it assigns to a local "+
					"and drops it — the #8830 shape, which the source-based "+
					"converse predicate cannot see.", f.key, f.stmt)
			}
		})
	}
}

// The comparison must see a difference that exists ONLY in cfg.Warnings.
// Asserted directly so the property does not rest on some real keyword
// happening to have a warnings-only effect.
func TestConverseComparisonSeesWarnings8830(t *testing.T) {
	a := &Config{}
	b := &Config{}
	b.Warnings = []string{"an advisory and nothing else"}
	if reflect.DeepEqual(a, b) {
		t.Error("two configs differing ONLY in Warnings compare EQUAL, so the " +
			"behavioural predicate would score a keyword whose sole effect is an " +
			"advisory as UNREAD. A keyword read only into a warning is still read.")
	}
	if !reflect.DeepEqual(a, &Config{}) {
		t.Error("two identical empty configs compare UNEQUAL, so every row would " +
			"read as changed and the predicate would report nothing — the check " +
			"above would pass for the wrong reason")
	}
}
