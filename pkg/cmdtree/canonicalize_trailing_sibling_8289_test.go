package cmdtree

import "testing"

// #8289: a word after a childless LEAF must not resolve against the leaf's own
// SIBLINGS.
//
// `Canonicalize` used to `continue` when `node.Children == nil`, leaving
// `current` at the PARENT map, so `show version configuration` canonicalized OK
// as a three-word command.
//
// WHY THAT IS AN RBAC BYPASS, and it is not the one it looks like. Both
// dispatchers run it as plain `show version` — `case "version"` in
// pkg/cli/cli_show.go and pkg/grpcapi/server_show.go each call a no-argument
// showVersion and drop the rest — so the trailing word is NOT executed as
// `show configuration`. The hazard is the reverse: the authorizer decides on
// the JOINED canonical string, so it judged three words while the box ran two.
// An operator's anchored deny therefore missed. The end-to-end demonstration
// lives in pkg/cli (TestAnchoredDenySurvivesATrailingSibling8289); this file
// pins the canonicalization it rests on.
func TestCanonicalizeRefusesTrailingSiblingAfterLeaf8289(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want CanonicalizeResult
		why  string
	}{
		// The defect.
		{"sibling after a leaf", []string{"show", "version", "configuration"}, CanonicalUnknown,
			"`configuration` is a sibling of `version`, not a child of it"},
		{"another sibling after the same leaf", []string{"show", "version", "interfaces"}, CanonicalUnknown,
			"the defect is the parent map staying current, so ANY sibling took it"},

		// THE CONTROLS. These are the rows that fail if the fix is merely
		// stricter rather than aimed. A command whose next word is legitimately
		// consumed — a typed leaf's value, a placeholder, a real child — must
		// still canonicalize, because a caller MUST fail closed on anything
		// other than CanonicalOK, so an over-rejection here REFUSES a lawful
		// command for every operator with a restricted login class.
		{"the leaf alone", []string{"show", "version"}, CanonicalOK, "the prefix must still resolve"},
		{"the sibling on its own", []string{"show", "configuration"}, CanonicalOK,
			"`show configuration` is a real command; only the TRAILING position was wrong"},
		{"value after a value-taking node", []string{"ping", "10.0.0.1"}, CanonicalOK,
			"a value slot must still consume the next word"},
		{"interface value", []string{"show", "interfaces", "ge-0/0/0"}, CanonicalOK,
			"an interface name is a value, not a sibling keyword"},
		{"value deeper in", []string{"monitor", "traffic", "interface", "ge-0/0/0"}, CanonicalOK,
			"the value arm must survive at depth, not only at depth 2"},
		{"ordinary two-word command", []string{"show", "route"}, CanonicalOK, ""},
		{"ordinary three-word command", []string{"show", "security", "policies"}, CanonicalOK,
			"a genuine CHILD must still be descended into"},
		{"request path", []string{"request", "system", "reboot"}, CanonicalOK, ""},
		{"show system users", []string{"show", "system", "users"}, CanonicalOK, ""},

		// Pre-existing, unchanged by this fix — measured on master before and
		// after. Listed so a future reader does not attribute them here.
		{"already-unknown deep path", []string{"show", "version", "system", "zeroize"}, CanonicalUnknown,
			"rejected on master too; the control that the function was never accepting everything"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, res := Canonicalize(OperationalTree, tc.in)
			if res != tc.want {
				t.Fatalf("Canonicalize(%v) = %v, want %v. %s", tc.in, res, tc.want, tc.why)
			}
		})
	}
}
