package cmdtree

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7172 cut 1 — canonical command spelling.
//
// The point of these cells is a bypass, not a formatting nicety: a deny regex
// is written against one spelling and Junos accepts many, so without
// canonicalization `req sys reb` walks past a deny on `request system reboot`.

func TestCanonicalizeExpandsUniquePrefixes7172(t *testing.T) {
	got, res := Canonicalize(OperationalTree, []string{"req", "sys", "reb"})
	if res != CanonicalOK {
		t.Fatalf("expected CanonicalOK, got %v (words %v)", res, got)
	}
	want := []string{"request", "system", "reboot"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("abbreviated command did not expand.\n got %v\nwant %v\n"+
			"This is the bypass the function exists to close: a deny regex written "+
			"against %q must also catch %q.", got, want, "request system reboot", "req sys reb")
	}
}

// An already-canonical command must be unchanged — otherwise canonicalization
// is not idempotent and two consumers can disagree about the same input.
func TestCanonicalizeIsIdempotent7172(t *testing.T) {
	once, res := Canonicalize(OperationalTree, []string{"request", "system", "reboot"})
	if res != CanonicalOK {
		t.Fatalf("canonical input failed to canonicalize: %v", res)
	}
	twice, res2 := Canonicalize(OperationalTree, once)
	if res2 != CanonicalOK || !reflect.DeepEqual(once, twice) {
		t.Fatalf("not idempotent: %v -> %v (%v)", once, twice, res2)
	}
}

// AMBIGUITY AND ABSENCE ARE DIFFERENT, and neither may return OK. A caller that
// cannot canonicalize does not know what command it holds, so it cannot know a
// deny regex fails to match it.
//
// Both arms are asserted against REAL tree contents rather than a skip: "c" is
// a prefix of both `configure` and `clear`, "t" of both `test` and
// `traceroute`. An earlier version of this cell had a t.Skip branch and never
// exercised CanonicalAmbiguous at all — the distinction was named in the type
// and bound by nothing, which is the same gap that let a mutation escape in
// cut 2.
func TestCanonicalizeFailuresAreDistinguishedAndNeverOK7172(t *testing.T) {
	for _, tc := range []struct {
		name  string
		words []string
		want  CanonicalizeResult
	}{
		{"ambiguous configure/clear", []string{"c"}, CanonicalAmbiguous},
		{"ambiguous test/traceroute", []string{"t"}, CanonicalAmbiguous},
		{"unknown top-level word", []string{"zzzznotacommand"}, CanonicalUnknown},

		// THE DISCRIMINATING FIXTURE for the input-unchanged property, and the
		// reason it is here: every case above fails on the FIRST word, where
		// the partially-built output and the input are trivially identical, so
		// none of them can tell "return the input" from "return whatever was
		// rewritten so far". A mutation swapping one for the other escaped the
		// first matrix on exactly that.
		//
		// This one fails at word 1, AFTER "req" has already been resolved to
		// "request" in the working slice. Returning that slice would hand the
		// caller `[request zzzznotasub]` — a spelling the operator never typed
		// and the tree never accepted.
		{"failure after a successful expansion", []string{"req", "zzzznotasub"},
			CanonicalUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, res := Canonicalize(OperationalTree, tc.words)
			if res == CanonicalOK {
				t.Fatalf("returned OK for %v — a caller would then match a deny regex "+
					"against a command it never resolved, and a non-match reads as "+
					"\"allowed\"", tc.words)
			}
			if res != tc.want {
				t.Errorf("result = %v, want %v: ambiguity and absence are different "+
					"operator errors and a caller may want to report them differently",
					res, tc.want)
			}
			// On failure the input must come back UNCHANGED — a partially
			// canonicalized line is a third spelling nobody authorized.
			if !reflect.DeepEqual(got, tc.words) {
				t.Errorf("on failure the input must be returned unchanged, got %v want %v",
					got, tc.words)
			}
		})
	}
}

// A unique prefix is NOT ambiguous — the positive control. Without it, an
// implementation that returned CanonicalAmbiguous for everything would satisfy
// the cell above.
func TestUniquePrefixIsNotTreatedAsAmbiguous7172(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"s", "show"},
		{"re", "request"},
	} {
		got, res := Canonicalize(OperationalTree, []string{tc.in})
		if res != CanonicalOK {
			t.Fatalf("%q is a unique prefix and must resolve, got %v", tc.in, res)
		}
		if got[0] != tc.want {
			t.Errorf("%q -> %q, want %q", tc.in, got[0], tc.want)
		}
	}
}

// Value slots keep the raw word: they are operator data, not keywords, and
// rewriting them would change the command.
func TestCanonicalizeLeavesValueSlotsAlone7172(t *testing.T) {
	// `ping <host>` — the host is a placeholder/value, not a keyword.
	got, res := Canonicalize(OperationalTree, []string{"pin", "10.0.0.1"})
	if res != CanonicalOK {
		t.Fatalf("expected OK, got %v (%v)", res, got)
	}
	if got[0] != "ping" {
		t.Errorf("keyword slot must canonicalize: got %q", got[0])
	}
	if got[1] != "10.0.0.1" {
		t.Errorf("value slot must keep the raw word, got %q — rewriting operator data "+
			"changes the command being authorized", got[1])
	}
}

// THE AGREEMENT, pinned rather than assumed (#7172).
//
// The interactive dispatcher resolves its top-level word against a FLAT list
// (pkg/cli's operationalCommands) while canonicalization walks THIS tree. They
// agree today — both hold the same ten names — and nothing asserted it. A
// command present in one and not the other is a gap where the authorization
// gate cannot canonicalize what the dispatcher will happily run, which is the
// bypass in a different costume.
//
// Pinned HERE, in cmdtree, because cmdtree is the SSOT and pkg/cli imports it;
// the reverse import does not exist. The literal list is duplicated from
// pkg/cli/cli_dispatch.go deliberately — this is an agreement assertion, and
// importing the value from one side would make it agree with itself.
func TestOperationalTreeMatchesTheDispatcherTopLevelList7172(t *testing.T) {
	dispatcherList := []string{
		"configure", "show", "clear", "ping", "test", "traceroute",
		"monitor", "request", "quit", "exit",
	}
	tree := map[string]bool{}
	for _, k := range KeysOf(OperationalTree) {
		tree[k] = true
	}
	disp := map[string]bool{}
	for _, k := range dispatcherList {
		disp[k] = true
	}
	for k := range tree {
		if !disp[k] {
			t.Errorf("%q is in OperationalTree but NOT in pkg/cli's operationalCommands: "+
				"canonicalization can resolve it while the dispatcher rejects it", k)
		}
	}
	for k := range disp {
		if !tree[k] {
			t.Errorf("%q is in pkg/cli's operationalCommands but NOT in OperationalTree: "+
				"the dispatcher will run it and Canonicalize cannot resolve it, so an "+
				"authorization gate has no canonical spelling to match a deny against", k)
		}
	}
}

// The DYNAMIC value slot, bound separately from the placeholder one.
//
// `ping <host>` takes the PLACEHOLDER branch, so the dynamic branch was
// unexercised and a mutation rewriting dynamic values escaped. They are
// different code paths with the same contract, and a fixture for one says
// nothing about the other — the second time in this cut that a distinction was
// named and left unbound.
//
// Built on a synthetic tree rather than hunting a real command with a dynamic
// child: Canonicalize takes the tree as a parameter, so a purpose-built tree is
// a legitimate production-shaped input and pins the branch without depending on
// which real commands happen to use providers today.
func TestCanonicalizeLeavesDynamicValueSlotsAlone7172(t *testing.T) {
	tree := map[string]*Node{
		"showroute": {
			Desc: "synthetic",
			Children: map[string]*Node{
				"table": {
					Desc: "routing table",
					// A provider-backed value slot.
					DynamicFn: func(*config.Config) []string {
						return []string{"inet.0", "inet6.0"}
					},
				},
			},
		},
	}
	got, res := Canonicalize(tree, []string{"showroute", "tab", "inet.0"})
	if res != CanonicalOK {
		t.Fatalf("expected OK, got %v (%v)", res, got)
	}
	if got[1] != "table" {
		t.Errorf("the keyword slot must canonicalize: got %q want %q", got[1], "table")
	}
	if got[2] != "inet.0" {
		t.Errorf("a DYNAMIC value slot must keep the raw word, got %q. Rewriting a "+
			"provider-backed value changes the command being authorized, exactly as "+
			"rewriting a placeholder would.", got[2])
	}
}
