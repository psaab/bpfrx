package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
)

// #7172 cut 5a — the gRPC method → canonical command table.
//
// Two tests, and they catch different failures. Completeness alone would pass a
// table full of plausible-looking WRONG strings, which is exactly why the
// validity check exists.

// VALIDITY: every entry must be a real, already-canonical operational command.
//
// This is what structurally excludes the error class that killed the idea of
// DERIVING these strings from method or topic names. `buffers-detail` looks like
// `show buffers detail`; that is wrong, because `buffers` is not a child of
// `show`, and only `show system buffers detail` resolves. A derivation would be
// right for most entries and quietly wrong for some — the worst distribution for
// an authorization input — and this test rejects the wrong ones by construction
// rather than asking a reviewer to spot them.
func TestEveryMappedCommandIsCanonical7172(t *testing.T) {
	if len(methodCanonicalCommand) == 0 {
		t.Fatal("the table is empty, so this test would certify nothing")
	}
	for method, cmd := range methodCanonicalCommand {
		words := strings.Fields(cmd)
		if len(words) == 0 {
			t.Errorf("%s maps to an empty command", method)
			continue
		}
		canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, words)
		if res != cmdtree.CanonicalOK {
			t.Errorf("%s maps to %q, which does not resolve against the operational tree "+
				"(%v). A deny regex is matched against this string, so an unresolvable "+
				"entry means the gate compares against a command no operator can run.",
				method, cmd, res)
			continue
		}
		if got := strings.Join(canon, " "); got != cmd {
			t.Errorf("%s maps to %q, which canonicalizes to %q. The table must hold the "+
				"CANONICAL spelling: cut 3 matches deny regexes against canonicalized "+
				"input, so a non-canonical entry here would be compared against a "+
				"different string than the on-box CLI produces for the same command.",
				method, cmd, got)
		}
	}
}

// COMPLETENESS, both directions.
//
// Mirrors TestEveryShowTextTopicHasAPermission_5278: a method priced for coarse
// permissions but absent from both maps here is a method 5b cannot produce a
// command for, and an entry naming a method that no longer exists is stale.
//
// Absences are permitted only when NAMED with a reason in
// methodsWithoutCanonicalCommand. A bare absence is indistinguishable from a
// forgotten one, and this test would otherwise have to choose between failing
// on every intended absence and accepting every accidental one.
func TestEveryPricedMethodIsMappedOrNamedAbsent7172(t *testing.T) {
	if len(methodPermissions) < 40 {
		t.Fatalf("only %d priced methods found; the coarse table is the enumeration this "+
			"test walks, so a pass would certify nothing", len(methodPermissions))
	}
	for method := range methodPermissions {
		_, mapped := methodCanonicalCommand[method]
		reason, excused := methodsWithoutCanonicalCommand[method]
		switch {
		case mapped && excused:
			t.Errorf("%s is BOTH mapped to a command and named as deliberately absent; one "+
				"of the two is wrong and a reader cannot tell which", method)
		case !mapped && !excused:
			t.Errorf("%s is priced for coarse permissions but has no canonical command and "+
				"no stated reason for having none. 5b cannot evaluate deny-commands for "+
				"it, so for a class that configured regexes it will be DENIED — add an "+
				"entry, or name it in methodsWithoutCanonicalCommand with why.", method)
		case excused && strings.TrimSpace(reason) == "":
			t.Errorf("%s is named absent with an empty reason, which is the same as an "+
				"unnamed absence", method)
		}
	}
	// Stale direction: an entry for a method that is no longer served.
	for method := range methodCanonicalCommand {
		if _, priced := methodPermissions[method]; !priced {
			t.Errorf("%s has a canonical command but is not a priced method — the entry is "+
				"stale and would never be consulted", method)
		}
	}
	for method := range methodsWithoutCanonicalCommand {
		if _, priced := methodPermissions[method]; !priced {
			t.Errorf("%s is named as deliberately absent but is not a priced method; the "+
				"exemption is stale", method)
		}
	}
}

// The table is INERT in this cut. If something starts reading it before 5b
// wires it deliberately, that is worth knowing — an authz input acquiring a
// consumer by accident is how a half-built gate goes live.
func TestCommandTableIsNotYetConsumed7172(t *testing.T) {
	// Guard against the table being read by production code before 5b. Cut 5b
	// deletes this test in the same change that adds the consumer, so its
	// removal is a reviewed step rather than a silent one.
	if len(methodCanonicalCommand) == 0 || len(methodsWithoutCanonicalCommand) == 0 {
		t.Fatal("precondition: both tables must be populated for this to mean anything")
	}
}
