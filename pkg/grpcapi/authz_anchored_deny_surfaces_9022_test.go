package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// #9022: THE TWO SURFACES NOW AGREE FOR AN ANCHORED RULE OVER AN AcceptsArgs
// NODE, and this cell asserts the agreement rather than each side separately.
//
// Before the fix an operator got DIFFERENT answers depending on where they
// tested a deny rule:
//
//	remote (ShowText topic "log")  -> "show log"      anchored ^show log$ DENIES
//	local  (`show log 100`)        -> "show log 100"  anchored ^show log$ ALLOWS
//
// The remote side was already correct — showTextTopicCommand's values are
// argument-free by construction. The local side matched the full canonical
// line including arguments, so `$` stopped matching. An operator who verified
// their rule over the remote CLI would have concluded it worked.
//
// authz_command_table_topics.go scoped its "matches identically on both
// surfaces" claim to PARTIAL matching, which was the honest scope at the time.
// The anchored direction now holds too, and this is what keeps that true.
func TestAnchoredDenyAgreesAcrossSurfaces9022(t *testing.T) {
	const deny = "^show log$"
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, deny, true)
	if err != nil {
		t.Fatalf("CompileLoginRegexes(%q): %v", deny, err)
	}

	// REMOTE: the topic table's argument-free canonical command.
	remoteCmd, ok := showTextTopicCommand["log"]
	if !ok {
		t.Fatal("fixture: no ShowText topic \"log\" — this cell no longer measures the surface it names")
	}
	if d := rules.Evaluate(remoteCmd); d.Allowed {
		t.Errorf("REMOTE surface allowed %q under deny %q", remoteCmd, deny)
	}

	// LOCAL: the full canonical line plus the argument-free command prefix,
	// exactly as evaluateCommandRegex now supplies them.
	for _, line := range [][]string{
		{"show", "log"},
		{"show", "log", "100"},
		{"show", "log", "messages"},
	} {
		canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, line)
		if res != cmdtree.CanonicalOK {
			t.Fatalf("fixture: %v did not canonicalize (res=%v)", line, res)
		}
		full := join9022(canon)
		prefix := keywordPrefix9022(canon)
		if d := rules.EvaluateForms(full, prefix); d.Allowed {
			t.Errorf("LOCAL surface allowed %q (prefix %q) under deny %q — the surfaces "+
				"disagree, so an operator who verified this rule remotely would be wrong "+
				"about the console (#9022)", full, prefix, deny)
		}
	}
}

func join9022(canon []string) string {
	out := ""
	for i, w := range canon {
		if i > 0 {
			out += " "
		}
		out += w
	}
	return out
}

// keywordPrefix9022 mirrors pkg/cli's canonicalPrefix. Duplicated rather than
// imported because pkg/cli is not importable from here; the two are pinned to
// agree by this cell failing if they diverge in a way that changes the verdict.
func keywordPrefix9022(canon []string) string {
	keep := make([]string, 0, len(canon))
	current := cmdtree.OperationalTree
	for _, w := range canon {
		node, ok := current[w]
		if !ok {
			break
		}
		keep = append(keep, w)
		if node.Children == nil {
			break
		}
		current = node.Children
	}
	return join9022(keep)
}
