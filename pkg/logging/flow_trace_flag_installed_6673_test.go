package logging

import (
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Round-9 decision record for `security flow traceoptions flag`, pinned at the
// consumer instead of the compiler.
//
// THE DECISION. The leaf installs EVERY NON-EMPTY flag the operator authored,
// in every slot, independently of position. An empty token is not a flag: it
// contributes nothing, it does not suppress the flags authored beside it, and it
// does not re-enable the writer's defaults.
//
// WHY. Before #6659 the compiler read this leaf with nodeVal — the FIRST slot
// only — and dropped an empty selection, so what installed depended on where in
// the list the operator happened to write things:
//
//	flag [ session basic-datapath ]   → master installed {session} only.
//	                                     The operator asked for both and got one,
//	                                     with no diagnostic. This is the bug.
//	flag [ "" session ]               → master compiled NO flags, so
//	                                     NewTraceWriter fell back to BOTH of its
//	                                     defaults {basic-datapath, session}.
//	flag [ session "" ]               → master installed {session}.
//
// The last two are the same configuration with the tokens swapped, and master
// installed different flag sets for them. That is not a designed semantic; it
// falls out of slot-0 selection. Any fix that reads the whole list necessarily
// changes what installs for a multi-slot list — that IS the fix — so the honest
// choice is between a position-dependent rule nobody designed and a
// position-independent one. This takes the latter.
//
// WHAT IS NOT DONE, and why. An empty token is NOT rejected at commit: master
// accepted `flag [ "" session ]`, and inventing a rejection for a configuration
// that already committed is the failure mode this round exists to remove
// (see the mixed-shape guards in pkg/config). The "writer defaults apply" state
// is not lost either — it remains reachable the documented way, by authoring no
// `flag` stanza, which the third case below pins.
//
// This is an operator-visible upgrade behaviour change for any config with a
// multi-slot `flag` list; it is recorded in docs/config-schema.md.
func TestFlowTraceFlags6673InstalledSetIsPositionIndependent(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag string // the traceoptions body's flag statement(s), or ""
		// wantInstalled is the flag set NewTraceWriter must end up with.
		wantInstalled []string
		// sameAsMaster records whether origin/master installed that same set.
		// The two cases where it did NOT are the deliberate change; asserting
		// the difference keeps this test from passing under a revert.
		sameAsMaster bool
	}{
		{
			name:          "empty token first, real flag second",
			flag:          `flag [ "" session ];`,
			wantInstalled: []string{"session"},
			sameAsMaster:  false, // master: {basic-datapath, session} via the defaults
		},
		{
			name:          "empty token last, real flag first",
			flag:          `flag [ session "" ];`,
			wantInstalled: []string{"session"},
			sameAsMaster:  true, // master selected slot 0 = session
		},
		{
			name:          "two real flags",
			flag:          `flag [ session basic-datapath ];`,
			wantInstalled: []string{"basic-datapath", "session"},
			sameAsMaster:  false, // master: {session} only — the #6659 bug
		},
		{
			name:          "an empty token is the ONLY value",
			flag:          `flag "";`,
			wantInstalled: []string{"basic-datapath", "session"}, // writer defaults
			sameAsMaster:  true,
		},
		{
			name:          "no flag stanza at all (the documented way to get the defaults)",
			flag:          ``,
			wantInstalled: []string{"basic-datapath", "session"},
			sameAsMaster:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			to := compileTraceoptions6673(t, tc.flag)
			got := installedTraceFlags6673(t, to)
			if !equalStrings6673(got, tc.wantInstalled) {
				t.Fatalf("installed trace flags = %v, want %v (compiled "+
					"Flags=%q).\n"+
					"`flag` installs every NON-EMPTY authored value regardless "+
					"of slot; an empty token contributes nothing and must not "+
					"suppress its neighbours or re-enable the writer defaults.",
					got, tc.wantInstalled, to.Flags)
			}

			master := installedTraceFlags6673(t, masterTraceoptions6673(t, tc.flag))
			if same := equalStrings6673(got, master); same != tc.sameAsMaster {
				t.Fatalf("installed flags %v vs origin/master's %v: same=%v, "+
					"want same=%v.\n"+
					"This case records a DELIBERATE upgrade behaviour change "+
					"(or its absence). If the widened read is reverted, the two "+
					"collapse together and this fires.", got, master, same, tc.sameAsMaster)
			}
		})
	}
}

// compileTraceoptions6673 compiles a flow traceoptions stanza carrying flagStmt
// and returns the compiled options the daemon hands to NewTraceWriter.
func compileTraceoptions6673(t *testing.T, flagStmt string) *config.FlowTraceoptions {
	t.Helper()
	tree := parseTrace6673(t, flagStmt)
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	to := cfg.Security.Flow.Traceoptions
	if to == nil {
		t.Fatal("no compiled traceoptions")
	}
	return to
}

// masterTraceoptions6673 rebuilds what origin/master's compiler produced for the
// same stanza. Master's reader was
//
//	for _, flagNode := range toNode.FindChildren("flag") {
//	    if v := nodeVal(flagNode); v != "" { to.Flags = append(to.Flags, v) }
//	}
//
// i.e. the FIRST value of each `flag` statement, empties dropped. nodeVal is
// unexported, so it is spelled out here: Keys[1] when present, else the first
// child's name.
func masterTraceoptions6673(t *testing.T, flagStmt string) *config.FlowTraceoptions {
	t.Helper()
	tree := parseTrace6673(t, flagStmt)
	toNode := traceoptionsNode6673(t, tree)
	out := &config.FlowTraceoptions{File: "flow.log"}
	if toNode == nil {
		return out
	}
	for _, fn := range toNode.FindChildren("flag") {
		v := ""
		switch {
		case len(fn.Keys) >= 2:
			v = fn.Keys[1]
		case len(fn.Children) > 0:
			v = fn.Children[0].Name()
		}
		if v != "" {
			out.Flags = append(out.Flags, v)
		}
	}
	return out
}

func parseTrace6673(t *testing.T, flagStmt string) *config.ConfigTree {
	t.Helper()
	text := "security { flow { traceoptions { file flow.log; " + flagStmt + " } } }"
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse %q: %v", text, perrs)
	}
	return tree
}

func traceoptionsNode6673(t *testing.T, tree *config.ConfigTree) *config.Node {
	t.Helper()
	for _, root := range tree.Children {
		if root.Name() != "security" {
			continue
		}
		flow := root.FindChild("flow")
		if flow == nil {
			t.Fatal("no flow node")
		}
		return flow.FindChild("traceoptions")
	}
	t.Fatal("no security root")
	return nil
}

// installedTraceFlags6673 returns the flag set NewTraceWriter actually installs,
// sorted. This is the consumer's own map — including its "no implemented flags
// specified, trace everything" fallback — not a restatement of the compiler.
func installedTraceFlags6673(t *testing.T, to *config.FlowTraceoptions) []string {
	t.Helper()
	old := traceLogDir
	traceLogDir = t.TempDir()
	defer func() { traceLogDir = old }()

	tw, err := NewTraceWriter(to)
	if err != nil {
		t.Fatalf("NewTraceWriter(%+v): %v", to, err)
	}
	defer tw.Close()

	out := make([]string, 0, len(tw.flags))
	for f, on := range tw.flags {
		if on {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings6673(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestFlowTraceFlags6673DefaultsRemainReachable states the escape hatch the
// decision above depends on in the terms an operator would search for: with no
// `flag` stanza the writer traces everything, so nothing is lost by an empty
// token no longer forcing that state.
func TestFlowTraceFlags6673DefaultsRemainReachable(t *testing.T) {
	got := installedTraceFlags6673(t, compileTraceoptions6673(t, ``))
	if !equalStrings6673(got, []string{"basic-datapath", "session"}) {
		t.Fatalf("traceoptions with no `flag` stanza installed %v, want both "+
			"writer defaults; the #6673 decision to stop letting an empty "+
			"token select the defaults relies on this remaining the documented "+
			"way to get them", got)
	}
	if strings.Join(got, ",") == "" {
		t.Fatal("unreachable")
	}
}
