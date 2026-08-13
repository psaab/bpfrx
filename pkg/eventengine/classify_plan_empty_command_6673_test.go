package eventengine

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestClassifyPlan6673SkipsAnEmptyCommand pins the fact that the #6673 rationale
// for pkg/config's eventChangeConfigCommands rests on.
//
// That reader deliberately KEEPS an authored-but-empty `then change-configuration
// commands` entry. An earlier revision justified it with a fail-closed story:
// that an empty entry made this engine decline the WHOLE remediation batch, so
// filtering it would apply the batch in part. That story is FALSE. classifyPlan
// opens with `cmd = strings.TrimSpace(cmd); if cmd == "" { continue }` and has
// since the engine's first commit, so an empty command is SKIPPED and the batch
// runs identically whether or not the compiler emits the entry.
//
// The entry is kept for OUTPUT PARITY instead — the compiled ThenCommands slice
// is hashed into policySemanticRevision and printed verbatim by
// `show event-options`, so filtering it in the compiler would silently diverge
// the persisted policy from master's without changing what the policy does.
//
// This test exists so that rationale cannot rot back to the false one unnoticed:
// if classifyPlan is ever changed to REJECT an empty command, the comments in
// pkg/config/compiler_services.go, docs/config-schema.md and the sibling guard
// in pkg/config all become wrong at once, and this fails first.
func TestClassifyPlan6673SkipsAnEmptyCommand(t *testing.T) {
	e := &Engine{}
	for _, tc := range []struct {
		name    string
		cmds    []string
		wantOK  bool
		wantOps int
	}{
		{"empty in the FIRST slot", []string{"", "set system host-name foo"}, true, 1},
		{"empty in a NON-FIRST slot", []string{"set system host-name foo", ""}, true, 1},
		{"whitespace-only entry", []string{"   ", "set system host-name foo"}, true, 1},
		{"empty is the ONLY entry", []string{""}, true, 0},
		{"no empty at all (CONTROL)", []string{"set system host-name foo"}, true, 1},
		// The genuine batch-rejection case, kept as the contrast: an
		// UNSUPPORTED command really does decline the whole plan. That is what
		// an empty entry does NOT do.
		{"unsupported command DOES decline the batch", []string{"nonsense", "set system host-name foo"}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops, ok := e.classifyPlan(&config.EventPolicy{
				Name:         "p1",
				ThenCommands: tc.cmds,
			})
			if ok != tc.wantOK {
				t.Fatalf("classifyPlan(%q) ok = %v, want %v — an empty command "+
					"must be SKIPPED, not treated as a batch-rejecting entry; "+
					"the #6673 comments in pkg/config depend on this",
					tc.cmds, ok, tc.wantOK)
			}
			if len(ops) != tc.wantOps {
				t.Fatalf("classifyPlan(%q) produced %d ops, want %d — the empty "+
					"entry must contribute no operation while leaving the rest "+
					"of the batch intact", tc.cmds, len(ops), tc.wantOps)
			}
		})
	}
}

// TestPolicySemanticRevision6673EmptyCommandIsObservable pins the other half of
// that rationale: the empty entry is inert at EXECUTION but not invisible.
//
// policySemanticRevision hashes every ThenCommands entry, so a policy carrying
// an authored blank is a DIFFERENT policy from one that does not — which is
// exactly why the compiler must report the blank rather than deciding it away.
// If this stopped holding, "output parity" would no longer be a reason to keep
// the entry and the pkg/config comments would need rewriting again.
func TestPolicySemanticRevision6673EmptyCommandIsObservable(t *testing.T) {
	with := policySemanticRevision(&config.EventPolicy{
		Name:         "p1",
		Events:       []string{"e1"},
		ThenCommands: []string{"", "set system host-name foo"},
	})
	without := policySemanticRevision(&config.EventPolicy{
		Name:         "p1",
		Events:       []string{"e1"},
		ThenCommands: []string{"set system host-name foo"},
	})
	if with == without {
		t.Fatal("policySemanticRevision is blind to an authored-empty command; " +
			"the #6673 output-parity rationale for keeping it in " +
			"pkg/config/compiler_services.go rests on this difference")
	}
}
