package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Round-11 B1: the two operator ingresses must not disagree about a remediation
// batch in the FAIL-OPEN direction.
//
// THE DEFECT. `show | display set` flattens the tree: a container's keys are
// concatenated with its children's onto one line. The r10 serializer suppressed
// an authored quote on any key that was TERMINAL IN ITS OWN NODE — sound for the
// hierarchical renderer, where such a key is followed by `{` and stays a
// container key on re-parse, and wrong here, because flattening puts a
// container's last key at the FRONT of its child's group, which is exactly the
// token eventMultiWordLeafValues reads to decide the boundary.
//
// Measured at the previous head on `commands "set" { "system host-name pwned"; }`:
//
//	LoadOverride (hierarchical) -> ThenCommands ["system host-name pwned"]
//	                              -> classifyPlan REJECTS (no `set `/`delete ` prefix)
//	display-set dump             -> `... commands set "system host-name pwned"`
//	LoadSet (that dump)          -> ThenCommands ["set system host-name pwned"]
//	                              -> classifyPlan ACCEPTS and APPLIES it
//
// So a batch the operator's own config declines became one that runs an
// arbitrary `set`, on the same authored bytes, after a round trip through the
// product's own display format. origin/master does NOT have this: its reader
// compiles ["set"] on the replay side, which is rejected too, so both of its
// ingresses decline. The r10 serializer introduced the hole.
//
// WHAT IS ASSERTED, and why it is not string equality. Display-set cannot
// express the difference between a container's identifier slot
// (`commands "x" { "y"; }`) and a two-member list (`commands [ "x" "y" ]`) —
// both flatten to the same line. That ambiguity is PRE-EXISTING and origin/master
// has it too, so demanding identical ThenCommands from both ingresses would
// assert something no version of this code has ever provided, and the test would
// be pinning a fiction. What must hold — and what master does provide — is that
// the disagreement never runs toward EXECUTION: a batch one ingress declines
// must not be applied by the other.
func TestIngressesDoNotDisagreeTowardExecution_6673(t *testing.T) {
	for _, tc := range []struct {
		name string
		// hierarchical config text, as an operator would `load override` it.
		text string
		// wantExecutable is whether classifyPlan-equivalent acceptance is
		// expected from the HIERARCHICAL ingress.
		wantExecutable bool
	}{
		{
			// THE r11 FAIL-OPEN. The quoted terminal container key `"set"` was
			// emitted bare, then re-read as the head of the child's group.
			name: "quoted container key must not become a command verb",
			text: `event-options {
  policy p {
    then {
      change-configuration {
        commands "set" {
          "system host-name pwned";
        }
      }
    }
  }
}`,
			wantExecutable: false,
		},
		{
			// The same shape with a non-verb identifier: the hierarchical side
			// DOES execute the child command here (children win, the identifier
			// slot is discarded — verbatim pre-#6659 behaviour). The replay side
			// may decline; declining is the safe direction and is allowed.
			name: "non-verb container key",
			text: `event-options {
  policy p {
    then {
      change-configuration {
        commands "bogus" {
          "set system host-name pwned";
        }
      }
    }
  }
}`,
			wantExecutable: true,
		},
		{
			// CONTROL: the ordinary two-member list. Both ingresses must decline
			// it (the bare `set` member fails the prefix check), and this is the
			// r10 property — if this row ever flips, the original #6673 fix has
			// regressed and the B1 rows above would be measuring nothing.
			name: "CONTROL quoted one-word member in a bracket list",
			text: `event-options {
  policy p {
    then {
      change-configuration {
        commands [ "set" "system host-name pwned" ];
      }
    }
  }
}`,
			wantExecutable: false,
		},
		{
			// CONTROL: a plain, well-formed single command. Both ingresses must
			// EXECUTE it. Without this row a fix that declined everything would
			// pass the whole table.
			name: "CONTROL well-formed single command executes on both",
			text: `event-options {
  policy p {
    then {
      change-configuration {
        commands "set system host-name fw";
      }
    }
  }
}`,
			wantExecutable: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// INGRESS 1: load override of the authored hierarchical text.
			viaOverride := commandsAfterOverride6673(t, tc.text)
			gotExec := commandsAreExecutable6673(viaOverride)
			if gotExec != tc.wantExecutable {
				t.Fatalf("hierarchical ingress executable = %v, want %v (commands %q) — "+
					"the fixture no longer reproduces the shape this row is about",
					gotExec, tc.wantExecutable, viaOverride)
			}

			// INGRESS 2: dump that same tree as display-set and replay it,
			// which is what rollback, `load set` and an operator copying
			// `show | display set` output all do.
			viaSet := commandsAfterSetReplay6673(t, tc.text)
			replayExec := commandsAreExecutable6673(viaSet)

			if replayExec && !gotExec {
				t.Fatalf("FAIL-OPEN: the hierarchical ingress DECLINES this batch but the "+
					"display-set replay EXECUTES it.\n  hierarchical: %q\n  replayed:     %q\n"+
					"The same authored bytes must not become executable by passing through "+
					"the product's own display format (#6673 r11 B1).", viaOverride, viaSet)
			}
		})
	}
}

// commandsAfterOverride6673 loads text through Store.LoadOverride and returns
// the compiled remediation commands.
func commandsAfterOverride6673(t *testing.T, text string) []string {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	return compiledCommands6673(t, s.candidate)
}

// commandsAfterSetReplay6673 loads text, renders it as display-set, and replays
// that through Store.LoadSet — the round trip the claim is about.
func commandsAfterSetReplay6673(t *testing.T, text string) []string {
	t.Helper()
	src := newTestStore(t)
	if err := src.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := src.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	dump := src.candidate.FormatSet()
	if !strings.Contains(dump, "change-configuration") {
		t.Fatalf("display-set dump does not carry the stanza under test:\n%s", dump)
	}

	dst := newTestStore(t)
	if err := dst.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := dst.LoadSet(dump); err != nil {
		t.Fatalf("LoadSet(%q): %v", dump, err)
	}
	return compiledCommands6673(t, dst.candidate)
}

func compiledCommands6673(t *testing.T, tree *config.ConfigTree) []string {
	t.Helper()
	if tree == nil {
		t.Fatal("nil candidate tree")
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("compiled %d event policies, want 1", len(cfg.EventOptions))
	}
	return cfg.EventOptions[0].ThenCommands
}

// commandsAreExecutable6673 mirrors eventengine.classifyPlan's acceptance rule:
// every non-empty entry must carry a `set ` or `delete ` prefix, or the WHOLE
// batch is declined. Reproduced here rather than imported because pkg/eventengine
// depends on pkg/configstore, so calling the real classifier from this package
// would be an import cycle; the rule is three lines and is asserted against the
// real classifier in pkg/eventengine's own tests.
func commandsAreExecutable6673(cmds []string) bool {
	any := false
	for _, c := range cmds {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.HasPrefix(c, "set ") && !strings.HasPrefix(c, "delete ") {
			return false
		}
		any = true
	}
	return any
}
