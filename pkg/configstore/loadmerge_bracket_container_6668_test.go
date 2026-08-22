package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6668 — the INGEST half. `load merge <hierarchical-file>` does not merge the
// parsed tree; the hierarchical branch of LoadMergeAs renders it with
// FormatSet and replays the flat lines through applyEditLine. So an authoring
// shape that FormatSet could not spell was rewritten INSIDE the daemon, on a
// path reachable from the CLI (`load merge`), gRPC (LoadConfig) and REST, with
// the merge reported successful and every token still present.
//
// The corrupting shape is a bracket list at a CONTAINER position: a zone's
// `interfaces [ a b ] { host-inbound-traffic { ... } }` is ONE node with two
// keys, and the flat replay re-split it at the schema arity — `a` stayed the
// container and `b` was demoted to the first key of a LEAF with the whole body
// re-parented under it.
//
// `load override` is NOT affected (it installs the parse tree directly), and HA
// config sync is NOT affected (it ships Format(), whose `{` terminates the key
// list). This test therefore pins the merge path specifically, and pins the
// override path beside it as the control — if the two ever disagree again, the
// control says which one moved.

const bracketedZoneMergeFile6668 = `
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.2.1/24; } } }
}
security {
    zones {
        security-zone trust {
            interfaces {
                [ ge-0/0/0 ge-0/0/1 ] {
                    host-inbound-traffic {
                        system-services ssh;
                    }
                }
            }
        }
    }
}
`

// candidateHasIntactMemberPair reports whether the candidate still holds the
// authored two-member container rather than the demoted `a { b ... }` shape.
func candidateHasIntactMemberPair(t *testing.T, s *Store) (intact bool, got string) {
	t.Helper()
	setText := s.ShowCandidateSet()
	return strings.Contains(setText,
			"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ] host-inbound-traffic system-services ssh"),
		setText
}

// TestLoadMergeHierarchicalKeepsTheAuthoredMemberGroup_6668 is the regression.
// It is RED on revert: the pre-fix replay produces
// `... interfaces ge-0/0/0 ge-0/0/1 host-inbound-traffic system-services ssh`
// with `ge-0/0/1` as a leaf keyword, so the assertion on the member group trips
// and the compile check below reports the zone referencing an interface named
// "host-inbound-traffic".
func TestLoadMergeHierarchicalKeepsTheAuthoredMemberGroup_6668(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadMerge(bracketedZoneMergeFile6668); err != nil {
		t.Fatalf("LoadMerge: %v", err)
	}
	intact, got := candidateHasIntactMemberPair(t, s)
	if !intact {
		t.Fatalf("load merge rewrote the candidate; the authored member group is gone:\n%s", got)
	}

	// The corruption was not merely a shape change: the rewritten candidate is
	// a different config, and on this shape it does not commit. Assert the
	// merged candidate still COMPILES, and that both members carry the
	// host-inbound the operator wrote for them.
	tree, errs := config.NewParser(s.ShowCandidate()).Parse()
	if len(errs) > 0 {
		t.Fatalf("merged candidate does not re-parse: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("merged candidate does not compile: %v", err)
	}
	zone := cfg.Security.Zones["trust"]
	if zone == nil {
		t.Fatalf("merged config has no trust zone")
	}
	if len(zone.Interfaces) != 2 {
		t.Fatalf("trust zone members = %v, want both ge-0/0/0 and ge-0/0/1", zone.Interfaces)
	}
}

// TestLoadMergeAndLoadOverrideAgree_6668 is the control. LoadOverride installs
// the parse tree directly and never round-trips through FormatSet, so it was
// correct before this fix and must stay correct after it. Comparing the two
// paths on the same input is what makes the merge assertion above a statement
// about the ROUND TRIP rather than about this particular fixture: if both sides
// move together, the fixture changed; if only merge moves, the replay did.
func TestLoadMergeAndLoadOverrideAgree_6668(t *testing.T) {
	merged := newTestStore(t)
	if err := merged.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := merged.LoadMerge(bracketedZoneMergeFile6668); err != nil {
		t.Fatalf("LoadMerge: %v", err)
	}

	overridden := newTestStore(t)
	if err := overridden.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := overridden.LoadOverride(bracketedZoneMergeFile6668); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}

	if a, b := merged.ShowCandidateSet(), overridden.ShowCandidateSet(); a != b {
		t.Errorf("load merge and load override disagree on the same file\n--- merge ---\n%s\n--- override ---\n%s", a, b)
	}
}

// TestLoadSetReplayOfDisplaySetIsIdentity_6668 closes the operator-mediated
// loop: dump a config with `show | display set`, feed it back with `load set`,
// and the candidate must be the one you dumped. This is the workflow the issue
// names — copying a display-set dump to rebuild a box or seed a second one.
func TestLoadSetReplayOfDisplaySetIsIdentity_6668(t *testing.T) {
	src := newTestStore(t)
	if err := src.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := src.LoadOverride(bracketedZoneMergeFile6668); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	dump := src.ShowCandidateSet()

	dst := newTestStore(t)
	if err := dst.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	n, err := dst.LoadSet(dump)
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if n == 0 {
		t.Fatalf("LoadSet applied no lines")
	}
	if got := dst.ShowCandidateSet(); got != dump {
		t.Errorf("display-set dump did not replay to itself\n--- dumped ---\n%s\n--- replayed ---\n%s", dump, got)
	}
}
