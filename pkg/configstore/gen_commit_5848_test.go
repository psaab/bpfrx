// #5848: candidate preflight and promotion were two separately-locked store
// ops, so a concurrent REST/CLI candidate edit could land between them and the
// daemon would promote a candidate it never examined (device-map management-
// lockout bypass). The generation-bound commit transaction closes this: every
// candidate change bumps candidateGen; CompileCandidateGen snapshots the
// (compiled, generation) pair atomically; CommitWithDescriptionGen /
// CommitConfirmedGen promote ONLY if the generation is unchanged, else return
// ErrCandidateGenerationConflict without mutating state.
//
// FAIL-ON-REVERT: dropping the `s.candidateGen != expectedGen` check in
// CommitWithDescriptionGen / CommitConfirmedGen makes the stale-generation
// commit silently promote the unexamined C2 — the conflict tests then get a nil
// error and an active config carrying "c2", flipping both assertions RED.
package configstore

import (
	"errors"
	"strings"
	"testing"
)

func genStoreInConfig(t *testing.T, host string) *Store {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name " + host); err != nil {
		t.Fatalf("seed set: %v", err)
	}
	return s
}

// A commit bound to a stale generation (the candidate changed after the
// snapshot) must CONFLICT and promote NOTHING — the examined generation is not
// the promoted generation.
func TestCommitWithDescriptionGenConflictDoesNotPromote(t *testing.T) {
	s := genStoreInConfig(t, "c1")

	// Snapshot the generation the daemon would pre-flight (C1).
	compiled, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if compiled == nil {
		t.Fatalf("CompileCandidateGen returned nil compiled for a valid candidate")
	}

	// Concurrent edit lands between pre-flight and promote: candidate -> C2,
	// generation advances past the snapshot.
	if err := s.SetFromInput("system host-name c2"); err != nil {
		t.Fatalf("concurrent mutate: %v", err)
	}

	_, err = s.CommitWithDescriptionGen("desc", gen)
	if !errors.Is(err, ErrCandidateGenerationConflict) {
		t.Fatalf("stale-generation commit: err=%v, want ErrCandidateGenerationConflict", err)
	}
	// C2 was NEVER examined; it must not have been promoted.
	if active := s.ShowActiveSet(); strings.Contains(active, "host-name c2") {
		t.Fatalf("conflicting commit promoted the unexamined candidate C2; active=%q", active)
	}
}

// The generation is authoritative over CONTENT: a candidate edited and then
// reverted to byte-identical content still carries a NEW generation, so a commit
// bound to the original generation conflicts (the conservative, safe choice —
// the examined generation is gone even though the bytes match).
func TestCommitGenConflictOnChangeAndRevertToIdentical(t *testing.T) {
	s := genStoreInConfig(t, "c1")
	before := s.ShowCandidateSet()

	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}

	// Change away and back to byte-identical content.
	if err := s.SetFromInput("system host-name c2"); err != nil {
		t.Fatalf("edit away: %v", err)
	}
	if err := s.DeleteFromInput("system host-name c2"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.SetFromInput("system host-name c1"); err != nil {
		t.Fatalf("edit back: %v", err)
	}
	if now := s.ShowCandidateSet(); now != before {
		t.Fatalf("test setup: candidate not restored to identical content\nbefore=%q\nnow=%q", before, now)
	}

	if _, err := s.CommitWithDescriptionGen("desc", gen); !errors.Is(err, ErrCandidateGenerationConflict) {
		t.Fatalf("change-and-revert commit: err=%v, want ErrCandidateGenerationConflict (generation is authoritative)", err)
	}
}

// A commit bound to the CURRENT generation (no intervening edit) promotes
// exactly the prepared candidate — the pre-#5848 success path is preserved.
func TestCommitWithDescriptionGenSucceedsWhenUnchanged(t *testing.T) {
	s := genStoreInConfig(t, "c1")

	compiled, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}

	promoted, err := s.CommitWithDescriptionGen("desc", gen)
	if err != nil {
		t.Fatalf("in-generation commit failed: %v", err)
	}
	if promoted == nil {
		t.Fatalf("commit returned nil compiled")
	}
	if promoted != compiled {
		// Both compile the same unchanged candidate; they need not be the same
		// pointer, but the promoted active must carry C1.
		t.Logf("note: compiled snapshot and promoted config are distinct objects (expected)")
	}
	if active := s.ShowActiveSet(); !strings.Contains(active, "host-name c1") {
		t.Fatalf("in-generation commit did not promote C1; active=%q", active)
	}
}

// Two commits cannot both promote against ONE prepared generation: the first
// consumes it (bumping the generation on the post-commit candidate reset), so a
// replayed commit bound to the same generation conflicts.
func TestCommitGenCannotDoublePromote(t *testing.T) {
	s := genStoreInConfig(t, "c1")

	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if _, err := s.CommitWithDescriptionGen("first", gen); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if _, err := s.CommitWithDescriptionGen("second", gen); !errors.Is(err, ErrCandidateGenerationConflict) {
		t.Fatalf("replayed commit on a consumed generation: err=%v, want ErrCandidateGenerationConflict", err)
	}
}

// Commit-confirmed honors the same generation binding.
func TestCommitConfirmedGenConflictDoesNotPromote(t *testing.T) {
	s := genStoreInConfig(t, "c1")

	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if err := s.SetFromInput("system host-name c2"); err != nil {
		t.Fatalf("concurrent mutate: %v", err)
	}

	if _, err := s.CommitConfirmedGen(5, gen); !errors.Is(err, ErrCandidateGenerationConflict) {
		t.Fatalf("stale-generation commit-confirmed: err=%v, want ErrCandidateGenerationConflict", err)
	}
	if active := s.ShowActiveSet(); strings.Contains(active, "host-name c2") {
		t.Fatalf("conflicting commit-confirmed promoted the unexamined candidate C2; active=%q", active)
	}
	// Cancel any (should-be-absent) confirm timer to avoid a background rollback.
	_ = s.ConfirmCommit()
}

func TestCommitConfirmedGenSucceedsWhenUnchanged(t *testing.T) {
	s := genStoreInConfig(t, "c1")

	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if _, err := s.CommitConfirmedGen(5, gen); err != nil {
		t.Fatalf("in-generation commit-confirmed failed: %v", err)
	}
	if active := s.ShowActiveSet(); !strings.Contains(active, "host-name c1") {
		t.Fatalf("in-generation commit-confirmed did not promote C1; active=%q", active)
	}
	if err := s.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
}

// Every candidate-mutating store op must advance the generation, or a mutation
// slips past the guard. Table-driven so a newly-added mutator that forgets the
// bump is caught here.
func TestCandidateGenerationBumps(t *testing.T) {
	ops := []struct {
		name string
		// prep runs mutations that set up the op (not asserted); do returns the
		// op whose generation bump is asserted.
		prep func(t *testing.T, s *Store)
		do   func(t *testing.T, s *Store)
	}{
		{"set", nil, func(t *testing.T, s *Store) {
			if err := s.SetFromInput("system host-name h1"); err != nil {
				t.Fatal(err)
			}
		}},
		{"delete", func(t *testing.T, s *Store) {
			if err := s.SetFromInput("system host-name h1"); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, s *Store) {
			if err := s.DeleteFromInput("system host-name h1"); err != nil {
				t.Fatal(err)
			}
		}},
		{"deactivate", func(t *testing.T, s *Store) {
			if err := s.SetFromInput("interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24"); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, s *Store) {
			if err := s.DeactivateFromInput("interfaces ge-0-0-0"); err != nil {
				t.Fatal(err)
			}
		}},
		{"activate", func(t *testing.T, s *Store) {
			if err := s.SetFromInput("interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24"); err != nil {
				t.Fatal(err)
			}
			if err := s.DeactivateFromInput("interfaces ge-0-0-0"); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, s *Store) {
			if err := s.ActivateFromInput("interfaces ge-0-0-0"); err != nil {
				t.Fatal(err)
			}
		}},
		{"copy", func(t *testing.T, s *Store) {
			if err := s.SetFromInput("interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24"); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, s *Store) {
			if err := s.Copy([]string{"interfaces", "ge-0-0-0"}, []string{"interfaces", "ge-0-0-1"}); err != nil {
				t.Fatal(err)
			}
		}},
		{"rename", func(t *testing.T, s *Store) {
			if err := s.SetFromInput("interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24"); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, s *Store) {
			if err := s.Rename([]string{"interfaces", "ge-0-0-0"}, []string{"interfaces", "ge-0-0-9"}); err != nil {
				t.Fatal(err)
			}
		}},
		{"annotate", func(t *testing.T, s *Store) {
			if err := s.SetFromInput("system host-name h1"); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, s *Store) {
			if err := s.Annotate([]string{"system"}, "a comment"); err != nil {
				t.Fatal(err)
			}
		}},
		{"insert", func(t *testing.T, s *Store) {
			// Two ordered sibling nodes under the root so InsertBefore has a
			// valid element + same-parent reference to reorder.
			if err := s.SetFromInput("a"); err != nil {
				t.Fatal(err)
			}
			if err := s.SetFromInput("b"); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, s *Store) {
			if err := s.Insert([]string{"a"}, []string{"b"}, true); err != nil {
				t.Fatal(err)
			}
		}},
		{"load-override", nil, func(t *testing.T, s *Store) {
			if err := s.LoadOverride("system { host-name over; }"); err != nil {
				t.Fatal(err)
			}
		}},
		{"load-merge", nil, func(t *testing.T, s *Store) {
			if err := s.LoadMerge("set system host-name merged"); err != nil {
				t.Fatal(err)
			}
		}},
		{"load-set", nil, func(t *testing.T, s *Store) {
			if _, err := s.LoadSet("set system host-name loaded"); err != nil {
				t.Fatal(err)
			}
		}},
		{"rollback-0", func(t *testing.T, s *Store) {
			if err := s.SetFromInput("system host-name dirty"); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, s *Store) {
			if err := s.Rollback(0); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if op.prep != nil {
				op.prep(t, s)
			}
			before := s.CandidateGeneration()
			op.do(t, s)
			if after := s.CandidateGeneration(); after <= before {
				t.Fatalf("op %q did not advance candidateGen (before=%d after=%d) — mutation slips past the #5848 guard",
					op.name, before, after)
			}
		})
	}
}

// Entering and exiting configuration mode advance the generation too (the
// candidate identity changes), so a commit prepared against an old generation
// cannot survive a config-mode transition.
func TestCandidateGenerationBumpsOnEnterExit(t *testing.T) {
	s := newTestStore(t)
	g0 := s.CandidateGeneration()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	g1 := s.CandidateGeneration()
	if g1 <= g0 {
		t.Fatalf("EnterConfigure did not advance candidateGen (%d -> %d)", g0, g1)
	}
	s.ExitConfigure()
	g2 := s.CandidateGeneration()
	if g2 <= g1 {
		t.Fatalf("ExitConfigure did not advance candidateGen (%d -> %d)", g1, g2)
	}
}

// Rollback to a NUMBERED history slot (n > 0) also advances the generation — a
// distinct store_command/store_commit bump site from the rollback-0 case in the
// table above (which reclones the active). Driven standalone because it needs a
// committed history entry to roll back to.
func TestCandidateGenerationBumpsOnRollbackN(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// One commit creates a rollback slot (the pre-commit active config).
	if err := s.SetFromInput("system host-name v1"); err != nil {
		t.Fatalf("set v1: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// Stage a further change so the candidate differs from the rollback target.
	if err := s.SetFromInput("system host-name v2"); err != nil {
		t.Fatalf("set v2: %v", err)
	}
	before := s.CandidateGeneration()
	if err := s.Rollback(1); err != nil {
		t.Fatalf("Rollback(1): %v", err)
	}
	if after := s.CandidateGeneration(); after <= before {
		t.Fatalf("Rollback(1) did not advance candidateGen (before=%d after=%d)", before, after)
	}
}
