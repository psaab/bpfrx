package configstore

import (
	"errors"
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// ErrCandidateGenerationConflict is returned by the generation-bound commit
// entry points (CommitWithDescriptionGen / CommitConfirmedGen) when the
// candidate configuration changed between the caller's snapshot+pre-flight and
// the promotion attempt (#5848). It is a sentinel so callers can errors.Is it
// and RETRY the whole snapshot→pre-flight→commit against the new generation
// instead of promoting a candidate the external pre-flight never examined.
var ErrCandidateGenerationConflict = errors.New(
	"candidate configuration changed during commit preparation (generation conflict); re-validate and retry")

// bumpCandidateGenLocked advances the candidate generation token. It MUST be
// called under s.mu.Lock at EVERY site that changes the candidate tree's
// identity or content (mutation, load, rollback, enter/exit/reclaim config
// mode, peer-sync reset, post-commit reset). Missing a site would let a
// candidate change slip past the generation guard, so a table-driven test
// (TestCandidateGenerationBumps*) asserts each mutating store op advances it.
func (s *Store) bumpCandidateGenLocked() {
	s.candidateGen++
}

// CandidateGeneration returns the current candidate generation token. Used by
// the daemon's commit transaction (paired with CompileCandidateGen) and by
// tests asserting that mutating ops advance the token.
func (s *Store) CandidateGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.candidateGen
}

// CompileCandidateGen atomically compiles the current candidate AND reads the
// candidate generation token under a SINGLE read lock, so the returned compiled
// config and generation are a consistent pair describing the same candidate
// state (#5848). The daemon runs its external #1956 device-map hardware
// pre-flight on the returned compiled snapshot OUTSIDE the store lock, then
// commits with the returned generation via CommitWithDescriptionGen /
// CommitConfirmedGen so a concurrent candidate mutation between snapshot and
// promote is a CONFLICT, not a silent substitution.
//
// The generation is returned even when the candidate is absent or fails
// commit-check: the daemon still gen-binds the subsequent commit so that a
// candidate which a concurrent edit turns FROM non-compiling INTO a valid
// (e.g. management-stranding) config cannot be promoted without a fresh
// pre-flight. When compilation fails the returned *config.Config is nil and the
// caller skips the hardware pre-flight (there is nothing to examine); the
// generation-bound commit then recompiles under the lock and surfaces the SAME
// compile/mode error when the candidate is unchanged.
func (s *Store) CompileCandidateGen() (*config.Config, uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	gen := s.candidateGen
	if s.candidate == nil {
		return nil, gen, fmt.Errorf("not in configuration mode")
	}
	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, gen, err
	}
	return compiled, gen, nil
}
