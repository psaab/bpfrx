package configstore

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// ShowCandidate returns the candidate configuration as hierarchical text.
func (s *Store) ShowCandidate() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.Format()
	}
	return ""
}

// ShowCandidatePath returns the candidate configuration subtree at the given path.
func (s *Store) ShowCandidatePath(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatPath(path)
	}
	return ""
}

// ShowActive returns the active configuration as hierarchical text.
func (s *Store) ShowActive() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.Format()
}

// ShowActivePath returns the active configuration subtree at the given path.
func (s *Store) ShowActivePath(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPath(path)
}

// ShowCandidateSet returns the candidate configuration as flat set commands.
func (s *Store) ShowCandidateSet() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatSet()
	}
	return ""
}

// ActiveConfig returns the compiled active configuration.
func (s *Store) ActiveConfig() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.compiled
}

// CompileCandidate strictly compiles the current candidate WITHOUT mutating
// any store state (no promote, no persist, no confirm-timer). It is the
// read-only pre-commit hook the daemon's #1956 device-map commit pre-flight
// uses to resolve the proposed map against live hardware BEFORE the store
// promotes it — so a map that would strand management on next boot is
// rejected while the operator is still connected, not at the next reboot.
// Returns the same compiled config Commit() would, or the commit-check error.
func (s *Store) CompileCandidate() (*config.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}
	return s.compileTree(s.candidate)
}

// EverCommitted reports the #1922 step-0 marker: true once a config has
// been successfully committed or synced to this store, or loaded from a
// committed/legacy DB (migration rule C3 defaults a marker-less DB to
// committed). It is false on a fresh store and after the Item 1b
// first-commit rollback persists the never-committed marker. The daemon's
// five-case boot predicate reads it to disambiguate operator-committed-empty
// (normal) from never-committed (bootstrap) when the active config is empty.
func (s *Store) EverCommitted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.everCommitted
}

// ActiveTree returns a deep copy of the active configuration tree.
func (s *Store) ActiveTree() *config.ConfigTree {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active == nil {
		return nil
	}
	return s.active.Clone()
}

// ExportJSON exports the active config as JSON (for debugging).
func (s *Store) ExportJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.MarshalIndent(s.compiled, "", "  ")
}

// ShowActiveSet returns the active configuration as flat set commands.
func (s *Store) ShowActiveSet() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatSet()
}

// ShowActivePathSet returns an active config subtree as flat set commands.
func (s *Store) ShowActivePathSet(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathSet(path)
}

// ShowCandidatePathSet returns a candidate config subtree as flat set commands.
func (s *Store) ShowCandidatePathSet(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatPathSet(path)
	}
	return ""
}

// ShowActiveJSON returns the active configuration as JSON.
func (s *Store) ShowActiveJSON() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatJSON()
}

// ShowActivePathJSON returns an active config subtree as JSON.
func (s *Store) ShowActivePathJSON(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathJSON(path)
}

// ShowCandidateJSON returns the candidate configuration as JSON.
func (s *Store) ShowCandidateJSON() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatJSON()
	}
	return "{}\n"
}

// ShowCandidatePathJSON returns a candidate config subtree as JSON.
func (s *Store) ShowCandidatePathJSON(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatPathJSON(path)
	}
	return ""
}

// ShowActiveXML returns the active configuration as XML.
func (s *Store) ShowActiveXML() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatXML()
}

// ShowActivePathXML returns an active config subtree as XML.
func (s *Store) ShowActivePathXML(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathXML(path)
}

// ShowCandidateXML returns the candidate configuration as XML.
func (s *Store) ShowCandidateXML() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatXML()
	}
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n</configuration>\n"
}

// ShowCandidatePathXML returns a candidate config subtree as XML.
func (s *Store) ShowCandidatePathXML(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatPathXML(path)
	}
	return ""
}

// ShowCandidateInheritance returns the candidate with groups expanded and
// annotated with "## inherited from" comments.
func (s *Store) ShowCandidateInheritance() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatInheritance()
	}
	return ""
}

// ShowCandidatePathInheritance returns a subtree with inheritance annotations.
func (s *Store) ShowCandidatePathInheritance(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.candidate != nil {
		return s.candidate.FormatPathInheritance(path)
	}
	return ""
}

// ShowActiveInheritance returns the active config with inheritance annotations.
func (s *Store) ShowActiveInheritance() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatInheritance()
}

// ShowActivePathInheritance returns an active config subtree with inheritance annotations.
func (s *Store) ShowActivePathInheritance(path []string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.FormatPathInheritance(path)
}

// ShowRollback returns the content of rollback slot n (1-based) as hierarchical text.
func (s *Store) ShowRollback(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, err := s.history.Get(n - 1)
	if err != nil {
		return "", err
	}
	return entry.Config.Format(), nil
}

// ShowRollbackSet returns the content of rollback slot n (1-based) as flat set commands.
func (s *Store) ShowRollbackSet(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, err := s.history.Get(n - 1)
	if err != nil {
		return "", err
	}
	return entry.Config.FormatSet(), nil
}

// ShowCompareRollback returns a diff between rollback slot n and the candidate.
func (s *Store) ShowCompareRollback(n int) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return "", fmt.Errorf("not in configuration mode")
	}

	entry, err := s.history.Get(n - 1)
	if err != nil {
		return "", err
	}

	diff := config.FormatCompare(entry.Config, s.candidate)
	if diff == "" {
		return "[no changes]\n", nil
	}
	return diff, nil
}

// ShowCompare returns a hierarchical diff between the active and candidate
// configurations in Junos [edit] context format.
func (s *Store) ShowCompare() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return ""
	}

	diff := config.FormatCompare(s.active, s.candidate)
	if diff == "" {
		return "[no changes]\n"
	}
	return diff
}

// splitLines splits a string into non-empty lines.
func splitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
