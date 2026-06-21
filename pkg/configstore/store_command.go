package configstore

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// Set applies a "set" command to the candidate configuration.
func (s *Store) Set(path []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if err := s.candidate.SetPath(path); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// SetFromInput parses a "set ..." command string and applies it.
func (s *Store) SetFromInput(input string) error {
	path, err := config.ParseSetCommand("set " + input)
	if err != nil {
		return err
	}
	return s.Set(path)
}

// Delete removes a node at the given path from the candidate configuration.
func (s *Store) Delete(path []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if err := s.candidate.DeletePath(path); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// DeleteFromInput parses a "delete ..." command string and applies it.
func (s *Store) DeleteFromInput(input string) error {
	path, err := config.ParseSetCommand("delete " + input)
	if err != nil {
		return err
	}
	return s.Delete(path)
}

// DeactivateFromInput marks the candidate node at the given path inactive
// (#2051), implementing the interactive Junos `deactivate <path>` verb. input
// is the bare path WITHOUT the verb (mirroring SetFromInput/DeleteFromInput).
//
// It routes through applyEditLine — the same centralized verb switch used by
// LoadSet / LoadMerge flat-line replay (store.go applyEditLine) — so the verb
// logic lives in exactly one place. It deliberately does NOT go through
// ParseSetCommand("set "+input): that parser would build the junk path
// "deactivate <path>" (a config node literally named "deactivate"), never
// reaching DeactivatePath. The node must already exist; DeactivatePath on an
// already-inactive node is idempotent (it re-sets a bool).
func (s *Store) DeactivateFromInput(input string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	if err := applyEditLine(s.candidate, "deactivate "+input); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// ActivateFromInput clears the inactive marker on the candidate node at the
// given path (#2051), implementing the interactive Junos `activate <path>`
// verb. Symmetric with DeactivateFromInput; ActivatePath on an already-active
// node is idempotent.
func (s *Store) ActivateFromInput(input string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	if err := applyEditLine(s.candidate, "activate "+input); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// Copy duplicates a config subtree from srcPath to dstPath.
func (s *Store) Copy(srcPath, dstPath []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	if err := s.candidate.CopyPath(srcPath, dstPath); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// Rename moves a config subtree from srcPath to dstPath.
func (s *Store) Rename(srcPath, dstPath []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	if err := s.candidate.RenamePath(srcPath, dstPath); err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// Insert moves an element before or after a reference element within the
// same parent's ordered children list.
func (s *Store) Insert(elementPath, refPath []string, before bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	var err error
	if before {
		err = s.candidate.InsertBefore(elementPath, refPath)
	} else {
		err = s.candidate.InsertAfter(elementPath, refPath)
	}
	if err != nil {
		return err
	}
	s.dirty = true
	return nil
}

// Annotate sets a comment on a configuration node in the candidate config.
func (s *Store) Annotate(path []string, comment string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	children := s.candidate.Children
	var target *config.Node
	for _, key := range path {
		found := false
		for _, child := range children {
			for _, k := range child.Keys {
				if k == key {
					target = child
					children = child.Children
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return fmt.Errorf("path not found: %s", strings.Join(path, " "))
		}
	}

	target.Annotation = comment
	s.dirty = true
	return nil
}

// LoadOverride replaces the entire candidate config with the parsed input.
// The input can be hierarchical Junos config or flat "set" commands.
func (s *Store) LoadOverride(content string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	tree, errs := config.NewParser(content).Parse()
	if len(errs) > 0 {
		return fmt.Errorf("parse error: %v", errs[0])
	}

	s.candidate = tree
	s.dirty = true
	return nil
}

// LoadMerge merges the parsed input into the existing candidate config.
// For flat "set" commands, each line is applied individually.
// For hierarchical input, it's converted to set commands and merged.
func (s *Store) LoadMerge(content string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	// Detect format: if content has set/delete/deactivate/activate lines,
	// process as flat command lines.
	lines := strings.Split(content, "\n")
	isSetFormat := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "set ") ||
			strings.HasPrefix(trimmed, "delete ") ||
			strings.HasPrefix(trimmed, "deactivate ") ||
			strings.HasPrefix(trimmed, "activate ") {
			isSetFormat = true
			break
		}
	}

	if isSetFormat {
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if err := applyEditLine(s.candidate, trimmed); err != nil {
				return fmt.Errorf("line %q: %w", trimmed, err)
			}
		}
	} else {
		// Parse as hierarchical config and merge each top-level node
		tree, errs := config.NewParser(content).Parse()
		if len(errs) > 0 {
			return fmt.Errorf("parse error: %v", errs[0])
		}
		// Convert hierarchical to flat commands and apply each one. FormatSet
		// emits a `deactivate <path>` line after every inactive node's `set`
		// line(s), so the hierarchical -> flat -> tree round trip must honor
		// the deactivate verb (#2008 H1) to preserve Inactive — applying it as
		// a plain set would silently re-activate the node.
		setLines := strings.Split(tree.FormatSet(), "\n")
		for _, line := range setLines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if err := applyEditLine(s.candidate, trimmed); err != nil {
				return fmt.Errorf("merge: %w", err)
			}
		}
	}

	s.dirty = true
	return nil
}

// applyEditLine parses a single flat command line and applies the correct
// edit to tree based on its verb (#2008 H1): set, delete, deactivate, or
// activate. Centralizing the verb switch keeps every flat-line replay path
// (LoadMerge flat + hierarchical-via-FormatSet, LoadSet) in agreement, so
// `show | display set` output — which emits `deactivate <path>` for inactive
// nodes — round-trips back to an inactive node instead of being skipped (and
// reloaded active) or parsed as a junk path literally starting "deactivate".
func applyEditLine(tree *config.ConfigTree, line string) error {
	verb, path, err := config.ParseSetVerb(line)
	if err != nil {
		return err
	}
	switch verb {
	case "delete":
		return tree.DeletePath(path)
	case "deactivate":
		return tree.DeactivatePath(path)
	case "activate":
		return tree.ActivatePath(path)
	default: // "set" (or a bare, unprefixed path)
		return tree.SetPath(path)
	}
}

// LoadSet applies multiple flat command lines to the candidate config.
// Each line starting with a recognized verb — set, delete, deactivate, or
// activate (#2008 H1) — is parsed and applied; other lines (e.g. comments)
// are skipped. The deactivate/activate verbs make `show | display set`
// output round-trippable: previously a `deactivate <path>` line was skipped
// here, so an inactive node reloaded ACTIVE.
func (s *Store) LoadSet(content string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.candidate == nil {
		return 0, fmt.Errorf("not in configuration mode")
	}
	count := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "set ") &&
			!strings.HasPrefix(line, "delete ") &&
			!strings.HasPrefix(line, "deactivate ") &&
			!strings.HasPrefix(line, "activate ") {
			continue
		}
		if err := applyEditLine(s.candidate, line); err != nil {
			return count, fmt.Errorf("line %q: %w", line, err)
		}
		count++
	}
	s.dirty = true
	return count, nil
}
