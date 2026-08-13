package configstore

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// Set applies a "set" command to the candidate configuration. It is the
// internal/system entry point (no session ownership check); the gRPC user path
// uses SetAs to carry the caller's session for config-lock holder enforcement
// (#5059).
func (s *Store) Set(path []string) error { return s.SetAs("", path) }

// SetAs is Set scoped to a config-lock holder session (#5059). sessionID == ""
// bypasses ownership (internal/system caller).
//
// It carries NO quote provenance, so nodes it creates record none — correct for
// a synthesized path, and the reason the operator-facing entry point
// (SetFromInputAs) uses SetAsQuoted instead (#6673).
func (s *Store) SetAs(sessionID string, path []string) error {
	return s.SetAsQuoted(sessionID, path, nil)
}

// SetAsQuoted is SetAs carrying the per-token quote provenance produced by
// config.ParseSetCommandQuoted (#6673). It is what lets a bracketed list
// authored through the flat-set path — `set ... commands [ "set" "system
// host-name x" ]` — keep the one bit that distinguishes its members from the
// words of a single unquoted command.
func (s *Store) SetAsQuoted(sessionID string, path []string, quoted []bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if err := s.candidate.SetPathQuoted(path, quoted); err != nil {
		return err
	}
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// SetFromInput parses a "set ..." command string and applies it.
func (s *Store) SetFromInput(input string) error { return s.SetFromInputAs("", input) }

// SetFromInputAs is SetFromInput scoped to a config-lock holder session (#5059).
func (s *Store) SetFromInputAs(sessionID, input string) error {
	path, quoted, err := config.ParseSetCommandQuoted("set " + input)
	if err != nil {
		return err
	}
	return s.SetAsQuoted(sessionID, path, quoted)
}

// Delete removes a node at the given path from the candidate configuration. The
// internal/system entry point; the gRPC user path uses DeleteAs (#5059).
func (s *Store) Delete(path []string) error { return s.DeleteAs("", path) }

// DeleteAs is Delete scoped to a config-lock holder session (#5059).
func (s *Store) DeleteAs(sessionID string, path []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if err := s.candidate.DeletePath(path); err != nil {
		return err
	}
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// DeleteFromInput parses a "delete ..." command string and applies it.
func (s *Store) DeleteFromInput(input string) error { return s.DeleteFromInputAs("", input) }

// DeleteFromInputAs is DeleteFromInput scoped to a config-lock holder session
// (#5059).
func (s *Store) DeleteFromInputAs(sessionID, input string) error {
	path, err := config.ParseSetCommand("delete " + input)
	if err != nil {
		return err
	}
	return s.DeleteAs(sessionID, path)
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
	return s.DeactivateFromInputAs("", input)
}

// DeactivateFromInputAs is DeactivateFromInput scoped to a config-lock holder
// session (#5059).
func (s *Store) DeactivateFromInputAs(sessionID, input string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	if err := applyEditLine(s.candidate, "deactivate "+input); err != nil {
		return err
	}
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// ActivateFromInput clears the inactive marker on the candidate node at the
// given path (#2051), implementing the interactive Junos `activate <path>`
// verb. Symmetric with DeactivateFromInput; ActivatePath on an already-active
// node is idempotent.
func (s *Store) ActivateFromInput(input string) error {
	return s.ActivateFromInputAs("", input)
}

// ActivateFromInputAs is ActivateFromInput scoped to a config-lock holder
// session (#5059).
func (s *Store) ActivateFromInputAs(sessionID, input string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	if err := applyEditLine(s.candidate, "activate "+input); err != nil {
		return err
	}
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// Copy duplicates a config subtree from srcPath to dstPath.
func (s *Store) Copy(srcPath, dstPath []string) error { return s.CopyAs("", srcPath, dstPath) }

// CopyAs is Copy scoped to a config-lock holder session (#5059).
func (s *Store) CopyAs(sessionID string, srcPath, dstPath []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	if err := s.candidate.CopyPath(srcPath, dstPath); err != nil {
		return err
	}
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// Rename moves a config subtree from srcPath to dstPath.
func (s *Store) Rename(srcPath, dstPath []string) error { return s.RenameAs("", srcPath, dstPath) }

// RenameAs is Rename scoped to a config-lock holder session (#5059).
func (s *Store) RenameAs(sessionID string, srcPath, dstPath []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	if err := s.candidate.RenamePath(srcPath, dstPath); err != nil {
		return err
	}
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// Insert moves an element before or after a reference element within the
// same parent's ordered children list.
func (s *Store) Insert(elementPath, refPath []string, before bool) error {
	return s.InsertAs("", elementPath, refPath, before)
}

// InsertAs is Insert scoped to a config-lock holder session (#5059).
func (s *Store) InsertAs(sessionID string, elementPath, refPath []string, before bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
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
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// Annotate sets a comment on a configuration node in the candidate config. It
// is the internal/system entry point (no session ownership check); a
// session-scoped caller uses AnnotateAs to carry the caller's session for
// config-lock holder enforcement (#5379).
func (s *Store) Annotate(path []string, comment string) error {
	return s.AnnotateAs("", path, comment)
}

// AnnotateAs is Annotate scoped to a config-lock holder session (#5379,
// mirroring the #5059 *As mutators). sessionID == "" bypasses ownership
// (internal/system caller). Annotate was the one candidate mutator missing the
// ensureHolderLocked ownership check that every sibling enforces, so a caller
// that did not hold the config lock could annotate another session's candidate
// and refresh (extend) the true holder's idle lease with no ownership check.
func (s *Store) AnnotateAs(sessionID string, path []string, comment string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	// #3900: reject a comment delimiter (or control character) in the
	// annotation up front. An annotation is emitted verbatim into a
	// `/* */` comment, so a `*/` would close the comment early and let the
	// trailing text be re-parsed as configuration on the next Format→Parse
	// (HA config sync, rollback/archive reload). The strict commit path
	// enforces the same rule; this is the immediate-feedback layer.
	if err := config.ValidateAnnotationText(comment); err != nil {
		return err
	}

	// #4587: resolve the target via the shared navigatePath traversal
	// (ConfigTree.AnnotatePath) instead of a hand-rolled walk. The old walk
	// consumed ONE path token per node but matched it against ANY key in a
	// node's Keys, so a named / multi-key container — Keys=[security-zone,
	// trust], [from-zone,untrust,to-zone,trust,policy,p], [family,inet] — was
	// entered on its first key and then failed to find the argument token
	// (trust, inet, ...) as a child: "path not found" for every zone, policy,
	// interface-unit, and family-inet path. Annotate worked only for a chain
	// of pure single-key nodes such as `system`. navigatePath consumes a
	// multi-key node as a unit, so those paths now resolve; the single-key
	// case is unchanged.
	if err := s.candidate.AnnotatePath(path, comment); err != nil {
		return err
	}
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// LoadOverride replaces the entire candidate config with the parsed input.
// The input can be hierarchical Junos config or flat "set" commands.
func (s *Store) LoadOverride(content string) error { return s.LoadOverrideAs("", content) }

// LoadOverrideAs is LoadOverride scoped to a config-lock holder session (#5059).
func (s *Store) LoadOverrideAs(sessionID, content string) error {
	if err := checkConfigSize(content); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	tree, errs := config.NewParser(content).Parse()
	if len(errs) > 0 {
		return fmt.Errorf("parse error: %v", errs[0])
	}

	s.candidate = tree
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return nil
}

// LoadMerge merges the parsed input into the existing candidate config.
// For flat "set" commands, each line is applied individually.
// For hierarchical input, it's converted to set commands and merged.
func (s *Store) LoadMerge(content string) error { return s.LoadMergeAs("", content) }

// LoadMergeAs is LoadMerge scoped to a config-lock holder session (#5059).
func (s *Store) LoadMergeAs(sessionID, content string) error {
	if err := checkConfigSize(content); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	// Detect format: if content has set/delete/deactivate/activate lines,
	// process as flat command lines.
	lines := strings.Split(content, "\n")
	isSetFormat := false
	for _, line := range lines {
		if hasFlatVerb(strings.TrimSpace(line)) {
			isSetFormat = true
			break
		}
	}

	// #5187: merge into a deep clone of the candidate and swap it in only on
	// complete success. Both branches below previously applied each line
	// directly to s.candidate and returned on the first error, leaving every
	// EARLIER set/delete line committed to the live candidate while the
	// RPC/CLI reported the merge FAILED — a non-atomic import (a partial
	// delete could drop replacement deny lines that followed the failing line
	// = fail-open). Mirror LoadOverride's parse-into-a-separate-tree-then-swap
	// discipline so a mid-body error leaves the candidate byte-identical to
	// before the request (dirty/lease state untouched).
	working := s.candidate.Clone()

	if isSetFormat {
		// #3442 M3: once flat set-format is selected, every non-comment line
		// MUST start with a recognized verb. Otherwise ParseSetVerb treats a
		// typo/free-text line (e.g. "not-a-set-line") as a bare `set` path and
		// materializes a junk top-level node. Fail loudly on the bad line
		// instead — the bare-path default in ParseSetVerb is reserved for
		// internal callers that prepend the verb themselves (SetEdit, Deactivate,
		// Activate, ...).
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if !hasFlatVerb(trimmed) {
				return fmt.Errorf("line %d: %q is not a set/delete/deactivate/activate command", i+1, trimmed)
			}
			if err := applyEditLine(working, trimmed); err != nil {
				return fmt.Errorf("line %d: %q: %w", i+1, trimmed, err)
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
			if err := applyEditLine(working, trimmed); err != nil {
				return fmt.Errorf("merge: %w", err)
			}
		}
	}

	s.candidate = working
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: candidate changed — advance the generation
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
// hasFlatVerb reports whether a line begins with one of the flat config-edit
// verbs that applyEditLine can actually replay (set/delete/deactivate/
// activate) followed by at least one path token. It is the fail-closed gate
// for the service-mode load paths (LoadMerge flat branch + LoadSet): a line
// that does not start with one of those verbs is malformed input, NOT a bare
// path.
//
// The verb set is deliberately EXACTLY the set applyEditLine -> ParseSetVerb
// dispatches. The interactive structural-edit verbs annotate/copy/insert/
// rename (pkg/cli/cli_dispatch.go, pkg/cmdtree ConfigTopLevel) are NOT
// recognized here on purpose: they have distinct multi-clause grammar
// (`copy X to Y`, `insert X before Y`, `annotate X "comment"`), are handled
// only by the interactive CLI, and never appear in a flat-load artifact —
// `show | display set` (ConfigTree.FormatSet) emits only `set`/`deactivate`
// lines. Pre-#3442 such a line was silently turned into a junk `set
// annotate ...` node by the bare-path default, so rejecting it is correct,
// not a regression of any previously-working load.
//
// The first token is matched against the verb set after splitting on any
// whitespace, so a tab between the verb and the path (the lexer treats tabs
// as whitespace) is tolerated as well as a space.
func hasFlatVerb(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		// A blank line or a bare verb with no path is not a replayable
		// flat command.
		return false
	}
	switch fields[0] {
	case "set", "delete", "deactivate", "activate":
		return true
	default:
		return false
	}
}

func applyEditLine(tree *config.ConfigTree, line string) error {
	verb, path, quoted, err := config.ParseSetVerbQuoted(line)
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
		// Quote provenance rides along so a `show | display set` dump replays
		// into the same tree it was rendered from (#6673).
		return tree.SetPathQuoted(path, quoted)
	}
}

// LoadSet applies multiple flat command lines to the candidate config.
// Each line starting with a recognized verb — set, delete, deactivate, or
// activate (#2008 H1) — is parsed and applied. Blank lines and `#` comments
// are skipped; any other non-empty line is rejected with a line-numbered
// error (#3442 M4 — silently skipping a malformed line, e.g. "sett system
// host-name fw", let an operator commit a config missing the intended
// command). The deactivate/activate verbs make `show | display set` output
// round-trippable: previously a `deactivate <path>` line was skipped here,
// so an inactive node reloaded ACTIVE.
func (s *Store) LoadSet(content string) (int, error) { return s.LoadSetAs("", content) }

// LoadSetAs is LoadSet scoped to a config-lock holder session (#5059).
func (s *Store) LoadSetAs(sessionID, content string) (int, error) {
	if err := checkConfigSize(content); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return 0, err
	}
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return 0, err
	}
	if s.candidate == nil {
		return 0, fmt.Errorf("not in configuration mode")
	}
	// #5187: replay every line into a deep clone of the candidate and swap it
	// in only after ALL lines apply. Applying directly to s.candidate advanced
	// it line-by-line and, on the first failing line, left every EARLIER
	// set/delete line committed to the live candidate while the RPC/CLI
	// reported the load FAILED — a non-atomic import. A partial delete was
	// fail-open: replacement deny lines that followed the failing line were
	// dropped, yet the candidate had already advanced. Mirror LoadOverride's
	// parse-into-a-separate-tree-then-swap discipline so a mid-body error
	// leaves the candidate byte-identical to before the request (dirty/lease
	// state untouched).
	working := s.candidate.Clone()
	count := 0
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// #3442 M4: a non-blank, non-comment line that is not a recognized
		// verb is malformed input (e.g. "sett system host-name fw"). Previously
		// LoadSet silently `continue`d on it, so REST/gRPC/CLI returned OK while
		// dropping the intended command — the operator could commit a config
		// missing it. Fail with a line-numbered error instead.
		if !hasFlatVerb(line) {
			return count, fmt.Errorf("line %d: %q is not a set/delete/deactivate/activate command", i+1, line)
		}
		if err := applyEditLine(working, line); err != nil {
			return count, fmt.Errorf("line %d: %q: %w", i+1, line, err)
		}
		count++
	}
	s.candidate = working
	s.touchConfigLockLocked()  // #4476: refresh the config-lock idle lease
	s.bumpCandidateGenLocked() // #5848: candidate changed — advance the generation
	s.dirty = true
	return count, nil
}
