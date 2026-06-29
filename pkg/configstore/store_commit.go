package configstore

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// Rollback/archive persistence seams (#3441, following the #1916
// pkg/api/tls_test.go pattern). Production code must never mutate these;
// tests override them to record durability calls (so a test fails RED if a
// WriteFileDurable is downgraded to atomic or a SyncDir is dropped) and to
// inject write failures. nil-free: each aliases the real fsatomic writer.
var (
	rbWriteFileDurable = fsatomic.WriteFileDurable
	rbWriteFileAtomic  = fsatomic.WriteFileAtomic
	rbSyncDir          = fsatomic.SyncDir
	rbRemove           = os.Remove
)

// CommitCheck validates the candidate configuration without applying it.
func (s *Store) CommitCheck() (*config.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, err
	}

	return compiled, nil
}

// Commit validates, compiles, and applies the candidate configuration.
// Returns the compiled config for the caller to apply to the dataplane.
// Identical to CommitWithDescription with an empty description (the two
// were verbatim duplicates before #1799 unified them).
func (s *Store) Commit() (*config.Config, error) {
	return s.CommitWithDescription("")
}

// CommitWithDescription validates, compiles, and applies the candidate configuration
// with an optional comment/description attached to the history and journal entries.
//
// Persistence contract (#1799, Option A — persist-before-promote): the
// candidate tree is written to the on-disk active config BEFORE any
// in-memory promotion. WriteActive is temp-file + rename atomic
// (db.go), so a persist failure leaves the previous active config
// intact on disk; the commit then fails with the candidate left
// intact and NOTHING mutated — no active/candidate/compiled/dirty
// change, no history push, no journal entry, no rollback-file save.
// A commit that reports success can therefore never silently revert
// to the previous config on daemon restart.
func (s *Store) CommitWithDescription(description string) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, fmt.Errorf("commit check failed: %w", err)
	}

	// #1799 Option A: persist BEFORE promote. On failure the old
	// active stays on disk and in memory; the operator sees the
	// error and the candidate is still there to retry.
	if err := s.writeActive(s.candidate); err != nil {
		return nil, fmt.Errorf("commit failed: persist active config: %w", err)
	}
	s.persistDegraded = false       // disk now holds the current config
	s.everCommitted = true          // #1922 step-0: a real commit has succeeded
	s.persistMarkerCommitted = true // #1922: degraded-retry writes committed=1

	// Push current active to history with description
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
		Comment:   description,
	})

	// Promote candidate to active
	s.active = s.candidate
	s.candidate = s.active.Clone()
	s.compiled = compiled
	s.dirty = false

	// Log to journal with description
	s.journalLog(&JournalEntry{
		Action:     "commit",
		Detail:     description,
		ConfigHash: journalConfigHash(s.active),
	})

	s.saveRollbackFiles()

	// Auto-archive if configured (#3441 H4). Capture the JUST-COMMITTED
	// text, directory, max, and a nanosecond-resolution timestamp INSIDE
	// the commit critical section, then hand only those immutable values
	// to the async writer. The previous code passed nothing and let the
	// goroutine read s.active.Format() whenever it eventually ran: two
	// rapid commits raced so goroutine A could archive commit B's tree
	// (mislabeled archive), and the second-resolution filename meant two
	// same-second commits wrote the same path (later overwrote earlier).
	// The nanosecond timestamp makes the filename unique per commit (no
	// overwrite) and correctly labels the captured tree.
	if s.archiveDir != "" {
		dir := s.archiveDir
		max := s.archiveMax
		if max <= 0 {
			max = 10
		}
		data := s.active.Format()
		ts := time.Now()
		seq := s.archiveSeq.Add(1)
		go func() {
			if err := writeArchive(dir, max, data, ts, seq); err != nil {
				slog.Warn("auto-archive failed", "err", err)
			}
		}()
	}

	return compiled, nil
}

// SetRollbackExecutor registers the daemon's commit-confirmed timeout
// rollback transaction (#1922 Item 1a). The executor is invoked (on the
// timer's own goroutine, never under s.mu) with the confirm generation
// that armed the timer. It MUST acquire the daemon apply semaphore
// first, then call PromoteRollback(gen) + re-apply the returned config,
// so store promotion and dataplane re-apply are atomic under the same
// lock that serializes commits. Registering nil disables the executor
// and reverts to the self-contained performAutoRollback fallback.
func (s *Store) SetRollbackExecutor(fn func(gen uint64)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollbackExecutor = fn
}

// CommitConfirmed validates, compiles, and applies the candidate with an
// automatic rollback timer. If minutes is 0, defaults to 10.
// If a bare "commit" is not issued within the timeout, the config auto-reverts.
//
// Persistence contract (#1799, Option A + confirm-state ordering): the
// candidate is persisted BEFORE any in-memory promotion AND before any
// confirm state is touched. On persist failure nothing changes: no
// promotion, no timer armed, and an EXISTING pending confirm (its
// timer and rollback target) is left fully intact — the prior ordering
// cancelled the pending timer and overwrote the rollback target before
// the write, so a persist failure could strand a pending confirmed
// commit with no auto-rollback.
//
// Nested confirmed commits (a second CommitConfirmed while one is
// still pending) PRESERVE the existing confirmPrevTree/confirmPrevCfg:
// the rollback target must stay the last truly CONFIRMED config.
// Overwriting it with s.active (the unconfirmed commit-1 tree, as the
// code did before #1799) meant a commit-2 timeout "rolled back" to the
// equally-unconfirmed commit 1 and stayed there forever, because
// commit 1's own timer had been cancelled.
func (s *Store) CommitConfirmed(minutes int) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, fmt.Errorf("commit check failed: %w", err)
	}

	if minutes <= 0 {
		minutes = 10
	}

	// #1799 Option A: persist BEFORE promoting and BEFORE touching
	// any confirm state (see contract above).
	if err := s.writeActive(s.candidate); err != nil {
		return nil, fmt.Errorf("commit confirmed failed: persist active config: %w", err)
	}
	s.persistDegraded = false // disk now holds the current config
	// #1922 step-0: a commit confirmed persists the candidate as the
	// active config (committed=1 on disk via writeActive). The marker is
	// set here, NOT gated on confirmation — the on-disk DB is now a real
	// committed config; if the timer fires, the Item 1b first-commit
	// rollback path (prevCfg==nil) re-writes the never-committed marker.
	s.everCommitted = true
	s.persistMarkerCommitted = true

	if s.confirmTimer != nil {
		// Nested confirmed commit: cancel the pending timer but keep
		// the original rollback target (last confirmed config).
		s.confirmTimer.Stop()
		s.confirmTimer = nil
	} else {
		// Save current active state for potential rollback.
		s.confirmPrevTree = s.active.Clone()
		s.confirmPrevCfg = s.compiled
	}

	// Push current active to history
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
	})

	// Promote candidate to active
	s.active = s.candidate
	s.candidate = s.active.Clone()
	s.compiled = compiled
	s.dirty = false

	// Log to journal
	s.journalLog(&JournalEntry{
		Action:     "commit_confirmed",
		ConfigHash: journalConfigHash(s.active),
	})

	s.saveRollbackFiles()

	// Start auto-rollback timer. The closure captures the generation
	// at arm time; a stale callback from a superseded timer no-ops in
	// performAutoRollback.
	s.confirmGen++
	gen := s.confirmGen
	s.confirmTimer = time.AfterFunc(time.Duration(minutes)*time.Minute, func() {
		s.fireConfirmTimer(gen)
	})

	slog.Info("commit confirmed started", "timeout_minutes", minutes)
	return compiled, nil
}

// ConfirmCommit cancels the auto-rollback timer, confirming the config.
func (s *Store) ConfirmCommit() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.confirmTimer == nil {
		return fmt.Errorf("no pending confirmed commit")
	}

	s.confirmTimer.Stop()
	s.confirmGen++ // invalidate a callback that already fired and is blocked on s.mu
	s.confirmTimer = nil
	s.confirmPrevTree = nil
	s.confirmPrevCfg = nil

	slog.Info("commit confirmed")
	return nil
}

// IsConfirmPending returns true if a commit confirmed is awaiting confirmation.
func (s *Store) IsConfirmPending() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.confirmTimer != nil
}

// fireConfirmTimer is the commit-confirmed auto-rollback timer's expiry
// dispatch (#1922 Item 1a). It runs on the timer's own goroutine.
//
// It prefers the daemon-owned rollback transaction (rollbackExecutor) so
// store promotion + dataplane re-apply run atomically under the daemon
// apply semaphore — and so SERVICE-mode (gRPC/REST/remote-cli) timeouts
// re-apply the dataplane at all, which the old interactive-only callback
// never did. The executor is read under s.mu but invoked WITHOUT holding
// s.mu (it acquires applySem then re-enters the store via PromoteRollback;
// holding s.mu across that would invert the applySem->s.mu lock order).
// When no executor is registered (tests / non-daemon embedders) it falls
// back to the self-contained performAutoRollback (store-state only).
func (s *Store) fireConfirmTimer(gen uint64) {
	s.mu.Lock()
	exec := s.rollbackExecutor
	s.mu.Unlock()
	if exec != nil {
		exec(gen)
	} else {
		s.performAutoRollback(gen)
	}
}

// PromoteRollback performs ONLY the store-state half of a commit-confirmed
// timeout rollback, atomically under s.mu, and returns the compiled
// pre-confirmed config so the caller can re-apply it to the dataplane
// (#1922 Item 1a, Path Option B). The store is the single owner of the
// promotion primitive; the daemon's rollback executor holds the apply
// semaphore around this call + its own re-apply so promotion and re-apply
// are one critical section relative to a concurrent commit.
//
// gen must be the confirmGen captured when the calling timer was armed.
// A mismatch means the callback was superseded (nested CommitConfirmed
// re-armed, or ConfirmCommit confirmed) after it fired but before it took
// s.mu; rolling back would revert a NEWER commit to an older tree (Codex
// review on PR #1817). On mismatch — or when there is no pending rollback
// target (confirmPrevTree==nil, e.g. a stale/double timer fire) — this
// returns (nil, false) and mutates nothing.
//
// IMPORTANT: ok=true means "store state was promoted", NOT "prevCfg is
// non-nil". On a FIRST commit confirmed (fresh store) the rollback target
// tree is the empty pre-config tree (confirmPrevTree != nil) but the
// compiled config recorded at arm time is nil (a fresh store has
// active=&ConfigTree{} but compiled=nil). PromoteRollback then promotes
// the store back to the empty tree exactly as the prior performAutoRollback
// did and returns (nil, true). The caller MUST nil-check prevCfg before
// applying it to the dataplane — exactly as the old code's
// `if fn != nil && prevCfg != nil` guard did. Re-applying that
// first-commit-to-bootstrap case to the dataplane (and not persisting an
// empty *committed* tree) is #1922 Item 1b, DEFERRED to PR-2; this PR
// leaves that path's behavior unchanged (store reverts, dataplane is not
// re-applied). The #1817 confirmGen guard and #1799 persist-failure
// semantics are preserved verbatim.
func (s *Store) PromoteRollback(gen uint64) (prevCfg *config.Config, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if gen != s.confirmGen {
		return nil, false
	}
	if s.confirmPrevTree == nil {
		return nil, false
	}

	s.active = s.confirmPrevTree
	s.compiled = s.confirmPrevCfg
	if s.candidate != nil {
		s.candidate = s.active.Clone()
	}
	s.dirty = false

	s.confirmTimer = nil
	s.confirmPrevTree = nil
	// #1922 Item 1b: first-commit rollback target. On a fresh-store FIRST
	// commit confirmed, confirmPrevCfg is nil here, so prevCfg below is nil
	// and ok is true — the store reverts to the empty tree. The caller
	// (the daemon executor) detects prevCfg==nil and rolls the dataplane
	// back via enterBootstrapMode rather than applying an empty config.
	prevCfg = s.confirmPrevCfg
	s.confirmPrevCfg = nil
	firstCommitRollback := prevCfg == nil

	// Persist reverted config to disk. Option B (#1799): the rollback
	// ALWAYS proceeds in memory — reverting the running config is the
	// safety property — but a persist failure here used to leave the
	// UNCONFIRMED candidate on disk, so a reboot would load the config
	// the operator never confirmed. The degraded flag + singleton
	// retry make the failure visible (/health 503, gauge, journal
	// ERROR) and heal the disk in the background.
	//
	// #1922 Item 1b: on a first-commit rollback the reverted tree is the
	// empty bootstrap tree. It MUST be persisted with the never-committed
	// marker (committed=0), NOT as an operator-committed-empty config —
	// otherwise a subsequent restart would classify committed-empty =>
	// normal (Item 2 case 5) and take over interfaces on an empty config.
	// everCommitted is cleared so the in-memory predicate also reads
	// never-committed without a restart.
	var perr error
	if firstCommitRollback {
		// Record the never-committed marker for BOTH the immediate write
		// and the degraded-retry loop, so a failed-then-healed write still
		// persists committed=0 (Codex r1 release-blocker).
		s.persistMarkerCommitted = false
		s.everCommitted = false
		perr = s.writeActiveMarker(s.active, false)
	} else {
		s.persistMarkerCommitted = true
		perr = s.writeActive(s.active)
	}
	if perr != nil {
		s.noteActivePersistFailureLocked("auto_rollback", perr)
	} else {
		s.persistDegraded = false
	}

	// Log to journal
	s.journalLog(&JournalEntry{
		Action:     "auto_rollback",
		ConfigHash: journalConfigHash(s.active),
	})

	return prevCfg, true
}

// performAutoRollback is the self-contained fallback rollback used when no
// daemon rollback executor is registered (tests / non-daemon embedders).
// It promotes store state via PromoteRollback (the single promotion
// primitive); it does NOT re-apply the dataplane — a non-daemon embedder
// has no dataplane to re-apply, and the daemon path goes through
// SetRollbackExecutor + executeConfirmedRollback instead (#1922 Item 1a).
// gen must be the confirmGen captured when the calling timer was armed.
func (s *Store) performAutoRollback(gen uint64) {
	if _, ok := s.PromoteRollback(gen); !ok {
		return
	}
	slog.Warn("commit confirmed timed out, configuration rolled back")
}

// Rollback reverts the candidate to a previous configuration.
// n=0 reverts to active; n>0 reverts to the nth previous commit.
func (s *Store) Rollback(n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}

	if n == 0 {
		s.candidate = s.active.Clone()
		s.dirty = false
		return nil
	}

	entry, err := s.history.Get(n - 1)
	if err != nil {
		return err
	}
	s.candidate = entry.Config.Clone()
	s.dirty = true
	return nil
}

// ListHistory returns all history entries, most recent first (goroutine-safe).
func (s *Store) ListHistory() []*HistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.history.List()
}

// ListCommitHistory returns recent commit journal entries (most recent
// last). The journal read is bounded by limit (#1896): the tail scan
// stops after limit entries, so cost is O(limit), not O(lifetime
// journal). Semantics preserved from v1: the last `limit` entries of
// ANY action are read first, THEN filtered to commit actions — fewer
// than `limit` commits can come back when other actions interleave.
// limit <= 0 reads everything (persist_failure_test relies on it).
// No Store.mu needed: the journal serializes Log/Tail internally.
func (s *Store) ListCommitHistory(limit int) ([]*JournalEntry, error) {
	entries, err := s.journal.Tail(limit)
	if err != nil {
		return nil, err
	}
	// Filter to commit/rollback actions only
	var commits []*JournalEntry
	for _, e := range entries {
		switch e.Action {
		case "commit", "commit_confirmed", "auto_rollback":
			commits = append(commits, e)
		}
	}
	return commits, nil
}

// CommitDiffSummary returns a human-readable summary of changes between
// the active and candidate configs. Must be called while in config mode.
func (s *Store) CommitDiffSummary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return ""
	}

	activeSet := s.active.FormatSet()
	candidateSet := s.candidate.FormatSet()

	activeLines := splitLines(activeSet)
	candidateLines := splitLines(candidateSet)

	activeMap := make(map[string]bool, len(activeLines))
	for _, line := range activeLines {
		activeMap[line] = true
	}
	candidateMap := make(map[string]bool, len(candidateLines))
	for _, line := range candidateLines {
		candidateMap[line] = true
	}

	var added, removed int
	for _, line := range activeLines {
		if !candidateMap[line] {
			removed++
		}
	}
	for _, line := range candidateLines {
		if !activeMap[line] {
			added++
		}
	}

	total := added + removed
	if total == 0 {
		return ""
	}

	return fmt.Sprintf("%d statement(s) changed (%d added, %d removed)", total, added, removed)
}

// rollbackPath returns the file path for rollback slot n (1-based).
func (s *Store) rollbackPath(n int) string {
	return filepath.Join(filepath.Dir(s.filePath), fmt.Sprintf("%s.%d", filepath.Base(s.filePath), n))
}

// saveRollbackFiles writes rollback history entries to numbered files.
// Must be called under write lock.
//
// Durability split (#1894, adjudicated in the plan round): these files
// are the CANONICAL rollback history (loadRollbackHistory reads them at
// boot; the DB rollback slots have no production callers). Slot 1 — the
// immediate `rollback 1` target — is written durably; slots 2..N use
// the atomic writer (never missing, never torn, so loadRollbackHistory's
// break-on-first-missing stays sound; they may lag behind after a power
// cut). One trailing SyncDir then makes the whole shuffle AND the
// stale-slot unlinks durable for the cost of a single dir fsync,
// instead of ~50 file+dir fsync pairs under the store mutex.
func (s *Store) saveRollbackFiles() {
	if s.filePath == "" {
		return
	}

	entries := s.history.List() // most-recent-first
	degraded := false
	for i, entry := range entries {
		path := s.rollbackPath(i + 1)
		data := entry.Config.Format()
		var err error
		if i == 0 {
			err = rbWriteFileDurable(path, []byte(data), 0644)
		} else {
			err = rbWriteFileAtomic(path, []byte(data), 0644)
		}
		if err != nil {
			slog.Warn("failed to write rollback file", "path", path, "err", err)
			degraded = true
		}
	}
	s.cleanupRollbackFiles(len(entries) + 1)
	if len(entries) > 0 {
		if err := rbSyncDir(filepath.Dir(s.filePath)); err != nil {
			slog.Warn("failed to sync rollback directory", "err", err)
			degraded = true
		}
	}
	// #3441 L1: a rollback-slot write or dir-sync failure used to be
	// warning-only — the commit reported success and health stayed green
	// while xpf.conf.1 silently went missing/stale, so a restart loaded a
	// degraded text rollback history with no signal. Record the loss in a
	// degraded bit (surfaced via RollbackHistoryDegraded) and a journal
	// entry. The commit still succeeds: the canonical active config already
	// persisted durably via the #1799 persist-before-promote path; only the
	// best-effort text rollback copies are affected.
	if degraded && !s.rollbackPersistDegraded {
		s.journalLog(&JournalEntry{
			Action: "rollback_persist_error",
			Detail: "one or more rollback history files failed to persist; rollback history may be stale after restart",
		})
	}
	s.rollbackPersistDegraded = degraded
}

// cleanupRollbackFiles removes stale rollback files starting at startN.
//
// #3441 L3: stop only when a slot is genuinely absent (os.IsNotExist) — the
// contiguous-sequence invariant the loader assumes. A non-not-found remove
// error (e.g. EACCES, EBUSY) used to break the loop and leave higher slots
// behind, which then violated that invariant on the next boot; log and keep
// going so every reachable stale slot is cleared.
func (s *Store) cleanupRollbackFiles(startN int) {
	for i := startN; i <= s.history.MaxSize()+1; i++ {
		path := s.rollbackPath(i)
		if err := rbRemove(path); err != nil {
			if os.IsNotExist(err) {
				break // genuinely absent: contiguous sequence ends here
			}
			slog.Warn("failed to remove stale rollback file, continuing", "path", path, "err", err)
			continue
		}
	}
}

// loadRollbackHistory reads numbered rollback files and populates the history.
// Must be called under write lock.
func (s *Store) loadRollbackHistory() {
	if s.filePath == "" {
		return
	}

	var entries []*HistoryEntry
	for i := 1; i <= s.history.MaxSize(); i++ {
		path := s.rollbackPath(i)
		data, err := os.ReadFile(path)
		if err != nil {
			// #3441 L2: stop only at a genuinely missing slot (the
			// contiguous-sequence terminator). A transient/permission
			// error on an intermediate slot must NOT drop all the later
			// readable slots — log and continue so the rest of the
			// history still loads.
			if os.IsNotExist(err) {
				break
			}
			slog.Warn("error reading rollback file, continuing", "path", path, "err", err)
			continue
		}
		parser := config.NewParser(string(data))
		tree, errs := parser.Parse()
		if len(errs) > 0 {
			slog.Warn("skipping corrupt rollback file", "path", path, "err", errs[0])
			continue
		}
		// Use file modification time as timestamp
		info, _ := os.Stat(path)
		ts := time.Now()
		if info != nil {
			ts = info.ModTime()
		}
		entries = append(entries, &HistoryEntry{
			Config:    tree,
			Timestamp: ts,
		})
	}

	// Push oldest-first so History ordering is correct
	for i := len(entries) - 1; i >= 0; i-- {
		s.history.Push(entries[i])
	}

	if len(entries) > 0 {
		slog.Info("loaded rollback history", "entries", len(entries))
	}
}
