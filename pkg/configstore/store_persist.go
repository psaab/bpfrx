package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// Load builds the configuration from disk.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tree, committed, err := s.db.ReadActiveMeta()
	if err != nil {
		// A read/parse/decrypt/envelope failure on a PRESENT active.json is
		// the fail-closed case (#1917 increment B, D1): an unparseable or
		// too-new DB must NOT be silently overwritten by a blind bootstrap.
		// Tag it with ErrConfigDBUnreadable so the daemon can make it fatal
		// (daemon_run.go), distinct from a compile error (handled leniently
		// below) or an absent DB (handled above as start-fresh).
		return fmt.Errorf("read config: %w: %w", ErrConfigDBUnreadable, err)
	}
	if tree == nil {
		// Absent DB: start fresh. everCommitted stays false (a never-booted
		// store has never committed); the daemon's bootstrapFromFile may
		// import a preseeded xpf.conf, which resolves NOT-bootstrap on its
		// own (case 2). The #1922 step-0 marker only governs the DB-present
		// disambiguation.
		return nil
	}
	// #1922 step-0 marker: record whether the on-disk DB represents a
	// successfully-committed config. A legacy/older-build DB (no envelope
	// field) reads committed=true (migration rule C3), so an upgrade never
	// misclassifies an existing active config into bootstrap.
	s.everCommitted = committed
	// Seed the degraded-retry marker from the on-disk state too (Copilot
	// finding): if Load reads a never-committed DB (committed=0) and a later
	// persist failure triggers the #1799 retry loop BEFORE any commit/sync
	// resets the marker, the retry must re-write committed=0 — not the
	// New() default of true, which would silently heal the never-committed
	// marker into an operator-committed-empty DB and re-enable takeover.
	s.persistMarkerCommitted = committed

	// Rolling-upgrade tolerance (#1373 / #1525): a node may boot
	// with `system dataplane-type ebpf` or `... dpdk` persisted
	// from before the retirement-strict validator landed. Without
	// this rewrite, compileTree below returns
	// ErrEBPFDataplaneRetired / ErrDPDKDataplaneRetired, the daemon
	// gets nil active config, and bootstraps blind. Rewriting the
	// leaf to absent (defaults to userspace) lets the daemon come
	// up so the operator can fix the config from CLI.
	rewriteRetiredDataplaneType(tree, LoadCaller)

	// #1798 migration: a persisted free-text value carrying control
	// characters (e.g. a "lan\nDHCP=ipv4" description committed before
	// the strict commit-time gate landed) must neither fail boot now
	// nor make the operator's next unrelated commit fail mysteriously.
	// Scrub the tree in place with a warning — this tree becomes the
	// active config (and the candidate clones from it), so the next
	// strict commit sees only clean values.
	for _, p := range config.SanitizeTreeControlChars(tree) {
		slog.Warn("sanitized control characters in persisted config value",
			"path", p, "issue", "#1798")
	}

	// Tolerant compile: an already-persisted config must boot through
	// (see compileTreeLenient for the validator downgrades).
	compiled, err := s.compileTreeLenient(tree)
	if err != nil {
		// #1960 fail-closed: the bytes read+parsed fine (this is NOT
		// ErrConfigDBUnreadable) but a PRESENT, previously-committed config
		// no longer compiles. s.everCommitted was already set true above, so
		// the daemon could otherwise see ActiveConfig()==nil + everCommitted
		// and resolve to NORMAL boot — positional claim-all interface naming.
		// Tag the error with ErrConfigCompile so the daemon can detect this
		// edge with errors.Is and refuse takeover (enter the #1922
		// bootstrap/lifeline safe state) instead.
		//
		// s.compiled MUST stay nil — ActiveConfig() returns s.compiled, and
		// nil is precisely the signal that forces bootstrap (computeBootClass).
		// BUT retain the parsed-but-broken tree as s.active and load rollback
		// history, so the recovery the daemon advertises ("fix the config from
		// the CLI/gRPC and commit, or roll back") actually works (Codex #1991
		// r1): EnterConfigure clones s.active into the candidate, so `configure`
		// + `show | compare` surface the broken stanza for the operator to fix,
		// and Rollback(n) / `show | compare rollback n` reach the on-disk
		// history. Without this, s.active stayed the empty New() tree and the
		// history was never loaded — the operator saw an empty config and no
		// rollbacks, with no in-band way to recover. s.active is always non-nil
		// (New seeds an empty tree), so the (active non-nil, compiled nil) shape
		// here is the same one a fresh boot already has — no new invariant.
		s.active = tree
		s.loadRollbackHistory()
		return fmt.Errorf("compile config: %w: %w", ErrConfigCompile, err)
	}

	s.active = tree
	s.compiled = compiled
	s.loadRollbackHistory()
	return nil
}

// Save persists the active configuration to disk.
func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.writeActive(s.active)
}

// writeActive persists tree as the on-disk active configuration.
// Routes through the writeActiveFn test seam when set (#1799);
// otherwise uses the DB's durable temp + fsync + rename + dir-fsync
// write (#1894). Caller must hold s.mu (read or write lock).
func (s *Store) writeActive(tree *config.ConfigTree) error {
	if s.writeActiveFn != nil {
		return s.writeActiveFn(tree)
	}
	return s.db.WriteActive(tree)
}

// writeActiveMarker persists tree as the on-disk active config with an
// explicit #1922 step-0 committed marker. committed=false writes the
// never-committed marker (Item 1b first-commit rollback). Routes through
// the writeActiveMarkerFn test seam when set; otherwise the production
// DB.WriteActiveMarker. Caller must hold s.mu. When only the legacy
// writeActiveFn seam is set (older tests), the marker degrades to that seam
// (the committed bit is not observable through it, which is acceptable for
// those tests — the marker behavior has dedicated coverage via the DB seam).
func (s *Store) writeActiveMarker(tree *config.ConfigTree, committed bool) error {
	if s.writeActiveMarkerFn != nil {
		return s.writeActiveMarkerFn(tree, committed)
	}
	if s.writeActiveFn != nil {
		return s.writeActiveFn(tree)
	}
	return s.db.WriteActiveMarker(tree, committed)
}

// journalLog appends an audit entry; a failure is surfaced as a
// warning only — journaling must never fail a commit/sync/rollback,
// and the persist_error path must not recurse into journaling its own
// failure (#1896).
func (s *Store) journalLog(e *JournalEntry) {
	if err := s.journal.Log(e); err != nil {
		slog.Warn("config journal append failed", "action", e.Action, "err", err)
	}
}

// journalConfigHash returns the sha256 hex of the tree's Format() text
// — the same text saveRollbackFiles writes to rollback slots, so a
// retained rollback file can be correlated to its journal entry with
// `sha256sum` (#1896). Best-effort correlation: slots shift on every
// commit and only history.MaxSize() of them are kept.
func journalConfigHash(tree *config.ConfigTree) string {
	if tree == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(tree.Format()))
	return hex.EncodeToString(sum[:])
}

// ConfigPersistDegraded reports whether the running active config
// failed to persist to disk on an Option-B path (SyncApply /
// performAutoRollback) and the background retry has not yet succeeded
// (#1799). While true, a daemon restart would load a STALE config;
// /health returns 503 and xpf_daemon_config_persist_degraded reads 1.
func (s *Store) ConfigPersistDegraded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.persistDegraded
}

// noteActivePersistFailureLocked records a WriteActive failure on an
// Option-B path (#1799): the in-memory apply already happened (HA
// convergence / auto-rollback safety win over disk trouble), so the
// failure must become visible and self-healing instead of fatal.
// Flips the degraded flag, writes a journal ERROR entry, and starts
// the singleton retry goroutine. Must be called with s.mu held
// (write lock).
func (s *Store) noteActivePersistFailureLocked(action string, err error) {
	slog.Error("active config persist failed — running config is not durable; restart would load stale config",
		"action", action, "err", err, "issue", "#1799")
	s.persistDegraded = true
	// The retry loop re-writes s.active with the marker last requested by the
	// failing path. Callers that need the never-committed marker (Item 1b)
	// set s.persistMarkerCommitted=false BEFORE invoking this; all other
	// paths leave it at the default true.
	s.journalLog(&JournalEntry{
		Action: "persist_error",
		Detail: fmt.Sprintf("%s: write active config failed: %v", action, err),
	})
	if s.persistRetryActive {
		return
	}
	s.persistRetryActive = true
	initial := s.persistRetryInitialBackoff
	if initial <= 0 {
		initial = time.Second
	}
	maxBackoff := s.persistRetryMaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 60 * time.Second
	}
	go s.persistRetryLoop(initial, maxBackoff)
}

// persistRetryLoop retries persisting the CURRENT active config with
// doubling backoff until a write succeeds or the degraded flag is
// cleared by a successful write on another path (#1799). Each attempt
// re-reads s.active under s.mu and writes while holding the lock —
// never a stale captured tree — so rapid successive syncs cannot
// persist out-of-order state (the commit paths themselves write under
// s.mu, so lock-held writes are the existing serialization).
//
// Shutdown safety: the Store has no close signal, and none is needed.
// This is a plain goroutine outside any WaitGroup — it sleeps between
// attempts and holds s.mu only for the duration of one atomic
// temp-file write, so it cannot block daemon shutdown; process exit
// simply abandons it.
func (s *Store) persistRetryLoop(backoff, maxBackoff time.Duration) {
	for {
		time.Sleep(backoff)
		s.mu.Lock()
		if !s.persistDegraded {
			// A successful write on a commit/sync path already
			// persisted the current active config.
			s.persistRetryActive = false
			s.mu.Unlock()
			return
		}
		// #1922: re-write with the marker the failing path requested
		// (committed=false only for a first-commit rollback). For every
		// other path persistMarkerCommitted is true, so this matches the
		// pre-#1922 committed=1 write exactly.
		err := s.writeActiveMarker(s.active, s.persistMarkerCommitted)
		if err == nil {
			s.persistDegraded = false
			s.persistRetryActive = false
			s.journalLog(&JournalEntry{
				Action: "persist_recovered",
				Detail: "active config persisted after earlier write failure",
			})
			s.mu.Unlock()
			slog.Info("active config persisted after earlier write failure", "issue", "#1799")
			return
		}
		s.mu.Unlock()
		slog.Warn("active config persist retry failed", "err", err, "retry_in", backoff*2)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// SetArchiveConfig configures automatic archival on commit.
func (s *Store) SetArchiveConfig(dir string, max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.archiveDir = dir
	s.archiveMax = max
}

// ArchiveConfig saves a timestamped copy of the active config. The active
// text and the timestamp are captured together under the lock so the
// written archive matches the config that was active at the call (#3441 H4),
// then the actual write happens off-lock via writeArchive.
func (s *Store) ArchiveConfig(archiveDir string, maxArchives int) error {
	s.mu.RLock()
	data := s.active.Format()
	s.mu.RUnlock()
	return writeArchive(archiveDir, maxArchives, data, time.Now())
}

// writeArchive writes the captured config text to a uniquely-named archive
// file and rotates old archives. data and ts are immutable values captured
// by the caller; writeArchive never reads shared store state, so it is safe
// to call from the async auto-archive goroutine.
//
// #3441 H4: the filename carries a nanosecond-resolution timestamp
// (config-YYYYMMDD-HHMMSS.nnnnnnnnn.conf). The previous second-resolution
// name let two same-second commits resolve to the same path, so the later
// atomic write silently overwrote the earlier archive. Nanosecond precision
// makes each commit's archive a distinct, never-overwritten file while still
// sorting chronologically for rotateArchives. (An alternative is an O_EXCL
// open with a retry-on-EEXIST seq suffix; the per-commit nanosecond ts is
// simpler and unique across process restarts too.)
func writeArchive(archiveDir string, maxArchives int, data string, ts time.Time) error {
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return fmt.Errorf("create archive dir: %w", err)
	}

	filename := fmt.Sprintf("config-%s.conf", ts.Format("20060102-150405.000000000"))
	path := filepath.Join(archiveDir, filename)
	// AtomicGeneratedConfig (#1894): archives are best-effort history
	// copies — atomic so a crash never leaves a torn archive, but not
	// worth an fsync.
	if err := rbWriteFileAtomic(path, []byte(data), 0644); err != nil {
		return fmt.Errorf("write archive: %w", err)
	}

	slog.Info("config archived", "path", path)

	// Rotate old archives
	if maxArchives > 0 {
		rotateArchives(archiveDir, maxArchives)
	}
	return nil
}

// RollbackHistoryDegraded reports whether the most recent commit failed to
// durably persist its text rollback history files (#3441 L1). The commit
// itself still succeeded — the canonical active config persisted via the
// #1799 path — but loadRollbackHistory would read a stale/lossy history
// after a restart. Surfaced so callers (status/health) can report the loss
// instead of it being warning-only.
func (s *Store) RollbackHistoryDegraded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rollbackPersistDegraded
}

// rotateArchives keeps only the most recent maxArchives files.
func rotateArchives(dir string, maxArchives int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var archives []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "config-") && strings.HasSuffix(e.Name(), ".conf") {
			archives = append(archives, e.Name())
		}
	}

	if len(archives) <= maxArchives {
		return
	}

	// Sort alphabetically (timestamps sort naturally)
	sort.Strings(archives)

	// Remove oldest
	for i := 0; i < len(archives)-maxArchives; i++ {
		path := filepath.Join(dir, archives[i])
		if err := os.Remove(path); err != nil {
			slog.Warn("failed to remove old archive", "path", path, "err", err)
		}
	}
}

// rescuePath returns the path for the rescue configuration file.
func (s *Store) rescuePath() string {
	return filepath.Join(filepath.Dir(s.filePath), "rescue.conf")
}

// SaveRescueConfig saves the active config as rescue configuration.
func (s *Store) SaveRescueConfig() error {
	s.mu.RLock()
	data := s.active.Format()
	s.mu.RUnlock()

	path := s.rescuePath()
	// DurableState (#1894): the rescue config is the operator's
	// explicitly-requested safety net — it must survive power loss.
	if err := fsatomic.WriteFileDurable(path, []byte(data), 0644); err != nil {
		return fmt.Errorf("save rescue config: %w", err)
	}
	slog.Info("rescue configuration saved", "path", path)
	return nil
}

// DeleteRescueConfig removes the rescue configuration.
func (s *Store) DeleteRescueConfig() error {
	path := s.rescuePath()
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no rescue configuration exists")
		}
		return fmt.Errorf("delete rescue config: %w", err)
	}
	slog.Info("rescue configuration deleted", "path", path)
	return nil
}

// LoadRescueConfig returns the rescue configuration text, or "" if none.
func (s *Store) LoadRescueConfig() (string, error) {
	path := s.rescuePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read rescue config: %w", err)
	}
	return string(data), nil
}
