// Package configstore implements the Junos-style candidate/active
// configuration management with commit and rollback support.
package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore/journal"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// JournalEntry is the audit-log record type, owned by the journal
// subpackage since #1896 (compact v2 entries: no config payloads —
// full trees live in the rollback slots; see journal.Entry).
type JournalEntry = journal.Entry

// Store manages the candidate and active configuration.
type Store struct {
	mu        sync.RWMutex
	active    *config.ConfigTree
	candidate *config.ConfigTree
	compiled  *config.Config // compiled active config
	history   *History
	dirty     bool
	configDir bool // true if in configuration mode
	filePath  string

	// Persistent storage
	db      *DB
	journal *journal.Journal

	// writeActiveFn is a test seam for active-config persistence
	// (#1799). nil (production) means s.db.WriteActive. Set via
	// SetWriteActiveForTesting; never assigned on production paths.
	writeActiveFn func(*config.ConfigTree) error

	// #1799 Option B (degrade-not-fail) state for the persist paths
	// that must proceed in memory even when the disk write fails
	// (SyncApply HA convergence, performAutoRollback safety revert).
	// persistDegraded is surfaced via ConfigPersistDegraded() to the
	// /health 503 check and the xpf_daemon_config_persist_degraded
	// gauge. persistRetryActive is the singleton guard for the
	// background retry goroutine (exactly one loop at a time). The
	// backoff fields are test seams; zero means the production
	// defaults (1s initial, doubling to a 60s cap).
	persistDegraded            bool
	persistRetryActive         bool
	persistRetryInitialBackoff time.Duration
	persistRetryMaxBackoff     time.Duration

	// Commit confirmed state. confirmGen is a generation token
	// guarding the auto-rollback callback against staleness: a timer
	// that has already fired and is blocked on s.mu when a nested
	// CommitConfirmed (or ConfirmCommit) supersedes it must become a
	// no-op — time.Timer.Stop() cannot un-fire a callback that has
	// started (Codex review on PR #1817). Every arm/confirm bumps the
	// generation; the callback carries the value at arm time and
	// performAutoRollback rejects mismatches.
	confirmGen      uint64
	confirmTimer    *time.Timer
	confirmPrevTree *config.ConfigTree // active tree before confirmed commit
	confirmPrevCfg  *config.Config     // compiled config before confirmed commit

	// rollbackExecutor is the daemon-registered transaction that owns
	// the WHOLE commit-confirmed timeout rollback (#1922 Item 1a). When
	// set, the auto-rollback timer hands it the confirm generation and
	// the executor acquires the daemon's apply semaphore FIRST, then
	// calls PromoteRollback (store-state promotion) + the dataplane
	// re-apply inside that one critical section. This makes promotion and
	// re-apply atomic with respect to a concurrent commit (which also
	// holds applySem), closing the store-vs-kernel split-brain window of
	// the old centralRollbackFn callback. It also wires the rollback in
	// SERVICE mode (gRPC/REST/remote-cli), where no interactive CLI.Run
	// ever registered the old callback. When nil (tests, non-daemon
	// embedders such as the standalone `cli` binary) the timer falls back
	// to performAutoRollback, which stays self-contained and correct for
	// that path.
	rollbackExecutor func(gen uint64)

	// Exclusive configuration mode
	exclusiveHolder string // who holds exclusive lock (empty = unlocked)

	// Config lock tracking: session ID of the holder (for auto-release on disconnect)
	configHolder string    // unique session ID of the config lock holder
	configLockAt time.Time // when the lock was acquired

	// Cluster read-only mode: secondary nodes reject config mutations
	clusterReadOnly bool

	// Cluster node ID for ${node} variable expansion in apply-groups.
	// -1 means non-cluster (use CompileConfig), >= 0 means use CompileConfigForNode.
	nodeID int

	// Edit path for hierarchical navigation (edit/top/up)
	editPath []string

	// Archival settings
	archiveDir string // local archive directory (empty = disabled)
	archiveMax int    // max archives to keep
}

// New creates a new config store. It fails closed when the .configdb
// directory cannot be created (#1893): there is no file-only fallback
// backend — every persistence path (Load, writeActive, the #1799
// persist-retry goroutine) dereferences the DB, so constructing a Store
// without one would trade this precise boot-time error for a delayed
// nil-pointer panic on the first Load/Save/commit.
func New(filePath string) (*Store, error) {
	dbDir := filepath.Join(filepath.Dir(filePath), ".configdb")
	db, err := NewDB(dbDir)
	if err != nil {
		return nil, fmt.Errorf("config db %s unusable: %w (no file-only fallback exists; refusing to run without config persistence)", dbDir, err)
	}

	journalPath := filepath.Join(filepath.Dir(filePath), ".config.journal")

	return &Store{
		active:   &config.ConfigTree{},
		history:  NewHistory(50),
		filePath: filePath,
		db:       db,
		journal:  journal.New(journalPath),
		nodeID:   -1,
	}, nil
}

// SetConfigDBWriterVersion sets the xpf build version stamped into the
// config-DB compatibility-envelope header on write (#1917 increment B).
// Call once at startup before any Commit/Save; the daemon's single init
// path is the only caller.
func (s *Store) SetConfigDBWriterVersion(v string) {
	s.db.SetWriterVersion(v)
}

// Load builds the configuration from disk.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tree, err := s.db.ReadActive()
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
		return nil // start fresh with empty config
	}

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
		return fmt.Errorf("compile config: %w", err)
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
		err := s.writeActive(s.active)
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

// SetClusterReadOnly toggles cluster read-only mode. When enabled, config
// mutations (EnterConfigure, Commit, Load, Set, Delete) are rejected.
// Used to prevent config changes on secondary cluster nodes.
func (s *Store) SetClusterReadOnly(ro bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clusterReadOnly = ro
}

// ClusterReadOnly returns whether the store is in cluster read-only mode.
func (s *Store) ClusterReadOnly() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clusterReadOnly
}

// SetNodeID sets the cluster node ID for ${node} variable expansion in
// apply-groups. Use -1 (default) for non-cluster mode.
func (s *Store) SetNodeID(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodeID = id
}

// compileTree compiles a config tree using the appropriate method based on
// whether the store is in cluster mode (nodeID >= 0) or standalone.
//
// Order of operations (#1319): the typed-leaf SchemaValidate gate runs
// BEFORE compile, but against the same apply-groups-expanded view the
// compiler consumes. Running on the raw candidate tree would let invalid
// typed leaves inside `groups { ... }` bypass the gate while still reaching
// the compiler after expansion. We still validate at commit time rather
// than at `set` time so the candidate-edit flow stays permissive —
// operators can stage half-typed values without each `set` line being
// rejected — and `commit check` is the one place that fails loud on garbage
// like `transmit-rate asd`. The tolerant Load/SyncApply ingress goes through
// compileTreeLenient below, which downgrades the same gate to a warning
// (#1319 PR 2 boot safety). cfg is nil at this point because we haven't
// compiled yet; the typed-leaf validators shipped so far don't need it.
func (s *Store) compileTree(tree *config.ConfigTree) (*config.Config, error) {
	return compileTreeStrict(tree, s.nodeID)
}

// compileTreeStrict is the package-level strict commit-check pipeline
// (typed-leaf SchemaValidate gate on the apply-groups-expanded view,
// then strict compile). It backs both Store.compileTree (every
// operator-driven commit / commit-check) and CheckText (check.go —
// the #1879 `xpfd check-config` day-0 validation gate), so the two
// callers can never drift apart.
func compileTreeStrict(tree *config.ConfigTree, nodeID int) (*config.Config, error) {
	if err := schemaValidateExpandedTreeForNode(tree, nodeID); err != nil {
		return nil, err
	}
	if nodeID >= 0 {
		return config.CompileConfigForNode(tree, nodeID)
	}
	return config.CompileConfig(tree)
}

// compileTreeLenient is compileTree with the tolerant-path validator
// downgrades enabled (config.CompileConfigLenient /
// CompileConfigForNodeLenient: #1798 control-char sanitize, lenient
// VRRP track duplicates). It is used ONLY by the passive load
// (Store.Load) and HA peer-sync (Store.SyncApply) ingress paths, NOT by
// any operator-driven candidate commit / commit-check path.
//
// Rationale: Store.Load and Store.SyncApply compile a config the operator
// did NOT just author — a persisted active config on local boot, or a
// config pushed from a possibly-un-upgraded cluster primary. A strict
// reject here would (a) fail Store.Load on an upgraded node carrying a
// legacy config, leaving the daemon with no active config (operational
// blackout), and (b) fail Store.SyncApply on an upgraded standby
// receiving such a config from an un-upgraded primary, alarm-looping HA
// config sync. The operator's next strict candidate commit rejects it.
//
// (The original #1733 equal-flow worker-cap downgrade that motivated
// this split was retired in #1830 (e) — the dataplane no longer caps
// equal-flow-enforcement at 32 workers.)
func (s *Store) compileTreeLenient(tree *config.ConfigTree) (*config.Config, error) {
	// #1319 PR 2: the typed-leaf SchemaValidate gate is STRICT only on the
	// operator-driven commit / commit-check path (compileTree). Here — the
	// tolerant Store.Load / Store.SyncApply ingress for configs the
	// operator did NOT just author — a violation downgrades to a warning.
	// A persisted config written by an older binary (pre-gate, or before a
	// leaf's range was typed/tightened) may carry values the current gate
	// rejects; hard-failing would blackout-boot the node (Load) or
	// alarm-loop HA config sync (SyncApply), even though the compiler
	// accepted the value when it was committed and still compiles it the
	// same way today. This is the same doctrine as the #1733/#1798/#1814
	// lenient compile gates (see freetext.go); the operator's next strict
	// commit rejects the stale value loudly.
	if err := s.schemaValidateExpandedTree(tree); err != nil {
		slog.Warn("typed-leaf schema violation in tolerated config; continuing (a strict commit would reject this)",
			"err", err, "issue", "#1319")
	}
	if s.nodeID >= 0 {
		return config.CompileConfigForNodeLenient(tree, s.nodeID)
	}
	return config.CompileConfigLenient(tree)
}

func (s *Store) schemaValidateExpandedTree(tree *config.ConfigTree) error {
	return schemaValidateExpandedTreeForNode(tree, s.nodeID)
}

func schemaValidateExpandedTreeForNode(tree *config.ConfigTree, nodeID int) error {
	if tree == nil {
		return nil
	}
	expanded := tree.Clone()
	if nodeID >= 0 {
		vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
		if err := expanded.ExpandGroupsWithVars(vars); err != nil {
			return fmt.Errorf("apply-groups: %w", err)
		}
		// Pass the PRE-expansion candidate as the cross-reference
		// definitions source: expansion removes the groups stanza, and
		// definitions living only in un-applied peer-node groups must
		// keep satisfying shared-section references (#1319 PR 3).
		return config.SchemaValidateWithDefinitions(expanded, tree, nil)
	}
	if err := expanded.ExpandGroups(); err != nil {
		if strings.Contains(err.Error(), `undefined group "${node}"`) {
			vars := map[string]string{"node": "node0"}
			if err2 := expanded.ExpandGroupsWithVars(vars); err2 != nil {
				return fmt.Errorf("apply-groups: %w", err2)
			}
		} else {
			return fmt.Errorf("apply-groups: %w", err)
		}
	}
	return config.SchemaValidateWithDefinitions(expanded, tree, nil)
}

// SyncApply applies a config received from the cluster primary.
// Bypasses cluster read-only checks. The chassisPreserve function, if set,
// lets the caller patch the parsed tree before compiling (e.g. to preserve
// local chassis cluster settings).
func (s *Store) SyncApply(content string, chassisPreserve func(*config.ConfigTree)) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tree, errs := config.NewParser(content).Parse()
	if len(errs) > 0 {
		return nil, fmt.Errorf("sync config parse error: %v", errs[0])
	}

	// Let caller patch the tree (e.g. preserve local chassis cluster settings).
	if chassisPreserve != nil {
		chassisPreserve(tree)
	}

	// Rolling-upgrade tolerance (AGY r4 finding on #1476): an
	// un-upgraded primary may push a config that still selects
	// the retired DPDK or eBPF dataplane. Strict-validator-driven
	// sync rejection would alarm-loop the cluster. Rewrite the
	// retired leaf so the standby boots through cleanly while the
	// operator updates the primary.
	rewriteRetiredDataplaneType(tree, SyncCaller)

	// #1798 migration: same tolerance as Load — a peer-synced config
	// from a possibly-un-upgraded primary may carry control characters
	// in free-text values. Scrub the tree in place with a warning so
	// HA config sync does not alarm-loop and the standby's stored tree
	// stays clean for any later strict commit.
	for _, p := range config.SanitizeTreeControlChars(tree) {
		slog.Warn("sanitized control characters in peer-synced config value",
			"path", p, "issue", "#1798")
	}

	// Tolerant compile: a config peer-synced from a possibly-un-upgraded
	// primary must not alarm-loop HA sync (see compileTreeLenient for
	// the validator downgrades).
	compiled, err := s.compileTreeLenient(tree)
	if err != nil {
		return nil, fmt.Errorf("sync config compile error: %w", err)
	}

	// Push current active to history.
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
	})

	s.active = tree
	s.compiled = compiled
	s.dirty = false

	// If in config mode, update candidate too.
	if s.configDir {
		s.candidate = s.active.Clone()
	}

	// #1799 Option B (degrade-not-fail): the in-memory apply above
	// MUST stand even if the disk write fails — failing the
	// secondary's apply on local disk trouble would silently diverge
	// the cluster (sync is one-way fire-and-forget; the primary is
	// already running the new config and is never notified). The
	// failure becomes visible (degraded flag → /health 503 +
	// Prometheus gauge + journal ERROR) and self-healing (singleton
	// background retry with backoff).
	if err := s.writeActive(s.active); err != nil {
		s.noteActivePersistFailureLocked("config_sync", err)
	} else {
		s.persistDegraded = false
	}

	s.journalLog(&JournalEntry{
		Action:     "config_sync",
		ConfigHash: journalConfigHash(s.active),
	})

	s.saveRollbackFiles()
	return compiled, nil
}

// EnterConfigure enters configuration mode by cloning the active config.
// Returns an error if another session is already in config mode.
func (s *Store) EnterConfigure() error {
	return s.EnterConfigureSession("")
}

// EnterConfigureSession enters configuration mode with a session identifier.
// If the same session already holds the lock, it's a no-op.
func (s *Store) EnterConfigureSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clusterReadOnly {
		return fmt.Errorf("configuration database is not writable (secondary node)")
	}
	if s.configDir {
		// Allow re-entry by same session.
		if sessionID != "" && s.configHolder == sessionID {
			return nil
		}
		return fmt.Errorf("configuration is locked by another user")
	}
	s.candidate = s.active.Clone()
	s.configDir = true
	s.dirty = false
	s.configHolder = sessionID
	s.configLockAt = time.Now()
	return nil
}

// EnterConfigureExclusive enters exclusive configuration mode.
func (s *Store) EnterConfigureExclusive(holder string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clusterReadOnly {
		return fmt.Errorf("configuration database is not writable (secondary node)")
	}
	if s.configDir {
		return fmt.Errorf("configuration is locked by another user")
	}
	s.candidate = s.active.Clone()
	s.configDir = true
	s.dirty = false
	s.exclusiveHolder = holder
	s.configLockAt = time.Now()
	return nil
}

// ExitConfigureSession exits configuration mode only if the given session holds
// the lock. Returns true if the lock was released.
func (s *Store) ExitConfigureSession(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configDir {
		return false
	}
	if sessionID != "" && s.configHolder != sessionID {
		return false
	}
	s.candidate = nil
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.configHolder = ""
	s.editPath = nil
	return true
}

// ForceExitConfigure exits configuration mode regardless of who holds the lock.
// Used for stale lock cleanup.
func (s *Store) ForceExitConfigure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configDir {
		return
	}
	slog.Warn("force-releasing stale config lock", "holder", s.configHolder,
		"held_for", time.Since(s.configLockAt).Round(time.Second))
	s.candidate = nil
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.configHolder = ""
	s.editPath = nil
}

// ConfigHolder returns the session ID of the current config lock holder
// and whether the lock is held.
func (s *Store) ConfigHolder() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configHolder, s.configDir
}

// IsExclusiveLocked returns true if exclusive mode is active.
func (s *Store) IsExclusiveLocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exclusiveHolder != ""
}

// ExitConfigure exits configuration mode, discarding the candidate.
func (s *Store) ExitConfigure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidate = nil
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.editPath = nil
}

// SetEditPath sets the edit path for hierarchical navigation.
func (s *Store) SetEditPath(path []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.editPath = path
}

// GetEditPath returns a copy of the current edit path.
func (s *Store) GetEditPath() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.editPath...)
}

// NavigateUp moves the edit path up one level.
func (s *Store) NavigateUp() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.editPath) > 0 {
		s.editPath = s.editPath[:len(s.editPath)-1]
	}
}

// NavigateTop resets the edit path to the root.
func (s *Store) NavigateTop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.editPath = nil
}

// InConfigMode returns true if currently in configuration mode.
func (s *Store) InConfigMode() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configDir
}

// IsDirty returns true if the candidate differs from active.
func (s *Store) IsDirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dirty
}

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

	// Detect format: if content has "set " lines, process as set commands
	lines := strings.Split(content, "\n")
	isSetFormat := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "set ") || strings.HasPrefix(trimmed, "delete ") {
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
			if strings.HasPrefix(trimmed, "set ") {
				path, err := config.ParseSetCommand(trimmed)
				if err != nil {
					return fmt.Errorf("line %q: %w", trimmed, err)
				}
				if err := s.candidate.SetPath(path); err != nil {
					return fmt.Errorf("line %q: %w", trimmed, err)
				}
			} else if strings.HasPrefix(trimmed, "delete ") {
				path, err := config.ParseSetCommand(trimmed)
				if err != nil {
					return fmt.Errorf("line %q: %w", trimmed, err)
				}
				if err := s.candidate.DeletePath(path); err != nil {
					return fmt.Errorf("line %q: %w", trimmed, err)
				}
			}
		}
	} else {
		// Parse as hierarchical config and merge each top-level node
		tree, errs := config.NewParser(content).Parse()
		if len(errs) > 0 {
			return fmt.Errorf("parse error: %v", errs[0])
		}
		// Convert hierarchical to set commands and apply each one
		setLines := strings.Split(tree.FormatSet(), "\n")
		for _, line := range setLines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			path, err := config.ParseSetCommand(trimmed)
			if err != nil {
				continue
			}
			if err := s.candidate.SetPath(path); err != nil {
				return fmt.Errorf("merge: %w", err)
			}
		}
	}

	s.dirty = true
	return nil
}

// LoadSet applies multiple set commands to the candidate config.
// Each line starting with "set " is parsed and applied.
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
		if !strings.HasPrefix(line, "set ") {
			continue
		}
		path, err := config.ParseSetCommand(line)
		if err != nil {
			return count, fmt.Errorf("line %q: %w", line, err)
		}
		if err := s.candidate.SetPath(path); err != nil {
			return count, fmt.Errorf("line %q: %w", line, err)
		}
		count++
	}
	s.dirty = true
	return count, nil
}

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
	s.persistDegraded = false // disk now holds the current config

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

	// Auto-archive if configured
	if s.archiveDir != "" {
		max := s.archiveMax
		if max <= 0 {
			max = 10
		}
		go func() {
			if err := s.ArchiveConfig(s.archiveDir, max); err != nil {
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
	// #1922 Item 1b (PR-2): first-commit rollback target. On a fresh-store
	// FIRST commit confirmed, confirmPrevCfg is nil here, so prevCfg below
	// is nil and ok is true — the store reverts to the empty tree but the
	// caller skips the dataplane re-apply (prevCfg==nil guard). Rolling
	// that case back to bootstrap + persisting a never-committed marker
	// instead of an empty committed tree is DEFERRED to PR-2.
	prevCfg = s.confirmPrevCfg
	s.confirmPrevCfg = nil

	// Persist reverted config to disk. Option B (#1799): the rollback
	// ALWAYS proceeds in memory — reverting the running config is the
	// safety property — but a persist failure here used to leave the
	// UNCONFIRMED candidate on disk, so a reboot would load the config
	// the operator never confirmed. The degraded flag + singleton
	// retry make the failure visible (/health 503, gauge, journal
	// ERROR) and heal the disk in the background.
	if err := s.writeActive(s.active); err != nil {
		s.noteActivePersistFailureLocked("auto_rollback", err)
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
	for i, entry := range entries {
		path := s.rollbackPath(i + 1)
		data := entry.Config.Format()
		var err error
		if i == 0 {
			err = fsatomic.WriteFileDurable(path, []byte(data), 0644)
		} else {
			err = fsatomic.WriteFileAtomic(path, []byte(data), 0644)
		}
		if err != nil {
			slog.Warn("failed to write rollback file", "path", path, "err", err)
		}
	}
	s.cleanupRollbackFiles(len(entries) + 1)
	if len(entries) > 0 {
		if err := fsatomic.SyncDir(filepath.Dir(s.filePath)); err != nil {
			slog.Warn("failed to sync rollback directory", "err", err)
		}
	}
}

// cleanupRollbackFiles removes stale rollback files starting at startN.
func (s *Store) cleanupRollbackFiles(startN int) {
	for i := startN; i <= s.history.MaxSize()+1; i++ {
		path := s.rollbackPath(i)
		if err := os.Remove(path); err != nil {
			break // stop on first not-found (contiguous sequence)
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
			break // stop on first not-found
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

// SetArchiveConfig configures automatic archival on commit.
func (s *Store) SetArchiveConfig(dir string, max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.archiveDir = dir
	s.archiveMax = max
}

// ArchiveConfig saves a timestamped copy of the active config.
func (s *Store) ArchiveConfig(archiveDir string, maxArchives int) error {
	s.mu.RLock()
	data := s.active.Format()
	s.mu.RUnlock()

	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return fmt.Errorf("create archive dir: %w", err)
	}

	filename := fmt.Sprintf("config-%s.conf", time.Now().Format("20060102-150405"))
	path := filepath.Join(archiveDir, filename)
	// AtomicGeneratedConfig (#1894): archives are best-effort history
	// copies — atomic so a crash never leaves a torn archive, but not
	// worth an fsync.
	if err := fsatomic.WriteFileAtomic(path, []byte(data), 0644); err != nil {
		return fmt.Errorf("write archive: %w", err)
	}

	slog.Info("config archived", "path", path)

	// Rotate old archives
	if maxArchives > 0 {
		rotateArchives(archiveDir, maxArchives)
	}
	return nil
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
