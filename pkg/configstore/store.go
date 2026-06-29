// Package configstore implements the Junos-style candidate/active
// configuration management with commit and rollback support.
//
// The Store type is split across several same-package files for
// readability (#2158 code-motion, no behavior change):
//   - store.go         — Store struct, New, node/cluster accessors, the
//     compile/schema-validate pipeline, SyncApply
//   - store_persist.go — Load/Save, writeActive*, journal helpers, the
//     #1799 degrade-and-retry persist machinery,
//     config archival, and rescue config
//   - store_lock.go    — config-mode enter/exit locking + edit-path nav
//   - store_command.go — candidate edit verbs (set/delete/copy/...) and
//     the flat-line replay (LoadSet/LoadMerge/...)
//   - store_commit.go  — commit / commit-confirmed / rollback, the
//     confirm-timer machinery, and rollback-history
//     file persistence
//   - store_format.go  — the Show* render family + read-only accessors
package configstore

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore/journal"
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

	// writeActiveMarkerFn is the marker-aware test seam for the #1922
	// step-0 committed marker. nil (production) routes to
	// db.WriteActiveMarker. Set via SetWriteActiveMarkerForTesting.
	writeActiveMarkerFn func(*config.ConfigTree, bool) error

	// everCommitted is the #1922 step-0 marker as loaded/observed in
	// memory: true once a config has been successfully committed or
	// synced to this store (or loaded from a committed/legacy DB), false
	// on a fresh store and after the Item 1b first-commit rollback writes
	// the never-committed marker. The boot predicate (BootClassify) reads
	// it to disambiguate operator-committed-empty (normal) from
	// never-committed (bootstrap). Default false on a new Store; Load sets
	// it from the on-disk envelope marker (absent/legacy DB => true).
	everCommitted bool

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

	// persistMarkerCommitted records the #1922 step-0 committed flag the
	// degraded-persist retry loop must re-write. Defaults true; set false
	// ONLY by the Item 1b first-commit rollback so a FAILED never-committed
	// marker write that later heals via the retry loop persists committed=0
	// (never-committed), NOT committed=1 — otherwise a restart would
	// misclassify the rolled-back box as operator-committed-empty (normal)
	// and take over interfaces on an empty config (Codex r1 release-blocker).
	// Every successful committed write resets it to true.
	persistMarkerCommitted bool

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

	// archiveSeq is a monotonic per-process counter appended to every
	// archive filename (#3441 H4, Codex MAJOR). The wall-clock timestamp
	// alone is not a unique key: two successive (mutex-serialized) commits
	// can format the SAME nanosecond under a coarse clock or an NTP
	// step-back, and the later atomic write would overwrite the earlier
	// archive. The seq always advances, so config-<ts>.<seq>.conf is unique
	// even on an identical timestamp; the ts still gives chronological
	// sort/prune order (it dominates the lexical compare).
	archiveSeq atomic.Uint64

	// rollbackPersistDegraded records that the most recent
	// saveRollbackFiles() failed to durably write a rollback slot or sync
	// the directory (#3441 L1). The commit itself still succeeds — the
	// canonical active config persisted via the #1799 persist-before-promote
	// path — but the text rollback history (loadRollbackHistory reads it at
	// boot, #1894) is now stale/lossy. Surfaced via RollbackHistoryDegraded()
	// and a journal entry so the loss is visible instead of warning-only.
	// Cleared by the next fully-successful saveRollbackFiles().
	rollbackPersistDegraded bool
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
		active:                 &config.ConfigTree{},
		history:                NewHistory(50),
		filePath:               filePath,
		db:                     db,
		journal:                journal.New(journalPath),
		nodeID:                 -1,
		persistMarkerCommitted: true,
	}, nil
}

// SetConfigDBWriterVersion sets the xpf build version stamped into the
// config-DB compatibility-envelope header on write (#1917 increment B).
// Call once at startup before any Commit/Save; the daemon's single init
// path is the only caller.
func (s *Store) SetConfigDBWriterVersion(v string) {
	s.db.SetWriterVersion(v)
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
	// #2008 H1: strip `inactive:` subtrees BEFORE group expansion so the
	// schema/check path agrees with the compile path (strip -> expand ->
	// validate; see compileConfigWithOpts in compiler.go). ExpandGroups
	// (ast_groups.go) collects every `apply-groups` node by name WITHOUT
	// checking Inactive, so without this an `inactive: apply-groups foo`
	// would still expand group foo (false-validating inherited content the
	// compiler will never apply) and an `inactive: apply-groups missing`
	// would still fail commit-check as an undefined group. Stripping here —
	// not only inside SchemaValidateWithDefinitions, which runs AFTER
	// expansion — makes the marker actually deactivate group inheritance.
	// WithoutInactive is a no-op (no clone) on the all-active path; the
	// pre-strip tree is still passed as defsSource so a definition living
	// only in an un-applied peer-node group keeps satisfying shared-section
	// references (#1319 PR 3), with that defsSource stripped of inactive
	// nodes inside SchemaValidateWithDefinitions.
	stripped := tree.WithoutInactive()
	expanded := stripped.Clone()
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
	//
	// #1922 step-0: a successful config sync from the primary counts as a
	// commit for the never-vs-empty disambiguation — a synced secondary has
	// an authoritative config and must never read as never-committed. Set
	// the markers BEFORE the persist so a failed-then-healed write (the
	// retry loop) also stamps committed=1.
	s.everCommitted = true
	s.persistMarkerCommitted = true
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
