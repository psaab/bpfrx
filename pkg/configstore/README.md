# pkg/configstore

Durable candidate / active / rollback configuration persistence. JSON
files written via `fsatomic.WriteFileDurable` (#1894: temp + fsync +
rename + parent-dir fsync — they survive power loss, not just crashes),
with a JSONL audit journal and rolling commit history. AES-GCM at-rest
encryption when a master password is set.

The constructor is fail-closed (#1893): `New(filePath) (*Store, error)`
returns an error when the `.configdb` directory cannot be created.
There is no file-only fallback backend — every persistence path
dereferences the DB, so the old "falling back to file-only" warning was
describing code that never existed, followed by a nil-pointer panic on
the first Load/Save/commit.

## Entry points

- `Store` — high-level API. Public methods include `ShowCandidate`,
  `ShowActive`, `ActiveConfig`, `ActiveTree`, `Commit`,
  `CommitCheck`, `CommitConfirmed`, `Rollback`, `ListHistory`,
  `EnterConfigure`, `EnterConfigureSession`,
  `EnterConfigureExclusive`, `ExitConfigure`, `SyncApply`. (See
  `store.go` for the full surface — there's no shorthand
  `Candidate()` or `History()`; use the `Show*` / `List*` forms.)
- `DB` — `db.go`. Low-level durable file I/O (via `pkg/fsatomic`).
  `NewDB` sweeps crash-leaked `.*.tmp-*` temps from `.configdb`.
- `History` — `history.go`. Bounded ring of recent commits.
- `journal.Journal` — subpackage `journal/` (#1896). Append-only,
  size-rotated, tail-readable JSONL audit trail; `configstore` keeps
  the alias `JournalEntry = journal.Entry`. See "Audit journal" below.
- `crypto.go` — AES-256-GCM at-rest encryption helpers
  (`maybeEncryptTreeJSON`, `maybeDecryptTreeJSON`,
  `deriveEncryptionKey`). No public type; the encryption hooks are
  methods on `*DB`. The encryption key is derived via HKDF
  (info string `xpf-configstore-master-password`, mode 0600 random
  bytes) from a randomly-generated `master.key` file in the
  configstore directory. The "master-password" naming is an HKDF
  info string only — it isn't a user-supplied password.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`, `pkg/api`.

## Dependencies

`pkg/config` only.

## Persist-failure semantics (#1799)

A `db.WriteActive` failure used to be non-fatal everywhere (one-shot
WARN), so a commit could report success and silently revert to the
previous on-disk config at the next restart. The contract is now
per-path:

- **Operator commits (`Commit`, `CommitWithDescription`,
  `CommitConfirmed`) — Option A, persist-before-promote.** The
  candidate is written to the on-disk active config BEFORE any
  in-memory promotion. On failure the commit returns an error with the
  candidate left intact and NOTHING mutated: no
  active/candidate/compiled/dirty change, no history push, no journal
  entry, no rollback-file save. Since `WriteActive` is temp-file +
  rename atomic, the old active survives on disk — a restart after a
  failed commit serves the previous config and the operator saw an
  error, never a silent revert.
- **Crash window (persist-then-promote ambiguity).** Because the disk
  write happens first, a crash after `WriteActive` succeeds but before
  the in-memory promotion completes means a restart loads the NEW tree
  even though the commit never reported success (no history/journal
  entry, and for `CommitConfirmed` no armed rollback timer). This is
  the deliberate trade: the old ordering's failure mode was a commit
  that REPORTED success and silently reverted on restart. A
  disconnected operator should treat an unanswered commit as
  ambiguous — same as Junos — and inspect `show configuration` after
  reconnecting.
- **`CommitConfirmed` ordering.** Confirm state is only touched after
  the persist succeeds: on failure the rollback timer is NOT armed and
  an existing pending confirm (timer + rollback target) is left fully
  intact. A generation token guards the rollback callback: a timer
  that already fired but lost the lock race to a nested re-arm or an
  explicit confirmation no-ops instead of reverting the newer commit.
  Nested confirmed commits (a second `CommitConfirmed` while
  one is pending) PRESERVE `confirmPrevTree` — the rollback target
  stays the last truly CONFIRMED config, not the unconfirmed
  commit-1 tree.
- **`SyncApply` (HA config-sync receive) — Option B,
  degrade-not-fail.** The in-memory apply always proceeds (failing it
  would silently diverge the cluster; sync is one-way fire-and-forget).
  A persist failure sets the store's degraded flag — surfaced by
  `ConfigPersistDegraded()` as `/health` 503 and the
  `xpf_daemon_config_persist_degraded` Prometheus gauge — writes a
  `persist_error` journal entry, and starts a SINGLETON background
  retry goroutine (1s backoff doubling to a 60s cap) that re-reads the
  CURRENT `s.active` under `s.mu` on each attempt, clears the flag on
  success, and exits. Successful writes on any commit/sync path also
  clear the flag.
- **`PromoteRollback` / `performAutoRollback` (confirm-timer expiry) —
  Option B.** The in-memory rollback always proceeds (reverting the
  running config is the safety property); a persist failure gets the
  same degraded flag + retry, which replaces the unconfirmed candidate
  the earlier `CommitConfirmed` left on disk with the rolled-back tree.

### Commit-confirmed timeout rollback ownership (#1922 Item 1a)

The store owns ONLY the store-state promotion primitive
(`PromoteRollback(gen) (prevCfg, ok)`): under `s.mu` it honors the
#1817 `confirmGen` staleness guard, promotes `active`/`compiled` to the
saved pre-confirmed state, persists with the #1799 degrade-not-fail
semantics, journals `auto_rollback`, and returns the compiled
pre-confirmed config. It does NOT touch the dataplane.

The DAEMON owns the rollback *transaction*. xpfd registers
`executeConfirmedRollback` via `SetRollbackExecutor` at daemon init, so
the confirm timer (which fires on its own goroutine) hands it the
generation; the executor acquires the apply semaphore FIRST, then calls
`PromoteRollback` + the full dataplane reconcile inside that one
critical section. This makes store promotion and dataplane re-apply
atomic with respect to a concurrent `commit` (which also holds the apply
semaphore), and — unlike the old interactive-only
`SetCentralRollbackHandler` callback — wires the rollback in SERVICE
mode (gRPC/REST/remote-cli) too. When no executor is registered (tests,
non-daemon embedders) the timer falls back to the self-contained
`performAutoRollback`, which promotes store state but does not re-apply
a dataplane it has no handle on.

The `prevCfg == nil` first-commit rollback target (#1922 Item 1b) is now
implemented: on a FRESH-store first `commit confirmed` timeout
`PromoteRollback` reverts the store to the empty bootstrap tree, persists
the **never-committed marker** (committed=0, NOT an empty *committed*
tree — see step-0 marker below), clears the in-memory `everCommitted`
flag, and returns `(nil, true)`. The daemon executor detects the nil
`prevCfg` and calls `enterBootstrapMode` (interface/FRR/dataplane takeover
cleanup, keeping the management lifeline) instead of applying an empty
config to the dataplane. A subsequent restart therefore re-classifies into
bootstrap (the marker disambiguates never-committed from
operator-committed-empty).

### Step-0 committed marker (#1922 Item 2)

The config-DB compatibility envelope (#1917) carries a `committed=` header
field that records whether the on-disk `active.json` is a
successfully-committed config (`committed=1`) or the never-committed
marker (`committed=0`) written by the Item-1b first-commit rollback. The
five-case boot predicate (in `pkg/daemon`) reads `Store.EverCommitted()`
to decide bootstrap vs normal when the active config is empty.

**Migration rule (mandatory):** a DB written by an OLDER build omits the
field; `parseEnvelopeHeader` defaults a missing `committed=` to **true**,
and a legacy no-envelope DB also reads committed. An upgraded box with an
existing active config can therefore never misclassify into bootstrap; the
never-committed marker is forward-only. `WriteActive` stamps
`committed=1`; `WriteActiveMarker(tree, false)` writes the never-committed
marker. `everCommitted` is set on `Commit` / `CommitConfirmed` /
`SyncApply` and cleared by the first-commit rollback.

Test seams (`test_seams.go`): `SetWriteActiveForTesting` injects
persistence failures on every persist path;
`SetWriteActiveMarkerForTesting` observes the step-0 committed bit;
`SetPersistRetryBackoffForTesting` makes the retry loop deterministic.

### `Store.Load` error sentinels (fail-closed boot)

`Load` returns one of three error shapes the daemon distinguishes with
`errors.Is`:

- **`ErrConfigDBUnreadable` (#1917 D1)** — a PRESENT `active.json` whose
  bytes cannot be read (JSON parse error, decrypt failure, or a too-new
  compatibility envelope). The daemon FAILS CLOSED by exiting `Run`, so an
  unreadable/too-new DB is never overwritten by a blind bootstrap.
- **`ErrConfigCompile` (#1960)** — a PRESENT `active.json` that read+parsed
  fine but no longer COMPILES, even through the tolerant `compileTreeLenient`
  path (e.g. a committed config whose referenced apply-group was later
  deleted in a partially-edited DB). `Load` has already set
  `everCommitted=true` from the on-disk `committed=` marker but leaves
  `compiled` nil, so `ActiveConfig()` returns nil. Without a guard that
  tuple (`ActiveConfig()==nil` + `EverCommitted()==true`) drives the daemon
  boot predicate to NORMAL and positional claim-all interface naming. The
  daemon detects `ErrConfigCompile`, skips the text-config bootstrap import,
  and enters the #1922 bootstrap/lifeline safe state (mgmt preserved, no
  claim-all, control plane up) instead of exiting (a hard exit would also
  strand mgmt). See `pkg/daemon` `classifyLoadError` / `computeBootClass`.
  - **`Load` still populates for in-band recovery.** `compiled` MUST stay nil
    (that is the bootstrap signal), but on this path `Load` assigns the
    parsed-but-broken tree to `active` and calls `loadRollbackHistory()`
    anyway. So the operator's recovery is real: `EnterConfigure` clones the
    broken tree (the candidate shows the config to fix, not an empty tree),
    and `Rollback(n)` reaches the on-disk history. `active` is always non-nil
    (the constructor seeds an empty tree), so `(active non-nil, compiled nil)`
    here is the same shape a fresh boot already has — no new invariant.
- **any other error** — logged as a warning; the daemon proceeds and the
  boot predicate decides bootstrap vs normal as usual.

An ABSENT DB is NOT an error (`Load` returns nil; start-fresh).

## Audit journal (#1896)

`.config.journal` (next to the config file) is a JSONL audit trail
owned by the `journal/` subpackage.

- **Compact v2 entries** — `{v, timestamp, action, detail,
  config_hash}`. The v1 format appended the FULL compiled config per
  commit (read by nobody — `show system commit` prints only
  timestamp/action/detail) so the file grew by a config snapshot per
  commit and leaked config content (incl. secrets) into a 0644 file.
  Full trees live in the rollback files (above), which remain the
  canonical config history.
- **`config_hash`** — sha256 hex of the post-action active tree's
  `Format()` text, the same text `saveRollbackFiles` writes: while a
  slot is retained, `sha256sum <config>.N` correlates the rollback
  file to its journal entry. Best-effort correlation only — slots
  shift every commit and only ~50 are kept.
- **Bounded reads** — `ListCommitHistory(limit)` is O(limit), not
  O(lifetime): `journal.Tail` reverse-scans segments newest-first in
  64 KiB chunks and stops at `limit` entries. Semantics preserved from
  v1: last `limit` entries of ANY action, then filtered to commit
  actions. `limit <= 0` still reads everything. Line assembly is
  capped at 16 MiB (corrupt newline-free content is skipped, not
  buffered whole).
- **Rotation** — at append time, when the current segment reaches
  1 MiB it rotates to `.config.journal.1` (keep 2 rotated segments,
  oldest deleted). A pre-#1896 fat journal rotates to `.1` intact on
  the first append — old history stays readable until it ages out; no
  migration pass, and boot never reads the journal.
- **Durability** — appends are fsynced (operator-paced; the commit
  path already pays several fsyncs), `fsatomic.SyncDir` covers
  create/rotate namespace changes, and a torn tail (crash between
  write and fsync) is confined to one line: the reader's parse-or-skip
  rule drops it and the next append starts on a fresh line.
- **Back-compat** — legacy v1 lines (with `before`/`after` payloads)
  decode tolerantly; unknown fields are ignored. A journal `Log`
  failure is a `slog.Warn`, never a commit failure, and the
  `persist_error` path does not recurse.
- **Concurrency** — `Journal` serializes `Log`/`Tail` internally;
  `ListCommitHistory` deliberately takes no `Store.mu` (rotation +
  concurrent read would otherwise duplicate entries).

## Gotchas

- Durable write protocol (#1894): `fsatomic.WriteFileDurable` — temp
  file in `.configdb`, fsync, rename, parent-dir fsync. The previous
  file survives an interrupted write intact, and a completed write
  survives power loss (the pre-#1894 writer skipped both fsyncs, so a
  "successful" commit could surface as a zero-length file or silently
  revert after a power cut).
- Rollback text files (`<config>.N`) are the CANONICAL rollback
  history (`loadRollbackHistory` reads them at boot; the DB rollback
  slots have no production callers). `saveRollbackFiles` writes slot 1
  durably and slots 2..N atomically (never missing, never torn; they
  may lag after a power cut), then one `fsatomic.SyncDir` makes the
  shuffle and the stale-slot unlinks durable — a single dir fsync
  instead of ~50 fsync pairs under the store mutex.
- Rollback-history degradation (#3441 L1): a rollback-slot write or the
  trailing dir-sync failing no longer just logs a warning. The commit
  still succeeds (the canonical active config already persisted via the
  #1799 path), but the store sets a degraded bit — surfaced by
  `RollbackHistoryDegraded()` — and journals a `rollback_persist_error`
  entry, so a stale-on-restart rollback history is visible rather than
  silent. The bit clears on the next fully-successful save.
- `loadRollbackHistory` / `cleanupRollbackFiles` stop ONLY on a
  genuinely-missing slot (`os.IsNotExist`), not on an arbitrary read/
  remove error (#3441 L2/L3): a transient or permission error on an
  intermediate slot logs-and-continues so the later readable slots still
  load and every stale slot is still cleared (preserving the
  contiguous-sequence invariant the loader assumes).
- Auto-archive correctness (#3441 H4): `CommitWithDescription` captures
  the JUST-COMMITTED `Format()` text plus a nanosecond-resolution
  timestamp inside the commit critical section and hands only those
  immutable values to the async archive goroutine. Previously the
  goroutine read `s.active.Format()` whenever it eventually ran (so a
  rapid second commit could make it archive the wrong tree) and named
  the file at second resolution (so two same-second commits overwrote
  one another). The nanosecond filename
  (`config-YYYYMMDD-HHMMSS.nnnnnnnnn.conf`) is unique per commit and
  still sorts chronologically for rotation. The rollback/archive writers
  route through package-var seams (`rbWriteFileDurable`,
  `rbWriteFileAtomic`, `rbSyncDir`, `rbRemove`) so tests can pin the
  durability call and inject failures (#1916 pattern).
- `master.key` is written durably BEFORE any tree encrypted with it
  (the key persist runs inside writeTree's encrypt step) — a lost key
  meant a permanently undecryptable active config.
- The candidate (in-memory) tree may be dirty (uncommitted edits
  accumulating). `Commit` atomically promotes candidate → active
  and bumps the rollback ring — but only after the new active has
  durably persisted (#1799 Option A above).
- Rollback slots are 0..49 (FIFO). Oldest is silently discarded when
  the ring is full.
- The encryption key lives at `<db.dir>/master.key` (mode 0600,
  generated on first encrypted commit). If the file is missing on a
  node that previously committed encrypted state, decryption fails —
  there is no plaintext fallback.
- Commit atomicity (#846): `pkg/daemon` wraps `Commit()` together with
  `applyConfig()` under a single semaphore. Bypassing the daemon (e.g.
  using `Store` directly) loses that serialization, so concurrent CLI +
  HTTP commits can race.
