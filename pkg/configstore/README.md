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
- `Journal` — `journal.go`. Append-only JSONL audit trail.
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
- **`performAutoRollback` (confirm-timer expiry) — Option B.** The
  in-memory rollback always proceeds (reverting the running config is
  the safety property); a persist failure gets the same degraded flag
  + retry, which replaces the unconfirmed candidate the earlier
  `CommitConfirmed` left on disk with the rolled-back tree.

Test seams (`test_seams.go`): `SetWriteActiveForTesting` injects
persistence failures on every persist path;
`SetPersistRetryBackoffForTesting` makes the retry loop deterministic.

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
