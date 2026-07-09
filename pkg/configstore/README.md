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

## File permissions — secrets at rest (#4056)

Every persisted copy of the full config carries the config's secret
leaves (IKE/IPsec PSKs, WireGuard/auth keys, SNMP community, routing
auth). Those leaves are stored **cleartext** unless `system
master-password` is set (which AES-GCM-encrypts only the JSON DB body,
not the text copies). So all secret-bearing files are written
**owner-only 0600**, never world-readable 0644 — a 0644 copy exposed
every firewall secret to any local user and defeated the point of
master-password encryption. `fsatomic` enforces the mode on the temp fd
before the rename (`WriteFileAtomic`/`WriteFileDurable` replace the
inode on every write), so an existing 0644 file from a pre-#4056 build is
re-created 0600 on the next commit.

| File | Path | Mode | Writer |
|------|------|------|--------|
| Active / candidate / rollback DB | `.configdb/{active,candidate,rollback.N}.json` | 0600 | `db.go writeTreeMarked` |
| Pending commit-confirmed state (#4577) | `.configdb/confirm.json` | 0600 | `db.go WriteConfirm` |
| `master.key` | `.configdb/master.key` | 0600 | `crypto.go readOrCreateMasterKey` |
| Text rollback slots | `<config>.N` (e.g. `xpf.conf.1`) | 0600 | `store_commit.go saveRollbackFiles` |
| Rescue config | `rescue.conf` | 0600 | `store_persist.go SaveRescueConfig` |
| Config archives | `<archive-dir>/config-*.conf` | 0600 | `store_persist.go writeArchive` |
| Audit journal (#4579 A4-02) | `.config.journal` | 0600 | `journal/journal.go Log` |

The `.configdb` and archive directories are created **0700** (they hold
only secret-bearing files); the daemon owns them, so read-back is
unaffected. The v2 audit journal (`.config.journal`) is compact metadata
only (timestamp/action/config-hash) and never config content or secret
values (#1896), so it is not a secret store the way the JSON DB is.
It is nevertheless written **0600** (#4579 A4-02): its `Detail` field
carries the operator's free-text commit comment verbatim, so a comment
that names a credential ("rotated the vpn psk to …") would otherwise be
world-readable. Tightening it to match the rest of the config surface is
cheap defense-in-depth; the daemon owns the file, so the history tail
read is unaffected.

### Threat model — what 0600 + 0700 defends, and what it does not (#4056)

The `0600` file perms plus `0700` directory perms defend against
**non-root local users** (a compromised low-privilege process or an
interactive account without root) reading the secret leaves, and against
**casual leakage** of an individual file. That is the exposure #4058
closed — the world-readable 0644 copies previously handed every firewall
secret to any local user.

They do **not** defend against **root compromise** or **physical disk
theft** (a stolen disk, backup, or VM snapshot). At-rest encryption of
the config store is intentionally **not** applied to the persisted text
copies, and encrypting them with the on-box `master.key` would add **no
real defense** against those two threats: this is an **unattended-boot
appliance**, so the decryption key must live on the box (`rollback N` /
`loadRollbackHistory` and a future rescue-load must restore secrets with
no operator present). `master.key` is a plain random 0600 file
(`crypto.go readOrCreateMasterKey`) in the same 0700 `.configdb`
directory as the ciphertext, with **no TPM/HSM substrate** in the tree
to seal it. An attacker who can read `xpf.conf.N` can equally read
`master.key` one directory over and decrypt — so on-box encryption is
theater against the root/disk-theft threat, not defense. A genuine
at-rest feature therefore requires a **TPM/HSM-sealed key** (a separate,
maintainer-gated work item — deferred, see #4056), not symmetric
encryption with an on-box key.

The JSON DB body is the one copy that IS AES-GCM encrypted when
`system master-password` is set; the text rollback slots, archives, and
`rescue.conf` stay cleartext-at-rest (0600) by the reasoning above.

**Off-box copy — `transfer-on-commit`:** the honest place to control the
residual is the off-box transfer, not on-box encryption. When
`system archival configuration transfer-on-commit` is set, the daemon
`scp`s the raw config file (cleartext secret leaves included) to the
operator-configured archive sites on every commit
(`daemon_flow.go scpArchiveTransfer`, `StrictHostKeyChecking=no`). This
is the one genuine off-box copy of the secrets; the operator must secure
the destination host and transport (extends the #651 warning about
inline archive-site passwords).

## Entry points

- `Store` — high-level API. Public methods include `ShowCandidate`,
  `ShowActive`, `ActiveConfig`, `ActiveTree`, `Commit`,
  `CommitCheck`, `CommitConfirmed`, `Rollback`, `ListHistory`,
  `EnterConfigure`, `EnterConfigureSession`,
  `EnterConfigureExclusive`, `ExitConfigure`, `SyncApply`. (See
  `store.go` for the full surface — there's no shorthand
  `Candidate()` or `History()`; use the `Show*` / `List*` forms.)
- `MaxConfigSize` (16 MiB) + `checkConfigSize` — `store.go`. The
  transport-independent input-size ceiling checked at the head of every
  parse entry point: `LoadOverride`, `LoadMerge`, `LoadSet`, the HA
  `SyncApply` ingress, and the `CheckText` day-0 config-drive validator
  (#1879). It rejects an over-large or corrupt payload with a
  clean `config too large` error before `config.NewParser`, so a
  pathological input cannot exhaust memory or (with the pkg/config
  lexer/depth guards) crash xpfd with a stack overflow (H-2). It backstops
  the `grpc.MaxRecvMsgSize` / `http.MaxBytesReader` transport caps for the
  HA peer-sync path and any non-transport caller. Real configs are well
  under 1 MiB, so the ceiling never rejects a legitimate config.
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

### At-rest crypto hardening notes (#4579 A4-05/A4-06, #4705)

- **Split `system` stanza resolution (#4705).** "The tree declares a
  master-password" is decided by `masterPasswordPRF`, which scans **every**
  top-level `system` child — reusing `systemBlocksOf` (the same all-matches
  helper the dataplane-retirement walk uses) plus per-node
  `FindChildren("master-password")` — not just the first `FindChild("system")`
  match. The Junos parser does not merge duplicate top-level stanzas
  (`parseStatements` appends each) and `LoadOverride` / `SyncApply` feed the
  raw parsed tree to the write path, so a `master-password` living in a second
  `system {}` block is semantically active (the compiler folds all `system`
  nodes into one `cfg.System`). A first-match resolver missed it and wrote the
  whole DB — secrets included — in plaintext despite encryption being
  configured. Resolution now fails **closed**: if any `system` stanza carries a
  `pseudorandom-function`, the body is encrypted. Because the A4-06
  downgrade warning below also keys off `masterPasswordPRF`, centralizing the
  resolution here fixes that path for the split-stanza case too (the warning
  now fires when a second-stanza master-password DB is read back as plaintext).
- **Unexpected-plaintext warning (A4-06).** Every write path encrypts the
  body when the tree declares a master-password, so `readTreeMeta` reading
  a config back as *plaintext* while its tree still declares a
  master-password means the file was written without the AES-GCM envelope
  — a downgrade to an older build, a restore from an unencrypted backup, or
  tampering. `maybeDecryptTreeJSON` reports whether it actually decrypted;
  `readTreeMeta` logs a one-time `slog.Warn` on the plaintext-with-declared-
  master-password case so the silent at-rest exposure is visible instead of
  loading the cleartext secrets without a trace. Reaching that state needs
  write access to the 0600/0700 `.configdb` (root/owner), so this is a
  visibility improvement, not a privilege-escalation fix.
- **GCM AAD binding (A4-05) — deliberately NOT changed.** `Seal`/`Open` pass
  a nil additional-authenticated-data argument. Binding the envelope header
  (PRF/salt) as AAD is textbook defense-in-depth, but the scheme already
  fails *closed* on any header swap: the key is HKDF-derived from the PRF
  and the stored salt, so tampering with either yields the wrong key and
  `Open` fails the GCM tag anyway. More importantly, switching to a non-nil
  AAD is a **ciphertext-format change**: an `active.json` sealed by an older
  build with nil AAD would fail to open after the change (the tag no longer
  matches), bricking decryption on upgrade. The non-exploitable gap does not
  justify an upgrade-brick risk, so the nil AAD is retained.

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
- **`commit confirmed` survives a crash inside the window (#4577).**
  The auto-rollback timer is an in-memory `time.AfterFunc` that does NOT
  outlive the process, so before this fix a daemon crash/reboot inside
  the confirm window made the UNCONFIRMED config PERMANENT — the
  safety hatch was silently lost (an operator commits a
  management-stranding config relying on the auto-revert, the daemon
  crashes, the box is stranded). `CommitConfirmed` now also persists a
  `confirm.json` in `.configdb` holding the absolute **deadline**, the
  **rollback-target tree** (`confirmPrevTree` — the ORIGINAL
  last-confirmed tree for a nested re-arm), and the **first-commit**
  flag (`confirmPrevCfg == nil`, the #1922 Item 1b never-committed
  case). It is written durably (temp+fsync+rename+dir-fsync),
  encrypted with the same master-password machinery as `active.json`
  (the target tree may carry secret leaves), 0600, AFTER the successful
  `writeActive`+promote (a failed commit-confirmed never leaves a
  `confirm.json`). `Store.Load` (`recoverPendingConfirmLocked`) restores
  it at boot: if the deadline already passed during downtime it rolls
  back to the prev tree now (including the Item 1b committed=0 marker on
  a first-commit target); if the deadline is still in the future it
  re-arms the timer for the REMAINING duration. Every confirmation path
  (`clearPendingConfirmLocked` — plain commit / HA sync / explicit
  confirm / demotion) and the timeout rollback (`PromoteRollback`)
  remove `confirm.json`; a nested `commit confirmed` re-writes it with
  the extended deadline. A clean restart inside the window also keeps
  the hatch (Junos parity: the pending confirm persists across a
  reboot and rolls back if not confirmed). One residual window remains:
  a crash in the microseconds between the `writeActive` syscall and the
  `confirm.json` write leaves no `confirm.json` — vastly smaller than
  the whole multi-minute window this closes.
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
- **A plain commit CONFIRMS a pending `commit confirmed` (#3861).**
  Junos semantics: any subsequent explicit `commit` confirms a pending
  `commit confirmed`. The frontend `commit` path intercepts a pending
  confirm (`IsConfirmPending`) and calls `ConfirmCommit` before it ever
  reaches the store commit — the interactive cli/gRPC/REST handlers all
  do this dance at their own layer. The NON-frontend committer that
  bypasses it is the eventengine autonomous-remediation commit, which
  reaches `Commit`/`CommitWithDescription` directly during a pending
  window (any future direct-store caller is covered too — the fix is
  defense-in-depth at the store layer, not a per-caller patch). Those
  paths now call `clearPendingConfirmLocked` AFTER the
  persist+promote succeeds: it cancels the armed rollback timer and
  bumps `confirmGen` so the just-promoted config becomes the confirmed
  config. Without it the pending timer's stale rollback target (the
  pre-confirm T0 tree) fired and SILENTLY reverted the background
  commit, discarding it (the eventengine sequence: operator `commit
  confirmed 5`; remediation `Store.Commit` at T+2; T+5 timeout reverts
  to T0, losing the remediation). This does NOT touch the nested
  confirmed→confirmed re-arm (that goes through `CommitConfirmed`, which
  re-arms and preserves the target) — only a PLAIN commit confirms.
- **A bare `commit` during the window also commits any NEW candidate edits
  (#4000).** The frontend intercept confirms-only (`ConfirmCommit`, timer
  cancel with no promotion) ONLY when the candidate is UNCHANGED
  (`!IsDirty()`). If the operator staged edits after `commit confirmed`, the
  intercept falls through to the normal commit, so `CommitWithDescription`
  applies the new candidate AND clears the timer (via the #3861
  `clearPendingConfirmLocked`). Junos semantics: a `commit` during a confirm
  window confirms the pending config AND commits new edits — they must not be
  silently dropped. The pre-#4000 intercept confirmed-and-discarded (the new
  edits were lost while `commit` returned success). `ConfirmCommit` itself
  never promotes the candidate, so routing a dirty candidate through it is the
  silent-loss bug; the `!IsDirty()` guard is the fix at all three frontends
  (cli/gRPC/REST).
- **`SyncApply` (HA config-sync receive) — Option B,
  degrade-not-fail.** The in-memory apply always proceeds (failing it
  would silently diverge the cluster; sync is one-way fire-and-forget).
  An authoritative config synced from the cluster primary also CONFIRMS
  any commit-confirmed window still pending on this node (#3861): a node
  that armed `commit confirmed`, failed over to standby, then received a
  primary sync must not later revert the synced config to its stale
  local pre-confirm tree. `SyncApply` calls `clearPendingConfirmLocked`
  with the in-memory promotion (the timer cancel stands even if the disk
  write below fails, matching the degrade-not-fail contract).
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

### Config lock: shared/private vs. exclusive holders (#3979)

Only one session edits config at a time. The store tracks the holder in
two fields depending on the mode the session entered:

- **shared / private** (`EnterConfigure`, `EnterConfigureSession`) —
  holder recorded in `configHolder`.
- **exclusive** (`EnterConfigureExclusive`, from `configure exclusive`) —
  holder recorded in `exclusiveHolder`; `configHolder` stays empty.
  `IsExclusiveLocked()` keys off `exclusiveHolder != ""`.

The release path (`ExitConfigureSession`) must match the session against
**whichever field its acquiring mode set**. It compares against
`effectiveHolderLocked()` — `exclusiveHolder` when set, else
`configHolder` — so a session releases the exact lock it holds.

**#3979 (fixed):** the release guard previously compared only
`configHolder`. An exclusive holder sets `exclusiveHolder` and leaves
`configHolder` empty, so the guard saw `configHolder("") != sessionID`
and returned `false` **without clearing anything**. The exclusive lock
then persisted with no live holder, and every subsequent
`configure` / `configure exclusive` / `configure private` was rejected
until daemon restart — a single operator running `configure exclusive`
then disconnecting bricked all future config edits. The disconnect
auto-release (`configLockInterceptor` in `pkg/grpcapi/server.go`) routes
through `ExitConfigureSession`, so it silently failed too; matching the
effective holder restores that stale-holder reclaim on disconnect.

`ConfigHolder()` likewise reports the effective holder, so
`clear system config-lock` / diagnostic output attributes an exclusive
lock to its real holder instead of an empty string. A genuinely-active
holder still blocks other sessions (`EnterConfigure*` rejects with
`ErrConfigLocked` while `configDir` is set), and a non-holder's exit
cannot steal the lock. `ForceExitConfigure` (`clear system config-lock`)
remains the unconditional operator override.

### Config lock: idle-lease reaper (#4476)

The gRPC config path auto-releases the lock when a client disconnects
(`configLockInterceptor` in `pkg/grpcapi/server.go` calls
`ExitConfigureSession` once `ctx.Err() != nil`). The **REST** config
path has no such hook: `POST /api/v1/config/enter`
(`configEnterHandler`) takes the global lock with an empty holder, and a
stateless HTTP client that never calls `/config/exit` leaves it held. On
its own that wedged every CLI/gRPC/REST config edit with `ErrConfigLocked`
until `clear system config-lock` or a daemon restart — a management-plane
config-edit DoS.

`configLockAt` (recorded at acquire) now backs an **idle-lease reaper**:

- **Refresh on activity** — every config mutation calls
  `touchConfigLockLocked()` (`store_lock.go`), which stamps
  `configLockAt = now` while `configDir` is set. Both transports funnel
  edits through the store's mutating methods (`Set`/`Delete`/`Deactivate`/
  `Activate`/`Copy`/`Rename`/`Insert`/`Annotate`/`Load*` in
  `store_command.go`; `Commit`/`CommitConfirmed`/`Rollback` in
  `store_commit.go`), and same-session re-entry refreshes too. Reads
  (`show`/status polls) deliberately do **not** refresh, so a lock whose
  holder stops editing ages out. The internal HA-sync ingress
  (`SyncApply`) and the commit-confirmed timeout revert
  (`PromoteRollback`) are timer/peer paths, not user activity, and do not
  refresh.
- **Reclaim on acquire** — `EnterConfigureSession` /
  `EnterConfigureExclusive` call `reclaimStaleLockLocked()` before
  rejecting a would-be entrant. It releases the current lock (mirroring
  `ForceExitConfigure`'s teardown, including `exclusiveHolder` /
  `editPath`) **only** when `time.Since(configLockAt) >=
  configLockLeaseTTL`, then the caller enters cleanly. A stale lock is
  therefore reclaimed exactly when another session needs it — the only
  moment a stuck lock causes harm — so no background goroutine is
  required.

`configLockLeaseTTL` defaults to **10 minutes**: long enough that an
operator hand-composing a change (each `set`/`delete` refreshes the
lease) is never reclaimed mid-edit, short enough to bound a wedged REST
lock. An actively-edited lock is never stolen; only a genuinely-idle one
is. The tests in `store_lock_lease_4476_test.go` cover both directions
(stale lock reclaimed, active/refreshed lock preserved) and are the
RED-on-revert guard. Note that recovery still surfaces the lock while it
is stale — a companion REST clear-config-lock action (L-1 / #4484) would
let a REST operator release it explicitly without waiting for the next
entrant; that is tracked separately.

### Cluster read-only gate (#3893)

On an HA chassis cluster the RG0 primary is the sole config authority;
the secondary is read-only and receives config only via `SyncApply`
(peer sync from the primary). The daemon toggles the store's read-only
mode on the RG0 primary↔secondary transition:
`SetClusterReadOnly(true)` when this node becomes secondary,
`SetClusterReadOnly(false)` when it is promoted to primary
(`pkg/daemon/daemon_ha.go`).

`clusterReadOnly` was originally checked ONLY at the `EnterConfigure*`
gate. That left two holes: a config session **opened before** the node
became secondary, and any mutating path that did not re-enter
`EnterConfigure`. Once a session was open, `Set`/`Delete`/`Commit`/
`Load*`/`Rollback` only verified `candidate != nil` — so an open session
could `Set` + `Commit` on the read-only secondary and **diverge** its
active config from the primary (a local edit the primary never sees,
which the next config-sync overwrites — churn/divergence).

The gate is now enforced on **every user-session mutating op** through
`ensureWritableLocked()` (called under `s.mu`): `Set`, `Delete`,
`DeactivateFromInput`/`ActivateFromInput`, `Copy`, `Rename`, `Insert`,
`Annotate`, `LoadOverride`/`LoadMerge`/`LoadSet`, `CommitWithDescription`
(and thus `Commit`), `CommitConfirmed`, and `Rollback`, in addition to
the retained `EnterConfigure*` gate. A rejected op returns the
`ErrClusterReadOnly` sentinel ("configuration is read-only on the
cluster secondary"), which `errors.Is` distinguishes from the transient
`ErrConfigLocked`.

**Internal-sync bypass (load-bearing):** the secondary must still APPLY
config authored by the primary. `SyncApply` (HA peer-sync ingress) and
`PromoteRollback` (commit-confirmed timeout revert) promote the
`active`/`compiled` state **directly** and never route through the gated
`Set`/`Commit`/`Load`/`Rollback` methods, so they are unaffected by this
gate — exactly the distinction between a user-driven mutation (blocked
on a secondary) and an internal convergence apply (must proceed).
Boot-time `bootstrapFromFile` enters config mode first, so it too is
governed by the same gate (a no-op there because `clusterReadOnly` is
`false` at boot, before any RG0 transition).

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
- **`system_action` entries (#4108 F8)** — `Store.LogSystemAction(verb)`
  appends a `{action: "system_action", detail: <verb>}` record for the
  destructive maintenance verbs `reboot`/`halt`/`power-off`/`zeroize`
  (written by `grpcapi.Server.SystemAction` BEFORE the action runs). The
  append is fsynced, so the record is durable on disk before the box goes
  down or the config is wiped — the `slog.Warn` line only reaches
  journald, which does not survive a reboot. For `reboot`/`halt`/`power-off`
  the on-disk record persists across the reboot. For `zeroize`, the wipe
  now **removes `.config.journal`** (and its rotated `.config.journal.N`
  segments) as part of the factory reset (#4576 — a completed reset must
  not hand its audit log / commit history / comments to the next tenant,
  and legacy v1 fat lines could carry full config incl. secrets in a 0644
  file). The cross-wipe trail is therefore the pre-execution fsync (an
  *interrupted* wipe still leaves the record) plus remote syslog — not
  on-box journal survival. `system_action` is deliberately EXCLUDED from
  `ListCommitHistory` (`show system commit` shows config commits only). The
  local gRPC transport is unauthenticated, so no operator identity is
  attributed — action + timestamp is the best-effort record.
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
  one another). The filename
  (`config-YYYYMMDD-HHMMSS.nnnnnnnnn.<seq>.conf`) carries a nanosecond
  timestamp PLUS a monotonic per-process sequence number: the timestamp
  alone is not unique (two serialized commits can format the same
  nanosecond under a coarse clock or an NTP step-back), so the seq
  guarantees no archive is ever overwritten while the leading timestamp
  keeps rotation's lexical sort chronological. `ArchiveConfig` captures
  the text, timestamp AND seq together under the lock (no after-unlock
  `time.Now()` race). The rollback/archive writers
  route through package-var seams (`rbWriteFileDurable`,
  `rbWriteFileAtomic`, `rbSyncDir`, `rbRemove`) so tests can pin the
  durability call and inject failures (#1916 pattern).
- Remote transfer-on-commit source (#3867): the daemon's
  `archiveConfig` (`system archival configuration transfer-on-commit`,
  `pkg/daemon/daemon_flow.go`) serializes the CURRENT active config via
  `Store.ShowActive()` — the SAME `s.active.Format()` text this local
  auto-archive and `show configuration` render — writes it to a temp
  file, and scp's THAT to each archive site. It no longer scp's the
  boot file `d.opts.ConfigFile` (`/etc/xpf/xpf.conf`): that file is
  written once at install and is never rewritten now the store is
  DB-canonical, so uploading it archived the day-0 config on every
  commit (a silently-wrong DR/compliance archive while scp logged
  success). The temp file keeps the boot-file basename so a
  directory-destination site retains the historical remote filename,
  and is removed after every upload completes. The transfer step is
  injectable behind `Daemon.archiveTransfer` (default
  `scpArchiveTransfer`) so tests can capture the uploaded bytes and
  assert the archive-source selection.
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
- Flat-load fail-closed (#3442 M3/M4): `LoadSet` and the flat-set branch
  of `LoadMerge` (`store_command.go`) reject any non-blank, non-`#` line
  that does not start with a recognized verb (gate `hasFlatVerb`) with a
  line-numbered error. Previously `LoadMerge` ran such a line through
  `applyEditLine` → `ParseSetVerb`, whose bare-path default turned a
  typo/free-text line (e.g. `not-a-set-line`) into a junk top-level node,
  and `LoadSet` silently `continue`d on it so REST/gRPC/CLI returned OK
  while dropping the intended command. The `ParseSetVerb` bare-path default
  is reserved for internal callers that prepend the verb themselves
  (`SetEdit`, `Deactivate`, `Activate`).
  - **Recognized verbs = exactly what `applyEditLine` replays:** `set`,
    `delete`, `deactivate`, `activate`. The interactive structural-edit
    verbs `annotate`/`copy`/`insert`/`rename` (handled only in
    `pkg/cli/cli_dispatch.go`) are intentionally NOT accepted on the flat
    path — they use distinct multi-clause grammar (`copy X to Y`,
    `insert X before Y`, `annotate X "comment"`) and never appear in a
    flat-load artifact, since `show | display set`
    (`ConfigTree.FormatSet`) emits only `set`/`deactivate` lines. Pre-fix
    they were already silently mangled into junk `set annotate ...` nodes,
    so rejecting them is the M3 fix, not a regression.
  - **Whitespace:** the gate matches the first whitespace-delimited token,
    so a tab between the verb and the path is tolerated (the lexer treats
    tabs as whitespace) — not only a literal space.
  - Hierarchical `LoadMerge` is unaffected — it round-trips through
    `FormatSet()`, which always emits verb-prefixed lines.
- Commit atomicity (#846): `pkg/daemon` wraps `Commit()` together with
  `applyConfig()` under a single semaphore. Bypassing the daemon (e.g.
  using `Store` directly) loses that serialization, so concurrent CLI +
  HTTP commits can race.
