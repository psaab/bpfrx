# Plan: #1893 + #1894 — configstore fail-closed constructor + pkg/fsatomic durable writer

**Status:** v2 — round-1 adjudicated (Codex PLAN-NEEDS-MAJOR task-mqal7v2u-8adha1,
AGY PLAN-NEEDS-MAJOR adversarial-review-mqal37pw-ehzagk; both endorse the
architectural premise). All sustained findings adopted below; see the
"Round-1 adjudication" section at the end for the finding-by-finding record,
including the evidence-backed refutation of AGY finding 4 (stale checkout).

## Issue framing

Two issues from Codex audit `codex-review-008`, combined because they touch the
same constructor and write paths:

- **#1893** — `configstore.New()` (store.go:90-107) logs "falling back to
  file-only" when `NewDB` fails, then stores the nil `*DB`. No file-only
  backend exists; there are zero nil guards package-wide. `Load()` (:114) or
  the first `writeActive()` (:173) panics on the nil receiver. A boot-time
  storage error becomes a misleading warning followed by a crash. The #1799
  persist-retry goroutine would panic the same way.
- **#1894** — no fsync anywhere on durable state. `writeTree` (db.go:118-136)
  is temp+rename with no `Sync`, no close-error check (hidden by
  `os.WriteFile`), no dir fsync — yet the #1799 persist-before-promote commit
  contract (store.go:898-917) is built on it. `saveRollbackFiles` (:1339) and
  `SaveRescueConfig` (:1674) are plain `os.WriteFile` (not even atomic).
  `readOrCreateMasterKey` (crypto.go:243-248) is temp+rename without fsync —
  a lost/truncated `master.key` after power loss makes an encrypted active
  config permanently undecryptable. Every other subsystem encodes write
  policy ad hoc.

## Honest scope/value framing

This is boot-robustness + crash-durability work, not perf work. The win:

- A daemon that cannot persist config fails at construction with a precise
  error instead of a delayed nil-deref panic behind a lying log line.
- "Commit reported success" actually survives power loss — today the rename
  can land pointing at a zero-length temp after power-cut, silently reverting
  config, or losing `master.key` (bricking encrypted configs).

Costs are fsyncs on **operator-paced commit paths only** (commit, rollback
save, rescue save, DUID persist, frr.conf reload). The
`AtomicGeneratedConfig` class exists precisely so hot apply paths (networkd
snippets, swanctl, Kea) pay **zero** fsync. No packet-path or poll-tick code
is touched. If reviewers conclude the churn outweighs the value, PLAN-KILL is
an acceptable verdict.

## Verified facts the design rests on (origin/master 0c4f92354)

1. `configstore.New` has exactly **one** production caller:
   `pkg/daemon/daemon.go:363` (`daemon.New`). `daemon.New` has exactly one
   production caller: `cmd/xpfd/main.go:166`. 32 `_test.go` files call
   `configstore.New`; zero test files call `daemon.New`.
2. The **text rollback files** (`xpf.conf.N`, written by `saveRollbackFiles`)
   are the **canonical** rollback history — `loadRollbackHistory`
   (store.go:1358) reads them at boot. The DB rollback/candidate slots
   (`WriteRollback`/`ReadRollback`/`WriteCandidate`/`ReadCandidate`) have
   **zero** production callers; `writeTree` only serves `active.json` in
   production.
3. FRR's `atomicWriteFile` (pkg/frr/manager.go:589-672, post-#1883) is the
   in-repo precedent: CreateTemp in same dir, symlink resolution,
   fchmod/fchown-on-fd mode/owner preservation, `tmp.Sync()`, close-error
   check, rename. Missing only the parent-dir fsync.
4. `daemon_run.go:136` treats `store.Load()` failure as a warning and
   bootstraps from the text config file — deliberate tolerance for corrupt
   JSON, preserved as-is. #1893 is about the *constructor*, not Load.

## Concrete design

### Part 1 — #1893 fail-closed constructor

```go
// New creates a new config store. It fails when the .configdb directory
// cannot be created: there is no file-only fallback backend, and every
// persistence path dereferences the DB, so booting without one would
// trade a precise boot error for a delayed nil-pointer panic (#1893).
func New(filePath string) (*Store, error)
```

- On `NewDB` error: `return nil, fmt.Errorf("config db %s unusable: %w (no file-only fallback exists; refusing to boot without config persistence)", dbDir, err)`.
  The "falling back to file-only" warning is deleted.
- `daemon.New` becomes `(*Daemon, error)`; `cmd/xpfd/main.go` prints the
  error to stderr and exits 1 (same shape as the existing `d.Run` error
  path).
- 32 test call sites across 25 `_test.go` files updated mechanically
  (`store := configstore.New(p)` → `store, err := configstore.New(p)` +
  fatal-on-err). No `MustNew` panic helper added to the production surface.
- New test: place a **regular file** at the `.configdb` path so `MkdirAll`
  fails with ENOTDIR — root/CAP_DAC_OVERRIDE-proof, unlike a 0555 parent
  (Codex round-1 finding 6); assert a non-nil error mentioning the dbDir and
  **no panic** (the exact regression #1893 demands).

Boot semantics: hard fail-closed. Today the daemon panics at `Load()`
moments later anyway; this converts the crash into a diagnosable error with
systemd restart semantics (`RestartSec=1`) unchanged.

### Part 2 — pkg/fsatomic

```go
package fsatomic

type Option func(*options)
func WithPreserveExisting() Option // mode+owner lifted from existing target (fchmod/fchown on the fd)
func WithResolveSymlinks() Option  // EvalSymlinks/Readlink target resolution (FRR semantics)

// WriteFileAtomic writes data via CreateTemp-in-same-dir + fchmod +
// close-check + rename. Namespace atomicity only — NO fsync. For
// regenerated configs on apply paths (AtomicGeneratedConfig class).
func WriteFileAtomic(path string, data []byte, perm os.FileMode, opts ...Option) error

// WriteFileDurable is WriteFileAtomic plus tmp.Sync() before close and a
// parent-directory fsync after rename. For state that must survive power
// loss (DurableState class). A dir-fsync failure is an error, not a warn.
func WriteFileDurable(path string, data []byte, perm os.FileMode, opts ...Option) error

// SyncDir fsyncs a directory, making preceding renames/unlinks in it
// durable. Used to batch namespace durability (rollback-file shuffle +
// stale-slot cleanup pay ONE dir fsync, not one per file).
func SyncDir(dir string) error
```

Shared unexported core; one code path, `durable bool`. Temp file removed on
every failure path. The symlink + mode/owner-preserve logic is a mechanical
lift of FRR's `atomicWriteFile` (behavior-preserving; that code was just
reviewed in #1883).

Semantics adopted from round-1 review:

- **Inode replacement, constant mode.** Unlike `os.WriteFile` over an
  existing file (which keeps the target inode's mode/owner and writes
  through symlinks), temp+rename replaces the inode and enforces the
  caller's `perm` on every write. For every migrated site except frr.conf
  the file is created/owned by xpfd with a fixed mode, so this is a
  deliberate normalization, documented per-site (Codex finding 1). Symlinked
  targets get replaced by regular files unless `WithResolveSymlinks` is
  passed — only FRR opts in. Hardlinks: rename breaks `nlink>1`
  write-through; documented in the fsatomic README, no rejection logic
  (none of these paths is plausibly hardlinked) (Codex finding 2).
- **Symlink-resolved dir fsync.** With `WithResolveSymlinks`, the temp file,
  rename, and the parent-dir fsync all use the *resolved target's*
  directory, not the symlink's (AGY finding 2).
- **EINTR.** Go's `os.File.Sync` routes through `internal/poll.FD.Fsync`,
  which wraps `syscall.Fsync` in `ignoringEINTR` — the stdlib already
  retries; noted in a code comment, no extra loop (Codex finding 3).
- **No post-rename fsync of the target file** — the temp-fd fsync already
  flushed data+metadata; the dir fsync makes the rename durable (AGY).
- **Crash-leaked temps.** `CreateTemp` names (`.<base>.tmp-*`) can leak on
  crash. `NewDB` sweeps `.*.tmp-*` in `.configdb` at construction; FRR
  already tolerates its own (`.frr.conf.tmp-*`) and is left as-is.

Test seams (same-package, `test_seams` pattern already used in configstore):
unexported function vars for CreateTemp / write / chmod / chown / sync /
close / rename / dir-open / dir-sync. One injected-failure test per stage
asserting: error surfaced, target file untouched, temp file cleaned up.

### Part 3 — migration table

| Site | Class | Writer | Notes |
|---|---|---|---|
| `configstore/db.go writeTree` (active.json + dormant candidate/rollback slots) | DurableState | `WriteFileDurable` 0644 | backs the #1799 persist-before-promote contract |
| `configstore/crypto.go readOrCreateMasterKey` | DurableState | `WriteFileDurable` 0600 | loss = undecryptable config |
| `configstore/store.go saveRollbackFiles` | DurableState (slot 1) + AtomicGeneratedConfig (slots 2..N) | `WriteFileDurable` slot 1, `WriteFileAtomic` rest, then ONE `SyncDir` after `cleanupRollbackFiles` | canonical rollback history (fact 2); was plain WriteFile. Slot 1 is the immediate rollback target; atomic rename keeps slots 2..N never-missing/never-torn so `loadRollbackHistory`'s break-on-first-missing stays sound (they may lag after power cut — documented); the trailing dir fsync makes the whole shuffle **and the stale-slot unlinks** durable at the cost of one fsync (Codex findings 4+5, AGY finding 3) |
| `configstore/store.go SaveRescueConfig` | DurableState | `WriteFileDurable` 0644 | operator-requested safety net |
| `configstore/store.go ArchiveConfig` | AtomicGeneratedConfig | `WriteFileAtomic` 0644 | new unique file per commit; best-effort archive (not in issue inventory; included for no-torn-file) |
| `dhcp/dhcp.go saveDUID` | DurableState | `WriteFileDurable` 0644 | lost DUID changes client identity across reboot |
| `frr/manager.go atomicWriteFile` | DurableState | thin wrapper over `WriteFileDurable` + both options | frr.conf carries non-managed operator content; gains the missing dir-fsync; mechanical lift |
| `ipsec/ipsec.go Apply` | AtomicGeneratedConfig | `WriteFileAtomic` 0600 | regenerated on apply |
| `dhcpserver writeKeaConfig` | AtomicGeneratedConfig | `WriteFileAtomic` 0644 | regenerated on apply |
| `networkd writeIfChanged` | AtomicGeneratedConfig | `WriteFileAtomic` 0644 | many small files on apply path — zero fsync by design |
| `networkd restoreSlowPathRPFilter` (:222) | BestEffortKernelKnob | direct `os.WriteFile` stays | procfs: rename is impossible there; comment added |
| `configstore/journal.go` | — | untouched | #1896 owns the journal redesign |

Fsync-cost note: with the slot-1-durable design the commit path pays 2 file
fsyncs + 3 dir fsyncs total (active.json durable, rollback slot 1 durable,
one trailing SyncDir) instead of the v1 worst case of ~50 — all under the
store mutex but operator-paced and bounded (Codex finding 4, AGY finding 3
both demanded this; adopted).

Canary: an **AST-based** test (`go/parser` over the migrated packages'
production files, resolving the `os` import's local name and matching
`os.WriteFile` call selectors) with an explicit allowlist (procfs knob,
journal pending #1896). Grep is brittle against comments and import aliases
(Codex finding 7).

## Public API changes (deliberate, audited)

- `configstore.New(string) *Store` → `(*Store, error)` — fail-closed (#1893).
- `daemon.New(Options) *Daemon` → `(*Daemon, error)`.
- New package `pkg/fsatomic` (two functions, two options).
- Everything else signature-stable.

## Hidden invariants preserved

- **#1799 commit contract**: persist-before-promote ordering unchanged;
  the disk write merely becomes actually durable. Failure handling
  (`noteActivePersistFailureLocked`, degraded flag, retry goroutine)
  untouched — and can no longer nil-panic.
- **FRR #1883 semantics**: symlink resolution, fchmod/fchown-on-fd,
  owner-preserve-only-when-different, error-not-silent on chown failure —
  preserved verbatim in the lift; frr package tests must pass unmodified
  (modulo import).
- **Mode/ownership per site**: each migrated call keeps its existing perm
  bits (0600 master.key + swanctl, 0644 others); no umask surprises (fchmod
  on fd, as FRR does today).
- **Hot paths**: no fsync on networkd/swanctl/Kea apply paths; nothing in
  pkg/dataplane or userspace-dp touched.

## Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW-MED | constructor signature is the only semantic change; write paths are byte-identical outputs with stronger flush guarantees |
| Lifetime/borrow | n/a | Go only |
| Performance regression | LOW | fsyncs confined to operator-paced paths; hot apply paths use the no-fsync class |
| Architectural mismatch | LOW | fsatomic is the FRR precedent generalized; the issue itself prescribes this shape |

## Test plan

- `go build ./...` + full `go test ./...` (UNMASKED, echo $?).
- `go test -race ./pkg/configstore/ ./pkg/fsatomic/`.
- New: per-stage injected-failure tests in fsatomic; #1893
  constructor-failure test; canary test.
- Live (lock protocol, `test/incus/with-cluster.sh`): deploy; verify normal
  boot + commit + `show system rollback`/rollback list; then on fw1 move
  `.configdb` aside + make `/etc/xpf` read-only, restart xpfd, prove
  **fail-closed with the precise journal error** (no panic, no misleading
  file-only line); restore + verify recovery. Re-apply CoS after deploy.

## Out of scope

- #1896 journal redesign (depends on this package; stays open).
- Any backend interface / `pkg/configstore/backend` split — the minimal
  correct fix per the issue is the constructor change.
- O_TMPFILE / linkat optimizations; cross-platform (Linux-only daemon).

## Round-1 adjudication (Codex task-mqal7v2u-8adha1, AGY adversarial-review-mqal37pw-ehzagk)

Both reviewers: PLAN-NEEDS-MAJOR, premise endorsed (fail-closed constructor
right, fsatomic shape right, hot-path classing right, single-caller claim
independently verified by both).

| # | Finding | Verdict | Disposition |
|---|---|---|---|
| C1 | Mode/symlink inode-replacement semantics underspecified outside FRR | SUSTAINED | "Semantics adopted" section: constant-mode normalization documented per-site; only FRR opts into preserve/resolve |
| C2 | Hardlink write-through silently broken by rename | SUSTAINED (doc-level) | Documented in fsatomic README; no nlink rejection |
| C3 | EINTR policy for fsync unstated | SUSTAINED (doc-level) | Go stdlib `poll.FD.Fsync` uses `ignoringEINTR`; code comment |
| C4 / A3 | 50 durable writes per commit under the store mutex too expensive | SUSTAINED | Slot-1 Durable + slots 2..N Atomic + one trailing `SyncDir` |
| C5 | `cleanupRollbackFiles` unlink durability ignored — stale slots can resurrect post-crash | SUSTAINED | Covered by the same trailing `SyncDir` |
| C6 | 0555-parent constructor test is root-brittle | SUSTAINED | Regular file at `.configdb` → ENOTDIR |
| C7 | "32 test files" wrong (32 sites / 25 files); grep canary brittle | SUSTAINED | Corrected; AST-based canary |
| A2 | Dir fsync must target the symlink-RESOLVED parent | SUSTAINED | Adopted explicitly |
| A4 | "Hallucination: `noteActivePersistFailureLocked` / persist-before-promote don't exist; code is promote-before-persist" | **REFUTED with evidence** | AGY audited the stale main checkout `/home/ps/git/bpfrx` at `ecdc16f2e` (its own file links say so), not this worktree at `0c4f92354`. In the worktree: `noteActivePersistFailureLocked` is defined at `pkg/configstore/store.go:194`, `persistDegraded` at `:48`, and the persist-before-promote contract comment at `:898-917`. `grep -c noteActivePersistFailureLocked` = 4 in worktree, 0 in the stale main checkout — exactly the #1799 machinery AGY claims doesn't exist |
| A — | Post-rename fsync of target redundant | CONFIRMS design | No-op |

Resolved former open questions: fail-closed boot YES (both reviewers);
rollback slot-1 fallback ADOPTED; FRR migration PROCEED (no objection,
frr_test.go:556/:604 pin behavior); dir fsync post-rename only CONFIRMED;
ArchiveConfig Atomic KEPT (no objection); mechanical test update KEPT.
