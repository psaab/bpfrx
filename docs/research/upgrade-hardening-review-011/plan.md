# Upgrade-subsystem hardening — plan of action (review-011)

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)
**Base:** `3cd181323` (origin/master)
**Issues:** #1964 (F1, HIGH), #1965 (F2, HIGH), #1966 (F3, LOW), #1967 (C1–C4, MEDIUM)
**Scope of this plan:** the two HIGH architectural findings (#1964 seed, #1965
lock) drive the design; #1967 is a mechanical hardening annex; #1966 is a
ship-direct doc edit (no review). `/research` only — no code is written here.

## 1. Issue framing

The in-place upgrade subsystem (`pkg/upgrade/*`, `cmd/xpfd/upgrade*.go`,
`debian/*`) shipped across #1917/#1930/#1933. A Codex adversarial review (011)
plus a completeness pass found two HIGH correctness gaps and four MEDIUM/LOW
robustness gaps, all verified against `3cd181323`:

- **#1964 (F1):** first `.deb` install seeds no versioned runtime, so the
  *first* package upgrade has `PreviousVersion==""` and `rollback()` hard-
  refuses (`flip.go:125-130`). dpkg has already overwritten the old binary in
  `staged/`, so a failed first cut after STOP/FLIP strands the host. Hits every
  baked appliance exactly once (bake.py does not seed `versions/current`).
- **#1965 (F2):** no host-local lock anywhere in `pkg/upgrade/` or
  `cmd/xpfd/upgrade*.go` (verified by grep). Concurrent mutators
  (operator + postinst auto-cut, two shells, binary + kernel) silently corrupt
  the journal (`loadJournal`→modify→`saveJournal`, last-write-wins) and collide
  on fixed `.tmp` symlink names.

## 2. Honest scope/value framing

These are not perf changes — they are crash-safety/correctness gaps in the
lowest-frequency but highest-blast-radius code path (the appliance upgrade).
#1964 is the single highest-risk transition in the lifecycle and it is
*guaranteed* to occur once per appliance. #1965's journal race is silent
corruption of rollback state. Both are worth fixing. *If reviewers conclude a
given sub-fix is over-engineered for the actual threat model (e.g. C1 is only
reachable by a trusted package), PLAN-KILL or down-scope of that item is an
acceptable verdict.*

## 3. What is already shipped / partially batched

- The STOP→FLIP→START state machine, journal idempotency (temp+fsync+rename),
  symlink atomicity (`repointSymlink` temp+rename+`SyncDir`), DB-snapshot-
  before-reflip ordering, `StateRollingBack` (prevents resuming a failed
  forward cut), GC protection for running+predecessor versions, and CopyTree
  checksum re-verify are all in place and **confirmed solid** (completeness
  pass). The fixes below must compose with them, not rebuild them.
- HA nodes (`/etc/xpf/node-id` present) are already postinst-stage-only; the
  auto-cut races (#1965) are standalone-only. The cluster `/tmp/xpf-cluster.lock`
  (deploy-level) is cluster-scoped and does not serialize host-local mutators.
- `XPF_NO_POSTINST_CUT=1` already suppresses the postinst auto-cut.

## 4. Design — #1964 (seed a real rollback target)

The root cause is that the *runtime layout* (`versions/<v>` + `current` symlink
+ sbin pointing through `current`) is only ever created by `xpfd upgrade`, never
by install. So the first upgrade has nothing to roll back to, and — worse — the
old binary is destroyed by dpkg before the cut runs.

### Path options

- **Option A — seed on first install (postinst).** First-install branch copies
  `staged/*` → `versions/<v>/bin/*`, sets `versions/current → <v>`, points
  `/usr/local/sbin/*` through `versions/current`. PRO: every host has the
  upgrade layout from day 0; bake benefits automatically; no first-cut special
  case. CON: does **not** help a host *already* in the field on the legacy
  direct-staged layout — its next upgrade (the one that introduces seeding) is
  still rollback-less because the new postinst seeds *going forward* only.
- **Option B — pre-overwrite snapshot (preinst).** A new `debian/xpf.preinst`
  `upgrade` hook (runs *before* dpkg unpacks the new files, while the OLD
  binaries are still on disk) snapshots the currently-installed binaries into
  `versions/<oldver>/` and sets `versions/current → <oldver>` if absent. PRO:
  fixes the legacy-migration upgrade AND the first upgrade — every upgrade then
  has a real, immutable previous. CON: adds a maintainer script; must derive
  `<oldver>` (use dpkg `$2` old-version arg, or `staged/xpfd version`).
- **Option C — refuse-before-STOP fail-safe.** `runner.go` hard-fails the cut
  *before* StopUnit when `PreviousVersion==""` and the run is not explicitly a
  sanctioned no-rollback first cut. PRO: never stops a healthy daemon without a
  rollback target. CON: insufficient alone — the running daemon survives in
  memory, but its on-disk binary is already gone, so the *next* restart/reboot
  execs the (untested) new binary. A safety net, not a fix.

### Recommendation

**B (preinst snapshot) + A (first-install seeding) + C (refuse-before-STOP as
belt-and-suspenders).** B is the load-bearing fix because it is the only option
that gives the *legacy-migration* upgrade a rollback target (it captures the old
binary before dpkg clobbers it). A makes fresh installs uniform. C guarantees we
never tear down a running daemon we cannot restore. All three live in a new
**`pkg/upgrade/runtime/` (or `bootstrap/`) module** that owns versioned-runtime
seeding + legacy direct-staged migration, keeping it out of the already-
overloaded `runner.go`.

### Required regression test

Simulate the direct-staged first-install layout, stage an unhealthy `2.0.0`,
and assert **either** rollback succeeds to the snapshotted previous **or** the
cut refuses before StopUnit (daemon stays up). Plus: preinst snapshot is
idempotent and a no-op when `versions/current` already exists.

## 5. Design — #1965 (host-local upgrade lock)

### Path options

- **Lock scope:** (a) one host-wide lock for all mutators (binary + kernel +
  postinst), or (b) separate binary/kernel locks. **Recommend (a)** — binary
  and kernel upgrades mutate the same host availability envelope and must never
  run concurrently; one lock = one policy + one test surface (Codex's
  modularity note).
- **Mechanism:** `unix.Flock(fd, LOCK_EX|LOCK_NB)` on `/run/xpf/upgrade.lock`
  held for the command's duration. `/run` is tmpfs → no stale lock across
  reboot (a crash mid-upgrade does not leave a dead lock; resume is governed by
  the journal, not the lock). Write owner metadata (PID, subcommand, target
  version/kernel, start time) into the lock file so errors name the owner.
- **postinst integration (open Q):** the postinst auto-cut takes the same lock.
  If an operator holds it, postinst must **not block apt** — recommend
  non-blocking acquire: on contention, log "another upgrade in progress; staged
  only — run `xpfd upgrade` when it completes" and exit 0 (staged, not cut).
- **Status commands** (`upgrade status`, kernel status) stay lock-free (or take
  a shared `LOCK_SH`).

### Required tests

Two mutators against a fake system: the second `LOCK_NB` acquire fails and the
process exits **before** any journal/symlink/systemd/boot-selector/reboot
mutation. Lock released on normal exit, on error, and on panic (deferred
close). Owner metadata surfaces in the busy error.

## 6. Design — #1967 hardening annex (mechanical)

- **C1 (version-string validation):** in `BinaryVersion()`
  (`system_linux.go:110-123`), reject any version not matching
  `^[A-Za-z0-9][A-Za-z0-9._-]*$` (no `/`, no `..`, no spaces) — hard-fail
  rather than fall back to the whole `version` output. Closes the path-escape /
  unit-ExecStart-injection / benign-format-drift cases.
- **C2 (reload re-validation):** after a resumed `flip()` re-runs daemon-reload,
  re-check the unit state; surface a clear error if the second reload fails
  rather than proceeding to START blind.
- **C3 (pre-START dir check):** before StartUnit, stat `versions/<ver>/xpfd`
  (and the helper) and fail fast to rollback if the dir vanished in the
  FLIP→START window.
- **C4 (sync after partial removal):** `SyncDir(VersionsDir)` immediately after
  `removeAllPartials()` so a crash cannot resurrect stale `.partial` entries.

These are localized; they do not need their own path options. Reviewers should
confirm none of them weaken the existing solid invariants in §3.

## 7. Public API / contract preservation

- No Go exported-signature changes required for #1965 (new internal
  `pkg/upgrade/lock` package) or #1967. #1964 adds a new internal
  `pkg/upgrade/runtime` package; `Runner` gains a dependency, not a new public
  method shape.
- `debian/` maintainer-script contract changes (new preinst, postinst seeding)
  must preserve: first-install starts the daemon immediately; HA stage-only;
  `XPF_NO_POSTINST_CUT=1` honored; apt never hangs.

## 8. Hidden invariants the change must preserve

- **First install must leave the daemon launchable immediately** — seeding must
  not force a cut or a verify gate at install time (the daemon may not be up).
- **The running in-memory daemon is never killed without a restorable on-disk
  target** (#1964 C + #1965 lock together).
- **Resume-after-crash is journal-driven, not lock-driven** — the lock must be
  reboot-clearing (`/run`) so it never blocks legitimate resume.
- **HA nodes stay stage-only**; the lock must not change that gating.
- **Atomic-rename + SyncDir ordering** for symlinks/dirs is preserved.

## 9. Risk assessment

| Class | Level | Note |
|---|---|---|
| Behavioral regression | MED | preinst/postinst changes touch the install path of every host; needs the baked-image + cluster-deb dogfood gates |
| Lifetime/borrow | LOW | Go; lock fd lifetime via defer |
| Performance | NONE | upgrade-path only, not packet hot path |
| Architectural mismatch | LOW–MED | #1964 module boundary is the main design call; B-vs-A-vs-C is the open question for review |

## 10. Out of scope (explicitly)

- True zero-gap dataplane cut-over (helper re-attach; future M-mech-2).
- Cluster-level orchestration changes (the `/tmp/xpf-cluster.lock` deploy lock
  stays as-is; #1965 is strictly host-local).
- #1961 virtio AF_XDP delivery, #1962 standalone helper-deploy gap, #1960
  positional-fallback — separately tracked.
- #1966 doc edit — ship-direct, not part of this plan's review.

## 11. Open questions for adversarial review

1. **#1964 path:** is B (preinst snapshot) the right primary, or is A
   (first-install seed) + C (refuse) sufficient if we accept that the single
   legacy-migration upgrade stays rollback-less (one-time, documented)? Does a
   preinst snapshot of the *old* binary risk doubling install disk/time?
2. **#1964 `<oldver>` source:** dpkg `$2` (debian version) vs `staged/xpfd
   version` (runtime version) — which keys `versions/<oldver>`? They can differ.
3. **#1965 postinst contention policy:** non-blocking-exit-0 (stage only) vs
   block-with-timeout. Does exit-0-on-contention silently skip a wanted cut?
4. **#1965 lock path:** `/run/xpf/upgrade.lock` (tmpfs, reboot-clear) vs
   `/var/lib/xpf/` (survives reboot — but then needs stale-lock detection). Is
   reboot-clear correct given journal-driven resume?
5. **#1965 kernel+binary single lock:** any legitimate need to run a kernel
   `status`/`promote` concurrently with a binary cut that a single exclusive
   lock would wrongly block?
6. **C1 severity:** is version-string validation worth it given the source is a
   package-trusted binary, or is it pure defense-in-depth that could be a LOW?
7. **C2/C3:** do these actually add safety, or does the existing auto-rollback
   already cover the FLIP→START window such that they are redundant?
