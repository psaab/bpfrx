# Upgrade-subsystem hardening — plan of action (review-011)

**Status:** DRAFT v2.2 — r1 all-three PLAN-NEEDS-MAJOR (folded in v2);
r2 Claude SMR + AGY both PLAN-NEEDS-MINOR (folded here in v2.2); Codex r2
infra-dropped, retried on v2.2. v2.2 adds: verify-dataplane as the real
torn-binary backstop (not the preinst gate), C as an unconditional pre-STOP
invariant, preinst idempotency hardening, lock re-entrancy for the rolling
path, flip-failure non-nil return, postrm purge handling, preinst exec
fallback.
**Base:** `3cd181323` (origin/master)
**Issues:** #1964 (F1, HIGH), #1965 (F2, HIGH), #1966 (F3, LOW), #1967 (C1–C4 +
two new must-fixes, MEDIUM). `/research` only — no code is written here.

## 1. Issue framing

In-place upgrade (`pkg/upgrade/*`, `cmd/xpfd/upgrade*.go`, `debian/*`, shipped
#1917/#1930/#1933). Verified findings against `3cd181323`:

- **#1964 (F1):** first `.deb` install seeds no versioned runtime →
  first/legacy-migration upgrade has `PreviousVersion==""` and `rollback()`
  hard-refuses (flip.go:125-130); dpkg already overwrote the old binary in
  `staged/`. Hits every appliance once (bake.py does not seed `versions/`).
- **#1965 (F2):** no host-local lock anywhere in `pkg/upgrade/` or
  `cmd/xpfd/upgrade*.go` (grep-verified) → silent journal corruption
  (`loadJournal`→modify→`saveJournal`) + fixed `.tmp` symlink collisions.

## 2. Honest scope/value framing

Crash-safety/correctness in the lowest-frequency, highest-blast-radius path.
#1964 is guaranteed to occur once per appliance. *If reviewers judge a
sub-item over-engineered for the threat model (e.g. C1 under signed packages),
down-scoping or dropping it is an acceptable verdict.*

## 3. r1 reviewer findings folded into v2 (audit trail)

- **Codex-1:** the legacy preinst migration **cannot** call the new
  `pkg/upgrade/runtime` Go helper — Debian preinst runs *before* the new
  package is unpacked (Policy §6.5/§6.6), so the new `xpfd` is not on disk
  yet. Migration must be **self-contained shell** in `debian/xpf.preinst`.
- **Codex-2:** preinst must **atomically repoint `/usr/local/sbin/*` through
  `versions/current` before unpack**, not merely snapshot — else dpkg clobbers
  the live restart/helper path (helper lookup uses `filepath.Dir(os.Args[0])`,
  process.go:168; unit ExecStart is `/usr/local/sbin/xpfd`).
- **Codex-3 / SMR-M3:** dpkg overwrites the shared `staged/` dir outside any
  Go lock. Resolution (see §5): `versions/` is **maintainer-script-managed
  runtime state, NOT in dpkg's file list**, so dpkg never clobbers a versioned
  rollback target; dpkg only ever writes `staged/`; a torn read of `staged/`
  during copy is caught by the existing CopyTree checksum re-verify (abort
  before STOP).
- **Codex / postrm:** `debian/xpf.postrm:24` removes only sbin links whose
  target is under `$STAGED`. After seeding, sbin → `versions/current`; postrm
  must handle that too (and decide `versions/` tree handling on purge).
- **AGY-1:** preinst snapshot must be **idempotent on a retried/crashed
  upgrade** — if a prior attempt unpacked the new `staged/` then crashed, a
  re-run must NOT snapshot the new binaries as "previous." Guard on both
  `versions/current` presence and a staged-version check.
- **AGY-3:** `runRollingWith` (rolling.go:88) runs peer-checks + ForceSecondary
  + ≤30 s drain **before** `r.Run()`; a lock taken only inside `r.Run()` leaves
  that window unlocked → lock at `RunRolling` start, hold through rejoin.
- **AGY-5 (new must-fix):** `flip()` failure (cutover.go:174-177) `return`s
  without rollback while the unit is already STOPPED (line 161-168) → daemon
  permanently offline. Must trigger rollback (or be guaranteed unreachable
  without a restorable target by C).
- **AGY-4 / Codex / SMR-M2:** version key = **runtime** version
  (`staged/xpfd version`), validated as a **safe single path segment** (no
  `/`, whitespace, control chars, `..`, or leading dot) — NOT a strict alnum
  regex (Debian versions carry `+`/`:`).
- **SMR-M1 (resolved):** B is required — we cannot assume zero already-deployed
  direct-staged hosts; the fix *introduces* seeding, so every pre-fix host
  needs B on its next upgrade. A handles fresh installs.
- **SMR-M4 / Codex:** C2 is largely redundant (flip.go:52 already returns
  daemon-reload failure); C3 kept only as diagnostic/HA-fail-fast. The real
  must-fix in that area is AGY-5 (flip-failure rollback).

## 4. Design — #1964 (seed a real, immutable rollback target)

**Layout contract (the spine of the fix):** `versions/<ver>/` and the
`current` symlink are **runtime state owned by maintainer scripts**, never in
dpkg's file list. dpkg only ever writes `/usr/local/share/xpf/staged/*`.
`/usr/local/sbin/*` are symlinks that, after this change, point through
`versions/current` (not at `staged/`). Consequence: dpkg can never clobber a
versioned rollback target, because it does not know those paths exist.

### Three composed mechanisms

- **A — first-install seed (postinst, may use the new Go module).** On first
  install (`$2` empty), after unpack, copy `staged/*` → `versions/<v>/`, set
  `versions/current → <v>`, repoint sbin through `versions/current`, all
  *before* `#DEBHELPER#` starts the unit (no cut/verify/stop). Owns the
  testable seeding logic in `pkg/upgrade/runtime`.
- **B — legacy-migration snapshot (preinst, self-contained shell).** On
  `upgrade` of a host whose `versions/current` is absent (pre-fix layout),
  `debian/xpf.preinst` — running *before* unpack, using only old on-disk files
  + coreutils — copies the OLD `staged/*` into `versions/<oldver>/` via a
  `.partial` dir + atomic rename, sets `versions/current → <oldver>`, and
  atomically repoints sbin through `versions/current`. **Idempotency /
  crash-safety (AGY-r2-1):** the no-op gate must check **both** that
  `versions/current` exists **AND** that every `sbin/*` already resolves
  through `versions/current` — a crash *after* `current` is created but
  *before* sbin is repointed must, on retry, still complete the sbin repoint
  (otherwise unpack overwrites `staged/` under a daemon still pointed there).
  Simplest robust form: always run the (idempotent, fast) sbin repoint
  unconditionally, and gate only the snapshot-copy on `versions/current`
  absence. Always `rm -rf versions/<oldver>.partial` before copying. Snapshot
  only when the staged runtime version still equals `<oldver>` (AGY-1).
  **`<oldver>` source (AGY-r2-4):** try `staged/xpfd version` (validated safe
  segment); if the old binary will not exec (corrupt / lib / arch mismatch),
  **fall back to a sanitized dpkg `$2`** and do NOT fail the transaction on
  exec failure. Writes **no** upgrade journal.
- **C — refuse-before-STOP (Go, runner.go).** Before `StopUnit`, hard-fail the
  cut when `PreviousVersion==""` and the run is not an explicitly sanctioned
  no-rollback first cut. Guarantees a healthy daemon is never stopped without a
  restorable on-disk target. Last-ditch — A/B should make this unreachable in
  the field.

**Module boundary:** `pkg/upgrade/runtime` owns first-install seed (A) +
postinst/runner-side logic + tests. The legacy preinst migration (B) is shell
in `debian/xpf.preinst` (cannot use the not-yet-unpacked Go binary).

**postrm (AGY-r2-§5.3):** extend `debian/xpf.postrm` to also remove sbin links
pointing through `versions/current`. `versions/` is package-derived (not user
config): **leave on `remove`, remove the maintainer-managed `versions/` tree on
`purge`** (Debian Policy §6.8 — purge removes all package state). Unlike
`/etc/xpf` (master.key/configdb — deliberately never touched), `versions/` is
just copied binaries, so purge-removal is correct.

**Version key:** `staged/xpfd version` (runtime), validated as a safe single
path segment (shared with C1).

### Required regression tests
1. Direct-staged first-install → unhealthy first/legacy upgrade: rollback
   succeeds to the snapshotted previous, OR the cut refuses before StopUnit.
2. Preinst idempotency: no-op when `versions/current` exists; does NOT snapshot
   new binaries on a retried post-unpack crash.
3. First-install seeding leaves the daemon launchable (sbin→versions→binary)
   without a cut.

## 5. Design — #1965 (host-local upgrade lock)

- **One host-wide lock** `/run/xpf/upgrade.lock` via `unix.Flock(LOCK_EX|
  LOCK_NB)`, covering `xpfd upgrade`, `xpfd upgrade --rolling`, postinst cut,
  and mutating `xpfd upgrade kernel …`. `/run` tmpfs → reboot-clear (resume is
  journal-driven, not lock-driven); `mkdir -p /run/xpf` before acquire (tmpfs
  may lack the dir after reboot — AGY-r2-§5.6). Owner metadata (PID, subcommand,
  target, start time) in the lock file; busy errors name the owner. Status /
  kernel `status` stay lock-free (or `LOCK_SH`).
- **Rolling scope (AGY-3) + re-entrancy (AGY-r2-4):** acquire at `RunRolling`
  entry, hold through rejoin — covers the peer-check + ForceSecondary + ≤30 s
  drain window, not just `r.Run()`. **`r.Run()` invoked under `RunRolling` must
  NOT re-acquire** (a second `flock` on a new fd of the same file would
  `EWOULDBLOCK` and abort the rolling upgrade): thread an
  `Options.LockAlreadyHeld` (or pass the held lock handle) so the inner cut
  skips acquisition.
- **dpkg-clobbers-staged (Codex-3 / SMR-M3) — CORRECTED in v2.1.** The rollback
  target is safe (it lives in `versions/`, dpkg-untracked — §4). But the *source
  race* — dpkg overwriting `staged/` while a concurrent operator `xpfd upgrade`
  copies it — is **NOT** caught by the CopyTree checksum. Verified against
  `copyStaged` (cutover.go:321-334): `sum` is computed by `copyTree` from the
  **source bytes as it reads them**, and `verifySum` re-reads the **dest**; a
  concurrent source overwrite yields matching torn bytes on both sides
  (undetected). The checksum catches copy/disk corruption, not concurrent
  source mutation. **Fix (layered, corrected per SMR-r2-m1):**
  (i) `debian/xpf.preinst` acquires `/run/xpf/upgrade.lock` (`LOCK_NB`) and
  **fails the package operation before unpack** if busy — this blocks the case
  where an operator *already holds* the lock when apt starts (clean fail-loud,
  apt aborts before any mutation). It does **NOT** fully serialize unpack vs a
  concurrent operator copy: a flock fd dies at preinst exit, so the lock is not
  held *during* dpkg's unpack, and an operator who acquires the (now-free) lock
  *during* unpack can still read a torn `staged/`. (ii) **The real torn-binary
  backstop is `verify-dataplane`** (cutover.go:151), which runs the kernel
  verify gate against the COPIED binary **before** StopUnit — a torn/non-
  execable ELF fails verify (or fails to exec) and aborts the cut while the
  daemon is still up. (iii) Document operator guidance: do not run `xpfd
  upgrade` during `apt upgrade`. So the outcome is safe (no bad cut commits),
  even though the preinst gate alone does not close the read window.
- **postinst contention policy (residual after the preinst guard):** in the
  rare TOCTOU case where the lock became busy between the preinst check and
  postinst, post-unpack `LOCK_NB` failure logs loudly "another upgrade in
  progress — staged only; run `xpfd upgrade` after it completes", drops a
  `/run/xpf/upgrade-deferred` marker, and **exits 0** (a non-zero postinst
  leaves dpkg half-configured, worse than a deferred cut on a host still
  running the old in-memory daemon). The fail-loud-non-zero behavior AGY wanted
  now lives at **preinst** (the correct pre-mutation gate); postinst's job is
  only the narrow residual.
- **Interaction with `/tmp/xpf-cluster.lock`:** documented order is
  cluster/deploy lock OUTSIDE, host upgrade lock INSIDE — no deadlock.

### Required tests
Two mutators against a fake system: the second `LOCK_NB` fails and exits before
any journal/symlink/systemd/boot-selector/reboot mutation. Lock released on
normal exit, error, and panic (deferred close). Rolling holds the lock across
the drain window.

## 6. Design — #1967 hardening annex

- **C1 (version validation):** reject any version that is not a safe single
  path segment (no `/`, whitespace, control chars, `..`, leading dot); hard-
  fail instead of the `BinaryVersion()` whole-output fallback
  (system_linux.go:123). MEDIUM robustness (defense-in-depth + benign
  format-drift).
- **NEW must-fix — flip-failure rollback (AGY-5):** on `flip()` failure
  (cutover.go:174-177), trigger rollback to `PreviousVersion`. This is safe
  because **C is an unconditional pre-STOP invariant** (§8): the unit is never
  stopped unless a restorable target exists OR it is a sanctioned no-rollback
  first cut. In the sanctioned-first-cut case (`PreviousVersion==""`) a flip
  failure has no prior daemon to preserve, but must still restart the
  first-install binary (present in `versions/current` via A/B). **The
  rollback-after-flip-failure path must return a non-nil error** (AGY-r2-4b) so
  `postinst` does not treat a rolled-back upgrade as success. **Add to #1967.**
- **NEW — postrm versioned-link cleanup (Codex):** §4. **Add to #1967.**
- **C2: DROP** (converged, SMR-r2 + AGY-r2 + Codex-r1) — flip.go:52 already
  returns daemon-reload failure; no added safety.
- **C3: KEEP as diagnostic only** — verify `versions/<ver>/` before StartUnit
  for clearer errors / HA fail-fast; the outcome is already covered by
  START-failure auto-rollback (cutover.go:183), so this is not a correctness
  fix.
- **C4:** `SyncDir(VersionsDir)` immediately after `removeAllPartials()`.

## 7. Public API / contract preservation

- New internal `pkg/upgrade/lock` + `pkg/upgrade/runtime` packages; `Runner`
  gains dependencies, no new public method shape. Legacy migration is shell
  (debian/xpf.preinst), not Go.
- `debian/` contract: first install starts the daemon immediately; HA
  stage-only; `XPF_NO_POSTINST_CUT=1` honored; apt never hangs / never left
  half-configured; sbin now resolves through `versions/current`.

## 8. Hidden invariants the change must preserve

- First install leaves the daemon launchable immediately (seed before
  `#DEBHELPER#`, no cut at install).
- **C is an unconditional pre-STOP invariant (SMR-r2-m2):** no cut path calls
  `StopUnit` unless (a) a restorable target exists (`PreviousVersion!=""` →
  flip-failure rollback can recover) OR (b) it is an explicitly sanctioned
  no-rollback first cut (no prior daemon to preserve; flip failure restarts the
  first-install binary from `versions/current`). Together with flip-failure
  rollback (§6) and the `versions/` contract, the daemon is never stopped
  without a recovery path. This coupling must be provably exhaustive (a test
  asserting no `StopUnit` is reachable with `PreviousVersion==""` outside the
  sanctioned first cut).
- `versions/` is maintainer-script-managed, dpkg-untracked → never clobbered by
  unpack; dpkg only writes `staged/`.
- Resume-after-crash stays journal-driven; lock is reboot-clearing (`/run`).
- HA nodes stay stage-only; the lock does not change gating.
- Atomic-rename + SyncDir ordering for symlinks/dirs preserved (incl. the new
  preinst snapshot, which uses `.partial`+rename).
- Preinst writes no upgrade journal.

## 9. Risk assessment

| Class | Level | Note |
|---|---|---|
| Behavioral regression | MED–HIGH | preinst/postinst/postrm + sbin-layer migration touch every host's install path; needs baked-image + cluster-deb dogfood gates and a legacy→seeded migration test |
| Lifetime/borrow | LOW | Go; lock fd via defer |
| Performance | NONE | upgrade path only |
| Architectural mismatch | LOW | r1 confirmed B+A+C shape; v2 fixed the module boundary + sbin-migration + idempotency details |

## 10. Out of scope

True zero-gap cut-over (M-mech-2); cluster-orchestration changes; #1961 /
#1962 / #1960; #1966 doc edit (ship-direct).

## 11. Resolutions (r2) + residual confirmations

Resolved in r2 (Codex r1 + AGY r1/r2 + SMR r1/r2):
1. **preinst lock gate** — fail-loud non-zero at preinst (system unmodified) is
   the right apt-citizen behavior (AGY-r2-3); it does not fully serialize unpack
   vs a concurrent operator copy — `verify-dataplane` is the torn-binary
   backstop (SMR-r2-m1, §5).
2. **CopyTree checksum** — does NOT close the staged source race (verified
   cutover.go:321-334); `staged/` has no writer besides dpkg (AGY-r2-§5.2).
3. **postrm** — leave `versions/` on `remove`, remove on `purge` (Policy §6.8,
   AGY-r2-§5.3).
4. **preinst `<oldver>`** — `staged/xpfd version` (safe segment); fall back to
   sanitized dpkg `$2`, don't fail on exec error (AGY-r2-§5.4).
5. **C2/C3** — drop C2, keep C3 diagnostic-only (§6).
6. **lock re-entrancy** — `r.Run()` under `RunRolling` must not re-acquire
   (`Options.LockAlreadyHeld`, AGY-r2-4); `mkdir -p /run/xpf` before acquire.

Residual for the final confirmation round:
- Codex r2 was infra-dropped; retried on v2.2 (per `feedback_codex_infra_must
  _retry`). If Codex stays infra-blocked, convergence rests on SMR + AGY (both
  PLAN-NEEDS-MINOR on v2.1, all minors folded here) with documented retries.
- Implementation-time: prove the C-pre-STOP-exhaustiveness test (§8) and the
  preinst crash-interleaving matrix (§4) actually hold.
