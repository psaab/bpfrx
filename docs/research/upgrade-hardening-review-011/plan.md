# Upgrade-subsystem hardening — plan of action (review-011)

**Status:** DRAFT v2.1 — r1 was PLAN-NEEDS-MAJOR from all three reviewers
(Codex, AGY, Claude SMR). v2 folded every r1 finding; v2.1 corrects the
staged-overwrite-race resolution (the CopyTree checksum does NOT close it —
verified; the fix is a preinst lock gate). Pending r2.
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
  atomically repoints sbin through `versions/current`. **Idempotent:** if
  `versions/current` already exists, no-op; additionally guard against a prior
  crashed attempt by recording the snapshot only when the staged binary's
  runtime version still equals `<oldver>` (AGY-1). Writes **no** upgrade
  journal (preserves journal idempotency).
- **C — refuse-before-STOP (Go, runner.go).** Before `StopUnit`, hard-fail the
  cut when `PreviousVersion==""` and the run is not an explicitly sanctioned
  no-rollback first cut. Guarantees a healthy daemon is never stopped without a
  restorable on-disk target. Last-ditch — A/B should make this unreachable in
  the field.

**Module boundary:** `pkg/upgrade/runtime` owns first-install seed (A) +
postinst/runner-side logic + tests. The legacy preinst migration (B) is shell
in `debian/xpf.preinst` (cannot use the not-yet-unpacked Go binary).

**postrm:** extend `debian/xpf.postrm` to also remove sbin links pointing
through `versions/current`. `versions/` is runtime state — treat like
`/etc/xpf`: leave on `remove`, and either leave on `purge` or remove only the
maintainer-managed tree (decide in r2; default: leave, like other runtime
state).

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
  journal-driven, not lock-driven). Owner metadata (PID, subcommand, target,
  start time) in the lock file; busy errors name the owner. Status / kernel
  `status` stay lock-free (or `LOCK_SH`).
- **Rolling scope (AGY-3):** acquire at `RunRolling` entry, hold through
  rejoin — covers the peer-check + ForceSecondary + ≤30 s drain window, not
  just `r.Run()`.
- **dpkg-clobbers-staged (Codex-3 / SMR-M3) — CORRECTED in v2.1.** The rollback
  target is safe (it lives in `versions/`, dpkg-untracked — §4). But the *source
  race* — dpkg overwriting `staged/` while a concurrent operator `xpfd upgrade`
  copies it — is **NOT** caught by the CopyTree checksum. Verified against
  `copyStaged` (cutover.go:321-334): `sum` is computed by `copyTree` from the
  **source bytes as it reads them**, and `verifySum` re-reads the **dest**; a
  concurrent source overwrite yields matching torn bytes on both sides
  (undetected). The checksum catches copy/disk corruption, not concurrent
  source mutation. **Real fix:** `debian/xpf.preinst` acquires
  `/run/xpf/upgrade.lock` (`LOCK_NB`) and **fails the package operation before
  unpack** if busy — serializing dpkg's `staged/` overwrite against an
  in-flight operator `xpfd upgrade`. Failing at preinst (before any mutation)
  is the clean place for fail-loud: the apt transaction aborts before unpack,
  no half-configured state. Caveat: a flock fd does not survive the preinst→
  postinst process boundary, so preinst check-and-release leaves a tiny TOCTOU
  window (operator grabs the lock between preinst and postinst) — covered by
  postinst's own `LOCK_NB` acquire (next bullet).
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
  (cutover.go:174-177), trigger rollback to `PreviousVersion` (or, where none
  exists, C has already prevented the STOP). Closes the stranded-offline-daemon
  path. **Add to #1967.**
- **NEW — postrm versioned-link cleanup (Codex):** §4. **Add to #1967.**
- **C2:** largely redundant — flip.go:52 already returns daemon-reload failure;
  keep only the resumed-flip re-validation nuance, or drop.
- **C3:** verify `versions/<ver>/` before StartUnit — optional, diagnostic /
  HA-fail-fast value (outcome already covered by START-failure auto-rollback,
  cutover.go:183).
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
- The running daemon is never stopped without a restorable on-disk target
  (C + flip-failure rollback + the `versions/` contract).
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

## 11. Open questions for r2

1. **preinst lock gate (§5):** is failing the apt transaction at preinst
   (non-zero, before unpack) when `/run/xpf/upgrade.lock` is busy the right
   apt-citizen behavior, vs letting unpack proceed and deferring at postinst?
   And is the preinst-check / postinst-reacquire TOCTOU acceptable given flock
   fds don't survive the process boundary?
2. **RESOLVED in v2.1:** the CopyTree checksum does NOT close the
   staged-overwrite source race (verified, cutover.go:321-334) — the preinst
   lock gate is the fix. r2: confirm there is no other concurrent writer of
   `staged/` besides dpkg that the preinst gate would miss.
3. **postrm on purge (§4):** leave `versions/` (like `/etc/xpf`) or remove the
   maintainer-managed tree?
4. **preinst `<oldver>` source under format drift:** `staged/xpfd version`
   validated as safe-segment; fallback if the old binary won't exec?
5. **C2/C3 final disposition:** drop C2 (redundant with flip.go:52) and keep C3
   diagnostic-only, or drop both and rely on auto-rollback + the new
   flip-failure rollback?
