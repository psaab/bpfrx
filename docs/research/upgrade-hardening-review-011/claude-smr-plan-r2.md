# Claude SMR hostile plan review — round 2

**Plan:** `plan.md` @ `704374a73` (v2.1)
**Verdict: PLAN-NEEDS-MINOR**

Self-correction first: my r1 was PLAN-NEEDS-MINOR; AGY and Codex were
PLAN-NEEDS-MAJOR and they were right — they found the preinst-cannot-use-the-
Go-module constraint, the sbin-migration-before-unpack requirement, the
rolling-lock-scope gap, the flip-failure-rollback gap, and the preinst re-run
idempotency hole, all of which I missed. v2 folded them. While writing v2 I also
made a *new* wrong claim (the CopyTree checksum closes the staged-overwrite
race); I caught it by reading `copyStaged` (cutover.go:321-334) and corrected it
in v2.1. That correction is itself the subject of my one remaining objection.

## m1 — the preinst LOCK_NB gate does NOT fully serialize unpack vs a concurrent operator copy

v2.1 §5 says the preinst `LOCK_NB`-before-unpack gate "serializes dpkg's
`staged/` overwrite against an in-flight operator `xpfd upgrade`." It does not,
fully. A flock fd dies when preinst exits, so preinst can only **check-and-
release**; the lock is **not held during dpkg's unpack**. Sequence that still
tears:

1. preinst checks lock free, exits (lock released).
2. dpkg begins overwriting `staged/`.
3. *During* unpack, an operator runs `xpfd upgrade` → acquires the now-free
   lock → `copyTree` reads `staged/` mid-overwrite → torn read.

So the preinst gate **narrows** the window (it blocks an operator who *already
holds* the lock at preinst time) but does not close it. v2.1 over-claims.

**The real backstop is `verify-dataplane`, not the lock and not the checksum.**
A torn ELF either fails to exec or fails the kernel verify-dataplane gate
(cutover.go:151), which runs against the COPIED binary **before** StopUnit — so
a torn copy aborts the cut while the daemon is still up. The plan should say
this plainly: preinst gate (narrows) + verify-dataplane (catches a torn/non-
execable binary before STOP) + documented operator guidance ("do not run
`xpfd upgrade` during `apt upgrade`") — *not* "the preinst gate closes the
race." This is a one-paragraph honesty fix, not a re-architecture.

## m2 — make the flip-failure-rollback ↔ C coupling explicit

§6's new flip-failure rollback says "trigger rollback (or where none exists, C
has already prevented the STOP)." That guarantee only holds if **C runs before
StopUnit on EVERY cut path**, not just package-upgrade paths. If any cut reaches
STOP with `PreviousVersion==""`, then flip() failure → rollback refuses →
daemon stranded (exactly AGY-5's failure, just relocated). The plan must state C
as an unconditional pre-STOP invariant: *no cut stops the unit unless a
restorable target exists OR it is an explicitly sanctioned no-rollback first
cut* — and in the sanctioned-first-cut case, flip-failure must restart the
just-stopped (old, still-on-disk in versions/ via A/B) daemon. Tighten the
wording so the two mechanisms are provably exhaustive.

## Confirmed sound in v2.1 (not nits)

- The `versions/`-is-maintainer-managed-runtime-state contract (dpkg never in
  its file list) is the right spine and correctly makes the *rollback target*
  un-clobberable (distinct from the *source* race in m1).
- Legacy migration as self-contained shell preinst (not the Go module) — Codex
  was right; v2.1 has it.
- preinst idempotency (no-op if `versions/current` exists; snapshot only if
  staged still == oldver) addresses AGY-1.
- rolling lock at `RunRolling` entry through rejoin — AGY-3, correct.
- safe-single-path-segment validation (not strict regex) — handles Debian `+`/
  `:`; correct.
- one host-wide `/run` lock, status lock-free, kernel subcommands participate.

## To reach PLAN-READY

1. Rewrite §5's staged-race paragraph to claim only what's true (preinst gate
   narrows; verify-dataplane is the torn-binary backstop; operator guidance
   documented). (m1)
2. State C as an unconditional pre-STOP invariant and define the sanctioned-
   first-cut flip-failure behavior. (m2)

Both are doc refinements; the architecture is sound. If Codex/AGY r2 surface
nothing larger, this converges at PLAN-READY after a v2.2 with these two edits.
