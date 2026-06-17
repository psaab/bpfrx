# Claude SMR hostile plan review — round 1

**Plan:** `docs/research/upgrade-hardening-review-011/plan.md` @ `99842573b`
**Verdict: PLAN-NEEDS-MINOR**

The findings are all independently verified (I read postinst, flip.go,
runner.go, system_linux.go, bake.py, debian/control directly — not just trusting
the workflow verifiers). The direction is sound and the solid-invariant
inventory is honest. But four substantive issues keep this from PLAN-READY.

## M1 — #1964 over-weights Option B (preinst snapshot); it may be unnecessary

The plan recommends **B (preinst) + A (first-install seed) + C (refuse)**, with B
load-bearing "because it is the only option that gives the legacy-migration
upgrade a rollback target." But the in-place upgrade mechanism itself is new
(#1917). **How many hosts are actually deployed on the legacy direct-staged
layout that B protects?** If the first appliances to ship are baked *with* the
fix, then A (seed at first install / in bake) fixes every host that will ever
exist, and there are zero legacy hosts for B to protect. In that world B is
pure complexity (a new maintainer script, doubled install-time disk for the
snapshot) guarding an empty population.

Recommendation: foreground **A + C** as the primary fix and gate B explicitly
on "do real direct-staged hosts exist in the field?" If the answer is no, B is
out of scope (or a one-line documented caveat: the single legacy-migration
upgrade is rollback-less, mitigated by C refusing to stop the daemon). This is a
scope-reduction the plan should make a decision on, not leave as open-Q #1.

## M2 — the `<oldver>` key derivation is load-bearing and unresolved

`versions/<v>` dirs are keyed by the **runtime** version string
(`BinaryVersion()` = `xpfd version` output → `readCurrentVersion()` does
`filepath.Base(symlink)`). The plan's open-Q #2 floats dpkg `$2` (the *debian
package* version) as an alternative key. **These are different namespaces.** If
seeding (A or B) keys `versions/<debian-$2>` but the cut keys
`versions/<runtime-version>`, `readCurrentVersion()` returns a dir the cut
never matches → `PreviousVersion` is wrong → rollback restores the wrong (or no)
version. Whatever seeds the layout MUST use the same runtime-version source the
cut uses (`staged/xpfd version`, validated per C1). This is not an open question
to defer — it is a correctness constraint the design must state.

## M3 — the lock does NOT serialize against dpkg's overwrite of `staged/`

#1965's lock serializes `xpfd upgrade` invocations, but `/usr/local/share/xpf/
staged/*` is shared mutable state that **dpkg** overwrites outside the lock. An
operator `xpfd upgrade` (holding the lock) whose CopyTree reads `staged/` while
a separate `apt` transaction is unpacking new binaries into `staged/` gets a
torn read. The plan should state explicitly that this is **caught** by the
confirmed-solid CopyTree post-copy checksum re-verify (a torn copy fails
verification and aborts the cut before STOP) — i.e. the lock is necessary but
not sufficient, and the checksum is what closes the staged-overwrite race. If
that reasoning is wrong (e.g. checksum is computed from the same torn source),
this becomes a real hole. Reviewers should confirm the checksum source is
independent of the copy.

## M4 — C2/C3 are largely redundant with existing auto-rollback

C3 (verify `versions/<ver>/` before START) and C2 (re-validate after a resumed
daemon-reload): if the dir vanished or the reload failed, START fails and
**auto-rollback already fires** — the outcome is identical. C2/C3 only make the
failure faster/clearer, not safer. Given the plan's own honesty rule, these
should be down-scoped to "diagnostic clarity, optional" or dropped, unless a
reviewer identifies a path where START *succeeds against a broken dir* (e.g.
partially-present binary that execs but misbehaves) that auto-rollback's health
check would miss. C1 (version validation) and C4 (sync-after-removal) are the
genuinely load-bearing items in #1967.

## Confirmed correct (not nits)

- F1/F2/F3/C1 mechanisms all verified at the cited lines; severities sound
  (F1/F2 HIGH, C1 MEDIUM-as-robustness-not-security, F3 LOW).
- `/run/xpf/upgrade.lock` reboot-clear is the right call given journal-driven
  resume — a `/var` lock would need stale-lock detection for no benefit.
- One host-wide lock covering binary + kernel is correct (shared availability
  envelope).
- The new-module boundary (`pkg/upgrade/runtime` + `pkg/upgrade/lock`) keeping
  this out of `runner.go` is right per the codebase's modularity discipline.

## What would move this to PLAN-READY

1. Decide M1 (is B in or out?) with a stated rationale tied to whether legacy
   direct-staged hosts exist.
2. State M2 as a design constraint (runtime-version key, not dpkg `$2`).
3. Add the M3 staged-overwrite/checksum reasoning to §8 invariants.
4. Down-scope or justify C2/C3 (M4).
