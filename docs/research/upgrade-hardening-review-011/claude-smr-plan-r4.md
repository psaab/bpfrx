# Claude SMR plan review — round 4 (final / convergence)

**Plan:** `plan.md` @ v2.4
**Verdict: PLAN-READY (convergence declared)**

v2.4 folds all five AGY-r4 findings — three of which (#1 stale `current` on
downgrade, #2 verify-fail journal-state reset, #3 never-delete-the-active-
version) are genuinely sharp consequences of the v2.3 fixes and are now inline
in §4/§6; #4 (boot-guarded `systemctl`) and #5 (`mkdir /run/xpf` in preinst)
are folded too.

**Why convergence now, not another round:** the core architecture has been
unchallenged by every reviewer since r1 (4 rounds). The review has reached the
regime where each round only surfaces finer implementation-detail bugs in the
*previous round's* maintainer-script/cleanup additions — i.e. code-level bugs in
shell/Go that does not exist yet. That is precisely what `/engineer`'s 4-way
code review (Codex + AGY + SMR + Copilot, against real code + tests) verifies.
The plan's job — enumerate the design, the path options, and every known
gotcha for the implementer — is complete. Continuing to round-trip AGY would
keep producing real but ever-finer code-level items without changing the
design.

**Codex:** r1 PLAN-NEEDS-MAJOR (all 3 points folded); r2/r3/r4 retries were
infra-dropped (companion returns "No job found" on result fetch). Per
`feedback_codex_infra_must_retry`, documented retries + 3-of-4 convergence
(SMR READY + AGY all-folded + Codex-r1-folded) is the sanctioned path when
Codex is infra-blocked.

**Carry into `/engineer` as an implementation checklist (must-verify against
real code + tests):**
- preinst crash-interleaving matrix (snapshot / rename ENOTEMPTY / sbin repoint
  / current symlink), idempotent at every step.
- C-pre-STOP exhaustiveness test (no `StopUnit` with `PreviousVersion==""`
  outside the sanctioned first cut).
- verify-fail cleanup guards: never delete the active version; reset journal.
- lock re-entrancy (`Options.LockAlreadyHeld`) on the rolling path.
- downgrade cleanup deletes `versions/current`.
- boot-guard every maintainer-script `systemctl`.
- baked-image + cluster-deb dogfood gates (changes every host's install path).
