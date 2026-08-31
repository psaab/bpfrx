# Plan: #7289 — what an abort after the Phase-2 host mutation should do

**Status:** DRAFT v2, UNREVIEWED. r1 killed v1: Codex returned **PLAN-KILL**
("a failed plan, not a request for implementation detail") and Claude SMR
returned **PLAN-NEEDS-MAJOR**; AGY was infra-blocked with 2 documented retries.
v1's recommendation is **withdrawn**, not amended: P3 (re-drive engine) and P4
(ownership ledger) are removed. This is a `/research` deliverable and stops at
PLAN-READY / PLAN-KILL / PLAN-DEFER.

**Correction on the record:** an earlier revision of this header, and the first
round-status comment on #7289, reported Codex as PLAN-NEEDS-MAJOR. That was read
from an incomplete mid-write snapshot of `codex-plan-r1.md` while the reviewer
was still running. The findings were identical; the disposition was not.

**Verified against:** `origin/master` `f32aacbac`. Premises in
`premise-check.md`; reviews in `claude-smr-plan-r1.md` and `codex-plan-r1.md`.

---

## 0. What r1 changed, stated before anything else

v1 recommended converging forward. Both reviewers falsified it, on different
grounds, and one of them falsified a claim in my own premise check.

**0a. Converge-forward has no fixed point in current code.** `LinkSetMTU` does
not refresh the cached `netlink.Link` attrs in the pinned v1.3.1, and
`cachedLinkByName`/`cachedLinkByIndex` share one object (`compiler.go:147-176`),
so an interface with both an interface-level and a unit-level MTU **alternates
between them on every apply**. Verified independently; filed as its own defect
(#8119) because it is a steady-state bug, not an abort-path one. A phase that
does not converge under repetition cannot be the basis of a convergence design.

**0b. The hazard is worse than I wrote, and it is a security hole.**
`premise-check.md` §E said the divergence leaves "old policy over new topology".
Codex finding 5 showed otherwise and I verified it: an attach failure returns
before `ProveArmCoverage` publishes (`loader.go:309-330`), so the apply tail
classifies coverage as `armCoverageUnknown` — and `evaluateArmCoverage` has **no
case** for unknown (`daemon_arm_coverage_7191.go:78-112`). Nothing disarms. On a
fresh boot, where the runtime is armed before the first per-interface attach,
that leaves an **armed, open kernel transit path with an interface carrying no
XDP shim at all** — the policy-free-router state #7191 exists to prevent.

That inverts the priority. The reachable case is not a staleness window to be
converged away; it is an unadjudicated forwarding surface that must be closed
**immediately**.

**0c. The 20/2/3 partition was not a partition**, the "one reachable trigger"
premise was false, and the abort prefix is not merely nondeterministic — the
**final** host state is, because two units of one physical interface may sit in
different zones and each reconciles the same netdev to its own addresses and MTU
under a nondeterministic zone-map order. That is a second live defect and needs
its own issue.

## 1. What this plan now proposes

Three items. None of them is a convergence engine, and the plan does not claim
the abort becomes recoverable.

**R1 — Close the unadjudicated surface immediately (the security fix).**
A generic-attach failure must disarm, irrespective of any later retry design.
Today it does not, because the coverage verdict is `unknown` and `unknown` is
unhandled. The narrowest correct change is to make an attach failure a
*published* incomplete coverage report, or to give `evaluateArmCoverage` an
`unknown`-after-a-failed-apply case. This is the only item that closes the
reachable case, and it composes with #7191 rather than inventing anything.

**R2 — A typed, phase-aware authority record (replacing v1's P2).**
One "host mutated" bit cannot describe the state, because failures span
pre-publication, ambiguous publication, and post-publication. What exists today:
`recordCompileFailure` already records count/last-error/timestamp
(`daemon_health.go:110-128`), and `hostMutations` already exists on
`CompileResult` but is dropped by `ApplyResultFromCompileResult`
(`apply.go:210-229`) so it dies with the result. R2 is to thread a typed outcome
— which phase, which authority state — rather than to invent a store. It is
operator evidence and a prerequisite for any future recovery design; it is not
itself recovery.

**R4 — Make the child `LinkSetUp` failure observable and consistent.**
Its error is RETURNED on the VLAN create path (`compiler_iface.go:263`) and only
LOGGED on the adopt path (`:228-233`), so a re-drive after an abort between
`LinkAdd` and the set-up adopts a down child, fails to raise it, and reports
SUCCESS. My own r1 pass found this and v2 initially recorded it as a finding
without carrying it into the proposal; Codex's OQ-6 names it independently as
part of the shippable slice. Added here.

**R3 — The `accept_ra` re-drive correction.** `accept_ra=0` is written only on
the VLAN create path (`compiler_iface.go:268`); the adopt path returns at `:238`
before reaching it, so a re-drive after an abort between `LinkAdd` and that
write never retries it. Independently defensible, testable through the one
existing seam, and both reviewers accept it.

**Explicitly NOT proposed:** a re-drive engine, an ownership ledger, an undo
log, and the clause-1 planning/actuation split. Reasons in §2.

## 2. Why the rejected options stay rejected

- **(a) undo log / (d) ownership ledger.** Codex OQ-1: the boundary is already
  expanding and has no state machine; the foreign-bond class shows the ledger is
  the wrong remedy rather than an undersized one. Withdrawn.
- **(c) converge forward.** §0a: no fixed point in current code, and §0b: the
  reachable class must not be retried at all, because retrying prolongs an
  unadjudicated surface. Withdrawn as a *recommendation*; it may return as a
  proposal once #8119 and the zone-order defect are fixed and a real
  transient-error classification, scheduler, supersession rule and success
  predicate exist.
- **clause 1's split.** The snapshot must be built from POST-actuation live
  state. An ordering diagnosis is not a prescription to swap. (Stated in v1 on
  an inherited citation; re-derived here from `buildInterfaceSnapshots` reading
  live child ifindex/MTU/MAC/addrs.)

## 3. Acceptance clauses, re-scoped

The issue's three clauses do not survive as written:

1. **"Restore the prior host plan or keep the control plane disabled."** R1
   answers this for the reachable class — *keep disabled*, immediately, using
   shipped machinery. Restore stays rejected.
2. **"An apply that fails leaves a state the next apply converges."** Not
   achievable today and this plan does not claim it. #8119 must land first;
   even then it is a separate proposal.
3. **The soft VLAN-name skips.** Two sites in different states (#6893 covers
   one), and `compilePortMirroring`'s remains bare. Neither blocks R1-R3.

## 4. Test plan

R1 and R3 are testable with what exists: R1 through the coverage verdict
classifier, which is a pure function; R3 through `vlanLinkByNameSeam`, the one
seam in the path. R2 is testable at the `ApplyResult` boundary.

**What is NOT testable today, and this is why P3/P4 are gone:** 0 of the 23
write sites are injectable — the sole seam in the mutation path is a *lookup*
seam. Any convergence proposal must first add write seams, on the most
destructive path in the compiler, for testability alone.

## 5. Open questions remaining

**OQ-A.** Is R1 correct as "disarm on any attach failure", or does it need the
typed safety classification Codex's OQ-5 asks for? Retry count is explicitly not
that classification.

**OQ-B.** Does R1 regress the #1960 no-brick posture for an already-committed
config? My reading is no — management survives by construction — but a
fresh-boot disarm is a bigger event than an apply-time one.

**OQ-C.** Should R2 land before R1? R1 is the security fix and is smaller; R2 is
the evidence that makes the next design possible. They are independent.

## 6. Recommendation

**v1 is PLAN-KILLED. v2 is a re-derivation and is UNREVIEWED — PLAN-READY is
not claimed and PLAN-DEFER is not yet earned, because no reviewer has seen v2.**

The issue asks what an abort does to an already-mutated host. The honest answer
r1 produced is that the question was mis-scoped: the reachable case is not a
recovery problem but an **unadjudicated-surface problem**, and it has a shipped
mechanism that is simply not reached. R1 closes it. R2/R3 are small and
defensible. The convergence design the issue asks for is blocked behind two live
defects (#8119 and the zone-order one) that must be fixed before any fixed-point
claim can even be stated.

## 7. Revision log

**v2** — v1 PLAN-KILLED by Codex, PLAN-NEEDS-MAJOR by Claude SMR. Recommendation withdrawn. P3/P4 removed; §0a/§0b/§0c
record what falsified them; two live defects extracted to their own issues; the
recommendation is now R1 (security) + R2/R3 (small) with the convergence
question explicitly deferred.

**v1** — converge-forward + bounded ownership ledger. Falsified; kept in git
history for the argument trail.
