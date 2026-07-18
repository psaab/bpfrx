# Claude SMR — HOSTILE plan review r2 (v2 fence-first redesign)

Plan under review: `docs/research/4960-apply-txn/plan.md` @ `9a60f235fd9e` (v2).
Posture: adversarial. I probed the fence-first model for NEW gaps the redesign
introduces, grounded in source.

## Verdict

**VERDICT: PLAN-NEEDS-MAJOR** — narrowly. The fence-first architecture is the
correct, reviewer-endorsed shape and v2 addresses every r1 finding accurately.
But the redesign introduces **one genuine correctness hole in its own core
mechanism** (F1: the persistent apply-fence races the independent status-loop
ctrl writer and can be silently re-enabled mid-apply) plus two under-specified
load-bearing pieces (F2: the daemon↔Manager fence API is required, not optional,
and is not designed; F3: the §4.6(ii) success-window residual is real and must be
stated as an accepted residual, not implied harmless). These are addable in a v3
without further redesign — but a fail-closed plan whose fence can be defeated by a
concurrent 1/s loop is not yet PLAN-READY.

## Findings

### F1 — The persistent apply-fence races the status-loop ctrl writer (NEW gap in the core mechanism). [CORRECTNESS]

The whole v2 contract is "ctrl stays disabled from FENCE (before P1) until a
verified commit (P7)" — a fence that must persist across P1-P5, which includes a
helper round trip with up to a 67s deadline (`process_control.go:42-56`). But
**ctrl is written by an independent second writer**: `applyHelperStatusLocked`
re-derives and writes `userspace_ctrl` from the helper's reported status, and it
runs BOTH on the apply path (`process_status.go:119`) AND from the `statusLoop`
goroutine every tick (`process_status.go:134-152`). If the status poll fires
during the fenced apply window and the helper still reports `Enabled` (it is
enforcing the OLD snapshot, which was armed), `applyHelperStatusLocked` will write
`userspace_ctrl.enabled=1` — **silently lifting the fence mid-apply**, exactly
when host/maps are in a candidate/mixed state. The fail-closed guarantee
evaporates.

They are both under `m.mu`, so they don't corrupt the map, but serialization is
not the issue — the issue is that the status loop's *intent* (reconcile ctrl to
helper status) contradicts the apply's *intent* (hold ctrl down until commit). A
one-shot ctrl=0 write at FENCE is not a fence; the fence must be a **state the
status-loop writer respects.**

**The fix already has precedent in the tree** (v2 should cite it): the manager
keeps ctrl disabled during RG handoff via `m.rgTransitionInFlight`
(`maps_sync.go:375-380` — `applyHelperStatusLocked` forces `ctrl.Enabled=0` while
`rgTransitionInFlight` is set). v2's fence needs an analogous
`applyInFlight`/`fenceHeld` gate that `applyHelperStatusLocked` checks and honors
(force ctrl=0 while held), set at FENCE and cleared only at P7. Without naming
this, §4.1's invariant is unenforceable. This is the single blocking item.

### F2 — The daemon↔Manager fence API is REQUIRED for #4960, and is not designed. [COMPLETENESS]

v2 §4.5/§7.4 correctly states `Manager.Compile` is not the sole host orchestrator
(the daemon reconciles VRF/xfrmi/bond/tunnel/fabric-IPVLAN before
`d.dp.ApplyConfig`, `daemon_apply.go:916-959`, and RETH MAC/VIP after). It then
says "simplest: the daemon establishes the fence before its host reconcile and
lifts it after the Manager reports a verified commit." **That is not a detail — it
is a new cross-package API** (`Manager.Fence()`/`Unfence()`/`FenceHeld()`, or a
fence token threaded through `ApplyConfig`) that land 2 cannot ship without. v2
leaves it as a gesture. For a PLAN-READY research doc the API surface must be named
concretely enough that `/engineer` knows what it is building — even if the
signature is provisional. Related: F1's `applyInFlight` gate and this daemon fence
are the SAME state (the daemon owns the outer fence; the Manager's status loop
must honor it), so they must be designed together, not as two independent gates.

### F3 — §4.6(ii)'s success-window residual is real; state it as an accepted residual. [HONESTY]

§4.6 recommends option (ii): keep the classifier-map-only path hitless on SUCCESS
(no up-front fence), fence only on a non-Accept outcome. v2 calls the transient
new-maps/old-helper success window "bounded, self-healing, harmless." It is
bounded and self-healing, but not unconditionally harmless: for a **removed**
local/NAT address, during the round trip the NEW local map no longer marks the
old address as local, so a packet to the old address is XSK-redirected to the
helper still enforcing the OLD snapshot (which still treats it as local) — a
transient misroute for the removed address until ACK. This is strictly smaller
than the #4959 bug (bounded to the round trip, self-heals on ACK, vs #4959's
persistent mismatch), and is the price of preserving hitless address-only commits.
But v2 must state it as an **explicitly accepted residual** (with the direction —
removed addresses — named), not imply the success window is inconsistency-free.
Otherwise a reviewer or `/engineer` will either "fix" it (regressing to
fence-always) or be blindsided. Option (i) fence-always eliminates it at the cost
of hitless; that tradeoff (OQ-A) is the right place to record this.

## Smaller notes

- N1: §4.3 outcome 2 ("pre-teardown reject, old live") assumes Go can read the
  Rust status on NACK to distinguish it from outcome 3 (post-teardown down). v2
  correctly flags (OQ-D) that the safe collapse is "any non-Accept ⇒ stay fenced."
  Recommend v3 make the collapse the DEFAULT and treat the finer distinction as a
  recovery-optimization, so the plan's correctness never depends on the Rust
  status being reliably parseable.
- N2: §4.2 P1 "new links created DOWN or shim-attached before going up" requires
  reordering `ensureVLANSubInterface` (`compiler_iface.go:105-154`), which today
  does `LinkAdd`→`LinkSetUp` immediately. v2 names this (§1) but the test list
  (test 7) should assert a newly-created VLAN child is NOT brought up before its
  shim attach under the fence.
- N3: the fence-window duration (OQ-B) should get a rough bound in the plan (P1
  host actuation + P2 build + P4 round trip) so the operator can judge the
  per-apply outage cost — even an order-of-magnitude ("sub-second typical,
  up-to-67s pathological on a stuck helper") is enough to make OQ-A/B decidable.

## What's right (keep)

- Dropping the rollback journal + B1 re-reconcile for the fence model — correct,
  and it dissolves the packet-observable-atomicity impossibility.
- P2-after-actuation snapshot build — correctly fixes Codex 6.1.
- Typed publication outcomes + "NACK ≠ old live" (#4952) — correct.
- Daemon typed dispositions + HA-readiness fence check — correctly identified as
  required, not optional.
- §12's point-by-point r1 response is accurate and complete.

VERDICT: PLAN-NEEDS-MAJOR — the fence-first architecture is sound and every r1
finding is addressed, but the plan's own fence can be silently lifted by the
concurrent status-loop ctrl writer (F1), and the daemon↔Manager fence that #4960
depends on is gestured at rather than designed (F2); both are addable in a v3
that names the `rgTransitionInFlight`-style apply-in-flight gate and the daemon
fence API, at which point this is PLAN-READY.
