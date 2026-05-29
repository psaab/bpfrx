# Claude SMR plan-review r2 — #1648 (on plan v2 / v2.1)

**Reviewer framing:** netlink / AF_XDP-startup / HA-failover / neighbor-cache
domain expert. Verdict r2: **PLAN-READY (converged).**

v2 resolved all three of my r1 CRITICALs and absorbed the r1 Codex + AGY rounds.
v2.1 absorbs the two genuinely-new Codex r2 points (crash-promote coverage +
kill-bar-must-use-cold-target). I confirm convergence.

## My r1 CRITICALs — resolution check
- **CRITICAL-1 (hypothesis ordering):** RESOLVED. v2 promotes H-0 (seq=0
  multicast drop in `initial_neighbor_dump`) to the lead. I was wrong in r1 to
  argue dump-ordering can't produce 1.7s — AGY's verified trace shows the
  *resolution advert* (the probe's own reply) arrives as a seq=0 multicast
  during the dump window and is dropped by `neighbor.rs:434`, so the buffered
  SYN sits to the 800ms timeout → drop → client 1s RTO. The dump need not be
  slow; the *resolution* is dropped. My CRITICAL-1 self-corrects: dump-ordering
  IS the mechanism, contingent on R1's daemon counter A confirming the seq=0
  drop. Correctly gated.
- **CRITICAL-2 (World 2 + kill bar):** RESOLVED. v2 added the passive-standby-
  learn mechanism and a quantitative kill bar; v2.1 sharpens it to the
  never-seen/aged target (Codex r2 CRITICAL-1 — a fast result on a prelearned
  target is a false negative).
- **CRITICAL-3 (5.C.2 self-defeating):** RESOLVED. v2 REJECTS 5.C.2 outright.

## r2 hostile pass — new pressure tests
1. **5.A.2 DEL safety:** I verified `parse_neighbor_msg` (`neighbor.rs:344-359`):
   for type 28 (NEW), INCOMPLETE|FAILED → remove, else upsert; type 29 (DEL) →
   remove. The remove on a NEW only fires for INCOMPLETE/FAILED, and a seq=0 DEL
   removes unconditionally. **Open risk for /engineer:** a seq=0 RTM_DELNEIGH
   processed during the dump could remove an entry the dump just inserted (e.g.
   a transient STALE→DELETE churn). The fix must order/guard so a mid-dump DEL
   doesn't race a same-key dump NEW. Low-probability (the cold target is being
   *added*, not deleted, during cold start) but must be a unit test at
   /engineer. Noted in plan §5.A.2. Not a plan blocker — an implementation
   guard.
2. **Promote critical path:** confirmed clean. 5.A.2 lives in
   `initial_neighbor_dump`, which runs in the detached neigh-monitor thread at
   bring-up — NOT on the `on_rg_promote_active` path (`ha.rs:164`, which only
   enqueues to the async warmer). No blocking work added to promote; VRRP
   (`pkg/vrrp/`, Go control plane) is untouched. ~60ms failover preserved.
3. **Kill bar tightness (Codex r2 CRITICAL-1):** v2.1's ≥4/5, both v4+v6, on the
   provably-cold target B, across BOTH clean and crash promote, is the right
   bar. Tightening to 5/5 would be brittle against the legitimate 0.6-3.7ms
   variance Gate-M already showed; ≥4/5 with a 200ms ceiling (≫ the 3.7ms p100)
   is correct.
4. **Missed mechanism check:** I re-checked whether the worker poll loop could
   itself be the 1.7s (e.g. the binding not steered at T0 → SYN XDP_PASS'd).
   v2 R1 step 7 (XDP-readiness check) covers this as a fallback hypothesis if
   H-0 is refuted. Adequate.

## Verdict
**PLAN-READY (converged).** The plan is measurement-first, the mechanism is
verified (pending R1 daemon-counter confirmation), the fix is minimal and
HA-safe, the rejected candidates are rejected on verified grounds, and the
kill-bar is now false-negative-resistant. Ship to Gate-R at /engineer; do NOT
write code until R1 counter A + R2 cold-target-crash-promote are measured.

If Gate-R confirms H-0 and World 1: 5.A.2 (~5-15 LOC) takes failover/restart
first-connect ~1.7s → ≤200ms (likely ~5-15ms), VRRP unchanged. If R2 = World 2
on the cold target: ship 5.A.2 anyway as the cheap correct deploy-restart fix,
or PLAN-KILL with the measurement.
