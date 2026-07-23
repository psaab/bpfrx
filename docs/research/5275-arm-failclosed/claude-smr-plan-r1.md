# Claude SMR — hostile plan review r1 (#5275)

Reviewing `docs/research/5275-arm-failclosed/plan.md` @ r2-draft. Posture:
adversarial. I verified the load-bearing claims firsthand against origin/master
@ 6131eb4e6 rather than trusting the doc.

## Verified TRUE (firsthand)

- **Terminal abort skips the tail.** `applyConfigLocked` (daemon_apply.go:288)
  `if err != nil { return d.closeoutHostAuthOnCancel(err, cfg) }` short-circuits
  BEFORE `applyRoutingRules` (318), `applyServicesReconcile` (335), and
  `applyTailReconciles` (355). For a non-cancellation error `closeoutHostAuthOnCancel`
  returns it unchanged. So A1's "abort ⇒ no tail publish" holds. ✓
- **Attach error propagates.** `attachUserspaceShimXDP` both-fail (loader.go:242)
  → `CompileUserspaceShim` (loader.go:191) → userspace `Manager.Compile`
  (manager_compile.go:187) → userspace `Manager.ApplyConfig` (manager.go:354-355)
  → `applyDataplaneAndHACore` (daemon_apply.go:1073). ✓
- **`recalcWeight` clobbers weight-0** (election.go:503) — B2 rightly rejected;
  B1 (StateSecondaryHold) is sticky. ✓
- **election.go:165 peer-yield on StateSecondaryHold** exists and precedes the
  weight/preempt compares. ✓

## MAJOR? No. MINOR corrections required (the plan's MECHANISM description is
## wrong in one load-bearing spot):

### M1 — `applyConfig` is VOID; the plan's "arm sites capture the return" is
### unimplementable as written. (Correctness gap in §5.A/§8.)

`func (d *Daemon) applyConfig(cfg *config.Config)` (daemon_apply.go:49) returns
NOTHING — it swallows `applyConfigLocked`'s error internally
(`slog.Warn("apply config failed"...); return`). So `armBuiltDataplaneAndApplyBootConfig`
CANNOT "capture applyConfig's (now non-discarded) return" — there is no return,
and `applyConfig` has many callers (DHCP callback, feed, config-poll, in-process
CLI commit). Changing its signature is invasive and out of scope.

**Required fix:** the detection AND the `enterDataplaneArmFailedFailClosed`
invocation must live INSIDE the apply pipeline where the error is known —
`applyDataplaneAndHACore` (classification) / `applyConfigLocked` (line ~288) —
gated on `!d.dataplaneEverArmed.Load()`, NOT at the two arm sites. The arm sites
call `applyConfig` unchanged; the pipeline self-fails-closed. This is actually
CLEANER and covers all entry points uniformly (boot arm, bootstrap-exit arm, and
a post-bootstrap first-ever operator commit that is the first arm), while
`dataplaneEverArmed==true` keeps every day-2 commit on #5679.

Note: invoking the handler mid-pipeline runs the ~40 s FRR clear + VRRP teardown
under `applySem`. Acceptable on boot; the handler's calls (`frr.Clear`,
`vrrpMgr.UpdateInstances`, `cluster.SetArmFailedHold`) do not re-acquire
`applySem`, so no deadlock — but the plan must state this and the reviewer/impl
must confirm it.

### M2 — Specify WHEN `dataplaneEverArmed` flips, for A1/A2 consistency.

If ApplyConfig returns nil but `ForwardingArmed()==false` (A2 silent-partial
case), setting `dataplaneEverArmed=true` purely on "ApplyConfig returned nil"
would wrongly mark a never-actually-armed node as ever-armed. **Required:** set
`dataplaneEverArmed=true` only when ApplyConfig returns nil AND
`ForwardingArmed()==true`. Otherwise fail closed (never-armed).

### M3 — §7 hard escalation MUST exclude the protected mgmt set (violates G2 as
### written).

"Escalate to administratively DOWN the transit/data interfaces" — if that set is
computed naively it can catch `fxp0` / the mgmt-VRF member and sever the lifeline,
violating G2. **Required:** the escalation must reuse the same protected-interface
resolver networkd uses (`resolveProtectedInterfaces` / `SetProtectedResolver`,
derived from ActiveConfig independently of ManagedInterfaces) and NEVER down a
protected/mgmt interface. State this explicitly in §7.

### M4 — §6 must state WHY the non-listed ActiveConfig readers are out of scope.

A hostile reviewer will point at `daemon_ha_userspace_stream` (session sync),
`daemon_dhcp` (relay), `daemon_ddns`, SNMP, `daemon_ha_fabric` (fabric),
`daemon_neighbor` (proactive neighbor) and ask "why aren't these gated?" The plan
must pre-empt this: none of them publish TRANSIT FORWARDING, ROUTE ADVERTISEMENT,
or VIP/OWNERSHIP — the #5275 hole is specifically policy-free transit +
advertisement + HA takeover. Session sync / fabric are no-ops with `d.dp==nil`;
relay/DDNS/SNMP are control-plane, not transit policy. List them explicitly as
"considered, out of scope, reason" so the enumeration is auditable — otherwise the
canary test's publisher set is unjustified.

### M5 — Clarify that A1 minimizes the §7 teardown surface.

On the A1 abort path the tail never published, so the handler's VRRP/FRR teardown
acts on a node that never took ownership — the §7 blackhole-ordering concern
applies mainly to (a) the A2 backstop (applyConfig ran fully, published, then torn
down) and (b) `cluster.Start()` having already claimed primary via the isolated
single-node election before the arm result was known. State this so the ordering
rationale is scoped correctly (it is still REQUIRED for those two cases).

## Nits

- §9.3 smoke: the "force both attach modes to fail on the data VF" injection needs
  a concrete seam (an env/test hook), else it is not runnable — name the seam or
  mark it as a follow-up harness item, per `feedback_runnable_repro_before_measurement_claim`.
- Confirm `closeoutHostAuthOnCancel` truly returns a non-cancellation arm-failure
  err unchanged (the comment says so; the impl should be re-read at /engineer time).

## Verdict

The ARCHITECTURE is sound: A3 detection with the `dataplaneEverArmed` #5679 guard,
B1 `StateSecondaryHold` peer-yield, a central `ownershipFrozen()` gate + canary,
and relinquish-before-slow-clear teardown are the right calls and are
firsthand-consistent with the source. But M1 is a real mechanism error (void
`applyConfig`), and M2–M4 are required tightenings. Revise to r2.

VERDICT: PLAN-NEEDS-MINOR
