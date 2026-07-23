# Plan of action — #5275: fail closed on dataplane ARM/ATTACH failure at boot

- **Issue:** #5275 (HIGH; bug, dataplane, security, vsrx-parity)
- **Research branch:** `research/5275-arm-failclosed`
- **Base:** origin/master @ `6131eb4e6`
- **Revision:** r3 (major rework after Codex PLAN-NEEDS-MAJOR + Claude SMR r1;
  shifts from a reactive enable-then-withdraw model to a fail-closed-from-boot
  quarantine)
- **Prior art:** PR #6358 (draft, `fix/5275-arm-failure-failclosed`) —
  MERGE-NEEDS-MAJOR. This plan supersedes it; §3 records reuse vs rewrite.
- **Status:** PLAN-READY candidate (research only — no production code;
  implementation via `/engineer 5275`).

---

## 1. Problem statement & scope

#1960/#1993 make the daemon fail **closed** only when a persisted config fails to
**COMPILE** at boot. A config that compiles but whose dataplane then fails to
**arm** (load the shim, or attach the AF_XDP shim to the data interfaces) is NOT
covered: the daemon logs "config-only mode", nils the backend, and continues to
enable kernel IP forwarding, publish FRR/RA route advertisement, and take
VRRP/VIP/cluster ownership. On a **cold boot** with no prior policy this converts
a security appliance into a **plain Linux router enforcing zero policy**.

Scope: make a compile-success + arm/attach-failure on any **first-arm path**
(boot arm, bootstrap-exit arm, config-less-HA first config) fail closed exactly
like the #1960 compile-failure boot — no transit forwarding, no route
advertisement, no HA/VIP ownership — while keeping the management/console lifeline
reachable, while **preserving #5679 day-2 semantics** (a day-2 attach failure on
an *already-armed* node keeps the old policy live and merely fails the commit —
never tears down a working dataplane), and while avoiding the HA hazards (both
nodes secondary, dual VIP ownership, transient blackhole) a naive fix introduces.

Out of scope: changing the AF_XDP attach mechanism; the native→generic fallback
(the documented iavf degraded mode is *not* a failure); the #5679 day-2 path.

---

## 2. STEP-0 evidence (firsthand-confirmed on origin/master @ 6131eb4e6)

### 2.1 The real arm boundary is the first ApplyConfig attach, NOT `Start()`

- `d.dp.Start()` == `Manager.LoadUserspaceShim()` (loader.go:152) loads only the
  shim **program + shared maps**; it attaches XDP to **no interface**.
- The per-interface AF_XDP attach is `attachUserspaceShimXDP()` (loader.go:204-247),
  reached through `CompileUserspaceShim → userspace Manager.Compile
  (manager_compile.go:185-187) → userspace Manager.ApplyConfig (manager.go:354-355)
  → d.dp.ApplyConfig (daemon_apply.go:1073)`, run during the **first `applyConfig`**.
- `attachUserspaceShimXDP`: native fail + generic success ⇒ NO error (documented
  iavf fallback, still policy-enforcing — loader.go:214-224); **both native AND
  generic fail** on a data interface ⇒ error (loader.go:240-242) — the #5275 hole
  (no XDP program attached; kernel forwards transit unpoliced).

### 2.2 The both-attach-fail error is mis-classified as #5679-deferred, not abort

`applyDataplaneAndHACore` (daemon_apply.go:1069-1094): only
`compileErrorMustAbortApply(err)` (== `IsRequiredProtocolGateError`) aborts; an
attach failure is NOT that, so it becomes the **#5679 ordinary-deferred** error —
the tail (VRRP, FRR, RA, services) still runs; on a day-2 commit the old policy
stays live and the commit fails.

### 2.3 On cold boot, forwarding + cluster are already live BEFORE the attach

- `enableForwarding()` runs **before** `d.dp.Start()`/attach at BOTH sites
  (bringup:211-215 `if !NoDataplane && !inBootstrap { enableForwarding() }`;
  bootstrap-exit naming:225). So `ip_forward=1` is set before the attach is even
  attempted. **Any post-attach-failure handler is REACTIVE** — it withdraws
  already-published state; it is not "never published."
- The cluster manager is constructed before dataplane setup (bringup:161).
- Boot arm (`applyConfig`, bringup:490-522) **discards** its result; `applyConfig`
  (daemon_apply.go:49) is **void** — it swallows `applyConfigLocked`'s error.

### 2.4 A terminal abort skips the inner apply tail but NOT the commit transaction

`applyConfigLocked` line 288 `if err != nil { return closeoutHostAuthOnCancel }`
short-circuits before `applyRoutingRules`/`applyServicesReconcile`/`applyTailReconciles`
(318/335/355). BUT the outer commit wrapper (`daemon_apply_commit.go`) still runs:
`applyErrSkipsPeerSync` (line 303) skips the peer config-sync only for
required-protocol + ctx-cancel classes; every OTHER error still **pushes the
committed config to the peer and clears sessions** (line 247/270), on the stated
invariant "the dataplane armed." A new arm-failure error falls through that
invariant.

### 2.5 HA + publisher facts that constrain the fix (all firsthand)

- New/unseen RGs init `State: StateSecondary, Weight: 255` (group_state.go). #6358's
  `SetArmFailedHold` demotes only `rg.State == StatePrimary` groups, so a
  high-priority **secondary** group keeps advertising ordinary secondary ⇒ the
  both-secondary hazard survives.
- `StateSecondaryHold` is not a free yield signal: RG0's transition handler treats
  `StateSecondary`/`StateSecondaryHold` as demotion and calls
  `ConfirmPendingOnDemotion()` (daemon_ha.go ~471) — reusing it during a failed
  first-arm **`commit confirmed`** would CONFIRM the config whose arm just failed.
- `recalcWeight` (election.go:503) overwrites `rg.Weight` on recalculation, so a
  weight-0 yield is not sticky (ISSU `ForceSecondary` relies on `ManualFailover`
  state, not weight).
- Ownership state reaches the peer only on the ~100 ms heartbeat; local VIP
  actuation is async via `watchClusterEvents`; in **no-RETH/direct-VIP** mode
  `vrrpMgr.UpdateInstances(nil)` removes nothing (direct VIP removal happens only
  when the async cluster event fires). No completion/ACK barrier exists.
- Ungated ownership/forwarding publishers beyond the #6358 three:
  `vrrpTimer` AfterFunc (daemon_ha.go:315), ip-mon `actuateRouteOverlayLocked`
  (daemon_ipmon.go:296, only `isResetting` gate), proxy-ARP
  (daemon_proxyarp.go:126/274), standalone RA (daemon_apply_routing.go:40),
  **cluster RA reconciler** (daemon_ra_reconcile.go / daemon_ha.go:962),
  **direct-VIP GARP/NA** (daemon_ha_vip.go), **DHCP relay** — a per-packet
  userspace forwarder started independent of arm (daemon_run.go:449) with an
  always-open standalone/RG0 gate (daemon_dhcp.go), bypassing `ip_forward`,
  **DDNS Surface A** publishing the firewall's own addresses (daemon_ddns_surface_a.go,
  always-open standalone gate), **Kea DHCP** (advertises this node as router).
- Partial attach leaks: the attach loop can pin interface A then fail on B
  (loader.go:214-224); setting `d.dp=nil` without `Teardown()`/`DetachXDP`
  (manager.go:478 / loader.go:639) loses the cleanup owner and leaks XDP
  links/pins. Bootstrap-exit also starts the NAT pool-alarm monitor after
  `Start()` (naming:240) whose sampler reads `d.dp` concurrently — a fail-close
  that nils `d.dp` must stop/join it.

**Net:** cold boot + valid config + both-attach-fail ⇒ policy-free router; a naive
reactive fix additionally risks both-secondary, dual VIP, blackhole, a wrongly
CONFIRMED failed commit, a config pushed to the healthy peer, and leaked XDP pins.

---

## 3. What #6358 got RIGHT vs WRONG

**Reuse (correct concepts):** the sticky `d.dataplaneArmFailed atomic.Bool`; the
handler *idea* (disable forwarding + clear FRR + cluster hold + VRRP teardown);
`disableForwarding` clearing ONLY the two transit sysctls (mgmt-VRF knobs stay);
`clearFRRManagedSectionOnFailClosedBoot(reason)` sharing the #1993 live-forwarding
probe.

**Must change:** (1) wrong boundary — guards `Start()` not the attach (§5.A); (2)
`SetArmFailedHold` demote scope + `StateSecondary` target → both-secondary +
side-effects (§5.B); (3) incomplete + racy publisher gating (§6); (4) reactive,
unsafe, non-atomic teardown with no real dataplane cleanup (§7). The whole model
moves from **reactive withdraw** to **fail-closed-from-boot quarantine**.

---

## 4. Design goals & invariants

- **G1 — Fail closed on first-arm attach failure.** Never-armed node whose first
  attach fails ends: transit forwarding DENIED (kernel FORWARD-drop barrier
  verified installed), no FRR/RA/route advertisement, no VIP/ownership in ANY mode
  (RETH VRRP, direct-VIP, cluster RA), cluster peer owns ALL RGs, dataplane torn
  down cleanly (no leaked XDP pins), `d.dp==nil`, `dataplaneArmFailed==true`.
- **G2 — Management lifeline preserved.** SSH/console/gRPC reachable; the barrier
  exempts the mgmt lifeline. Not a dead box.
- **G3 — Preserve #5679 day-2.** A day-2 attach failure on an **ever-armed** node
  keeps the old policy live and fails the commit; the fail-closed path fires ONLY
  when `!dataplaneEverArmed`. The commit wrapper (peer-sync, session-clear) treats
  a first-arm failure distinctly from an ever-armed #5679 failure (§5.A).
- **G4 — Exactly one primary, no dual VIP, no both-secondary.** The peer becomes
  and stays primary for every RG; the failed node yields via a signal that (a)
  covers current AND future RGs, (b) survives every state writer, (c) has no
  RG0-demotion side effect (no auto-confirm of the failed commit).
- **G5 — No blackhole and no dual ownership during teardown.** Ownership is
  relinquished with a bounded completion/verify before local forwarding is cut;
  the security-correct default on ambiguity is FAIL CLOSED (drop), not unpoliced.
- **G6 — Sticky + race-free.** No later apply/reconcile/engine-tick/timer re-opens
  the hole; a freeze that races an in-flight publish callback wins (epoch/gen at
  the sink or cancel-and-join). Recovery is a daemon restart.
- **G7 — Publisher-complete + structurally future-proof.** Every
  forwarding/advertisement/ownership sink fails closed, and a new sink cannot
  bypass by construction (a mandatory frozen-aware façade or an enforceable rule),
  not merely a registry a new publisher can forget to join.
- **INV — the native→generic fallback is armed, not a failure.**

---

## 5. Multiple Path Options

### 5.A — Detecting the first-arm attach failure (Finding 1)

Common to all: `attachUserspaceShimXDP` returns a **structured arm outcome**, not
a bare error — the minimum credible contract is `{generation, requiredIfindexes,
attachedIfindexes, mode(native|generic) per iface, err}` surfaced on
`d.dp.ApplyConfig`'s `ApplyResult` (and a typed sentinel `ErrShimAttachFailed`
wrapping the both-fail case). "Armed" = every required data ifindex has a live XDP
program (native OR generic); a missing configured interface or a read failure
counts as **unarmed** (fail closed). A bare bool accessor is insufficient (it
cannot express partial/required-set/mode).

**Option A1 — Abort-class + first-arm teardown, detection INSIDE the pipeline.
RECOMMENDED.**
- The check runs **immediately after `d.dp.ApplyConfig` returns inside
  `applyDataplaneAndHACore`** (daemon_apply.go:1069-1094) — NOT at the arm sites
  (`applyConfig` is void; bootstrap-exit's `Start()` site has no completed apply
  to inspect; a config-less-HA first commit is a third path). Two triggers:
  - ApplyConfig returns `ErrShimAttachFailed`; OR
  - ApplyConfig returns nil but the structured outcome shows a required ifindex
    unarmed (the silent-partial backstop).
- If triggered AND `!d.dataplaneEverArmed.Load()` → enter the first-arm
  fail-closed path (§7) and return a terminal abort so `applyConfigLocked`
  short-circuits the tail (verified daemon_apply.go:288). Set
  `dataplaneEverArmed=true` only when ApplyConfig returns nil AND the outcome is
  fully armed.
- **Commit-wrapper handling (§2.4):** add the arm-failure sentinel to
  `applyErrSkipsPeerSync` semantics with the correct outcome — the failed node
  must NOT be treated as "armed", must NOT clear its sessions on the invariant
  "new policy applied", and must NOT push *its* fail-closed state to the peer; but
  the *committed config text* may still be valid for a healthy peer, so the design
  chooses one of: (i) suppress the auto peer-sync and let the operator/peer
  reconcile, or (ii) sync config text but NOT ownership. Recommend (i) for a
  first-arm failure (simplest, no ambiguous half-state); document the tradeoff.
- **Pro:** single choke-point; covers boot/bootstrap-exit/config-less-HA
  uniformly; day-2 (#5679) preserved via `dataplaneEverArmed`.
- **Con:** touches the commit wrapper; requires the structured outcome.

**Option A2 — Post-apply positive verification only (no abort).** Let apply run,
then verify `armed`; if not, run the teardown. Rejected as primary: it publishes
then withdraws (flap) and still needs the same teardown; kept only as the
belt-and-suspenders *verification* folded into A1 (the silent-partial backstop).

Recommendation: **A1** with the structured outcome + the A2 verification as the
second trigger. Keep #6358's `Start()`-failure wiring (an independent shim-load
failure routes to the same first-arm path).

### 5.B — Making the peer own the RGs (Finding 2)

The failed node must yield ALL RGs to the peer, stickily, without RG0-demotion
side effects. #6358's demote-only-primary + `StateSecondary` fails on all three.

**Option B1 — Central advertised-state override "arm-failed". RECOMMENDED.**
- Add a manager-level `armFailedHold` flag (kept) AND make the **advertised**
  cluster state derive through a single override: while `armFailedHold`, every RG
  advertises a *yield* posture to the peer and `IsLocalPrimary*` returns false —
  regardless of the RG's stored `State` and regardless of which writer last
  touched it. Implement as: (a) the election gate already returns no-change under
  `armFailedHold` (holds local state), PLUS (b) `SetArmFailedHold` sets **every
  non-disabled RG** (not just primaries) to the yield posture, PLUS (c) the
  heartbeat builder and `IsLocalPrimary*` consult `armFailedHold` so a later
  `recalcWeight`/transfer-finalize write cannot un-yield the advertised posture.
- **Yield signal choice:** to avoid the `StateSecondaryHold` RG0 auto-confirm
  side-effect (§2.5), do NOT reuse `StateSecondaryHold` as the stored state.
  Instead advertise the yield through a **dedicated heartbeat field/flag**
  (`ArmFailed bool` per node, or a reserved group state) that the peer's election
  treats as "peer cannot own — I take all RGs", added with explicit
  **mixed-version** handling (older peer that ignores the flag must still see a
  posture that makes it primary — e.g. weight-0 in the heartbeat *in addition to*
  the flag, accepting the recalc caveat only on the wire copy, not the stored
  state). This is the cleanest correct signal; it is a small wire addition.
- **Pro:** covers current+future RGs, survives all state writers, no RG0
  side-effect, explicit peer-facing contract.
- **Con:** a wire-format addition (HA protocol version bump + mixed-version
  path) — heavier than a local state poke, but the local-only options are all
  provably insufficient (§2.5).

**Option B2 — Reuse `StateSecondaryHold` for all RGs + gate every state writer.**
Lighter (no wire change) but must (a) set it on every RG, (b) suppress the RG0
`ConfirmPendingOnDemotion` for the arm-failed case, (c) intercept every writer
(`recalcWeight`, `ForceSecondary`, transfer-finalize) — a large, error-prone
surface. Viable fallback if a wire change is rejected, but the RG0-auto-confirm
suppression is mandatory and easy to miss. Documented as the no-wire-change
alternative.

**Option B3 — weight-zero.** Rejected (`recalcWeight` clobbers; not sticky).

Recommendation: **B1** (dedicated arm-failed wire signal + central advertised
override), with B2 as the documented no-wire-change fallback if the HA-protocol
bump is deemed too heavy at `/engineer` time.

### 5.C — HA ownership-handoff barrier (Finding, from Codex C10/C19-C21)

Before cutting local transit forwarding, the failed node must have actually
relinquished VIPs to the peer, in every mode. Options:

- **C1 — Acknowledged handoff (RECOMMENDED where a peer is present):** reuse the
  existing coordinated-transfer discipline — mark yield, wait (bounded) for the
  local demotion **actuation** (direct-VIP removal via the cluster event path,
  RETH VRRP instance stop join, GARP/NA withdrawal) to complete and, where
  possible, for the peer's promotion to be observed, THEN cut forwarding. Bounded
  by a timeout after which we cut anyway (fail closed).
- **C2 — Fail-closed-first (RECOMMENDED where isolated / on timeout):** install
  the kernel FORWARD-drop barrier FIRST (transit denied immediately, no unpoliced
  window), THEN relinquish ownership, THEN the slow FRR clear. This makes the
  security barrier authoritative and independent of handoff timing — the
  security-correct default per G5.

Recommendation: **C2 as the invariant** (drop barrier first = no unpoliced and no
blackhole-that-forwards-unpoliced), with **C1 layered on** to minimize VIP
dual-ownership/blackhole duration when a peer is present. The drop barrier removes
the "1 ms vs blackhole" dilemma entirely: transit is dropped from t0; the only
question is how fast the peer starts carrying it, which C1 optimizes.

---

## 6. Publisher completeness + structural gate (Finding 3)

**Complete forwarding/advertisement/ownership publisher set** (each must fail
closed): kernel transit forwarding (FORWARD-drop barrier + `ip_forward`),
`applyKernelTuning`, FRR managed section (`applyRoutingRules`), ip-mon
`actuateRouteOverlayLocked`, RETH VRRP (apply tail + periodic reconcile +
**`vrrpTimer` AfterFunc**), **direct-VIP GARP/NA** (daemon_ha_vip.go), **cluster
RA reconciler** (daemon_ra_reconcile.go / daemon_ha.go:962), standalone RA,
proxy-ARP, **DHCP relay** (per-packet forwarder — gate its master-gate closed when
frozen), **DDNS Surface A**, **Kea DHCP server**.

**Structural, race-free gate (G6/G7):**
- A single `d.ownershipFrozen()` predicate (== `dataplaneArmFailed`) AND an
  **epoch/generation** stamped at each publication sink: a publish records the
  epoch it computed its desired set at; the sink rejects a stale-epoch publish, so
  a callback that read "not frozen" before the freeze cannot re-publish after the
  freeze bumps the epoch (closes the `vrrpTimer`/actuator TOCTOU, Codex C18).
  Equivalent: freeze acquires the same `applySem` the publishers use and issues a
  final withdraw under it, and long-lived callbacks re-check under the lock.
- **Future-proofing (Codex C17):** rather than a registry a new publisher can
  forget to join, prefer routing the *actual sinks* (FRR reload, `ra.Apply`,
  `vrrpMgr.UpdateInstances`, VIP add, relay master-gate, DDNS publish) through a
  small **frozen-aware façade** so bypassing it is a visible code smell; add a
  test that greps/asserts these sink calls are only reachable via the façade.
  (A registry canary is the weaker fallback.)
- **Out of scope, with lifecycle proof required at `/engineer`:** session sync,
  fabric redirect, SNMP, proactive neighbor — they do not advertise/forward
  transit; but the plan requires each be shown a no-op under `d.dp==nil`/frozen
  (not assumed), since Codex correctly notes "no-op after an unsynchronized
  `d.dp=nil`" is not proof.

---

## 7. Fail-closed posture: quarantine + first-arm teardown (Finding 4 + Codex C4/C23/C24/C25)

### 7.0 Quarantine model (install-at-boot, release-on-proof) — RECOMMENDED

Codex C4/C23: on cold boot `enableForwarding()` and cluster construction run
BEFORE the attach, so a purely *reactive* fail-close withdraws already-open state.
Mirror #1960 instead — start CLOSED, open on proof:

- **Install + verify the kernel FORWARD-drop barrier BEFORE `enableForwarding`**
  (and before cluster election) at boot / bootstrap-exit, so transit is denied
  from t0. `enableForwarding` may still set `ip_forward=1`; the barrier keeps
  transit dropped, so there is no unpoliced pre-arm window.
- **Release the barrier ONLY after a verified fully-armed outcome** (§5.A). The
  normal success path removes the barrier as its last arm step; a fail
  (or a never-completed arm) leaves it in place.
- **Option (lighter, if the boot-sequence change is rejected): reactive install.**
  Install the barrier only in the fail-close handler (step 2 below). Tradeoff: a
  boot-time-only window between `enableForwarding` and the arm result where
  `ip_forward=1` with no barrier — low exploitability at cold boot (no established
  transit yet), but not a true fail-closed posture. Documented as the fallback;
  the quarantine is recommended.

### 7.1 First-arm teardown sequence

Ordered, each step verified (never "logged and continue" for a security step):

1. **Set `dataplaneArmFailed=true`** and bump the publication epoch (§6) so every
   in-flight/future callback fails closed.
2. **Ensure the FORWARD-drop barrier is present + verified** (installed at boot in
   the quarantine model; installed here in the reactive fallback) — a dedicated
   nftables `xpf_failclosed` FORWARD-chain drop for transit, exempting the mgmt
   lifeline (reuse the host-inbound/lo0 nft machinery). This is the authoritative
   transit-deny (robust to relay/`ip_forward` bypass, no data-interface
   enumeration — Codex C11/C26). `disableForwarding` (ip_forward=0,
   readback-hardened) is a secondary belt.
3. **Relinquish cluster/VIP ownership** via the §5.B override for ALL RGs and the
   §5.C handoff (bounded ACK/verify; drop barrier already denies transit so a
   timeout is safe). Tear down RETH VRRP (join the instance-stop), withdraw
   direct-VIP GARP/NA, close the DHCP-relay master-gate, stop cluster RA.
4. **Stop + join background dataplane consumers** that read `d.dp` (NAT pool-alarm
   monitor, samplers) BEFORE nil-ing the backend, to avoid the bootstrap-exit
   data race (Codex C25).
5. **Real dataplane teardown:** call `d.dp.Teardown()` (detach/unpin every XDP
   link incl. the partially-attached interface) and verify, THEN set `d.dp=nil`
   under the same lock the readers use. Do NOT nil first (loses the cleanup owner,
   leaks pins — Codex C24).
6. **Clear the FRR managed section** (slow, ~40 s worst case, degraded reload may
   leave stale removals on retry — so it is LAST, after the drop barrier already
   denies transit; the barrier makes any residual advertised route non-forwarding
   locally).

**Lifeline safety (G2):** the drop barrier and any interface action MUST exempt
the protected mgmt set (`resolveProtectedInterfaces`); a FORWARD-chain drop that
exempts host-inbound/mgmt is safer than inferring the full transit topology (Codex
C26). A verify/parse failure on any security step means **unsafe → stay closed**
(never report success).

---

## 8. Recommended design (concrete summary)

- **Detection:** structured arm outcome on `ApplyResult` + `ErrShimAttachFailed`;
  check inside `applyDataplaneAndHACore` right after `d.dp.ApplyConfig`; first-arm
  gate `!dataplaneEverArmed`; commit-wrapper suppresses peer-sync/session-clear on
  first-arm failure (§5.A / A1).
- **Peer-yield:** dedicated arm-failed heartbeat signal + central advertised
  override for all RGs, no `StateSecondaryHold` reuse (§5.B / B1; B2 fallback).
- **Handoff:** drop-barrier-first invariant + acknowledged handoff when a peer is
  present (§5.C / C2+C1).
- **Publishers:** complete set gated via a frozen-aware façade + epoch-at-sink,
  no TOCTOU (§6).
- **Posture:** quarantine — FORWARD-drop barrier installed before `enableForwarding`
  at boot, released only on a verified fully-armed outcome (§7.0); the ordered,
  verified teardown of §7.1 incl. real `Teardown()` and consumer stop/join.
- **Stickiness:** `dataplaneArmFailed` never cleared at runtime; `d.dp` never
  rebuilt; recovery = daemon restart.

This is materially larger than #6358 (a wire-signal option + a kernel drop barrier
+ commit-wrapper + real teardown). That scope is the finding: the hole is not a
missing `if`, it is a fail-closed *posture* the boot sequence never had.

---

## 9. Test plan (must BIND real seams — Codex C27)

Fake-flag toggles and direct `electRG` calls do not bind; tests exercise the real
seams:

### 9.1 Detection / #5679 boundary
- `attachUserspaceShimXDP`: both-fail ⇒ `ErrShimAttachFailed` + outcome shows the
  ifindex unarmed; native-fail/generic-success ⇒ armed (INV); partial (A pinned, B
  fails) ⇒ outcome unarmed AND the teardown detaches A (no leaked pin).
- Pipeline: first-arm both-fail ⇒ terminal abort, tail not run, first-arm path
  entered, `dataplaneArmFailed` set, `d.dp==nil` AFTER `Teardown()` was called
  (recorder). Silent-partial (ApplyConfig nil, outcome unarmed) ⇒ same.
- Day-2 (`dataplaneEverArmed==true`) attach failure ⇒ #5679 (old policy live,
  handler NOT invoked, `Teardown` NOT called) — RED if the `dataplaneEverArmed`
  guard is dropped.
- Commit wrapper: first-arm failure ⇒ NOT pushed to peer, sessions NOT cleared on
  the "armed" invariant — a fail-on-revert on the `applyErrSkipsPeerSync` change.
- First-arm paths: boot, bootstrap-exit, config-less-HA first config, empty→first,
  remove-all→add, hitless-restart — each reaches the first-arm gate.

### 9.2 HA
- `SetArmFailedHold` yields ALL RGs (primary, already-secondary, newly-added) and
  the heartbeat advertises the arm-failed signal; a peer election with the signal
  ⇒ peer primary for every RG; RED if the demote covers only primaries.
- Higher-priority failed node + preempting lower-priority peer ⇒ peer primary (the
  Finding-2 regression), through the real heartbeat/election path, not a direct
  `electRG` call.
- Yield survives `recalcWeight` / `ForceSecondary` / transfer-finalize writes.
- RG0 first-arm `commit confirmed` failure does NOT get auto-confirmed on the
  yield (the `StateSecondaryHold` side-effect is absent) — RED if B2's
  suppression is dropped.
- Mixed-version peer (ignores the new flag) still promotes.
- Handoff: local VIP actuation completes / times-out into fail-closed before
  forwarding is reported cut; no dual-ownership window in direct-VIP mode.

### 9.3 Publishers / teardown
- Each sink (FRR, ip-mon actuator, vrrpTimer AfterFunc, direct-VIP GARP/NA,
  cluster RA, standalone RA, proxy-ARP, DHCP-relay master-gate, DDNS Surface A,
  Kea) publishes nothing / withdraws when frozen; each with an armed negative
  control. TOCTOU: a timer callback that read not-frozen before a freeze cannot
  republish after (epoch-at-sink) — a targeted race test.
- Teardown ordering + verification: drop barrier installed+verified before
  forwarding is claimed cut; `Teardown()` called before `d.dp=nil`; NAT-alarm
  monitor stopped+joined (run under `-race`); sysctl/link/VRRP-withdraw/degraded-FRR
  failures each escalate to "unsafe/stay-closed", not silent success.

### 9.4 Parent-RED recipe + smoke
- Every neutralization an ASSERTION failure with imports still used
  (`feedback_red_on_revert_must_be_assertion_not_build_break`).
  `GOCACHE=/dev/shm/gc-5275 GOTMPDIR=/dev/shm TMPDIR=/tmp go test
  ./pkg/daemon/... ./pkg/dataplane/... ./pkg/cluster/... 2>&1 | tail`.
- **Smoke (parent, loss cluster):** `make test-failover` (v4+v6, push+reverse)
  PLUS a runnable both-attach-fail injection — a build-tag/env seam that forces
  `link.AttachXDP` to fail both modes on the data VF (mirroring `failedNativeXDP`).
  Assert: the injected node has the FORWARD-drop barrier, `ip_forward=0`, no FRR
  managed section, no VIPs in the configured mode, cluster peer owns all RGs and
  carries sustained iperf3 (`feedback_verify_forwarding_with_sustained_iperf`),
  SSH/console stay reachable. The seam must land WITH the fix, not as a follow-up.

---

## 10. Blast radius

Larger than #6358: `pkg/dataplane` (structured arm outcome + sentinel + verified
`Teardown` on partial attach), `pkg/daemon` (pipeline detection, commit-wrapper,
FORWARD-drop barrier via nft, façade + epoch gating of ~10 publishers, consumer
stop/join, boot-sequence quarantine), `pkg/cluster` + HA wire (arm-failed signal +
central override + mixed-version), `pkg/vrrp` (verified teardown). Estimate:
several hundred LOC + a HA protocol version bump (Option B1). Highest risks: a
day-2 regression tearing down a working dataplane (G3 guard + RED test) and an HA
regression (both-secondary / dual-VIP) — both gated by real-seam tests + `make
test-failover`. Given the size, `/engineer` may reasonably split this into
sequenced PRs: (1) detection + teardown + FORWARD-drop barrier (standalone
fail-closed), (2) publisher façade + epoch, (3) HA peer-yield + handoff — each
independently mergeable and smoke-gated, advancing #5275 without one giant PR.

---

## 11. Risks, rollback, docs

- **Risk — day-2 regression.** Mitigation: G3 `dataplaneEverArmed` guard +
  dedicated RED test; commit-wrapper distinctness test.
- **Risk — HA both-secondary / dual-VIP / mixed-version.** Mitigation: §5.B/§5.C
  real-seam tests + mixed-version test + `make test-failover`.
- **Risk — the yield's RG0 auto-confirm side-effect** (if B2 chosen). Mitigation:
  mandatory suppression + RED test.
- **Risk — drop barrier severs mgmt.** Mitigation: exempt the protected mgmt set;
  verify SSH reachable in smoke.
- **Risk — scope/latency of the FRR clear + handoff at boot.** Mitigation: barrier
  denies transit first, so the slow steps are not on the security-critical path.
- **Rollback:** Go control-plane + one HA wire field (additive, version-gated);
  `git revert` restores current behaviour (hole re-opens, nothing else regresses).
  If sequenced (§10), each PR reverts independently.
- **Docs:** `pkg/daemon/README.md` (fail-closed posture: quarantine, barrier,
  publisher list, teardown order), `pkg/cluster` doc (arm-failed wire signal +
  mixed-version), `pkg/dataplane/README.md` (structured arm outcome +
  partial-attach teardown), and `_Log.md`.

---

## Appendix — key source coordinates (origin/master @ 6131eb4e6)

- `pkg/dataplane/loader.go:152` `LoadUserspaceShim` (==`Start`); `:204-247`
  `attachUserspaceShimXDP` (native@214/generic@240, both-fail err@242, partial
  pin@214-224); `:482-576` `AttachXDP`; `:639` `DetachXDP`; `:1223` `Teardown`
- `pkg/dataplane/userspace/manager.go:354-355` ApplyConfig→Compile; `:478` `Teardown`
- `pkg/daemon/daemon_apply.go:49` `applyConfig` (VOID); `:288` terminal-abort
  short-circuit; `:1069-1094` ApplyConfig error classification (#5679)
- `pkg/daemon/daemon_apply_commit.go:247/270/303` peer-sync + session-clear +
  `applyErrSkipsPeerSync`
- `pkg/daemon/daemon_run_bringup.go:161` cluster ctor; `:211-215` enableForwarding
  before attach; `:490-522` boot arm (result discarded)
- `pkg/daemon/daemon_run_naming.go:225` enableForwarding; `:230` Start; `:240` NAT
  alarm monitor start (bootstrap-exit arm)
- `pkg/daemon/daemon_system.go` `applyKernelTuning`; `pkg/daemon/bootstrap.go`
  `clearFRRForFailClosedBoot`
- `pkg/daemon/daemon_ha.go:315` vrrpTimer AfterFunc; `:471` RG0
  `ConfirmPendingOnDemotion`; `:962` cluster RA re-drive; `:545`
  `reconcileVRRPInstances`
- `pkg/daemon/daemon_ipmon.go:296` `actuateRouteOverlayLocked` (isResetting gate)
- `pkg/daemon/daemon_proxyarp.go:126/274`; `daemon_apply_routing.go:40` standalone
  RA; `daemon_ra_reconcile.go` cluster RA; `daemon_ha_vip.go` direct-VIP GARP/NA;
  `daemon_dhcp.go` relay master-gate; `daemon_run.go:449` relay start;
  `daemon_ddns_surface_a.go` / `daemon_ddns.go:332` DDNS Surface A;
  `daemon_natpoolalarm.go` NAT-alarm sampler
- `pkg/cluster/election.go:51` armFailedHold gate; `:165` StateSecondaryHold
  peer-yield; `:496-503` `recalcWeight`; `group_state.go` new-RG init
  (StateSecondary/255); `failover.go:128` StateSecondaryHold, `:140`/`:464`/`:840`
  ordinary-secondary writers; `heartbeat_manager.go:273-278` heartbeat fields
