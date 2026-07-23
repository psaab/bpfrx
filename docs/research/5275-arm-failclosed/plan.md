# Plan of action — #5275: fail closed on dataplane ARM/ATTACH failure at boot

- **Issue:** #5275 (HIGH; bug, dataplane, security, vsrx-parity)
- **Research branch:** `research/5275-arm-failclosed`
- **Base:** origin/master @ `6131eb4e6`
- **Revision:** r2 (incorporates Claude SMR r1 M1–M5)
- **Prior art:** PR #6358 (draft, `fix/5275-arm-failure-failclosed`) — returned
  MERGE-NEEDS-MAJOR. This plan supersedes it; §3 records what to reuse vs rewrite.
- **Status:** PLAN-READY (research only — no production code; implementation via
  `/engineer 5275`).

---

## 1. Problem statement & scope

#1960/#1993 make the daemon fail **closed** only when a persisted config fails to
**COMPILE** at boot. A config that compiles successfully but whose dataplane then
fails to **arm** (load the shim, or attach the AF_XDP shim to the data
interfaces) is NOT covered: the daemon logs "config-only mode", nils the backend,
and continues to enable kernel IP forwarding, publish the FRR managed section,
and take VRRP/VIP/cluster ownership. On a **cold boot** with no prior policy this
converts a security appliance into a **plain Linux router enforcing zero policy**.

Scope of this plan: make a compile-success + arm/attach-failure at the **two arm
sites** (boot and bootstrap-exit) fail closed exactly like the #1960
compile-failure boot — no transit forwarding, no route advertisement, no HA/VIP
ownership — while keeping the management/console lifeline reachable, and while
**preserving the #5679 day-2 semantics** (a day-2 commit whose attach fails must
keep the *already-armed* old policy live and merely fail the commit — it must NOT
tear down a working dataplane).

Out of scope: changing the AF_XDP attach itself, the native→generic fallback
(the documented iavf degraded mode is *not* a failure), or the #5679 day-2 commit
path.

---

## 2. STEP-0 evidence (firsthand-confirmed on origin/master @ 6131eb4e6)

### 2.1 The real arm boundary is the first ApplyConfig attach, NOT `Start()`

- `d.dp.Start()` == `Manager.LoadUserspaceShim()`
  (`pkg/dataplane/loader.go:152`) loads only the shim **program + shared maps**.
  It attaches XDP to **no interface**. It rarely fails.
- The actual **per-interface AF_XDP attach** is `attachUserspaceShimXDP()`
  (`pkg/dataplane/loader.go:204-247`), reached through
  `CompileUserspaceShim → userspace Manager.Compile → d.dp.ApplyConfig`, which
  runs during the **first `applyConfig`**.
- `attachUserspaceShimXDP` behaviour (verified):
  - **Native attach fails, generic succeeds** → NO error; logs a WARN and runs
    in generic/skb mode (loader.go:214-224). This is the documented iavf
    fallback — the shim is still attached and still steers to userspace-dp, so
    it is **still policy-enforcing**. NOT a fail-close case.
  - **Both native AND generic fail** on a required data interface → returns an
    error (loader.go:240-242). This is the #5275 hole: no XDP program is attached
    to that interface, so the kernel forwards transit unpoliced.

### 2.2 The both-attach-fail error is mis-classified as #5679-deferred, not abort

- In `applyDataplaneAndHACore` (`pkg/daemon/daemon_apply.go:1069-1094`),
  `d.dp.ApplyConfig` errors are classified:
  - `compileErrorMustAbortApply(err)` → terminal abort (caller bails before the
    tail). But that predicate only matches `dpuserspace.IsRequiredProtocolGateError`
    (policy-scheduler / persistent-source-NAT protocol gates) — **NOT** an attach
    failure.
  - Everything else → `applyErr` = the **#5679 ordinary-deferred** error: the
    tail reconciles (VRRP, FRR routing rules, services) **still run**; on a
    day-2 commit the old policy stays live and the commit reports failure.
- So a both-attach-fail becomes `applyErr` → the tail publishes FRR/VRRP anyway.

### 2.3 On boot the arm result is discarded entirely

- Boot arm (`pkg/daemon/daemon_run_bringup.go:490-522`): `d.applyConfig(cfg)` at
  line 520 **discards its return** — even the #5679 deferred error is swallowed.
- `enableForwarding()` already ran in manager init (a successful compile is not
  bootstrap), and `applyKernelTuning` re-writes `ip_forward=1` at the apply tail
  (`pkg/daemon/daemon_system.go`). So `ip_forward=1` is live regardless.
- `clearFRRForFailClosedBoot(compileFailed=false)` is a no-op on this path
  (`pkg/daemon/bootstrap.go`), so `applyConfig` (re)publishes the FRR managed
  section.
- The periodic `reconcileVRRPInstances` (`pkg/daemon/daemon_ha.go:545`) reads the
  still-non-nil `ActiveConfig`, so VRRP/VIP ownership is (re)created.

**Net:** cold boot + valid config + both-attach-fail ⇒ `ip_forward=1`, FRR
advertising, VRRP owning VIPs, **no XDP on the data interface** ⇒ policy-free
router. Firsthand-confirmed. Bootstrap-exit arm
(`pkg/daemon/daemon_run_naming.go:runBootstrapExitStartup`) has the same shape.

---

## 3. What #6358 got RIGHT (reuse) vs WRONG (must change)

### Reuse verbatim (correct, keep)

- **Sticky `d.dataplaneArmFailed atomic.Bool`** — the fail-closed flag, never
  cleared at runtime (recovery = daemon restart). Correct concept.
- **`enterDataplaneArmFailedFailClosed()` handler** — the set-of-actions
  (disable transit forwarding, clear FRR managed section, cluster hold, VRRP
  teardown). Correct actions; §7 re-orders them (Finding 4).
- **`disableForwarding()` clearing ONLY the two transit sysctls** (leaves the
  mgmt-VRF `l3mdev`/`accept_local` knobs so SSH/console survive). Correct.
- **The three gates it added** — `applyKernelTuning` (no ip_forward re-enable),
  `applyRoutingRules` (skip FRR publish), the apply-tail VRRP collect + periodic
  `reconcileVRRPInstances` (empty desired set). Correct but INCOMPLETE (§6).
- **`clearFRRManagedSectionOnFailClosedBoot(reason)`** sharing the #1993
  two-stage `failClosedBootShouldClearFRR` live-forwarding probe. Correct.
- **`SetArmFailedHold` election gate** (`|| m.armFailedHold` in both `electRG`
  and `electSingleNode`) + the demote-already-primary loop. The **gate** is
  correct; the **demote target** is wrong (§5.B).

### Must change

1. **WRONG BOUNDARY (crux).** #6358 wires the handler only to `d.dp.Start()`
   failure, which almost never fires. The real failure — both-attach-fail in the
   first ApplyConfig — is never routed to fail-closed. **Fix: §5.A.**
2. **Both-secondary stranding.** `SetArmFailedHold` demotes to ordinary
   `StateSecondary` while keeping the failed node's priority/weight; a healthy
   lower-priority PRIMARY with preempt sees the held node's higher effective
   priority and demotes ITSELF ⇒ persistent both-secondary. **Fix: §5.B.**
3. **Ungated publishers.** Four additional `ActiveConfig`-driven ownership
   publishers bypass the flag. **Fix: §6.**
4. **Teardown sequencing + silent sysctl failure.** **Fix: §7 (Finding 4).**

---

## 4. Design goals & invariants

- **G1 — Fail closed on first-arm attach failure.** A never-armed node whose
  first attach fails must end in: `ip_forward=0` (+ IPv6), no FRR managed
  section, no VRRP/VIP ownership, cluster held non-primary, `d.dp == nil`,
  `dataplaneArmFailed == true`.
- **G2 — Management lifeline preserved.** SSH/console/gRPC stay reachable; only
  transit forwarding + advertisement + HA ownership are withheld. Not a dead box.
- **G3 — Preserve #5679 day-2 semantics.** A day-2 commit whose attach fails must
  keep the *already-armed* old policy live and fail the commit — never tear down
  a working dataplane. The fail-closed routing fires ONLY when the node has
  **never** successfully armed (`!dataplaneEverArmed`).
- **G4 — Peer owns the RGs, exactly one primary.** In a cluster the healthy peer
  must become/stay primary; never both-secondary, never split-brain.
- **G5 — No HA blackhole during teardown.** Ownership (VRRP/cluster) is
  relinquished to the peer BEFORE the slow (~40 s) FRR clear.
- **G6 — Sticky.** No later apply/reconcile/engine-tick re-opens the hole; the
  only recovery is a daemon restart.
- **G7 — Publisher-complete + future-proof.** Every ownership publisher fails
  closed, and a test prevents a newly-added publisher from silently bypassing.
- **INV — the native→generic fallback is NOT a failure.** Detection must treat a
  generic-mode attach as armed.

---

## 5. Multiple Path Options

### 5.A — Detecting the attach failure and failing closed (Finding 1)

The attach failure is only known *during* the first `applyConfig`, which is *past*
the point where #6358's "skip applyConfig" freeze could act. Three shapes:

**Option A1 — Abort-class classification (prevent-the-publish). RECOMMENDED.**
- `attachUserspaceShimXDP` returns a typed sentinel `ErrShimAttachFailed`
  (wrapping the both-fail per-ifindex error) so the case is distinguishable from
  ordinary compile/snapshot errors. Verified propagation:
  `attachUserspaceShimXDP` (loader.go:242) → `CompileUserspaceShim`
  (loader.go:191) → userspace `Manager.Compile` (manager_compile.go:187) →
  userspace `Manager.ApplyConfig` (manager.go:354-355) → `d.dp.ApplyConfig` in
  `applyDataplaneAndHACore` (daemon_apply.go:1073).
- **The detection + fail-closed action live INSIDE the apply pipeline, NOT at the
  arm sites** — because `applyConfig` (daemon_apply.go:49) is **void** (it
  swallows `applyConfigLocked`'s error with an internal `slog.Warn`, and has many
  callers). So the arm sites keep calling `applyConfig` unchanged; the pipeline
  self-fails-closed:
  - In `applyDataplaneAndHACore`, when `d.dp.ApplyConfig` errors: if
    `applyErrorIsArmFailure(err) && !d.dataplaneEverArmed.Load()` → return it as a
    **terminal abort** (like `compileErrorMustAbortApply`). Verified this
    short-circuits: `applyConfigLocked` line 288 `if err != nil { return ... }`
    bails **before** `applyRoutingRules`/`applyServicesReconcile`/`applyTailReconciles`
    (lines 318/335/355), so networkd-tail/RETH-MAC/VRRP/FRR/RA never publish.
  - `applyConfigLocked` (right after the line-288 bail) detects the
    arm-failure-abort class and calls `d.enterDataplaneArmFailedFailClosed()`
    before returning. (The handler's calls — `frr.Clear`,
    `vrrpMgr.UpdateInstances(nil)`, `cluster.SetArmFailedHold` — do NOT
    re-acquire `applySem`, so invoking it under the held `applySem` cannot
    deadlock; confirm at /engineer time.)
  - Otherwise the existing branches stand (required-protocol-gate abort; #5679
    deferred for everything else — a day-2 attach failure on an ever-armed node
    keeps the old policy live).
- **`dataplaneEverArmed` flips to true ONLY when ApplyConfig returns nil AND
  `ForwardingArmed()==true`** (A2 below) — so a silent partial attach that
  returned no error does not wrongly mark the node ever-armed.
- **Pro:** no ownership is ever published (no flap); the abort short-circuits the
  tail; day-2 (#5679) untouched via the `dataplaneEverArmed` guard; a single
  choke-point covers boot arm, bootstrap-exit arm, AND a post-bootstrap
  first-ever operator commit uniformly.
- **Con:** requires the sentinel + `dataplaneEverArmed` + `ForwardingArmed()`.
  Aborting before networkd on boot leaves interfaces in startup-naming state —
  exactly the #1960 "freeze in last-known-good" behaviour. The handler's ~40 s
  FRR clear runs under `applySem` on boot (acceptable).

**Option A2 — Post-apply positive arm verification (tear-down-after).**
- Let the first `applyConfig` run fully, then on the boot/bootstrap-exit arm
  query a new dataplane accessor `ForwardingArmed()` (does every required data
  ifindex have an attached shim link, native or generic?). If not armed →
  `enterDataplaneArmFailedFailClosed()` (which tears down what applyConfig just
  published).
- **Pro:** positive proof of arm, robust to future error shapes; catches a
  *silent* partial attach that returns no error.
- **Con:** ownership is briefly published then torn down (FRR advertises then
  clears; VRRP may briefly master) — a real, if short, boot-time flap.

**Option A3 — Hybrid: A1 primary + A2 as a defense-in-depth assertion.
RECOMMENDED to ship.**
- Ship A1 (abort-class, no flap) as the primary mechanism AND add the A2
  `ForwardingArmed()` check as a cheap post-apply backstop at the two arm sites,
  so a future silent (no-error) attach regression is still caught. Belt and
  suspenders; both routes converge on the same `enterDataplaneArmFailedFailClosed`
  handler.

Recommendation: **A3** (A1 mechanism + A2 backstop). Keep #6358's `Start()`
-failure wiring too — an independent shim-load failure must also fail closed.

### 5.B — Peer-yield signal so the healthy peer owns the RGs (Finding 2)

The held node must (a) never become primary itself, AND (b) signal the peer to
take over. #6358 does (a) via the `armFailedHold` election gate but not (b): it
demotes to ordinary `StateSecondary` and keeps priority/weight, so a preempting
healthy peer sees the held node's *higher* effective priority and demotes itself.

**Option B1 — `StateSecondaryHold` peer-yield. RECOMMENDED.**
- `SetArmFailedHold` demotes any owned RG to `StateSecondaryHold` (not
  `StateSecondary`). The heartbeat already propagates `State`
  (`heartbeat_manager.go:277`), and the peer's election already yields to it:
  `electRG` line 165 (`peerGroup.State == StateSecondaryHold → electLocalPrimary`,
  "Peer transfer out") — checked BEFORE the weight/preempt comparison. The local
  `armFailedHold` gate keeps the held node in `StateSecondaryHold`.
- **Naturally sticky.** `recalcWeight` (election.go:503) unconditionally resets
  `rg.Weight = 255 - totalLost` on every monitor tick, so a weight-based yield is
  clobbered; a State-based yield is immune (the peer keys on `State`, and the
  local `armFailedHold` gate returns before any election mutates `State`).
- Do NOT set `ManualFailover` — the `armFailedHold` flag is the local hold; that
  keeps the arm-failed path out of the manual-failover / dual-resign state
  machine.
- **Pro:** reuses the proven transfer-out yield path; sticky; single-line change
  to the demote target; works in both preempt and non-preempt.
- **Con:** reuses a state named for manual failover — must document intent and
  confirm no local `StateSecondaryHold` side-effects (GARP/RA) fire on the held
  node (VIP ownership keys on `StatePrimary`, so SecondaryHold owns nothing).

**Option B2 — Weight-zero yield.**
- `SetArmFailedHold` sets `rg.Weight = 0`. Peer sees `peerWeight <= 0 →
  electLocalPrimary` (election.go:152-158).
- **Con:** NOT sticky — `recalcWeight` resets weight to 255 on the next monitor
  tick (this is why even ISSU `ForceSecondary` relies on `ManualFailover`, not
  weight, for its hold). Would additionally require gating `recalcWeight` on
  `armFailedHold`. More surface, more fragile. Rejected.

**Option B3 — Priority-floor yield.**
- Clamp `LocalPriority` to 1. **Con:** only works with peer preemption enabled;
  in non-preempt a both-secondary initial state falls through to a priority
  compare that the floor may still lose/tie unpredictably; priority-0 is
  RFC-special. Weakest. Rejected.

Recommendation: **B1** (`StateSecondaryHold`).

---

## 6. Complete ownership-publisher enumeration + the gate architecture (Finding 3)

Rather than scatter `if d.dataplaneArmFailed.Load()` across every site (fragile —
this is exactly how #6358 missed four), route every publisher's **desired-set**
through a single predicate and add a canary test.

- **Central predicate:** `d.ownershipFrozen()` ≙ `d.dataplaneArmFailed.Load()`
  (a named method, so the intent is greppable and the canary can assert coverage).

**Every ownership/advertisement/forwarding publisher and its gate:**

| # | Publisher | File:sym | #6358 | Action |
|---|-----------|----------|-------|--------|
| 1 | `ip_forward=1` re-enable | `daemon_system.go` `applyKernelTuning` | gated | keep |
| 2 | FRR managed-section publish (commit) | `daemon_apply_routing.go` `applyRoutingRules` | gated | keep |
| 3 | VRRP collect (apply tail) | `daemon_apply_tail.go` `applyTailReconciles` | gated | keep |
| 4 | VRRP periodic reconcile | `daemon_ha.go:545` `reconcileVRRPInstances` | gated | keep |
| 5 | **VRRP debounced re-publish (500 ms `vrrpTimer` AfterFunc)** | `daemon_ha.go:315-325` `watchClusterEvents` | **UNGATED** | gate: skip re-publish when frozen (keep desired set empty) |
| 6 | **ip-monitoring FRR re-render + overlay publish** | `daemon_ipmon.go:296` `actuateRouteOverlayLocked` | **UNGATED** (only `isResetting`) | gate: return `false` (stay dirty) when frozen, before `applyFRRConfig` |
| 7 | **Proxy-ARP responders + GARP** | `daemon_proxyarp.go:126/274` `reconcileProxyARP`/`reassertProxyARPOnce` | **UNGATED** | gate: reconcile to the withdrawn (empty) responder set when frozen |
| 8 | **Standalone RA senders** | `daemon_apply_routing.go:40` `applyServicesReconcile` | **UNGATED** | gate: `Withdraw()` (no `Apply`) when frozen |
| 9 | Cluster RA senders | `daemon_ha.go` `applyRethServicesForRG`/`reconcileClusterRAServices` | indirect | driven by VRRP MASTER; VRRP teardown (§7) + gate #5 prevent a re-arm — assert in test |

**Architecture recommendation:** for the reconcile-style publishers (5,6,7,8),
express the freeze as "the desired published set is empty/withdrawn when frozen",
i.e. converge-to-fail-closed rather than an early-return edge gate (matches the
project's "reconcile-to-desired, edge-gate-is-a-smell" idiom). Add a **canary
test** that enumerates the ownership publishers and asserts each consults
`ownershipFrozen()` (a compile-time/registry check or a table test), so a future
publisher cannot silently bypass — the specific miss that made #6358 MAJOR.

**Considered and OUT of scope (with reason)** — these `ActiveConfig` readers do
NOT publish transit forwarding, route advertisement, or VIP/ownership, so they are
not part of the #5275 fail-closed surface:

- `daemon_ha_userspace_stream` (session sync) — syncs conntrack sessions; a no-op
  with `d.dp==nil` (arm-failed) and not a forwarding/advertisement publish.
- `daemon_ha_fabric` (fabric redirect) — for peer-owned synced sessions; no-op
  with `d.dp==nil`.
- `daemon_dhcp` (relay), `daemon_ddns`, SNMP (ifTable) — control-plane services,
  not transit policy enforcement or route/VIP advertisement.
- `daemon_neighbor` (proactive neighbor resolution) — populates ARP/ND for
  next-hops; advertises nothing and, in cluster mode, is gated on VRRP MASTER
  (which never fires on a frozen node).

They are listed so the enumeration is auditable and the canary's publisher set is
justified; if a future change makes any of them advertise/forward, it joins the
gated set.

---

## 7. Teardown sequencing + hard sysctl failure (Finding 4)

`enterDataplaneArmFailedFailClosed` in #6358 runs: set flag → `disableForwarding`
→ **synchronous FRR clear (~40 s)** → `SetArmFailedHold` (demote) → VRRP teardown.
Two problems:

- **Blackhole window:** an already-primary node still owns the VIPs and still
  advertises VRRP throughout the ~40 s FRR clear (demotion/teardown come last), so
  transit lands on a node with forwarding off ⇒ ~40 s blackhole.
- **Silent sysctl failure:** `writeForwardingSysctl` only logs on error, so a
  failed `ip_forward=0` write leaves transit enabled while the node reports
  fail-closed.

**Fix — re-order and harden the handler:**

1. `d.dataplaneArmFailed.Store(true)` — first, so any concurrent reconcile/tick
   already sees frozen.
2. **Relinquish ownership to the peer FIRST:** `cluster.SetArmFailedHold()`
   (demote → `StateSecondaryHold`, peer promotes) **and** `vrrpMgr.UpdateInstances(nil)`
   (priority-0 goodbye burst → peer masters VIPs in ~1 ms per the planned-shutdown
   path). (G5.)
3. `disableForwarding()` — now that the peer owns the VIPs, disabling transit on
   this node drops nothing.
4. `clearFRRManagedSectionOnFailClosedBoot("dataplane-arm-failed")` — the slow
   (~40 s) clear runs last, after ownership is already gone.

   > Tradeoff (design decision to record): relinquish-first leaves a ~1 ms window
   > where this node still owns VIPs while forwarding is briefly still on
   > (unpoliced transit) before step 3 disables it. That ~1 ms of *unpoliced*
   > transit is preferable to a multi-second *blackhole*; both are avoided in the
   > common standalone case (no VIPs owned). The alternative order
   > (disable-forwarding-before-relinquish) trades the 1 ms unpoliced window for a
   > ~1 ms blackhole — either is acceptable; relinquish-first is recommended
   > because the peer is the intended forwarder.

5. **Harden `disableForwarding`:** after each write, read the value back; if still
   `1`, retry a bounded number of times, and on persistent failure ESCALATE — do
   not report fail-closed-success. The hard escalation is to administratively bring
   the transit/data interfaces DOWN (the shim is being detached anyway), which
   fails closed independently of `ip_forward`, plus a loud alarm/log. Never leave
   the code path claiming fail-closed while `ip_forward=1`.
   - **Lifeline safety (G2):** the escalation MUST reuse the SAME protected-mgmt
     resolver networkd uses (`resolveProtectedInterfaces` /
     `SetProtectedResolver`, derived from ActiveConfig independently of
     `ManagedInterfaces`) and NEVER bring down a protected/mgmt interface
     (`fxp0` / mgmt-VRF member). A naive "down all transit interfaces" that
     catches the mgmt NIC would sever the console lifeline — the exact opposite of
     the design goal.

**Scope note (A1 minimizes this surface):** on the recommended A1 abort path the
tail never published, so the handler's VRRP/FRR teardown acts on a node that never
took ownership — the blackhole-ordering concern above applies mainly to (a) the A2
backstop (applyConfig ran fully and published before the tear-down) and (b)
`cluster.Start()` having already claimed primary via the isolated single-node
election before the arm result was known. The re-order is still REQUIRED for those
two cases.

Optionally the FRR clear may run asynchronously *after* the ownership relinquish
(management does not depend on it); the minimum required change is the re-order so
the slow clear is last. Recommend keeping it synchronous-but-last for
determinism at boot; revisit only if boot latency is measured to matter.

---

## 8. Recommended design (concrete)

- **Detection (A3):** `attachUserspaceShimXDP` returns `ErrShimAttachFailed`
  sentinel; `applyErrorIsArmFailure` classifier; in `applyDataplaneAndHACore`
  route an arm-failure abort when `!dataplaneEverArmed`, and in `applyConfigLocked`
  (after the line-288 bail) call `enterDataplaneArmFailedFailClosed()` on that
  abort class — the detection lives in the pipeline, NOT at the arm sites (because
  `applyConfig` is void). Set `dataplaneEverArmed=true` only when ApplyConfig
  returns nil AND `d.dp.ForwardingArmed()==true`; use `ForwardingArmed()` as the
  A2 backstop (fail closed if ApplyConfig returned nil but nothing armed). Keep
  #6358's `Start()`-failure wiring at the two arm sites.
- **Peer-yield (B1):** `SetArmFailedHold` demotes to `StateSecondaryHold`.
- **Publishers (§6):** central `ownershipFrozen()` predicate; gate #5–#8; canary
  test.
- **Teardown (§7):** re-order (relinquish → disable-forwarding → FRR clear);
  read-back + escalate on sysctl-write failure.
- **Stickiness:** `dataplaneArmFailed` never cleared at runtime; `d.dp` never
  rebuilt; recovery = daemon restart.

---

## 9. Test plan

### 9.1 Fail-on-revert unit tests (each RED on gate revert, GREEN restored)

- `pkg/dataplane` — `attachUserspaceShimXDP` returns `ErrShimAttachFailed` when
  BOTH native and generic attach fail (fake attach seam); returns nil when
  native fails but generic succeeds (INV — generic is armed, not a failure).
- `pkg/daemon`:
  - **Boot arm both-attach-fail fails closed, skips the tail** (A1): a fake
    backend whose ApplyConfig returns `ErrShimAttachFailed` with
    `dataplaneEverArmed==false` ⇒ no VRRP/FRR published, `dataplaneArmFailed` set,
    `d.dp==nil`. Neutralize the abort branch ⇒ RED (tail publishes).
  - **Day-2 attach failure keeps #5679, does NOT fail closed** (G3): ApplyConfig
    returns `ErrShimAttachFailed` with `dataplaneEverArmed==true` ⇒ commit fails
    (deferred), `dataplaneArmFailed` stays false, handler NOT invoked. Neutralize
    the `dataplaneEverArmed` guard ⇒ RED (working dataplane torn down).
  - **`ForwardingArmed()` backstop** (A2): ApplyConfig returns nil but
    `ForwardingArmed()==false` on first arm ⇒ fail closed.
  - **Handler immediate actions + ORDER** (Finding 4): assert relinquish
    (SetArmFailedHold + VRRP teardown) happens BEFORE the FRR clear (recorder
    ordering), and `disableForwarding` read-back escalates on a stuck sysctl.
  - **Each publisher gate #5–#8** (Finding 3): frozen ⇒ vrrpTimer AfterFunc
    publishes nothing; `actuateRouteOverlayLocked` returns false without
    `applyFRRConfig`; proxy-ARP reconciles to empty; standalone RA `Withdraw`s not
    `Apply`s. Each with an `_Armed_` negative control (gate is not a blanket
    disable).
  - **Publisher canary** (G7): enumerates the ownership publishers and asserts
    each consults `ownershipFrozen()`.
- `pkg/cluster`:
  - **`SetArmFailedHold` demotes to `StateSecondaryHold`** and the peer promotes:
    peer election with `peerGroup.State==StateSecondaryHold` ⇒ `electLocalPrimary`;
    isolated held node stays non-primary across re-election. Neutralize the
    demote-to-Hold ⇒ RED (both-secondary reproduces).
  - **Higher-priority held node + preempting lower-priority peer ⇒ peer primary,
    not both-secondary** (the exact Finding-2 regression).

### 9.2 Parent-RED recipe

Per `feedback_red_on_revert_must_be_assertion_not_build_break`: every
neutralization must be an ASSERTION failure with imports still used (invert a
comparison / delete a line / target-count assert), never a build break. Run:
`GOCACHE=/dev/shm/gc-5275 GOTMPDIR=/dev/shm TMPDIR=/tmp go test ./pkg/daemon/...
./pkg/dataplane/... ./pkg/cluster/... 2>&1 | tail` (short `TMPDIR` — the
event_stream unix-socket test hits the sun_path 108 limit under a long GOTMPDIR).

### 9.3 Smoke (parent runs at merge)

Touches VRRP/HA/forwarding ⇒ **loss-cluster `make test-failover`** is required
(v4+v6, push+reverse). Additionally, a targeted manual check: on a node, inject a
both-attach-fail (e.g. force both attach modes to fail on the data VF) and assert
the PEER holds the VIPs and forwards (no both-secondary), the injected node has
`ip_forward=0` + no FRR managed section + no VIPs, and SSH/console stay reachable.
Per `feedback_verify_forwarding_with_sustained_iperf`, verify with sustained
iperf3 through the peer, not a health-200. The both-attach-fail injection needs a
concrete test seam (an env var / build-tag hook that forces `link.AttachXDP` to
fail both modes on a chosen data ifindex, mirroring the existing
`failedNativeXDP` path) — name it in the implementation PR or land it as a
harness follow-up rather than a hand-wave (`feedback_runnable_repro_before_measurement_claim`).

---

## 10. Blast radius

- **Files touched (est.):** `pkg/dataplane/loader.go` (sentinel), a dataplane
  accessor (`ForwardingArmed`), `pkg/daemon/daemon_apply.go` (classifier +
  `dataplaneEverArmed`), `daemon_run_bringup.go` + `daemon_run_naming.go` (capture
  arm result at both sites), `bootstrap.go` (handler re-order + hardened
  `disableForwarding`), `daemon_system.go` (keep), `daemon_apply_routing.go`
  (RA + FRR gates), `daemon_apply_tail.go` (keep), `daemon_ha.go` (gate #5),
  `daemon_ipmon.go` (gate #6), `daemon_proxyarp.go` (gate #7),
  `pkg/cluster/arm_failed_hold.go`/`election.go`/`manager.go` (StateSecondaryHold
  demote + gate), plus tests. Order-of a few hundred LOC net.
- **Runtime risk:** the day-2 path is explicitly preserved (G3) — the highest
  risk is a regression that tears down a working dataplane on a day-2 attach
  failure; the `dataplaneEverArmed` guard + its dedicated fail-on-revert test are
  the primary guard. HA risk (both-secondary / split-brain) is covered by the
  cluster tests + `make test-failover`.

---

## 11. Risks, rollback, docs

- **Risk — day-2 regression (tear down working DP).** Mitigation: G3 guard +
  dedicated RED test; call-site scoping (only the two arm sites route to
  fail-closed).
- **Risk — StateSecondaryHold side-effects on the held node.** Mitigation: verify
  no GARP/RA fires on a non-primary node (VIP ownership keys on `StatePrimary`);
  do not set `ManualFailover`; cluster test asserts held node owns nothing.
- **Risk — publisher not enumerated.** Mitigation: the §6 canary test.
- **Risk — `ForwardingArmed()` false-negatives on generic mode.** Mitigation: the
  accessor counts a generic-mode attach as armed (INV); explicit unit test.
- **Rollback:** all changes are Go control-plane; `git revert` of the
  implementation PR restores current behaviour (the hole re-opens but nothing
  else regresses). No persisted-state or wire-format change.
- **Docs to update (module contract):** `pkg/daemon/README.md` (fail-closed
  section — extend the #6358 draft text to the attach boundary + the publisher
  list + teardown order), `pkg/cluster` doc note on `StateSecondaryHold` reuse
  for arm-failed yield, and `_Log.md`.

---

## Appendix — key source coordinates (origin/master @ 6131eb4e6)

- `pkg/dataplane/loader.go:152` `LoadUserspaceShim` (== `Start`, shim+maps only)
- `pkg/dataplane/loader.go:204-247` `attachUserspaceShimXDP` (native@214,
  generic@240 — the real attach; both-fail returns error@242)
- `pkg/dataplane/loader.go:482-576` `AttachXDP` (native vs generic, `AttachXDP@556`)
- `pkg/daemon/daemon_apply.go:1069-1094` ApplyConfig error classification (#5679)
- `pkg/daemon/daemon_apply.go` `compileErrorMustAbortApply` (== `IsRequiredProtocolGateError` only)
- `pkg/daemon/daemon_run_bringup.go:490-522` boot arm (`applyConfig` return discarded@520)
- `pkg/daemon/daemon_run_naming.go` `runBootstrapExitStartup` (bootstrap-exit arm)
- `pkg/daemon/daemon_system.go` `applyKernelTuning` (ip_forward=1)
- `pkg/daemon/bootstrap.go` `clearFRRForFailClosedBoot` / `enterDataplaneArmFailedFailClosed` (#6358 draft)
- `pkg/daemon/daemon_ha.go:315-325` vrrpTimer AfterFunc (Finding 3a) ; `:545`
  `reconcileVRRPInstances`
- `pkg/daemon/daemon_ipmon.go:269-320` `actuateRouteOverlayLocked` (Finding 3b, only `isResetting` gate@280)
- `pkg/daemon/daemon_proxyarp.go:126/274` proxy-ARP (Finding 3c)
- `pkg/daemon/daemon_apply_routing.go:40-53` standalone RA (Finding 3d)
- `pkg/cluster/election.go:51` armFailedHold gate ; `:165` StateSecondaryHold
  peer-yield ; `:496-505` `recalcWeight` (weight-0 clobber) ; `:175-207` preempt
- `pkg/cluster/failover.go:128` `StateSecondaryHold` (transfer-out precedent) ;
  `ForceSecondary` (ISSU weight-0 relies on ManualFailover, not weight)
- `pkg/cluster/heartbeat_manager.go:273-278` heartbeat carries State/Priority/Weight
