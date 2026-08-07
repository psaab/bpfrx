# Plan of action — #5275: fail closed on dataplane ARM/ATTACH failure at boot

- **Issue:** #5275 (HIGH; bug, dataplane, security, vsrx-parity)
- **Research branch:** `research/5275-arm-failclosed`
- **Base:** origin/master @ `6131eb4e6`
- **Revision:** r13 (CONVERGED — applies Codex r11's two prescribed wording fixes to r12;
  Codex r11 = PLAN-NEEDS-MINOR with "no remaining genuine safety defect or false source
  claim" + only those two wording items, now corrected; Claude SMR = PLAN-READY. The r12
  substance stands: the crash-restart gate + the path-specific scrub-failure fallback
  (crash-restart sender-silent; LIVE re-arm keeps its incumbent heartbeat/takeover
  interlock until the scrub SUCCEEDS, then atomically holds+yields, fail-closed
  meanwhile). Architecture ruled VIABLE across eight Codex rounds; D1–D4 + D5 + facade +
  barrier + delayed-promotion + arm-state machine all Codex-accepted.)
- **Convergence:** Codex PLAN-NEEDS-MINOR (r11, wording-only, now applied) + Claude SMR
  PLAN-READY. AGY infra-down (best-effort, per `feedback_codex_infra_must_retry`
  2-of-3). The one remaining OPEN item is a HUMAN operations sign-off (§13-D5:
  accept the pre-existing dead-node timeout window vs add external STONITH), not a code
  defect — exactly the `/engineer` manual-approval gate.
- **Prior art:** PR #6358 (draft) — MERGE-NEEDS-MAJOR. Superseded.
- **Status:** PLAN-READY candidate (research only — no production code;
  `/engineer 5275`).
- **Honest sizing (the core research finding):** #5275 done correctly is a
  foundational fail-closed *architecture* — a daemon-owned revocable dataplane
  runtime + an arm-proof state machine gating all ownership/forwarding, an atomic
  HA hold+yield, and a staged surface-activation transaction. It is NOT a one-`if`
  fix and #6358's shape cannot be salvaged. §10 phases it honestly.

---

## 1. Problem & the shape of the correct fix

#1960/#1993 fail **closed only on a COMPILE failure**. A config that COMPILES but
whose dataplane fails to **arm** (attach the AF_XDP shim to the data interfaces)
degrades a cold-booted firewall to a policy-free router. Four Codex hostile rounds
+ firsthand verification established the invariants a correct fix must satisfy —
because in the current boot sequence, **election, direct-VIP/RA/Kea ownership,
VRRP, and `enableForwarding` are all published in `initManagers` BEFORE the arm**
(`setupDataplaneAndInitialConfig`), and the arm is not even fully proven at the
first `ApplyConfig` (RETH MAC link-cycle + a deferred-worker reapply follow it).

The fix is a **positive arm-proof gate**: no ownership, forwarding, or route/VIP
advertisement is published until the dataplane is proven armed for the current
config generation, on a daemon-owned revocable runtime, with the HA peer owning
the RGs while this node is unproven. The shipped #1930 pre-election hold is the
precedent for the cluster-election piece, but is only one of several contracts.

---

## 2. Daemon-owned arm-state machine (Codex r4 §1) — the spine

A single daemon-owned state, installed in boot BEFORE `initManagers` publishes
anything and OUTSIDE the `if cfg.Chassis.Cluster != nil` block (so it governs the
STANDALONE case too — the shipped #1930 hold returns early when `d.cluster == nil`,
kernel_selfrecover.go:58, so it cannot be the standalone mechanism):

```
armState:  armPending  ->  armed        (coverage proof, §5)
                       \->  armFailed    (arm failure; sticky until restart)
```

- **`armPending`** is the initial state for any boot that will attempt an arm
  (NOT NoDataplane/retired builds — those never attempt, so they are `armed`-by-N/A
  and behave exactly as today). While `armPending`: the transit barrier (§6) is up,
  `enableForwarding` is deferred, election/ownership is held (§3), and the apply
  pipeline runs only the barrier-protected arm transaction (§8).
- **`armed`** is reached ONLY by the coverage proof at the final arm boundary (§5);
  it is the single ownership-enabling transition (release ordering in §5).
- **`armFailed`** is sticky (recovery = restart). It quarantines the runtime (§7),
  keeps the barrier, and the apply gate permits persistence/validation ONLY (§8).

The **cluster election hold is a CONSUMER of this state, not the source**: use a
**composed reason** `effectiveHold = dataplaneUnproven || kernelTrialUnpromoted`
(Codex r4 §1), each owner clearing ONLY its own reason. Do NOT rename/reuse
#1930's `kernelUpgradeHold` flag: rejoin/reset paths clear it without an arm proof
(failover.go:170) and the kernel-promotion marker (kernel_selfrecover.go:96) would
clear the dataplane reason prematurely. `dataplaneUnproven` is cleared only by §5.

---

## 3. Suppress AND withdraw pre-existing ownership (Codex r4 §1)

Holding election blocks NEW Primary transitions but does not withdraw ownership a
**former-Primary daemon left behind on a crash restart** (a crash leaves it — and note
even orderly shutdown does NOT stop Kea or clear persisted FRR, daemon_run_shutdown.go,
so the scrub below must cover Kea/FRR regardless of how the prior daemon exited). A
held/`armPending` startup that detects inherited ownership
must run a **verified withdrawal-only scrub BEFORE it advertises yield**:

- direct VIPs + stable link-locals (reconcile-removed today, daemon_ha.go:891) —
  withdraw explicitly + readback;
- goodbye RA (reconcile-driven) — explicit withdraw;
- VRRP stale VIPs (only removed after instances run) — explicit removal;
- Kea — authoritative `Apply(nil)` (dhcpserver.go:239);
- FRR — clear the managed section (it can advertise persisted state);
- **RG0 authority:** a held RG0 is created directly Secondary and emits NO demotion
  event, so `applyRG0OwnershipTransition` (daemon_ha.go:417) never makes the store
  read-only → both nodes could accept divergent authoritative commits. But the
  store read-only gate (`ensureWritableLocked` → `ErrClusterReadOnly`,
  store_lock.go) rejects user Set/Delete/**Commit**, so simply forcing read-only
  would ALSO block the promised fix-forward recovery (Codex r5 §2). The resolution
  is the **delayed-promotion config-authority contract (§8.5)**, not a blanket
  read-only: a held node never promotes a candidate to AUTHORITATIVE active, so it
  cannot diverge the cluster, yet it can still accept a corrected candidate for the
  next restart.

**Withdrawal scrub gates the yield (Codex r5 hole + r9/r10 refinement):** on a held
STARTUP (crash-restart/boot) the inherited VIP + stable link-local + Kea are withdrawn
SYNCHRONOUSLY and VERIFIED **before** this node publishes its first weight-zero yield;
if that scrub FAILS the startup node stays sender-silent and falls back to the
pre-existing peer-timeout window (it must never yield-before-scrub). The LIVE re-arm
case (a running primary) has a DIFFERENT failure fallback — it keeps its incumbent
heartbeat until the scrub succeeds rather than going silent — see §13-D5(c). The nft
barrier (§6) stops transit but NOT attraction / dual service ownership, which is why the
synchronous VIP+link-local+Kea scrub gating the yield is required in addition to the
barrier. FRR route de-dup is async (availability/ECMP behind the barrier, not an
ownership defect).

---

## 4. HA hold + yield are ATOMIC and need a pre-proof heartbeat (Codex r4 §3)

The #1930 hold does NOT by itself avoid both-secondary for the uncoordinated
arm-failure: the heartbeat still advertises the held node's normal priority/weight
(heartbeat_manager.go:251), so a lower-priority healthy peer with preempt demotes
on seeing the higher-priority held node while the held node refuses promotion →
both-secondary. Therefore, in HA, **the hold and the yield must activate
atomically**:

- **Yield = advertised weight-zero** in the fixed five-byte per-RG heartbeat record
  (heartbeat.go:93): legacy peers already promote on peer-weight-zero (mixed-version
  safe with no new field/bit), the STORED monitor weight is unchanged (so recalc is
  a non-issue — only the advertised copy is forced zero while unproven), and
  existing heartbeat authentication already covers it. A new "cannot-own" bit is
  rejected (an old peer ignores it unless weight-zero is also present).
  - **The advertised weight-zero MUST be gated on `effectiveHold` (§2), not on
    `dataplaneUnproven` alone (Codex r5 hole):** otherwise the dataplane proof could
    restore normal advertised weight while `kernelTrialUnpromoted` still blocks local
    ownership → the higher-priority-node both-secondary returns. Any active hold
    reason ⇒ advertise weight-zero.
- **Pre-proof heartbeat-only lifecycle:** the held node MUST heartbeat its yield so
  the peer takes over — but `startClusterComms` (the sole heartbeat starter,
  daemon_ha_sync.go:687/:771) today also bundles watchdog + session/config sync +
  dataplane consumers, which must NOT run while unproven. Split a **heartbeat-only**
  start (advertise weight-zero yield, receive peer state, no ownership, no
  consumers) from the full post-proof `startTakeoverMachinery` (§9). This closes
  r5's contradiction (yield needs a heartbeat that r5 placed behind the proof).

Consequence for phasing: PR1 (standalone) MUST be inert whenever cluster config
exists; the generalized hold cannot activate in HA without the atomic yield +
pre-proof heartbeat, so those land together (PR2). PR2 also fixes a latent #1930
gap (its "peer-non-preempt" property does not exist for uncoordinated failure).

---

## 5. Coverage proof at the FINAL arm boundary (Codex r4 §2)

Proving coverage after the FIRST `ApplyConfig` is too early:
`applyDataplaneAndHACore` continues with networkd, RETH MAC link-cycle, VIP
recovery, and an AF_XDP **reapply that starts deferred workers** — and a RETH path
deliberately publishes a workerless `DeferWorkers` snapshot whose later reapply
failure is reduced to retry debt (daemon_apply_dataplane.go:467); `Compile` can
also return success with snapshot publication still deferred (manager_compile.go:257).
So an expected program can be attached while the helper generation / XSK bindings
are not operational.

**Two-stage proof (Codex r5 §1 — proof must not be followed by proof-invalidating
mutation):**
- **PRELIMINARY attachment proof** — during the staged surface transaction (§9), a
  per-interface check that the expected shim program attached (so the transaction
  can decide to proceed/abort). This is NOT the release trigger.
- **FINAL post-mutation proof** — taken AFTER the LAST mutation that can affect the
  attachment: networkd, RETH MAC link-cycle, and the AF_XDP rebind/deferred-worker
  reapply (daemon_apply_dataplane.go:219/386). Addresses, FRR, services, barrier
  removal, forwarding enable, and ownership release all happen ONLY after this final
  proof. The reapply/rebind must RETURN proof-or-failure, not record retry debt.

**CORRECTION (#5275 PR1, re-verified against origin/master `ad9591177`): coverage
is THREE-valued, not a native/generic binary.** Implemented as written below, the
proof fails on every VLAN sub-interface — the loss cluster runs `reth0.50`/`reth0.80`
and the standalone VM runs VLAN 50 — i.e. it fail-closes essentially every real
deployment. A required surface resolves to exactly one of:

  - **direct** — a shim instance is attached here. NATIVE and GENERIC (skb-mode)
    both count: a generic shim still steers to userspace-dp and still enforces
    policy, `attachUserspaceShimXDP` treats a native failure as a warning and
    re-attaches generic, and iavf SR-IOV VFs have no native XDP at all, so the
    fallback is a supported steady state. #5275 exists to prevent a POLICY-FREE
    kernel; a fallback box is not policy-free.
  - **delegated** — no attach is expected here BY DESIGN. A VLAN sub-interface
    under the userspace shim is never attached (both attach loops skip it; it is
    recorded in `Manager.VlanSubInterfaces`) because the PARENT's XDP sees
    VLAN-tagged frames before kernel VLAN demuxing, and attaching the child breaks
    IPv6 NDP under generic-mode `XDP_PASS`. Coverage is the parent's and MUST be
    resolved — skipping VLAN children unconditionally would pass a surface whose
    coverage was never checked.
  - **uncovered** — anything else, including a readback that failed. Unarmed.

See `pkg/dataplane/armproof.go` (observe-only implementation + rationale) and
`armproof_5275_test.go` (both decisions pinned). **That implementation is the
PRELIMINARY stage, not the FINAL one** — it runs inside `CompileUserspaceShim`,
before networkd, the RETH MAC link-cycle and the AF_XDP rebind, so the
divergence rate it emits is a LOWER BOUND on what the FINAL-stage gate will see.
It is phase PR0 in §10, not PR1.

A **fourth** kind fell out of implementing it, which the classification above
still misses: **skipped**. FOUR soft skips drop a configured attach point while
the compile SUCCEEDS, so a surface the compiler declined to arm is
indistinguishable from one it armed — three per-interface in `mapZoneInterface`
(interface not found, VLAN child create failed, administratively disabled) and
one per-ZONE in `programZoneMaps` (`if zone == nil { continue }`, reachable on
the tolerant and HA-peer-sync config paths, which drops every interface in that
zone and cannot be resolved to per-interface coverage because `zone.Interfaces`
is the deref the guard prevents).

The sharp variant is `set interfaces <if> disable` whose `netlink.LinkSetDown`
then fails (a `slog.Warn` and nothing else): the netdev stays UP, is still
address-reconciled, is still in a zone, is still forwarded through by the
kernel, and carries no XDP. **The gating PR must treat that as uncovered**; a
skip whose netdev genuinely went down is a legitimate operator action and must
not fail the box closed. PR0 reports `skipped` for everything else — including
the nil zone — so PR1 inherits an explicit, unresolved decision rather than a
silent zero. `WouldGate` in PR0 deliberately excludes `skipped`.

**Coverage proof ingredients are PER-STAGE (§13-D1; readback-fail ⇒ unarmed) —
NOT identical across both stages:** the PRELIMINARY stage proves only the attach-point
INVENTORY + strict program INSTANCE identity (ID/tag) on every mapped attach point
(direct or, for a delegated surface, its delegate) — because ready XSK bindings do not exist yet on the
deferred-worker path; the FINAL stage (after the last rebind/reapply) adds the exact
candidate config digest + reconciled helper snapshot generation + ALL registered/
armed/ready XSK bindings. Neither stage uses the global `ProbeForwardingArmed`
(boot_probe.go, flags only) nor the pre-compile probe (the next compile deletes every
`xdp_*` pin before attach, manager_compile.go:162, so a pre-compile "covered" can be
destroyed).

**One atomic release owner (Codex r5 §4 — clearing the hold is the FINAL act):**
`startTakeoverMachinery()` is the SOLE `armPending → armed` release path and owns the
full post-proof lifecycle inventory IN ORDER: enable forwarding (+readback) → remove
barrier (+readback) → start the post-proof consumers (session/config sync, GC,
watchdog, reconcile loops) → **OPEN the revocable dataplane facade (§7)** →
**clear `dataplaneUnproven` LAST** (which may synchronously re-elect, so it must be the
final ownership-enabling action, with nothing following it). A crash at any earlier
step stays closed. `dataplaneUnproven` is never cleared outside this owner.

---

## 6. Mandatory transit barrier — bridge + flowtable, not just inet FORWARD (Codex r4 §2)

While `armPending`, a verified transit-deny MUST be in place BEFORE any destructive
interface mutation (compilation creates/addresses VLANs and brings links UP —
compiler_iface.go:521 — before deferred XDP attach). An `inet` FORWARD-hook
unconditional drop (management is INPUT, not FORWARD — no mgmt exemption) is
necessary but NOT sufficient: this repo creates Linux **bridge** domains
(compiler_iface.go:975) whose bridged L2 traffic need not traverse the inet forward
hook, and offloaded **flowtable** traffic bypasses it. The barrier therefore needs:

- the inet FORWARD unconditional drop (atomic `nft -f`, mirroring daemon_nft.go),
  plus `ip_forward=0` (v4+v6) with readback; AND
- a **bridge-family barrier** (or proved-down bridge ports); AND
- an explicit **flowtable disable/flush + readback**.

Removed (verified) ONLY at the §5 release ordering step. Not optional, not released
on any partial/unverified state.

---

## 7. Revocable dataplane runtime (Codex r4 §2 §5)

`d.dp=nil` does NOT contain the backend: gRPC/REST/CLI capture backend **aliases at
construction** (daemon_run_servers.go:88, daemon_run.go:597), and they expose
mutators (`SetForwardingArmed`, …, server_diag_system_action.go:396) that do NOT
traverse the apply gate — directly exploitable on bootstrap-exit, where management
already holds the backend when the later arm fails. Require a **shared revocable
facade** that starts **SEALED** (Codex r5 §5): every consumer holds the facade, not
the raw backend; while `armPending` the facade rejects all operational calls and
permits arming ONLY through a private capability held by the arm transaction; it is
OPENED atomically at the §5 final release; on arm failure (or any time) it is REVOKED
stickily against concurrent calls (all method calls fail closed) and the real backend
moves to a quarantined cleanup owner. Hardened `Teardown` keeps its per-handle
retention (loader.go:1203/1223 must retain each failed handle, aggregate errors,
readback that every link/pin incl. the partial attach is gone; barrier stays on
teardown debt). This is a foundational change (facade + revocation), which is why
it anchors PR1.

---

## 8. Three-route apply-admission gate (Codex r4 §2 §4)

One gate at the top of the apply pipeline, three explicit routes:

- **`armPending`** — permit ONLY the barrier-protected arm transaction (the staged
  surface activation, §9); no other publication.
- **`armFailed`** — permit config persistence + validation ONLY (so an operator can
  fix-forward and a restart re-arms against the corrected config); publish NO
  forwarding/ownership; the store stays non-authoritative for RG0 (§3) so a held
  node cannot diverge the cluster. Also: a first-arm failure must NOT clear sessions
  on the armed-invariant and must NOT push this node's state to the peer
  (daemon_apply_commit.go:303 `applyErrSkipsPeerSync`).
- **`armed`** — the normal pipeline.

## 8.5 Config authority = DELAYED PROMOTION (Codex r5 §2 §3) — resolves the
## publisher-generation TOCTOU AND the fix-forward contradiction with one contract

Today `commit` PROMOTES + PERSISTS the candidate as authoritative `ActiveConfig`
BEFORE the apply/arm (`applyAndSyncCommitted` runs on an already-committed+active
config, daemon_apply_commit.go:225). So independent reconcilers (DDNS, RA, direct-VIP)
that read `ActiveConfig` can publish an UN-ARMED candidate even if the current apply
stack aborts (Codex r5 §3) — aborting the apply is insufficient. And a blanket
read-only on a held node blocks fix-forward (Codex r5 §2). Both are resolved by
**delayed promotion**:

- **The candidate is promoted to authoritative `ActiveConfig` ONLY after the §5 final
  arm proof.** Until then, every publisher reads a durable **applied/published
  generation** that stays at the LAST ARMED config (a first-ever arm has none → the
  fail-closed empty/default-deny). On arm failure the applied generation never
  advances, so no reconciler can publish the un-armed candidate — the TOCTOU is
  structurally gone, not raced.
- **Fix-forward recovery:** the failed candidate is retained in a NON-authoritative
  recovery slot (persisted for the next restart) so an operator can correct it; a
  restart re-arms against the corrected config. A held HA node accepts a
  **narrowly-scoped inbound authoritative sync** from the primary (the existing
  `SyncApply` ingress already bypasses the read-only gate, store_lock.go) but does
  NOT itself promote a local candidate as authoritative while held — so it can
  receive the primary's correction without diverging the cluster.
- **`pkg/configstore` enters the blast radius** (the promote-after-arm reordering +
  the recovery slot). This is the one contract that reaches beyond `pkg/daemon`/
  `dataplane`/`cluster`.

---

## 9. Staged surface-activation transaction (Codex r4 §4) — B + empty transitions

"Do not bring up B until proven" conflicts with the current order (VLAN create +
link-up + address BEFORE deferred attach, compiler_iface.go:521). Replace it with an
explicit staged transaction, used for a newly-required interface B AND for
committed-empty→first-interface AND remove-all→add (these are NOT handled by a
one-way `startTakeoverMachinery`; a vacuous empty proof that releases the hold and
then reactively "re-enters" on the first add is a hole — they need the same staged
transaction, so they depend on the PR3 machinery, not PR1):

1. compute the candidate surface diff BEFORE mutation;
2. quarantine each newly-required surface (incl. a pre-existing/up one);
3. create it DOWN + unaddressed only as needed to obtain an ifindex;
4. attach + take the **PRELIMINARY** attachment proof (§5) — decide proceed/abort;
5. run the remaining attachment-affecting mutations (networkd, RETH MAC link-cycle,
   AF_XDP rebind/reapply) — see Codex r5 §1: these come AFTER the preliminary proof;
6. take the **FINAL** post-mutation coverage proof (§5); ONLY on success promote the
   candidate (§8.5) and publish address / FRR / services + release ownership (§5
   release owner);
7. on failure, do NOT promote (delayed promotion §8.5 keeps the prior armed
   generation authoritative for every publisher) and abort the candidate's staged
   surface, RETAINING the prior armed generation's policy (#5679 keeps the
   already-covered surface live).

`startTakeoverMachinery()` (idempotent, §2/§5) is the release path from `armPending`
to `armed`; it must be callable from BOTH the boot arm-proof AND the bootstrap-exit
arm-proof (runBootstrapExitStartup, daemon_run_naming.go:200, which today starts no
gated machinery — the half-start gap).

---

## 10. Phased delivery (honest — NOT each-PR-independently-complete)

Codex r4 is right that "multi-PR" is honest but "each PR independently correct" was
not. Corrected phasing, each a real architecture increment gated by smoke:

- **PR0 — pre-PR1 MEASUREMENT (observe-only), gates nothing:** the coverage
  classification of §5 implemented as a pure diagnostic, run at the PRELIMINARY
  attachment stage inside `CompileUserspaceShim`, reporting what a gating build
  would have decided (`WouldGate`) and that nothing was withheld (`DidGate`). No
  arm-state machine, no facade, no barrier, no apply gate — none of PR1's
  architecture. It exists because "armed" today is materially weaker than the
  proof PR1 will enforce (`attachUserspaceShimXDP` treats a NATIVE attach failure
  as a warning and re-attaches generic; iavf SR-IOV VFs have no native XDP at
  all), so the divergence rate has to be known before the gate is load-bearing.
  What it measures is the PRELIMINARY-stage rate — a lower bound on the FINAL
  stage's, which PR1 owns. `pkg/dataplane/armproof.go`, shipped as #6864.
  This phase was NOT in the original plan; the word "observe" appears nowhere
  else in this document, and PR1 below is a gate, not a diagnostic.
- **PR1 — foundation (standalone), INERT under cluster config:** the daemon-owned
  arm-state machine (§2), the revocable sealed-until-armed runtime facade + quarantine
  + hardened teardown (§7), the bridge+flowtable+FORWARD barrier (§6), deferred
  forwarding + the single-owner release ordering (§5), the three-route apply gate +
  delayed-promotion config authority (§8/§8.5), and the two-stage coverage proof (§5).
  Fixes the STANDALONE cold-boot policy-free-router hole end-to-end. PR1 handles the
  BOOT single-generation arm (the whole configured surface arms or the node stays
  fail-closed); it does NOT require the §9 multi-generation staged transaction (that
  is the day-2 add-interface case, PR3) — so §8's PR1 gate must not depend on §9.
  Explicitly inert when `cfg.Chassis.Cluster != nil` (no HA behaviour change) so it
  cannot half-activate HA.
- **PR2 — HA hold+yield atomic + pre-proof heartbeat + withdrawal scrub + RG0:**
  §3, §4. Activates the arm-state in cluster mode: the composed election hold, the
  atomic advertised-weight-zero yield, the pre-proof heartbeat-only lifecycle, and
  the verified withdrawal scrub of inherited ownership. Also closes the latent #1930
  both-secondary gap. Requires the two-node smoke.
- **PR3 — staged surface transaction:** §9. Covers day-2 add-B AND
  committed-empty→first AND remove-all→add.

Partial PRs say "advances #5275", never a close-keyword.

---

## 11. Blast radius, risks, docs

- **Blast radius:** `pkg/dataplane` (structured arm outcome + final-boundary
  coverage with program-instance readback + hardened per-handle Teardown +
  revocable facade), `pkg/daemon` (arm-state machine, bridge/flowtable/FORWARD
  barrier, deferred forwarding + release ordering, revocable-facade wiring for
  gRPC/REST/CLI/sampler, three-route apply gate, staged surface transaction,
  withdrawal scrub, bootstrap-exit `startTakeoverMachinery`), `pkg/cluster`
  (composed-reason hold, advertised-weight-zero yield, pre-proof heartbeat-only
  start), `pkg/configstore` (delayed promotion: promote-after-arm + the
  non-authoritative recovery slot + PromoteRollback arm-gating + commit-confirmed at
  the promotion boundary, §8.5/§13-D3/D4), and `pkg/networkd` (link/address phase
  split, §13-D2). Genuinely large; the facade + arm-state + barrier +
  delayed-promotion + the networkd phase split are foundational.
- **Risks:** (1) day-2 regression tearing a working dataplane — per-generation
  coverage + #5679 retention + RED tests; (2) the facade wiring missing a captured
  alias — a grep/audit of every `d.dp` capture + a revocation test on each consumer
  incl. gRPC/CLI; (3) barrier missing a bridge/flowtable bypass — an actual bridged
  + offloaded-flow smoke, not only inet FORWARD; (4) proof taken too early — a
  DeferWorkers/reapply-failure test that asserts unarmed; (5) HA both-secondary /
  mixed-version — the advertised-weight-zero two-node smoke + a legacy-peer golden;
  (6) release-ordering crash-safety — a fault-injection test at each step stays
  closed.
- **Docs:** `pkg/daemon/README.md` (the arm-state machine + barrier + release
  ordering + apply gate), `pkg/cluster` (composed hold + yield + pre-proof
  heartbeat), `pkg/dataplane/README.md` (final-boundary coverage + revocable facade
  + hardened Teardown), `_Log.md`.

---

## 12. Test plan (bind the dangerous seams — Codex r1–r4 lists)

- **Coverage @ final boundary:** attached-but-DeferWorkers/deferred-snapshot ⇒
  unarmed (proof after the reapply, which returns proof-or-failure not debt);
  program-instance-identity mismatch ⇒ unarmed; readback failure ⇒ unarmed;
  native-fail/generic-success ⇒ armed (INV); empty-but-expected ⇒ unarmed;
  pre-compile-probe-covered-then-pin-deleted-then-attach-fails ⇒ unarmed.
- **Barrier:** inet FORWARD drop + ip_forward=0 + bridge-family barrier + flowtable
  disabled/flushed, all present BEFORE interface mutation and removed only at the
  release step; a bridged L2 flow AND an offloaded flow are dropped while pending; a
  crash between coverage-proof and barrier-removal stays closed.
- **Revocable sealed facade:** while `armPending` every captured consumer (gRPC,
  REST, CLI, sampler) gets fail-closed results (facade sealed) EXCEPT the private arm
  capability; on arm failure the revoke is sticky against a concurrent in-flight call;
  bootstrap-exit late-arm-failure revokes the alias management already held.
- **Delayed promotion (§8.5):** on arm failure `ActiveConfig`/the published generation
  never advances to the candidate — an independent DDNS/RA/direct-VIP reconcile reads
  the last-armed generation, never the un-armed candidate (the TOCTOU is structurally
  absent); the recovery slot holds the failed candidate; a narrowly-scoped inbound HA
  sync still lands on a held node. Final proof taken AFTER networkd/RETH-rebind ⇒ a
  proof-then-mutation ordering bug is RED.
- **Arm-state / apply gate:** armPending permits only the arm transaction; armFailed
  permits persistence+validation only (no publish, RG0 non-authoritative, no peer
  push, no session clear); armed = normal.
- **HA:** held node advertises weight-zero yield via the pre-proof heartbeat ⇒ peer
  owns every mutually-configured, eligible RG (real heartbeat/election), no
  both-secondary even at higher held priority, no dual VIP in direct-VIP mode;
  weight-zero stays asserted while ANY hold reason is set (effectiveHold), so a
  dataplane proof under a still-set kernel-trial hold does not un-yield; the first
  weight-zero yield is NEVER published before the synchronous verified VIP + stable
  link-local removal + Kea stop (§13-D5(c)); on scrub failure the CRASH-restart path
  stays sender-silent (pre-existing timeout window) while the LIVE re-arm path KEEPS its
  incumbent heartbeat (peer stays backup) until the scrub succeeds — it never goes
  silent-while-holding; FRR route de-dup is async; legacy-peer golden promotes on
  weight-zero; held RG0 store is non-authoritative.
- **Staged transaction:** add-B-fails ⇒ B never addressed/up, A's policy retained,
  commit fails; committed-empty→first-interface + remove-all→add use the same
  staged transaction (RED if they take the one-way release path).
- **#5679 day-2 preserved:** ever-armed node's day-2 attach failure on an EXISTING
  surface keeps old policy live (not torn down).
- **Parent-RED:** assertion failures, imports used
  (`feedback_red_on_revert_must_be_assertion_not_build_break`).
  `GOCACHE=/dev/shm/gc-5275 GOTMPDIR=/dev/shm TMPDIR=/tmp go test ./pkg/daemon/...
  ./pkg/dataplane/... ./pkg/cluster/... 2>&1 | tail`.
- **Smoke (parent, loss cluster):** `make test-failover` + a runnable both-attach-fail
  injection (build-tag/env seam forcing `link.AttachXDP` both modes to fail on the
  data VF): injected node is lifeline (barrier up incl. bridge/flowtable,
  ip_forward=0, no XDP, no FRR/VRRP/VIP, held, yield advertised), peer carries
  sustained iperf3 (`feedback_verify_forwarding_with_sustained_iperf`), SSH up.
  Seam lands WITH the fix.

---

## 13. Resolved design decisions (Codex r6) — recommended choices for human go/no-go

Codex r6 fully closed release-ownership (§5), the sealed facade (§7), and
weight-zero gating (§4), and confirmed the delayed-promotion and recovery-slot
DIRECTIONS are right. Four contracts required an explicit design decision; each is
resolved below with a recommended choice (the human approves/overrides at `/engineer`):

- **D1 — Two-stage proof INGREDIENTS split (Codex r6 §1).** The preliminary stage
  cannot require ready XSK bindings (they do not exist until the deferred-worker
  rebind, daemon_apply_dataplane.go / manager_compile.go:318). Resolution:
  *preliminary* proves the attach-point INVENTORY + the exact shim program instance
  (ID/tag) per required surface; *final* (after the last rebind/reapply) proves the
  candidate digest + reconciled helper generation + ALL registered/armed/ready
  bindings. Only the FINAL proof triggers release.

  **Delivered so far (PR1, observe-only).** `pkg/dataplane/armproof.go` implements
  the INVENTORY half. It *reports* the program instance each tracked `bpf_link`
  carries but does **not** compare it against `m.programs[m.XDPEntryProgram()]`,
  and does not check `Info.XDP().Ifindex`. That is deliberate for a diagnostic:
  the mismatch is not a state this tree can produce (every writer of
  `m.xdpLinks` installs the entry program, `m.programs` has one shim writer
  post-#1476, and nothing outside the package can reach a tracked link), so the
  comparison would measure nothing while adding a new way to report a false
  `uncovered` — an unreadable expected program. **The ID/tag comparison lands
  with the GATING PR**, which must also resolve the direction PR1 has no
  evidence for: whether an unreadable expected program fails closed. Residual
  written down at `xdpLinkProgramID` and in `pkg/dataplane/README.md`.

- **D2 — networkd link/address phase split (Codex r6 §2; `pkg/networkd` now in the
  blast radius).** `networkd.Apply` writes link+address and reloads (can bounce the
  link, networkd.go:130). Resolution: split into a **link-only pre-proof phase**
  (create/rename to obtain an ifindex + attach — no address/route/reload that bounces
  the attached link) and an **attachment-neutral post-proof address/route phase**
  (address-only apply that does not re-cycle the proven link). Recommended over
  relocating the final boundary, which would leave addresses published pre-proof.

- **D3 — Delayed-promotion transaction invariants (Codex r6 §3).** Resolution:
  1. **Digest binding:** promote EXACTLY the immutable candidate tree that was
     proved; if the candidate mutated since the proof, reject (no silent substitution).
  2. **Boot selection:** `Store.Load` exposes the **last-armed applied** generation
     to publishers as authoritative; the failed candidate lives in a SEPARATE
     non-authoritative **recovery slot** used only for the next restart's arm attempt.
  3. **commit confirmed:** the confirm timer + durable rollback record begin at
     PROMOTION (post-arm). An arm failure ⇒ no promotion ⇒ no confirm timer; the prior
     armed generation stays authoritative (a bootstrap-takeover commit-confirmed that
     fails to arm falls back to the prior armed state, never a half-confirmed one).
  4. **Automatic rollback:** `PromoteRollback` routes through the arm-proof too — the
     rollback target must re-arm-prove before it is promoted+published (else it
     recreates the very publication race delayed promotion removes); if the rollback
     target also fails to arm, stay fail-closed.
  5. **History / RG0-demotion / confirmation** are recorded at the promotion boundary,
     not at candidate-commit.

- **D4 — Inbound HA recovery lifecycle (Codex r6 §4).** Reusing `SyncApply`
  (store.go:611 — it immediately promotes+resets) pre-proof would reopen the TOCTOU,
  and full config-sync starts only post-proof (an `armFailed` node never reaches it).
  Resolution: an **authenticated inbound-config-ONLY** ingress available pre-proof
  (separate from the full session/config-sync machinery) that lands the primary's
  config into the **recovery slot** (NOT immediate promote/reset), acknowledged with a
  **durably-staged recovery receipt** (§13-D4, Codex r7 — explicitly NOT an
  "applied-high-water": it must NEVER advance the existing live-applied generation used
  for failover readiness, or it would reopen the very TOCTOU delayed promotion closes);
  the primary's authoritative config supersedes a local recovery edit (a held node is
  non-authoritative). Recovery is thus RESTART-based: the correction is staged for the
  next restart's arm attempt; the held node never promotes it live.

- **D5 — Fail-closed HA ownership handoff (Codex r6 §5 → r7 → r8; the ONE remaining
  human design decision).** Two distinct cases; the crash case is bounded by an
  EXISTING mechanism, the live case needs a small new gate.

  **(a) Former-primary CRASH restart — reuse the SHIPPED preserved-address recovery;
  #5275 must NOT accelerate takeover ahead of the scrub (Codex r9).** When only `xpfd`
  crashes but the kernel keeps the NODAD VIPs, the design ALREADY treats this as a known
  duplicate-address hazard: `reconcileDirectVIPOwnership` runs EVERY tick because "the
  kernel preserves NODAD addresses across daemon restarts, so stale addresses can exist
  without a state transition" (daemon_ha.go:910), and `surfaceStaleVIP` (#5482,
  instance_vip.go) retries a failed VIP removal (a bounded RETRY budget — 5 delayed
  retries — not guaranteed convergence). A truly-dead box has no reachable VIPs; when
  the peer times out and promotes, its GARP steers hosts to the peer.
  - **The #5275 hazard Codex r9 found:** with a LONG (valid) heartbeat timeout, the
    crashed primary can RESTART before the peer times out. TODAY that node re-elects as
    sole owner → NO dual ownership. Under a naive yield, the arm-failed restart would
    publish weight-zero WHILE its inherited VIP/Kea still exist, and the peer promotes
    IMMEDIATELY on receiving weight-zero (heartbeat_manager.go:293 → election.go:138,
    peer-weight-0 promotes) → dual VIP + dual DHCP before the async scrub — an overlap
    #5275 would CREATE by accelerating takeover. That is not excused by the STONITH
    tradeoff.
  - **Fix (unify with (b)): the FIRST weight-zero yield — on the crash-restart path
    TOO — is gated on the SYNCHRONOUS, verified removal of the owned VIP + stable
    link-local + the Kea stop.** The arm-failed restart scrubs those synchronously
    BEFORE it publishes any weight-zero; only then does it yield. **If the synchronous
    scrub FAILS, it does NOT publish weight-zero** — it stays sender-silent and falls
    back to the PRE-EXISTING peer-timeout window (so #5275 never accelerates takeover
    into an un-scrubbed state; it is then "no worse than the existing crash window",
    which the human accepts or replaces with STONITH). Only FRR route de-dup is async
    (availability/ECMP behind the §6 barrier, not an ownership-safety defect).

  **(b) Live re-arm (a RUNNING primary loses its dataplane) — gate zero-publication on
  completed fast fencing.** Here the node IS running and controls its actions, but the
  shipped `shouldSuppressPeerHeartbeatTimeout` guard only covers the TIMEOUT path — a
  received **weight-zero heartbeat runs election immediately** (heartbeat_manager.go:293),
  so the interlock cannot be the keepalive alone. The gate is on OUR side: **emit the
  weight-zero yield ONLY AFTER** the synchronous, verified fast withdrawal of the owned
  VIP **and** the Kea stop (so when the peer elects on our zero, the VIP/DHCP authority
  is already gone). FRR route de-dup is async (the §6 barrier already blocks forwarding;
  the transient ECMP equals today's failover). For a zero-DROP (not merely
  no-dual-owner) handoff, an OPTIONAL acknowledged suppression lease (extend
  `SendLivenessKeepalive` with an ack + a bounded lease, dead node still promotes on
  expiry) is a follow-up, not required for safety.

  **(c) State machine + the yield gate (SHARED gate, PATH-SPECIFIC failure handling —
  Codex r10).** Define `armed → (arm-verify fails) → fencing → armFailed` with the
  arm-coverage proof (§5) as the failure detector. **Shared invariant:** a node NEVER
  publishes its first weight-zero yield until it has SYNCHRONOUSLY removed + verified its
  owned VIP + stable link-local + stopped Kea. **The scrub-FAILURE fallback differs by
  path (this is the Codex r10 correction — sender-silent is safe ONLY for crash-restart):**
  - **Crash-restart (node was DOWN):** on scrub failure stay **sender-silent** → the
    peer's pre-existing timeout window takes over (no #5275 acceleration). Safe because
    the node was not a healthy sender.
  - **Live re-arm (node is a RUNNING primary):** on scrub failure it must NOT go silent
    (silencing a healthy sender makes the peer time out and activate VIP/Kea while THIS
    node still holds them → dual ownership). Instead the `fencing` state is **pre-hold
    and KEEPS the incumbent heartbeat/takeover interlock** (the peer stays backup) UNTIL
    the scrub SUCCEEDS; only THEN does it ATOMICALLY enter `effectiveHold`/`armFailed`
    and publish weight-zero. While it remains in fencing/pre-hold with the scrub
    incomplete it is fail-CLOSED
    (the §6 barrier drops transit — a fail-closed blackhole, the security-correct
    default over dual-ownership), until the scrub succeeds or a **separately verified
    service/host fence** (the STONITH sign-off) resolves it. It NEVER yields
    before the scrub and NEVER goes silent-while-holding.
  Only FRR route de-dup is async (availability/ECMP behind the barrier). `pkg/cluster` +
  `pkg/vrrp` (the sticky `fencing` state: gates the first zero-publication, keeps the
  incumbent heartbeat on the live path until scrub, prevents VIP re-addition / queued
  Kea restart) + the scrub sequencing are the §13-D5 deliverables.

  **HUMAN SIGN-OFF (D5):** with the yield gate in place (a node never yields before its
  synchronous scrub; on scrub failure a CRASH-restart node stays sender-silent while a
  LIVE re-arm node keeps its incumbent heartbeat until scrub succeeds — §13-D5(c)),
  #5275 never ACCELERATES takeover into an un-scrubbed state. The residual is the
  pre-existing case
  where the node is TRULY DEAD (never restarts) and the peer's ordinary timeout expires
  with the kernel VIP still up — the SAME window ANY `xpfd` crash has today. Accept that
  existing window (RECOMMENDED, no new hardware) **versus** adding external STONITH
  fencing for a zero dual-address guarantee (new operational/hardware dependency). This
  is the one #5275 decision that is a genuine operations tradeoff, not a code detail.

Two minor residuals folded: §8's `armPending` route now distinguishes the **boot
single-generation arm** (PR1) from the §9 **staged-delta transaction** (PR3); the §5
release inventory places **facade OPEN immediately before the final `dataplaneUnproven`
clear**.

---

## Appendix — key source coordinates (RE-VERIFIED at origin/master @ `ad9591177`)

Every symbol below still exists; only the line numbers marked *(was N)* moved.
The architectural claims — ownership published in `initManagers` BEFORE the arm,
and an attach failure surfacing as an ORDINARY #5679 deferred error so the apply
tail still publishes — were re-verified directly and hold.

- `pkg/daemon/daemon_run_bringup.go:47` `initManagers` (BEFORE dataplane-setup):
  `:163` cluster-only block; `:179` `holdSecondaryIfKernelCandidateArmed` (#1930
  precedent) BEFORE `:181` `UpdateConfig`(=election); `:203` `watchClusterEvents`;
  `:215` `enableForwarding`; `:219-223` VRRP. `:414` `setupDataplaneAndInitialConfig`
  (arm; `applyConfig`@520 discarded)
- `pkg/daemon/kernel_selfrecover.go:58` #1930 hold returns when `d.cluster==nil`
  (why standalone needs a daemon-owned state); `:81` is `SetKernelUpgradeHold`
  (the plan previously named `ClearKernelUpgradeHold` here); `:96` kernel-promotion clear;
  `pkg/cluster/failover.go:170` rejoin/reset clears the hold without arm proof
- `pkg/daemon/daemon_apply.go:288` terminal-abort short-circuit; `:1069-1094`
  #5679 classification; `daemon_apply_dataplane.go:467` DeferWorkers reapply→debt;
  `daemon_apply_commit.go:303` `applyErrSkipsPeerSync`
- `pkg/dataplane/userspace/manager_compile.go:162` pin-deletion-before-attach;
  `:257` Compile-success-with-deferred-snapshot; `loader.go:211` empty-set success;
  `:214-247` attach (both-fail@242); `:1203/1223` Teardown (discards handles);
  `boot_probe.go:24` global-flags-only probe
- `pkg/daemon/daemon_ha.go:417` `applyRG0OwnershipTransition` (read-only only on a
  transition); `:891` reconcile-removes-inherited-VIP/linklocal;
  `daemon_ha_vip.go:162` direct-VIP; `daemon_nft.go` atomic nft;
  `pkg/dataplane/compiler_iface.go` iface up/addr before attach + bridge domains
  (the plan previously cited this file with no package prefix);
  `dhcpserver.go:239` Kea `Apply(nil)`
- `pkg/cluster/heartbeat.go:93` fixed 5-byte per-RG record (weight field);
  `heartbeat_manager.go:251` advertises stored priority/weight;
  `pkg/daemon/daemon_ha_sync.go:687/:771` `startClusterComms`/`StartHeartbeat`
  (sole heartbeat starter — needs a pre-proof heartbeat-only split);
  `daemon_run_servers.go:117` (gRPC) and `:255` (REST) capture the `d.dp` alias
  *(was :88)*; `SetForwardingArmed` is reachable via
  `pkg/grpcapi/server_diag_system_action.go:405` *(was :396)* and
  `pkg/cli/cli_request_chassis.go:158` without traversing the apply gate
