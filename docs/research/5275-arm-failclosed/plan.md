# Plan of action — #5275: fail closed on dataplane ARM/ATTACH failure at boot

- **Issue:** #5275 (HIGH; bug, dataplane, security, vsrx-parity)
- **Research branch:** `research/5275-arm-failclosed`
- **Base:** origin/master @ `6131eb4e6`
- **Revision:** r6 (complete design contract — folds Codex r1–r4; r4 confirmed the
  architecture is VIABLE and specified the contracts a full fail-closed spec needs)
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
**former-Primary daemon left behind on a crash restart** (orderly shutdown scrubs;
a crash does not). A held/`armPending` startup that detects inherited ownership
must run a **verified withdrawal-only scrub BEFORE it advertises yield**:

- direct VIPs + stable link-locals (reconcile-removed today, daemon_ha.go:891) —
  withdraw explicitly + readback;
- goodbye RA (reconcile-driven) — explicit withdraw;
- VRRP stale VIPs (only removed after instances run) — explicit removal;
- Kea — authoritative `Apply(nil)` (dhcpserver.go:239);
- FRR — clear the managed section (it can advertise persisted state);
- **RG0 read-only:** a held RG0 is created directly Secondary and emits NO demotion
  event, so `applyRG0OwnershipTransition` (daemon_ha.go:417) never sets the store
  read-only → both nodes could accept divergent commits. Force the RG0 read-only
  gate explicitly while `armPending`/`armFailed` (the apply gate §8 also blocks
  publication, but the store-write gate must be set independently so a config
  divergence cannot even be persisted-as-authoritative on a held node — see §8 for
  the persist-but-not-authoritative nuance).

The nft barrier (§6) stops transit but NOT traffic attraction / dual service
ownership, which is why the scrub is required in addition to the barrier.

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

**Coverage proof (all required, readback-fail ⇒ unarmed):**
- exact candidate config digest + successfully reconciled helper snapshot generation;
- the exact expected registered / armed / ready XSK bindings;
- strict program INSTANCE identity (ID/tag) on every mapped attach point (native or
  generic) — NOT the global `ProbeForwardingArmed` (boot_probe.go, flags only), and
  NOT the pre-compile probe (the next compile deletes every `xdp_*` pin before
  attach, manager_compile.go:162, so a pre-compile "covered" can be destroyed);
- proof taken AFTER the final link-cycle/reapply/rebind mutation; the second
  reapply/rebind must RETURN proof-or-failure, not record retry debt.

**Release ordering (Codex r4 §2 — the hold clears LAST):**
`final mutation → complete coverage proof → enable forwarding (+readback) → remove
barrier (+readback) → clear dataplaneUnproven / advertise armed → startTakeoverMachinery`.
A crash at any earlier step stays closed.

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
mutators (`SetForwardingArmed`, …) — directly exploitable on bootstrap-exit, where
management already holds the backend when the later arm fails. Require a **shared
revocable facade**: every consumer holds the facade, not the raw backend; on arm
failure the facade is REVOKED (all method calls fail closed) and the real backend
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
4. attach + prove program identity + helper-generation/binding coverage (§5);
5. ONLY THEN publish address / networkd / VRF / FRR / service changes for it;
6. on failure, abort ALL candidate downstream publication while RETAINING the prior
   armed generation's policy (#5679 keeps the already-covered surface live).

`startTakeoverMachinery()` (idempotent, §2/§5) is the release path from `armPending`
to `armed`; it must be callable from BOTH the boot arm-proof AND the bootstrap-exit
arm-proof (runBootstrapExitStartup, daemon_run_naming.go:200, which today starts no
gated machinery — the half-start gap).

---

## 10. Phased delivery (honest — NOT each-PR-independently-complete)

Codex r4 is right that "multi-PR" is honest but "each PR independently correct" was
not. Corrected phasing, each a real architecture increment gated by smoke:

- **PR1 — foundation (standalone), INERT under cluster config:** the daemon-owned
  arm-state machine (§2), the revocable runtime facade + quarantine + hardened
  teardown (§7), the bridge+flowtable+FORWARD barrier (§6), deferred forwarding +
  the release ordering (§5), the three-route apply gate (§8), and the coverage proof
  at the final boundary (§5). Fixes the STANDALONE cold-boot policy-free-router hole
  end-to-end. Explicitly inert when `cfg.Chassis.Cluster != nil` (no HA behaviour
  change) so it cannot half-activate HA.
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
  start). Genuinely large; the facade + arm-state + barrier are foundational.
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
- **Revocable facade:** on arm failure every captured consumer (gRPC, REST, CLI,
  sampler) gets fail-closed method results; bootstrap-exit late-arm-failure revokes
  the alien management already held the backend through.
- **Arm-state / apply gate:** armPending permits only the arm transaction; armFailed
  permits persistence+validation only (no publish, RG0 non-authoritative, no peer
  push, no session clear); armed = normal.
- **HA:** held node advertises weight-zero yield via the pre-proof heartbeat ⇒ peer
  owns every RG (real heartbeat/election), no both-secondary even at higher held
  priority, no dual VIP in direct-VIP mode; legacy-peer golden promotes on
  weight-zero; withdrawal scrub removes inherited VIP/RA/Kea/FRR before yield;
  held RG0 store is non-authoritative.
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

## Appendix — key source coordinates (origin/master @ 6131eb4e6)

- `pkg/daemon/daemon_run_bringup.go:47` `initManagers` (BEFORE dataplane-setup):
  `:163` cluster-only block; `:179` `holdSecondaryIfKernelCandidateArmed` (#1930
  precedent) BEFORE `:181` `UpdateConfig`(=election); `:203` `watchClusterEvents`;
  `:215` `enableForwarding`; `:219-223` VRRP. `:414` `setupDataplaneAndInitialConfig`
  (arm; `applyConfig`@520 discarded)
- `pkg/daemon/kernel_selfrecover.go:58` #1930 hold returns when `d.cluster==nil`
  (why standalone needs a daemon-owned state); `:81` `ClearKernelUpgradeHold`
  re-elects immediately; `:96` kernel-promotion clear;
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
  `compiler_iface.go:521` iface up/addr before attach; `:975` bridge domains;
  `dhcpserver.go:239` Kea `Apply(nil)`
- `pkg/cluster/heartbeat.go:93` fixed 5-byte per-RG record (weight field);
  `heartbeat_manager.go:251` advertises stored priority/weight;
  `pkg/daemon/daemon_ha_sync.go:687/:771` `startClusterComms`/`StartHeartbeat`
  (sole heartbeat starter — needs a pre-proof heartbeat-only split);
  `daemon_run_servers.go:88` / `daemon_run.go:597` gRPC/sampler capture `d.dp` alias
