# Plan of action — #5275: fail closed on dataplane ARM/ATTACH failure at boot

- **Issue:** #5275 (HIGH; bug, dataplane, security, vsrx-parity)
- **Research branch:** `research/5275-arm-failclosed`
- **Base:** origin/master @ `6131eb4e6`
- **Revision:** r5 (converges on GENERALIZING the shipped #1930 pre-election
  dataplane-arm hold, after Codex r1–r3 established that ownership/forwarding is
  published in `initManagers` BEFORE the arm and that a correct fix is a positive
  arm-proof gate, not a reactive flag)
- **Prior art:** PR #6358 (draft) — MERGE-NEEDS-MAJOR. Superseded.
- **Status:** PLAN-READY candidate (research only — no production code;
  `/engineer 5275`).
- **Honest sizing:** this is a real architecture change (a boot-sequence arm-proof
  gate + dataplane-lifetime quarantine + apply-admission), not a one-`if` fix. §9
  gives a phased delivery. That sizing IS the research finding.

---

## 1. Problem & the shape of the correct fix

#1960/#1993 fail **closed only on a COMPILE failure**. A config that COMPILES but
whose dataplane fails to **arm** (attach the AF_XDP shim to the data interfaces)
degrades a cold-booted firewall to a policy-free Linux router. Three Codex hostile
rounds + firsthand verification established that a correct fix cannot be a reactive
"`dataplaneArmFailed` flag gating publishers", because **election, VIP/RA ownership
publication, VRRP, and `enableForwarding` all run in `initManagers` (manager-init)
BEFORE the arm** (`setupDataplaneAndInitialConfig`) — so by the time an arm failure
is known, a preempt node has already claimed Primary and published direct-VIP/RA
ownership, and suppressing anything afterward strands it (dual-owner / both-owner).

**The correct shape is a positive arm-proof GATE that defers all ownership +
forwarding until the dataplane is proven armed for the current config generation —
and this pattern already ships in #1930.**

---

## 2. Root architecture — generalize the #1930 pre-election dataplane-arm hold

`initManagers` already calls `holdSecondaryIfKernelCandidateArmed()` **before**
`d.cluster.UpdateConfig(cc)` (daemon_run_bringup.go:179-181). Its own comment
states the exact invariant #5275 needs: the hold "MUST precede UpdateConfig — not
merely Start() — or the node is already StatePrimary by the time the hold is set
and Start()'s heartbeat/VRRP would advertise primary and preempt the healthy peer",
and it keeps "an unverified candidate from blackholing traffic". #1930's hold
(`kernelUpgradeHold`) is:

- set BEFORE the first election (so the node never becomes Primary, even isolated);
- honored by the election gate (`electRG`/`electSingleNode` return no-change);
- NOT auto-cleared for an isolated node (a broken node never self-promotes);
- cleared ONLY when a promotion gate verifies the dataplane.

**#5275 = generalize this hold from "kernel-candidate boot" to "any boot whose
dataplane is not yet proven armed", and change its clear-condition from the kernel
promotion gate to a per-generation arm-coverage proof.**

Concretely — an `armProofHold` (may reuse/rename the #1930 hold plumbing):

1. **`initManagers` installs `armProofHold` BEFORE `UpdateConfig`** (exactly where
   #1930 installs its hold). Election never makes the node Primary →
   `watchClusterEvents` produces/consumes no Primary transition → NO direct-VIP,
   GARP/NA, per-RG RA, or Kea ownership is published (daemon_ha.go:329 /
   daemon_ha_vip.go:162 never fire); VRRP stays BACKUP.
2. **`enableForwarding` is NOT called while held** — moved behind the arm proof
   (replacing the unconditional bringup:215 call), AND a **mandatory verified
   transit barrier** is in place during the held window (§5) because interface
   compilation brings links up/addresses them and the compile deletes XDP pins
   BEFORE attach (Codex D4/§4).
3. **The arm-coverage proof (per-generation, §4) CLEARS the hold**, then and only
   then does the node run `startTakeoverMachinery()` (§3) — normal election,
   ownership publication, heartbeat/sync, forwarding open. On a normal boot this is
   the same end-state as today, reached a few steps later.
4. **Arm FAILURE keeps the hold** (like a #1930 candidate whose dataplane never
   verified) → fail-closed: no ownership ever published, forwarding barrier stays,
   dataplane quarantined + torn down (§6), apply-admission blocks re-publish (§7).

**Peer takeover (no both-secondary):** #1930's hold already prevents the held node
from preempting the healthy peer, and the held node still runs heartbeat, so the
peer has full state. The one uncoordinated-failure gap #1930 does not face (it is a
coordinated drain) is the **higher-priority held node + preempting peer →
both-secondary** case (Codex r1 Finding 2): while held, the node must also advertise
a **yield posture** (weight-0 / an explicit "cannot-own" bit) in its heartbeat so a
preempting peer does not defer to its stored priority. This is the ONE piece of new
HA wire behaviour; it is small, and it is layered on the shipped hold rather than a
new state machine. (If a wire bit is undesirable, advertising weight-0 while held is
the no-new-field fallback; note `recalcWeight` must not overwrite the *advertised*
copy while held.)

This dissolves the dual-owner failure Codex r3 §2 found: the node never becomes
Primary in the first place (hold precedes election), so there is nothing to strand.

---

## 3. `startTakeoverMachinery()` — a reusable, idempotent lifecycle (Codex r3 §3)

Today the takeover machinery is scattered: election in `UpdateConfig`
(initManagers), `watchClusterEvents` start (initManagers), `enableForwarding`
(initManagers), then the goroutine section (`startClusterComms`,
`proxyARPReassertLoop`, DDNS loops, `watchVRRPEvents`, reconcile loop, relay
master-gate, GC/session-sync/event-stream). A flag around the boot section is
insufficient (Codex r3 §3): bootstrap-exit does NOT re-run the boot section, so a
gated boot would leave a successful bootstrap-exit permanently half-started.

**Deliver a single idempotent `startTakeoverMachinery()`** that performs: clear the
`armProofHold` (allow election), open forwarding (remove the barrier, verified),
and start every ownership/consumer that must only run once armed. It is called from
BOTH the boot arm-proof and the bootstrap-exit arm-proof (`runBootstrapExitStartup`,
which today only does naming/forwarding/`dp.Start`/seed/NAT-monitor —
daemon_run_naming.go:200). Idempotent so a re-arm/reconcile cannot double-start. The
management plane (gRPC/REST/CLI/SSH) starts INDEPENDENTLY of this and always (the
lifeline).

---

## 4. Detection — per-generation coverage with program identity (Codex r3 §4)

`d.dp.ApplyConfig` returns a **structured arm outcome**: for THIS candidate
generation, the required data-interface surface (resolved ifindexes + unresolved
logical identities), and per required surface the **expected shim program ID/tag**,
mode (native/generic), interface identity, and a KERNEL readback of the attached
program — plus the config/candidate digest and helper snapshot generation. "Armed" =
every required surface carries the expected program (native or generic); a
missing/unresolved required interface, an empty-but-expected mismatch, or any
readback failure ⇒ **unarmed** (fail closed). This is per-generation coverage, NOT a
historical `everArmed` boolean.

Two hazards this must handle (both Codex-verified):

- **Empty required set returns success** (loader.go:211): a committed-empty boot is
  vacuously "armed" with no data surface — that is fine as a held→released
  transition ONLY because there is no transit; the FIRST data interface added must
  RE-prove coverage, and a later attach failure on it re-enters the hold /
  fail-closed (this makes committed-empty→first-interface and remove-all→add
  in-scope, handled, not deferred).
- **Pin-deletion-before-attach** (manager_compile.go:162 deletes every `xdp_*` pin
  before a fresh attach): the pre-compile hitless probe (`ProbeForwardingArmed`,
  boot_probe.go — global `Enabled && ForwardingArmed`, NOT per-interface identity)
  cannot be trusted as surviving coverage, because the very next compile can destroy
  the old links and then fail the new attach. Coverage MUST be proven by post-attach
  kernel readback of the expected program on every required surface, AFTER the
  compile, not by the pre-compile global probe.

**Where:** immediately after `d.dp.ApplyConfig` returns, inside
`applyDataplaneAndHACore` (the arm sites' `applyConfig` is void). On success →
`startTakeoverMachinery()`; on failure → terminal pre-tail abort (verified skips the
tail, daemon_apply.go:288) + fail-closed (§6).

---

## 5. Mandatory transit barrier during the held window (Codex r3 §4)

While `armProofHold` is set (from before `UpdateConfig` until a coverage proof), a
**verified transit-forwarding deny MUST be in place before any destructive interface
mutation** — because interface compilation creates/addresses VLANs and brings links
UP (compiler_iface.go:350/521) and the compile deletes XDP pins BEFORE attach, so a
window exists where interfaces are up with no XDP and forwarding could route. The
barrier is:

- an **UNCONDITIONAL** nftables `inet` FORWARD-hook drop of transit (Codex r3 §1:
  management is INPUT, not FORWARD — do NOT exempt the mgmt interface; that would be
  a routed bypass), installed atomically (`nft -f`, mirroring daemon_nft.go) with a
  priority that a later `ct established accept` cannot override, ruling out
  bridge/flowtable bypass; AND
- `ip_forward=0` (v4+v6) with readback (belt).

It is removed (verified) ONLY by `startTakeoverMachinery()` on the coverage proof.
It is NOT optional and NOT released on any partial/unverified state. (It does not
cover the DHCP relay — a local-socket forwarder — but the relay master-gate/loop is
part of the machinery that is not started while held, §3, so relay does not forward
either.)

---

## 6. Dataplane quarantine + teardown (Codex r3 §5)

On arm failure, the operational backend must become UNREACHABLE while it is cleaned:

- **Move the backend to a separate quarantined field** (`d.dpCleanup`), set the
  operational `d.dp = nil`. gRPC/REST/CLI/sampler dereference `d.dp`
  (daemon_run_servers.go:78, daemon_run.go:578) and expose mutators
  (`SetForwardingArmed`, …, server_diag_system_action.go:396) — so a retained
  OPERATIONAL backend would be re-armable. The quarantined field is reachable only
  by the teardown/retry path.
- **Hardened `Teardown()`**: aggregate close/unpin/detach/pin-removal errors +
  kernel/pin readback that every XDP link/pin (incl. the partially-attached
  interface, loader.go:214-224) is gone; the LOWER layer must RETAIN each failed
  resource handle for retry (today loader.go:1203/1223 discards handles and
  propagates only the final `RemoveAll`) — retaining only the outer object is
  useless if the sole handle was dropped. On persistent failure, keep the transit
  barrier (§5) up and record teardown debt.
- Because the takeover machinery + dataplane consumers were never started (held),
  there is no consumer racing the nil — the quarantine + barrier make the state safe
  without a global dataplane-lifetime lock for the first-arm case.

---

## 7. Apply-admission gate (Codex r3 §5) — sticky, one place

"Sticky until restart" needs an admission gate, not just a set flag: a later
management commit re-enters `applyConfigLocked`; with `d.dp==nil` it would publish
FRR/VRRP/services with no enforcement. Add ONE admission check at the top of the
apply pipeline: while the arm-proof hold is set / arm-failed, the apply runs config
persistence + validation but PUBLISHES no forwarding/ownership (no FRR, no VRRP, no
services) and returns a fail-closed status. This is the single choke-point
equivalent for day-2 commits, replacing per-publisher gates. It also covers the
commit wrapper: a first-arm failure must NOT clear sessions on the armed-invariant
and must NOT push this node's state to the peer (daemon_apply_commit.go:303
`applyErrSkipsPeerSync`).

---

## 8. Scope: day-2 binding expansion (Codex r3 §6) — folded, not deferred

The in-scope first-arm cases — boot, bootstrap-exit, committed-empty→first-interface,
remove-all→add — are all handled by §2–§7 (the hold + per-generation coverage +
machinery lifecycle). (Note: a *config-less* HA node acquiring HA at runtime is NOT
a current path — runtime HA construction is restart-required,
cluster_topology_preflight.go:24 — so it is not a case to design for.)

The **day-2 A-armed / add-B-fails** case (the machinery is already running) is folded
with a **pre-mutation quarantine of B**: per-generation coverage identifies B as
newly-required; the compile must NOT bring up/address B until its attach is proven,
and B's attach failure aborts the B-specific downstream publication while RETAINING
A's old policy (#5679 keeps A live). Bringing B down *after* it was addressed
(reactive) is insufficient (a forwarding window + no persistence vs a retry) — the
quarantine is pre-mutation. This keeps A continuously protected and closes B's hole,
so it is folded into #5275 rather than deferred.

---

## 9. Phased delivery, blast radius, risks, docs

**Phased (each independently correct + smoke-testable, no half-published state):**
- **PR1 — standalone arm-proof gate:** structured per-generation coverage + the
  `armProofHold` generalization + `startTakeoverMachinery()` + the §5 barrier +
  §6 quarantine/teardown + §7 apply-admission, on a STANDALONE node (no cluster).
  Fixes the core cold-boot policy-free-router hole; cluster-safe (the hold reuses
  #1930's peer-non-preempt property).
- **PR2 — HA yield posture:** the held-node weight-0/cannot-own advertisement so a
  higher-priority held node never strands the peer (both-secondary), + the two-node
  smoke.
- **PR3 — day-2 pre-mutation B quarantine** (§8).
Partial PRs say "advances #5275".

**Blast radius:** `pkg/dataplane` (structured arm outcome + program-identity
readback + hardened per-handle Teardown), `pkg/daemon` (generalize the #1930 hold in
initManagers, `startTakeoverMachinery`, defer enableForwarding + the nft FORWARD
barrier, dataplane quarantine field, apply-admission, bootstrap-exit wiring),
`pkg/cluster` (the held-node yield advertisement; reuse the #1930 election gate).
Real but bounded by reusing #1930.

**Risks:** (1) day-2 regression tearing a working dataplane — per-generation coverage
+ #5679 retention of A + RED tests; (2) the generalized hold wrongly held on a
legitimate NoDataplane/retired build — the hold is armed only when an arm is
attempted-and-unproven (NoDataplane never attempts) + negative control; (3) hitless
survivor mis-proof — post-attack kernel readback, not the global probe, + test; (4)
barrier severs mgmt — it is FORWARD-only (mgmt is INPUT) + SSH-reachable smoke; (5)
half-started after bootstrap-exit — the idempotent `startTakeoverMachinery` called
from both arm sites + test.

**Docs:** `pkg/daemon/README.md` (generalize the #1930 fail-closed hold to all
first-arm boots; the barrier; the lifecycle), `pkg/cluster` (held-node yield),
`pkg/dataplane/README.md` (structured arm outcome + hardened Teardown), `_Log.md`.

---

## 10. Test plan (bind the dangerous seams — Codex r3 §6 list)

- **Coverage:** both-attach-fail ⇒ `ErrShimAttachFailed` + outcome shows the
  required program absent by ID/tag; native-fail/generic-success ⇒ armed (INV);
  empty-but-expected mismatch ⇒ unarmed; post-attach readback failure ⇒ unarmed;
  hitless survivor via post-attach kernel readback (NOT the pre-compile probe).
- **Hold precedes election:** with an arm that will fail, assert the node NEVER
  reaches Primary and publishes NO direct-VIP/GARP/RA/Kea/VRRP-master (the actual
  `watchClusterEvents`/election seams, not a fake) — RED if the hold is installed
  after `UpdateConfig`.
- **Machinery lifecycle:** `startTakeoverMachinery` is the ONLY path that opens
  forwarding + starts ownership; called from boot arm-proof AND bootstrap-exit
  arm-proof; idempotent (double-call is a no-op); a successful bootstrap-exit is
  fully started (not half).
- **Barrier:** the FORWARD drop + ip_forward=0 are present BEFORE interface
  compilation/pin-deletion and removed only on coverage proof; blocked attach ⇒ no
  transit forwards (an established v4/v6 conntrack flow started before the failure
  is dropped, not merely the final state).
- **Quarantine/teardown:** arm failure ⇒ operational `d.dp==nil`, backend in
  `d.dpCleanup`, gRPC/CLI cannot re-arm it; `Teardown` aggregates errors + readback
  + retains each failed handle; barrier stays on teardown debt.
- **Apply-admission:** a day-2 commit while held/arm-failed persists config but
  publishes NO FRR/VRRP/services and reports fail-closed — RED if the admission
  check is removed. First-arm failure does NOT clear sessions / push to peer.
- **#5679 day-2 preserved:** an ever-armed node's day-2 attach failure on an
  EXISTING surface keeps old policy live (not torn down). Add-B-fails: A stays
  protected, B never brought up, commit fails.
- **HA (two-node):** a held/arm-failed node advertises the yield posture ⇒ the peer
  owns every RG and carries sustained iperf3 (real heartbeat/election, not a direct
  `electRG`); no both-secondary even when the held node has higher priority; no dual
  VIP in direct-VIP mode.
- **Parent-RED:** assertion failures, imports used
  (`feedback_red_on_revert_must_be_assertion_not_build_break`).
  `GOCACHE=/dev/shm/gc-5275 GOTMPDIR=/dev/shm TMPDIR=/tmp go test ./pkg/daemon/...
  ./pkg/dataplane/... ./pkg/cluster/... 2>&1 | tail`.
- **Smoke (parent, loss cluster):** `make test-failover` + a runnable both-attach-fail
  injection (build-tag/env seam forcing `link.AttachXDP` both modes to fail on the
  data VF): injected node is lifeline (barrier up, ip_forward=0, no XDP, no
  FRR/VRRP/VIP, held), peer carries sustained iperf3
  (`feedback_verify_forwarding_with_sustained_iperf`), SSH up. Seam lands WITH the fix.

---

## Appendix — key source coordinates (origin/master @ 6131eb4e6)

- `pkg/daemon/daemon_run_bringup.go:47` `initManagers` (manager-init, BEFORE
  dataplane-setup): `:159` ipmon.Start; `:179` `holdSecondaryIfKernelCandidateArmed`
  (THE #1930 hold to generalize) BEFORE `:181` `UpdateConfig`(=election); `:203`
  `watchClusterEvents`; `:215` `enableForwarding`; `:219-223` `vrrpMgr` Start.
  `:414` `setupDataplaneAndInitialConfig` (the arm; `applyConfig`@520 discarded)
- `pkg/daemon/daemon_run.go:143-158` boot phases (manager-init@154 BEFORE
  dataplane-setup@157); goroutine section @356/384/450/532/545/565/569 (started
  after, but election/VIP/VRRP already published in initManagers)
- `pkg/daemon/daemon_run_naming.go:200` `runBootstrapExitStartup` (does NOT start the
  gated machinery today — needs `startTakeoverMachinery`)
- `pkg/daemon/daemon_apply.go:49` void `applyConfig`; `:288` terminal-abort
  short-circuit; `:1069-1094` ApplyConfig classification (#5679);
  `daemon_apply_commit.go:303` `applyErrSkipsPeerSync`
- `pkg/dataplane/loader.go:211` empty-set success; `:214-247` `attachUserspaceShimXDP`
  (both-fail@242); `:1203/1223` `Teardown` (discards handles, only final RemoveAll);
  `userspace/manager_compile.go:162` pin-deletion-before-attach;
  `userspace/boot_probe.go:24` `ProbeForwardingArmed` (global flags only);
  `compiler_iface.go:350/521` interface up/addr before attach
- `pkg/cluster/election.go` #1930 hold gate (`electRG`/`electSingleNode`);
  `group_state.go:125` `UpdateConfig`→`electSingleNode`; `heartbeat_manager.go:273`
  heartbeat carries State/Priority/Weight
- `pkg/daemon/daemon_ha.go:329` RG0 transition/ownership; `daemon_ha_vip.go:162`
  direct-VIP; `daemon_nft.go` atomic nft (barrier machinery);
  `daemon_run_servers.go:78` / `daemon_run.go:578` gRPC/sampler deref `d.dp`
