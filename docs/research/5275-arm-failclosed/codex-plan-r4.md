# Codex hostile plan-review r4 (#5275) — VERDICT: PLAN-NEEDS-MAJOR (design viable, not an executable contract yet)

Reviewed plan.md @ r5. Final synthesis (file-read dumps stripped):

### 3. PR2 cannot safely be deferred as written

The supposed #1930 “peer-non-preempt property” does not exist. Heartbeats still advertise the held node’s normal priority and weight ([heartbeat_manager.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:251)). A lower-priority healthy peer can demote on seeing the higher-priority held node, while the held node refuses promotion: both-secondary. The earlier coordinated drain state is in-memory and lost across reboot.

An advertised-only weight-zero override is the credible mixed-version design:

- weight is already in the fixed five-byte per-RG record ([heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat.go:93));
- legacy peers already promote when peer weight is zero;
- stored monitor weight can remain unchanged;
- existing heartbeat authentication covers the override.

The unspecified “weight-zero / cannot-own bit” choice is not plan-ready. An old peer will ignore a new bit unless weight zero is also present.

There is also a direct lifecycle contradiction: r5 says the held node heartbeats its yield posture, but places `startClusterComms` inside post-proof machinery. Heartbeat starts only inside that function, which also bundles watchdog, session/config sync, and dataplane consumers ([daemon_ha_sync.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha_sync.go:687)). A safe pre-proof heartbeat-only lifecycle must be separated.

Accordingly:

- PR1 is safe only if explicitly inert whenever cluster configuration exists.
- If PR1 activates the generalized hold in HA, yield must land atomically with it.
- PR2 is not a small optional wire follow-up; it includes lifecycle separation and fixes a latent #1930 problem.

### 4. B quarantine and empty transitions are still assertions

“Do not bring up/address B until attach is proven” conflicts with current ordering: VLAN creation, link-up, and address reconciliation occur before deferred XDP attachment ([compiler_iface.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:521)).

The plan needs an explicit staged transaction:

1. Compute the candidate surface diff before mutation.
2. Quarantine B, including a pre-existing/up B.
3. Create it down and unaddressed only as needed to obtain an ifindex.
4. Attach and prove program plus helper-generation/binding coverage.
5. Only then publish address, networkd, VRF, FRR, and service changes.
6. On failure, abort all candidate downstream publication while retaining A’s old generation.

Committed-empty→first and remove-all→add are not handled by the current one-way `startTakeoverMachinery`. Once the vacuous empty proof releases the hold and starts ownership, merely saying the first add “re-enters” the hold is reactive. These cases require the same pre-mutation transaction as B, making them dependent on PR3 contrary to r5’s PR1 claims.

The apply gate likewise needs three explicit routes: `armPending` permits only the barrier-protected arm transaction; `armFailed` permits persistence/validation only; `armed` permits the normal pipeline. “While held, publish nothing” otherwise blocks the very first arm or permits unspecified pre-proof mutations.

### 5. Round-3 closure and sizing

r5 genuinely improves:

- clean-start pre-election ordering;
- exact post-attach identity as a required proof component;
- mandatory pre-mutation containment;
- separate cleanup ownership and lower per-handle retention;
- the reusable bootstrap-exit lifecycle concept;
- recognition that B requires pre-mutation staging.

It only appears to close:

- complete ownership suppression, because inherited publishers and RG0 remain;
- coverage, because the proof is before the real final arm boundary;
- backend quarantine, because captured API aliases survive;
- empty transitions and B, because no staged transaction is defined;
- HA peer takeover, because yield has no pre-proof heartbeat path and is deferred.

Calling this a multi-PR architecture is honest; calling each proposed PR independently correct is not. A foundational arm-state/revocable-runtime change, atomic HA hold-plus-yield activation, and staged surface activation are all architecture work. The design is viable, so this is not `PLAN-KILL`, but r5 is not an executable security contract yet.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
311,423
No. r5 has the right local-election primitive, but it overstates what the shipped #1930 mechanism proves and still leaves several security-critical contracts undefined.

The narrow win is real: installing an unconditional hold before `UpdateConfig` prevents a fresh clustered process from becoming Primary during manager initialization. Both election paths honor that hold ([election.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/election.go:44)). That resolves round 3’s specific “already Primary before ARM” ordering failure for a clean start.

### 1. The generalized hold is neither sufficient nor safely reused

The existing flag cannot simply be renamed or given a new clear condition.

- #1930 holds until a durable kernel-promotion marker confirms a broader verification gate. Clearing it on XDP coverage would prematurely release a kernel candidate ([kernel_selfrecover.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/kernel_selfrecover.go:96)).
- Existing rejoin/reset paths clear that flag without an arm proof ([failover.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/failover.go:170)). Reusing it would let an operator reset bypass #5275 containment.
- The required model is composed reasons: `effectiveHold = dataplaneUnproven || kernelTrialUnpromoted`, with each owner authorized to clear only its reason.

It also blocks only new election transitions. It does not withdraw state inherited from a former-Primary daemon restart:

- direct VIPs and stable link-locals are removed by reconciliation;
- startup goodbye RA is also reconciliation-driven ([daemon_ha.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:891));
- VRRP removes stale VIPs only after its instances run;
- Kea requires an authoritative `Apply(nil)`;
- FRR can continue advertising persisted state.

The nft barrier prevents transit, not traffic attraction or dual service ownership. A held startup needs a verified withdrawal-only scrub before it advertises yield.

RG0 is also still unsafe. A held RG0 is created directly as Secondary, producing no demotion event. The store defaults writable, while only `applyRG0OwnershipTransition` makes it read-only ([daemon_ha.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha.go:417)). r5 explicitly permits persistence while held, so both nodes can accept divergent commits.

Standalone composition is missing altogether. The shipped hold returns when `d.cluster == nil` ([kernel_selfrecover.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/kernel_selfrecover.go:58)). r5 needs a daemon-owned `pending/armed/quarantined` state installed outside the cluster conditional; the cluster election hold should merely consume that state.

### 2. The arm proof and containment are not sound yet

Post-attach XDP identity is necessary, but r5 proves it at the wrong boundary and defines “Armed” too weakly.

`applyDataplaneAndHACore` continues after the first `ApplyConfig` with networkd changes, RETH MAC/link cycling, VIP recovery, and AF_XDP rebind/reapply. In one RETH path, the first apply deliberately publishes a workerless `DeferWorkers` snapshot; only a later reapply starts workers, and its failure is currently reduced to retry debt ([daemon_apply_dataplane.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_dataplane.go:467)). `Compile` can also return success while snapshot publication remains deferred ([manager_compile.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/userspace/manager_compile.go:257)).

Therefore an expected shim program can be attached while the candidate helper generation and XSK bindings are not operational. The proof must occur after the final link-cycle/reapply mutation and require:

- exact candidate digest and successfully reconciled helper generation;
- exact expected registered/armed/ready bindings;
- strict program instance identity on every mapped attach point;
- readback failure meaning unarmed;
- the second reapply/rebind returning proof or failure, not merely recording debt.

The mandatory barrier is directionally correct, but `inet` FORWARD cannot “rule out bridge/flowtable bypass” through priority. This repository creates Linux bridge domains ([compiler_iface.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:975)); bridged L2 traffic need not traverse the inet forward hook, and already-offloaded flowtable traffic can bypass it. The contract needs a bridge-family barrier or proved-down bridge ports, plus explicit flowtable disable/flush/readback.

Release is backwards too. `ClearKernelUpgradeHold` immediately re-elects ([kernel_selfrecover.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/kernel_selfrecover.go:81)). r5 clears it before verified barrier removal. Required ordering is final mutation → complete arm proof → forwarding enable/readback → barrier removal/readback → clear the election hold as the final ownership-enabling action.

The quarantine only appears to close round 3 §5. gRPC, REST, and CLI capture backend aliases at construction rather than dynamically dereferencing `d.dp` ([daemon_run_servers.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run_servers.go:88), [daemon_run.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_run.go:597)). This is directly exploitable on bootstrap exit: management already holds the backend when the later arm fails. Setting `d.dp=nil` does not revoke those aliases. A shared revocable facade is required.

The lower per-handle teardown retention is a genuine improvement and should remain.

### 3. PR2 cannot safely be deferred as written

The supposed #1930 “peer-non-preempt property” does not exist. Heartbeats still advertise the held node’s normal priority and weight ([heartbeat_manager.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:251)). A lower-priority healthy peer can demote on seeing the higher-priority held node, while the held node refuses promotion: both-secondary. The earlier coordinated drain state is in-memory and lost across reboot.

An advertised-only weight-zero override is the credible mixed-version design:

- weight is already in the fixed five-byte per-RG record ([heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat.go:93));
- legacy peers already promote when peer weight is zero;
- stored monitor weight can remain unchanged;
- existing heartbeat authentication covers the override.

The unspecified “weight-zero / cannot-own bit” choice is not plan-ready. An old peer will ignore a new bit unless weight zero is also present.

There is also a direct lifecycle contradiction: r5 says the held node heartbeats its yield posture, but places `startClusterComms` inside post-proof machinery. Heartbeat starts only inside that function, which also bundles watchdog, session/config sync, and dataplane consumers ([daemon_ha_sync.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_ha_sync.go:687)). A safe pre-proof heartbeat-only lifecycle must be separated.

Accordingly:

- PR1 is safe only if explicitly inert whenever cluster configuration exists.
- If PR1 activates the generalized hold in HA, yield must land atomically with it.
- PR2 is not a small optional wire follow-up; it includes lifecycle separation and fixes a latent #1930 problem.

### 4. B quarantine and empty transitions are still assertions

“Do not bring up/address B until attach is proven” conflicts with current ordering: VLAN creation, link-up, and address reconciliation occur before deferred XDP attachment ([compiler_iface.go](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dataplane/compiler_iface.go:521)).

The plan needs an explicit staged transaction:

1. Compute the candidate surface diff before mutation.
2. Quarantine B, including a pre-existing/up B.
3. Create it down and unaddressed only as needed to obtain an ifindex.
4. Attach and prove program plus helper-generation/binding coverage.
5. Only then publish address, networkd, VRF, FRR, and service changes.
6. On failure, abort all candidate downstream publication while retaining A’s old generation.

Committed-empty→first and remove-all→add are not handled by the current one-way `startTakeoverMachinery`. Once the vacuous empty proof releases the hold and starts ownership, merely saying the first add “re-enters” the hold is reactive. These cases require the same pre-mutation transaction as B, making them dependent on PR3 contrary to r5’s PR1 claims.

The apply gate likewise needs three explicit routes: `armPending` permits only the barrier-protected arm transaction; `armFailed` permits persistence/validation only; `armed` permits the normal pipeline. “While held, publish nothing” otherwise blocks the very first arm or permits unspecified pre-proof mutations.

### 5. Round-3 closure and sizing

r5 genuinely improves:

- clean-start pre-election ordering;
- exact post-attach identity as a required proof component;
- mandatory pre-mutation containment;
- separate cleanup ownership and lower per-handle retention;
- the reusable bootstrap-exit lifecycle concept;
- recognition that B requires pre-mutation staging.

It only appears to close:

- complete ownership suppression, because inherited publishers and RG0 remain;
- coverage, because the proof is before the real final arm boundary;
- backend quarantine, because captured API aliases survive;
- empty transitions and B, because no staged transaction is defined;
- HA peer takeover, because yield has no pre-proof heartbeat path and is deferred.

Calling this a multi-PR architecture is honest; calling each proposed PR independently correct is not. A foundational arm-state/revocable-runtime change, atomic HA hold-plus-yield activation, and staged surface activation are all architecture work. The design is viable, so this is not `PLAN-KILL`, but r5 is not an executable security contract yet.

VERDICT: PLAN-NEEDS-MAJOR
