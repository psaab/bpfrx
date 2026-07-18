# Hostile adversarial plan review — round 1

The plan is not ready. Its recommended Path C host floor plus B1 map rollback does not implement the atomicity invariant it states: it can expose candidate maps while the old helper is live, roll maps backward after the helper actually committed, and leave new host state with old maps/helper and ctrl still enabled. The proposed pre-actuation snapshot build also cannot produce the live VLAN ifindexes, addresses, MTU, or connected routes that the helper snapshot requires.

## Axis 1 — Path C floor + B1 versus host rollback versus pure validation

### Finding 1.1 — the recommendation recreates the generation skew it claims to close

Today `CompileUserspaceShim` completes `CompileConfig`, host mutation, and XDP attachment before `Manager.Compile` builds/publishes the helper snapshot (`pkg/dataplane/loader.go:173-208`; `pkg/dataplane/userspace/manager_compile.go:185-211,300-334`). B1 restores only classifier maps and explicitly leaves ctrl at its prior value, while the recommendation defers the host journal (`docs/research/4960-apply-txn/plan.md:199-212,438-446`). If host actuation succeeds and `apply_snapshot` then rejects, a successful B1 produces **new host + old maps/helper + prior ctrl**, which is exactly the cross-generation condition #4960 is about. The plan's §4.4 justification assumes “host-first with host rollback,” but the final recommendation removes that rollback.

B1 is not atomic even before considering host state. `syncUserspaceClassifierMapsLocked` updates ingress, local, and interface-NAT maps sequentially, and its fail-closed wrapper disables ctrl only when a map operation errors; a successful candidate sync leaves ctrl enabled throughout the helper round trip (`pkg/dataplane/userspace/maps_sync.go:247-282`). For a large snapshot that round trip can have a 67-second deadline (`pkg/dataplane/userspace/process_control.go:42-56,108-123`). Populate-before-clear prevents some per-map holes; it is not an atomic swap across three maps and cannot erase the period in which packets saw candidate maps with the old helper.

### Finding 1.2 — neither the bounded journal nor pure validate-first satisfies the stated invariant

The proposed journal is not “full host rollback.” It omits RX-VLAN offload mutation (`pkg/dataplane/compiler.go:1387-1449`), speed/duplex (`pkg/dataplane/compiler.go:1507-1536`), txqueuelen/rings/RPS/RFS/XPS/RSS (`pkg/dataplane/compiler.go:1585-1653`), XDP/TC link state (`pkg/dataplane/loader.go:211-253`; `pkg/dataplane/userspace/manager_compile.go:522-545`), stale-bond deletion (`pkg/dataplane/compiler_iface.go:1128-1140`), and the FIB-generation map (`pkg/dataplane/compiler.go:298-304`; `pkg/dataplane/maps_fabric.go:78-95`). A journal can restore eventual state; it cannot make immediate netlink writes invisible to packets.

Pure validation is still valuable, but cannot be the only protection. The final snapshot must be rebuilt from post-actuation live state, and that build deliberately returns an error on a transient kernel `RuleList` failure (`pkg/dataplane/userspace/routes.go:15-33`). Runtime `LinkAdd`, attach, map, and control-socket operations also remain fallible after all config-shaped checks pass (`pkg/dataplane/compiler_iface.go:105-154`; `pkg/dataplane/loader.go:211-253`; `pkg/dataplane/userspace/manager_compile.go:300-334`).

### Independent judgment for OQ-1

#4960 does **not** require a host journal if the accepted contract is an explicit fail-closed outage. It does require a fence established before the first observable mutation, new links kept down or shim-protected while staged, obsolete hooks retained until commit, and the fence retained on every unproven outcome; `ensureVLANSubInterface` currently brings a new child up before the later shim attachment, so merely writing ctrl=0 on old attachments is insufficient (`pkg/dataplane/compiler_iface.go:123-154`; `pkg/dataplane/loader.go:183-198`). If the product promise is “previous-good forwarding remains live,” then comprehensive host **and attachment** rollback/staging is required; the bounded journal in this plan does not meet that promise. Pure validate-first alone is insufficient.

## Axis 2 — OQ-2: reused `!samePlanRefresh` path

### Finding 2.1 — the plan's process-lifecycle premise is false, but this direct leg is initially fail-closed

`ensureProcessLocked` reuses a healthy helper whenever the userspace process config is equal and ping succeeds; binding-plan identity is not part of `configEqual` (`pkg/dataplane/userspace/process.go:18-33,269-277`). `stopLocked` is called only for an unhealthy or differently configured process and disables ctrl before teardown (`pkg/dataplane/userspace/process.go:28-33,197-267`). Therefore `!samePlanRefresh` is not a “full-restart path,” and an `apply_snapshot` error does not stop either a reused or newly started process (`pkg/dataplane/userspace/manager_compile.go:304-333`).

The sharp answer is nevertheless **no** for the direct bootstrap/reuse sequence. `programBootstrapMapsLocked` first writes `userspace_ctrl.Enabled=0`, then clears bindings, and only then syncs candidate classifiers (`pkg/dataplane/userspace/maps_sync.go:121-195`). A subsequent reject leaves candidate bootstrap/maps behind a disabled ctrl, not enabled transit. On the next status pass, unchanged old `m.lastSnapshot` is used to re-sync classifier maps before ctrl can be written enabled; a map failure keeps ctrl disabled (`pkg/dataplane/userspace/process_status.go:143-165`; `pkg/dataplane/userspace/maps_sync.go:729-797`). Exact local-map restoration is still subject to the OQ-6 defect below.

### Independent judgment for OQ-2

The helper can be reused, but the direct `!samePlanRefresh` reject is a fail-closed outage, not a second enabled-map fail-open. The plan must delete the false claims that this branch always restarts and that a reject stops the process, and it must give the already-fenced branch recovery and daemon error semantics. Scope is still incomplete for the separate `pendingXSKStartup` publisher described in Finding 7.2.

## Axis 3 — OQ-3: host-first versus helper-first

### Finding 3.1 — publish-last is preferable, but only behind a real staging fence

Helper-first commits the new logical dataplane before host actuation has run. If host actuation then fails, the helper has the new snapshot and the host is old/partial; a literal old-generation compensating snapshot is rejected by the helper's monotonicity gate (`userspace-dp/src/server/handlers/snapshot.rs:83-105`). Recovery would need a newly generated old-content snapshot, coherent map restoration, and a second publish whose own outcome can be ambiguous.

Host-first keeps helper acceptance as the final logical commit point and is also forced by live interface materialization: a new VLAN ifindex is created by `ensureVLANSubInterface`, and snapshot construction later reads that live child (`pkg/dataplane/compiler_iface.go:350-413`; `pkg/dataplane/userspace/interfaces.go:239-275,430-449`). But raw host-first is not safe: host changes are visible while the old helper is forwarding, and B1 may leave ctrl enabled after failure (`pkg/dataplane/userspace/manager_compile.go:179-185,300-334`).

### Independent judgment for OQ-3

Choose **fence/stage first, host actuation second, final snapshot/maps third, helper publish last, verified re-enable last of all**. New ingress surfaces must remain down or receive the ctrl-disabled shim before becoming live, and obsolete XDP hooks must not be removed until commit. This minimizes the worst security blast radius: any host or publish failure leaves transit fenced, whereas helper-first requires a fallible compensating helper transaction after a host failure. The plan's “host topology is more expensive to churn” rationale is not a correctness argument.

## Axis 4 — OQ-4: peer synchronization after rollback or fencing

### Finding 4.1 — “fenced/rolled-back” is not one outcome class

A verified rollback that restored host/maps and proved the old helper still armed should still push the committed config. That follows #4034: the store is already committed, and ordinary nonfatal apply errors still sync so the peer does not remain on stale config (`pkg/daemon/daemon_apply.go:369-376,384-431`). A genuinely fenced/disarmed node should suppress the push to avoid propagating a deterministic outage to the standby, matching the required-protocol-gate policy (`pkg/daemon/daemon_apply.go:434-455`).

There is no magic answer that avoids all divergence. Suppression leaves the local store committed to the new config while the peer store stays old; propagation can leave the peer successfully enforcing new while the local node is restored/fenced, or can fence both nodes if the fault is deterministic. The plan must state that tradeoff and identify the retry/reverse-sync owner.

### Finding 4.2 — the daemon cannot remain unchanged

An ordinary userspace publish error is not an abort sentinel: `applyDataplaneAndHACore` records it and continues the new-config pipeline (`pkg/daemon/daemon_apply.go:1220-1246`), while `applyErrSkipsPeerSync` recognizes only required-protocol gates and context termination (`pkg/daemon/daemon_apply.go:447-455,2602-2624`). The daemon then clears sessions and pushes the peer under the assumption that the new dataplane is armed (`pkg/daemon/daemon_apply.go:399-431`).

The needed classification has two independent dimensions: (1) whether the local new-config tail may continue, and (2) whether the peer should receive the committed config. A restored-but-old dataplane should stop new-config host tail work yet may sync the peer; a fenced dataplane should stop the tail and suppress the peer. The present `compileErrorMustAbortApply`/`applyErrSkipsPeerSync` coupling cannot express that, so the “daemon surface unchanged” claim is architecturally wrong.

### Independent judgment for OQ-4

Sync only a **verified restored-and-armed** outcome; suppress a **fenced, post-teardown, or outcome-unknown** one. This is a principled state-based rule, but its store/divergence cost is unavoidable without distributed prepare/commit and must be explicit in the plan.

## Axis 5 — OQ-6: whether old-snapshot re-sync is a rollback

### Finding 5.1 — the proposed restore can synthesize a state that never existed

`buildDesiredLocalAddressSets(oldSnap)` starts with old snapshot-derived keys and then unions addresses enumerated from the kernel **at rollback time** (`pkg/dataplane/userspace/maps_sync.go:1080-1121`). Host-first compilation has already removed stale host addresses and added candidate addresses (`pkg/dataplane/compiler_iface.go:184-246,365-399,572-610`). The resulting “restore” can therefore be `old-config addresses ∪ candidate/current-kernel addresses`, not the pre-apply map. VRRP changes between the two calls create the same problem, and the separate v4/v6 dumps are not a historical atomic view (`pkg/dataplane/userspace/maps_sync.go:1090-1121`).

#3924 makes the mismatch more definite under partial enumeration. Adds are applied first; if either family dump is incomplete, stale-key pruning is skipped and the function returns nil (`pkg/dataplane/userspace/maps_sync.go:986-1013`). Candidate keys can remain while B1 declares rollback successful and leaves ctrl enabled. The guard is correct for local-address availability, but it is incompatible with claiming an exact transaction rollback.

### Finding 5.2 — the wrapper also hides a non-BPF side effect

`syncInterfaceNATAddressMapsLocked` installs nftables RST-suppression rules and mutates `lastRST*` tracking (`pkg/dataplane/userspace/maps_sync.go:1188-1212`). Those rules suppress kernel RSTs for userspace-owned NAT addresses (`pkg/nftables/rst_suppress.go:26-56`). Installation failure is warning-only and the sync still returns nil, so B1 can report a successful restore while nftables remains on the candidate set (`pkg/dataplane/userspace/maps_sync.go:1203-1213`). The rollback anchor and invariant mention only classifier maps and `lastIngressIfaces`; they omit this actual kernel state.

### Independent judgment for OQ-6

No: re-running the sync is a **semantic reconciliation against old config plus current kernel state**, not restoration of previous-good. An exact map preimage, a policy for concurrent kernel-owned VIP changes, authoritative-enumeration status, host-state ordering, and nftables state are required before ctrl may be re-enabled. If any of those are unknown, remain fenced.

## Axis 6 — feasibility of the `planZones`/`actuateZoneHostState` split

### Finding 6.1 — the planned cut breaks the actual userspace snapshot dependency

The plan notices that VLAN map entries need the created ifindex, but misses the load-bearing consumer in the Rust snapshot. `ensureVLANSubInterface` creates the child and returns its ifindex, which also feeds `pendingXDP`/generic attachment state (`pkg/dataplane/compiler_iface.go:350-413,623-625`). Later, `buildInterfaceSnapshots` independently queries the live child for ifindex, MTU, MAC, and addresses (`pkg/dataplane/userspace/interfaces.go:239-275,430-449`). `snapshotBindingPlanKey` then includes the ifindex and parent ifindex (`pkg/dataplane/userspace/maps_sync.go:1596-1628`). A snapshot built before ordinary VLAN creation therefore carries an unresolved child and the wrong binding plan.

Address/route materialization is also ordered after actuation for a reason. Snapshot construction unions live addresses with configured addresses rather than subtracting stale live rows (`pkg/dataplane/userspace/interfaces.go:482-513`), and connected routes are derived from those snapshot addresses (`pkg/dataplane/userspace/routes.go:191-205`). Building before address reconciliation can retain an old live address and connected route that actuation subsequently deletes; it also captures the pre-change MTU.

### Finding 6.2 — `host.err` does not exist for much of the proposed actuator

The current host helpers often warn and continue: existing-VLAN `LinkSetUp` is unchecked, VLAN-create failure is skipped, and address reconciliation returns no error while swallowing lookup/parse/list/delete/add failures (`pkg/dataplane/compiler_iface.go:113-154,187-247,342-357`). MTU/admin failures are warnings (`pkg/dataplane/compiler_iface.go:385-397,498-543,598-609`), ethtool/buffer tuning returns no error (`pkg/dataplane/compiler.go:1511-1536,1589-1653`), and unmanaged/bond cleanup does not propagate failures (`pkg/dataplane/compiler_iface.go:1128-1165`). Path C cannot “fence on any host-actuation failure” until the plan defines critical versus best-effort operations and changes critical contracts to return partial-operation results.

### Finding 6.3 — the 925-line host-op IR is not the only credible design

For the userspace shim, all legacy `DataPlane` map methods are no-ops (`pkg/dataplane/loader.go:352-454`). Phases 3-11 can therefore be run as a config-validation pass before host work, while a final live-state snapshot is built only after the existing host-heavy zone pass. A smaller design should be evaluated: validate all cross-references and config-only phases, build a validation-only snapshot, fence/stage, run the existing zone host pass late, then build the final live snapshot and publish. The final build remains fallible, so this reduces deterministic failure exposure but does not replace the fence.

The proposed split is **not realistic as scoped**. It needs either symbolic link identities with an explicit post-actuation materialization pass, or the smaller two-pass userspace flow above. It also changes tolerated behavior—missing interfaces and malformed addresses currently warn/skip rather than hard-fail—so “unchanged error semantics” is false unless that compatibility decision is made explicitly (`pkg/dataplane/compiler_iface.go:197-203,342-357`).

## Axis 7 — additional missing invariants, failure modes, and wrong claims

### Finding 7.1 — B1 treats an ambiguous commit as a definite reject

Go writes the serialized request and only then waits for a response (`pkg/dataplane/userspace/process_control.go:103-123`). The code explicitly documents a timeout after the helper has applied the snapshot live (`pkg/dataplane/userspace/process_control.go:47-50,108-113`). Dial/write/read/decode/timeout failures and explicit `OK:false` all collapse into an ordinary `error`, and `requestLocked` preserves no outcome class (`pkg/dataplane/userspace/process_control.go:103-143,187-195`). Rolling maps to old after an ACK-loss can therefore create **old maps + new helper**, the inverse of #4959.

Even an explicit NACK does not prove the old dataplane is live. The Rust #4952 post-teardown worker-spawn branches restore old snapshot identity but explicitly report the dataplane down (`userspace-dp/src/server/handlers/snapshot.rs:183-223,341-369`). Rust attaches status to the response after handler execution, but Go discards the response when `OK=false` (`userspace-dp/src/server/handlers/mod.rs:257-264`; `pkg/dataplane/userspace/process_control.go:137-143`). B1 may therefore restore maps and leave ctrl enabled while no workers remain.

The design needs at least four typed outcomes: definite pre-teardown rejection with old helper proven live; unknown/ACK-lost; post-teardown rejection/down; and accepted snapshot followed by a post-commit reconcile error. Unknown and post-teardown outcomes must stay fenced until generation/status reconciliation proves a coherent state.

### Finding 7.2 — the asynchronous XSK-startup publisher is an uncovered #4959-equivalent path

`pendingXSKStartup` is reachable with a running, previously published helper whose liveness is neither proven nor failed (`pkg/dataplane/userspace/manager_compile.go:230-257`). Ctrl can be enabled for an XSK liveness probe while `xskLivenessProven` remains false (`pkg/dataplane/userspace/maps_sync.go:470-495`). The branch syncs candidate classifiers, advances `m.lastSnapshot`, returns success, and does not publish (`pkg/dataplane/userspace/manager_compile.go:257-298`).

The status loop then calls `applyHelperStatusLocked` first; that method re-syncs maps from the new `m.lastSnapshot` and may enable ctrl. Only afterward does the loop call `syncSnapshotLocked`, whose `apply_snapshot` error has no rollback or fence (`pkg/dataplane/userspace/process_status.go:101-104,143-165`; `pkg/dataplane/userspace/maps_sync.go:779-797`). A wrapper around the synchronous branch at `manager_compile.go:300-334` cannot cover this separate publication owner. It needs persistent transaction/debt state shared with `syncSnapshotLocked`.

### Finding 7.3 — XDP/TC attachment state is outside the transaction and outside the fence

After building the candidate snapshot but before helper publication, `syncInterfaceAttachments` detaches XDP/TC links excluded by the candidate and only logs detach failures (`pkg/dataplane/userspace/manager_compile.go:211,522-545`). `DetachXDP` closes the link and removes it from the manager (`pkg/dataplane/loader.go:637-666`). If publication rejects, the old helper may remain but an old ingress hook is already gone; ctrl=0 cannot govern an interface on which its shim is detached. Whether the resulting kernel path is exploitable is deployment-dependent, but loss of the intended userspace enforcement hook is certain. New attachments can likewise be left partial if a later generic attach fails (`pkg/dataplane/loader.go:211-253`).

The transaction resource set must include attachment additions/removals and pin state. The safe partial order is add/stage under a fence, publish, then remove obsolete hooks; or journal and verify their restoration.

### Finding 7.4 — `Manager` is not the sole host orchestrator

The daemon performs VRF, xfrmi/bond/tunnel, and fabric-IPVLAN reconciliation before `d.dp.ApplyConfig` (`pkg/daemon/daemon_apply.go:916-959`). On an ordinary dataplane apply error it continues new-config RETH MAC/VIP and later reconcile work (`pkg/daemon/daemon_apply.go:1220-1246,1330-1469`). A Manager-local host journal cannot roll those owners back, so the plan's “single apply orchestrator in `Manager.Compile`” is false for host topology.

The Manager also changes HA control state before helper acceptance: `m.clusterHA` and `m.haGroups` are set from the candidate before publish (`pkg/dataplane/userspace/manager_compile.go:226-227`; `pkg/dataplane/userspace/manager_ha.go:277-300`), and the status loop branches on `m.clusterHA` (`pkg/dataplane/userspace/process_status.go:180-217`). These fields are absent from the proposed rollback anchor.

### Finding 7.5 — successful publication is followed by fallible work

After `apply_snapshot` succeeds, Go advances `lastSnapshot`, published/applied identity, and the content hash, then performs fallible status, HA, and desired-forwarding synchronization (`pkg/dataplane/userspace/manager_compile.go:332-392`). Such an error is post-commit and must not trigger old-map or old-host rollback. The plan's single success/failure transaction model has no post-commit outcome and no recovery owner for it.

### Finding 7.6 — a ctrl fence is invisible to HA takeover readiness

`failClosedUserspaceCtrlLocked` changes the ctrl map and local ctrl bookkeeping, not helper `ForwardingArmed` (`pkg/dataplane/userspace/maps_sync.go:230-244`). `takeoverReadyLocked` checks helper status, mode, liveness, session mirror, and event stream, but does not inspect the ctrl map or `ctrlWasEnabled` (`pkg/dataplane/userspace/manager_ha.go:401-447`). The predicate can therefore call a ctrl-fenced node ready. Whether a concrete cluster transition reaches this state is a reachability hypothesis requiring an HA test, but the predicate's blindness is definite.

### Finding 7.7 — locking, “zero mutation,” and test claims are wrong

Host compile and attachment pruning currently run before `m.mu` is acquired (`pkg/dataplane/userspace/manager_compile.go:185-213`), and direct `userspace.Manager.ApplyConfig` has no daemon `applySem` (`pkg/dataplane/userspace/manager.go:318-327`). Extending `m.mu` over host actuation is a new design requiring lock/liveness analysis, not a preserved invariant. XDP pins are deleted before validation, and `CompileUserspaceShim` performs TC/map-pin cleanup before `CompileConfig`, contradicting a literal “zero mutation before planning succeeds” claim (`pkg/dataplane/userspace/manager_compile.go:162-175`; `pkg/dataplane/loader.go:173-183,267-334`).

The proposed byte-identical actuation-order golden test has no stable baseline because `compileZones` iterates unsorted zone and interface maps (`pkg/dataplane/compiler_iface.go:278,644,931`). Tests need deterministic traversal or per-interface partial-order assertions. Direct package-level netlink calls also mean the proposed mock-netlink failure tests require an injected actuator seam or a network namespace; neither is designed (`pkg/dataplane/compiler_iface.go:105-247,350-610,1103-1165`).

### Finding 7.8 — #5680 is not a ctrl-fence precedent

The #5680 hybrid guard rejects before `apply_snapshot` and leaves the previous snapshot identity untouched; it does not disable ctrl (`pkg/dataplane/userspace/manager_overlay.go:140-175,208-229`). It is a refuse-before-publish precedent, not part of a “#2138/#5680 fence doctrine.” Conflating identity retention with dataplane fencing obscures the exact behavior this plan must specify.

## Independent answers to all seven open questions

1. **Host rollback scope:** a journal is optional only under an honest fail-closed contract with pre-mutation fencing plus down-or-shim-protected staging for new links and commit-gated removal of old hooks. Pure validation cannot cover final live snapshot, netlink, attach, map, or socket failures (`pkg/dataplane/userspace/routes.go:15-33`; `pkg/dataplane/loader.go:211-253`). Previous-good availability requires comprehensive host/attachment rollback or staging, not the proposed bounded journal.

2. **Full-restart path fail-open:** the helper can be reused, contrary to the plan, but bootstrap writes ctrl=0 before candidate maps, so the direct reused reject is initially fail-closed (`pkg/dataplane/userspace/process.go:18-33`; `pkg/dataplane/userspace/maps_sync.go:121-195`). The answer is no for that leg; the pending-XSK asynchronous leg is a separate uncovered yes-risk (`pkg/dataplane/userspace/manager_compile.go:257-298`; `pkg/dataplane/userspace/process_status.go:101-104,143-165`).

3. **Host-first versus helper-first:** use publish-last host-first only inside a fence/staging protocol. Helper-first makes host failure require a compensating higher-generation helper publish because rollback generations are rejected (`userspace-dp/src/server/handlers/snapshot.rs:83-105`); raw host-first still exposes mixed live state (`pkg/dataplane/userspace/manager_compile.go:185-211,300-334`).

4. **Peer sync:** push only after verified restoration with the old dataplane armed; suppress when fenced, down, or outcome-unknown. The store was already promoted, so either choice has a documented divergence cost (`pkg/daemon/daemon_apply.go:369-376,399-455`). Local-pipeline abort and peer propagation must become separate dispositions.

5. **`BumpFIBGeneration`:** do not fence merely because the bump failed. The map implementation already logs WARN and returns an error (`pkg/dataplane/maps_fabric.go:78-95`), while a successful full snapshot advances config generation and the Rust flow cache invalidates on either config or FIB generation mismatch (`pkg/dataplane/userspace/manager_compile.go:199`; `userspace-dp/src/afxdp/flow_cache.rs:983-991`). Record/metric/retry it, or move a chosen fatal check before host actuation; surfacing it as a late fatal error would create another #4960 failure point without a demonstrated security benefit.

6. **Rollback re-sync correctness:** no. It recomputes old config plus current kernel addresses, and #3924 can return success without pruning candidate keys (`pkg/dataplane/userspace/maps_sync.go:986-1013,1080-1121`). It must not authorize ctrl re-enable unless host state, enumeration authority, map contents, and nft RST state are all proven coherent.

7. **Is atomicity the right frame?:** atomicity is a valid target but the proposed rollback is not atomic at the packet-observable boundary because ctrl stays enabled during sequential map mutation and publication (`pkg/dataplane/userspace/maps_sync.go:247-282`; `pkg/dataplane/userspace/process_control.go:108-123`). A corrected fence-first/staged Path C is simpler and more honest than the partial journal if outage is acceptable; pure validate-first or fence-only-after-error is not sufficient.

## Minimum redesign required before round 2

1. Define a state machine with explicit phases and commit point: config-only validation; pre-mutation fence/staging; host and attachment actuation; post-actuation live snapshot materialization; candidate map programming; typed helper publication; verification; commit-gated obsolete-hook removal; then ctrl re-enable. The current order and live dependencies are visible at `pkg/dataplane/userspace/manager_compile.go:185-334` and `pkg/dataplane/userspace/interfaces.go:239-275,430-449`.
2. Expand the transaction resource set to host links/addresses/admin state, XDP/TC links and pins, all classifier maps, nft RST suppression, ctrl state, HA manager state, and snapshot identity. Current mutation sites prove that maps/snapshot alone are incomplete (`pkg/dataplane/userspace/maps_sync.go:945-1213`; `pkg/dataplane/userspace/manager_compile.go:211,226-227,336-392`).
3. Preserve publication outcomes instead of flattening them: definite pre-send failure, definite old-state NACK, ambiguous post-write failure, post-teardown/down NACK, accepted, and accepted-with-post-commit-error (`pkg/dataplane/userspace/process_control.go:80-143`; `userspace-dp/src/server/handlers/snapshot.rs:183-223,341-369`).
4. Design two daemon dispositions—stop/continue the local tail and suppress/push peer sync—and make HA readiness reject a ctrl-fenced node (`pkg/daemon/daemon_apply.go:399-455,1220-1246`; `pkg/dataplane/userspace/manager_ha.go:401-447`).
5. Add tests for ACK loss after helper commit, post-teardown NACK, pending-XSK deferred reject, live VRRP churn, #3924 incomplete rollback, nft restore failure, new-VLAN live materialization, XDP detach/partial attach, reused-process rejection, post-commit status failure, daemon tail/peer disposition, and HA takeover readiness. The current test list covers none of these controlling distinctions.

VERDICT: PLAN-NEEDS-MAJOR
The recommended Path C+B1 architecture can expose or manufacture mixed generations, and its snapshot-before-actuation split cannot produce correct live interface metadata. The plan is salvageable only after a major redesign around pre-mutation fencing or real staging, outcome-typed publication, complete resource/daemon/HA boundaries, and post-actuation snapshot materialization.
