PLAN NO


Reviewed at `842904ac2`. Part A remains converged, but concrete Part-B kill traces remain.

1. **BLOCKER — Persistent peer INSTALL can be interpreted under the wrong configuration epoch.**

   The fold requires the standby to derive `PersistentSourceKey` from its current rule’s persistence mode and permit, without carrying those inputs on the wire ([plan.md:954](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:954), [source.rs:145](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:145)). But config receipt only queues asynchronous application ([sync_conn_read.go:298](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:298)), while a session INSTALL is processed immediately ([sync_conn_read.go:96](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:96)). `configEpochStale` rejects only epochs below the high-water mark; a future `g2` INSTALL can therefore pass while `g1` remains locally applied ([sync_conn_gen.go:398](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:398)).

   Concrete trace: C1 uses `target-host-port`; C2 uses `any-remote-host`. Under C2, F1/F2 with the same internal tuple and different remotes share P ([tests_pool.rs:2536](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/tests_pool.rs:2536)). B receives their `g2` INSTALLs before applying C2 and derives distinct C1 keys. F1 creates P; F2 is rejected as a different persistent lease. The later C2 apply reuses the allocator because its key omits permit ([source.rs:327](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:327), [source.rs:723](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:723)). Crash takeover is not gated on config application ([manager.go:321](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/manager.go:321)); F2 is absent and re-resolves under C2, where P belongs to the incorrectly keyed F1 lease, so F2 obtains Q. That is a prohibited mid-flow SNAT port swap. INSTALL processing must wait for the exact applied epoch, retain version-addressable NAT policy, or carry authoritative lease derivation inputs.

2. **BLOCKER — The allocator cutover fence does not cover every ownership-creating path.**

   The fold specifically freezes `allocate_translation` ([plan.md:1173](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1173)), but workers can claim ownership through independent paths:

   - deterministic PAT: [source.rs:1431](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:1431)
   - deterministic NAT64: [source.rs:995](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:995)
   - address-only: [source.rs:1523](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:1523)
   - persistent address-only: [source.rs:1497](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:1497)

   B is constructed while A remains worker-visible ([snapshot_refresh.rs:212](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:212)); workers retain A until their loop refresh ([loop_body/mod.rs:467](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:467)). After the migration snapshot, an old worker can therefore claim P through one of these paths only in A; B is then published without P, and a B worker can issue P independently. The dual-record text also defines retain creation but not which B-side record is released when A later releases its holder ([plan.md:1220](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1220)). The cutover flag/bridge must cover every allocator ownership mutation, including release, or the design must require quiescence.

3. **HIGH — Ordinary persistent address-only peer INSTALLs still use the wrong reservation model.**

   The new ordinary-install rule universally calls for an atomic persistent lease plus “port-bit reservation” ([plan.md:960](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:960)). Persistent address-only allocation does not consume a port bit: it uses `address_only_owners` and a separate lease object ([allocator.rs:1894](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1894)). The bitmap normally begins at port 1024 ([source.rs:675](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:675)), and exact bitmap reservation rejects out-of-range ports ([allocator.rs:537](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:537)).

   Thus a valid address-only persistent flow preserving source port 80 can be rejected on standby. After failover, its missing copy is reconstructed through the address allocator and can receive another public address, swapping the live public tuple. The restore section is routed by allocation kind, but the ordinary peer-INSTALL contract needs the same explicit dispatch.

4. **HIGH — The mixed-version DELETE contract remains internally contradictory.**

   The revised §9 matrix correctly suppresses new→legacy identity-dependent deletes ([plan.md:2451](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2451)), but §5.2 still says a mixed pair keeps today’s unconditional generation-based delete on the old peer ([plan.md:1543](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1543)).

   Under that surviving clause, A’s stale E1 Close reaches legacy B. B accepts an equal/fresh generation ([sync_conn_gen.go:263](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:263)) and key-deletes current E2 plus its companions ([sync_conn_gen.go:493](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:493)). This is directly an HA-propagated kill. The §5.2 sentence must be removed or narrowed to the §9 old→new, non-locally-authoritative case.

5. **LOW — Selector inventories are repaired, but one Phase-1 statement is stale.**

   The normative wire schema, Go sidecar, atomic snapshot and node-local shared-map inventory now consistently include both selectors ([plan.md:2070](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2070), [plan.md:2148](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2148)). Test (f) no longer names the superseded content-version field. However, [plan.md:2155](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2155) says all listed shared-map fields are never wire-carried in Phase 1, contradicting the normative identity/selector tail. This is editorial, not verdict-driving.

**Round-30 dispositions**

1. Allocator compatibility/cutover: **partially resolved** — allocation mode and symmetric occupancy checks close the original cross-mode trace, but the cutover fence and retain/release bridge remain incomplete.
2. Persistent peer INSTALLs: **partially resolved** — same-config PAT co-holder handling is defined; configuration-epoch interpretation and address-only installs remain unsafe.
3. Temporary stop/rebind escrow: **resolved** — the generalized handoff, preserved synced maps, and rebind replay-consumption lifecycle close the link-cycle trace.
4. Mixed-version matrix: **not resolved** — §9 is corrected, but §5.2 still authorizes the unsafe behavior.
5. Selector inventories: **resolved** — all required inventories and the test field list now agree; only the low-severity Phase-1 wording remains.

The blind-demote gate remains converged, and the temporary-stop and selector folds are substantively sound. Nevertheless, a future-epoch persistent INSTALL can still be interpreted with the wrong lease policy and leave a co-holder absent at takeover; allocator cutover still has ownership paths outside its stated fence; and §5.2 still permits a stale Close to delete a legacy peer’s replacement flow. Those are concrete SNAT mid-flow swap and HA-propagated-kill traces, so final sign-off is not yet warranted.
