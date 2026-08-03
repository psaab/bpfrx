PLAN-NEEDS-MAJOR

Verified immutable target:

- `pwd`: `/home/ps/git/xpf-worktrees/6744-plan-r8-review`
- `HEAD`: `bebffd32c7a0c2956a7eabbf584a92c6604ec5b2`
- `git status --short`: clean
- Write scope: **NONE**

The following are source-grounded material blockers, not optional polish.

1. Legacy epoch zero can recreate a stale permit after a successful config sweep

The plan deliberately admits zero-epoch sessions once any protected baseline exists ([plan.md:1127](/home/ps/git/xpf-worktrees/6744-plan-r8-review/docs/research/6744-kimi-review-003/plan.md:1127)). That is unsafe with the actual outbound ordering:

- Sessions are stamped, encoded, and placed on `sendCh` ([sync_conn_write.go:53](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_conn_write.go:53)).
- Config bypasses `sendCh` and writes directly under `writeMu` ([sync_conn_config.go:230](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_conn_config.go:230)).
- The send loop may drain the older session later ([sync_conn_write.go:268](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_conn_write.go:268)).

Failure trace:

1. A mixed-version peer queues zero-epoch session S under C0.
2. Its stricter C1 config overtakes S through the direct config writer.
3. The receiver closes the gate, applies C1, sweeps deleted policy state, and reopens.
4. S arrives after the sweep.
5. The plan’s zero-epoch compatibility rule admits S, recreating the stale permit.
6. Because it was admitted, no refusal debt or type-29 recovery is armed.

The positive test “legacy zero after baseline” ([plan.md:1613](/home/ps/git/xpf-worktrees/6744-plan-r8-review/docs/research/6744-kimi-review-003/plan.md:1613)) would bless this fail-open behavior. The plan must choose a safe mixed-version contract—such as ordering config behind earlier session frames or withholding legacy traffic until a causally post-config authoritative bulk—rather than leaving that decision to implementation.

2. Reconnect baselines are not tied to a connection incarnation

The plan says a full disconnect closes admission until the first successful post-reconnect config, including a lower generation ([plan.md:1146](/home/ps/git/xpf-worktrees/6744-plan-r8-review/docs/research/6744-kimi-review-003/plan.md:1146)). Its gate has no connection incarnation, however ([plan.md:1104](/home/ps/git/xpf-worktrees/6744-plan-r8-review/docs/research/6744-kimi-review-003/plan.md:1104)).

Production config work is queued as only `{gen,text}` ([sync.go:686](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync.go:686), [sync_conn_read.go:298](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_conn_read.go:298)). The persistent consumer applies it later ([sync_conn_config.go:312](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_conn_config.go:312)). Full disconnect resets bulk and waiter state but neither drains nor invalidates queued config work ([sync_conn.go:480](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_conn.go:480)).

Two failing traces remain:

- Old generation G is queued, disconnect occurs, rebooted peer reconnects with lower H, then old G is consumed as the supposed post-reconnect baseline. H is rejected as lower.
- G is already applying when disconnect sets `baselinePending`; its callback later succeeds and clears `baselinePending`, even though no config from the new connection established that baseline.

Each received config needs a connection-incarnation token. Completion of an old-incarnation callback may update local applied state but must not open the new connection’s session gate. The reconnect test can currently pass using an empty queue while missing both production races.

3. The RG0 role-transition state machine is unspecified and the current hook is too late

The plan asserts that `protected` changes before a role transition exposes traffic ([plan.md:1121](/home/ps/git/xpf-worktrees/6744-plan-r8-review/docs/research/6744-kimi-review-003/plan.md:1121)), but supplies neither a transition API nor the required state changes.

Current promotion enables `rg_active`, removes blackholes, and may force VRRP master first ([daemon_ha.go:285](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/daemon/daemon_ha.go:285)). Only afterward does it invoke the RG0 ownership hook ([daemon_ha.go:417](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/daemon/daemon_ha.go:417)), whose current responsibility is configuration ownership, not session admission ([daemon_ha.go:425](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/daemon/daemon_ha.go:425)).

The plan must define:

- `unprotected → protected`: when the gate closes, whether it waits for existing installs, how `acceptedEpoch` is invalidated, and when `baselinePending` and debt are armed.
- `protected → unprotected`: disposition of an active apply, baseline wait, outstanding request, awaited bulk, and readiness debt.
- The exact pre-actuation daemon call site for promotion/demotion.
- How an old-role config callback completing after the transition is prevented from reopening the new-role gate.
- The active/active inverse behavior through both transition directions.

An isolated gate “role transition” test ([plan.md:1617](/home/ps/git/xpf-worktrees/6744-plan-r8-review/docs/research/6744-kimi-review-003/plan.md:1617)) can pass without exercising the production HA event order.

4. The outbound producer barrier has an unresolved check/enqueue race

The plan says to set a producer gate, enqueue a barrier, and defer subsequent session deltas ([plan.md:1154](/home/ps/git/xpf-worktrees/6744-plan-r8-review/docs/research/6744-kimi-review-003/plan.md:1154)). It never specifies an atomic protocol shared by producers and the bulk sender.

Current producers enqueue directly through `queueMessage` ([sync_conn_write.go:36](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_conn_write.go:36)); this includes normal installs/deletes, delete-journal replay ([sync_conn_write.go:135](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_conn_write.go:135)), and sweep replay ([sync_conn_sweep.go:137](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_conn_sweep.go:137)). `bulkSendMu` is currently held only by `BulkSync` ([sync_bulk.go:50](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_bulk.go:50)).

Failure trace for a flag-only implementation:

1. Producer observes the gate open.
2. Bulk sender closes it and enqueues the barrier.
3. Producer enqueues its already-authorized frame after the barrier.
4. The send loop writes the barrier and then that frame.
5. BulkStart and snapshot direct writes follow, so the ordinary incremental contaminates the authoritative window.

The plan must require one shared lock or equivalent linearization mechanism across producer gate-check plus enqueue/defer, and enumerate every production producer entrypoint. Tests limited to `QueueSession` could pass while sweep or journal traffic violates the window.

5. Type 29 cannot identify the bulk that satisfies its debt

The proposed request has zero payload, while only an undefined “matching BulkEnd” may complete its token ([plan.md:1173](/home/ps/git/xpf-worktrees/6744-plan-r8-review/docs/research/6744-kimi-review-003/plan.md:1173)). Existing BulkStart/BulkEnd carry only a sender-local epoch ([sync_bulk.go:65](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_bulk.go:65), [sync_bulk.go:183](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_bulk.go:183)); the receiver validates only that epoch against its current bulk ([sync_conn_read.go:183](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/cluster/sync_conn_read.go:183)).

Causal failure trace:

1. Sender already has unrelated bulk B in progress.
2. Receiver successfully writes debt request D before its receive goroutine has processed B’s BulkStart.
3. Sender receives D during B and, per the plan, arms another bulk.
4. Receiver then processes B’s valid BulkStart and BulkEnd.
5. With no request ID, acknowledged target epoch, or echoed debt token, B is indistinguishable from the requested repair bulk and can clear D prematurely.

Full-duplex TCP ordering does not create cross-direction causality here. A request token echoed by the repair bulk, or an ACK binding D to a future bulk epoch, is required. The stated “valid BulkEnd token completion” test ([plan.md:1628](/home/ps/git/xpf-worktrees/6744-plan-r8-review/docs/research/6744-kimi-review-003/plan.md:1628)) currently assumes a matching relation that the wire protocol cannot express.

6. RG helper clears are described as per-slot patches, but the helper performs full replacement

The plan clears each removed/new owner slot and “publishes the same inactive state” before publishing the new inventory ([plan.md:1044](/home/ps/git/xpf-worktrees/6744-plan-r8-review/docs/research/6744-kimi-review-003/plan.md:1044)). Production `update_ha_state` sends the entire `m.haGroups` set ([manager_ha.go:26](/home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/dataplane/userspace/manager_ha.go:26)), and Rust builds a new map and atomically replaces the previous map ([state.rs:4](/home/ps/git/xpf-worktrees/6744-plan-r8-review/userspace-dp/src/afxdp/ha/state.rs:4), [state.rs:72](/home/ps/git/xpf-worktrees/6744-plan-r8-review/userspace-dp/src/afxdp/ha/state.rs:72)).

For old `{RG1 active, RG2 active}` to new `{RG2 active, RG3 inactive}`:

- Sending only `RG1 inactive` clears RG2 from the helper and spuriously demotes it.
- Sending the old inventory cannot introduce/fence RG3.
- Sending the final inventory is a staged publication that must preserve RG2, omit/demote RG1, include RG3 inactive, and itself survive retry debt.
- Sequential per-slot requests must accumulate prior clears; otherwise a later replacement can replay a slot cleared earlier.

The plan needs an exact transitional full-inventory payload and retry ownership model. A fake helper treating requests as patches would let the listed per-slot tests pass while production behaves differently.

Audit of A–M

The remaining workstreams are sufficiently specified:

- A/B/C/D/E/F/G/H/J/K/L/M have no material design blocker found.
- SNMP now handles AST source-form indistinguishability honestly, retains conflict provenance through deep folding, makes equal-prefix `restrict` deny dominate allow, and routes one normalized root to gates and lowering.
- DDNS provides constructor-selected expected surfaces without a disk discriminator, covers raw scope versus canonical row FQDNs, orders validation → co-owner claim-only release → last-claimant authority, and preserves same-family `fpb1`/anchor behavior.
- RG preflight now correctly disclaims any freshness oracle.
- `ReadConfirm` uses the same bounded `PrevTree` validator without redesigning confirm hashing, timers, or transaction semantics.
- `LoadOverride` correctly leaves terminal Ctrl-C/non-EOF behavior and `pkg/cli` to #6548 and does not claim that test.
- Workstream I’s range, typed-binding, previous-good, and preflight portions are sound; its HA/session/bulk subdesigns are blocked as listed above.

Optional polish: none identified. All six findings require design decisions before implementation; they are not documentation niceties.