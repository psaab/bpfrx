# Claude SMR / independent fallback review - round 10

## Claude Code CLI attempt

The Claude Code CLI was invoked against immutable plan commit
`103acbfd28115993f8f6393ed6b55d632bcfb4ee`, but failed before analysis:

```text
You've hit your monthly spend limit. Upgrade your plan to continue using Claude Code.
```

No Anthropic-model verdict exists for this round.

## Independent SMR-method fallback

Reviewer agent: `019fc885-9a87-7402-8b13-8a3535ec2cae`

This is explicitly an independent SMR-method fallback, not an Anthropic
verdict.

### Verdict

`PLAN-NEEDS-MAJOR`

### Material blockers

1. **A received transport change deadlocks by stopping its own `SessionSync`.**
   `configApplyLoop` belongs to `s.wg`, synchronously invokes the config
   callback, and can reach `stopClusterComms -> ss.Stop -> s.wg.Wait` after the
   callback promotes a transport-changing config. The executing loop cannot
   return to its own `wg.Done`, so removing the five-second escape makes the
   deadlock permanent.
2. **Mutating config callbacks have no cancellation/recovery contract.** The
   callback is `func(string) error` and enters apply with
   `context.Background()`, but last-fabric loss and Stop must join it. A blocked
   operation after `SyncApply` promotion cannot be canceled, safely abandoned,
   or overlapped with replacement authority.
3. **Config-sync mode changes recursively drain their own callback.** The plan
   makes mode changes draining transitions while apply-time code calls the
   authority setter from inside the admitted callback. It needs a structured
   staged authority result committed only after callback success.
4. **Last-fabric retirement can join the receive worker initiating it.** A
   receive loop invokes disconnect handling before its deferred `wg.Done`, while
   the proposed drain joins that worker. EOF or an inline protocol violation can
   therefore self-deadlock. A coordinator outside every joined worker must own
   idempotent retirement and per-worker completion.
5. **RG0 state publishes before the daemon authority wrapper.** Election writes
   `rg.State` and heartbeat/readers can observe it before the asynchronous event
   invokes `BeginConfigAuthorityTransition`; delayed or dropped events therefore
   permit early role advertisement/authority. Desired and committed authority
   must be separate or transition must begin before raw state publication.

The reviewer found no additional material blocker in workstreams A-H or J-M,
and found the remaining capability, dual-fabric fencing, repair correlation,
partial-install handling, helper-debt ownership, legacy-ACK rejection,
readiness split, mixed-version restriction, and inactive-first stacking ideas
coherent subject to these authority/lifecycle blockers.

Checkout was verified clean and detached at
`103acbfd28115993f8f6393ed6b55d632bcfb4ee`. Read-only tests passed for
`./pkg/cluster`, `./pkg/daemon`, and `./pkg/dataplane/userspace`. The reviewer
made no file, branch, issue, or PR changes.

### Verbatim fallback output

```text
PLAN-NEEDS-MAJOR

This is an independent SMR-method fallback review, not an Anthropic verdict.

Material Blockers

1. A received transport change deadlocks by stopping its own SessionSync.
configApplyLoop is counted in s.wg (sync_conn.go:341) and synchronously invokes
the callback (sync_conn_config.go:350). That callback mutates the store
(daemon_apply_commit.go:353); a changed transport then calls stopClusterComms
(daemon_apply_tail.go:238), which calls ss.Stop() (daemon_ha_sync.go:1412).
Revision 10 prohibits the current five-second join escape (plan.md:1532).

Failure trace: add fabric 1 while fabric 0 remains usable; primary reconnects
on fabric 0 and sends the config; secondary runs configApplyLoop ->
handleConfigSync -> syncAndApply -> stopClusterComms -> ss.Stop -> s.wg.Wait.
The current goroutine owns one wg count and cannot return to wg.Done: permanent
deadlock.

2. Config callbacks that mutate and then block have no cancellation or recovery
contract. The callback remains func(string) error (sync.go:339) and invokes
apply with context.Background() (daemon_ha_sync.go:578). Yet last-fabric loss
must wait for that callback (plan.md:1335).

Failure trace: block an apply operation after Store.SyncApply has promoted
active state; drop both fabrics or call Stop. SessionSync cancellation cannot
reach the callback, replacement registration is prohibited, and shutdown waits
forever. A cancellable, mutation-aware callback contract is required; simply
abandoning it would allow stale mutation in a new authority epoch.

3. Config-sync enable/disable transitions recursively drain their own callback.
Revision 10 makes mode changes draining transitions (plan.md:1236), while
subsequent authority updates occur through the apply-time typed setter
(plan.md:1230); the existing analogous zone setter runs inside apply
(daemon_apply_dataplane.go:193).

Failure trace: a secondary with config sync disabled receives a config enabling
it; the callback mutates the store, invokes the setter, and the setter drains
admitted config work containing that same callback. Waiting deadlocks; not
waiting can expose protected state or issue the cold request before callback
publication. The callback must return a structured staged authority result
committed by configApplyLoop after callback completion.

4. Last-fabric retirement can join the receive worker initiating retirement. A
receive worker calls handleDisconnect before its deferred wg.Done
(sync_conn.go:132, sync_conn_read.go:14). The plan requires last-fabric drain to
join the receive worker (plan.md:1335); protocol violations can likewise
originate inline in that worker (plan.md:1518).

Failure trace: single-fabric EOF -> receiveLoop defer -> last-fabric drain ->
join receive worker -> wg.Done remains unreachable. "No same-loop wait" is not
an ownership design. The plan needs a dedicated lifecycle coordinator outside
every joined worker, with per-worker completion handles and idempotent retirement
ownership.

5. RG0 state is published before the proposed daemon authority wrapper can run.
Election mutates rg.State before sending the event (election.go:337); heartbeat
publication reads that mutated state directly (heartbeat_manager.go:263).
Events can be delayed or dropped (manager.go:470). A daemon wrapper invoked
afterward cannot satisfy revision 10's role-publication-waits invariant
(plan.md:1347).

Failure trace: local primary election writes RG0 secondary; heartbeat advertises
secondary before BeginConfigAuthorityTransition; peer promotes while local
forwarding/VIPs remain active because the event has not been consumed. This
creates dual ownership. Promotion has the inverse early-publication problem.
Manager needs separate desired and committed/advertised role state, or a
two-phase transition integrated before state publication.

SMR Disposition

A-H and J-M have no additional material blocker. Within I, capability setup for
new/new, new/old, old/new, keyed/unkeyed and delayed frames; dual-fabric fencing;
exact repair correlation; partial-install failure handling; helper debt
ownership; legacy ACK rejection; readiness separation; mixed-version
restriction; and inactive-first stacking are coherent.

Authority ownership, transition execution, callback failure containment, and
shutdown recovery fail on the traces above. Proposed tests cannot repair these
missing state-machine edges.

Checkout verified at /home/ps/git/xpf-worktrees/6744-plan-r10-review, HEAD
103acbfd28115993f8f6393ed6b55d632bcfb4ee, with empty final git status.
Read-only baseline tests passed for ./pkg/cluster, ./pkg/daemon, and
./pkg/dataplane/userspace. No files, branches, issues, or PRs were modified.

Optional Polish

None material beyond the blockers above.
```
