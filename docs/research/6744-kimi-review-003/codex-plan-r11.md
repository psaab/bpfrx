PLAN-NEEDS-MAJOR

## Checkout verification

- `pwd`: `/home/ps/git/xpf-worktrees/6744-plan-r11-review`
- `HEAD`: exactly `e316e5b0c193f844289a6a6aeb505929108a550a`, detached.
- `git status --short`: empty.
- Both staged and unstaged `git diff --exit-code` checks passed.
- Final status remained clean. I made no writes and changed no files, refs, issues, or PRs.
- I read all 2,918 lines of [plan.md](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1). Tests were inspected for coverage only; no test result is treated as proof.

## Material blockers

### 1. The config generation has no durable sender owner or bidirectional namespace

The plan requires a failed G2 apply to retire and reconnect so “the same generation” is re-pushed, including cancellation after promotion or dataplane arm ([plan.md:1583](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1583), [plan.md:1622](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1622), [plan.md:2518](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:2518)). No proposed state owns that generation across a connection or `SessionSync` restart.

Production currently allocates a new generation inside every `QueueConfig` call ([sync_conn_config.go:222](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_conn_config.go:222), [sync_conn_config.go:234](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_conn_config.go:234)). The daemon retains only a text hash and connection epoch ([daemon_ha_sync.go:381](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/daemon/daemon_ha_sync.go:381), [daemon_ha_sync.go:474](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/daemon/daemon_ha_sync.go:474)). Session frames are stamped from the sending instance’s local counter ([sync_conn_gen.go:119](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_conn_gen.go:119)).

Executable trace:

1. Authority sends text X as G2.
2. Receiver promotes X through `SyncApply`, then cancellation lands after promotion or after dataplane arm. It leaves G2 unaccepted and retires the transport as required.
3. Reconnect calls `QueueConfig(X)`.
4. `QueueConfig` allocates G3. G2 cannot be re-pushed. The normative test at plan line 2527 is impossible.

The same omission breaks active/active framing:

1. A sends authority config generation G100 to B.
2. B accepts G100 and owns sessions for a non-RG0 redundancy group.
3. B services A’s reciprocal type-29 request.
4. B’s existing sender namespace is its unrelated local counter, while A’s `acceptedConfigGen` is a receiver-side field. If B stamps its local counter, A compares unrelated namespaces. If B stamps G100, the plan never states where A records G100 as its expected inbound-session generation.
5. Valid B-owned sessions are either rejected or admitted without the promised equality fence.

Required revision: define a durable sender-owned record such as `{digest, text, wireConfigGen, outboundAuthorityGeneration}`, an explicit `QueueConfig(gen,text)` contract, retention across connection and post-config `SessionSync` restart, and one shared authority-config epoch stored on both peers. Separate local-authority epoch from peer-received high-water where necessary and state exactly which value every outbound ordinary/bulk session carries.

### 2. Non-RG0 role changes have no authority transition, despite active/active ownership depending on them

Initialization contains `RG0Role` and a copied `ZoneOwners` boolean map ([plan.md:1266](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1266)). The only concrete role coordinator advances authority for RG0 ([plan.md:1487](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1487), [plan.md:1541](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1541)). Yet the plan claims reciprocal active/active session ownership converges ([plan.md:1648](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1648)).

Production ownership is dynamic for every RG: `ShouldSyncZone` resolves zone→RG and calls `IsPrimaryForRGFn` ([sync_conn_sweep.go:65](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_conn_sweep.go:65)), wired to raw per-RG election state ([daemon_ha_sync.go:1169](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/daemon/daemon_ha_sync.go:1169)). Election changes every RG before event delivery ([election.go:311](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/election.go:311)) and events can be dropped ([manager.go:470](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/manager.go:470)).

Executable trace:

1. A owns RG1/zone Z; `ZoneOwnersA[Z]=true`. B owns another RG.
2. RG1 fails over from A to B without a config or RG0 change.
3. No specified API begins a SessionSync authority transition for RG1, atomically changes `ZoneOwners`, or advances the gate’s `roleGeneration`.
4. A’s already-authorized producer can continue sending Z sessions or answer a type-29 request using stale ownership. B simultaneously begins producing Z after promotion.
5. A receiver can now reconcile against two claimed owners, including deleting valid state absent from the stale owner’s bulk.

“Config/failover authority writers cancel and join the bulk” at [plan.md:1773](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1773) is not a transition protocol.

Required revision: define an all-RG ownership generation or per-RG committed authority snapshot, with begin/complete/supersession semantics, event-drop safety-net ownership, atomic `ZoneOwners` replacement, producer/receive-window invalidation, and fresh bidirectional repair after every ownership change.

### 3. The helper-debt mutex graph does not close over the real manager or all status-bearing helper completions

The plan names `haInventoryTxnMu -> manager HA state mutex`, releases the state mutex during helper I/O, and requires status/readiness to participate ([plan.md:1185](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1185)). Production has one broad `m.mu` protecting process, config, snapshots, status, HA groups, and readiness—not a defined narrow HA mutex ([manager.go:85](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/dataplane/userspace/manager.go:85)).

Current status polling holds `m.mu` across the helper request, returned-status application, snapshot repair, HA reconciliation, and forwarding publication ([process_status.go:152](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/dataplane/userspace/process_status.go:152)). Direct RG updates hold it across map and helper I/O ([manager_ha.go:657](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/dataplane/userspace/manager_ha.go:657)); watchdog writes the BPF map before taking it ([manager_ha.go:807](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/dataplane/userspace/manager_ha.go:807)). Numerous non-HA requests also receive and apply a full helper status, including `Status` ([manager_status.go:31](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/dataplane/userspace/manager_status.go:31)) and config publication ([manager_compile.go:350](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/dataplane/userspace/manager_compile.go:350)). `applyHelperStatusLocked` can re-enable `userspace_ctrl` from such a response ([maps_sync.go:809](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/dataplane/userspace/maps_sync.go:809)).

Executable stale-response trace:

1. Inventory transaction T installs debt under `m.mu`, releases `m.mu` as required, and begins pinned fencing before its `update_ha_state` RPC.
2. An unenumerated status-bearing helper path acquires `m.mu` without `haInventoryTxnMu` and reaches the Rust helper first.
3. The helper serializes the request against its current old HA state and returns `Enabled=true`.
4. Go applies that response through `applyHelperStatusLocked` while debt exists and rewrites `userspace_ctrl=1`.
5. Forwarding is re-enabled between the required fence and confirmed replacement, violating the core debt invariant.

A minimal wrapper also creates the inverse-lock trace:

1. Existing status loop holds `m.mu`.
2. A config/direct writer holds `haInventoryTxnMu` and waits for `m.mu`.
3. Status reconciliation attempts to enter `haInventoryTxnMu`.
4. Deadlock: `m.mu -> txn` versus `txn -> m.mu`.

The source canary proposed at [plan.md:1212](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1212) enumerates only `rg_active`, `ha_watchdog`, `m.haGroups`, and `update_ha_state`; it misses full-status applications that mutate control/readiness maps.

Required revision: define the actual `haStateMu` split or explicitly designate existing `m.mu`; give every helper request a process/config/debt-generation lease; make every returned `ProcessStatus` application debt-aware; enumerate all `applyHelperStatusLocked`, `userspace_ctrl`, binding, and readiness writers; and state top-level lock acquisition for status, Compile, shutdown, direct actuators, and retries.

### 4. Pre-registration setup workers are outside the last-fabric drain proof

The plan’s explicit join set covers the config callback, admitted installs, receive worker, and bulk sender ([plan.md:1455](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1455)). It does not include auth/capability setup workers, and no setup lease appears among the concrete token types.

Production tracks pre-auth connections separately under `preAuthMu` ([sync_admission.go:58](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_admission.go:58)). Setup goroutines use the global wait group ([sync_conn.go:423](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_conn.go:423)); only external `Stop` closes setup connections ([sync_admission.go:105](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_admission.go:105)). Setup completion currently proceeds to installation without an epoch lease ([sync_conn.go:100](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_conn.go:100), [sync_conn.go:130](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_conn.go:130)).

Executable trace:

1. Connection B begins auth/capability setup under old transport E but is not registered.
2. Registered connection A is the last fabric and hits EOF or protocol violation.
3. Coordinator drains only the named registered-worker set, advances E→E+1, and reopens registration.
4. B completes its delayed capability exchange and dispatches its staged frame/install attempt.
5. With no `{setupSerial, transportEpoch}` lease and no mandated setup join/rejection, pre-drain work enters the replacement authority interval.

The setup tests at [plan.md:2572](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:2572) cover framing and slot release, not last-fabric drain during delayed auth/capability.

Required revision: setup workers need a distinct tracked group or inclusion in the closed data-worker set; whole-transport drain must close and join every pre-drain setup connection; setup installation must revalidate a captured epoch/serial; add full-disconnect and `Stop` traces during auth, capability, and staged-frame handling on both fabrics.

### 5. Non-config protocol callbacks have neither an exact lifetime lease nor a complete join contract

The plan generically mentions protocol handlers at [plan.md:1467](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1467), but its explicit last-fabric join set omits them, supplies no callback context/signature change, and does not say whether their ACK is connection-, transport-, or process-scoped.

Production starts failover and prepare-activation handlers as bare goroutines ([sync_conn_read.go:397](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_conn_read.go:397), [sync_conn_read.go:486](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_conn_read.go:486)). They perform externally visible role mutations and waits ([sync_failover.go:423](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_failover.go:423), [daemon_ha_sync.go:999](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/daemon/daemon_ha_sync.go:999)). The ACK writer deliberately switches to whatever connection is currently active ([sync_failover.go:507](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_failover.go:507)).

Executable trace:

1. Old process P1 sends failover request R on the last fabric.
2. Handler demotes the local RG and blocks in `WaitFailoverApplied`.
3. Source connection reaches EOF; transport E is retired and P2 registers.
4. Old handler completes.
5. `sendFailoverResult` chooses P2’s current active connection and writes P1’s ACK R into P2’s stream. A colliding request ID can complete the wrong waiter; otherwise P2 receives an unsolicited applied ACK for an operation it never requested.
6. The same missing lease permits delayed `OnPrepareActivation` or commit callbacks to mutate state after role/transport supersession.

Required revision: enumerate every asynchronous protocol callback; track it in the drain set; give it a cancellable bounded context and immutable `{transport, connection where appropriate, process, role/authority, request}` lease; revalidate before mutation and ACK; and explicitly decide when a same-process survivor fabric is allowed. An old-process ACK must never migrate to a replacement connection.

### 6. The declared request/bulk token schema is internally incomplete

`repairAttempt` omits `peerProcessID` and accepted config generation, despite the prose saying the attempt captures process ([plan.md:1321](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1321), [plan.md:1857](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1857)). `pendingPeerBulkRequest` also omits process and debt/deadline state ([plan.md:1333](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1333)). Most importantly, no concrete outbound-bulk/pending-outbound-ACK token is declared even though capable ACK acceptance must fence process, role, config, authority generation, request, and debt ([plan.md:1877](/home/ps/git/xpf-worktrees/6744-plan-r11-review/docs/research/6744-kimi-review-003/plan.md:1877)).

Production illustrates why a local record is essential: the wire ACK alone contains only the bulk epoch, and current acceptance is backed only by `pendingBulkAckEpoch` ([sync_conn_read.go:249](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_conn_read.go:249), [sync_bulk.go:169](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_bulk.go:169)).

Executable trace:

1. Bulk B9/request R4 begins under authority generation A7, config G2, debt D12.
2. Sender records pending state and writes BulkEnd.
3. Config writer advances to A8/G3 and sends the newer config on the same live connection.
4. Delayed ACK `{B9,R4}` arrives.
5. The wire cannot distinguish A7/G2/D12 from A8/G3. The displayed gate has no pending outbound token against which to reject it.
6. Accepting it can set outbound authorization or complete D12 under G3; clearing an unspecified worker-local record may instead race the ACK and shutdown join.

Required revision: declare `outboundBulkLease` and `pendingOutboundAck` with their exact lock owner and fields. Add process/config fields to request records. For every token, state which of transport, connection, process, role generation, manager-authority serial, outbound-authority generation, accepted config generation, bulk epoch, request ID, and debt generation are required or intentionally omitted.

## Hostile-check disposition

The following revision-11 mechanisms are otherwise coherent in the normative design:

- Config transport restart is moved outside the callback’s wait group, and EOF/protocol violation retirement is moved to an external lifecycle coordinator. Those changes close the two explicit self-join paths, subject to setup/protocol workers being added to the lifetime graph.
- Config authority delta commit, apply-queue overflow retirement, and post-commit restart coalescing are correctly ordered.
- Pre-promotion/promoted/armed failure classification is sound, but the missing stable wire-generation owner prevents the promised same-generation reconnect proof.
- RG0’s transitioning-before-raw-state publication, previous-committed heartbeat advertisement, boot hold, dropped-event safety net, supersession, and raw-consumer canary form a consistent RG0 design.
- Receiver reconciliation is correctly moved outside locks with context checks and bounded chunks.
- Receiver ACK precommit correctly opens ordinary admission before an immediate deferred tail while withholding continuity/debt success until write completion.
- Record-before-send type-29 handling and one-claimed/one-pending bounded pressure are sound.
- Separate inbound/outbound authorization and reciprocal post-config requests are conceptually correct, but depend on the missing shared config epoch and non-RG0 ownership transition.
- Keyed/unkeyed/dual-accept setup framing, auth-consumed staging, two-fabric capability/process mismatch, legacy ACK rejection, mixed-version manual-transfer restriction, and the continuity/previous-good/timeout split are internally consistent.
- Ordered continuity events and notifier shutdown are adequately specified. The unresolved full-disconnect cases are setup workers and non-config protocol callbacks.

## A–M coverage

| Workstream | Source-level result |
|---|---|
| A | No material blocker. Dedicated warning-state locking closes the current shared-map access around [daemon_ha_vip.go:224](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/daemon/daemon_ha_vip.go:224). |
| B | No material blocker. Raw empty identity rejection before normalization correctly closes the empty special-token behavior in [compiler_validate_strict_zones.go:82](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/config/compiler_validate_strict_zones.go:82). |
| C | No material blocker. Canonical SNMP folding and explicit configured-intent validation address the two compile entry points at [compiler_dispatch.go:96](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/config/compiler_dispatch.go:96) and [compiler_system.go:514](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/config/compiler_system.go:514). |
| D | No material blocker. Passing the decoded ICMP type fixes the hardcoded type-zero flowless path at [flowless_verdict.rs:83](/home/ps/git/xpf-worktrees/6744-plan-r11-review/userspace-dp/src/afxdp/poll_descriptor/flowless_verdict.rs:83). |
| E | No material blocker. Same-family authority selection and deferred anchor rotation close the representative-updater lifetime in [manager.go:915](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/ddns/manager.go:915). |
| F | No material blocker. Detached parse/classify followed by atomic swap repairs current `LoadOverride` handling at [store_command.go:304](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/configstore/store_command.go:304). |
| G | No material blocker. Persisted-AST shape validation is a valid front gate for unsafe indexed compiler reads such as [compiler_interfaces.go:365](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/config/compiler_interfaces.go:365). |
| H | No material blocker. Sharing exact renderer cardinality is the correct fix for the route-map expansion model rooted at [naming.go:15](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/frr/naming.go:15). |
| I | Blocked by all six findings above. |
| J | No material blocker. Deterministic merging repairs the last-container replacement at [compiler_security_addressbook.go:221](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/config/compiler_security_addressbook.go:221). |
| K | No material blocker. Positive not-found classification versus transient retention matches the unsafe ownership removal in [bond.go:577](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/routing/bond.go:577) and [tunnel.go:1237](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/routing/tunnel.go:1237). |
| L | No material blocker. Positive applicability and explicit OPEN/CLOSE normalization fit the current decode surfaces in [ringbuf.go:545](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/logging/ringbuf.go:545). |
| M | No material blocker. Canonical-shape rejection before compilation is implementable and preserves the intended flat zone-policy model. |

## Optional polish

- Capability setup says both peers write and then read. Current authenticated setup deliberately performs concurrent write/read so fully synchronous transports cannot deadlock ([sync_auth.go:326](/home/ps/git/xpf-worktrees/6744-plan-r11-review/pkg/cluster/sync_auth.go:326)). Use the same pattern or specify asymmetric ordering.
- Publish an explicit maximum-duration table for config cancellation, helper RPC, reconcile drain, callback drain, notifier delivery, and shutdown. “Bounded” is insufficient operational guidance when existing helper deadlines can be long.
- Clarify the I-a/I-b activation boundary: I-a says runtime belts remain disabled, while I-b may independently activate helper-debt behavior. State exactly which I-a helpers I-b may invoke without activating rejected-config semantics.