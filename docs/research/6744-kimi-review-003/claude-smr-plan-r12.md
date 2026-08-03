# Claude CLI attempt and independent fallback

The Claude Code CLI was invoked for round 12 but stopped before analysis with
the account monthly-spend-limit error:

```text
You've hit your monthly spend limit - raise it at claude.ai/settings/usage?from=cc_cli_limit_message
```

No Anthropic-model verdict exists for this round. The review below is an
independent, non-Anthropic SMR-method fallback and is not represented as a
Claude verdict.

# Independent SMR review

This is an independent, non-Anthropic review. I read all 3,686 lines of [plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1) and inspected the cited production paths.

## Checkout verification

- `pwd`: `/home/ps/git/xpf-worktrees/6744-plan-r12-review`
- `HEAD`: `1f1325f3348c5904e451e1e3b4dcd8cc8ec71bc6`
- Detached: yes; `git symbolic-ref -q HEAD` returned no ref.
- Clean: `git status --short --branch` returned only `## HEAD (no branch)`.
- No unstaged diff: `git diff --exit-code` succeeded.
- No staged diff: `git diff --cached --exit-code` succeeded.
- The checkout remained unmodified.

## Specification model, A–M

| WS | State and transition owner | Linearization/failure model | Finding |
|---|---|---|---|
| A | Process-local `vipWarnedIfaces`, owned by daemon helper methods under the new dedicated mutex. | Reset/check/insert/delete linearize under that mutex; it must not nest with `directVIPMu` or `applySem`. Current reset and access are unsynchronized at [daemon_apply.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/daemon/daemon_apply.go:238) and [daemon_ha_vip.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/daemon/daemon_ha_vip.go:222). | Ready at plan level. |
| B | Canonical local and peer-effective prepared AST views. | Hard gate after inactive/group/interface-range normalization, before blank identities can be dropped by [sortDedupZones](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/types_security.go:486). Both node-effective views must pass before promotion. | Ready at plan level. |
| C | Normalized SNMP AST, nonsecret source observations, typed `SNMPConfig`, evaluated installable/rejected runtime set. | Deep fold is authoritative; intent validation precedes lowering; `Agent.UpdateConfig` publishes the evaluated runtime set atomically. Current root dispatch invokes `compileSNMP` repeatedly at [compiler_dispatch.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/compiler_dispatch.go:94), causing replacement rather than a complete fold. | Ready at plan level. |
| D | No durable state; one packet-local admission decision. | The helper call is the decision point. Current code derives `packet_icmp` but passes literal zero at [flowless_verdict.rs](/home/ps/git/xpf-worktrees/6744-plan-r12-review/userspace-dp/src/afxdp/poll_descriptor/flowless_verdict.rs:84). Passing `extra.icmp_type` only when `l4_present` preserves fragment fail-closed behavior. | Ready. |
| E | Durable per-surface ownership rows; process-local same-family current/previous updater anchors and claim snapshot. | Co-owner release linearizes at durable row removal before claim publication; last-claimant wire delete requires exact same-family fingerprint authority. Pre-rename failure restores ownership; post-rename-sync ambiguity converges to the visible removal but performs no provider I/O. Current representative cross-family fallback is visible at [manager.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/ddns/manager.go:900). | Ready at plan level. |
| F | Candidate AST, candidate generation, dirty bit, lock owner and lease deadline under `Store.mu`. | Parse/replay occurs on a detached tree; the single swap is the linearization point. Current implementation directly parses and swaps at [store_command.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/configstore/store_command.go:309). All classifier failures leave every candidate field unchanged. | Ready. |
| G | Durable active/candidate/rollback/confirm JSON trees. | Structural validation immediately after unmarshal is the read linearization gate; malformed authoritative active state becomes `ErrConfigDBUnreadable`. Current code returns directly after unmarshal at [db.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/configstore/db.go:377), allowing the two known empty-key panics at [compiler_interfaces.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/compiler_interfaces.go:364) and [compiler_services.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/compiler_services.go:1437). | Ready for the reproduced class, with the planned audit/source canary mandatory. |
| H | Pure derived route-map expansion/cardinality state. | Shared family expansion and highest-sequence helper must be the single guard/renderer authority. Current count ignores referenced-list contents at [routemap_seq_bound.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/routemap_seq_bound.go:30), while rendering expands mixed lists through [prefixListFamilies](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/frr/naming.go:67). | Ready. |
| I | Detailed below. | Detailed below. | Major blockers remain. |
| J | Typed global `AddressBook`, accumulated in source order. | One allocation followed by merge-by-name; no later root may replace the accumulator. Current compiler allocates and overwrites per root at [compiler_security_addressbook.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/compiler_security_addressbook.go:221). | Ready. |
| K | Process-local bond/tunnel ownership sets. | Forget ownership only after `LinkDel` success or positively classified absence; transient `LinkByName` errors retain retry state. Current bond and tunnel paths treat every lookup error as absence at [bond.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/routing/bond.go:576) and [tunnel.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/routing/tunnel.go:1236). | Ready. |
| L | Decoded `EventRecord`, binary action byte and formatted/API projections. | Normalize applicability at both decode boundaries before slog or record construction. Current raw action zero becomes `"permit"` through [actionName](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/logging/ringbuf.go:1264), and SSE prints it for lifecycle records at [sse.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/api/sse.go:272). | Ready. |
| M | Canonical expanded policy AST. | Exact four-key zone-pair shape is a hard pre-compilation gate on strict and tolerant paths; rejection precedes `compilePolicies` and peer promotion. | Ready. |

## Workstream I state machine

### State classes

Durable/external state:

- Config-store active/candidate/rollback/confirm trees.
- Pinned `rg_active`, `ha_watchdog`, bindings and `userspace_ctrl` maps.
- The helper process’s full HA inventory and applied snapshot.
- Dataplane session rows.

Long-lived process state:

- `RGAuthoritySnapshot{Desired, Committed, ChangedGroups, Serial, Transitioning}`.
- `haInventoryDebt` and `helperStatusLease`.
- Local `committedConfigRecord`, accepted remote epoch and failed-config mutation.
- `committedRuntimeConfig` and desired/running `clusterCommsEpoch`.
- `configInstallGate`, baseline/repair generations and continuity history.
- Per-transport capability/process identity, two connection incarnations and worker registries.
- Request, barrier, receive-window, pending-ACK and outbound-bulk records.
- Protocol callback replay ledger and the continuity outbox.

### Transition owners and linearization points

- Helper inventory: `userspace.Manager`, under `haInventoryTxnMu -> Manager.mu`. Debt installation/supersession precedes promotion; exact debt-generation publication after full fences and helper replacement is the success point.
- RG authority: manager mutation boundaries publish `Transitioning=true` before raw state changes. `PublishRGAuthority` with matching manager and SessionSync one-shot permits is the sole positive-authority linearization point.
- Config apply: daemon callback under `applySem`; gate publication of remote accepted epoch, local committed epoch, authority delta and receipt is the successful callback point.
- Config send: record and request are written under one `writeMu` transaction, with token validation before config and again before Type 29.
- Bulk receive: `BulkEnd` detaches the window into a joined reconciliation worker. Success only reaches ACK precommit; it is not yet continuity.
- ACK: exact ACK write is the causal wire point. A later serialized postcommit publishes continuity/debt completion only if the token remains current.
- Restart: daemon restart coordinator detaches, closes registration, cancels and joins the complete old `clusterCommsEpoch`, then publishes the replacement.
- Readiness: current capable inbound bulk success only. Timeout is a separate automatic-election availability input and cannot satisfy manual readiness.

### Lock order

The proposed orders are otherwise coherent:

- `applySem -> haInventoryTxnMu -> Manager.mu`
- `haInventoryTxnMu -> Manager.mu`
- `s.mu -> gate.mu`
- `bulkSendMu -> producerMu`
- `writeMu -> s.mu -> gate.mu`
- `continuityPublishMu -> [writeMu ->] s.mu -> gate.mu`

No state mutex may be held during network/helper I/O, cancellation waits or joins.

### Worker and cancellation edges

- Daemon lifetime: restart coordinator and failed-config recovery worker.
- `clusterCommsEpoch`: watchdog, heartbeat, gRPC, event stream, reconcile, IPsec and both fabric children.
- SessionSync lifetime: accept/connect loops, config loop, notifier and lifecycle coordinator.
- Per-transport setup registry: handshake/capability attempts registered before work begins.
- Per-transport data registry: receive/send, callbacks, installs, ACK, barriers, reconcile and bulk.
- Single-fabric loss joins connection-scoped work only.
- Last-fabric loss, process replacement and Stop close registration, cancel and join all setup/data work before advancing authority.
- An admitted config callback may complete under predecessor ownership; `BeginOwnershipTransition` joins it and adopts its receipt rather than self-cancelling it.

### Wire and replay identities

The steady-state wire namespace is well specified:

- Type 30 capability: exactly 26 bytes, with version, flags and process ID.
- Config: text plus 8-byte magic, sender generation and 32-byte digest.
- Type 29: exactly 48 bytes, declaring the requester’s local sender epoch.
- Capable BulkStart/BulkEnd/BulkAck: exactly 56 bytes, declaring/echoing the bulk responder’s local sender epoch.
- Ordinary session frames retain one compact generation; their digest is causally bound by the preceding request/bulk/ACK exchange.
- Tokens additionally bind transport, connection incarnation, process, ownership serial/generation, authority generation and repair debt.
- Local committed and accepted remote generations are never directly compared; canonical digest equality is the cross-peer equivalence condition.

### Failure/recovery states

- Helper uncertainty: full debt retained, affected slots fenced, helper disarmed, readiness false.
- Config callback failure: `authorityApplyFailed`, admissions closed, failed record retained, transport retired, exact/newer full reapply required.
- Ownership failure: manager remains transitioning and all positive acts remain prohibited.
- Reconciliation/member error: no ACK, callback, continuity or debt discharge.
- Ambiguous request/config/ACK write: retire transport and retain repair debt.
- Capability mismatch or mixed versions: ordinary legacy traffic only, no authoritative bulk or manual readiness.
- Config-sync-disabled digest mismatch: both directions remain closed until independently committed digests match.
- Last-fabric loss: current continuity clears; previous-good survives only for the explicit automatic peer-loss doctrine.

## Major blockers

### 1. Config-generation ownership, SessionSync restart and daemon boot are not one executable namespace

The plan says a sender generation belongs to the process that created it and is meaningful only with that process ID ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1596), [plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1923)). It simultaneously requires a complete cluster-comms restart to rotate the SessionSync process ID while reusing the exact same immutable committed record and generation ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:3196)). It also requires `Start` to receive a nonzero record while forbidding construction from deriving one from text ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1331)).

Executable trace:

1. SessionSync process `P1` owns committed `{g=7,d=X}`.
2. A transport-address commit completes and the daemon restarts cluster comms.
3. The replacement is required to use process ID `P2` but reuse `{g=7,d=X}`.
4. Either generation 7 still belongs to `P1`, contradicting the receiver key `(P2,7,X)`, or records are intentionally rebound to a new namespace, contradicting the “created by one process” invariant.
5. Now restart the entire daemon. The config DB contains the tree, not this in-memory record or counter. No local commit or peer apply occurs before initial authority initialization, yet `Start` requires a nonzero record and construction may not derive it.
6. At `MaxUint64`, rotating only the process ID cannot reset `max(counter, committed.generation)+1`; the retained immutable record still contains `MaxUint64`.

Current source exposes why this transition must be explicit: config generation is seeded inside each constructor at [sync.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/cluster/sync.go:837), every `QueueConfig` currently allocates at send time at [sync_conn_config.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/cluster/sync_conn_config.go:222), and daemon construction begins only from `store.ActiveConfig()` at [daemon_ha_sync.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/daemon/daemon_ha_sync.go:692).

The plan must choose and specify one model:

- a stable sender-generation namespace distinct from the restartable SessionSync/transport process identity; or
- an explicit, safe record-rebinding transition under a new identity.

It must also define the daemon-boot record-allocation linearization point, full-process restart behavior, and counter-exhaustion rebase. Production tests currently cover cluster-comms restart, but not this missing daemon-boot/max-generation transition.

### 2. Peer owner-inventory debt cannot precede `SyncApply` promotion through the current production API

The plan requires a config that changes inventory to compile the desired inventory first, install/supersede debt, and perform `SyncApply` promotion while still holding `haInventoryTxnMu` ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1247)).

Executable trace:

1. Active config `C1` binds owner slot 1. Peer config `C2` removes slot 1 and binds slot 2.
2. The callback acquires `applySem`.
3. It must derive `D2`, acquire `haInventoryTxnMu`, install the fences/debt for `D2`, and only then make `C2` active.
4. The only production API is `Store.SyncApply(text, preserve)`. It parses, applies local transforms, compiles, updates history and promotes `s.active` within one call at [store.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/configstore/store.go:634), with promotion at [store.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/configstore/store.go:681).
5. Before that call returns, the caller has no authoritative compiled `C2` from which to derive `D2`; after it returns, promotion already happened.
6. Installing debt afterward creates the forbidden active-`C2`/old-inventory interval. Separately parsing/compiling beforehand invents a second preparation pipeline whose equality with `SyncApply`—including chassis preservation, retired-dataplane rewrite, sanitation and lenient compilation—is unspecified.

The current daemon confirms this combined boundary: [syncAndApply](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/daemon/daemon_apply_commit.go:326) calls `SyncApply` first and only then enters runtime application.

The plan needs an explicit production transaction, such as `PrepareSyncApply` returning the exact immutable prepared tree/compiled config plus a one-shot `PromotePreparedSync`, with store-version validation. A real Store→daemon→userspace test must pause before and after that promotion and prove debt/fences are already installed and correspond to the exact promoted tree.

### 3. The protocol replay ledger and callback worker set are called “bounded” without a realizable bound or eviction invariant

The plan introduces closable data-worker maps and a “bounded idempotency ledger” for failover operations ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1669), [plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1728)). It gives no capacity, terminal retention rule, TTL, replay window, admission policy or full-ledger behavior. The only explicit capacity in the constants is the continuity outbox ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1580)); the deferred-delta FIFO is likewise merely described as bounded ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:2314)).

Executable pressure/replay trace:

1. A capable authenticated peer sends `N` distinct failover request IDs faster than callbacks finish.
2. Each request registers a data worker and an in-flight ledger entry. Current production dispatch demonstrates the direct goroutine surface at [sync_conn_read.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/cluster/sync_conn_read.go:397).
3. With no stated capacity, memory and goroutines grow without a protocol bound and last-fabric drain/Stop must join an arbitrarily large set.
4. If an implementer invents a capacity and evicts completed request `K`, an ACK for `K` may have been lost.
5. The same process retries exact `K`; with the record evicted, the ownership mutation runs again, violating the plan’s exact-retry rule.
6. If records never expire during an arbitrarily long peer-process lifetime, unique request IDs grow the ledger without bound.

This requires a real replay algorithm, not an adjective: per-kind capacities, in-flight and terminal quotas, monotonic high-water/replay-window semantics, eviction eligibility, lifetime relative to failover ACK/commit/auto-restore leases, and fail-closed behavior when full. The same table must cover `dataWorkers`, deferred deltas and waiter maps. The planned Type-29 flood test is good, but there is no equivalent production-frame saturation/eviction test for protocol callbacks.

### 4. Cancellation/join safety depends on deadlines that the plan never defines

The plan removes timeout abandonment and requires exact cancellation and joins for config callbacks, transport workers, reconciliation, restart and notifier delivery ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1644), [plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:2116)). It says callbacks have a bounded context and non-context operations use an “explicit bounded deadline,” but supplies no duration or end-to-end deadline for config apply, protocol callbacks, ownership completion, helper-debt retry, recovery backoff or continuity delivery ([plan.md](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:2057)).

Executable trace:

1. A peer config callback is admitted and reaches a cancellation-unaware post-promotion operation.
2. Last-fabric loss cancels its lease.
3. The lifecycle coordinator must join the callback before advancing `transportEpoch` or publishing replacement authority.
4. Because no concrete deadline is assigned to that operation or the whole callback, the callback may never return.
5. Replacement authority and cluster-comms restart never publish; external `Stop` also joins without the former escape.
6. The same failure exists if the synchronous continuity callback blocks: the fixed 64-entry outbox fills, a required false edge cannot receive delivery acknowledgment, and transition/Stop cannot proceed.

The source currently has precisely the unsafe boundaries being replaced: `handleConfigSync` calls `syncAndApply(context.Background(), ...)` at [daemon_ha_sync.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/daemon/daemon_ha_sync.go:573), `syncAndApply` substitutes the daemon apply context for the incoming lease at [daemon_apply_commit.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/daemon/daemon_apply_commit.go:479), and `SessionSync.Stop` currently abandons its wait after five seconds at [sync_conn.go](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/cluster/sync_conn.go:349).

The plan needs an exact timeout/budget table, including inheritance rules and fail-closed outcomes, plus production-entrypoint tests using each actual callback and a cancellation-unaware fake. “Existing RPC deadline” is acceptable where the cited source constant is identified, but the complete apply/join budget cannot be left to implementation.

## Round-11 blocker-class closure

Direct source comparison, rather than reliance on the prior synthesis, gives:

| Round-11 class | Round-12 status |
|---|---|
| Sender-owned generation/replay namespace | Improved substantially, but blocker 1 remains for namespace ownership, daemon boot and exhaustion. |
| Non-RG0/all-RG authority | Closed at specification level by full desired/committed snapshots, coarse global gating and final dual-token CAS. |
| Helper-debt lock/status consumers | Writer/status inventory is comprehensively enumerated; blocker 2 remains at the real peer compile/promote boundary. |
| Setup registration outside drain | Closed by pre-work registration and atomic setup→data transfer. |
| Non-config callback lifetime and ACK migration | Scope/connection ownership is closed; blockers 3–4 remain for resource and deadline completeness. |
| Bulk/request token schemas | Closed: Type 29 is 48 bytes; capable marker/ACK is 56 bytes and uses the correct requester/responder local namespaces. |
| Callback self-invalidating its authority lease | Closed by predecessor-lease completion plus `RGMutationReceipt` adoption. |
| Restart worker selecting promoted failed config | Closed by `committedRuntimeConfig` and a daemon-owned level-triggered coordinator. |
| Readiness notifier sequence inversion | Ordering is closed by reservation-before-sequence and delivery acknowledgments; notifier bounded-completion remains part of blocker 4. |
| Raw RG writers/positive actuators | Closed at specification level by two manager mutation boundaries, final-publish activation wrapper and AST-resolved source canaries. |

## Source canaries and production tests

The plan’s canary coverage is unusually strong for raw RG state, actuator sites, config-generation allocation, callback dispatch, writers, readiness setters, helper-status consumers and cluster-comms workers. Production-entrypoint coverage is also adequate for A–H and J–M.

The missing acceptance tests correspond exactly to the blockers:

- Full daemon restart/bootstrap and generation exhaustion/rebase.
- Real `Store.SyncApply` prepare/debt/promote ordering.
- Protocol callback/ledger saturation, eviction and lost-ACK replay.
- Concrete end-to-end callback/apply/notifier deadline expiration through production dispatch.

## Optional polish

- Replace “semantic equivalence” with “canonical committed-text equivalence” unless the serializer is intentionally proven to canonicalize every semantically irrelevant ordering.
- Label each proposed ledger as durable, daemon-lifetime, SessionSync-lifetime, transport-lifetime or connection-lifetime directly beside its type.
- Add one compact state-transition table to Workstream I; the prose is complete enough to derive one, but reviewers should not have to reconstruct it repeatedly.

The plan is not kill-worthy: the safety direction is sound, the round-11 architecture is substantially repaired, and the missing contracts are fixable. They are nevertheless implementation-defining invariants in the central HA transaction, replay and shutdown machinery, so implementation would still have to invent them.

PLAN-NEEDS-MAJOR
