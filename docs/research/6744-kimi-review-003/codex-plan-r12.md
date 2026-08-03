Environment verified before review and again afterward:

- `pwd`: `/home/ps/git/xpf-worktrees/6744-plan-r12-review`
- `HEAD`: `1f1325f3348c5904e451e1e3b4dcd8cc8ec71bc6`
- Status: `## HEAD (no branch)`
- Unstaged diff: none
- Staged diff: none
- Final diff checks exited 0

I read all 3,686 lines of `plan.md` and inspected the cited production paths. Tests were treated only as coverage proposals, not proof.

## Material blockers

1. Workstream I does not freeze the complete heartbeat election state before publication.

The authority snapshot contains only `Present` and `State`; the plan promises transition-before-raw-state publication and freezes only the prior committed `NodeState` in heartbeats ([plan.md:1760](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1760), [plan.md:1785](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1785), [plan.md:1843](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1843)). But production heartbeats also advertise live `Priority` and `Weight` ([heartbeat_manager.go:263](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/cluster/heartbeat_manager.go:263)), and the peer elects directly from those fields—including immediate promotion when peer weight becomes zero ([election.go:138](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/cluster/election.go:138), [election.go:152](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/cluster/election.go:152)).

Executable trace:

1. A is committed primary; B is secondary.
2. A’s monitor fails. `recalcWeight` writes `rg.Weight = 0` before running election ([election.go:611](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/cluster/election.go:611)).
3. A enters an authority transition, but its asynchronous coordinator has not yet fenced forwarding.
4. A emits a heartbeat containing previous committed `StatePrimary` but raw `Weight=0`.
5. B immediately elects primary because peer weight is zero.
6. B can finish its transition before A’s negative actuators complete, reopening the two-owner window the new authority design claims to eliminate.

A priority-changing config has the same problem. The committed snapshot must contain the complete election-relevant heartbeat row—at least presence, state, priority, and weight—and all wire-visible mutations must enter transition before those raw fields change. The validation plan needs production heartbeat decode traces paused between raw weight/priority mutation and negative fencing.

2. Last-fabric loss is not linearized against an already-running replacement setup.

The plan makes last-fabric loss special and says no replacement may register during its drain ([plan.md:1644](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1644)). Retirement, however, is deferred through coordinator requests, and an older incarnation request is expressly forbidden from retiring a replacement ([plan.md:1683](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1683), [plan.md:1695](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1695)). Current setup and installation are already separated in time ([sync_conn.go:88](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/cluster/sync_conn.go:88), [sync_conn.go:244](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/cluster/sync_conn.go:244)).

Executable trace:

1. F0 and F1 receive workers both encounter EOF and record retirement for `(E,F0,I0)` and `(E,F1,I1)`.
2. Before the coordinator acquires `s.mu`, an already-admitted F0 setup completes and installs `(E,F0,I2)`.
3. The old F0 request cannot retire I2.
4. The F1 request removes I1, but the registry is no longer empty because I2 exists.
5. No whole-transport drain occurs, so `transportEpoch`, baseline debt, continuity and transport-scoped callback authority survive a real interval in which both original data fabrics were absent.

The proposed tests only assert that old requests cannot close a replacement ([plan.md:3185](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:3185)); they do not test this reconnect-before-coordinator interleaving. Installation needs a retirement-pending veto, or the coordinator must atomically recognize that retirement requests cover every pre-reconnect data incarnation and force whole-transport retirement before accepting I2.

3. The claimed canonical cross-peer digest is not canonical across a real config-sync round trip.

The plan says `SHA-256(canonicalCommittedText)` proves semantic equivalence and that insignificant comments cannot change it ([plan.md:1921](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1921)). It then requires digest equality for Type 29 and bulk admission ([plan.md:1961](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1961), [plan.md:2336](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:2336)).

Production contradicts that premise:

- `Node.Annotation` is a user comment ([ast.go:26](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/ast.go:26)).
- `ConfigTree.Format()` emits annotations into the transmitted hierarchy ([ast_format.go:130](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/ast_format.go:130)).
- The parser discards block comments ([lexer.go:84](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/lexer.go:84), [lexer.go:251](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/lexer.go:251)).
- `SyncApply` parses the received text and promotes the resulting tree ([store.go:634](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/configstore/store.go:634)).

Thus A can hash and send text containing `/* annotation */`, while B’s committed tree re-renders without it. If B instead retains A’s original text only in the in-memory record, a daemon restart reconstructs from the annotation-less persisted tree and changes the digest. Config-sync-disabled reciprocal repair then remains permanently closed despite operationally identical configuration.

The plan needs a precisely defined, separately implemented digest domain that excludes annotations and survives send, parse, persistence, daemon restart, and independent commit. The production-path tests must include annotation-bearing configs, different local generations, config-sync-disabled operation, and restart.

4. `haInventoryTxnMu` has a capture-to-send hole for state-mutating helper requests.

The plan says non-debt requests capture a lease under `haInventoryTxnMu -> Manager.mu`, release both locks, perform helper I/O, and validate only when consuming the response ([plan.md:1221](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1221)). Config promotion separately takes the transaction mutex ([plan.md:1247](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1247)). This cannot establish the later claim that an older helper RPC completes before a newer candidate publishes ([plan.md:2851](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:2851)).

Executable trace:

1. `SetForwardingArmed(true)` captures an old positive lease and pauses before acquiring the control-socket serializer. Its production entrypoint is state-mutating ([manager_status.go:78](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/dataplane/userspace/manager_status.go:78)).
2. A new config acquires `haInventoryTxnMu`, installs debt, promotes and sends its helper work.
3. Alternatively, the helper process restarts at the same socket path.
4. The old request resumes and is delivered after the transition/restart.
5. Rust immediately changes and persists `forwarding_armed` before returning its status ([forwarding.rs:23](/home/ps/git/xpf-worktrees/6744-plan-r12-review/userspace-dp/src/server/handlers/forwarding.rs:23)).
6. Go rejects the stale response, but that cannot undo the helper-side mutation.

The same lifetime problem applies to other status-bearing control writers. The proposed tests pause only after the helper response ([plan.md:3126](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:3126)), too late to expose it.

State-mutating requests need either transaction ownership through the actual write, a closable admitted-request registry drained by config/process replacement, or a helper-enforced process/inventory token. Merely leasing the response is insufficient.

5. Counter-exhaustion recovery is contradictory and incomplete.

The plan says process-scoped counters rotate the process ID at `MaxUint64` ([plan.md:1590](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1590)), while local config allocation is always:

`max(localCounter, committedConfig.epoch.generation)+1`

([plan.md:1935](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1935)).

Executable trace:

1. The current immutable committed record has generation `MaxUint64`.
2. The next commit fails closed and rotates `peerProcessID`.
3. The plan also requires SessionSync replacement to reuse the exact immutable committed record ([plan.md:3196](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:3196)).
4. Under the new process identity, the next allocation still computes `max(..., MaxUint64)+1`; the node can never commit again.

A safe rekey/rebase transaction for the current record is missing. It must drain both fabrics, mint the new process identity, create a generation in the new namespace, re-establish baseline and invalidate every old token atomically.

The exhaustion rule also omits several ABA-sensitive counters used in exact leases: `transitionSerial`, manager authority serial, ownership/authority generations, debt generation, receive/ACK serials and `continuityEventSeq`. There are no explicit fail-on-revert exhaustion traces for these counters.

6. The failover idempotency ledger has no executable bounded-pressure invariant.

The plan promises a “bounded idempotency ledger” for single/batch request and commit callbacks ([plan.md:1728](/home/ps/git/xpf-worktrees/6744-plan-r12-review/docs/research/6744-kimi-review-003/plan.md:1728)), but specifies no capacity, retention duration, eviction order, full behavior, maximum duplicate waiters, or relationship to sender retry deadlines. Current production dispatch launches each request independently ([sync_conn_read.go:397](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/cluster/sync_conn_read.go:397)).

Executable trace:

1. An authenticated peer fills the ledger with distinct completed request IDs.
2. A new request either evicts an old result or must be refused.
3. If eviction occurs, a legitimate retry after lost ACK repeats the ownership mutation.
4. If insertion is refused, no timeout or recovery rule says when progress resumes.
5. Repeated exact duplicates can also attach unbounded waiters unless separately capped.

Because these callbacks change RG ownership, “bounded” without saturation semantics is not implementable safely. The plan needs exact capacity, protected in-flight policy, result-retention horizon, full response, waiter cap, and production-path saturation/retry tests.

## A–M disposition

| Workstream | Disposition |
|---|---|
| A | No additional blocker. The dedicated warning mutex and helper-only access exactly cover the unsynchronized reset and lazy map mutation visible in [daemon_apply.go:238](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/daemon/daemon_apply.go:238) and [daemon_ha_vip.go:222](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/daemon/daemon_ha_vip.go:222). |
| B | No additional blocker. The hard gate is placed before `sortDedupZones` erases empty elements ([types_security.go:486](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/types_security.go:486)) and covers both node-effective compile paths. |
| C | No additional blocker. The plan correctly unifies the currently independent top-level and `system snmp` lowerers ([compiler_dispatch.go:74](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/compiler_dispatch.go:74), [compiler_system.go:512](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/compiler_system.go:512)) and gives intent, secrets, listener lifecycle and malformed typed rows explicit owners. |
| D | No additional blocker. The exact production defect is the literal zero passed despite parsed `extra.icmp_type` ([flowless_verdict.rs:84](/home/ps/git/xpf-worktrees/6744-plan-r12-review/userspace-dp/src/afxdp/poll_descriptor/flowless_verdict.rs:84)). |
| E | No blocker within its expressly limited cross-family fix. Family-specific fingerprint authority, durable co-owner release and post-pass anchor retention are explicit. The separately acknowledged namespace/compound-operation/stale-snapshot research is not silently used as proof. |
| F | No additional blocker. Detached parsing and swap-after-complete-success provide the required atomicity. Terminal interrupt handling is explicitly excluded rather than accidentally promised. |
| G | No additional blocker. Validation at `readTreeMeta`/`ReadConfirm` plus safe local indexing belts covers the corrupt persisted-AST entrypoints. |
| H | No additional blocker. One shared family-expansion cardinality replaces divergence between the current estimator and renderer expansion ([prefix_list_render.go:259](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/frr/prefix_list_render.go:259)). |
| I | Fails on all six blockers above. Its Type 29/56-byte marker shapes, exact ACK comparison, two-fabric barrier membership, deferred-tail ordering, readiness split, source-only ACK routing and mixed-version refusal are otherwise materially specified. |
| J | No additional blocker. The proposed accumulator preserves `parseAddressBookEntries`; current `compileAddressBook` demonstrably replaces the book on each outer container ([compiler_security_addressbook.go:221](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/compiler_security_addressbook.go:221)). |
| K | No additional blocker. The exact transient-error ownership loss is present in both bond and tunnel paths ([bond.go:576](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/routing/bond.go:576), [tunnel.go:1237](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/routing/tunnel.go:1237)); the proposed `isLinkNotFound` classification is sufficient. |
| L | No additional blocker. Normalizing at both decode boundaries addresses the current unconditional `actionName(evt.Action)` derivation ([ringbuf.go:545](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/logging/ringbuf.go:545), [ringbuf.go:931](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/logging/ringbuf.go:931)) and defines every external surface. |
| M | No additional blocker. The pre-lowering shape gate removes the current silent nested fallback ([compiler_security_policy.go:83](/home/ps/git/xpf-worktrees/6744-plan-r12-review/pkg/config/compiler_security_policy.go:83)) with explicit strict, tolerant and peer-effective failure behavior. |

These are architecture and executable-validation gaps, not optional polish. They are repairable without abandoning the overall direction, so the plan does not merit `PLAN-KILL`, but Workstream I cannot be implemented from this document without inventing missing safety invariants.

PLAN-NEEDS-MAJOR