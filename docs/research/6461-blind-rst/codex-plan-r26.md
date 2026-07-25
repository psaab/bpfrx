PLAN NO

Review pinned to requested commit `413979104`. The worktree later advanced independently to `bd6bf429`; that cursor-only precision fold does not resolve the findings below. No files were edited. Part A remains converged.

1. **BLOCKER — INSTALL/Open identity and the atomic resend snapshot are still absent from the operative design.**

   The plan normatively defines only the DELETE identity tail and Close pipeline ([plan.md:1259](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1259), [plan.md:1338](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1338)); INSTALL/Open appears only in summary text ([plan.md:1746](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1746)). There is no helper API, sender/receiver store lifecycle, or atomic `(row, identity)` snapshot contract.

   Current bulk and periodic resend detach BPF rows at [sync_bulk.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:95) and [sync_conn_sweep.go:142](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_sweep.go:142); the BPF projection drops sync-only fields ([bpf_session_value.go:168](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:168)). `SessionDelta`, `SessionValue`, and `SyncedSessionEntry` likewise lack the pair ([entry.rs:283](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:283), [types.go:89](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/types.go:89), [worker/mod.rs:375](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs:375)).

   ABA trace: bulk captures E1’s row; E2 replaces the tuple and identity; a later sidecar lookup returns I2; the sender emits E1’s stale NAT decision labelled I2. The receiver can then install stale translation under E2’s identity or accept an I2 delete against it. The claimed atomic snapshot was supposed to close exactly this trace, but it is not in the plan.

   **Disposition — r25-B2: not resolved.**

2. **BLOCKER — Legacy suppression is neither connection-epoch-safe nor internally consistent.**

   The main rule now correctly suppresses every incarnation-dependent delete, including Close ([plan.md:1268](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1268)). But §9 still requires plain Close deltas to continue to legacy peers ([plan.md:1983](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1983)).

   Even following the main rule leaves a reconnect trace. Deletes are opaque `[]byte` queue/journal entries ([sync.go:467](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync.go:467), [sync_conn_write.go:114](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:114)). `sendLoop` retries an already-dequeued frame on whichever connection becomes active, without a send-time capability check ([sync_conn_write.go:268](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go:268)). Thus an E1 Close admitted while B was capable can cross after B reconnects as legacy and installs authoritative same-key E2; legacy B ignores identity and key-deletes E2 and its NAT companions.

   The cited handshake also carries no feature set and runs only when a PSK is configured ([sync_auth.go:321](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go:321), [sync_auth.go:345](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go:345)). Queue entries need a `requires_identity_enforcement` class checked against the exact connection at every write/replay.

   **Disposition — r25-B1: partially resolved.**

3. **BLOCKER — Per-command rejection cleanup deletes a successfully installed sibling replica.**

   The plan says “a REJECTED replay command” removes the shared family and pre-published BPF row ([plan.md:953](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:953)). But replay publishes once and fans the same entry to every worker ([coordinator/mod.rs:770](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs:770), [session_glue/mod.rs:838](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:838)).

   Mixed-outcome trace: W0 installs E1, retains its hold, and publishes successfully ([upsert_synced.rs:64](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64)); W1 rejects. W1’s cleanup carries the same incarnation, so alias fencing passes and deletes the common family/BPF row underneath W0’s live entry. Cleanup must occur only after the final outcome and only when `installed_count == 0`; an individual rejection may only decrement pending accounting.

   **Disposition — r25-H4a: partially resolved.**

4. **HIGH — The pool-generation fold is absent, and its advertised fallback would itself permit a port swap.**

   The plan’s only allocator identity remains the exact old `Arc<PortAllocator>` handle ([plan.md:1018](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1018)); no pool-generation field or migration rule appears.

   `SourceNatPoolAllocatorKey` includes `pool_name` ([source.rs:327](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:327)), and allocator reuse requires exact-key equality ([source.rs:549](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:549), [source.rs:726](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:726)). A name-only rename therefore creates B although the public collision domain and E1 translation are unchanged. Holding E1 only in A leaves B free to assign E1’s public tuple to another flow—the collision current reservation code exists to prevent ([source.rs:829](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:829), [allocator.rs:1617](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1617)). Invalidating E1 and re-resolving can then choose another port mid-connection.

   Compatible allocator changes require migration/reservation of the exact tuple into B before releasing A, using collision-domain compatibility rather than pool name.

   **Disposition — r25-H4b: not resolved.**

5. **HIGH — Policy identity semantics are corrected, but the historical stamp has no end-to-end home.**

   Stable `<from>-><to>/<name>` plus write-once `admission_fwd_generation` is the correct selector ([plan.md:1150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1150)). However, selection runs over shared aliases, while the stated shared schema adds only clock/incarnation fields ([plan.md:1750](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1750)). `SyncedSessionEntry` carries neither policy field ([worker/mod.rs:375](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs:375)).

   The text promises admission and generation from one forwarding snapshot, but cites the generation that currently lives in separately published `ValidationState`; coordinator and worker ordering permits old-validation/new-forwarding observation ([snapshot_refresh.rs:397](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:397), [loop_body/mod.rs:462](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:462)). On a modified-rule invalidation, a newly admitted E2 can therefore carry the old generation and satisfy the historical delete predicate.

   The design must add generation to `ForwardingState`, stamp both selector fields into local/shared/imported entries, and define their install/import carriage.

   **Disposition — r25-B3: partially resolved.**

6. **MEDIUM — The cursor has two incompatible normative definitions.**

   The main design now uses a coordinator-global immutable insertion sequence, but §9 still mandates `(install_epoch, key)` ([plan.md:2061](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2061)). `install_epoch` is worker-local and rewritten on mutation ([session/mod.rs:761](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:761), [session/mod.rs:1384](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1384)); `SessionKey` has no ordering ([key.rs:9](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs:9)). The acceptance test therefore still requires the rejected, non-stable cursor.

   **Disposition — r25-M5: partially resolved.**

### Prior-finding dispositions

| Findings | Disposition |
|---|---|
| r21-B1; r22-c; r23-3/r23-d; r24-B4; r25-B3 — policy selector/stamp | **partially resolved** |
| r21-B2; r22-a; r23-1/r23-c; r24-B2; r25-B2 — install identity | **not resolved** |
| r21-B3; r22-b; r23-2/r23-a; r24-B1; r25-B1 — mixed-version deletes | **partially resolved** |
| r21-H4; r22-d; r23-4/r23-b; r24-B3 — original permit/escrow lifetime | **resolved as originally framed** |
| r21-H5 — fence tuple | **resolved** |
| r21-M6; r22-e; r23-5; r24-M5; r25-M5 — live cursor | **partially resolved** |
| r21-M7; r22-f; r23-6; r24-L6; r25-L — contract reconciliation | **partially resolved** |
| r25-H4a — rejected-command cleanup | **partially resolved** |
| r25-H4b — allocator-domain/pool-generation fence | **not resolved** |
| Deferred to Phase 2 | **none** |

### Bottom line

Part A still removes the original one-packet-anytime blind-demotion channel. Part B is not signable: the resend-safe install identity pipeline claimed for v9.9.10 is absent; queued Close frames can cross a capability downgrade and delete authoritative E2; per-command rejection cleanup can remove a successfully replayed flow; and the allocator-change contract retains a concrete SNAT collision/port-swap trace. These are implementation-blocking named-harm paths, not Phase-2 preferences or documented residuals.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
