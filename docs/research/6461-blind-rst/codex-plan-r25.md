PLAN NO

Part A remains converged; no one-packet-anytime blind-demote trace has returned. At commit `2b5b2bbff`, however, Part B still permits concrete authoritative-session and SNAT kills.

1. **BLOCKER — New→legacy suppression exempts ordinary Close deltas, preserving an authoritative-E2 kill.**

   The plan suppresses invalidation/conditional deletes toward unnegotiated peers but explicitly continues plain Close deltas ([plan.md:1221](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1221), [plan.md:1240](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1240), [plan.md:1924](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1924)).

   Brief trace: during dual-primary overlap, legacy B replaces E1 with authoritative same-key E2. New A later emits E1’s legitimate—or documented in-window blind—Close; A’s local owner view passes [daemon_ha_userspace_stream.go:28](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_ha_userspace_stream.go:28), and Close enters the key-only delete path at [daemon_ha_userspace_stream.go:393](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_ha_userspace_stream.go:393). Legacy B ignores the identity tail, reads only generation ([sync_conn_read.go:150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:150)), accepts A’s fresh/non-stale generation ([sync_conn_gen.go:263](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:263)), then key-deletes current E2 and its NAT companions ([sync_conn_gen.go:493](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:493), [session_store.go:537](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/session_store.go:537)). Validation against E1 cannot establish incarnation equality with E2.

   Every incarnation-dependent delete, including Close, must be suppressed toward a receiver lacking identity enforcement.

2. **BLOCKER — INSTALL/Open identity remains an assertion, not a resend-safe pipeline.**

   The summary says INSTALL/Open gains the tail ([plan.md:1692](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1692)), but the operative design specifies only DELETE/Close carriage ([plan.md:1213](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1213), [plan.md:1284](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1284)) and calls BPF-omitted storage “Phase 2’s sidecar” ([plan.md:1297](/home/ps/git/kimi-xpf/.claude/worktrees/6461-blind-rst/docs/research/6461-blind-rst/plan.md:1297)).

   Current code has no identity fields in `SessionDelta`, `SessionValue`, the install codec, or `SyncedSessionEntry` ([entry.rs:283](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/entry.rs:283), [types.go:89](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/types.go:89), [sync_protocol.go:192](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_protocol.go:192), [worker/mod.rs:375](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/mod.rs:375)). Bulk and sweep rebuild installs from detached BPF rows ([sync_bulk.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_bulk.go:95), [sync_conn_sweep.go:142](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_sweep.go:142)), whose projection drops sync-only fields ([bpf_session_value.go:168](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:168)).

   A separate sidecar lookup is not sufficient without atomic row-version linkage: bulk can read E1’s BPF/NAT row, E2 can replace the tuple and sidecar, and bulk can then label E1’s decision with I2. The plan needs a helper-authoritative atomic snapshot or an explicit shared version/recheck contract.

3. **BLOCKER — The claimed stable-logical-policy rewrite is not present at `2b5b2bbff`.**

   The architecture still says the stable identity is a **content-addressed rule hash** ([plan.md:1137](/home/ps/git/kimi-xpf/.claude/worktrees/6461-blind-rst/docs/research/6461-blind-rst/plan.md:1137)); only the test section says `<from>-><to>/<name>` plus distinct content/generation fields ([plan.md:1916](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1916)). The commit’s only change from `7302cf8d4` is the escrow wording reconciliation.

   Concrete trace under the operative algorithm: P2(C) admits NAT flow E; distinct P1(C) is inserted and later deleted. Deletion discovery is logical-name keyed ([policies_ids.go:44](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/policies_ids.go:44)), but projecting P1 to `H(C)` selects E carrying the same hash and an older generation. E is deleted despite P2 still permitting it; final-holder release permits a subsequent pool-port reseed.

   The storage claim is also inconsistent: `install_epoch` is worker-local and rewritten during updates/promotions ([session/mod.rs:761](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:761), [session/mod.rs:1384](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1384)), not a write-once admission generation.

4. **HIGH — The durable escrow fixes its old lifetime race but leaves two SNAT completion gaps.**

   The explicit abandonment supersession is sound ([plan.md:993](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:993)). Two separate cuts remain:

   - When no replay command retained an allocation, the keeper releases ([plan.md:951](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:951)), but the shared family and pre-published BPF row need not be removed. Shared state survives teardown ([coordinator/mod.rs:709](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs:709)); replay publishes before command consumption ([coordinator/mod.rs:761](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs:761)); rejected upserts perform no family cleanup ([upsert_synced.rs:64](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64)). A later materialization sees stale E1 ([session_glue/mod.rs:1157](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1157)); failed retain then re-resolves, potentially changing the live flow’s port.
   - The token owns the exact old allocator ([plan.md:1005](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1005)). A pool rename creates allocator B because the allocator key includes `pool_name` ([source.rs:327](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:327)); retaining E1 in A does not reserve its public tuple in B. Current code explicitly identifies the resulting collision without a current-allocator reservation ([source.rs:829](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:829), [allocator.rs:1617](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1617)).

5. **MEDIUM — The cursor is named but still not implementable as an insertion-order cursor.**

   The index is ordered by `(install_epoch,key)` ([plan.md:1167](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1167), [plan.md:2002](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2002)). Existing `install_epoch` is per-worker and mutable, while `SessionKey` has no order ([key.rs:9](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/key.rs:9)). No coordinator-global immutable sequence, exclusive range cursor, scan-start high-watermark, or replacement rule is specified. The “same lock” analogy is also false today: shared maps have separate mutexes ([session_manager.rs:12](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/session_manager.rs:12)), and owner indexes are updated through another lock ([shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:897)).

6. **LOW — Contract reconciliation remains incomplete.**

   Section 6 still states the HA sync wire is unchanged ([plan.md:1708](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1708)), contradicting Part B’s INSTALL/Open and DELETE tails. The older test still says numeric-ID collision is disambiguated by epoch alone ([plan.md:2010](/home/ps/git/kimi-xpf/.claude/worktrees/6461-blind-rst/docs/research/6461-blind-rst/plan.md:2010)).

### Prior-finding dispositions

| Finding family | Disposition |
|---|---|
| r21-B1 policy selector | **partially resolved** |
| r22-c; r23-3/r23-d; r24-B4 policy selector | **not resolved** |
| r21-B2; r22-a; r23-1/r23-c; r24-B2 install identity | **not resolved** |
| r21-B3; r22-b; r23-2/r23-a; r24-B1 mixed-version delete | **partially resolved** — invalidation suppression is added, Close remains |
| r21-H4; r22-d; r23-4/r23-b; r24-B3 escrow lifetime/permit race | **resolved as originally framed** — Finding 4 identifies new completion/domain gaps |
| r21-H5 fence tuple | **resolved** |
| r21-M6; r22-e; r23-5; r24-M5 cursor | **partially resolved** |
| r21-M7; r22-f; r23-6; r24-L6 contract sweep | **partially resolved** |
| Deferred to Phase 2 | **none** |

Part A still eliminates the original one-packet-anytime blind demotion. Final sign-off nevertheless fails: a plain Close can still cross a new→legacy link and ABA-delete authoritative E2, the receiver identity fence lacks a replacement- and resend-safe INSTALL pipeline, and the pinned commit does not contain the claimed logical-policy rewrite. The remaining escrow gaps add independent SNAT-reseed/collision cuts. No files were edited.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
