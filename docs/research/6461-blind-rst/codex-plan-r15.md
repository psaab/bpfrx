PLAN NO

All plan references are to v9.5 at `65d79ce40`.

1. **BLOCKER — The external-map incarnation fence has neither storage nor atomic update semantics.**

   V9.5 says conntrack gains `flow_incarnation_id` in a “spare field,” with old Go decoders ignoring it ([plan.md:909](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:909)). No such field exists:

   - Rust’s v4/v6 values are exact 136/184-byte C mirrors ([bpf_map/mod.rs:144](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:144), [bpf_map/mod.rs:195](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:195), [bpf_map_tests.rs:190](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map_tests.rs:190)).

   - The C layouts end at `fib_gen`; their seven padding bytes are separate 1/2/4-byte alignment gaps, not a spare `u64` ([xpf_conntrack.h:17](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/bpf/headers/xpf_conntrack.h:17), [xpf_conntrack.h:82](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/bpf/headers/xpf_conntrack.h:82)).

   - Go derives the production map value size from that exact ABI and explicitly models every padding byte ([bpf_session_value.go:5](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:5), [bpf_session_value.go:59](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:59)). The cited precedent says `Generation` is not stored in BPF and is reconstructed as zero ([bpf_session_value.go:204](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:204)); it does not permit an appended field. A larger map value copied into an old smaller buffer is explicitly documented as an out-of-bounds write ([bpf_session_value.go:39](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:39)).

   This also contradicts “no shim/meta change, no `make generate`” at [plan.md:1333](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1333).

   Independently, the publish rule—write only when the slot is absent or already has the same incarnation ([plan.md:919](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:919))—rejects the legitimate E2 replacement while stale E1 remains. E2 then publishes canonical state, E1 later deletes its old external slot, and live E2 is left without userspace redirection.

   Relaxing the rule does not solve atomicity: publication uses `BPF_ANY`, while deletion is key-only ([publish_conntrack.rs:142](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs:142), [bpf_map/mod.rs:321](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:321)). E1 can lookup-match, E2 overwrite, then E1 delete E2. The redirect map stores only a one-byte action ([bpf_map/mod.rs:48](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:48)); DNAT values also lack incarnation ([xpf_maps.h:508](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/bpf/headers/xpf_maps.h:508), [xpf_maps.h:578](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/bpf/headers/xpf_maps.h:578)).

   `ExpiredSession` carrying an ID is necessary but insufficient. Part B needs either a coordinated map-ABI migration plus serialized replacement/deletion, or a process-wide incarnation sidecar/lock spanning redirect, conntrack, DNAT, and canonical publication.

2. **BLOCKER — Probation still permits a two-packet HA-authority promotion.**

   The periodic-push repair itself is sound: probation is explicit, skipped by the batch, and cannot lower the family timeout ([plan.md:1264](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1264)). But ownership promotion remains pre-commit.

   Brief trace:

   1. A refused no-baseline close materializes an alive `SharedMaterialize` probation entry.

   2. A later non-close reaches `maybe_promote_synced_session` during resolution ([session_glue/mod.rs:1238](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1238)). The helper immediately retags it `SharedPromote`, refreshes it, republishes shared state, replicates it, and emits an Open ([promote.rs:99](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:99), [promote.rs:131](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:131), [session/mod.rs:1480](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1480)).

   3. Final admission can still reject that packet afterward, including the TTL check at [poll_descriptor/mod.rs:846](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:846).

   4. By the plan’s own analysis, the `SharedPromote` flip arms Close authority at natural reap ([plan.md:684](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:684)). The resulting same-incarnation Close validly passes the new fences and deletes the shared/standby family.

   V9.5 simultaneously says non-closing promotion remains “exactly as today” ([plan.md:1200](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1200)) and calls it committed at [plan.md:1404](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1404). The concrete mechanics follow the former. Probation must suppress or stage ownership promotion, Open emission, replication, and every family-clock stamp until the successful dispatch commit clears probation.

3. **BLOCKER — `nat_hold: bool` does not define a complete holder lifecycle.**

   The atomic exact-tuple retain itself is implementable under the allocator’s existing `shared.live` mutex ([allocator.rs:1324](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1324), [allocator.rs:1664](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1664)). The ownership model around it is incomplete:

   - `upsert_synced_with_origin` unconditionally remove/replaces the prior entry ([install.rs:322](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:322)). Retaining the new copy while discarding the old `nat_hold` leaks one reference per refresh. Releasing the old hold first creates the release/reuse race the retain was meant to prevent. An atomic transfer is required.

   - Common removal returns an entry, but many callers discard it, and `SessionTable` has no allocator handle ([session/mod.rs:1746](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1746)). Worker exit drops the table without draining holders ([loop_body/mod.rs:1428](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1428)).

   - Embedded-ICMP consumers are one-shot decisions with no `SessionEntry` or reap, yet v9.5 includes them in mandatory verify-and-retain ([plan.md:832](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:832)). A durable boolean leaks per packet; read-only verification restores the release/reuse race.

   - A synthesized reverse holder cannot use the current release path, which returns immediately for reverse entries ([source.rs:789](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:789)).

   Part B needs an owned hold token containing exact allocator/allocation identity, scoped guards for one-shot users, retain-before-replace plus transfer/rollback semantics, explicit release for every non-reap deletion and worker drain, and checked refcount overflow. The required #6522 fence is not implementable from the stated boolean-plus-reap contract.

4. **HIGH — A detached control-plane purge still key-deletes a replacement incarnation.**

   Runtime tunnel-remap cleanup snapshots E1 keys/deltas under the shared lock, releases it, then deletes by key later ([tunnel_purge.rs:24](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/tunnel_purge.rs:24), [tunnel_purge.rs:77](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/tunnel_purge.rs:77)). During an armed runtime refresh, a worker can publish same-key E2 between those operations. `delete_synced_session` treats helper-local deletion as authoritative and unconditional ([session_import.rs:227](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:227)), re-reads the current entry, and deletes it and its external/shared companions ([session_import.rs:243](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:243), [session_import.rs:264](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:264)).

   The purge must carry E1’s `flow_incarnation_id` and compare-delete every side effect. It is absent from v9.5’s expanded detached-consumer inventory.

5. **MEDIUM — Absolute security wording still survives.**

   The qualified claim at [plan.md:1767](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1767) is correct. Unqualified “blind close remains inert/never marks” wording remains at [plan.md:963](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:963), [plan.md:1797](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1797), and [phase2-brief.md:14](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/phase2-brief.md:14). Those claims must remain limited to refused/out-of-window/no-baseline closes.

6. **MEDIUM — The normative test/scope contract remains internally inconsistent.**

   Reverse-synth atomic forward marking is now correctly specified and tested at [plan.md:1183](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1183) and [plan.md:1628](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1628), but old prose/test text still says reverse-only marking followed by next-hit propagation ([plan.md:729](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:729), [plan.md:1566](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1566)).

   Other stale contracts remain:

   - The old Close tuple `(origin_node_id, session_id)` at [plan.md:1586](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1586).

   - Obsolete Phase-2 implementation tests at [plan.md:1592](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1592).

   - Phase 2 simultaneously required and deferred/not required ([plan.md:1762](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1762), [plan.md:1788](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1788)).

   - Part-B tests still call the old reserve required and #6522 pending, contradicting v9.5’s required refcount ([plan.md:1640](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1640), [plan.md:1650](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1650)).

   The `expires_after_ns` schema correction itself is resolved at [plan.md:1333](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1333).

### Round-14 dispositions

R14-B1, destructive reserve is not an ownership fence — **partially resolved**. Atomic exact verify-and-retain is viable, but the holder lifecycle and one-shot/reverse forms are incomplete.

R14-B2, stale-E1 immediate/external cleanup — **not resolved**. `ExpiredSession` identity is folded, but the claimed map field and atomic external transaction do not exist, and the write predicate rejects E2.

R14-H3, detached-consumer coverage — **partially resolved**. Alias-plus-canonical comparison and the named packet/prewarm consumers landed; tunnel-remap purge remains unfenced.

R14-H4, probation clock push — **partially resolved**. Batch exclusion and monotone timeout landed; pre-commit ownership promotion still stamps and arms authority.

R14-M5, absolute wording — **partially resolved**.

R14-M6, reverse-synth/schema/test/Phase-2 consistency — **partially resolved**. The schema and newer reverse-synth contract are corrected; stale contradictory contracts remain.

Part A’s sequence-validation gate remains converged; I did not reopen its acceptance mechanics or require Phase 2. V9.5 Part B still fails confirmation because stale external cleanup cannot be incarnation-atomic with the specified maps, probation can be promoted into authoritative HA state before packet commit, and the required NAT refcount has no complete ownership lifetime. Those include a concrete same-incarnation HA Close path and a concrete E1/E2 external-state loss path, so the plan remains `PLAN NO` until the external-map transaction, commit-staged probation promotion, owned NAT-hold lifecycle, and remaining detached purges are made normative and testable.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
