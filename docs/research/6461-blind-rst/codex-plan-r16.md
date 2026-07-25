PLAN NO

1. **BLOCKER — Worker shutdown destroys the NAT state that reconcile intends to preserve.**

   The concrete lifecycle is:

   1. Reconcile snapshots shared session entries before teardown at [teardown.rs:54](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs:54).
   2. It stops and joins all workers at [teardown.rs:80](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs:80) and [worker_manager.rs:146](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/worker_manager.rs:146).
   3. V9.6 requires worker exit to drain every owned NAT hold; the last release frees the allocation at [plan.md:863](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:863) and [plan.md:880](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:880). The plan also makes last-holder release purge the NAT alias family at [plan.md:1434](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1434).
   4. Bring-up later replays only detached `SyncedSessionEntry` clones through [bringup.rs:421](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:421) and [coordinator/mod.rs:761](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs:761).
   5. V9.6 requires that replayed async upserts re-read the canonical/source alias and verify-and-retain an already-live allocation at [plan.md:831](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:831) and [plan.md:848](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:848). Both proofs are now absent, so [plan.md:892](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:892) requires rejection. Unlike a packet consumer, an `UpsertSynced` command has no packet to re-resolve.

   Therefore an ordinary compatible-config reconcile can free a live flow’s SNAT allocation and fail to restore it. Subsequent traffic can receive a different or reused pool port mid-connection—the exact harm class Part B must prevent. Worse, current replay publishes the BPF entry before workers consume the command at [coordinator/mod.rs:771](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs:771), potentially leaving external state for an entry the worker rejected.

   Reconcile needs explicit hold escrow: transfer one exact hold into `PreservedReconcileState` before joining workers, transfer/retain it into the new worker entries, and release the escrow only after successful replay or conclusive abandonment.

2. **HIGH — The owned-token representation and replacement protocol remain incomplete.**

   V9.6 first requires an owned token carrying exact allocator/allocation identity at [plan.md:862](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:862), then says the entry carries only `nat_hold: bool` at [plan.md:879](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:879). A boolean cannot identify the allocator generation or exact allocation: `NatDecision` contains only rewrite fields at [nat/mod.rs:90](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/mod.rs:90), while today’s release searches the current rule set at [source.rs:761](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:761).

   The plan specifies atomic transfer only for synced upsert at [install.rs:322](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:322). Other removal/replacement paths include fresh-install replacement at [install.rs:139](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:139), explicit deletion at [install.rs:538](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:538), expiry at [expire.rs:322](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/expire.rs:322), and `take_synced_local` at [lookup.rs:407](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:407).

   A concurrent same-entry reap is not the hazard: `SessionTable` is worker-owned and single-threaded at [session/mod.rs:429](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:429). The missing requirement is a linear `Option<NatHoldToken>`-style handoff, with every replacement, rollback, deletion, and existing manual release consuming that token exactly once.

3. **MEDIUM — Probation is architecturally repaired, but its normative prose and tests disagree.**

   Today promotion mutates at resolve time at [session_glue/mod.rs:1238](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1238), with retagging/publication/replication at [promote.rs:86](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs:86), before filtering and TTL admission at [poll_descriptor/mod.rs:592](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:592) and [poll_descriptor/mod.rs:846](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:846). Moving all effects to commit closes the dropped-packet authority path.

   A committed unauthenticated non-close may then clear probation and promote. That does not recreate #6461: it sets no close mark, retains the NAT decision, and refreshes/recomputes the ordinary established idle timeout at [session/mod.rs:1397](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1397) and [session/mod.rs:1430](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs:1430). Any Close is emitted only at normal inactivity expiry.

   But [plan.md:1247](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1247) incorrectly says a blind non-close neither promotes nor refreshes, while [plan.md:1580](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1580) correctly says a later non-close may promote. Tests must distinguish uncommitted non-closes—no clear, refresh, Open, replication, or stamp—from committed non-closes, which clear and may promote exactly once.

4. **MEDIUM — The promised test and contract sweep is still incomplete.**

   Remaining contradictions include:

   - Reverse-synth “reverse-only, later hit” behavior at [plan.md:729](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:729) and [plan.md:1607](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1607), versus atomic forward-family marking at [plan.md:1264](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1264).
   - The obsolete `(origin_node_id, session_id)` Close fence at [plan.md:1627](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1627), versus `(origin_process_nonce, flow_incarnation_id)` at [plan.md:976](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:976).
   - “Required reserve” and “pending #6522” at [plan.md:1685](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1685) and [plan.md:1695](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1695), despite refcount machinery now being mandatory Part B.
   - Phase 2 is both “REQUIRED” at [plan.md:1807](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1807) and explicitly optional at [plan.md:1833](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1833).

5. **LOW — Absolute blind-close wording remains.**

   The Phase-2 brief is now correctly qualified, but unqualified statements remain at [plan.md:992](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:992), [plan.md:1454](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1454), and [plan.md:1844](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1844). These must say refused/out-of-window/no-baseline close; an in-window blind guess remains accepted by design.

6. **LOW — The clarified alias transaction should be made normative in the document.**

   With the clarification that every external delete performs `canonical lock → re-read alias → one syscall delete → unlock`, and detached publications perform the analogous check-and-publish span, the E1/E2 interleavings are safe: whichever operation loses the lock either republishes afterward or observes the replacement incarnation and skips. No global transaction is required.

   The committed text at [plan.md:936](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:936) can still be read as caching the initial alias-delete win as authorization for every later delete. Current republish code deliberately drops the shared lock before its BPF write at [shared_ops.rs:446](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:446). The exact per-operation lock span and adversarial interleaving tests should be written down.

Round-15 dispositions:

- **R15-B1 — resolved.** The canonical alias plus the clarified per-delete/per-publish locked recheck closes the Rust E1/E2 external-map race without a BPF ABI change.
- **R15-B2 — resolved.** Promotion is commit-staged; committed traffic arms only ordinary idle-time cleanup, not an accelerated or unvalidated close.
- **R15-B3 — partially resolved.** Exact-token, reverse-release, scoped-guard, overflow, and normal worker-drain requirements are stated, but reconcile escrow and several token handoffs remain missing.
- **R15-H4 — resolved.** Expected-incarnation checks through tunnel purge, worker deletion, external side effects, and Close processing remove the detached E1 purge race.
- **R15-M5 — partially resolved.** The Phase-2 brief is fixed; three absolute claims remain in the plan.
- **R15-M6 — not resolved.** The stale reverse-synth, fence-tuple, refcount, probation-test, and Phase-2 contracts remain.

Bottom line: Part A remains converged for the fourth review and no blind-demote or probation-based accelerated HA kill survives. Part B still cannot ship because its unconditional worker-drain rule destroys the NAT allocation and aliases that compatible-config reconcile deliberately preserves, making replay fail and reopening mid-connection SNAT port replacement. Add reconcile hold escrow, replace the boolean with a genuinely linear token across every removal/replacement path, and sweep the remaining normative contradictions; until then, PLAN NO.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
