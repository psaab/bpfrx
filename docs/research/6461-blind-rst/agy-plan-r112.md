# AGY hostile plan-review — round 112 (v10.28.0)

Reviewer: AGY (direct binary). Verdict: SOUND.

## Verbatim review

SOUND

### Summary of Consistency Review (v10.28.0)

The round-112 folds in `docs/research/6461-blind-rst/plan.md` (v10.28.0) have been thoroughly reviewed against the codebase at commit `1d906da09e42` (`research/6461-blind-rst`). All design invariants, commit-hook structures, pending-queue mechanics, report contracts, consumer sets, and test vectors were verified.

#### Key Verification Highlights:

1. **Matched-Entry Overdue Test vs. Commit-Hook Structure**
   - The direct matched-entry test (`entry.probation && entry.last_seen_ns.saturating_add(entry.expires_after_ns) <= now_ns`) correctly gates the probation clear+refresh at the commit hook independently of materialization.
   - This prevents phase-shifted direct local hits on overdue probation entries from clearing probation or extending stale timers when `MaterializeReport::NONE` (no shared materialization triggered).

2. **Admission-Point Establishment Promote vs. Pending-Queue Mechanics**
   - In [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:5057-5068`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L5057-L5068), missing-neighbor packets that pass all admission checks (filters, TTL, admission policy) are enqueued to `binding.pending_neigh`.
   - Enqueue to `pending_neigh` is the authoritative commit-to-deliver event for buffered packets. [`userspace-dp/src/afxdp/neighbor_dispatch.rs:272-405`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/neighbor_dispatch.rs#L272-L405) dequeues frames after ARP/NDP resolution and lacks access to `SessionTable`.
   - Performing the establishment promote for a buffered proof-passing SYN-ACK at enqueue time ensures `SessionEntry` establishes without requiring `neighbor_dispatch.rs` to mutate session state, and prevents the forward flow from lingering in `OPENING` when subsequent forward ACK/data packets arrive.

3. **MaterializeReport Total Invariant & Consumer Completeness**
   - The normative invariant `site = None → effective_transition = None`, legal `site-2c T → Some(T)`, invalid `site-2c → Some(OverdueSkipped)`, with `Some(TransitionResult::None)` being unreachable, holds across all producer sites.
   - All 5 consumers (teardown, anchor commit hook, flow-cache insert, probation clear+refresh, ownership promote) correctly handle `OverdueSkipped` and `UpsertRefused` transitions.
   - `OverdueSkipped` and `UpsertRefused` composability in `MissingNeighbor` dispatches correctly routes to the `ExistingResolved` buffer-only arm, avoiding unintended transient seed creation in `install.rs:139`.

4. **Document Consistency Sweep**
   - Version citations across all sections (§1, §3, §5.2, §5.5, §5.6, §5.8, §7, §9, §11) are consistent with v10.28.0.
   - Code line citations match the underlying implementation files and base commit `023f17a606d8` / current master `fff7a4ab5`.

No consistency or soundness defects were found.
