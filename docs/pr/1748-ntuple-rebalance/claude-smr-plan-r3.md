# Claude-SMR r3 — #1748 plan v3 @ 0f52cc85b

**Verdict: PLAN-READY (with one implementation requirement, below).**
v3's two-origin transfer closes every verified round-2 finding. Codex + AGY r3
pending; this is my pass.

## Round-2 findings → v3 resolution (all closed)
- **Conntrack 5th site (Codex#1/AGY)** → AGY's early-return guard at the top of
  `delete_session_map_entry_for_removed_session_with_origin` covers redirect +
  conntrack in one place. ✓
- **Never-cleanup leak (Codex#2)** → `RebalancedOwner` on W_new
  (`is_peer_synced()`=false) emits Close on real expiry and owns shared-map +
  conntrack + broadcast + SNAT cleanup. Exactly one owner. ✓
- **HA/export marker leak (Codex#3)** → `RebalancedOut` excluded from
  `demote_owner_rg`/`refresh_owner_rgs`/peer-export/delta-sync. ✓
- **UAPI** → exact AGY-verified layout as compile-time offset asserts +
  round-trip test. ✓

## The promote/demote race (item 3) — SAFE, given an ordering requirement
Sequence: (2) promote W_new→`RebalancedOwner`, (3) demote W_old→`RebalancedOut`,
(4) install rule. Why no two-owner/zero-owner hazard:
- **Per-worker loop serialization**: `WorkerCommand`s and `expire_stale_entries`
  both run in the *same* single-threaded worker loop. On W_old, `DemoteRebalanced`
  is processed before any subsequent GC tick observes the entry → GC always sees
  `RebalancedOut`, never a stale `ForwardFlow`. On W_new, `PromoteRebalanced` is
  processed before the rule install routes packets there.
- **Zero-owner impossible**: W_old remains an owner (`ForwardFlow`) until step 3;
  W_new becomes an owner at step 2 — so ≥1 owner at all times, briefly 2.
- **Transient two-owner is harmless**: between step 2 and 3 both entries would
  only act *on expiry*; neither expires in the sub-tick window (W_old is still
  actively refreshed — the rule isn't installed until step 4; W_new was just
  promoted). No double-cleanup.

**Implementation requirement (NEEDS-MINOR, fold into §4.5):** the controller MUST
issue promote(W_new) + demote(W_old) + rule-install within a single rebalance
tick, and the design MUST assert `rebalance_interval` (and the move sequence
duration) ≪ `SESSION_GC_INTERVAL_NS` so no GC sweep interleaves the transfer.
State this ordering+timing invariant explicitly; do not leave it implicit.

## Residual to watch at code-review time (not plan-blocking)
- `RebalancedOwner` must be reachable by `demote_owner_rg` on a real RG failover
  (it IS a local owner that should demote to `SyncImport` like `ForwardFlow` when
  its RG goes inactive) — i.e. RebalancedOwner is excluded from the *rebalance*
  suppression but NOT from normal HA demotion. Only `RebalancedOut` is the
  inert/excluded origin. Verify the two variants get opposite treatment in the
  HA paths.
- The promote tag-flip must touch ONLY `origin` — no re-publish, no NAT
  re-resolve. A unit test should assert the SNAT allocation refcount/owner is
  unchanged across promote.

Net: architecture is sound and now complete. Proceed to implement once Codex +
AGY r3 concur, folding the single-tick ordering invariant into §4.5.

---
## SELF-CORRECTION (post Codex r3)
My race analysis above was WRONG. I claimed "per-worker loop serialization"
makes the promote/demote ordering safe — but that only serializes commands vs GC
*within one worker*. The two commands go to TWO independent per-worker queues
(`loop_body/mod.rs:591`), with no cross-worker ordering. Codex correctly showed
W_old can demote before W_new promotes → a real zero-owner window. The fix is an
applied-command barrier (ack between promote and demote), now in v4 §4.5. This
is exactly the SMR-soft-pass → Codex-catches-real-race pattern the methodology
guards against; recording it.
