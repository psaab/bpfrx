v3 is directionally correct. The fix is now aimed at the real blocker. I would not send it to implementation unchanged, but the remaining issues are specification holes, not a dead architecture.

**Q1 Rate Safety**

For hard-cap exact guarantee queues, the raised bucket watermark is rate-safe in the long run. The local bucket is filled through `maybe_top_up_cos_queue_lease`; for nonzero exact queues it requires a shared queue lease and grants only through `acquire_via_lease` [token_bucket.rs:180](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/token_bucket.rs:180), [token_bucket.rs:191](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/token_bucket.rs:191). The v8 grant path is bounded by epoch cap, class room, and worker share [shared_cos_lease/mod.rs:1041](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1041), [shared_cos_lease/mod.rs:1092](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1092), with cap published as `rate * min(elapsed, 200us)` [rotate_epoch_v8.rs:215](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:215). Sends debit actual bytes from both local queue tokens and the shared queue lease [tx_completion.rs:676](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/tx_completion.rs:676), [tx_completion.rs:719](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/tx_completion.rs:719).

Caveats to write into the plan: transparent queues bypass rate metering when `transmit_rate_bytes() == 0` [token_bucket.rs:167](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/token_bucket.rs:167), and exact `surplus_sharing` queues intentionally bypass the per-queue exact lease in Surplus phase [queue_service/mod.rs:1118](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/queue_service/mod.rs:1118), [tx_completion.rs:343](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/tx_completion.rs:343). Gate 4 must say “hard-cap exact guarantee traffic,” not every possible CoS queue.

**Q2 Deficit Field**

A separate `guarantee_deficit_bytes` is unnecessary if P2 really removes the quantum byte clamp. Once `queue.hot.tokens` can bank above one epoch and completion debits actual sent bytes, the sub-MTU remainder stays in `queue.hot.tokens` instead of being discarded [token_bucket.rs:197](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/token_bucket.rs:197), [tx_completion.rs:512](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/tx_completion.rs:512). The current loss is because selectors clamp to `cos_guarantee_quantum_bytes()` [queue_service/mod.rs:879](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/queue_service/mod.rs:879), [queue_service/mod.rs:985](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/queue_service/mod.rs:985), [queue_service/mod.rs:1064](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/queue_service/mod.rs:1064), while drain stops on whole-frame budget exhaustion [drain.rs:69](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/queue_service/drain.rs:69).

**Q3 N=8**

N=8 is a sane starting point for 100m. It gives about 32 KiB, roughly 13 epochs of 100m credit, and should eliminate the one-frame-per-epoch pathology without changing sustained rate. It should not overdeliver 1g in steady state because grants are still rate-metered; it only increases burst tolerance.

Minor required fix: the plan must account for `max_total_leased`. Today that cap is computed from the old `lease_bytes.max(tx_frame_capacity()) * active_shards` [shared_cos_lease/mod.rs:712](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:712), [shared_cos_lease/mod.rs:713](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:713), and v8 refuses grants above that outstanding cap [shared_cos_lease/mod.rs:1510](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1510). If implementation only raises the local token-bucket watermark, single-shard or low-shard cases can still be capped below the intended bank. Either update the shared lease config cap or explicitly prove the cluster’s `active_shards` makes the effective cap sufficient.

`TX_BATCH_SIZE=64` is acceptable as the hard per-visit frame bound; all drain loops stop at that count [afxdp/mod.rs:225](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/mod.rs:225), [drain.rs:56](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/queue_service/drain.rs:56), [drain.rs:189](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/queue_service/drain.rs:189).

**Q4 Non-Exact**

P2 covers non-exact guarantee queues: they accumulate via `refill_cos_tokens` [queue_service/mod.rs:1033](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/queue_service/mod.rs:1033), then lose efficiency only because the selector clamps to the guarantee quantum [queue_service/mod.rs:1064](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/queue_service/mod.rs:1064). But best-effort/uncapped surplus traffic is a separate surplus-deficit path [queue_service/mod.rs:1147](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/queue_service/mod.rs:1147), [queue_service/mod.rs:1157](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/cos/queue_service/mod.rs:1157). Do not claim P2 “fixes q0/q11” unless they are actually non-exact guarantee queues in the fixture.

**Q5 Path B**

Rejecting Path B is valid. Rotation currently deliberately resets epoch grant counters [rotate_epoch_v8.rs:53](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:53), [rotate_epoch_v8.rs:61](/home/ps/git/bpfrx/.claude/worktrees/1630-research-cos-equalize-rootcause/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:61). You do not need to carry rotation state if local `queue.hot.tokens` can carry already-granted credit across epochs. That is exactly what a token bucket burst window is for.

Remaining changes before implementation: add the `max_total_leased` sizing requirement, scope Gate 4 to hard-cap exact guarantee traffic, and clarify that P2 covers non-exact guarantee, not surplus q0/q11 behavior.

VERDICT: PLAN-NEEDS-MINOR

---

## Codex r3b confirmation pass on v3.1 (session 019e7012-f58f-78f3-9047-98f4d034e05c)

All three r3 minors (max_total_leased sizing, Gate 4 scope to hard-cap
exact, non-exact-vs-surplus clarity) confirmed resolved in v3.1.

VERDICT: PLAN-READY
