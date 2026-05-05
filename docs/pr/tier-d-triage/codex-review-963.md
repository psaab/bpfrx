# Codex hostile PLAN review — Tier D issue #963

Source rollout: `rollout-2026-05-04T23-20-40-019df6cb-b763-7311-b23c-1650e611ac23.jsonl`

---

Verdict: PLAN-NEEDS-MINOR. The #963 KILL is correct; the doc needs small factual cleanup.

Findings:

1. The cited file is stale. `userspace-dp/src/afxdp/frame.rs` does not exist on current `master`; the function is now in [frame/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/frame/mod.rs:661). The module is already split.

2. The prescribed split already shipped in substance. Current code has `rewrite_prepare_eth`, `rewrite_apply_v4`, and `rewrite_apply_v6` immediately above `rewrite_forwarded_frame_in_place` in [frame/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/frame/mod.rs:481). The hot cached TCP/UDP path is `RewriteDescriptor` plus `apply_rewrite_descriptor`, not a monolithic editor path; see [frame/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/frame/mod.rs:781).

3. The hot-path claim does not hold as a reason to revive #963. The per-packet cached path tries `apply_rewrite_descriptor` first and only falls back to `rewrite_forwarded_frame_in_place` on mismatch/special cases in [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:265). Also, flow cache excludes NAT64/NPTv6 in [flow_cache.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/flow_cache.rs:167).

4. The measured cost is structurally elsewhere. The cross-UMEM copy is the `copy_nonoverlapping` body copy in [frame/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/frame/mod.rs:262), and TX dispatch only permits in-place rewrite when ingress and egress share the same UMEM in [tx/dispatch.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/tx/dispatch.rs:415). An `Ipv4Editor`/`Ipv6Editor` abstraction does not remove that copy.

Minor doc fixes before I’d call the triage section ready:
- `frame/ is now 8 files` is inaccurate as written; current tree has 9 files including tests, or 6 non-test files. Say which count you mean.
- `build_forwarded_frame_into_from_frame() at line 262` should point to the actual copy at lines 267-268, not just the output slice binding.
- Avoid implying `rewrite_forwarded_frame_in_place` is never per-packet. It has per-packet call sites, but they are fallback/gated and not the measured cross-UMEM copy cost.

Caveat: `gh issue view 963 --json title,body` was blocked by the sandbox network policy. I used the checked-in #963 redux design doc, which quotes the issue prescription, plus current `master` code.
