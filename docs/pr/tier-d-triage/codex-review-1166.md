# Codex hostile PLAN review — Tier D issue #1166

Source rollout: `rollout-2026-05-04T23-21-24-019df6cc-606c-73d1-92c3-e7c08513e600.jsonl`

---

**Verdict: PLAN-KILL for the triage plan. Do not kill #1166.**

Blocking finding: the triage’s central claim is false. `segment_forwarded_tcp_frames_into_prepared` still exists in [dispatch.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/tx/dispatch.rs:1204), and it runs through line 1484: 281 lines, not a thin adapter. It does not delegate to `frame/tcp_segmentation.rs`; it directly parses, segments, writes UMEM TX frames, drains TX if needed, pushes `PreparedTxRequest`s, and bounds the prepared queue.

The hot-path claim is not fully proven, but it is not safely dismissible. The only call site is inside the per-`PendingForwardRequest` loop in `enqueue_pending_forwards`, gated by `forwarded_tcp_may_need_segmentation` at [dispatch.rs:252](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/tx/dispatch.rs:252). That means the large body is not per every packet, but it is on the oversized non-tunnel TCP forward path, not a debug or rare administrative path.

The shipped extraction is only partial. [frame/tcp_segmentation.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/frame/tcp_segmentation.rs:12) owns the pure `Vec<Vec<u8>>` segmentation builder and is used as the fallback at [dispatch.rs:298](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/tx/dispatch.rs:298). It does not cover the prepared-TX zero-copy path that #1166 names.

Structural note: an exact move to `afxdp/frame/segmentation.rs` is probably the wrong boundary because the remaining function is tightly coupled to TX state and `BindingWorker`. But that argues for a revised plan, likely a `tx`-owned software TSO/prepared segmentation stage, not for killing the issue.

I could not read the live GitHub issue body because `gh issue view 1166 --json title,body` was blocked by the sandbox network policy. The codebase checks alone are enough to reject the triage verdict.
