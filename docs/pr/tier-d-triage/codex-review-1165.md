# Codex hostile PLAN review — Tier D issue #1165

Source rollout: `rollout-2026-05-04T23-21-24-019df6cc-65ea-7bc3-8f5e-d3d7ef3d452a.jsonl`

---

**Verdict: PLAN-NEEDS-MAJOR**

Major finding: the KILL rationale overclaims. `OVERSIZED_RX_LOG` and `RX_RST_LOG_COUNT` in [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:2225) are behind `debug-log` and are reached from the per-descriptor loop, but production builds without that feature should compile those bodies out.

`SEG_MISS_LOG` in [dispatch.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/tx/dispatch.rs:366) is different. It is not `debug-log` gated. It sits in `enqueue_pending_forwards`, which is called from the worker forwarding path when `pending_forwards` is non-empty, and the TLS access remains in release for any forwarded frame that reaches `!copied_source_frame && source_frame.len() > 1514`. The logging is capped, but `SEG_MISS_LOG.with(...)` is still the guard used to enforce the cap. So the plan’s statement that “release-build hot path has zero `thread_local!` cost” is false for one of the cited sites.

The issue’s broad “every packet in the 14.8M pps loop” premise does not hold for the poll descriptor TLS blocks, and probably not for normal MTU forwarding. But the dispatch claim is not dead: a release-visible TLS block still exists in a forwarding path, and the triage has not proven it is structurally impossible or operationally irrelevant.

I could not read the live GitHub issue body because `gh issue view 1165 --json title,body` failed with sandbox network denial. This verdict is based on the triage’s quoted claim plus current `origin/master` code at `dab78ef6`.
