# Codex hostile PLAN review — Tier D issue #961

Source rollout: `rollout-2026-05-04T23-49-38-019df6e6-3fca-7c33-9bcb-6844853c2a92.jsonl`

---

Verdict: PLAN-NEEDS-MAJOR

I would reject the triage’s `PLAN-KILL` as written.

Caveat: `gh issue view 961 --json title,body` could not run in this sandbox: GitHub API access failed with `socket: operation not permitted`, and the issue was not publicly readable through browser fallback. So I cannot certify the exact issue-body wording. But current tree evidence is enough to say the triage overkills #961.

Findings:

- The target still exists. `poll_binding_process_descriptor` is still present and still hot-path: [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:31), called from [worker/lifecycle.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/worker/lifecycle.rs:190), and loops per descriptor at [poll_descriptor.rs:52](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:52).
- The repo itself still says #961 tracks the remaining smell after #945: [engineering-style.md](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/docs/engineering-style.md:229). That directly contradicts killing the issue outright.
- The triage is right that the 4-type ownership graph is real and load-bearing: `PendingForwardFrame::{Live, Owned, Prebuilt}` and `PendingForwardRequest` are in [types/tx.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/types/tx.rs:26), `PreparedTxRequest.recycle` / `PreparedTxRecycle` are in [types/tx.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/types/tx.rs:54), and `PendingNeighPacket` is separate in [types/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/types/mod.rs:77). A single typestate `PacketContext<'a>` flattening those would be suspect.
- But that only kills the specific typestate design, not the issue. The prescribed pattern has already partly shipped under narrower names: `WorkerContext` / `TelemetryContext` for passed-through batch context at [types/runtime.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/types/runtime.rs:207), and per-packet `raw_frame` / `packet_frame` reuse at [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:61).

Required plan change: rewrite #961 from “KILL” to “kill the broad typestate PacketContext, keep/retarget the remaining poll descriptor context/scratchpad problem.” The triage needs to distinguish “bad proposed architecture” from “issue no longer valid.”
