# Codex hostile PLAN review — Tier D issue #1189

Source rollout: `rollout-2026-05-04T23-21-29-019df6cc-745f-73b1-971f-6a33a4dee945.jsonl`

---

**Verdict: PLAN-NEEDS-MAJOR**

The triage should not support PLAN-KILL or “close/downgrade” for #1189. The exact “3,000-line monolith” number is stale, but the issue’s substance still holds: `Coordinator` still exists, [coordinator/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/coordinator/mod.rs:17) is still 1959 LOC, and most behavior remains there.

Key findings:

- The cited file/symbol still exists. `Coordinator` owns `BpfMaps`, HA, CoS, neighbor/session/worker state, forwarding state, event stream, slow path, RG epochs, and panic slots in one struct at [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/coordinator/mod.rs:17).
- The manager pattern has only partially shipped. `WorkerManager`, `NeighborManager`, and `SessionManager` exist, but they are thin state containers with only `new()` methods, e.g. [worker_manager.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/coordinator/worker_manager.rs:13) and [session_manager.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/coordinator/session_manager.rs:12). `ConfigManager` does not exist.
- The config/snapshot work that a `ConfigManager` would own is still in `Coordinator`: [refresh_runtime_snapshot](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/coordinator/mod.rs:916), CoS runtime refresh, forwarding rebuild, validation update, and HA publication are all coupled there.
- This is not a packet hot-path refactor. Coordinator calls are control-plane/server driven, e.g. [handlers.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/server/handlers.rs:53) and [helpers.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/server/helpers.rs:253). Packet work is in `worker_loop`, which receives shared state Arcs at [worker/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/worker/mod.rs:445).
- Structural constraints make a naive split risky, but not impossible. `reconcile` crosses BPF maps, worker planning, session replay, forwarding, HA, CoS, neighbor monitor startup, tunnel sources, event stream, and status refresh in one flow, especially [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/coordinator/mod.rs:549). That argues for a scoped redesign, not closure.

So the corrected triage should say: stale line count, partially decomposed already, but the issue remains valid as NEEDS-MAJOR. Remove “could close” / “good first issue” language and require a concrete rescope, likely one domain slice first, with invariants and tests.

Review limitation: `gh issue view 1189 --json title,body` was blocked by sandbox networking, and the issue was not visible via public web search. I verified the claims exposed in the triage and prompt against local `origin/master` at `dab78ef6`; relevant coordinator structure matches local `master` at `4d3c0964`.
