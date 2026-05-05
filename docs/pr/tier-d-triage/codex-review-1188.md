# Codex hostile PLAN review — Tier D issue #1188

Source rollout: `rollout-2026-05-04T23-21-24-019df6cc-6926-7df0-826a-f8fe744b457b.jsonl`

---

**Verdict: PLAN-NEEDS-MAJOR**

Reject the triage’s `KILL` for #1188. Its central factual claim is wrong against `master@4d3c096`.

Findings:

- `RuntimeSnapshot` does not exist, but the cited symbols do: `BindingWorker` and `worker_loop()` are live in [worker/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/worker/mod.rs:445).
- `worker_loop()` loads multiple `ArcSwap`s every loop iteration: validation, forwarding, five CoS maps, HA runtime, and fabrics. See [worker/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/worker/mod.rs:721), [worker/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/worker/mod.rs:738), [worker/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/worker/mod.rs:801), [worker/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/worker/mod.rs:908). That is at least the issue’s “up to 8” claim; current code is arguably 9.
- The triage is only partially right that this is not inside the per-descriptor loop. `poll_descriptor.rs` receives already-loaded snapshots/references via `validation` and `WorkerContext`, see [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/poll_descriptor.rs:31) and [runtime.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/types/runtime.rs:218).
- But “binding-poll cadence (~10-100 Hz)” is not defensible. `poll_binding` is called once per binding per worker-loop iteration, and busy-poll active iterations immediately `continue`; max RX work is `4 * 64 = 256` packets per binding poll, not a 10-100 Hz timer. See [worker/lifecycle.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/worker/lifecycle.rs:1) and [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/mod.rs:173).
- The prescribed pattern has not already shipped. `WorkerContext` bundles borrowed snapshots after the loads; `HaState` and `SharedCoSState` group fields but still expose separate `ArcSwap`s. See [ha_state.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/coordinator/ha_state.rs:3) and [cos_state.rs](/home/ps/git/bpfrx/.claude/worktrees/867-ack-ip-sweep/userspace-dp/src/afxdp/coordinator/cos_state.rs:3).

There are real structural constraints: CoS map changes have separate side effects, lease releases, and rebuild triggers, so a single `RuntimeSnapshot` plan must preserve per-field identity/change detection. That makes this a major design problem, not an impossible or already-solved one.

Note: `gh issue view 1188 --json title,body` was blocked by the sandbox network policy, so I reviewed the quoted issue claim from the triage plus `master` code directly.
