# Codex hostile PLAN review — Tier D issue #948

Source rollout: `rollout-2026-05-04T23-20-39-019df6cb-b6f1-7372-8a3d-2ed7aed623a3.jsonl`

---

Verdict: **PLAN-NEEDS-MAJOR** for the #948 triage. Do **not** accept `PLAN-KILL` as written.

Findings:

- Major: the triage says `conntrack_v4_fd` is “install-time, not per-packet” and that workers do not call BPF map syscalls. That is overclaimed. `poll_binding_process_descriptor` directly takes `conntrack_v4_fd` in the descriptor-processing function at [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:31), and calls `publish_bpf_conntrack_entry` from the packet loop on session-create/local-miss paths at [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:386). That reaches `libbpf_sys::bpf_map_update_elem` at [bpf_map.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/bpf_map.rs:549). It is not steady-state every-packet, but it is worker-loop, critical-path new-flow/session-install work.

- Major: the “prescribed Mediator already shipped as `mpsc_inbox`” claim is wrong for #948’s control/data-plane boundary. `mpsc_inbox` explicitly backs cross-worker TX redirect, not worker control commands, at [mpsc_inbox.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/mpsc_inbox.rs:1) and [umem/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/umem/mod.rs:407). The worker command path still uses `Arc<Mutex<VecDeque<WorkerCommand>>>` in [types/runtime.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/types/runtime.rs:20), [coordinator/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/coordinator/mod.rs:610), and [session_glue/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/session_glue/mod.rs:286).

- Major: the cited symbol is not stale enough to kill the issue. `userspace-dp/src/afxdp.rs` is gone, but `conntrack_v4_fd` survived in the current worker/poll path. A stale file path would justify correcting the issue, not claiming the premise disappeared.

- Major: no structural impossibility is proven. There is a real ordering constraint: shared sessions are synchronously published to the BPF map before worker command replay to avoid an XDP redirect window, documented at [shared_ops.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/shared_ops.rs:153). That makes a naive async mediator risky, but it does not prove a mediator/refactor is impossible.

The triage can probably be salvaged by citing the stronger #960 syscall audit: BPF syscalls were measured at ~412/s and below the offload threshold. But the current #948 section should be rewritten: “not steady-state per-packet and not worth optimizing based on #960 data” is defensible; “workers do not call BPF syscalls” and “mpsc already shipped for this boundary” are not.
