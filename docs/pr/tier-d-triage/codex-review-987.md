# Codex hostile PLAN review — Tier D issue #987

Source rollout: `rollout-2026-05-04T23-20-40-019df6cb-ba91-78a0-9347-b3be54b354fa.jsonl`

---

Verdict on the #987 triage entry: **PLAN-NEEDS-MAJOR**. I reject the current **PLAN-KILL** rationale.

Findings:

- **HIGH:** The coupling premise still holds. `poll_binding` directly reads `binding.xsk.rx.available()` and passes `&mut BindingWorker` into `poll_binding_process_descriptor`; that function directly calls `binding.xsk.rx.receive()` inside the RX batch path. See [worker/lifecycle.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/worker/lifecycle.rs:116) and [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:31).

- **HIGH:** The prescribed pattern has **not** already shipped. `git grep` found no `PacketSource`, `PacketSink`, or `MockDriver` in current code. `WorkerXskRings` is only a structural grouping of concrete AF_XDP ring handles, and its own comment says ring objects, FD lifetimes, and access semantics are unchanged. See [worker/xsk_rings.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/worker/xsk_rings.rs:1).

- **MEDIUM:** The structural constraints are real, but they do not prove the refactor impossible. UMEM ownership is tight (`Rc::get_mut(...).expect("single-owner umem")`), bind returns concrete libxdp `User/RingRx/RingTx/DeviceQueue`, and fill/completion/wake ordering is driver-sensitive. See [umem/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/umem/mod.rs:55), [bind.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/bind.rs:296), and [tx/rings.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/tx/rings.rs:71). That argues against a naive fake driver, not against any HAL boundary.

- **MEDIUM:** The perf argument only kills a performance-motivated HAL claim. The profile does show `__memmove` and RX poll as the costs, not driver dispatch, but `poll_binding_process_descriptor` is itself the RX hot path at 9.45%. See [diagnostic.md](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/docs/pr/778-skb-alloc-zerocopy/diagnostic.md:50). “Cluster smoke already validates” is not a substitute for proving the issue’s testability premise false.

Caveat: `gh issue view 987 --json title,body` was blocked by the sandboxed network (`socket: operation not permitted`), and no local/cache copy of the issue body was present. Based on the triage’s quoted claim and current master code, the #987 section needs a major rewrite: either downgrade to NEEDS-MAJOR with explicit HAL design constraints, or produce stronger evidence that the original issue made a false performance/hot-path claim.
