Verdict for #966: **PLAN-KILL**.

Findings:

- The issue premise does not survive code inspection. There is no per-packet 10K-rule scalar classifier. BPF policy lookup is a flat `BPF_MAP_TYPE_ARRAY` keyed by `from_zone * MAX_ZONES + to_zone`, then a bounded `policy_rules` array walk: [xpf_maps.h](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/headers/xpf_maps.h:182), [xdp_policy.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/xdp/xdp_policy.c:1234), [xdp_policy.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/xdp/xdp_policy.c:1295). DPDK uses `rte_hash` for the zone pair, then `ps->num_rules`: [policy.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/dpdk_worker/policy.c:165). Userspace AF_XDP uses `FxHashMap<ZonePairKey, Vec<usize>>`, not all-rules scan: [policy.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/policy.rs:187), [policy.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/policy.rs:287).

- There are real policy callsites, but they are miss/new-flow paths, not the steady packet path. BPF tail-calls policy on conntrack miss: [xdp_conntrack.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/xdp/xdp_conntrack.c:999). DPDK calls `policy_check` only for `CT_NEW`: [pipeline.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/dpdk_worker/pipeline.c:166). Userspace checks the flow cache before “session lookup + policy + NAT + FIB”: [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/afxdp/poll_descriptor.rs:138), and calls `evaluate_policy` on miss paths: [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/afxdp/poll_descriptor.rs:991), [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/afxdp/poll_descriptor.rs:1929).

- The ≥2% perf bar is not met. The fresh data names `memmove`, RX poll, TX dispatch, BPF hash probe, and SKB fallback. No policy symbol appears. Rust inlining could hide a small amount inside `poll_binding_process_descriptor`, but the call frequency makes a sustained P=12 reverse TCP workload the wrong shape for policy classification to dominate.

- The plan doc needs a small correction before it is used as close rationale: §3 says BPF `zone_pair_policies` is a hash and “current default ~32-64”; in this checkout it is an array, and `MAX_RULES_PER_POLICY` is `256`: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/docs/pr/simd-triage/plan.md:55), [xpf_common.h](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/headers/xpf_common.h:142), [types.go](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/pkg/dataplane/types.go:349). That weakens the issue, not the kill case.

Implementation cost is unjustifiable for xpf’s target. SIMD bit-vector/TSS would need new rule compilation, update invalidation, CPU dispatch/fallback, global-rule ordering, hit counters, IPv4/IPv6 prefix semantics, and app matching correctness. The existing code already has the important algorithmic cuts, including packed zone IDs and adaptive prefix sets: [policy.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/policy.rs:9), [prefix_set.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/prefix_set.rs:1).

Final: **PLAN-KILL #966**. Minor doc cleanup only; no implementation should proceed without a new measurement showing policy classification itself above 2% under a real xpf workload.

Codex session ID: 019df694-271f-77c3-a680-353ba3b50995
Resume in Codex: codex resume 019df694-271f-77c3-a680-353ba3b50995
