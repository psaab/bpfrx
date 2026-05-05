**Verdict: PLAN-KILL**

#968 does not survive review. The SYN-cookie part is dead: generation and validation are delegated to kernel BPF helpers in [bpf/xdp/xdp_screen.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/xdp/xdp_screen.c:138) and [bpf/xdp/xdp_screen.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/xdp/xdp_screen.c:282), with validation via [bpf/xdp/xdp_screen.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/xdp/xdp_screen.c:419) and [bpf/xdp/xdp_screen.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/xdp/xdp_screen.c:555). I found no userspace SYN-cookie generator. AES-NI/SHA-Ext in xpf userspace would not touch this path.

Hostile correction to the plan: its flow-hash wording is too broad. xpf does have small software hashes: CPUMAP fanout in [bpf/xdp/xdp_main.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/xdp/xdp_main.c:23), BPF flow-cache slots in [bpf/xdp/xdp_zone.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/xdp/xdp_zone.c:83) and [bpf/xdp/xdp_zone.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/xdp/xdp_zone.c:342), userspace flow-cache indexing in [userspace-dp/src/afxdp/flow_cache.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/afxdp/flow_cache.rs:331), CoS bucket hashing in [userspace-dp/src/afxdp/cos/flow_hash.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/afxdp/cos/flow_hash.rs:109), and fabric queue selection in [userspace-dp/src/afxdp/worker/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/afxdp/worker/mod.rs:182). But none is the alleged software RSS/ECMP crypto path, and none has a ≥2% measurement.

Perf gate fails. Fresh data shows no SYN-cookie, crypto, AES/SHA, Rust hash, or flow-hash symbol at ≥2%. The only listed hash cost is `htab_map_hash` at 1.52%, below threshold and in kernel BPF map lookup, not the proposed userspace SIMD target.

Implementation cost is unjustified for xpf’s 22+ Gb/s / 6-worker target. This would add CPU-feature dispatch, fallbacks, test burden, and probably no measurable movement while the actual hot spots remain memcpy, RX polling, and TX dispatch.

I would update the plan wording to acknowledge the small existing software hashes, then close #968 as **PLAN-KILL**.

Codex session ID: 019df694-27c3-7002-bd13-e80517a6e416
Resume in Codex: codex resume 019df694-27c3-7002-bd13-e80517a6e416
