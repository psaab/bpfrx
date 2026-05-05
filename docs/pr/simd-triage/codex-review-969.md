**Verdict: PLAN-KILL for #969.**

The issue’s core premise does not survive. Legacy BPF FIB lookup is via kernel `bpf_fib_lookup`, not an xpf-owned trie: [xdp_zone.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/bpf/xdp/xdp_zone.c:1479). The AF_XDP Rust path does have a userspace route lookup on session miss, but it is a sorted `Vec` scan, not a DIR-24-8 trie or 64-way gather batch: [forwarding_build.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/afxdp/forwarding_build.rs:281), [forwarding/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/afxdp/forwarding/mod.rs:1130). DPDK uses `rte_lpm_lookup`, again not a custom gather target: [zone.c](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/dpdk_worker/zone.c:267).

The only plausible AF_XDP callsite is session-miss resolution from `poll_binding_process_descriptor`: [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/afxdp/poll_descriptor.rs:641). Established traffic bypasses this through flow/session cached decisions: [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/afxdp/poll_descriptor.rs:138), [session/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/userspace-dp/src/session/mod.rs:139). Fresh perf has no `lookup_forwarding_resolution`, `PrefixV4::contains`, route scan, LPM, or FIB symbol at >=2%; the visible costs are memmove, RX descriptor processing, TX dispatch, and BPF hash: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/simd-triage/docs/pr/simd-triage/plan.md:31).

One plan-doc correction: §3 is too broad when it says xpf “does NOT walk a userspace LPM trie.” Better: BPF uses kernel `bpf_fib_lookup`; AF_XDP Rust has a userspace linear route-vector lookup on session miss; DPDK uses DPDK `rte_lpm`. Also the cited `xpf_helpers.h:2419` is weak for the main lookup; cite `xdp_zone.c` instead.

That correction does not rescue #969. A DIR-24-8 + AVX2 gather implementation would be a new route-table architecture with VRF/next-table/tunnel/neighbor semantics and CPU-specific fallback, aimed at an unmeasured session-miss subpath. Not worth it for the 22+ Gb/s / 6-worker target.

Codex session ID: 019df694-2bd6-7b32-be86-237b30947a03
Resume in Codex: codex resume 019df694-2bd6-7b32-be86-237b30947a03
