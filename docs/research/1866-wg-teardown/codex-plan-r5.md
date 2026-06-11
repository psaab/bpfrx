===== RESULT =====
Verdict: PLAN-READY

Reviewed v5 at `3b7aeaabf`. The r4 attachment finding is resolved. v5 now says it will “record the spawn ATTACHMENT (logical_ifindex + tunnel name)” and include it in “both the apply-time stale condition and the sweep’s coherence tuple” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:19). The entry now records `spawned_ifindex` and `spawned_tunnel_name` in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:251), stale prune is `engine ptr differs OR attachment differs` in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:253), and the sweep tuple includes “attachment (interface / linux_name / ifindex)” in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:301). Tests 6d/6e pin both the defer tombstone case and apply-time live rename restart in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md:493).

Round-5 answers:

1. Attachment semantics are sound and complete. The current closure captures tunnel name, endpoint id, engine, listen port, peer endpoint, exception ring, and stop flag in [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/mod.rs:545); `wg_control_loop` consumes exactly those parameters in [wg_control.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/wg_control.rs:80). Engine identity covers keys/peer config; listen port and peer endpoint are already in `wg_identity_unchanged` in [wg.rs](/home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/forwarding_build/wg.rs:87). The new attachment fields cover the remaining runtime TUN attachment. `recent_exceptions` and `stop` are not config-derived spawn parameters.

2. I do not see a remaining incoherent spawn or respawn sequence. Apply-time stale prune now catches engine or attachment drift before the spawn pass, and the periodic path is tombstone-only plus snapshot-coherent. A live old thread can still exist during `defer_workers` because forwarding is intentionally not reconciled there, but v5 prevents the bad case: creating or recreating a thread whose params disagree with the latest stored snapshot.

3. Nothing else blocks PLAN-READY from this pass. I did not run tests; this was a read-only plan/code review.

Codex session ID: 019eb666-4821-7522-9ebe-b10515bf063c
Resume in Codex: codex resume 019eb666-4821-7522-9ebe-b10515bf063c
