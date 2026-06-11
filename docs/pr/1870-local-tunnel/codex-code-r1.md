===RESULT===
1. No Critical/High/Medium/Low findings.

I hostile-verified the requested surfaces. The `UpsertLocal` arm constructs `SessionInstall` with all old positional fields preserved and uses `allow_replace_local=true`: [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/session_glue/mod.rs:556). Below cap, the old install and new upsert share remove/reinsert/index/wheel behavior; the new path only removes the cap check and delta push path: [session/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/session/mod.rs:748), [session/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/session/mod.rs:834).

The debug assert is currently safe: production `UpsertLocal` producers are only in `tunnel.rs`, with forward `SyncImport` and reverse `SyncImport`: [tunnel.rs](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/tunnel.rs:191), [shared_ops.rs](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/shared_ops.rs:664), [tunnel.rs](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/tunnel.rs:329). The seven pins cover at-cap pair install, two-worker divergence, cap-1 partial prevention, below-cap replacement, at-cap replacement, owner-RG bulk-export exclusion, and session-level infallibility: [tests.rs](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/session_glue/tests.rs:4470), [tests.rs](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/session/tests.rs:2612). The filler keys do not collide with forward or reverse pair keys: [tests.rs](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/session_glue/tests.rs:4416), [key.rs](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/session/key.rs:154).

Docs and metric help text no longer claim `UpsertLocal` contributes to `create_drops`: [README.md](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/session/README.md:94), [metrics_descriptors.go](/home/ps/git/bpfrx/.claude/worktrees/1870-engineer/pkg/api/metrics_descriptors.go:553). I ran static diff/grep verification and `git diff --check`; I did not run cargo/go tests because this review worktree/sandbox is read-only.

Verdict: MERGE-READY

Codex session ID: 019eb8cc-14f4-7ee2-9096-538680186475
Resume in Codex: codex resume 019eb8cc-14f4-7ee2-9096-538680186475
