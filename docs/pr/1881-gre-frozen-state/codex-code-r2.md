No findings.

Verdict: MERGE-READY.

The round-1 counterexample is closed. In the `!same_plan` defer path, the server calls the GRE prune before storing the new snapshot and before skipping worker spawn: [snapshot.rs](/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/server/handlers/snapshot.rs:113) lines 113-129, then stores/replans/skips at lines 131-144. The prune now compares each existing entry against the new snapshot row: absent, mode flip, or `row.ifindex`/row label drift all become stale at [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/mod.rs:855) lines 855-878. That handles `id=1`, still `gre`, moved ifindex/name as `attachment_changed_deferred`.

The delivery sender is unpublished before join: `publish_local_tunnel_deliveries_excluding(&stale_ids)` runs before `stop_remove_local_tunnel_entry` at [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/mod.rs:886) lines 886-889, and the publisher excludes stale ids/live-only entries at lines 690-700. The stop/remove helper then stops and joins at lines 671-681.

The label fallback matches forwarding build semantics: forwarding uses `linux_name` else logical name at [interfaces.rs](/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/forwarding_build/interfaces.rs:44) lines 44-49; the prune uses the same fallback at [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/mod.rs:869) lines 869-874.

Same-snapshot keep is still pinned: the test prunes the identical `snap` and asserts entry `1` remains at [tests.rs](/home/ps/git/bpfrx/.claude/worktrees/1881-engineer-impl/userspace-dp/src/afxdp/coordinator/tests.rs:2675) lines 2675-2681. The new moved-attachment and re-armed full-removal checks are at lines 2685-2698.

I did not run tests; this was review-only in a read-only sandbox.

Codex session ID: 019eba8b-14b2-7730-ac53-31d6f0938b88
Resume in Codex: codex resume 019eba8b-14b2-7730-ac53-31d6f0938b88
