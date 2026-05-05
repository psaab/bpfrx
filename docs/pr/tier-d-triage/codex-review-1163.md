# Codex hostile PLAN review — Tier D issue #1163

Source rollout: `rollout-2026-05-04T23-21-22-019df6cc-608e-7071-860b-cdcb1b342484.jsonl`

---

Verdict: PLAN-NEEDS-MAJOR

The triage’s `PLAN-KILL` is too strong. The issue premise is not fully wrong.

Findings:

- The cited symbol and shape still exist on `master`: `lookup_forwarding_resolution_v4` is still recursive, bounded by `MAX_NEXT_TABLE_DEPTH = 8`, and compares `next_table_name == table` before recursing. See [forwarding/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/forwarding/mod.rs:1109) and recursion at [forwarding/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/forwarding/mod.rs:1194).

- `next_table` is still stored as `String`, and route tables are still keyed by `FastMap<String, Vec<RouteEntry*>>`. See [types/forwarding.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/types/forwarding.rs:21) and [types/forwarding.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/types/forwarding.rs:84). `forwarding_build.rs` still clones `route.next_table` into those entries at [forwarding_build.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/forwarding_build.rs:296).

- The triage’s call-site claim is incomplete. `lookup_forwarding_resolution_in_table_with_dynamic` is called inside `poll_binding_process_descriptor`, inside the per-descriptor packet loop, on session miss after flow-cache/session lookup falls through. See [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:31), flow cache at [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:138), session miss at [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:453), and the route lookup at [poll_descriptor.rs](/home/ps/git/bpfrx/.claude/worktrees/tier-d-triage/userspace-dp/src/afxdp/poll_descriptor.rs:641).

- The issue is still not “every packet cache-hit hot path.” Established eligible traffic hits `flow_cache.lookup` first and bypasses this route recursion. But “session install only, not hot path” is sloppy: new-flow misses and some ineligible/session-resolution cases are still packet-loop work.

- The prescribed integer/interned-table pattern has not shipped for userspace FIB. There is a `UserspaceDpMeta.routing_table` field in the BPF metadata path, and zone names have already been moved to IDs, but userspace route lookup still uses table-name strings and formatted routing-instance names.

The plan should not kill #1163 as “premise wrong.” It should revise to something like: issue is valid for packet-loop miss path, invalid for flow-cache hit path, and needs either quantified miss-path evidence or a scoped table-name interning/table-id refactor proposal.

Caveat: `gh issue view 1163 --json title,body` was blocked by the sandbox network policy (`socket: operation not permitted`), and the browser could not access the private issue. I validated against the issue claims quoted in the triage doc and current local `master`.
