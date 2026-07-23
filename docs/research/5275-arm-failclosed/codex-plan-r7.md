# Codex hostile plan-review r7 (#5275) — VERDICT: PLAN-NEEDS-MAJOR (D1-D4 SOUND; only D5 unsafe)

Reviewed plan.md @ r8 §13. Final synthesis (file-read dumps stripped):


[35m[3mcodex[0m[0m
The decisive counterexample is confirmed in source: a steady peer promotes on its own stale-heartbeat clock before invoking optional peer fencing, and valid configuration can reduce that clock to 1 ms. The replacement node therefore does not control the ordering D5 claims; Kea’s stop path also has 15-second-per-call bounds, not a millisecond guarantee.
[3mOverall audit complete: architecture remains viable and D1–D4 are sound, but D5 fails its core fence-before-election invariant in a covered crash-restart scenario and is contradicted by source timing/order behavior.[0m
  [32m✓[0m Read r8 plan and codex-plan r1–r6
  [32m✓[0m Trace §13 claims to cited source firsthand
  [32m✓[0m Assess D1–D5 for safety and source consistency
  [32m✓[0m Perform overall contract audit and issue calibrated verdict
[35m[3mcodex[0m[0m
D1–D4 are sound. D5 is genuinely unsafe, so r8 is not yet approvable for `/engineer`.

| Decision | Assessment | Review |
|---|---|---|
| D1 | **SOUND** | The preliminary/final split matches the deferred-worker lifecycle: ready XSK bindings cannot exist during the preliminary proof, while digest, helper generation, and complete ready bindings are appropriate final-release evidence. Minor cleanup: §5 still incorrectly says all proof ingredients apply to “both stages,” contradicting the controlling D1 wording ([plan.md:164](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:164), [plan.md:414](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:414)). |
| D2 | **SOUND** | Current networkd configuration co-mingles topology/link state with addresses and performs broad reload/reconfigure operations. A link-only staging primitive followed by an attachment-neutral address/route primitive is the correct contract. “Attachment-neutral” must prohibit reuse of the current broad reconfigure behavior ([networkd.go:46](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/networkd/networkd.go:46), [networkd.go:215](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/networkd/networkd.go:215)). |
| D3 | **SOUND** | Digest-bound promotion, separate authoritative/recovery slots, promotion-bound history and confirmation, and proof-before-rollback all correctly reverse the current promote-before-apply ordering. These are coherent transaction invariants, not premature implementation detail ([store_commit.go:213](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/configstore/store_commit.go:213), [daemon_apply_commit.go:225](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_commit.go:225)). |
| D4 | **SOUND, wording fix** | Config-only authenticated ingress into a non-authoritative recovery slot is safe and avoids current `SyncApply` immediate promotion. However, its ACK must be explicitly named a **durably staged recovery receipt**, not an “applied high-water.” It must never advance the existing live-applied generation used for failover readiness ([store.go:611](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/configstore/store.go:611)). |
| D5 | **UNSAFE / CONTRADICTED** | The claimed ordering is false for former-primary crash restart and unsafe for live re-arm. |

The fatal D5 trace is straightforward:

1. A former Primary crashes while kernel VIP state, Kea, or FRR ownership persists—the exact case §3 places in scope ([plan.md:73](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:73)).
2. The healthy peer already has a `lastSeen` value. Its steady-state timeout continues independently of whether the replacement daemon has started.
3. On expiry, the peer calls `electSingleNode()` **before** optional peer fencing ([heartbeat_manager.go:404](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:404)).
4. The replacement node therefore does not “control” peer election by delaying its new yield heartbeat. It may not even be running when promotion happens.
5. Roughly 500 ms is only the default. Valid configuration permits a 1 ms interval and threshold 1 ([schema_chassis.go:74](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/config/schema_chassis.go:74)).
6. The asserted millisecond fence is also unsupported: `Kea Apply(nil)` may perform multiple systemd queries/stops, each with a 15-second timeout plus `WaitDelay` ([dhcpserver.go:29](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcpserver/dhcpserver.go:29)).

For live re-arm, “stop advertising during the fence” itself starts the peer’s takeover timer. Existing heartbeat restart code already requires a separate peer-side liveness-suppression mechanism because restart exceeds the default timeout ([heartbeat_manager.go:171](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:171)). D5 supplies no equivalent.

D5 must be redesigned around:

- continued authenticated suppression during a live local fence, followed by weight-zero yield only after verification;
- a peer-side promotion interlock or independent watchdog/lease/fencing mechanism for crash takeover;
- explicit resolution of D5’s asynchronous FRR clear versus §3’s requirement that attraction be cleared and verified before takeover.

The architecture remains viable, so this is not PLAN-KILL. But D5 leaves the previously identified scrub-before-election architecture hole open and makes a source-false safety claim. That meets the requested threshold for major revision.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
286,295
D1–D4 are sound. D5 is genuinely unsafe, so r8 is not yet approvable for `/engineer`.

| Decision | Assessment | Review |
|---|---|---|
| D1 | **SOUND** | The preliminary/final split matches the deferred-worker lifecycle: ready XSK bindings cannot exist during the preliminary proof, while digest, helper generation, and complete ready bindings are appropriate final-release evidence. Minor cleanup: §5 still incorrectly says all proof ingredients apply to “both stages,” contradicting the controlling D1 wording ([plan.md:164](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:164), [plan.md:414](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:414)). |
| D2 | **SOUND** | Current networkd configuration co-mingles topology/link state with addresses and performs broad reload/reconfigure operations. A link-only staging primitive followed by an attachment-neutral address/route primitive is the correct contract. “Attachment-neutral” must prohibit reuse of the current broad reconfigure behavior ([networkd.go:46](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/networkd/networkd.go:46), [networkd.go:215](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/networkd/networkd.go:215)). |
| D3 | **SOUND** | Digest-bound promotion, separate authoritative/recovery slots, promotion-bound history and confirmation, and proof-before-rollback all correctly reverse the current promote-before-apply ordering. These are coherent transaction invariants, not premature implementation detail ([store_commit.go:213](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/configstore/store_commit.go:213), [daemon_apply_commit.go:225](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/daemon/daemon_apply_commit.go:225)). |
| D4 | **SOUND, wording fix** | Config-only authenticated ingress into a non-authoritative recovery slot is safe and avoids current `SyncApply` immediate promotion. However, its ACK must be explicitly named a **durably staged recovery receipt**, not an “applied high-water.” It must never advance the existing live-applied generation used for failover readiness ([store.go:611](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/configstore/store.go:611)). |
| D5 | **UNSAFE / CONTRADICTED** | The claimed ordering is false for former-primary crash restart and unsafe for live re-arm. |

The fatal D5 trace is straightforward:

1. A former Primary crashes while kernel VIP state, Kea, or FRR ownership persists—the exact case §3 places in scope ([plan.md:73](/home/ps/git/bpfrx/.claude/worktrees/5275-research/docs/research/5275-arm-failclosed/plan.md:73)).
2. The healthy peer already has a `lastSeen` value. Its steady-state timeout continues independently of whether the replacement daemon has started.
3. On expiry, the peer calls `electSingleNode()` **before** optional peer fencing ([heartbeat_manager.go:404](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:404)).
4. The replacement node therefore does not “control” peer election by delaying its new yield heartbeat. It may not even be running when promotion happens.
5. Roughly 500 ms is only the default. Valid configuration permits a 1 ms interval and threshold 1 ([schema_chassis.go:74](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/config/schema_chassis.go:74)).
6. The asserted millisecond fence is also unsupported: `Kea Apply(nil)` may perform multiple systemd queries/stops, each with a 15-second timeout plus `WaitDelay` ([dhcpserver.go:29](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/dhcpserver/dhcpserver.go:29)).

For live re-arm, “stop advertising during the fence” itself starts the peer’s takeover timer. Existing heartbeat restart code already requires a separate peer-side liveness-suppression mechanism because restart exceeds the default timeout ([heartbeat_manager.go:171](/home/ps/git/bpfrx/.claude/worktrees/5275-research/pkg/cluster/heartbeat_manager.go:171)). D5 supplies no equivalent.

D5 must be redesigned around:

- continued authenticated suppression during a live local fence, followed by weight-zero yield only after verification;
- a peer-side promotion interlock or independent watchdog/lease/fencing mechanism for crash takeover;
- explicit resolution of D5’s asynchronous FRR clear versus §3’s requirement that attraction be cleared and verified before takeover.

The architecture remains viable, so this is not PLAN-KILL. But D5 leaves the previously identified scrub-before-election architecture hole open and makes a source-false safety claim. That meets the requested threshold for major revision.

VERDICT: PLAN-NEEDS-MAJOR
