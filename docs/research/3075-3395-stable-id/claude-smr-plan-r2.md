# Claude SMR — plan review r2 (convergence)

Target: `docs/research/3075-3395-stable-id/plan.md` @ v2. Posture: hostile,
then converge only where source forces it. r1 verdict was NEEDS-REVISION.

## Verdict r2: PLAN-READY (both halves)

My three r1 objections are resolved — two against my own framing, after I and
AGY independently verified the disputed facts against source. I withdraw the
"P1 over-scoped" objection. The plan's thesis (two schemes, one pattern, NOT a
unified allocator) was correct in r1 and is now backed by AGY concurrence and a
clean source check. Outstanding AGY correctness catches are folded.

## Disposition of my r1 blocking items

- **Z1 (prove the event-stream widen is same-version).** RESOLVED. Verified:
  xpfd spawns the helper as a child (`process.go:78,87`); STOP→FLIP→START stops
  the old daemon (killing the helper) before starting the new one; the socket is
  unlinked+recreated (`process.go:53-61`) and reconnect triggers FullResync
  (`eventstream.go:441-442`). Reader and writer are always the same build. AGY
  reached the same conclusion independently. The §6 proof + the
  `ProcessStatus.ConfigSnapshotProtocolVersion` advertisement satisfy the demand.

- **Z2 (group-scoped gate `if`).** RESOLVED in the demanding direction. Zones ARE
  `${node}`/apply-groups scoped (`ha-cluster-userspace.conf`), so v2 makes the
  three-view collision gate REQUIRED (§5.1.3) and drops the `if`. Good.

- **P1 over-scoped → demote to P0/defer.** WITHDRAWN. This was my biggest r1
  objection and it was WRONG. I claimed (echoing the #3322 commit) that the
  close-delta path holds no `PolicyState`, so the close-log half needed risky new
  plumbing. AGY disputed it. Resolving against source: `flush_session_deltas`
  already takes `forwarding: &ForwardingState` (`session_delta.rs:74`) and
  `ForwardingState.policy` is populated (`forwarding_build/mod.rs:233`). The
  close path can read `forwarding.policy` directly — no new plumbing. So full P1
  (live rows + close log) is the proportionate fix; P0 is unnecessary. v2 retires
  P0 and recommends P1. This is the campaign lesson in action: reviewer-vs-reviewer
  factual divergence resolved against SOURCE, trusting neither — and the source
  said I was wrong.

## AGY catches — all folded, all correct

- **AGY Obj 1 (deleted-rule fallback).** This is a real correctness bug that BOTH
  v1 and my own r1 review endorsed (we both wrote "fall back to frozen = never a
  wrong rule"). AGY is right: the frozen positional id CAN become a wrong rule if
  a later reorder reoccupies that index. v2 §5.2.4 now resolves a deleted rule to
  the unattributed sentinel (`DefaultPolicySentinelID`), and §9 adds the
  RED-on-revert test (delete admitting rule → reorder occupant into the freed
  index → assert unattributed, not the occupant). Good catch; my r1 missed it.
- **AGY Obj 2 (`PolicyRuleCounter.rule_id`).** Correct implementation detail —
  the bound handle must carry the rule_id to re-resolve. Folded §5.2.1.
- **AGY Obj 3 (`ZoneIDReservedMin` Go const).** Correct; folded §5.1.1.

## Residual hostility (non-blocking, recorded so the engineer keeps them honest)

- **Zone C-vs-B is genuinely close.** v2 §10 now presents it as the maintainer's
  real choice (C buys #2391-retirement + #1873 unification; B is cheaper and the
  triggering edit is rare). I am satisfied the plan no longer assumes C.
- **`DefaultPolicySentinelID` reuse for "rule-deleted".** Semantically it means
  "default/implicit policy," not "deleted." It is close enough for a forensic
  surface and v2 flags the one-constant sub-decision for engineer time. Acceptable.
- **The O(1) re-resolution map must actually be rebuilt per-snapshot, not
  per-refresh.** v2 §5.2.2 states this; the engineer must not regress it into a
  per-session linear scan under the control-socket-contention rule.
- **P2 / HA-peer-after-reorder residual stays dead.** Correct disposition; a
  later round must not resurrect the three-wire change for a Medium forensic edge.

## Convergence

Claude SMR r2 = PLAN-READY. AGY = PLAN-READY-equivalent (all NEEDS-REVISION items
folded; thesis + same-version IPC + birthday math + migration endorsed). Codex =
infra-blocked (2 documented attempts), proceed 2-of-3. Converged recommendation:
**#3075 = Option C (name-hash + u16 widen, supersede #2391); #3395 = P1
(bound-local re-resolution, no wire); two schemes one pattern, NOT a unified
allocator; P2 + persistent allocator deferred/rejected.**
