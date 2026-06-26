# #2118 — `show security policies hit-count` reads 0: diagnosis + display-gate unification

> **SUPERSEDED IN PART BY #3073.** This plan's "the increment chain is correct,
> the PERMIT-row 0 is the single-flow `0 is really 1` artifact (one new flow
> bumps a permit rule by exactly packets=1)" diagnosis described the
> *intended-at-the-time* behavior: the counter was incremented ONCE per flow on
> the cold path. That per-flow accounting was itself the #3073 bug — operators
> expect per-PACKET packet/byte counts (vSRX parity). #3073 adds the
> established-fast-path / flow-cache re-count so a long-lived flow now reports
> `packets=N`, not `1`. The display-gate unification below is unchanged.

- **Status:** IMPLEMENT — diagnosis complete, fix is small + localized.
- **Base:** origin/master `325d106838` (research base was `5fa964c13`).
- **Research:** converged PLAN-READY (Option A) on branch
  `research/2118-policy-hit-count`, r3 after hostile A+B + SMR.

## 1. Diagnosis (code-read, no live break found)

The per-rule hit-count chain is **intact end-to-end** and Go-unit-tested.
Verified by static reading + an independent second-pass agent:

- **Rust increment** (`policy.rs:1068`, `try_match_rule`): unconditional
  `rule.hit_counter.add(packet_len)` on `src_ok && dst_ok`, for permit
  AND deny actions. No `count`/policy-stats gate. Reached at BOTH call
  sites: `poll_descriptor/mod.rs:1110` (ForwardCandidate) and `:2342`
  (MissingNeighbor cold path), both passing the real `desc.len`.
- **Arc identity:** worker increment and coordinator `counter_snapshots()`
  (`policy.rs:502`) hit the SAME `Arc<PolicyRuleCounter>`
  (`PolicyCounterStore.rule_hit_counter` reuses Arcs by `rule_id`;
  `PolicyRule::clone` is a shallow Arc clone; the worker ArcSwap carries
  `Arc::new(self.forwarding.clone())`).
- **Wire:** `policy_rule_counters` is serde-default (Rust) / omitempty
  (Go), numeric — #1961-safe. No field-name mismatch.
- **Go read** (`policycounters.go:53`): `ReadPolicyCounters` maps
  `policyID → rule_id → m.lastStatus.PolicyRuleCounters`; `m.lastStatus`
  is populated by the 1Hz status loop. Unit-tested.

So the live "all 0" is NOT a broken chain. It is explained by:

1. **DENY rows = 0 is CORRECT** (confirmed). The loss cluster config
   (`docs/ha-cluster-userspace.conf:34`) has `default-policy deny-all`
   and ONLY explicit `permit` rules — no explicit deny rules. Blocked
   traffic rode the implicit default-deny → aggregate `policy_deny`
   increments, no per-rule counter. Not a bug. Do NOT "fix".
2. **The smoke ran with `policy-stats` OFF** (confirmed). The config has
   no `policy-stats system-wide enable`. Under Junos parity (#2008 M4),
   0 is the intended read.
3. **The PERMIT-row 0** is most plausibly the single-flow "0 is really 1"
   artifact (one new flow bumps a permit rule by exactly packets=1),
   amplified by the real bug below: the CLI/gRPC text + structured paths
   are UNGATED, so they would show the raw (ungated) count regardless of
   the knob. The display-gate inconsistency is the genuine, fixable bug.

## 2. The genuine bug: display-gate inconsistency (#2008 M4 follow-on)

#2008 M4 gated ONLY the Prometheus collector
(`pkg/api/metrics_counters.go:131`, early return when
`!cfg.Security.PolicyStatsEnabled`). The three text/structured display
paths were NOT gated:

| Surface | File | Gated on `PolicyStatsEnabled`? |
|---------|------|--------------------------------|
| Prometheus `policy_hits_total` | `pkg/api/metrics_counters.go:131` | YES (M4) |
| gRPC text `show ... hit-count` | `pkg/grpcapi/server_show_policies_text.go:26` | NO |
| gRPC text `show ... detail` | `pkg/grpcapi/server_show_policies_text.go:88` | NO |
| Local CLI `show ... hit-count` | `pkg/cli/cli_show_security.go:21` | NO |
| Local CLI `show ... brief` (Hits col) | `pkg/cli/cli_show_security_dispatch.go:176` | NO |
| Structured gRPC `GetPolicies` | `pkg/grpcapi/server_show_zones.go:95` | NO |
| REST `GET /api/v1/security/policies` | `pkg/api/security.go:103` | NO |

(The CLI `brief` and REST surfaces were found by Codex's hostile review
after the first three were gated — the gate is now uniform across all
six display surfaces.)

This is divergent behavior: the same traffic+config can read nonzero on
CLI/gRPC but zero on Prometheus. That is the consistency defect #2118
points at.

## 3. Fix (Option A, Step 3 — display-gate unification)

Gate the three ungated text/structured surfaces on
`cfg.Security.PolicyStatsEnabled`, matching M4's Prometheus behavior, so
all FOUR surfaces agree: when the knob is off, the per-rule counter
columns read 0 (skip `ReadPolicyCounters`); when on, they show live
counts.

- Display-only gate. Keep the Rust increment always-on (single relaxed
  atomic; §7 of research). No wire change, no `policy_stats_enabled`
  flag, no protocol bump. Smallest diff, #1961-safe.
- The table/struct SHAPE is unchanged (rows/fields still present); only
  the count value is forced to 0 when the knob is off — consistent with
  M4, which suppresses metric emission entirely (a metric reading 0 ==
  not emitted, for a counter).

No Rust change required: the increment chain is correct; the second
increment site / MissingNeighbor over-count is a pre-existing transient
that #2118 does not need to alter (no behavior change to packet path).

## 4. Tests

- **Go (manager):** `ReadPolicyCounters` is the read primitive and is
  intentionally NOT gated (the gate belongs at the display layer so
  Prometheus/CLI/gRPC can each decide). Existing tests stay green.
- **Go (gRPC text):** new test — `showPoliciesHitCount` shows 0 for a
  populated dataplane when `PolicyStatsEnabled` is false, nonzero when
  true. Mirror for `GetPolicies` (structured) in
  `server_show_zones_test.go`.
- **Go (CLI):** new test for `cli_show_security.go showPoliciesHitCount`
  gate parity (capture stdout).
- **Go (golden):** add `policies-hit-count` to `goldenShowTopics` so a
  future all-0/gate regression in the rendered table fails the golden.
- **Rust:** assert `try_match_rule` bumps the snapshotted counter for a
  permit AND a deny match, and that `counter_snapshots` reflects it
  (fills the gap that let the "is the chain alive?" question stand).

## 5. Junos divergence — FLAG for the user (do NOT change unilaterally)

xpf PRESERVES per-policy hit counts across a recompile as long as the
stable `from→to/name` identity is unchanged (`reconcile_rules` retains
the Arc). Junos RESETS per-policy hit counters on a commit that changes
the policy. The research recommends KEEPING the preserve-on-recompile
behavior (more useful for long-running rules) and documenting the
divergence. This plan does NOT change it; it is surfaced for a decision.

## 6. Out of scope

- No wire-protocol change.
- No change to aggregate flow counters (they work).
- No change to the Rust increment or the two-site invariant (no live
  break; #2118 is a display-consistency bug).
- The CLI `showPoliciesDetail` does not render counters at all
  (`_ = ruleID`) while gRPC's does — a separate display gap, not the
  hit-count surface #2118 names. Noted, not fixed here.
