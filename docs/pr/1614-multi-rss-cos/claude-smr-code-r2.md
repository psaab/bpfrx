# Claude SMR code-review r2 — PR #1618 (step-1 scope)

Reviewer: Claude (SMR — network scheduling / shaper semantics / AF_XDP
queue physics / CPU microarchitecture / Junos CoS contract / Rust
soundness / Go API discipline).

Target: PR #1618 HEAD `82dc1d65f` on branch
`refactor/1614-multi-rss-cos`, **re-scoped to step-1 only**.

Step-2 (per-queue epoch-cap mechanism producing the visible
distribution change) is filed as
[#1625](https://github.com/psaab/xpf/issues/1625).

Method: hostile-verify against the re-scoped acceptance criteria.
Plan-review and step-2 deferral are closed; this round only judges
the step-1 wire-surface + scaffold + smoke-harness + commit-warning.

Verdict: **MERGE-READY** on the step-1 scope.

## What changed since SMR r1 (19005fedf → 82dc1d65f)

- `9a7fb6213`: Codex code-r1 fixes. Three behavioural fixes (#3, #4,
  #5) plus a wording cleanup. New runtime fields
  `waterfill_pass1_remaining_bytes` + `waterfill_phase2_cursor` added
  to `CoSInterfaceRuntime` for the Phase-1/Phase-2 scaffold algorithm.
  A2 / A3 comments rewritten to "WIRE SURFACE ONLY in PR #1618".
  Smoke harness reducer now reads retransmits from `sum_sent`
  (where iperf3 stores the sender-side counter). One new test
  `waterfill_guarantee_rate_fraction_changes_pass1_budget` exercises
  the fraction-state-change path.

- `82dc1d65f`: `docs/pr/1614-multi-rss-cos/smoke-finding.md` records
  the empirical observation that the v5 byte-budget scaffold does
  NOT yet produce a visibly different distribution under
  oversubscription at `guarantee-rate 0.7`. Root cause: bounding
  total Phase-1 byte budget rather than per-queue rate. Filed as
  step-2 #1625.

## Acceptance vs the step-1 contract

### Wire surface

- Go: `pkg/dataplane/userspace/protocol.go` `InterfaceSnapshot` gains
  `CoSOversubscriptionPolicy`, `CoSOversubscriptionGuaranteeFraction`,
  `CoSPriorityLowMinShareBytes`. `CoSSchedulerSnapshot` gains
  `CodelTargetNS`. All `omitempty`.
- Rust: `userspace-dp/src/protocol/snapshot.rs` `InterfaceSnapshot`
  + `userspace-dp/src/protocol/cos.rs` `CoSSchedulerSnapshot`
  matching fields with `#[serde(default)]`.
- Live smoke confirms the wire flows end-to-end: snapshot file on
  the loss userspace cluster after applying
  `set class-of-service interfaces reth0 unit 80
  oversubscription-policy guarantee-rate 0.7` contains
  `cos_oversubscription_policy: "guarantee-rate"` +
  `cos_oversubscription_guarantee_fraction: 0.7`.

CLOSED.

### Default proportional mode is bit-for-bit unchanged

The early-return branch at the top of
`select_exact_cos_guarantee_queue_with_lease_telemetry` gates on
`policy == GuaranteeRate AND fraction > 0`. Both empty / unset
policy AND fraction == 0 fall through to the unchanged legacy
selector body.

Empirical: live smoke at default config (no `oversubscription-policy`
set) reproduces the baseline distribution within token-bucket noise
on the loss userspace cluster.

CLOSED.

### A4 commit warning fires + surfaces active policy

`pkg/config/compiler.go::validateCoSOversubscriptionWarnings` iterates
`cos.Interfaces[*].Units[*]` (all nil-safe), computes `sumExact` over
the unit's scheduler-map exact entries, and emits a warning when
`sumExact > unit.ShapingRateBytes`. Format names the active policy
(`proportional` default vs `guarantee-rate <X>`).

Tests `TestValidateCoSOversubscriptionWarning` and
`TestValidateCoSOversubscriptionWarningGuaranteeRate` cover both
modes. Live xpfd log on the cluster shows the warning fires
correctly on the canonical fixture.

CLOSED.

### A2 + A3 are explicitly wire-surface-only

Codex r1 #3 + #4 were "comments overclaim hot-path behaviour". v5.1
rewrites all four comment sites (Rust: `snapshot.rs:105`,
`types/cos.rs:55`, `types/cos.rs:587`; Go: `protocol.go:155` and
`protocol.go:227`) to say "WIRE SURFACE ONLY in PR #1618; the
[mechanism] is deferred to a focused follow-up". No reader of these
fields would conclude they affect runtime behaviour today.

The runtime state fields (`priority_low_reserved_tokens`,
`priority_low_last_refill_ns`) are documented as "reserved for the
deferred cap_eff mechanism; currently UNUSED". They occupy a few
bytes per `CoSInterfaceRuntime`; the cost is well below noise.

CLOSED.

### Smoke harness reads correct retransmit source

Codex r1 #5: previously `end.sum_received.retransmits` (always
zero). v5.1 reducer now reads throughput from `sum_received ??
sum_sent` and retransmits explicitly from `sum_sent.retransmits`.
Live smoke run confirms non-zero retransmit values appear in the
verdict per-class.

CLOSED.

### Test coverage

4 Rust tests + 2 Go tests added. The Rust set:
- `waterfill_default_proportional_mode_uses_legacy_rr` — pins the
  bit-for-bit early-return invariant.
- `waterfill_guarantee_rate_mode_picks_smallest_rate_first` — pins
  sorted-ascending iteration in `GuaranteeRate` mode.
- `waterfill_guarantee_rate_skips_non_exact_queues` — pins that
  non-exact queues are unaffected.
- `waterfill_guarantee_rate_fraction_changes_pass1_budget` — pins
  that the fraction value is consulted (not used as a boolean)
  across multiple service calls.

The Go set:
- `TestValidateCoSOversubscriptionWarning` — warning fires +
  proportional policy mention.
- `TestValidateCoSOversubscriptionWarningGuaranteeRate` — warning
  fires + guarantee-rate value (0.7) surfaces in the message; the
  AST-walk handles the flat-keys Junos set syntax correctly.

5/5 flake check on the 4 new Rust tests. Both Go tests pass.

CLOSED.

### R8 Phase 0

PASSED 2026-05-27 (reverse-simul 22.72 G aggregate; generator CPU
20-58% idle). Live smoke at HEAD reconfirms with this PR's binary:
gate 8 reverse-simul-22g = true.

CLOSED.

## What's intentionally NOT in this PR (step-2 #1625)

- Per-queue per-epoch byte allocation tracking in
  `select_exact_cos_guarantee_queue_waterfill` so small classes hit
  their configured rate first under oversubscription.
- `cap_eff = root.tokens.saturating_sub(priority_low_min_share_pass)`
  subtraction before the A1 selector + Phase-3 admission of the
  priority-low queue up to its min-share.
- CoDel sojourn-time dequeue check.
- Acceptance gates 1 + 3 from plan §7.

These are filed as #1625 with Codex r1 findings #1 + #2 captured
as the step-2 success criteria. Not dismissed; deferred with a
tracked target.

## No new findings on step-1 scope

The implementation is internally consistent, the wire surface is
correctly additive, the default-off feature flag means production
behaviour is unchanged, the commit warning provides operator-
visible awareness of oversubscription, and the smoke harness is
ready as the canonical regression gate for step-2 + future CoS PRs.

## Decision

**MERGE-READY on step-1 scope.** The PR's stated acceptance is
fully met. Step-2 is properly filed and traceable. Recommend
merge after Codex r2 + AGY r2 (if they wish to re-attest at the
re-scoped state) + Copilot + clean fast smoke (`-P 12 -R` v4 + v6,
0 retrans).
