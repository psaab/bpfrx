# Codex code review r2 - PR #1618 step-1 scope

Verdict: NEEDS-MINOR

Scope discipline: I am treating the visible fraction-honoring distribution behavior as out of scope for this PR. That belongs to follow-up #1625. I did not find a verified counterexample that breaks the step-1 wire surface or the proportional-mode preservation claim.

Findings:

1. Minor: `cargo fmt --check` fails on this branch, including the newly added CoS struct literal fields (`codel_target_ns`, `oversubscription_policy`, `oversubscription_guarantee_fraction`, `priority_low_min_share_bytes`) in Rust tests. The failure is broad and not a functional step-1 break, but this should not be merged unformatted.

2. Minor: `waterfill_guarantee_rate_fraction_changes_pass1_budget` is weaker than its claimed invariant. It exercises both fractions and checks that selection continues, but it does not assert that the two fractions leave different internal state or select differently. This is not a step-1 blocker because visible distribution is #1625, but the test name/comment overstate what is pinned.

Verified step-1 claims:

- Wire fields exist with default-compatible JSON behavior: Go `InterfaceSnapshot` has `cos_oversubscription_policy`, `cos_oversubscription_guarantee_fraction`, and `cos_priority_low_min_share_bytes` with `omitempty`; Go `CoSSchedulerSnapshot` has `codel_target_ns` with `omitempty`; Rust snapshot structs use `serde(default)` for the matching fields.
- The fields are plumbed through parser/typed config/snapshot/Rust config/runtime for active CoS interfaces. `codel_target_ns` reaches queue config/runtime state but is documented as wire-surface-only.
- Proportional default is preserved by `select_exact_cos_guarantee_queue_with_lease_telemetry`: the new waterfill path is entered only when policy is `GuaranteeRate` and fraction is positive; otherwise the legacy exact RR path runs.
- A2 and A3 comments now explicitly mark wire-surface-only status at the requested Rust and Go protocol sites.
- A4 warning is nil-safe and reports the active policy tail. The guarantee-rate warning test verifies `guarantee-rate 0.7`; the default test verifies `proportional`.
- The smoke reducer reads throughput from `sum_received.bits_per_second` with fall-through to `sum_sent.bits_per_second`, and reads retransmits only from `sum_sent.retransmits`. `bash -n` passes.

Validation run:

- `bash -n test/incus/cos-simul-load-smoke.sh` - pass
- `go test ./pkg/config ./pkg/dataplane/userspace` - pass
- `cargo test waterfill_` - pass, 4 tests
- `cargo test cos_scheduler_snapshot_surplus_sharing_default_false` - pass
- `cargo test wire_invariant_default_specimens` - pass
- `cargo fmt --check` - fail, formatting drift across branch
- `git diff --check origin/master...HEAD` - fail on pre-existing trailing whitespace in review docs

Merge position: mergeable after formatting cleanup, or merge as-is only if this branch intentionally does not gate on rustfmt/diff whitespace. No CODE-KILL and no step-1 NEEDS-MAJOR finding.
