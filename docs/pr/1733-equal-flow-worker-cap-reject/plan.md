# Plan of Action — #1733 Phase 1: hard-reject `workers > 32` when equal-flow enforcement is enabled

- **Status**: DRAFT v1 — pending adversarial plan review
- **Issue**: #1733 (sub-issue of #1731; research plan
  `research/1731-cos-mqfq-generalize:docs/research/1731-cos-mqfq-generalize/plan.md` §4.3)
- **Base**: master `c9e552689` (canary-green #1723 lineage; latest merge #1730)
- **Scope**: control-plane config validation ONLY. No dataplane behavior
  change. No removal of the 32-worker cap (that is the deferred #1731-e
  heap-scratch follow-up).

## 1. Issue framing

`maybe_rotate_epoch_v8` (`userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:71-79`)
sizes its per-worker scratch arrays from a compile-time
`const MAX_WORKERS_SCRATCH: usize = 32`. Worker ids `>= 32` are clamped
out of the sampled set (`n_workers = len.min(32)`, `:72`) and only guarded
by a `debug_assert!` (`:73`) that is **stripped in release builds**. When a
worker beyond index 31 is active, `active_outside_scratch` is set (`:106-107`),
and `publish_equal_flow_epoch_v8` (`publish_equal_flow_epoch_v8.rs:30-34`)
takes the `fail_open(UnsampledActiveWorker)` branch and **silently disables
equal-flow enforcement for the epoch**.

Result: on a 48-/64-core deployment with `equal-flow-enforcement` configured,
the fairness guarantee the operator asked for is silently NOT enforced —
a fail-OPEN, not a loud failure. There is no config-time cap: the worker
count is parsed by `compiler_system.go:443-446` (`strconv.Atoi`, no max) and
`lifecycle.rs:269-273` (`.max(1)`, no upper bound).

**Phase 1 (this issue):** make the unsupported combination fail LOUDLY at
`commit`/apply time — hard-reject the config when
`workers > 32 AND any scheduler has equal-flow-enforcement` — instead of
fail-opening at runtime in release. Plus surface the existing dataplane
fail-open-reason counter as the runtime visibility for the (now
config-unreachable in a supported deploy) condition.

**Out of scope / deferred to #1731-e:** removing the 32 cap by replacing
the stack-scratch arrays with reusable heap scratch owned by `V8State`.
This plan does NOT touch `rotate_epoch_v8.rs` or `publish_equal_flow_epoch_v8.rs`
logic.

## 2. Honest scope / value framing

This is a small, high-certainty correctness/safety fix: it converts a
silent prod fail-open on high-core boxes into a commit-check rejection the
operator sees immediately. The "win" is not perf; it is operator-facing
honesty — the firewall must not accept a config whose fairness contract it
will silently not honor.

The blast radius is one new strict validator (mirrors the three existing
ones at `compiler.go:284-293`) and a doc/test touch. There is no hot-path
change, no allocation change, no HA change.

*If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.* (Here there is no perf claim at all;
the kill criterion would instead be "this validator is the wrong locus" or
"the 32 constant is not actually the supported ceiling".)

## 3. Where worker-count and equal-flow-enable are BOTH known (verified)

- **Worker count**: `cfg.System.UserspaceDataplane.Workers`
  (`pkg/config/types_system.go:23,44`); set via `set system dataplane workers N`,
  parsed at `compiler_system.go:443-446`. `UserspaceDataplane` is a pointer,
  nil when no `dataplane` stanza is present.
- **Equal-flow-enable**: per-scheduler `EqualFlowEnforcement bool`
  (`pkg/config/types_cos.go:89`), set via
  `set class-of-service schedulers <name> equal-flow-enforcement`
  (`compiler_class_of_service.go:252-253`), validated today by
  `validateClassOfServiceStrict` (`compiler.go:427-431`) which only sees
  `cos`, not the system config.
- **Both reachable from `*Config`**: `validatePolicySchedulerReferencesStrict(cfg *Config)`
  (`compiler.go:385`) is the existing precedent for a strict validator that
  takes the WHOLE `*Config`. The cross-cutting worker×equal-flow check needs
  the same signature because the two facts live in different sub-structs.

**Decision: the locus is a NEW `*Config`-scoped strict validator**, appended
to the independent strict-validator accumulator in `compileExpanded`
(`compiler.go:284-293`). It is independent of the other three (reads its
own two sub-structs, fail-fasts internally), satisfying the documented
accumulator contract at `compiler.go:270-283`.

## 4. The 32 constant — value provenance

`MAX_WORKERS_SCRATCH = 32` (`rotate_epoch_v8.rs:71`) is the supported
equal-flow worker ceiling. Per the #1731 plan FACT (§4.3, F4 RESOLVED):
the 32 cap is PURELY the stack-scratch array sizing — there is NO hidden
packed-width ceiling (`PackedEpochGrant` encodes tag+byte-grant, not
worker-id; worker arrays are heap-sized to actual count). So 32 is the
exact, correct reject threshold for equal-flow, and only equal-flow.

I will introduce a single named Go constant
`MaxEqualFlowWorkers = 32` in `pkg/config` with a doc comment pointing at
`rotate_epoch_v8.rs:71` so the two sites are greppable as a pair (and the
#1731-e follow-up that removes the cap has one Go site to delete).

## 5. Concrete design

### 5.1 Go control-plane hard-reject (the gate)

`pkg/config/compiler.go` — new validator + accumulator wire-up:

```go
// MaxEqualFlowWorkers is the supported worker ceiling for CoS
// equal-flow-enforcement. It mirrors MAX_WORKERS_SCRATCH in
// userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:71 —
// above this count the v8 rotation's per-worker stack scratch clamps the
// sampled set and equal-flow silently fail-opens (UnsampledActiveWorker).
// Reject loudly at commit instead. Removing this cap (heap scratch) is
// tracked as #1731-e; this constant and that Rust const must be retired
// together.
const MaxEqualFlowWorkers = 32

// validateEqualFlowWorkerCapStrict rejects a config that enables CoS
// equal-flow-enforcement on more workers than the v8 rotation can sample.
func validateEqualFlowWorkerCapStrict(cfg *Config) error {
	if cfg == nil || cfg.ClassOfService == nil {
		return nil
	}
	usd := cfg.System.UserspaceDataplane
	if usd == nil || usd.Workers <= MaxEqualFlowWorkers {
		return nil
	}
	for _, sched := range cfg.ClassOfService.Schedulers {
		if sched != nil && sched.EqualFlowEnforcement {
			return fmt.Errorf(
				"class-of-service scheduler %q equal-flow-enforcement is unsupported with "+
					"system dataplane workers %d (max %d); equal-flow fairness silently "+
					"fail-opens above %d workers — reduce workers or disable "+
					"equal-flow-enforcement (cap removal tracked as #1731-e)",
				sched.Name, usd.Workers, MaxEqualFlowWorkers, MaxEqualFlowWorkers)
		}
	}
	return nil
}
```

Wire into the accumulator (`compiler.go:284-293`):

```go
if err := validateEqualFlowWorkerCapStrict(cfg); err != nil {
	strictErrs = append(strictErrs, err)
}
```

`cfg.System` is a value (not pointer) on `*Config` — confirmed by
`validatePolicySchedulerReferencesStrict` reading `cfg.Security` directly;
`cfg.System.UserspaceDataplane` is the only pointer hop, nil-guarded above.

### 5.2 Runtime visibility (the "status counter for the fail-open reason")

The dataplane already exposes the fail-open reason end-to-end:
- Rust: `V8EqualFlowFailOpenReason::UnsampledActiveWorker`
  (`shared_cos_lease/mod.rs:444`), `fail_open_reason`/`fail_open_count`
  atomics, accessors `v8_equal_flow_fail_open_reason()` /
  `v8_equal_flow_fail_open_count()` (tested in `shared_cos_lease_tests.rs`).
- Go/Prometheus: `cosEqualFlowFailOpen` (`pkg/api/metrics.go:117`) +
  `fairnessEqualFlowUnsampledActiveWorkers` (`:204`).

So the *runtime* fail-open visibility the issue asks for already exists.
Phase 1's additional visibility is the **commit-check rejection** itself
(the loud control-plane failure). I will NOT add a duplicate counter.
The plan documents this mapping in `docs/` (CoS scheduler doc) so an
operator who sees `cosEqualFlowFailOpen` incrementing on a legacy stored
config (workers>32 that predates this gate, replayed on upgrade) knows the
condition and the fix.

**Stored-config upgrade nuance:** a config with workers>32+equal-flow that
was committed before this gate exists is now rejected on the next
`commit`/`commit check`. It is NOT auto-rejected at `Store.Load` (Junos
candidate semantics — live config stays unchanged). This matches how the
other strict validators behave and is the intended UX (operator sees the
error on next edit). Documented explicitly.

### 5.3 No Rust change in Phase 1

`rotate_epoch_v8.rs` / `publish_equal_flow_epoch_v8.rs` are untouched. The
cargo lease tests are run as a regression gate to prove the existing
fail-open machinery (the thing we are now preventing in supported configs)
still behaves, NOT because we modify it.

## 6. Public API preservation

No public API change. New unexported validator + new exported package
constant `MaxEqualFlowWorkers`. No proto, gRPC, CLI grammar, or schema
change (the `equal-flow-enforcement` and `workers` set-paths already exist).

## 7. Hidden invariants the change must preserve

- **Accumulator independence** (`compiler.go:270-283`): the new validator
  reads only `cfg.System.UserspaceDataplane` + `cfg.ClassOfService`, does
  not depend on another validator's success, fail-fasts internally. ✓
- **errors.Join framing**: single-error path must stay newline-free
  (the existing `TestCompileMultipleStrictErrorsAccumulated` pins this).
  New validator returns a single error like the others. ✓
- **Nil-safety**: `UserspaceDataplane` pointer + `ClassOfService` pointer +
  nil scheduler entries all guarded. ✓
- **Threshold correctness**: reject only `Workers > 32` (strictly greater);
  exactly 32 is supported (indices 0..31). ✓ (`min(32)` admits 32 workers).
- **No false reject when equal-flow absent**: the loop requires at least
  one `EqualFlowEnforcement` scheduler; a 64-worker box with no equal-flow
  is untouched. ✓

## 8. Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | LOW | Pure additive validator; only rejects a config that today silently misbehaves. Existing valid configs (≤32 workers, or equal-flow absent) compile unchanged. |
| Lifetime / borrow | N/A (Go) | No Rust change. |
| Performance regression | NONE | Validator runs once per `commit`, O(schedulers). No hot-path touch. |
| Architectural mismatch | LOW | Locus is the established `*Config`-scoped strict-validator pattern (precedent: `validatePolicySchedulerReferencesStrict`). Risk would be if reviewers think the gate belongs in the Rust `lifecycle.rs` arg-parse instead — addressed in Open Questions. |

## 9. Test plan

- `go build ./...` clean.
- **FAILING-then-fixed config test** (`pkg/config/compiler_test.go`):
  `TestCompileRejectsEqualFlowAbove32Workers` — set fixture
  `set system dataplane workers 33` +
  `set class-of-service schedulers s1 transmit-rate <bytes> exact` +
  `set class-of-service schedulers s1 equal-flow-enforcement`, assert
  `CompileConfig` returns an error matching the worker-cap message.
  Companion `TestCompileAcceptsEqualFlowAt32Workers` (workers=32, same
  scheduler) asserts NO worker-cap error (boundary). And
  `TestCompileAcceptsAbove32WorkersWithoutEqualFlow` (workers=64, no
  equal-flow) asserts acceptance. Confirm the test FAILS before the
  validator wiring (red), PASSES after (green).
- Extend `TestCompileAllThreeStrictValidatorsAccumulated` →
  four-validator accumulation OR add a dedicated accumulation assertion so
  a silent removal of the new append is caught (same rationale as the
  comment at `compiler_test.go:168-186`).
- **Go suite**: `go test ./...` (30 packages) green.
- **Cargo lease tests** (regression, no code change):
  `cargo test --release -p userspace-dp shared_cos_lease` (the
  `equal_flow_fail_open_*` tests) green — proves we did not perturb the
  fail-open machinery.
- **No cluster smoke**: this is control-plane config-validation on the
  reject path; no dataplane/runtime change, no HA change. `make
  test-failover` NOT needed. (Stated explicitly per skill "when to not
  smoke".)

## 10. Out of scope (explicitly)

- Removing the 32 cap via heap scratch (#1731-e).
- Any change to `rotate_epoch_v8.rs` / `publish_equal_flow_epoch_v8.rs`.
- A new Prometheus counter (the existing `cosEqualFlowFailOpen` +
  `fairnessEqualFlowUnsampledActiveWorkers` already cover runtime
  visibility).
- Mirroring the reject in `lifecycle.rs` arg-parse (the daemon receives an
  already-validated config from the control plane; double-validating in the
  helper is redundant — see Open Question Q2).

## 11. Open questions for adversarial review

1. **Locus**: is the `*Config`-scoped strict validator in `compiler.go` the
   right home, or should the gate ALSO live in `lifecycle.rs` arg-parse to
   defend against a hand-crafted `--workers 64` invocation that bypasses the
   control plane? (Belief: control-plane reject is the supported path; the
   helper is not an independent config source in production. KILL-worthy if
   reviewers show a supported path that constructs >32 workers + equal-flow
   without passing through `CompileConfig`.)
2. **Threshold**: is `> 32` exactly right? `n_workers = len.min(32)` admits
   indices 0..31 = 32 workers; worker index 32 (the 33rd) is the first
   `active_outside_scratch`. So 32 is supported, 33 is the first rejected
   count. Confirm no off-by-one.
3. **Does equal-flow truly require exact** (so the reject can't be dodged)?
   `compiler.go:427` already rejects equal-flow without transmit-rate-exact.
   Could a config enable equal-flow on a non-exact scheduler to slip past?
   (Belief: no — the existing validator rejects that first; our check is
   independent and fires regardless.)
4. **Stored-config replay**: is rejecting a previously-valid stored config on
   next `commit` (rather than at `Store.Load`) the correct UX, matching the
   other strict validators? Any rolling-upgrade hazard?
5. **Constant drift**: is a Go `MaxEqualFlowWorkers = 32` mirroring the Rust
   `MAX_WORKERS_SCRATCH = 32` acceptable, or does the project prefer a single
   generated source of truth? (Two hand-synced consts with a cross-reference
   comment is the proposed approach; #1731-e retires both together.)
6. **Visibility**: is "the commit-check error is the Phase-1 visibility, the
   existing dataplane counter is the runtime visibility" a complete answer to
   the issue's "add a status counter/visibility for the fail-open reason", or
   does the issue demand a NEW distinct counter?
