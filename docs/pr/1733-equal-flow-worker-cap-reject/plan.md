# Plan of Action — #1733 Phase 1: hard-reject `workers > 32` when equal-flow enforcement is enabled

- **Status**: DRAFT v2 — round-1 converged MAJOR (Codex + AGY) folded in:
  the commit-time reject MUST be paired with a Load/SyncApply rewrite
  bridge or upgrade/HA-sync blacks out. Section 5.2/5.3 rewritten.
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
`commit`/`commit check` time — hard-reject when
`workers > 32 AND any scheduler has equal-flow-enforcement` — instead of
fail-opening silently at runtime in release. Pair the commit-time reject
with a **Load/SyncApply rewrite bridge** (mirroring
`rewriteRetiredDataplaneType`) so a legacy persisted/peer-synced config
does NOT black out daemon boot or break HA sync. Plus surface the existing
dataplane fail-open-reason gauge as the runtime visibility for the
condition.

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

**Predicate-precision note (Codex r1 minor):** `cfg.Workers > 32` is the
*configured* worker count, which is a conservative proxy for the *runtime*
lease worker count. The runtime lease is sized from planned workers
(`coordinator/mod.rs:845` `last_planned_workers()`), and binding assignment
is `queue_id % workers` over detected RX queues (`server/helpers.rs:618,636`),
so a `workers 64` config on hardware with <=32 usable RX queues may build
<=32 lease slots and NOT actually fail-open. The Phase-1 policy is
deliberately "configured workers above 32 WITH equal-flow is unsupported" —
reject the *configuration*, not only configs that provably misbehave on the
current hardware. This is the safe, hardware-independent contract; the plan
text no longer claims it rejects "only configs that currently misbehave".

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

### 5.2 Load/SyncApply rewrite bridge (round-1 MAJOR — REQUIRED)

**The round-1 fatal (Codex + AGY converged):** my v1 claimed a legacy
`workers>32 + equal-flow` config is "NOT auto-rejected at `Store.Load`".
That is FALSE and verified false: `Store.Load()` (`configstore/store.go:105`)
and `Store.SyncApply()` (`:222`) both call `s.compileTree(tree)` →
`CompileConfig`/`CompileConfigForNode` → `compileExpanded` → the strict
accumulator. Wiring the reject into the accumulator ALONE would, on a node
upgraded past this gate:
- fail `Store.Load()` at boot → daemon runs with nil active config (blind);
- fail `Store.SyncApply()` on an upgraded standby receiving a >32+equal-flow
  config from an un-upgraded primary → HA config-sync alarm loop.

**Fix — mirror `rewriteRetiredDataplaneType` (`configstore/dataplane_retire.go`).**
Add `rewriteEqualFlowOverWorkerCap(tree, caller)` invoked AFTER parse,
BEFORE compile, in BOTH `Store.Load()` (after the existing
`rewriteRetiredDataplaneType(tree, LoadCaller)` at `store.go:103`) and
`Store.SyncApply()` (after `:214`'s retired rewrite, `SyncCaller`). It:
1. Discovers the effective worker count by walking
   `system { dataplane { ... } }` for a `workers` leaf, handling BOTH AST
   shapes verified empirically:
   - normal: `dataplane` -> leaf `Keys:["workers","N"]`;
   - redundant `set system dataplane userspace workers N`
     (`compiler_system.go:415-436`): `dataplane` -> leaf
     `Keys:["userspace","workers","N"]` (3-key leaf — the walk must match
     a `workers` token anywhere in the dataplane leaf keys, not only
     `Keys[0]=="workers"`).
   Walk top-level AND `groups { <g> { system {...} } }` nesting — reuse the
   existing `systemBlocksOf` / `groupsBlocksOf` / `systemBlocksOfNode`
   helpers in `dataplane_retire.go`. Absent `workers` leaf => effective
   count 1 (`lifecycle.rs:257`) => rewrite is a no-op.
2. If `workers > MaxEqualFlowWorkers`, strip every
   `equal-flow-enforcement` leaf (AST shape verified: `class-of-service`
   -> `schedulers <name>` -> leaf `Keys:["equal-flow-enforcement"]`) from
   both top-level and grouped `class-of-service` stanzas, logging one
   `slog.Warn` per strip with caller-specific remediation.

**Why stripping equal-flow is the behaviorally-correct rewrite (not a
silent override):** a legacy `workers>32 + equal-flow` config was ALREADY
fail-opening equal-flow at runtime in release (the exact bug #1733
documents). Removing the leaf on load therefore *preserves the actual
running behavior* (equal-flow effectively off), boots clean, and warns —
precisely analogous to rewriting a retired `dataplane-type` to the
userspace default. The operator's next `commit` that re-adds equal-flow
without reducing workers will hard-reject, surfacing the limit.

Threshold parity: the rewrite uses the SAME `MaxEqualFlowWorkers` constant
as the commit-time validator, so reject-set and rewrite-set are identical
by construction (no skew).

Caller phrasing: reuse the existing `retireRewriteCaller`
(LoadCaller/SyncCaller) — its local-`commit` vs update-the-primary
distinction matches this case exactly. (If reuse turns out to couple the
two rewrites awkwardly at implementation, fall back to a parallel
two-value enum; the doc comment will cross-reference either way.)

### 5.3 Runtime visibility (the "status counter for the fail-open reason")

The dataplane already exposes the fail-open reason end-to-end:
- Rust: `V8EqualFlowFailOpenReason::UnsampledActiveWorker`
  (`shared_cos_lease/mod.rs:444`), `fail_open_reason` + `fail_open_count`
  (`:497`) atomics, accessors `v8_equal_flow_fail_open_reason()` /
  `v8_equal_flow_fail_open_count()` (tested in `shared_cos_lease_tests.rs`).
- Go/Prometheus: `xpf_userspace_cos_equal_flow_fail_open` is a **GaugeValue
  with a `reason` label** (`metrics_userspace.go:977-981`,
  `metrics_descriptors.go:349`); the `reason="unsampled_active_worker"`
  series is the >32-worker fail-open signal. (Codex precision: it is a
  reason GAUGE, not a monotonic end-to-end counter — accurate framing.)

So the *runtime* fail-open visibility the issue asks for already exists as
a reason-labelled gauge. Phase 1's additional visibility is the **loud
commit-check rejection** + the **Load/SyncApply WARN log**. I will NOT add
a duplicate Prometheus counter. The plan documents this mapping in the CoS
scheduler doc so an operator who sees the `unsampled_active_worker` gauge
series on a legacy config knows the condition and the fix.

### 5.4 No Rust change in Phase 1

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
- **Load/SyncApply tolerance (round-1 MAJOR)**: a legacy persisted/synced
  `workers>32 + equal-flow` config must NOT blackout-boot or break HA sync;
  the §5.2 rewrite bridge strips equal-flow (preserving the already-running
  fail-open behavior) and warns, exactly as `rewriteRetiredDataplaneType`
  does for retired backends. ✓
- **Rewrite/reject threshold parity**: both use `MaxEqualFlowWorkers` — the
  rewrite cannot strip a config the validator would have accepted, nor vice
  versa. ✓

## 8. Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | LOW | Additive validator + load/sync rewrite. The rewrite strips equal-flow only when workers>32 — which was already fail-opening at runtime — so running behavior is preserved. Valid configs (<=32 workers, or equal-flow absent) compile unchanged. |
| Upgrade / HA-sync regression | MED→LOW | Round-1 MAJOR: bare accumulator reject would blackout boot + break sync. MITIGATED by the §5.2 Load/SyncApply rewrite bridge mirroring the proven `rewriteRetiredDataplaneType` pattern. Must be covered by configstore tests (§9). |
| Lifetime / borrow | N/A (Go) | No Rust change. |
| Performance regression | NONE | Validator runs once per `commit`, O(schedulers); rewrite once per Load/SyncApply, O(tree). No hot-path touch. |
| Architectural mismatch | LOW | Locus is the established `*Config`-scoped strict-validator pattern (`validatePolicySchedulerReferencesStrict`) + the established Load/SyncApply rewrite-bridge pattern (`rewriteRetiredDataplaneType`). Both are precedented in-tree. |

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
- **Load/SyncApply rewrite tests** (`pkg/configstore`, mirroring
  `TestRewriteRetiredDataplaneType`): assert that a tree with
  `workers 33` + `equal-flow-enforcement` (a) loads/sync-applies WITHOUT a
  compile error (no blackout), (b) has the `equal-flow-enforcement` leaf
  stripped post-rewrite, (c) leaves equal-flow intact when `workers <= 32`,
  (d) covers the `groups { ... }`-nested workers + CoS shape. This is the
  regression gate for the round-1 MAJOR.
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
- A new Prometheus counter (the existing reason-labelled
  `xpf_userspace_cos_equal_flow_fail_open` gauge already covers runtime
  visibility).
- Auto-reducing workers or any silent config mutation OTHER than the
  load/sync equal-flow strip (which only matches the already-running
  fail-open behavior).
- Mirroring the reject in `lifecycle.rs` arg-parse (the daemon receives an
  already-validated config from the control plane; double-validating in the
  helper is redundant — see Open Question Q2).

## 11. Open questions for adversarial review (round-2)

Round-1 RESOLVED (verified, see §): Q-locus — no supported bypass of
`CompileConfig` (Codex + AGY both confirmed Load/SyncApply/commit all
route through it). Q-threshold — `> 32` exact, no off-by-one (both
confirmed: id 32 is first `active_outside_scratch` at len 33). Q-dodge —
equal-flow already requires transmit-rate exact (`compiler.go:427`),
cannot slip past. Q-visibility — existing reason-labelled gauge +
commit-check error + WARN log is sufficient; no new counter. Q-constant —
hand-synced const with cross-ref accepted (AGY: pragmatic; #1731-e retires
both); a canary test asserting parity is the cheap insurance (Codex
suggestion — adopted, see below).

Open for round-2:

1. **Rewrite-bridge correctness (the round-1 MAJOR fix)**: is stripping
   `equal-flow-enforcement` on Load/SyncApply when workers>32 the right
   rewrite (preserving the already-running fail-open behavior), or should
   the bridge instead leave equal-flow and reduce/clamp workers? (Belief:
   strip equal-flow — clamping workers would silently change the dataplane
   worker topology, a far larger behavioral change than removing a knob
   that was already a runtime no-op. Mirrors retired-dataplane strip.)
2. **Rewrite caller reuse**: reuse `retireRewriteCaller` (Load/Sync) vs a
   new parallel enum — any coupling hazard from reuse?
3. **Constant-parity canary**: should a Go test assert
   `MaxEqualFlowWorkers == 32` with a comment pinning it to
   `rotate_epoch_v8.rs:71`'s `MAX_WORKERS_SCRATCH` (Codex r1 suggestion)?
   (Belief: yes — cheap, catches a future Rust-side bump that forgets Go.
   Adopted in §9.)
4. **Worker-count discovery in the rewrite**: the rewrite reads `workers`
   from the AST (pre-compile). Are there worker-count forms the AST walk
   could miss (e.g. `set system dataplane userspace workers N` redundant
   path at `compiler_system.go:415-436`, or split `system` stanzas)? The
   walk must cover the same shapes `compileUserspaceDataplane` accepts.
5. **Default-workers semantics in the rewrite**: if no `workers` leaf is
   present, the effective count is 1 (`lifecycle.rs:257`), so the rewrite
   is a no-op — confirm the walk treats "absent" as <=32, never as >32.
