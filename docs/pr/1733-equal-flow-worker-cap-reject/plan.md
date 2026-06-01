# Plan of Action — #1733 Phase 1: hard-reject `workers > 32` when equal-flow enforcement is enabled

- **Status**: PLAN-READY (v3, round-3 converged). Round-3 Codex + AGY both
  flagged the SAME final item — read-only peer-display active-tree
  re-compiles (`cli_show_interfaces.go`, `server_show_interfaces.go`) must
  be lenient too — now fixed. AGY independently verified all other v3
  points sound. Design history: v1 (accumulator-only) killed by the
  Load/SyncApply blackout MAJOR; v2 (AST-walk rewrite) killed by Codex's
  semantic-set-parity defect; v3 lenient-compile-mode adopted. Implemented
  + tested; see §9 results.
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
with a **lenient compile mode** on `Store.Load` / `Store.SyncApply` that
downgrades ONLY this one validator to a loud `cfg.Warnings` entry (+ WARN
log) so a legacy persisted/peer-synced config does NOT black out daemon
boot or break HA sync. Plus surface the existing dataplane
fail-open-reason gauge as the runtime visibility for the condition.

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

### 5.2 Lenient compile mode on Load/SyncApply (round-1 MAJOR + round-2 parity fix)

**Round-1 fatal (Codex + AGY converged):** my v1 claimed a legacy
`workers>32 + equal-flow` config is "NOT auto-rejected at `Store.Load`".
FALSE and verified: `Store.Load()` (`configstore/store.go:105`) and
`Store.SyncApply()` (`:222`) both call `s.compileTree(tree)` ->
`CompileConfig`/`CompileConfigForNode` -> `compileExpanded` -> the strict
accumulator. A bare accumulator reject would blackout boot + break HA sync.

**Round-2 refinement (Codex):** my v2 proposed an AST-walk rewrite that
strips `equal-flow-enforcement` when a raw-tree `workers` leaf > 32. That
has a **semantic-set-parity defect**: the raw AST walk does NOT replicate
the compiler's effective-config computation. `CompileConfig` /
`CompileConfigForNode` run `ExpandGroups`/`ExpandGroupsWithVars` BEFORE
`compileExpanded` (`compiler.go:51,82`). So a config like
`groups { node0 { system dataplane workers 64 } }` + `apply-groups
"${node}"` + equal-flow has EFFECTIVE workers 64 only on node0; on node1 it
is the default (≤32). A raw walk would **false-strip** equal-flow on node1
(and on a generic non-node compile). The validator, by contrast, sees the
correctly-expanded per-node effective config and would NOT reject node1.
Threshold-constant parity does not fix this — it is *worker-discovery*
parity that is broken, and re-implementing group expansion in the rewrite
is exactly the duplication that would drift.

**Adopted fix — lenient compile mode (Codex's design).** Add a compile
variant that runs the IDENTICAL pipeline (same expansion, same node
context, same effective config) but downgrades ONLY
`validateEqualFlowWorkerCapStrict` from a hard error to a
`cfg.Warnings` append + one `slog`-style WARN. Everything else stays
strict.

Concretely:
- Thread a `strictMode` (or a `lenientEqualFlowWorkerCap bool`) through
  `compileExpanded`: `CompileConfig`/`CompileConfigForNode` (strict, used
  by candidate commit) keep today's behavior; new
  `CompileConfigLenient`/`CompileConfigForNodeLenient` set the lenient flag.
  In `compileExpanded`, when lenient, the equal-flow-worker-cap validator's
  error is appended to `cfg.Warnings` instead of `strictErrs`.
- `Store.compileTree` gains a lenient sibling (or a mode arg) used ONLY by
  `Store.Load()` and `Store.SyncApply()`. Candidate commit / `commit
  check` (`Store.CommitCheck`/`Commit`/`CommitConfirmed`, which compile
  `s.candidate` directly — AGY confirmed they do NOT go through Load/Sync)
  stay strict and hard-reject.

**Why this is correct and beats the AST rewrite:**
- The effective worker count is computed ONCE, by the real compiler, with
  the right node context — zero re-implementation, zero false-strip.
- A legacy `workers>32 + equal-flow` config loads/sync-applies clean; the
  equal-flow leaf stays in the typed config and the runtime continues to
  fail-open it exactly as it does today — *running behavior preserved*,
  identical to the pre-gate release (the AGY "preserve running behavior"
  property holds, without mutating the tree).
- The operator sees the condition via `cfg.Warnings` (surfaced by
  `show ... | display ... warnings` / commit warnings) and the WARN log;
  their next candidate commit that keeps the combo hard-rejects.

**Warning text (AGY r2 minor):** do NOT reuse the retired-dataplane
phrasing. The lenient-path warning is equal-flow-specific, e.g.
`"system dataplane workers %d exceeds the equal-flow cap of %d: equal-flow
fairness is silently disabled at runtime; reduce workers or remove
equal-flow-enforcement (this config was tolerated on load/sync — your next
commit will be rejected)"`. The Load vs Sync remediation hint differs
(local `commit` vs update the un-upgraded primary), mirroring
`retireRewriteCaller.remediation()` but with equal-flow wording.

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
  the §5.2 lenient compile mode downgrades ONLY this validator to a warning
  on Load/Sync so the config loads clean, equal-flow stays in the typed
  config, and the runtime continues to fail-open it as today. ✓
- **Effective-config parity (round-2 MAJOR)**: leniency uses the SAME
  compile pipeline (same group expansion, same node context) as the strict
  path, so the lenient warning fires on EXACTLY the configs the strict
  reject would — no false-strip on `${node}`/split-stanza/group configs
  whose effective workers ≤32. ✓ (This is why AST mutation was rejected.)
- **Read-only active-tree re-compiles must be lenient (round-3, Codex +
  AGY converged)**: the peer-interface display paths
  `cli_show_interfaces.go:577` and `server_show_interfaces.go:436`
  re-compile the (already lenient-loaded) active tree for the peer node and
  swallow errors with `if err == nil`. A STRICT re-compile there would now
  error on a tolerated legacy config and silently drop peer-interface
  display on a healthy cluster. Both switched to
  `CompileConfigForNodeLenient`. ✓ (Audited all `config.CompileConfig*`
  callers — these two are the only non-commit active-tree re-compiles.)

## 8. Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | LOW | Additive validator + lenient Load/Sync mode. On load the equal-flow leaf is untouched and the runtime fail-opens it as today — running behavior preserved. Valid configs (<=32 effective workers, or equal-flow absent) compile unchanged. |
| Upgrade / HA-sync regression | MED→LOW | Round-1 MAJOR: bare accumulator reject would blackout boot + break sync. MITIGATED by §5.2 lenient compile mode (downgrade-to-warning on Load/SyncApply only). Covered by configstore + compiler tests (§9). |
| False-strip / semantic-parity | round-2 MAJOR → RESOLVED | The v2 AST-walk could false-strip equal-flow on `${node}`/group configs whose effective workers ≤32. ELIMINATED by computing effective workers via the real compiler in lenient mode (no separate worker-discovery). |
| Lifetime / borrow | N/A (Go) | No Rust change. |
| Performance regression | NONE | Validator runs once per compile, O(schedulers). No hot-path touch, no extra tree walk. |
| Architectural mismatch | LOW | Lenient-compile-mode + `*Config`-scoped strict validator are both standard control-plane patterns. No AST mutation of stored config. |

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
- **Lenient-mode compiler tests** (`pkg/config`): assert
  `CompileConfigLenient` on `workers 33` + equal-flow returns NO error,
  with a `cfg.Warnings` entry naming the cap; and that strict
  `CompileConfig` on the SAME tree returns the hard error. Boundary:
  `workers 32` + equal-flow → no warning, no error in both modes.
- **Semantic-parity test (round-2 MAJOR gate)** (`pkg/config`): a config
  with `workers 64` inside `groups { node0 { ... } }` + a benign
  `groups { node1 { ... } }` (no workers) + `apply-groups "${node}"` +
  equal-flow — `CompileConfigForNode(tree, 1)` (node1, node0 group not
  applied) must NOT warn/reject (effective workers ≤32), while
  `CompileConfigForNode(tree, 0)` (node0) strict-rejects and
  `CompileConfigForNodeLenient(tree, 0)` warns. The benign `node1` group is
  required so `${node}` expansion for node1 does not error on an undefined
  group (Codex r3). This is the test an AST-walk rewrite would have failed.
- **Store Load/SyncApply tests** (`pkg/configstore`): assert a persisted /
  peer-synced `workers 33` + equal-flow config loads / sync-applies WITHOUT
  error (no blackout) and produces a warning; and that a `workers 32` +
  equal-flow config is unaffected. Regression gate for round-1 MAJOR.
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
- Auto-reducing workers or any config MUTATION on load/sync. The lenient
  mode does NOT mutate the tree — it only downgrades the validator verdict.
- Mirroring the reject in `lifecycle.rs` arg-parse (the daemon receives an
  already-validated config from the control plane; double-validating in the
  helper is redundant).

## 11. Open questions for adversarial review (round-3)

ROUND-1 RESOLVED (verified): Q-locus — no supported bypass of
`CompileConfig` (Load/SyncApply/commit all route through it). Q-threshold —
`> 32` exact (id 32 is first `active_outside_scratch` at len 33). Q-dodge —
equal-flow already requires transmit-rate exact (`compiler.go:427`).
Q-visibility — existing reason-labelled gauge + reject error + WARN
sufficient; no new counter. Q-constant — hand-synced const + parity canary
test (adopted §9).

ROUND-2 RESOLVED: the v2 AST-walk rewrite is ABANDONED for a semantic-set
parity defect (false-strip on `${node}`/group/split-stanza configs whose
effective workers ≤32). Replaced by the lenient-compile-mode design
(§5.2), which computes effective workers via the real compiler — no
worker-discovery duplication, no false-strip. AGY's log-phrasing minor
folded into the warning text.

Open for round-3:

1. **Lenient-mode plumbing shape**: is threading a `strictMode` flag /
   adding `CompileConfigLenient` siblings the cleanest way to downgrade ONE
   validator, or is there a less invasive hook? (Belief: a single bool
   threaded into `compileExpanded` that routes this one validator's error
   to `cfg.Warnings` is minimal and local.)
2. **Candidate-path strictness**: confirm `CommitCheck`/`Commit`/
   `CommitConfirmed` compile `s.candidate` WITHOUT the lenient flag so
   operator edits still hard-reject (AGY confirmed they bypass Load/Sync;
   re-verify in implementation).
3. **Rollback path** — RESOLVED in plan: `Store.Rollback` (`store.go:946`)
   only swaps `s.candidate` (no compile); the compile happens on the
   subsequent `Commit` (strict). So an operator rolling back to a legacy
   >32+equal-flow config and committing it correctly gets the hard reject
   (active operator action, not a passive load). Lenient applies ONLY to
   `Store.Load` (`:105`) and `Store.SyncApply` (`:222`); `compileTree`
   stays strict for all commit paths — implement as a separate
   `compileTreeLenient` rather than a flag on the shared `compileTree`.
4. **Worker-count source for the validator** — the validator reads the
   TYPED `cfg.System.UserspaceDataplane.Workers` (post-compile), NOT the
   AST, so every worker-count form `compileUserspaceDataplane` accepts
   (normal leaf, redundant `userspace`-prefixed leaf, split `system`
   stanzas) is already normalized to one int by the compiler. This is the
   key advantage over the abandoned AST walk: discovery parity is free.
   Absent `workers` => `cfg.Workers == 0` => `0 <= 32` => no reject (the
   runtime defaults to 1; 0/absent is correctly treated as ≤cap).
