# #1538 — Accumulate strict validation errors into a multierror

## Status

v4 — addresses Codex round-3 PLAN-NEEDS-MINOR (3 findings) and
AGY round-3 PLAN-NEEDS-MINOR (1 finding):
- Drop the "REQUIRED to prevent short-circuiting" rationale for
  `set system dataplane-type userspace`; it's harmless
  explicitness because `validateDataplaneTypeStrict` only
  rejects explicit `dpdk`, and unset == userspace via
  `effectiveDataplaneType` in `pkg/config/compiler.go`
  (pinned by `TestDataplaneTypeOmittedCompilesCleanly` at
  `pkg/config/parser_ast_test.go`). Line stays as
  self-documenting future-proofing.
- Fix test-count to three throughout (was "two" at v3
  plan.md:69 and :86).
- Replace bad three-color-policer syntax
  `action loss-priority high then discard` with schema-clean
  `then discard` — the `action` form parses via the
  schema-less fallback in `pkg/config/ast_edit.go` but
  is silently ignored by `compiler_firewall.go` which
  only traverses the `then` child.
- Rewrite the gRPC test plan to match the existing direct-handler
  test style at `pkg/grpcapi/server_config_test.go`
  (no bufconn — the existing tests construct `*Server`
  directly with a temp-dir Store and call handlers). Use
  `store.LoadSet(...)` per existing pattern, not nonexistent
  `LoadCandidate` / `Edit` APIs.

v3 — addresses Codex round-2 PLAN-NEEDS-MINOR. AGY round-2 was
PLAN-READY. The minor: the v2 fixture for
`TestCompileMultipleStrictErrorsAccumulated` used the "both
buffer-size bytes AND percent set" condition which is NOT
parser-reachable (the parser's compile_class_of_service.go clears
the alternate buffer field; `validateClassOfServiceStrict`
explicitly documents that the both-set state can only arise from
constructed configs). v3 fixes by:
(a) using `equal-flow-enforcement` without `transmit-rate exact`
as the parser-reachable CoS strict-validator error; and
(b) clarifying the test count (three new tests, not two) and
splitting fixture-build technique by test (parser-driven for the
accumulator tests; direct-helper-call for the byte-identity test).

v2 — addresses Codex round-1 PLAN-NEEDS-MAJOR (4 findings). AGY
round-1 was PLAN-READY. Refactored to (a) preserve #1536's
DPDK-first / no-leak contract by keeping `validateDataplaneTypeStrict`
as a separate fail-fast precheck, (b) drop the "matches Junos"
overclaim and frame as an xpf UX choice, (c) tighten wording to
"one error per validator family," (d) add a gRPC rendering test.

## Issue framing

The strict-validator block in `pkg/config/compiler.go::compileExpanded`
currently short-circuits on the first failure across three independent
validator families:

- `validateClassOfServiceStrict`   (compiler.go)
- `validateThreeColorPolicersStrict` (compiler.go)
- `validatePolicySchedulerReferencesStrict` (compiler.go)

In an upgrade scenario where a legacy candidate carries multiple
dormant structural errors (e.g., a malformed CoS scheduler-map
plus a misconfigured three-color-policer that was committed
months ago and never re-validated), the operator hits a
whack-a-mole cycle: each `commit` surfaces one finding, they
fix it, commit again, surface the next, and so on.

Issue #1538 asks the strict-validator block to accumulate
failures across these three families via `errors.Join` (Go 1.20+)
and return one combined error so the operator sees the full
picture from a single `commit check` response.

**Scope is exactly three validator families.** The
`validateDataplaneTypeStrict` precheck (added by #1536) is
explicitly EXCLUDED — see "DPDK precheck contract" below.

## Honest scope/value framing

This is a UX/operator-friction change, not a perf or correctness
change. The benefit is concentrated on **first-touch upgrade** and
**rare bulk-import** flows; once an operator has done one `commit`
cycle, the day-to-day "edit one stanza, commit, fix typo, commit"
loop is unchanged.

Absolute scale of the win:

- Affected user population: operators upgrading a multi-year-old
  candidate that survived through a feature deprecation window.
- Round-trips saved per first-touch upgrade: O(number of dormant
  strict-family errors). For most upgrades this is 1 (already a
  single pass). For the upgrade scenario the issue body lays out
  explicitly, it's 2–3 (one error per family, capped at 3).
- Surface area touched: ~6 lines of compile-driver code in
  `compileExpanded` plus three new tests (accumulator multi-error,
  single-element byte-identity, gRPC rendering). No new public
  API, no new config knob, no change to individual validator
  signatures or messages.

**Honest caveat on "one error per family."** Each existing
strict validator still fail-fasts INTERNALLY (e.g.,
`validateThreeColorPolicersStrict` returns on the first bad
policer; `validateClassOfServiceStrict` returns on the first
bad scheduler; same for `validatePolicySchedulerReferencesStrict`
— all in `pkg/config/compiler.go`). This PR does NOT
expand intra-validator accumulation. The operator gets at most
ONE error from each family in a single response — a maximum of
three findings, not "every dormant error." Future work could
extend per-validator accumulation but that's deliberately out
of scope (separate signatures + per-validator test rewrites).

**If reviewers conclude the UX gain (one round-trip saved on a
rare upgrade path) is too small to justify even ~6 LOC plus
three tests, PLAN-KILL is an acceptable verdict.** The counter-position
worth taking seriously: "fail-fast is simpler to reason about;
trains the operator to fix one thing at a time; multi-error
responses risk confusing operators about which finding is the
root cause." If reviewers weight this argument over the
upgrade-friction win, PLAN-KILL.

## DPDK precheck contract — preserved verbatim

PR #1536 (merged as commit cdad3c31 / merge 4508d714) installed
`validateDataplaneTypeStrict` at `pkg/config/compiler.go`
BEFORE the other strict validators with explicit UX intent
(`compiler.go`): the operator must see the migration
message FIRST when a candidate has both a retired dataplane-type
AND any unrelated structural error.

The brittle-by-design test `TestDataplaneTypeDPDKRejectedAtCommitFiresFirst`
at `pkg/config/parser_ast_test.go` asserts BOTH:

1. The DPDK retirement substring is present in the error
   (`parser_ast_test.go`).
2. The string "three-color-policer" does NOT leak through
   (`parser_ast_test.go`).

#1538 must NOT break either assertion. The clean answer is to
KEEP `validateDataplaneTypeStrict` as a separate fail-fast
precheck and only accumulate errors across the remaining three
families. This is exactly the resolution path Codex round-1
asked for ("keep DPDK as a separate pre-accumulator fail-fast
gate").

Concrete `compileExpanded` shape:

```go
// DPDK retirement is a migration message: it must surface FIRST
// and alone when a candidate also has unrelated structural errors,
// per #1526/#1536 UX intent and TestDataplaneTypeDPDKRejectedAtCommitFiresFirst.
if err := validateDataplaneTypeStrict(cfg); err != nil {
    return nil, err
}

// Remaining independent strict-validator families accumulate so
// `commit check` returns one error per family in a single
// response — saves operator round-trips on first-touch upgrades
// from legacy candidates carrying multiple dormant findings.
//
// Validators in this group MUST be independent of each other:
// each one reads its own typed sub-struct of *Config and does
// not depend on any other validator's having succeeded. If a
// future validator depends on another's success it must be
// added as a SEPARATE post-accumulator step with its own guard.
//
// Note: each accumulated validator still fail-fasts INTERNALLY
// (returns on its first finding within its own family). The
// accumulator surfaces at most one error per family.
var strictErrs []error
if err := validateClassOfServiceStrict(cfg.ClassOfService); err != nil {
    strictErrs = append(strictErrs, err)
}
if err := validateThreeColorPolicersStrict(cfg.Firewall.ThreeColorPolicers); err != nil {
    strictErrs = append(strictErrs, err)
}
if err := validatePolicySchedulerReferencesStrict(cfg); err != nil {
    strictErrs = append(strictErrs, err)
}
if err := errors.Join(strictErrs...); err != nil {
    return nil, err
}
```

`errors.Join` with no args returns nil; the guard handles the
empty case naturally. We use a slice + explicit `Join(...)`
rather than a helper struct because:

- It's a 6-line pattern, no new package surface.
- The `errors` package is already imported in compiler.go
  (verified at implementation time; added if not).

## Junos semantics — framing as xpf UX, not parity claim

Codex round-1 correctly observed that the v1 plan's
"matches Junos commit check accumulation" framing was an
overclaim: Junos's official documentation shows the
`[edit ...]` rendering format but does NOT provide a public
transcript proving accumulation across the specific validator
classes touched here (CoS scheduler-map + three-color-policer
+ scheduler-reference). It is plausible Junos accumulates;
plan v2 does NOT claim this without evidence.

**Plan v2 framing:** this PR makes the xpf strict-validator
block accumulate errors across three independent families as
an xpf UX choice grounded in operator-friction reduction on
upgrade flows. We do NOT claim Junos parity. The DPDK
precheck remains fail-fast per #1536's explicit intent. If
operators report Junos-divergence pain, a follow-up issue can
add a `set system commit fail-fast-strict-validators` knob or
similar.

## Public API preservation

- `CompileConfig(tree *ConfigTree) (*Config, error)` —
  signature unchanged; return semantics unchanged (`(nil, err)`
  on any strict validation failure, where the err is now an
  `errors.Join` of up to 3 family errors when DPDK is NOT in
  play; or the DPDK error alone when it is).
- `CompileConfigForNode(tree *ConfigTree, nodeID int) (*Config, error)`
  — same.
- Individual validator signatures
  (`validateDataplaneTypeStrict(*Config) error`,
  `validateClassOfServiceStrict(*ClassOfServiceConfig) error`,
  `validateThreeColorPolicersStrict(map[string]*ThreeColorPolicerConfig) error`,
  `validatePolicySchedulerReferencesStrict(*Config) error`) —
  unchanged.
- `Store.Commit()` / `Store.CommitCheck()` /
  `Store.CommitWithDescription()` / `Store.CommitConfirmed()` —
  signatures unchanged; wrap-text unchanged.
- gRPC `CommitCheck` / `Commit` — signatures unchanged.
  `status.Errorf(codes.InvalidArgument, "%v", err)` renders the
  joined multi-line text inside the gRPC error message.

## errors.Join semantics — verified properties

1. **`Error()` rendering.** `errors.Join(a, b).Error()` ==
   `a.Error() + "\n" + b.Error()` (Go std lib spec).
2. **`Is()` traversal.** `errors.Is(join, target)` returns true
   if `errors.Is(any-joined-err, target)`. `errors.Join` returns
   a `joinError` with `Unwrap() []error`, traversed by
   `errors.Is` since Go 1.20.
3. **Wrap chain.** `fmt.Errorf("commit check failed: %w", join)`
   at `pkg/configstore/store.go` wraps the join into a
   single `%w` chain; `errors.Is/As` traverse through that
   wrap AND the underlying join.
4. **Substring contracts.** `strings.Contains(join.Error(), substr)`
   works because `errors.Join` preserves each constituent's
   bytes; the only added bytes are `\n` separators between
   children. No existing test in `pkg/config/*_test.go` or
   `pkg/configstore/*_test.go` uses byte-exact `==` matching
   on these errors (audited by Gemini/AGY rounds).

## Hidden invariants the change must preserve

1. **DPDK fail-fast + no-leak.** Documented above. Verified by
   `TestDataplaneTypeDPDKRejectedAtCommitFiresFirst`.

2. **Validator independence within the accumulator.**
   - `validateClassOfServiceStrict` (`compiler.go`) —
     reads `cos.Schedulers` and `cos.SchedulerMaps` only. Nil-safe
     on `cos == nil`, each `sched == nil`, each `schedMap == nil`,
     missing scheduler reference.
   - `validateThreeColorPolicersStrict` (`compiler.go`) —
     reads `cfg.Firewall.ThreeColorPolicers` map only. Nil-safe
     on each `pol == nil`.
   - `validatePolicySchedulerReferencesStrict` (`compiler.go`) —
     reads `cfg.Schedulers` and `cfg.Security.Policies` /
     `cfg.Security.GlobalPolicies` only. Nil-safe on `cfg == nil`,
     `zpp == nil`, `pol == nil || pol.SchedulerName == ""`.

   `compileExpanded` only reaches the strict block after all
   compile_* phases succeed (`compiler.go`), so the
   typed sub-structs are independently populated regardless of
   whether any one validator returns an error. Cross-contamination
   is impossible: validators are pure functions over the typed
   `*Config`.

3. **Error message bytes preserved.** Each validator's
   `fmt.Errorf(...)` call site is unchanged. Only the calling
   block is restructured.

4. **Ordering preserved when reported.** The slice append order
   is CoS → policers → policy-scheduler-references. `errors.Join`
   prints in slice order. This matches the v1 fail-fast order
   so existing operator muscle memory (and any external runbook
   pinning the visual order) is preserved.

5. **No silent drop on the "no errors" path.** The
   `if err := errors.Join(strictErrs...); err != nil { return nil, err }`
   guard handles the empty-slice case (returns nil) and the
   all-nil case. Happy path returns `(cfg, nil)` exactly as
   before.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Validator outputs unchanged; only caller assembly differs. Existing per-validator tests continue to pass. |
| DPDK contract break | NONE | DPDK precheck kept as separate fail-fast; `TestDataplaneTypeDPDKRejectedAtCommitFiresFirst` continues to pass. |
| Performance regression | NONE | `commit check` runs once per commit; running 3 validators vs short-circuiting is microseconds. |
| `errors.Join` semantics | LOW | Pattern already established (10+ existing sites). Go 1.20+ std lib. |
| Substring contract drift | LOW | Audited — only `strings.Contains` matches exist on these errors; `\n` separators are inert. |
| Junos UX divergence | UNKNOWN | We're not claiming parity. If operators report pain a fail-fast knob can be added in a follow-up. |
| AST/parser interaction | NONE | Parser unaffected. |

## Test plan

### New tests — three total

**Fixture choice — parser-reachable strict-validator errors.**

The CoS "both buffer-size bytes AND percent set" condition is
NOT parser-reachable: `pkg/config/compiler_class_of_service.go`
clears the alternate field, and the validator at
the comment in `pkg/config/compiler.go` notes the state "can only arise in
constructed or externally-assembled configs." For tests that
drive through `CompileConfig` we use parser-reachable conditions:

- **CoS family error (parser-reachable):**
  `set class-of-service schedulers <name> equal-flow-enforcement`
  WITHOUT a `transmit-rate exact` setter — triggers
  `class-of-service scheduler %q equal-flow-enforcement requires
  positive transmit-rate exact` in `validateClassOfServiceStrict`.
- **Policer family error (parser-reachable):**
  `set firewall three-color-policer <name> single-rate color-blind`
  WITHOUT a `committed-information-rate` setter — triggers
  `firewall three-color-policer %q requires positive
  committed-information-rate` in `validateThreeColorPolicersStrict`.

For the byte-identity test we call the helper directly (no parser).

---

1. **`TestCompileMultipleStrictErrorsAccumulated`** —
   `pkg/config/compiler_test.go` (new file, or appended to
   `parser_class_of_service_test.go` if size allows). Drive via
   `CompileConfig`. Construct a `ConfigTree` via
   `ParseSetCommand` + `tree.SetPath` loop per CLAUDE.md "Parser
   Dual AST Shape & Set Syntax Testing":

   ```
   set system dataplane-type userspace
   set class-of-service schedulers bad-sched equal-flow-enforcement
   set firewall three-color-policer bad-pol single-rate color-blind
   set firewall three-color-policer bad-pol then discard
   ```

   The `set system dataplane-type userspace` line is harmless
   explicitness (unset == userspace via `effectiveDataplaneType`
   in `pkg/config/compiler.go`, so `validateDataplaneTypeStrict`
   returns nil either way — see
   `TestDataplaneTypeOmittedCompilesCleanly` in
   `pkg/config/parser_ast_test.go`). Keeping the line in the
   fixture makes the test self-documenting and guards against
   any future change to the default-dataplane behavior.

   The `then discard` line uses the schema-supported action
   syntax for three-color-policer per the `three-color-policer`
   entry in `pkg/config/ast.go`; an earlier draft used the
   schema-less `action loss-priority high then discard` which
   parses (via the fallback path in `ast_edit.go`) but is
   silently ignored by the three-color-policer compile block in
   `compiler_firewall.go` because the compiler only traverses
   the `then` child. Schema-clean syntax keeps the test honest.

   Assertions:
   - `err != nil`.
   - `strings.Contains(err.Error(), "equal-flow-enforcement")` —
     CoS family error present.
   - `strings.Contains(err.Error(), "committed-information-rate")` —
     policer family error present.
   - `strings.Count(err.Error(), "\n") == 1` — exactly one
     newline between the two joined errors (verifies multi-error
     rendering, not one validator winning by ordering).
   - `errors.Is(err, ErrDPDKDataplaneRetired) == false` (DPDK
     not in play; defense-in-depth).

2. **`TestCompileSingleStrictErrorJoinPath`** —
   `pkg/config/compiler_test.go`. Drives through the production
   path `ParseSetCommand` → `tree.SetPath` → `CompileConfig`
   with a fixture that triggers ONLY the CoS family (no policer
   lines), so the accumulator slice ends up length-1. Asserts
   `err.Error()` is byte-identical to a direct
   `validateClassOfServiceStrict` call on an equivalent stub
   `*ClassOfServiceConfig` (the direct call is the reference
   value; the test only USES it for comparison, not as the
   production path). Plus zero-`\n`-separator and an incidental
   `errors.Is(err, ErrDPDKDataplaneRetired) == false`
   wrap-chain traversal assertion. Pins `errors.Join`'s
   single-element semantics (Go std lib documents
   byte-identity in the std `errors.Join` source). Exercising
   the production `CompileConfig` path catches any future
   regression that wraps or reformats the single-error result
   inside `compileExpanded` (per Codex code-review round-1
   finding on the original test design).

3. **`TestCompileCheckMultiErrorRendersThroughGRPC`** —
   `pkg/grpcapi/server_config_test.go`. Construct a `*Server`
   directly with a temp-dir-backed `configstore.Store` per the
   existing pattern in that file (no bufconn — the existing
   tests construct handlers directly with a `*Server` value
   plus a `*configstore.Store`). Seed the candidate via
   `store.EnterConfigure()` + repeated `store.LoadSet(...)`
   with the same fixture lines as test 1 (CoS
   `equal-flow-enforcement` + policer `single-rate color-blind`
   + `then discard`). Call `s.CommitCheck(...)`; assert the
   returned gRPC error has `status.Code() == codes.InvalidArgument`
   and `status.Message()` contains BOTH error substrings (CoS
   family + policer family) verbatim, separated by a single
   `\n`.

   Rationale (Codex r2 agreed): the rendering layer being
   tested is `pkg/grpcapi/server_config.go`, not
   configstore. Configstore only emits raw/wrapped errors via
   `pkg/configstore/store.go` (`Commit` wraps the compile
   error). Testing at the gRPC
   boundary captures the actual operator-facing surface, and
   doing it via direct-handler call (not bufconn) matches the
   existing test style.

### Existing test gates (must not regress)

- `TestDataplaneTypeDPDKRejectedAtCommitFiresFirst`
  (`pkg/config/parser_ast_test.go`) — DPDK contract.
- `TestDPDKConfigCompileRejects`
  (`pkg/config/parser_ast_test.go`) — DPDK substring + sentinel.
- `TestCompileClassOfServiceBothBufferFieldsRejected`
  (`pkg/config/parser_class_of_service_test.go`) — direct
  validator call, unaffected.
- `TestCommit_RejectsDPDKDataplaneType`
  (`pkg/configstore/store_test.go`) — wrapped DPDK
  substring through Commit, unaffected.
- All other commit/commit-check substring tests in
  `pkg/configstore/store_test.go`.

### Flake check

5× loop on `TestCompileMultipleStrictErrorsAccumulated`,
`TestCompileSingleStrictErrorJoinPath`, and
`TestCompileCheckMultiErrorRendersThroughGRPC` after
implementation. Per standing rule.

### Build / test cycle

- `go build ./...` clean.
- `go test ./pkg/config/... ./pkg/configstore/... ./pkg/grpcapi/...` clean.
- `go test ./...` clean.
- `cargo build --release` clean (no Rust touched).

### Smoke matrix

Full per-standing-rule matrix on `loss:xpf-userspace-fw0/fw1`:
v4 + v6 × push + reverse × CoS-off + CoS-on. Per-standing rule
the smoke is a sanity gate (config-compile-side only — no
dataplane/Rust/FRR/networkd touched). Any throughput deviation
vs master baseline is a smoke-environment issue (re-apply CoS,
repeat), not a regression.

## Out of scope (explicitly)

- `set system commit fail-fast-strict-validators` knob —
  follow-up if operator pain materializes.
- Intra-validator accumulation. Each strict family still
  fail-fasts internally; the PR only accumulates ACROSS
  families.
- Touching `validateDataplaneTypeStrict` — fail-fast precheck
  intentionally preserved per #1536.
- Touching the `ValidateConfig` warnings path.
- Touching parse-phase errors (already fail-fast; parser bails
  on lexer-level errors so the AST is incomplete and
  subsequent validation would crash anyway).
- Rendering changes to the CLI / gRPC `commit check` output
  format. `%v` over an `errors.Join` renders newline-separated
  by default; we accept that and don't add a custom formatter.
- Adding a sentinel for "multiple validation errors." Callers
  still match individual findings via `errors.Is` and substring;
  no aggregate sentinel needed.

## Implementation order

1. Land plan; iterate to PLAN-READY across Codex + AGY (took 4
   rounds; plan v4 is the final).
2. Edit `compileExpanded` per the design above (keep DPDK
   precheck; accumulate the remaining 3).
3. Add the three new tests.
4. `go test ./...` clean.
5. 5× flake loop on the new tests.
6. cargo build sanity.
7. Smoke matrix on loss userspace cluster.
8. Open PR, dispatch Codex + AGY code review, wait for Copilot.
9. Iterate to MERGE-READY across all four (Claude SMR + Codex
   + AGY + Copilot). Auto-merge when 4-of-4 agree.
10. Report PR URL + verdicts.

## Open questions for adversarial reviewers (historical)

1. **Test placement for the gRPC rendering test.** Is
   `pkg/grpcapi/server_config_test.go` the right home, or
   should it live in `pkg/configstore/store_test.go` since
   that's where the wrap chain originates? Plan picks
   `pkg/grpcapi` because that's where the rendering layer
   tested (`%v` of a `status.Errorf`) actually lives. Open
   to alternative if reviewer prefers configstore.

2. **One-element Join byte-identity guarantee.** Plan asserts
   `errors.Join(singleErr).Error() == singleErr.Error()` per
   Go std lib spec. Is there a documented edge case where
   the joinError adds framing for the one-element case?
   The Go `errors.Join` docstring says it returns nil if
   every error is nil and otherwise concatenates with `\n`;
   for a single non-nil input the concatenation is
   single-element so no separator is emitted. Verify against
   Go 1.20+ source if in doubt.

3. **`errors.Is` traversal through Join + %w wrap.** Plan
   relies on Go 1.20's multi-unwrap behavior. The wrap chain
   here is `fmt.Errorf("commit check failed: %w", join)` →
   `join.Unwrap() []error` → individual validator errors.
   `errors.Is` traverses both. If a reviewer has evidence of
   Go-version-specific behavior or a particular sentinel
   that won't traverse, flag.

4. **Smoke is a sanity gate, not a regression gate.** This is
   a Go-only config-side change. Per standing-rule smoke we
   still run the full 6-port v4+v6 × push+reverse × CoS
   matrix, but expectations are byte-identical throughput
   vs master. Reviewers concerned about hidden coupling
   should call it out.

5. **PLAN-KILL grounds.** The UX win is one round-trip saved
   on the rare upgrade path. Codex round-1 did NOT
   PLAN-KILL but the counter-argument ("fail-fast is simpler
   to reason about") is still valid. Reviewers who weight
   the simplicity argument over the upgrade-friction one
   should PLAN-KILL explicitly.
