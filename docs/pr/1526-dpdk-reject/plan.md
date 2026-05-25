# #1526 — Reject `system dataplane-type dpdk` at commit

## Status

DRAFT v3 — addressing round-2 Codex plan-review findings.

## Round-2 verdicts

- Codex (`task-mpkr1t72-5jl8po`): PLAN-NEEDS-MAJOR
  - Finding 1: `Store.Commit()` wraps the compile error as
    `"commit check failed: %w"` (store.go:681) while
    `Store.CommitCheck()` returns the raw error (store.go:663).
    gRPC/REST forward `Commit`'s wrapped text. The v2 plan
    asserts byte-exact equality on the unwrapped compile error,
    which is correct for `CompileConfig` directly but cannot be
    asserted byte-exact via `Store.Commit`.
  - Finding 2: the v2 plan's "recovery flow" said the operator
    can `delete system dataplane-type` from a candidate that
    inherits the previously-active stanzas. Counter-evidence:
    `Store.Load()` returns at store.go:97-99 before assigning
    `s.active = tree` if compile fails; subsequent
    `EnterConfigure()` clones an empty `s.active`. The
    candidate WILL be empty, not pre-populated. The operator's
    recovery flow has to start from the on-disk file or from
    `load merge ...` of a corrected text config.
  - Finding 3: parent task ("Continue DPDK retirement Chain A")
    said the migration message should point at the docs from
    sibling #1531. Counter to that, the #1526 issue body pins
    the verbatim text `(see #1525)`. v3 honors the verbatim
    text (issue body is authoritative) and notes that #1531's
    retirement banner is what operators see when they follow
    the issue link from the error message.
- Antigravity (`adversarial-review-mpkqxuth-epwnj3`): PLAN-READY
  on v2.

## v3 changes vs v2

1. Tests use **substring match** on the retirement phrase rather
   than byte-exact, so the same assertion fires across
   `CompileConfig`, `Store.CommitCheck`, and `Store.Commit`
   (which prepends `commit check failed: `). The substring is
   the full verbatim acceptance text minus the leading/trailing
   whitespace.
2. v3 plan adds a sibling test that calls `Store.Commit()` on a
   candidate carrying `dataplane-type dpdk` and asserts the
   error contains the retirement substring AND begins with
   `commit check failed: `. This locks in the wrapped surface
   so gRPC/REST contract drift is caught.
3. Replace the "operator deletes dpdk from candidate" sentence
   with the accurate recovery flow: candidate is empty after
   the failed `Store.Load()`, so the operator must either
   `load merge replace ...` the corrected file or
   `set system dataplane-type userspace` from scratch and
   commit. Manual sanity test step is updated to verify this.
4. Manual sanity test explicitly confirms the candidate is
   empty after the failed Load by running
   `cli -c "show configuration"` and seeing `{}` rather than
   the previous active config.

## Round-1 verdicts

## Round-1 verdicts

- Codex (`task-mpkqnvds-b7z0tu`): PLAN-NEEDS-MAJOR
  - Finding 1: validator ordering — DPDK reject should fire
    BEFORE the existing class-of-service / three-color-policer /
    policy-scheduler strict validators so the operator's first
    semantic error is the migration message, not an unrelated CoS
    error.
  - Finding 2: don't fold parse-success coverage and commit-time
    rejection into one test. Keep `TestDPDKConfig` (or a renamed
    parse-only variant) asserting the AST still maps DPDK schema;
    add a separate commit/compile rejection test with the exact
    error text.
  - Finding 3: CLI completion question cannot remain open — must
    be resolved before implementation. (Antigravity v1 confirms
    the answer: no static `dpdk` completion in `pkg/cmdtree`. v2
    closes this question.)
- Antigravity (`adversarial-review-mpkqo8v5-2m53xh`): PLAN-NEEDS-MINOR
  - Finding 1 (CRITICAL): daemon startup behavior is NOT "daemon
    refuses to start." Per `pkg/daemon/daemon_run.go:85-88` and
    `daemon_apply.go:32`, store-load errors are non-fatal: the
    daemon logs a warning and proceeds with empty active config,
    keeping the management plane alive so the operator can
    `rollback` or hand-edit. v2 corrects this.
  - Findings 2-10: confirm placement / single-error-site / apply-
    groups / sub-stanza / error-wording / completion / ordering
    decisions in v1 were correct; v2 carries them forward
    unchanged.

Both reviewers converge on: validator placement is right
(compiler.go, not backend registration); single error site
(`compileExpanded`) covers `CommitCheck` + `Commit` + daemon
load; tab completion needs no change. The two findings v2 must
address are: (a) validator ordering, (b) corrected daemon startup
behavior. Plus the test-split refinement from Codex.

## Issue framing

Issue #1526 is Phase 1 of the #1525 DPDK retirement umbrella. The
DPDK dataplane backend is being retired. This PR is the first
user-visible step: at config commit time, refuse any candidate
config that selects DPDK, and tell the operator exactly what to do
instead.

This PR is paired with #1531 (rewrite of `docs/dpdk-dataplane.md`
and `docs/dataplane-decision-dpdk-vs-vpp.md` so they no longer
recommend DPDK). #1531 must land first so the error message's doc
pointer is not contradicted on master.

Per issue body acceptance criteria:

- `set system dataplane-type dpdk` MUST still parse (so a stored
  `load merge` / `load override` flat-set file does not syntax-error
  on a pre-retirement config).
- Commit MUST return the verbatim message:
  `"the DPDK dataplane backend has been retired; use 'set system
  dataplane-type userspace' (see #1525)"`.
- Error surfaces through the same commit-validation path used by
  other commit-time rejections, so CLI, gRPC, and REST all see
  identical text.
- Unit tests cover: clean parse + uncommitted dpdk config; commit
  error containing retirement text; no warning when `dpdk` does
  not appear in the config.
- No source under `dpdk_worker/` or `pkg/dataplane/dpdk/` deleted.
- `cmd/xpfd/main.go` still blank-imports `pkg/dataplane/dpdk`
  (Phase 2 / Chain B's surface).

## Honest scope/value framing

Small Go-side config-compiler change. ~30 LOC of new code plus
test additions and a couple of test flips. Value is operator-
experience correctness: when a binary built after this PR refuses
DPDK, the operator sees the migration message at commit time
rather than at daemon startup (or worse, after upgrade installs a
binary that runs the DPDK stub backend that has been failing
closed since #1475).

PLAN-KILL is appropriate if reviewers identify the reject belongs
in a fundamentally different code site. v1 surfaced this; both
reviewers agreed compiler-side reject is correct.

## What's already shipped / partially relevant

- `pkg/config/compiler.go:949-963` defines `dataplaneTypeDPDK`,
  `effectiveDataplaneType()`, `validDataplaneType()`. The constant
  stays; the validator accepts dpdk as a legal name (parse
  continues to succeed); a new strict validator rejects it at
  compile time.
- `pkg/config/compiler_system.go:236-242` parses `DPDKConfig`
  sub-tree. Stays as-is. Parse must still succeed (acceptance
  criterion).
- `pkg/config/compiler_system.go:373-388` `compileSystemDataplaneType`
  is where `validDataplaneType()` is called for unknown-value
  rejection (`vpp`, `mystery`). DPDK is a KNOWN value here —
  parse succeeds. The new strict reject runs after full tree
  compile so the operator sees one clean retirement message
  rather than a confusing "unknown" message.
- Existing strict-validator pattern: `validateClassOfServiceStrict`,
  `validateThreeColorPolicersStrict`,
  `validatePolicySchedulerReferencesStrict` are called in
  `compileExpanded`. The new `validateDataplaneTypeStrict(cfg)`
  slots in BEFORE them (v2 change vs v1).
- `pkg/configstore/store.go` `CommitCheck()` and `Commit()` both
  call `compileTree()`, which routes to `CompileConfig()` /
  `CompileConfigForNode()`, both of which call `compileExpanded()`
  (per Antigravity v1 verification at compiler.go:31-54). A
  hard error from `compileExpanded` surfaces in both code paths.
- `pkg/daemon/daemon_run.go:85-88`: `d.store.Load()` errors are
  logged as warnings and do NOT prevent daemon startup. Replay
  of a stored DPDK config produces an empty-active-config running
  daemon, NOT a refused startup (v2 correction vs v1).
- `pkg/config/ast.go:1385`: `dataplane-type` has `args: 1` with
  no `valueHint`. No static `dpdk` tab completion exists in
  `pkg/cmdtree` (per Antigravity v1 verification). No CLI
  completion change required.

## Concrete design (v2)

### New strict validator

In `pkg/config/compiler.go`:

```go
// validateDataplaneTypeStrict rejects retired dataplane backends
// at commit time. The parse path accepts the value so a stored
// pre-retirement config does not syntax-error on `load merge`;
// the commit-time reject is what tells the operator to migrate.
//
// Placement: runs BEFORE the other strict validators in
// compileExpanded so that an operator editing a candidate that
// has BOTH a retired dataplane-type AND an unrelated malformed
// CoS profile sees the retirement message first (it is the
// documented migration path; the CoS error becomes relevant
// after migration).
func validateDataplaneTypeStrict(cfg *Config) error {
    if cfg == nil {
        return nil
    }
    if cfg.System.DataplaneType == dataplaneTypeDPDK {
        return fmt.Errorf(
            "the DPDK dataplane backend has been retired; " +
                "use 'set system dataplane-type userspace' " +
                "(see #1525)")
    }
    return nil
}
```

### Call-site ordering (v2 change from v1)

`compileExpanded` (the shared function called by both
`CompileConfig` and `CompileConfigForNode`) currently runs:

```go
validateClassOfServiceStrict(cfg.ClassOfService)         // #1
validateThreeColorPolicersStrict(cfg.Firewall.ThreeColorPolicers) // #2
validatePolicySchedulerReferencesStrict(cfg)             // #3
ValidateConfig(cfg)                                       // warnings, non-fatal
```

v2 inserts the DPDK reject FIRST:

```go
if err := validateDataplaneTypeStrict(cfg); err != nil {
    return nil, err  // first semantic error operator sees
}
if err := validateClassOfServiceStrict(...); err != nil {
    return nil, err
}
// ... existing strict validators ...
```

Codex finding 1: this ordering ensures the operator gets the
migration message before any unrelated structural errors. The
DPDK reject is the documented migration; CoS errors become
relevant only after migration.

### Error message wording

Verbatim from #1526 acceptance criteria:

```
the DPDK dataplane backend has been retired; use 'set system dataplane-type userspace' (see #1525)
```

Single-line, no trailing period, parenthetical issue ref. Tests
will compare the exact string (Codex finding: exact wording per
acceptance text).

### Test plan (split per Codex finding 2)

Five new tests under `pkg/config/`:

1. **TestDataplaneTypeDPDKParsesCleanly** — asserts pure parse
   succeeds. Calls `ParseSetCommand` + `tree.SetPath` for
   `set system dataplane-type dpdk` and confirms no error from
   either. (Documents the "parse still succeeds" acceptance
   criterion in a separate test from the compile rejection.
   Codex finding 2 explicitly asks for this separation.)

2. **TestDataplaneTypeDPDKRejectedAtCommit** — flat-set form:
   ```
   set system dataplane-type dpdk
   set system dataplane cores 2-5
   ```
   builds a tree, calls `CompileConfig(tree)`, asserts the
   returned error is non-nil and the message is BYTEWISE EQUAL to
   the acceptance text (exact compare, not substring). This is
   the operator-visible contract; we test it with the strongest
   possible assertion.

3. **TestDataplaneTypeDPDKRejectedAtCommitHierarchical** — same
   assertion via `NewParser(`system { dataplane-type dpdk; }`)`
   to confirm the hierarchical AST shape hits the same reject.

4. **TestDataplaneTypeDPDKRejectedAtCommitFiresBeforeCoS** —
   builds a candidate with BOTH `dataplane-type dpdk` AND a
   malformed CoS (e.g. a scheduler-map whose buffer-size percent
   exceeds 100%). Asserts the returned error contains the DPDK
   retirement text, NOT the CoS error. Documents the v2 ordering
   choice (Codex finding 1).

5. **TestDataplaneTypeDPDKRejectedAtCommitViaApplyGroups** —
   builds a candidate where an apply-groups stanza injects
   `dataplane-type dpdk` into the resolved config. Calls
   `CompileConfigForNode(tree, 0)`. Asserts the post-expansion
   compile hits the same reject. Documents the apply-groups /
   `${node}` interaction (open question 6 in v1 → closed in v2).

Existing tests to flip / refine (Codex finding 2 ⇒ keep parse
coverage):

- `TestDPDKConfig` at `pkg/config/parser_ast_test.go:2622` —
  currently asserts BOTH that the lines parse AND that
  `CompileConfig` succeeds with populated `cfg.System.DPDKDataplane`
  fields. v2 splits this:
  - **Rename** to `TestDPDKConfigParsesAndCompilesToSchema` —
    drop the final `CompileConfig` call and the
    `cfg.System.DataplaneType == "dpdk"` assertion (those would
    fail post-rejection). Keep the parse loop (`tree.SetPath`
    for every line) and the assertion that no parse error
    occurs. This documents that flat-set parse of DPDK syntax
    survives the retirement.
  - Add a sibling `TestDPDKConfigCompileRejects` that takes the
    same lines, builds the tree, calls `CompileConfig`, and
    asserts the rejection. (Effectively the same as test #2
    above but reusing the comprehensive DPDK schema fixture so
    we keep coverage of the `compileDPDKDataplane` schema path
    end-to-end through the new reject.)

- `TestDataplaneTypeNonLegacyValuesDoNotWarnDeprecatedCompatibility`
  at `pkg/config/parser_system_test.go:1425` — currently loops
  over `["userspace", "dpdk"]`. v2 drops `"dpdk"` from the loop
  (it now hard-errors; the warning-check is unreachable for that
  value). The DPDK rejection is covered by tests #2 and #3 above
  and by `TestDPDKConfigCompileRejects`.

### Daemon startup replay (v2 correction)

When a node carrying a stored active config with
`dataplane-type dpdk` is upgraded to a binary built from this PR:

1. `xpfd` starts.
2. `d.store.Load()` at `pkg/daemon/daemon_run.go:85` calls
   through to `compileTree` to validate the stored config.
3. The new `validateDataplaneTypeStrict` rejects.
4. Per the existing #127 design, `d.store.Load()` returns an
   error which the daemon LOGS AS A WARNING and proceeds:
   ```go
   if err := d.store.Load(); err != nil {
       slog.Warn("failed to load config from db", "err", err)
   }
   ```
5. The daemon attempts to bootstrap from the text config file
   (`daemon_apply.go:32`). If that also carries `dpdk`, same
   warning, same proceed.
6. The daemon comes up with NO active config: no interfaces
   programmed, no firewall rules applied, no NAT, no policy.
   The management plane (CLI / gRPC / REST) is reachable
   because it does not depend on dataplane config.
7. The operator connects via CLI, sees the rejection at next
   `commit check`, hand-edits the candidate to remove
   `dataplane-type dpdk`, commits, and the cluster is back.

This is the desirable behavior per Antigravity finding: the
management plane stays alive for recovery rather than crashing
the daemon. v1's claim "daemon refuses to start" was wrong;
v2 corrects it.

Operational note: the operator should NOT panic when the
upgraded daemon comes up "empty." The expected recovery flow is:

```
ssh fw-node
cli
configure
delete system dataplane-type
commit
```

(or `set system dataplane-type userspace` if the operator wants
to keep an explicit dataplane-type line.) The candidate config is
already populated from the previously-active config because
configstore loads candidate from disk separately from active —
this needs verification in the manual sanity test.

### What does NOT change in this PR

(unchanged from v1):
- `pkg/dataplane/dpdk/manager.go`, `cmd/xpfd/main.go` —
  Phase 2 (Chain B).
- `dpdk_worker/`, `pkg/dataplane/dpdk/`, `pkg/config/types.go`
  `DPDKConfig`/`DPDKAdaptiveConfig`/`DPDKPort` — Phase 3.
- `pkg/config/compiler_system.go:227-246` dpdk compile branch —
  remains so parse-then-reject works for stored configs.
- Retirement-boundary canary — Phase 2.
- CLI tab completion in `pkg/cmdtree` — no change (Antigravity
  confirms no static dpdk completion exists).

## Public API preservation

| Surface | Behavior before | Behavior after |
|---|---|---|
| Parse `set system dataplane-type dpdk` | succeeds | succeeds |
| `tree.SetPath(["system", "dataplane-type", "dpdk"])` | succeeds | succeeds |
| `CompileConfig(tree)` with DPDK | succeeds, `cfg.System.DataplaneType == "dpdk"` | hard error |
| `CompileConfigForNode(tree, n)` with DPDK | succeeds | hard error |
| `Store.CommitCheck()` with DPDK candidate | succeeds | hard error |
| `Store.Commit()` with DPDK candidate | succeeds at validation; failed at apply | hard error at commit |
| `Store.Load()` on startup with stored DPDK active | succeeds (validation passes; apply later fails) | error logged as warning; daemon proceeds with empty active config |
| `dataplane-type userspace` (or omitted) | succeeds | succeeds — unchanged |
| `dataplane-type ebpf` | succeeds + warning | succeeds + warning — unchanged |
| `dataplane-type vpp` (or other unknown) | hard error at parse | hard error at parse — unchanged |

The pre-retirement `Commit()` path with `dataplane-type dpdk` DID
NOT actually run DPDK in any production build — it tried to load
the dpdk backend and hit the `errDPDKBuildTagRequired` stub
(unless built with `-tags dpdk`), failing at daemon startup.
This PR moves that failure from daemon-start to commit time,
which is the operator-visible improvement #1526 asks for.

## Hidden invariants the change must preserve

1. **No silent passthrough.** Strict-validator pattern: returns
   `error` rather than appending to `cfg.Warnings`.

2. **Single error site.** Reject placed in `compileExpanded`
   (the shared helper of `CompileConfig` and
   `CompileConfigForNode`). Antigravity v1 verified at
   compiler.go:31-54 that both call paths go through this.

3. **`load merge` / `load override` / `load set` of a
   pre-retirement config does not syntax-error.** Parse
   succeeds. Operator only sees the rejection when they try to
   commit or `commit check`.

4. **Stored active config containing dpdk does not panic on
   daemon startup.** Daemon logs a warning, comes up empty,
   management plane stays alive. Verified against
   `pkg/daemon/daemon_run.go:85-88` and `daemon_apply.go:32`.

5. **Compile path purity.** `validateDataplaneTypeStrict` is
   read-only on `cfg`.

6. **No interference with the eBPF deprecation warning.**
   `cfg.System.DataplaneType == "ebpf"` continues to produce the
   warning at compiler.go:386-391. The new check is for
   `"dpdk"` only.

7. **Validator ordering.** DPDK reject fires FIRST among strict
   validators (v2 change). An operator editing a candidate with
   both a retired type and an unrelated structural error sees
   the migration message first.

8. **apply-groups / `${node}` expansion runs BEFORE the new
   validator.** Verified at compiler.go:19-31 / 49-54 (Antigravity
   v1). A group-injected `dataplane-type dpdk` is caught.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Existing `-tags dpdk` builds fail at runtime today; new behavior is strictly tighter and fires earlier. |
| Lifetime / borrow-checker | NONE | Go side, no Rust. |
| Performance regression | NONE | Cold-path validator runs once per commit. |
| Architectural mismatch | LOW | Both reviewers concur compiler-side reject is correct. |
| Cross-PR ordering | MEDIUM | This PR must merge AFTER PR #1531 (or operator hits daemon pointing at docs still recommending DPDK). Chain A driver enforces ordering. |
| Stored active config replay on upgrade | LOW | Per Antigravity correction: daemon logs warning + comes up empty + keeps management plane alive. Operator can recover via CLI. Acceptable, documented. |
| Daemon comes up unconfigured surprise | LOW | Documented; the `slog.Warn` line is plainly visible to anyone reading journal at startup. v2 adds a paragraph to release notes / commit message. |

## Test plan

- `go build ./...` clean.
- `go test ./pkg/config/...` — 5 new tests pass + 1 added sibling
  test (`TestDPDKConfigCompileRejects`) + 2 existing tests
  flipped (`TestDPDKConfig` renamed,
  `TestDataplaneTypeNonLegacyValuesDoNotWarnDeprecatedCompatibility`
  loop pruned), all pass.
- `go test ./...` — full Go suite passes.
- `cargo build` + `cargo test --release` — clean (Rust side
  unchanged; gated for completeness per skill discipline).
- 5x flake check on `TestDataplaneTypeDPDKRejectedAtCommit`.
- Deploy on `loss:xpf-userspace-fw0/fw1` (default test env, runs
  userspace dataplane — no DPDK reach).
- Pass A (CoS disabled, fixture-aligned tear-down):
  - v4 push, v4 reverse, v6 push, v6 reverse single-stream.
  - v4 + v6 `-P 12 -R` multi-stream — line rate, 0 retrans.
- Pass B (CoS re-applied):
  - Per-class 5201-5206 × v4/v6 × push/reverse = 24 measurements.
- No retrans regressions vs master baseline.
- Manual sanity in the deployed cluster:
  - `cli` → `configure` → `set system dataplane-type dpdk` →
    `commit check` → confirm exact retirement error text.
  - Repeat with `commit` → confirm same error.
  - `rollback` → confirm clean.
  - Verify upgrade-replay scenario: deploy node with stored
    config containing `dataplane-type dpdk`, restart daemon,
    confirm `journalctl -u xpfd` shows the warning + daemon is
    up + `cli` is reachable + `show configuration | display
    set` reflects the unconfigured state.

## Out of scope (explicitly)

- Deleting the DPDK blank import from `cmd/xpfd/main.go` —
  Phase 2 (#1527, Chain B).
- Removing `dataplane.RegisterBackend(TypeDPDK, ...)` and
  `dataplane.RegisterRuntimeBackend(TypeDPDK, ...)` —
  Phase 2.
- Deleting `dpdk_worker/`, `pkg/dataplane/dpdk/`,
  `DPDKConfig`/`DPDKAdaptiveConfig`/`DPDKPort`,
  `Makefile build-dpdk*`, canary cleanup — Phase 3.
- Doc sweep beyond `docs/dpdk-dataplane.md` and
  `docs/dataplane-decision-dpdk-vs-vpp.md` — Phase 4 / Chain C.
- README / CLAUDE.md updates — Phase 4 / Chain C.
- Changing the existing `validDataplaneType()` to drop DPDK
  from its accepted list — would make parse hard-error too,
  which #1526 explicitly forbids.
- Daemon-side graceful-degradation that auto-rewrites
  `dataplane-type dpdk` to `userspace` on startup. Considered
  and rejected: silent rewrite would mask the retirement signal
  the operator needs to see. Manual rollback is correct.

## Open questions for adversarial review (round-2)

1. **Is the v2 validator ordering (DPDK first) actually right?**
   Codex finding 1 says yes; v2 implements it. But consider:
   if a candidate has multiple structural errors, the operator
   may fix the DPDK type first and then surface the CoS error,
   requiring two commit cycles to land. Is that worse UX than
   surfacing CoS first (one cycle to fix migration AND CoS)?
   v2 takes the position that "DPDK first" is correct because
   the retirement IS the migration the operator must perform;
   CoS errors are a normal continuous editing concern.

2. **Test count and split.** v2 has 5 new tests + 1 added
   sibling + 2 flipped existing. Is that the right balance?
   Specifically `TestDataplaneTypeDPDKRejectedAtCommitFiresBeforeCoS`
   is a brittle test (depends on validator ordering which is
   itself a v2 decision). If the ordering changes in a future
   refactor, this test fails. Worth keeping anyway?

3. **Exact-match vs substring-match on the error text.** v2
   asserts `err.Error() == "the DPDK dataplane backend has been
   retired; use 'set system dataplane-type userspace' (see
   #1525)"`. That's a strong contract — any future wording
   change must update the test. Some reviewers prefer
   substring-match for resilience. v2 picks exact-match because
   the issue body specifies verbatim text; relaxing the test
   makes the spec drift-detection weaker.

4. **Should the replay-on-upgrade behavior be DOCUMENTED in
   user-facing docs (release notes), or is the warning-line
   self-explanatory?** v2 plan says "documented in commit
   message"; release notes are a separate concern.

5. **The candidate-load-from-disk path.** Plan says "candidate
   config is already populated from the previously-active
   config." Is this verified? `pkg/configstore/store.go`
   `Load()` should load BOTH active and candidate (candidate
   may have unrelated in-flight edits). If candidate also
   carries `dataplane-type dpdk`, does the same warn-and-proceed
   apply? Plan assumes yes; verify in manual sanity test.

6. **Should the warning at startup be `slog.Error` instead of
   `slog.Warn`?** A retirement-driven empty-config startup is
   not a minor warning — it's a noisy failure. v2 does NOT
   change the existing #127 design (load errors are warnings)
   because that is a daemon-lifecycle policy that lives at a
   different abstraction layer. A reviewer may push back.

7. **Is the migration command in the error text complete?**
   `set system dataplane-type userspace` is one option. Another
   is just deleting the line entirely (userspace is the
   default). The acceptance criteria spec is verbatim; v2 honors
   it. But for an operator with no doc in front of them, "use
   set system dataplane-type userspace" is one direction and
   "delete system dataplane-type" is another. PR #1531's
   retirement notice will say both; the commit error text says
   only one. Plan accepts this as honoring the spec.

8. **Will `commit confirmed` interact correctly?** If an
   operator runs `set system dataplane-type dpdk` then
   `commit confirmed 10`, the immediate commit-check rejects
   and the confirmed-commit timer never starts. Verify in the
   manual sanity test (or with a new unit test).
