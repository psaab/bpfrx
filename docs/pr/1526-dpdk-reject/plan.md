# #1526 — Reject `system dataplane-type dpdk` at commit

## Status

DRAFT v1 — pending adversarial plan review

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
- Commit MUST return:
  `"the DPDK dataplane backend has been retired; use 'set system
  dataplane-type userspace' (see #1525)"`.
- The error surfaces through the same commit-validation path used
  by other commit-time rejections, so CLI, gRPC, and REST all see
  identical text.
- Unit tests cover: clean parse + uncommitted dpdk config; commit
  error containing retirement text; no warning when `dpdk` does
  not appear in the config.
- No source under `dpdk_worker/` or `pkg/dataplane/dpdk/` is
  deleted. `cmd/xpfd/main.go` still blank-imports
  `pkg/dataplane/dpdk` (that is Phase 2, #1527 — Chain B's surface).

## Honest scope/value framing

Small Go-side config-compiler change. ~30 LOC of new code plus
unit-test flips. Value is operator-experience correctness: when a
binary built after this PR refuses DPDK, the operator sees the
migration message at commit time rather than at daemon startup (or
worse, after upgrade installs a binary that runs the DPDK stub
backend that has been failing closed since #1475).

If reviewers conclude the error message wording is wrong (e.g.
should also link to `docs/dpdk-dataplane.md` for context after PR
#1 rewrites it as a retirement notice), that is plan-NEEDS-MINOR.

PLAN-KILL is appropriate if reviewers identify that the reject
belongs in a different code site (e.g. at the dataplane backend
registration layer in `pkg/dataplane/dataplane.go`, not in
`pkg/config/compiler.go`). The current plan chooses the
compiler-side reject because that is where commit-time validation
lives and where the existing pattern (`validateClassOfServiceStrict`,
`validateThreeColorPolicersStrict`,
`validatePolicySchedulerReferencesStrict`) already runs.

## What's already shipped / partially relevant

- `pkg/config/compiler.go:949-963` defines `dataplaneTypeDPDK`,
  `effectiveDataplaneType()`, `validDataplaneType()`. The constant
  stays; the validator accepts dpdk as a legal name (parse continues
  to succeed); a new strict validator rejects it at compile time.
- `pkg/config/compiler_system.go:236-242` parses `DPDKConfig`
  sub-tree. This stays as-is. Parse must still succeed (acceptance
  criterion).
- `pkg/config/compiler_system.go:373-388` `compileSystemDataplaneType`
  is where `validDataplaneType()` is currently called for the
  unknown-value rejection (`vpp`, `mystery`). DPDK is a KNOWN value
  in that sense — parse succeeds. The new strict reject runs
  AFTER the full tree is compiled so the operator sees one clean
  retirement message rather than a confusing "unknown" message.
- Existing pattern: `CompileConfig` calls `validateXxxStrict(cfg)`
  early (compiler.go:218-225). The new
  `validateDataplaneTypeStrict(cfg)` slots in immediately after
  those calls and returns a hard error if
  `cfg.System.DataplaneType == "dpdk"`.
- `pkg/configstore/store.go:653, 671` — `CommitCheck()` and
  `Commit()` both call `compileTree()` which calls `CompileConfig()`.
  A hard error from `CompileConfig` surfaces in both code paths.
  No new wiring in configstore, grpcapi, cli — they already
  propagate the error.

## Concrete design

### New strict validator

In `pkg/config/compiler.go`, add:

```go
// validateDataplaneTypeStrict rejects retired dataplane backends
// at commit time. The parse path accepts the value so a stored
// pre-retirement config does not syntax-error on `load merge`;
// the commit-time reject is what tells the operator to migrate.
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

Call site, in `CompileConfig` after the existing strict validators:

```go
if err := validatePolicySchedulerReferencesStrict(cfg); err != nil {
    return nil, err
}
if err := validateDataplaneTypeStrict(cfg); err != nil {  // new
    return nil, err
}
if warnings := ValidateConfig(cfg); len(warnings) > 0 {
    // ...
}
```

### Error message wording

Verbatim from #1526 acceptance criteria, with two punctuation
cleanups:

```
the DPDK dataplane backend has been retired; use 'set system dataplane-type userspace' (see #1525)
```

Single-line, no trailing period, parenthetical issue ref — matches
the style of the existing eBPF deprecation warning at
compiler.go:386-391 (multiline string built via `+`).

The single-quoted `'set system dataplane-type userspace'` is a Junos
CLI command verbatim and stays single-quoted (matches Junos error
message style).

### What `set system dataplane-type userspace` selects

The userspace AF_XDP dataplane (`userspace-dp/`). This is also the
default — operators can either explicitly set it or simply remove
the `dataplane-type` line. The error message recommends explicit
set because:

1. An operator currently running `dataplane-type dpdk` wants to be
   sure their config still works after they edit it.
2. Setting it explicitly is the most direct "do this" instruction.

`dataplane-type ebpf` is also still valid (deprecated, warning,
not error) but is NOT recommended in the error message because the
operator's migration path is forward to userspace, not sideways to
the legacy eBPF path. The eBPF deprecation message at
compiler.go:386-391 already covers that case.

### Test plan (new tests in pkg/config)

1. **TestDataplaneTypeDPDKRejectedAtCommit** — flat-set form:
   ```
   set system dataplane-type dpdk
   set system dataplane cores 2-5
   ```
   asserts `CompileConfig` returns an error and the error message
   contains "the DPDK dataplane backend has been retired" AND
   "set system dataplane-type userspace" AND "#1525".

2. **TestDataplaneTypeDPDKRejectedAtCommitHierarchical** — same
   assertion via `NewParser(`...`)` with hierarchical syntax,
   confirming both AST shapes hit the reject.

3. **TestDataplaneTypeDPDKParsesCleanly** — asserts that parsing
   alone succeeds (`tree.SetPath` does not error). The reject
   fires at compile time, not at parse time. This documents the
   "still parses" acceptance criterion explicitly.

4. **TestDataplaneTypeUserspaceNoWarning** — asserts that an
   explicit `dataplane-type userspace` config does NOT carry the
   retirement warning in `cfg.Warnings`. (Existing test
   `TestDataplaneTypeNonLegacyValuesDoNotWarnDeprecatedCompatibility`
   covers `userspace` already; this is an additional explicit check.)

5. **TestDataplaneTypeEBPFNotAffected** — asserts that an
   explicit `dataplane-type ebpf` config still compiles cleanly
   with only the eBPF deprecation warning, NOT the DPDK
   retirement error. (Regression guard on the eBPF path.)

### Existing tests to flip

The issue body names two:

- `pkg/config/parser_ast_test.go:2622` `TestDPDKConfig` —
  currently expects `CompileConfig` to succeed with DPDK and
  inspects `cfg.System.DPDKDataplane.Cores` etc. Flip to:
  - either delete entirely (the DPDK schema is unobservable to
    operators after this PR), OR
  - rename to `TestDPDKConfigParsesButCommitRejects` and assert
    that `tree.SetPath(...)` succeeds for every line then
    `CompileConfig(tree)` returns an error containing the
    retirement text.
  - Plan picks the latter. It documents that flat-set parse
    survives the retirement (which is the operator-visible
    contract), and it preserves the test's coverage of the
    `compileDPDKDataplane` parser. The `DPDKDataplane` field
    assertions are dropped since `cfg` is nil on error.

- `pkg/config/parser_system_test.go:1425`
  `TestDataplaneTypeNonLegacyValuesDoNotWarnDeprecatedCompatibility`
  — currently loops over `["userspace", "dpdk"]` and asserts
  no eBPF deprecation warning. Flip: drop `"dpdk"` from the loop
  (it now hard-errors, so the warning-check is no longer
  reachable for that value). Add a separate
  `TestDataplaneTypeDPDKRejectedAtCommit` (covered above).

### What does NOT change in this PR

- `pkg/dataplane/dpdk/manager.go` — unchanged. The package still
  builds and still self-registers. Phase 2 (#1527) deletes the
  registration.
- `cmd/xpfd/main.go` — unchanged. Still blank-imports the dpdk
  package. Phase 2 (#1527) deletes the import.
- `dpdk_worker/` — unchanged. Phase 3 (separate sub-issue) deletes
  the source.
- `pkg/config/types.go` — `DPDKConfig`, `DPDKAdaptiveConfig`,
  `DPDKPort` stay. Phase 3 deletes them.
- `pkg/config/compiler_system.go:227-246` — the `case "dataplane":
  ... case dataplaneTypeDPDK:` branch stays so a stored config
  parses cleanly even if a `set system dataplane cores 2-5` line
  is also present. The reject fires on the type, not on the
  sub-stanza presence.
- The retirement-boundary canary
  `pkg/dataplane/retirement_boundary_canary_test.go` —
  `dpdkBackendImportAllowlist` still allows the xpfd main blank
  import. Phase 2 tightens this.

## Public API preservation

| Surface | Behavior before | Behavior after |
|---|---|---|
| Parse `set system dataplane-type dpdk` | succeeds | succeeds |
| `tree.SetPath(["system", "dataplane-type", "dpdk"])` | succeeds | succeeds |
| `CompileConfig(tree)` with DPDK | succeeds, `cfg.System.DataplaneType == "dpdk"` | hard error |
| `Store.CommitCheck()` with DPDK candidate | succeeds | hard error |
| `Store.Commit()` with DPDK candidate | succeeds (but daemon refuses load) | hard error at commit |
| `dataplane-type userspace` (or omitted) | succeeds | succeeds — unchanged |
| `dataplane-type ebpf` | succeeds + warning | succeeds + warning — unchanged |
| `dataplane-type vpp` (or other unknown) | hard error at parse | hard error at parse — unchanged |

The pre-retirement `Commit()` path with `dataplane-type dpdk`
DID NOT actually run DPDK in any production build — it tried to
load the dpdk backend, hit the `errDPDKBuildTagRequired` stub
(unless built with `-tags dpdk`), and failed at daemon start.
This PR moves that failure from daemon-start to commit time,
which is the operator-visible improvement #1526 asks for.

## Hidden invariants the change must preserve

1. **No silent passthrough.** A candidate config that selects
   DPDK MUST hard-error at commit, not warn-and-proceed. The
   strict-validator pattern (returning `error` rather than
   appending to `cfg.Warnings`) preserves this.

2. **Single error site.** The reject MUST be reachable from one
   site (CompileConfig). Adding it to `Store.Commit()` directly
   would miss `Store.CommitCheck()` and `compileTree()` direct
   callers. Adding it at `compileSystemDataplaneType` would
   conflate "unknown type" error (vpp) with "retired type" error
   (dpdk), making the operator-visible message less specific.

3. **`load merge` / `load override` / `load set` of a
   pre-retirement config does not syntax-error.** Parse succeeds.
   Operator only sees the rejection when they try to commit
   (or `commit check`).

4. **Stored active config containing dpdk does not panic on
   daemon startup.** The reject path is at commit time, not at
   load-from-disk time. If a tagged binary previously committed
   with DPDK, that stored config will replay through the same
   compile path on startup; if it still says DPDK it will be
   rejected and the daemon should refuse to start (acceptable —
   issue body says "deployments still carrying DPDK config can
   roll forward to a binary that no longer ships the backend
   without silently switching to a stub").

   The plan-review questions list calls out the startup-replay
   case for verification — see open question 1 below.

5. **Compile path purity.** The new validator must not mutate
   `cfg`. Strict validators in this file are read-only by
   convention.

6. **No interference with the eBPF deprecation warning.**
   `cfg.System.DataplaneType == "ebpf"` continues to produce the
   warning at compiler.go:386-391. The new check is for `"dpdk"`
   only.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | A binary built before this PR with `-tags dpdk` would have run the DPDK backend on a `dataplane-type dpdk` config. A binary built without `-tags dpdk` would have hit `errDPDKBuildTagRequired` at daemon startup (#1475 behavior). The new commit-time reject is strictly tighter than the existing #1475 startup failure. |
| Lifetime / borrow-checker | NONE | Go side, no Rust. |
| Performance regression | NONE | Cold-path validator runs once per commit. |
| Architectural mismatch | LOW | The plan places the reject in the existing strict-validator chain. Alternative sites (backend registration, daemon startup) would either duplicate the error message or fire too late. |
| Cross-PR ordering | MEDIUM | This PR must merge AFTER PR #1531 (or the operator hits a daemon that points at docs still recommending DPDK). The Chain A driver enforces ordering by opening PRs in sequence. |
| Replay of stored active config with `dataplane-type dpdk` after upgrade | MEDIUM | If an operator upgrades and their active config carries `dataplane-type dpdk`, daemon startup will replay the config through `compileTree` and hard-error. They must hand-edit the on-disk config to recover. Issue body explicitly accepts this. The error message tells them what to do. Plan-review open question 1. |

## Test plan

- `go build ./...` clean.
- `go test ./pkg/config/...` — 5 new tests pass + existing
  `TestDPDKConfig` + `TestDataplaneTypeNonLegacyValuesDoNotWarnDeprecatedCompatibility`
  updated, all pass.
- `go test ./...` — full Go suite passes.
- `cargo build` + `cargo test --release` — clean (Rust side
  unchanged; gated for completeness).
- 5x flake check on `TestDataplaneTypeDPDKRejectedAtCommit`.
- Deploy on `loss:xpf-userspace-fw0/fw1` (default test env, runs
  userspace dataplane — no DPDK reach).
- Pass A (CoS disabled, fixture-aligned tear-down):
  - v4 push, v4 reverse, v6 push, v6 reverse single-stream.
  - v4 + v6 `-P 12 -R` multi-stream — line rate, 0 retrans.
- Pass B (CoS re-applied):
  - Per-class 5201-5206 × v4/v6 × push/reverse = 24 measurements.
- No retrans regressions vs master baseline (validation-time
  change cannot reach the dataplane; smoke confirms no surprise
  build/link regressions).
- Manual sanity in the deployed cluster:
  - `cli` → `configure` → `set system dataplane-type dpdk` →
    `commit check` → confirm the retirement error text is
    surfaced to the operator (one of: CLI prompt, journalctl).
  - Repeat with `commit` → confirm same error.
  - `rollback` → confirm clean.

## Out of scope (explicitly)

- Deleting the DPDK blank import from `cmd/xpfd/main.go` —
  Phase 2 (#1527, Chain B).
- Removing `dataplane.RegisterBackend(TypeDPDK, ...)` and
  `dataplane.RegisterRuntimeBackend(TypeDPDK, ...)` from
  `pkg/dataplane/dpdk/manager.go` — Phase 2.
- Deleting `dpdk_worker/`, `pkg/dataplane/dpdk/`,
  `DPDKConfig`/`DPDKAdaptiveConfig`/`DPDKPort` from
  `pkg/config/types.go`, `Makefile` `build-dpdk*` targets,
  canary `dpdkEBPFImportAllowlist` cleanup — Phase 3.
- Doc sweep beyond `docs/dpdk-dataplane.md` and
  `docs/dataplane-decision-dpdk-vs-vpp.md` — Phase 4 / Chain C.
- README / CLAUDE.md updates — Phase 4 / Chain C.
- Changing the existing `validDataplaneType()` to drop DPDK from
  its accepted list. That would make parse hard-error too,
  which #1526 explicitly forbids.

## Open questions for adversarial review

1. **Daemon startup replay of an upgraded node's stored config.**
   If a node was running with `dataplane-type dpdk` and an
   operator deploys a binary built from this PR, the daemon
   loads the saved active config from disk, compiles it via the
   same `compileTree` path, and hard-errors. The daemon refuses
   to come up. Is that acceptable? The issue body says yes
   ("deployments still carrying DPDK config can roll forward to
   a binary that no longer ships the backend without silently
   switching to a stub"). But: is there a graceful degradation
   path needed (e.g. log loud, force `dataplane-type userspace`
   on the in-memory cfg, refuse to write back to disk)? The plan
   says no — operator must hand-edit. Validate this.

2. **Error message wording.** Issue body specifies:
   `the DPDK dataplane backend has been retired; use 'set
   system dataplane-type userspace' (see #1525)`. The plan
   uses that text verbatim. Should the message also link the
   rewritten `docs/dpdk-dataplane.md` (after PR #1531)? Plan
   currently does not; issue spec doesn't either; minimum-viable
   answer is no.

3. **Test scope.** Is 5 new tests + 2 flipped existing tests
   enough? Specifically, do we need a test that exercises the
   reject path through `Store.CommitCheck()` and `Store.Commit()`
   (not just `CompileConfig`)? Plan says no — `compileTree`
   delegates to `CompileConfig` and any error propagates. A
   reviewer may push back and demand an integration test that
   exercises the store boundary.

4. **`compileDPDKDataplane` dead-code.** After this PR the dpdk
   compile branch in `compiler_system.go:236-242` runs for any
   candidate that is in the brief window between parse and the
   strict-validator call. After the validator runs, `cfg` is
   discarded. So the dpdk compile branch produces output that is
   never read. Is that wasted work worth deleting (a behavior
   change with risk) or worth leaving as-is (cleanest scope)?
   Plan: leave as-is. Deleting it makes the dpdk schema
   un-roundtrippable on `load merge` which interferes with the
   "still parses" acceptance criterion.

5. **CLI surface.** Does `pkg/cmdtree/` expose `dataplane-type`
   completions that need updating? Plan: grep to find out before
   final commit. If the completion lists "dpdk" as an option,
   the operator's tab-completion experience contradicts the
   reject. May need to remove dpdk from completion list (a
   user-facing change worth surfacing) — but that's a separate
   minor question.

6. **Interaction with `${node}` apply-groups expansion.** If a
   config uses `apply-groups` and the resolved group contains
   `dataplane-type dpdk`, does the reject fire on the
   post-expansion config? The plan assumes yes —
   `CompileConfigForNode` calls the same `CompileConfig`
   internally. Verify.

7. **The legacy eBPF deprecation warning.** It currently says
   "Omitting system dataplane-type selects the userspace
   dataplane." It is good. Does the DPDK retirement error need
   to also mention that omitting selects userspace, in addition
   to recommending explicit set? Plan says no — explicit is
   cleaner for the migrator.

8. **Validator placement order.** Plan places the new validator
   AFTER the existing class-of-service / three-color-policer /
   policy-scheduler validators. If a candidate config has BOTH
   a DPDK type AND a malformed CoS config, the operator sees
   the CoS error first. Is that the right ordering? Plan: yes —
   DPDK retirement is the documented migration; the CoS error
   is the more actionable one to fix in the current edit.
   A reviewer may argue the dpdk reject should fire first so
   the operator doesn't fix two unrelated errors. Worth raising.
