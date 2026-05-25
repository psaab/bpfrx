# #1528 — DPDK Retirement Phase 3: Mechanical Source Removal

**Status:** DRAFT v1 — pending adversarial plan review (Codex + Antigravity)

## 1. Issue framing

#1528 is the mechanical-removal phase of the DPDK retirement umbrella
(#1525). Phase 1 (#1526) shipped the commit-time reject for `set system
dataplane-type dpdk`. Phase 2 (#1527) removed the boot-path import and
backend registration. Phase 4 (#1529) swept documentation. What remains
is the actual deletion of the DPDK source tree, the `pkg/dataplane/dpdk/`
Go package, the Makefile targets, the config schema fields, and the
retirement-boundary canary entries that exist solely to police the
not-yet-deleted DPDK package.

This is the DPDK equivalent of #1476 (eBPF mechanical source removal),
landing in a single auditable diff.

## 2. Honest scope / value framing

This PR is a **deletion-only refactor**. No new functionality, no
performance change, no architectural rearrangement. The win is:

- ~10 861 LOC of unmaintained C + Go deleted (`dpdk_worker/` 17 C files
  + headers + meson; `pkg/dataplane/dpdk/` 6 Go files including
  tests + cached `build/`).
- ~276 KB + ~108 KB of source removed from the tree.
- Three obsolete Makefile targets (`build-dpdk-worker`, `build-dpdk`,
  `clean-dpdk`) removed.
- Four DPDK schema types (`DPDKConfig`, `DPDKAdaptiveConfig`, `DPDKPort`,
  `SystemConfig.DPDKDataplane`) deleted.
- Three retirement-boundary canary structures
  (`dpdkEBPFImportAllowlist`, `dpdkBackendImportAllowlist`,
  `dpdkBackendImportForCanary`) and two canary tests
  (`TestDPDKBackendImportStaysBackendLocal`,
  `TestDPDKEBPFArtifactImportsStayAtLegacyAdapter`) become tautological
  (the package they police no longer exists) and are deleted.
- One canary test (`TestRetirementBoundaryDocsMentionDPDKPolicy`) that
  pins the verbatim text strings in the retirement boundary docs is
  rewritten/dropped — the policy it pins is "DPDK remains a separately
  supported backend", which is no longer true after Phase 3.

The PR provides no operator-visible improvement beyond reduced
compile time and code surface. If reviewers conclude the deletion
pattern is wrong (e.g. structural choices in the config schema removal,
or unsafe ordering of Phase 1 reject preservation), **PLAN-KILL is an
acceptable verdict**. The alternative is to fold scope into a later
phase or to ship in smaller increments.

## 3. What is already shipped

- **Phase 1 (#1526/#1536)**: `validateDataplaneTypeStrict()` in
  `pkg/config/compiler.go:319` returns `ErrDPDKDataplaneRetired` at
  commit time. `validDataplaneType()` still accepts `"dpdk"` so the
  parse path doesn't syntax-error on stored configs. Verbatim message:
  `"the DPDK dataplane backend has been retired; use 'set system
  dataplane-type userspace' (see #1525)"`. Tests:
  `TestDPDKConfigCompileRejects`,
  `TestDataplaneTypeDPDKRejectedAtCommit{,Hierarchical,FiresFirst,ViaApplyGroups}`.
- **Phase 2 (#1527/#1535)**: `cmd/xpfd/main.go` no longer blank-imports
  `pkg/dataplane/dpdk`. `pkg/dataplane/dataplane.go` exposes
  `ErrDPDKBackendRetired` and `TypeDPDK` purely as a token to intercept
  retirement-error paths in `NewDataPlane` / `NewRuntimeDataPlane`.
  `RegisterBackend(TypeDPDK, ...)` and
  `RegisterRuntimeBackend(TypeDPDK, ...)` panic. `daemon_run.go:247`
  soft-fallback path catches `ErrDPDKBackendRetired` and runs in
  config-only mode for a stored-config rolling upgrade case.
- **Phase 4 (#1529/#1537)**: docs swept; only retirement-note text
  remains.

## 4. Concrete design

### 4.1 The Phase 1 reject vs generic reject decision

The issue body says: "the daemon refuses `set system dataplane-type
dpdk` with the Phase 1 retirement message (still in tree for one release
cycle) OR with a generic 'unknown dataplane-type' rejection — issue
body decides." Two paths:

**Option A — Keep Phase 1 reject (RECOMMENDED).** Preserve everything in
this list and only delete the *backend* code:

- `pkg/config/compiler.go` keeps `dataplaneTypeDPDK = "dpdk"`,
  `ErrDPDKDataplaneRetired`, `validateDataplaneTypeStrict()`,
  the `validDataplaneType()` arm accepting `"dpdk"`.
- `pkg/dataplane/dataplane.go` keeps `TypeDPDK = "dpdk"`,
  `ErrDPDKBackendRetired`, the registry-panic guards, and the
  `case TypeDPDK: return nil, ErrDPDKBackendRetired` arms in both
  `NewDataPlane` and `NewRuntimeDataPlane`.
- `pkg/daemon/daemon_run.go:247` soft-fallback continues to work
  unchanged.
- All `TestDataplaneTypeDPDKRejected*` tests keep passing
  unchanged.

**Option B — Replace with generic reject.** Delete the sentinels and
the Phase 1 reject branch. Operator-facing message becomes "unknown
dataplane-type 'dpdk'". The `daemon_run.go:247` soft-fallback needs to
either be deleted (in which case any node booting with stored
`dataplane-type dpdk` either fatal-exits or has to be reconfigured
out-of-band) or to be widened to catch a generic "unknown dataplane
type" error class.

**Recommendation: Option A.** Rationale:

1. The Phase 1 reject is the operator-friendly migration message. The
   issue itself notes "still in tree for one release cycle". Phase 3
   removes the *backend code*, not the *commit-time reject*. The reject
   lives until a future cleanup PR after the release cycle.
2. The soft-fallback in `daemon_run.go:247` is the **only** safe
   stored-config rolling upgrade path. Without it, a node that boots
   with `dataplane-type dpdk` persisted in active config from before
   #1526 would fail to start, and there is no in-tree way to fix the
   config without the daemon running.
3. The verbatim retirement-message text is pinned by
   `dpdkRetirementSubstr` in `parser_ast_test.go:2779` and by 4+
   `TestDataplaneTypeDPDKRejected*` tests. Replacing it with a generic
   message means rewriting all of those tests.

Plan-review reviewers are asked to validate this recommendation. If
the reviewers prefer Option B, the plan is revised before any code
moves.

### 4.2 Files deleted entirely

| Path | Why | Notes |
|---|---|---|
| `dpdk_worker/` (entire directory) | DPDK C worker — 17 C files, 4 headers, `meson.build`, `README.md`, cached `build/` | issue lists every file by name; deletion is mechanical |
| `pkg/dataplane/dpdk/manager.go` | DPDK backend `dataplane.Manager` shape | only consumer was the now-removed registration import |
| `pkg/dataplane/dpdk/dpdk_cgo.go` (build-tag `dpdk`) | DPDK CGo bridge | not compiled by default; tested only with `-tags dpdk` (no CI) |
| `pkg/dataplane/dpdk/dpdk_stub.go` (build-tag `!dpdk`) | Stub implementation | every method returns `errDPDKBuildTagRequired`; never invoked after Phase 2 |
| `pkg/dataplane/dpdk/fib.go` | DPDK FIB sync helper | unreachable after backend deletion |
| `pkg/dataplane/dpdk/dpdk_stub_test.go` | Pins post-#1527 behavior: factory returns `ErrDPDKBackendRetired`, `RegisterBackend(TypeDPDK)` panics | Option A keeps the factory + panic invariants; we MIGRATE these assertions into `pkg/dataplane/dataplane_test.go` rather than dropping them on the floor |
| `pkg/dataplane/dpdk/dpdk_lookup_source_test.go` | Source-level check on `dpdk_cgo.go` | deleted with the package |

### 4.3 Files edited

| Path | Edit |
|---|---|
| `Makefile` | Remove `build-dpdk-worker`, `build-dpdk`, `clean-dpdk` from `.PHONY:` (line 16); remove `clean: clean-dpdk` (line 64); remove the `# --- DPDK targets ---` section (lines 239-251) including all three target recipes |
| `pkg/config/compiler_system.go` | Delete `case dataplaneTypeDPDK:` branch in the `dataplane` switch (lines 236-243). Delete the `compileDPDKDataplane()` function (lines 402-463). Phase 1 reject means the `dpdk` arm is unreachable but kept in `validDataplaneType()`; we delete the *compile-side* DPDK code because nothing reads `DPDKConfig` after this PR |
| `pkg/config/types.go` | Delete `DPDKConfig`, `DPDKAdaptiveConfig`, `DPDKPort` types and the `DPDKDataplane *DPDKConfig` field on `SystemConfig` |
| `pkg/config/ast.go` | Line 1389: the `"socket-mem"` schema node is ONLY consumed by `compileDPDKDataplane()` (verified by `grep -rn "SocketMem\|socket-mem" --include='*.go'`). Since `compileDPDKDataplane()` is deleted, the schema node is dead syntax. Two options: (a) delete the `"socket-mem"` schema-node entirely (cleanest), (b) keep it but rewrite the description as "Legacy DPDK socket memory (retired, ignored)". RECOMMENDED: (a) — the parse path retains acceptance via the parent `dataplane` block which the userspace path uses, but `socket-mem` itself is DPDK-only and useless now |
| `pkg/config/parser_ast_test.go` | Delete `TestDPDKConfigParsesCleanly` (2622-2666) and the supporting `dpdkRetirementSubstr` constant ONLY IF Option B chosen. Under Option A, `TestDPDKConfigParsesCleanly` is REWRITTEN: the flat-set parse must still succeed (because validator catches the reject at commit), but the assertion checking `DPDKDataplane` field population is dropped. `TestDPDKConfigCompileRejects` is kept verbatim |
| `pkg/config/parser_system_test.go:1380-1395` | Remove the `cfg.System.DPDKDataplane != nil` assertion in `TestDataplaneTypeOmittedSelectsUserspaceDataplaneDefault` — the field no longer exists, so the check is unreachable |
| `pkg/configstore/store_test.go:1462` (`TestCommit_RejectsDPDKDataplaneType`) | **KEPT VERBATIM** — Phase 1 reject contract for the `CommitCheck`/`Commit` wrap surface (gRPC/REST). Reads `system dataplane-type dpdk`, asserts the verbatim retirement substring, and locks the `"commit check failed: "` prefix on the wrapped Commit error. Option A preserves this test unchanged |
| `pkg/dataplane/retirement_boundary_canary_test.go` | Delete `dpdkEBPFImportAllowlist` (lines 69-78); delete `dpdkBackendImportForCanary` and `dpdkBackendImportAllowlist` (lines 26 and 80-85); delete `TestDPDKBackendImportStaysBackendLocal` (lines 198-238); delete `TestDPDKEBPFArtifactImportsStayAtLegacyAdapter` (lines 240-276); remove the `imp == dpdkBackendImportForCanary` check from `TestOperatorPackagesDoNotImportBPFArtifactsDirectly` (lines 182-188); update `TestRetirementBoundaryDocsMentionDPDKPolicy` (lines 1784-1810) — see §4.4 |
| `docs/pr/1373-retire-ebpf-dataplane/README.md` | The `## #1475 DPDK Backend Policy` section is now stale (the package is gone). Rewrite as `## #1475 DPDK Backend Retired (#1525)` with a 2-3 line note pointing at #1525 |
| `docs/dpdk-dataplane.md`, `docs/dataplane-decision-dpdk-vs-vpp.md` | Already largely swept in Phase 4 (#1529). Recheck and delete if stale, or trim to a 1-paragraph retirement note. **Pre-check `docs/dpdk-dataplane.md` exists** — issue body asks for short retirement notes; Phase 4 may have already deleted these |
| `pkg/dataplane/README.md` | Drop the #1475 DPDK Backend Policy section |

### 4.4 Canary test surgery (highest-risk edit)

`TestRetirementBoundaryDocsMentionDPDKPolicy` requires the retirement
boundary docs to contain these strings verbatim:

```
"## #1475 DPDK Backend Policy",
"DPDK remains a separately supported backend",
"outside the eBPF source-removal path",
"`pkg/dataplane/dpdk`",
"`cmd/xpfd/main.go`",
"`-tags dpdk`",
"root `DataPlane`",
```

All seven strings are STALE: the policy "DPDK remains a separately
supported backend" is false after #1525, and `pkg/dataplane/dpdk` is
gone after this PR. The canary intent was to lock-in the policy text
during the live-DPDK era. After Phase 3 the canary is **deleted** along
with the docs section, because there is nothing left to police.

Verbatim plan for the canary test:

1. Delete `TestRetirementBoundaryDocsMentionDPDKPolicy` outright.
2. Rewrite the docs section `## #1475 DPDK Backend Policy` →
   `## #1475 DPDK Backend Retired (#1525)` with a 2-3 line note. The
   text strings are NOT pinned anywhere else.
3. `TestRetirementBoundaryDocsMentionShimEscapeAssumptions` is
   independent of DPDK and stays unchanged.

### 4.5 `daemon_run.go` soft-fallback (Option A path)

```go
// pkg/daemon/daemon_run.go:247
if errors.Is(err, dataplane.ErrDPDKBackendRetired) {
    slog.Warn("the DPDK dataplane backend has been retired; running in config-only mode until config is updated",
        ...)
    d.dp = nil
} else if err != nil {
    ...
}
```

Under Option A, this branch is preserved. It catches the case where a
node boots with `system dataplane-type dpdk` persisted in
`active-config.json` (stored before #1526's commit-time reject).
Without this branch the daemon fatal-exits, leaving no path to fix the
config from CLI.

## 5. Public API preservation

Option A path:

| Symbol | Status |
|---|---|
| `dataplane.TypeDPDK` (const) | **Preserved** as retirement-error token |
| `dataplane.ErrDPDKBackendRetired` (sentinel) | **Preserved** |
| `dataplane.RegisterBackend(TypeDPDK, ...)` (panics) | **Preserved** |
| `dataplane.RegisterRuntimeBackend(TypeDPDK, ...)` (panics) | **Preserved** |
| `dataplane.NewDataPlane(TypeDPDK)` returns `ErrDPDKBackendRetired` | **Preserved** |
| `dataplane.NewRuntimeDataPlane(TypeDPDK)` returns `ErrDPDKBackendRetired` | **Preserved** |
| `config.dataplaneTypeDPDK` (const) | **Preserved** (commit-time validator key) |
| `config.ErrDPDKDataplaneRetired` (sentinel) | **Preserved** |
| `config.validateDataplaneTypeStrict()` | **Preserved** |
| `config.validDataplaneType("dpdk")` returns true | **Preserved** (parse still accepts) |
| `config.SystemConfig.DPDKDataplane` (field) | **Deleted** — nothing reads it after this PR |
| `config.DPDKConfig`, `DPDKAdaptiveConfig`, `DPDKPort` (types) | **Deleted** |
| `config.compileDPDKDataplane()` (function) | **Deleted** |
| `dpdk_worker/`, `pkg/dataplane/dpdk/` | **Deleted entirely** |

## 6. Hidden invariants the change must preserve

1. **Stored-config rolling upgrade.** A node booting with
   `system dataplane-type dpdk` persisted in `active-config.json` must
   still come up (in config-only mode) so the operator can fix the
   config from CLI. The soft-fallback in `daemon_run.go:247` preserves
   this under Option A.
2. **`load merge` / `load override` of pre-retirement configs.** The
   parser must still accept `system dataplane-type dpdk` as a syntactically
   valid leaf (commit rejects it). `validDataplaneType()` returning
   true for `"dpdk"` preserves this.
3. **Side-effect ordering at compile.** `validateDataplaneTypeStrict`
   must fire BEFORE any other strict validator that touches
   `cfg.System.DPDKDataplane` (now nil/absent). Since the field is
   deleted, no path can dereference it; safe.
4. **Canary coverage of #1451.** Deleting
   `TestDPDKBackendImportStaysBackendLocal` and
   `TestDPDKEBPFArtifactImportsStayAtLegacyAdapter` does NOT weaken
   #1451 — the package they police no longer exists. The directory walk
   target `pkg/dataplane/dpdk/` in the latter canary becomes a
   `filepath.Walk` over a nonexistent path and would fail at runtime;
   deletion is required, not optional.
5. **No other production import.** `grep -rn "pkg/dataplane/dpdk" cmd/
   pkg/` must return zero hits after this PR. Verified at code time.
6. **`-tags dpdk` build path.** Building with `-tags dpdk` after this
   PR is impossible (the package is gone). This is intentional; no CI
   ran this build path and `make build-dpdk` is removed.

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | All preserved paths are unchanged; deleted code has no production callers |
| Lifetime / borrow-checker | LOW | Go-only; no Rust changes |
| Build-system breakage | MED | Makefile `clean: clean-dpdk` dependency must be removed atomically with the `clean-dpdk` target. `.PHONY:` line must match. Mismatched edits produce a make warning, not a hard failure |
| Test breakage | MED | `parser_system_test.go:1382` references `cfg.System.DPDKDataplane`; missing the edit breaks compilation. Several `TestDPDKConfig*` tests in `parser_ast_test.go` need surgery; missing one breaks the test suite |
| Canary surgery | MED | `retirement_boundary_canary_test.go` has 5 DPDK-related test functions/constants. Missing one means either a stale allowlist entry fails the canary, or a deleted constant breaks compilation |
| Architectural mismatch | LOW | Mechanical deletion only; no architectural premise to fail |
| Phase 1 reject regression | MED if Option B chosen | Option A explicitly preserves Phase 1 reject; Option B would also need rewriting 4+ tests AND widening `daemon_run.go:247` soft-fallback |
| Documentation drift | LOW | Phase 4 (#1529) already swept docs; this PR catches the doc canary's pinned strings |
| Stored-config rolling upgrade | LOW under Option A; MED under Option B | See §6 |

## 8. Test plan

Gate-by-gate:

```bash
# 1. Go build clean
GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go build ./... 2>&1 | tail -5

# 2. Full Go suite
GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./... 2>&1 | grep -v "^ok\|^?" | tail

# 3. 5x flake on the retirement-reject test
for i in 1 2 3 4 5; do
  GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test -run TestDataplaneTypeDPDKRejectedAtCommit ./pkg/config/ 2>&1 | grep -E "PASS|FAIL|ok " | tail -1
done

# 4. Retirement-boundary canary tests
GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test -run TestOperatorPackagesDoNotImportBPFArtifactsDirectly ./pkg/dataplane/ 2>&1 | tail
GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test -run TestRetirementBoundary ./pkg/dataplane/ 2>&1 | tail

# 5. Make build (no -tags dpdk)
make build 2>&1 | tail -5

# 6. Make build-userspace-dp (unchanged target)
make build-userspace-dp 2>&1 | tail -5

# 7. Make test
make test 2>&1 | tail -10

# 8. Grep proof
grep -rIn 'dpdk\|Dpdk\|DPDK' --include='*.go' --include='*.c' --include='*.h' --include='Makefile*' . 2>&1 | grep -vE "retirement|retired|CHANGELOG" | head -30
```

Smoke matrix on the loss userspace cluster (delegated to singleton
smoke-runner via `<!-- AWAITING-SMOKE -->` marker per
`feedback_smoke_serialized_single_agent`):

- Pass A (CoS-off, best-effort): v4+v6 × push+reverse + 12-stream `-R`
- Pass B (CoS-on): per-class 5201-5206 v4+v6 × push+reverse

## 9. Out of scope (explicitly)

1. **Deleting `TypeDPDK`, `ErrDPDKBackendRetired`, and the Phase 1
   reject branch.** Deferred to a future cleanup PR after the
   one-release-cycle migration window. The issue body allows this
   explicitly.
2. **Removing `dpdk` from `validDataplaneType()`.** Same deferral —
   the parse path must continue to accept the stored-config value.
3. **Rolling upgrade telemetry / metrics.** No new counter for
   "node booted with retired dpdk config".
4. **CHANGELOG entry.** Phase 4 (#1529) handled the changelog sweep.
5. **Sibling #1476 eBPF mechanical removal.** Independent. Whichever
   lands first rebases the canary; this PR touches only DPDK-scoped
   surfaces.
6. **#1539 AST leakage guard.** If #1539 is still open after #1528
   merges, its plan target (a runtime check for DPDKConfig AST
   leakage) becomes compile-time-tautological. Coordinated handoff,
   not in this PR's scope.
7. **DPDK protobuf surfaces.** None exist (umbrella confirmed).

## 10. Open questions for adversarial plan review

These are real PLAN-KILL surfaces. Each question is asked because a
"wrong" answer is sufficient to PLAN-KILL or PLAN-NEEDS-MAJOR this
plan.

1. **Option A vs Option B (Phase 1 reject preservation).** The plan
   chooses Option A based on operator-friendly migration message,
   stored-config rolling-upgrade safety via `daemon_run.go:247` soft-
   fallback, and test-rewrite cost. Is Option A correct? If Option B,
   what is the safe alternative for the stored-config rolling upgrade
   case? (PLAN-KILL if reviewer can show Option A leaves a
   bootstrap-loop bug; PLAN-NEEDS-MAJOR if reviewer prefers Option B
   and the test-surgery scope is acceptable.)

2. **`dpdk_worker/build/` cached objects.** The issue body explicitly
   mentions the cached `build/` directory. Is deletion of cached
   meson/ninja artifacts safe? Does any CI step (release packaging,
   debian/, signing) read from that path? **Expected answer: NO**. The
   cache is tree-tracked from Feb 2026 (per #1525 status); no CI runs
   `make build-dpdk`. Plan reviewer to confirm by walking
   `.github/workflows/`, `debian/`, and `test/incus/` for any reference
   to `dpdk_worker/build/`.

3. **`dpdk_stub_test.go` deletion safety.** The stub test pins the
   post-#1527 behavior that `NewDataPlane(TypeDPDK)` returns
   `ErrDPDKBackendRetired` and that `RegisterBackend(TypeDPDK)`
   panics. Under Option A those invariants must still hold; the test
   currently lives in `pkg/dataplane/dpdk/` (package being deleted).
   The plan migrates the assertions into a new test file in
   `pkg/dataplane/` itself. Is that migration sufficient, or does
   deletion-without-migration leave an unverified path? (PLAN-NEEDS-
   MAJOR if reviewer can show the invariants need additional coverage;
   PLAN-KILL is too strong here.)

4. **Removing `TypeDPDK` would break what?** The plan keeps `TypeDPDK`.
   Suppose a reviewer argues for deletion: `daemon_run.go:247` uses
   `errors.Is(err, dataplane.ErrDPDKBackendRetired)`, which would break.
   `NewDataPlane`/`NewRuntimeDataPlane` would need to emit the
   retirement-sentinel via string compare on `dpType == "dpdk"` instead
   of `case TypeDPDK:`. Is the typed-token preservation correct, or
   should `TypeDPDK` and `ErrDPDKBackendRetired` be deleted in this PR
   as part of a "clean break"? Plan reviewer to weigh in.

5. **`DPDKConfig`/`DPDKAdaptiveConfig`/`DPDKPort` deletion breaking
   AST-level tests.** Beyond `parser_ast_test.go` and
   `parser_system_test.go:1382`, are there other tests that parse an
   old DPDK config file and inspect the `DPDKDataplane` field? `grep
   -rn "DPDKDataplane" --include='*.go'` returns only the two test
   sites and `pkg/config/types.go`/`compiler_system.go`. Reviewer to
   verify exhaustively.

6. **Schema-node `socket-mem` description rewrite.** Currently
   `pkg/config/ast.go:1389` describes `socket-mem` as "DPDK socket
   memory". The userspace path uses the same knob (?). Plan says
   "verify before removal" — is the userspace path ACTUALLY using
   this schema node, or is the description simply stale? If the latter,
   the description rewrites to "Legacy DPDK socket memory (retired,
   ignored)" or the schema-node is removed entirely. Reviewer to
   walk the userspace compile path and confirm.

7. **Canary deletion vs. migration.** `dpdkBackendImportForCanary` is
   used by TWO tests: `TestDPDKBackendImportStaysBackendLocal` (a
   `pkg/dataplane/dpdk/` package-existence check) AND
   `TestOperatorPackagesDoNotImportBPFArtifactsDirectly` (a more
   general "operator packages must not import the DPDK package" check).
   The plan deletes the first test and removes the DPDK arm from the
   second test. Is this correct, or should the second test keep a
   generic "no operator package imports any deleted-backend path"
   check? (PLAN-KILL if reviewer can show this weakens #1451 coverage.)

8. **`docs/pr/1373-retire-ebpf-dataplane/README.md` text strings.**
   The plan deletes `TestRetirementBoundaryDocsMentionDPDKPolicy`. If
   any OTHER canary or runtime check matches one of those 7 verbatim
   strings (e.g. "DPDK remains a separately supported backend"),
   deletion silently breaks that check. Reviewer to `grep -rn "DPDK
   remains a separately supported backend"` and confirm no second
   caller exists.

9. **Per-canary-string `_test.go` greps.** Worth listing every place
   the substring `dpdk` or `DPDK` appears in `_test.go` files after
   this PR. Plan-time grep:
   `grep -rIn -i "dpdk" --include='*_test.go' .`. Reviewer to
   confirm the post-PR list is bounded to the (kept) Phase 1 reject
   tests + the (moved) registry-panic tests, with no orphan
   references.

10. **Pre-existing dirty state on master.** `master` already has
    `pkg/dataplane/dpdk/` and `dpdk_worker/` in tree. This PR is the
    only auditable diff that removes them. Is there any in-flight PR
    (e.g. #1539 AST leakage guard, sibling #1476 eBPF retirement) that
    would conflict with the deletion? Coordinator note in §9 covers
    this; reviewer to spot-check `gh pr list` for active touch on
    `pkg/dataplane/dpdk/` or `dpdk_worker/`.

## 11. Reviewer dispatch contract

This plan dispatches Codex + Antigravity in parallel using the
canonical companion CLIs. Both reviewers receive the same hostile
prompt. Verdict aggregation:

- **Both PLAN-KILL** → close issue with rationale, no PR.
- **One PLAN-KILL, one not** → iterate v2 addressing the KILL findings;
  may converge on KILL at v3.
- **Both PLAN-NEEDS-MAJOR / NEEDS-MINOR** → iterate plan.
- **Both PLAN-READY** → proceed to Step 5 implementation.

Codex sandbox failures retried up to 3× per `feedback_codex_infra_must_retry`.
Antigravity hallucinations cross-checked against actual source before
propagation.
