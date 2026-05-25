# #1527 — DPDK retirement Phase 2: boot-path decouple and registration removal

## Status

v4 — IMPLEMENTATION COMPLETE.

v1 → v2 (Codex plan review task-mpkqsgf5-j2yag1, PLAN-NEEDS-MINOR):
1. Require Chain A (#1526) to land BEFORE this PR (sequencing
   constraint, was previously "either order works").
2. Drop Change 5 (docs edit) entirely. The required canary tokens
   are already present in `docs/pr/1373-retire-ebpf-dataplane/README.md`
   and Chain C (#1529) owns the docs sweep.
3. Acknowledge that `ErrDPDKBackendRetired` cannot be re-used by
   `pkg/config` for Chain A because `pkg/dataplane` already imports
   `pkg/config` (import cycle).  The sentinel is for runtime factory
   callers only.

v2 → v3 (Copilot inline review on PR #1535):
4. Soften the runtime-fatal behavior.  v2's `NewRuntimeDataPlane`
   returning `ErrDPDKBackendRetired` would `os.Exit(1)` the daemon
   on the next restart for any node that still had a persisted
   `system dataplane-type dpdk` from before Chain A landed.  v3
   adds an `errors.Is` branch in `pkg/daemon/daemon_run.go` that
   treats this sentinel the same as a `Start()` failure: `slog.Warn`
   plus config-only fallback.  Sequencing dependency on #1526 is
   downgraded from HARD to STRONGLY PREFERRED.
5. Clean up stale plan v1 prose still referencing docs edits and
   token-list trims (Codex code review task-mpkrohgl-dow3kd).

v3 → v4 (Codex + Antigravity hostile code reviews on a00d9111):
6. Fix nil-pointer panic in `daemon_ha_sync.go::OnFenceReceived`.
   The v3 soft-fallback path sets `d.dp = nil` but the peer-fence
   callback at line 670 unconditionally called `d.dp.HA().SetRGActive(...)`.
   A clustered node booted into config-only mode would panic on
   the next peer fence (heartbeat-timeout-driven). Added a
   `d.dp == nil` early-return with structured log.
7. Acknowledge the docs-prose drift Codex v3 flagged.  After this
   PR, `docs/pr/1373-retire-ebpf-dataplane/README.md` lines 64
   and 85 contain factually stale claims about
   `cmd/xpfd/main.go` keeping the DPDK blank import. The pinned
   canary tokens still pass (the literal tokens remain in the
   file), but the prose now describes a pre-#1527 reality. This
   PR intentionally leaves docs untouched per Chain C (#1529)
   scope boundary. The PR description and this plan flag the
   drift as a Chain C TODO.

Earlier verdicts preserved:
- Antigravity plan review: adversarial-review-mpkqkzkm-qfa19j → PLAN-READY.
- Codex plan review: task-mpkqsgf5-j2yag1 → PLAN-NEEDS-MINOR (resolved in v2).
- Codex code review v2: task-mpkrohgl-dow3kd → MERGE-NEEDS-MINOR (resolved in v3).
- Codex code review v3: task-mpkrwbtk-pd6nnw → MERGE-NEEDS-MAJOR (NPE + docs drift; NPE resolved in v4, docs drift acknowledged out-of-scope).
- Antigravity code review v3: adversarial-review-mpkrwmkk-2k24v4 → MERGE-NEEDS-MAJOR (same NPE; resolved in v4).

## Issue framing

Umbrella #1525 retires the DPDK dataplane backend in a staged
sequence (reject-at-commit → boot-path decouple → mechanical source
removal → docs sweep → final validation).

This issue (#1527) is **Phase 2**: stop the xpfd binary from pulling
`pkg/dataplane/dpdk` into its boot path, stop the package from
registering itself as a backend factory, and shrink the retirement-
boundary canary so the import is forbidden everywhere outside the
DPDK package itself. The DPDK source tree (`dpdk_worker/` and
`pkg/dataplane/dpdk/`) stays in place for Phase 3 (#1528) to delete
mechanically. After this PR, the package compiles but nothing in the
production binary references it, so its deletion is a pure no-link
file removal.

The user-facing commit-time rejection for `system dataplane-type
dpdk` is sibling Chain A (#1526). **This PR REQUIRES #1526 to land
first.** Today's behavior on a running daemon that loads a config
with `system dataplane-type dpdk` is:

- `dataplane.NewRuntimeDataPlane("dpdk")` succeeds (stub registers
  the backend, `pkg/daemon/daemon_run.go:245`).
- `d.dp.Start(ctx)` returns `errDPDKBuildTagRequired`, daemon logs
  `slog.Warn("failed to start dataplane, running in config-only
  mode")` and continues running (`daemon_run.go:251-254`).

After this PR's changes:

- `dataplane.NewRuntimeDataPlane("dpdk")` returns
  `ErrDPDKBackendRetired`.
- `daemon_run.go:248` returns `fmt.Errorf("create dataplane: %w",
  err)`, daemon exits with `os.Exit(1)`.

Without #1526 landing first, an operator who already committed
`set system dataplane-type dpdk` on the running config would see
their daemon refuse to start after the next restart. With #1526
landed first, the config never accepts `dpdk` at commit time, so
this PR's runtime path is only reachable via a malformed config
file written by hand (which is acceptable as a fatal error).

## Honest scope/value framing

This PR's value is purely **link-time** and **canary-discipline**:

- Removes one blank import (`cmd/xpfd/main.go:15`).
- Removes two `init()` registrations (`pkg/dataplane/dpdk/manager.go:18-25`).
- Shrinks one canary allowlist entry (`dpdkBackendImportAllowlist`
  in `pkg/dataplane/retirement_boundary_canary_test.go:71-73`).
- Adds a structured `errDPDKBackendRetired` return from
  `NewDataPlane(TypeDPDK)` / `NewRuntimeDataPlane(TypeDPDK)` so any
  remaining call site (there are none in production now, only the
  package-local test) sees a clear retirement error rather than the
  generic "unknown dataplane type" message.

The runtime payoff is:

1. The default `make build` no longer link-edits `pkg/dataplane/dpdk`,
   `pkg/dataplane/dpdk` no longer self-registers, and the boundary
   canary forbids any other production package re-introducing the
   import.
2. Phase 3 (#1528) can delete `dpdk_worker/` and `pkg/dataplane/dpdk/`
   without dangling imports.
3. The canary's purpose was to *sanction* the boot-path import. With
   the import gone, the sanction must go too — otherwise the canary
   silently allows a future regression to re-add it.

If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict. (For this PR there is no
perf claim — the value is discipline gate, not throughput.)

## What's already shipped / partially batched

- The `errDPDKBuildTagRequired` startup error
  (`pkg/dataplane/dpdk/dpdk_stub.go:17`) is gated behind
  `//go:build !dpdk` and only exists in non-`-tags dpdk` builds.
  After this PR's changes, the boot path no longer registers the
  DPDK backend at all (registration removed in both stub and
  `-tags dpdk` builds, since `manager.go` has no build tag). The
  package-local test `TestDPDKStubRequiresDPDKBuildTag` still
  exercises this sentinel directly (no factory path needed), so
  it stays in place until Phase 3 deletes the package.
- The retirement-boundary canary
  (`pkg/dataplane/retirement_boundary_canary_test.go`) already
  enforces the *narrow* policy that only `cmd/xpfd/main.go` may
  import the DPDK package. This PR shrinks that to "no production
  package may import the DPDK package."
- The `pkg/dataplane/runtime/import_canary_test.go` already forbids
  the runtime package from importing DPDK. No change required.
- Sibling Chain A (#1526) is preparing the user-facing commit-time
  rejection in `pkg/config/compiler.go validDataplaneType()`. This
  PR does **not** touch config validation; it touches only the
  Go boot path.

## Concrete design

### Change 1 — Remove blank import in `cmd/xpfd/main.go`

```diff
 import (
 	"context"
 	"flag"
 	"fmt"
 	"log/slog"
 	"os"

 	"github.com/psaab/xpf/pkg/daemon"
 	"github.com/psaab/xpf/pkg/dataplane"
-	_ "github.com/psaab/xpf/pkg/dataplane/dpdk"
 	_ "github.com/psaab/xpf/pkg/dataplane/userspace"
 	"github.com/psaab/xpf/pkg/frr"
 )
```

### Change 2 — Drop backend registration in `pkg/dataplane/dpdk/manager.go`

```diff
 // Compile-time assertion.
 var _ dataplane.DataPlane = (*Manager)(nil)
 var _ dataplane.ConfigSink = (*Manager)(nil)
 var _ dataplane.RuntimeDataPlane = (*Manager)(nil)

-func init() {
-	dataplane.RegisterBackend(dataplane.TypeDPDK, func() dataplane.DataPlane {
-		return New()
-	})
-	dataplane.RegisterRuntimeBackend(dataplane.TypeDPDK, func() dataplane.RuntimeDataPlane {
-		return New()
-	})
-}
```

The compile-time interface assertions stay so that the package
keeps building cleanly even though nothing uses it.

### Change 3 — Make `NewDataPlane(TypeDPDK)` / `NewRuntimeDataPlane(TypeDPDK)` return a retirement error

In `pkg/dataplane/dataplane.go`, before the registry fallback,
return a structured retirement error:

```go
// ErrDPDKBackendRetired is returned from NewDataPlane and
// NewRuntimeDataPlane when caller code still asks for the DPDK
// backend after Phase 2 of #1525.
var ErrDPDKBackendRetired = errors.New(
    "DPDK dataplane backend has been retired; use 'set system " +
    "dataplane-type userspace' (see #1525)")
```

Both factory functions check `dpType == TypeDPDK` early and return
`ErrDPDKBackendRetired`. `TypeDPDK` stays as a string constant so
the runtime path can detect it; the constant's docstring is updated
to mark it as a retired sentinel.

The `NewDataPlane` error message updates to remove `dpdk` from the
"valid: ..." list:

```diff
-		return nil, fmt.Errorf("unknown dataplane type %q (valid: ebpf, dpdk, userspace)", dpType)
+		return nil, fmt.Errorf("unknown dataplane type %q (valid: ebpf, userspace)", dpType)
```

### Change 4 — Shrink the canary allowlist

```diff
-var dpdkBackendImportAllowlist = map[string]string{
-	"cmd/xpfd/main.go": "backend registration and cleanup entry point",
-}
+// dpdkBackendImportAllowlist is intentionally empty after Phase 2 of
+// #1525.  The DPDK package may still exist in tree but no production
+// package outside it may import it.  Phase 3 (#1528) removes the
+// package entirely.
+var dpdkBackendImportAllowlist = map[string]string{}
```

`TestDPDKBackendImportStaysBackendLocal` is rewritten so that *any*
import of `pkg/dataplane/dpdk` from outside `pkg/dataplane/dpdk/`
is a violation. The test still ignores files under
`pkg/dataplane/dpdk/` itself. The "stale allowlist entry" logic
collapses to a non-issue because the map is empty.

`TestOperatorPackagesDoNotImportBPFArtifactsDirectly`
(line 137-159) currently allows `cmd/xpfd/main.go` to import DPDK.
That exemption is removed (the import is gone).

### Change 5 — REMOVED (Chain C scope)

The original plan v1 proposed editing
`docs/pr/1373-retire-ebpf-dataplane/README.md`'s `#1475 DPDK
Backend Policy` section. Codex round-1 plan review correctly
flagged that this is Chain C (#1529) scope.

The required canary tokens at
`pkg/dataplane/retirement_boundary_canary_test.go:1780-1788`
(`## #1475 DPDK Backend Policy`, `DPDK remains a separately
supported backend`, `outside the eBPF source-removal path`,
`` `pkg/dataplane/dpdk` ``, `` `cmd/xpfd/main.go` ``, `` `-tags
dpdk` ``, `` root `DataPlane` ``) are all still present in the
README untouched (verified by grep). The docs-token canary stays
green without any edit in this PR. Chain C will update the prose
to reflect the post-Phase-2 reality once Phase 3 (#1528) has
deleted the package.

### Change 6 — Adjust the DPDK package-local test

`pkg/dataplane/dpdk/dpdk_stub_test.go` lines 13-29 currently
exercises the registration path with
`dataplane.NewDataPlane(dataplane.TypeDPDK)`. After this PR the
registration is gone and the factory returns
`ErrDPDKBackendRetired`. The test is rewritten as
`TestDPDKConstructorsReturnRetirementError` and asserts the error
is `ErrDPDKBackendRetired`. The stub-build-tag test
`TestDPDKStubRequiresDPDKBuildTag` stays unchanged — `m := New()`
still exercises the stub directly without going through the
registry.

## Public API preservation

- `pkg/dataplane.DataPlane` interface — unchanged.
- `pkg/dataplane.RuntimeDataPlane` interface — unchanged.
- `pkg/dataplane.NewDataPlane(string)` signature — unchanged; the
  error return shape changes for the DPDK case.
- `pkg/dataplane.NewRuntimeDataPlane(string)` signature — unchanged;
  same.
- `pkg/dataplane.TypeDPDK` constant — preserved. (Chain A
  (#1526) cannot import `dataplane.ErrDPDKBackendRetired` from
  `pkg/config/compiler.go` without creating an import cycle —
  `pkg/dataplane/dataplane.go:9` already imports `pkg/config`.
  Chain A will keep its own string literal or local sentinel.
  The `TypeDPDK` constant is still useful as a typed token for
  the retirement-error code path in `NewDataPlane` /
  `NewRuntimeDataPlane`.)
- `pkg/dataplane/dpdk.Manager` type — unchanged; still compiles.
- `pkg/dataplane/dpdk.New()` constructor — unchanged; still
  callable but no longer registered.
- `errDPDKBuildTagRequired` — unchanged; still the stub's runtime
  error.

## Hidden invariants the change must preserve

1. **No production code path can construct a DPDK Manager.** After
   this PR, the only way to get a `*dpdk.Manager` is to call
   `pkg/dataplane/dpdk.New()` directly. No production package
   outside `pkg/dataplane/dpdk/` is allowed to import it. The
   canary enforces this.

2. **Canary tests stay green.** `TestDPDKBackendImportStaysBackendLocal`
   gets stricter (empty allowlist) but must still pass on this PR's
   tree. `TestOperatorPackagesDoNotImportBPFArtifactsDirectly`
   loses one exemption and must still pass.
   `TestRetirementBoundaryDocsMentionDPDKPolicy` requires the docs
   text edits to keep the right tokens present.

3. **`-tags dpdk` build path still works as a no-op-from-boot.**
   Even with `-tags dpdk`, removing the blank import means the
   `init()` registration never runs (since this PR also deletes
   the `init()`). That's intentional. A `-tags dpdk` build today
   would compile but the daemon would still reject DPDK selection
   via the Phase 1 commit-time rejection (Chain A) and via
   `ErrDPDKBackendRetired` from the factory.

4. **Test-side import of DPDK is still allowed.** The boundary
   canary scans production Go files only (`*.go` excluding
   `*_test.go`), per `productionGoFilesUnder()` at line 1591.
   That means `dpdk_stub_test.go` can still call
   `dataplane.NewDataPlane(dataplane.TypeDPDK)` to verify the
   retirement error.

5. **Runtime canary stays green.**
   `pkg/dataplane/runtime/import_canary_test.go` already forbids
   runtime from importing DPDK. No change.

6. **Phase 3 (#1528) blast radius shrinks but does not grow.**
   This PR does not delete any DPDK source. It only changes one
   `init()` and removes one import. Phase 3's manifest can stay
   exactly as planned.

## Risk assessment

| Class | Risk | Why |
|---|---|---|
| Behavioral regression | LOW | The default build never registered DPDK as a backend that could actually run packets (the stub always returned `errDPDKBuildTagRequired`). Removing the registration just means the rejection happens earlier (at factory call) rather than at `Load()`. |
| Lifetime / borrow-checker (Go) | NONE | This is Go, not Rust. No lifetime concerns. No new goroutines, channels, or state. |
| Performance regression | NONE | Pure link-time change. No hot-path code touched. |
| Architectural mismatch | LOW | Same shape as #1473 retirement Phase 1 — shrink canary allowlist, remove registration, leave package compilable for later deletion. |
| Canary drift | MED | The canary tests are fiddly. The `stale allowlist entry` branch of `TestDPDKBackendImportStaysBackendLocal` triggers if the map empties without the test logic understanding that empty-is-OK. The plan accounts for that by reading the test code, not just the allowlist. |
| Docs-token canary drift | NONE | `TestRetirementBoundaryDocsMentionDPDKPolicy` pins 7 token strings. This PR does NOT touch the docs prose at all — every required token already appears in `docs/pr/1373-retire-ebpf-dataplane/README.md` untouched. Chain C (#1529) will update the prose after Phase 3 deletion. |
| #1526 ordering | LOW (mitigated in v3) | Plan v2 required #1526 first because today's daemon falls through to config-only on stub Start() failure but this PR made the same config fatal at constructor time. **v3 mitigates this in `pkg/daemon/daemon_run.go`**: `NewRuntimeDataPlane(...)` returning `ErrDPDKBackendRetired` is detected via `errors.Is` and treated the same as a `Start()` failure — `slog.Warn` plus config-only fallback. Operators with a persisted `system dataplane-type dpdk` get a clear remediation log and a running daemon rather than an `os.Exit(1)` loop. The sequencing dependency on Chain A is no longer hard; #1526 still strongly preferred because it gives the same operator UX at commit time instead of startup time. |

## Test plan

### Build / unit
- `go build ./...` from worktree root — clean.
- `go build -tags dpdk ./...` — clean (with `-tags dpdk` ldflags
  fixed at link).
- `go test ./pkg/dataplane/...` — full canary + unit test pass.
- `go test ./...` from worktree root — all 30 Go packages pass.
- `cargo build` and `cargo test --release` from `userspace-dp/` —
  Rust side is untouched but smoke gates require it green.

### Cluster smoke (loss userspace cluster)

Standard skill matrix:

- Pass A (CoS-off): 4 single-stream baselines + 2 multi-stream
  reverse reproducers = 6 measurements.
- Pass B (CoS-on): per-class 5201-5206 × v4/v6 × push/reverse = 24
  measurements.

Total: 30 measurements per the skill's discipline. Required:
0 retrans for unshaped, shaped classes hit configured rate.

### Verification of canary

- `go test -run 'TestDPDKBackendImportStaysBackendLocal' ./pkg/dataplane/`
  — passes with empty allowlist.
- Manually re-add the import to a throwaway test file: canary
  fails with "unexpected imports".
- `go test -run 'TestOperatorPackagesDoNotImportBPFArtifactsDirectly' ./pkg/dataplane/`
  — passes (no DPDK production imports left).
- `go test -run 'TestRetirementBoundaryDocsMentionDPDKPolicy' ./pkg/dataplane/`
  — passes untouched (the required tokens already appear in
  `docs/pr/1373-retire-ebpf-dataplane/README.md`; Chain C #1529
  owns the docs prose sweep).

## Out of scope (explicitly)

- **Deletion of `dpdk_worker/`, `pkg/dataplane/dpdk/`, Makefile
  targets, and `DPDKConfig` schema** — Phase 3 (#1528).
- **Commit-time rejection of `system dataplane-type dpdk`** —
  Chain A (#1526).
- **Docs sweep across README.md, CLAUDE.md, `docs/feature-gaps.md`,
  etc.** — Chain C wave 2 (#1529).
- **Removing the `dpdkEBPFImportAllowlist`** — Phase 3 (#1528),
  since the file it points at (`pkg/dataplane/dpdk/manager.go`)
  goes away.
- **`TypeDPDK` constant deletion** — left to Chain C wave 2 once
  no caller references it (this PR is the last production user of
  it; the constant could in principle be deleted but doing so
  ripples into `dpdk_stub_test.go` which Chain C will delete anyway).
- **`-tags dpdk` build path full removal** — Chain C wave 2 when
  the DPDK source goes.
- **Any `pkg/config/types.go` `DPDKConfig` schema change** —
  Chain A / Chain C.

## Open questions for adversarial review

1. **Should `TypeDPDK` be deleted now rather than preserved as a
   sentinel?** Argument for delete: removes one more thing Chain C
   has to sweep. Argument against: Chain A (#1526) might want a
   typed sentinel in `validDataplaneType()` rather than a magic
   string `"dpdk"`. Default plan: keep it, document it as retired.
   PLAN-NEEDS-MAJOR if reviewer thinks it must go now.

2. **Should `init()` be removed or kept as a no-op with a comment?**
   Removed cleans up the file. Kept-as-no-op signals "this package
   used to register itself; Phase 3 will delete the package." Default
   plan: remove. Reviewer may push for keep-with-comment.

3. **Is the canary docs-token edit too aggressive?** The docs
   currently say "DPDK remains a separately supported backend." That
   sentence is *no longer accurate* after this PR. The plan rewrites
   it. Does the reviewer want a softer edit — e.g., "DPDK backend
   registration has been retired pending Phase 3 deletion" — that
   preserves more existing prose?

4. **Should `NewRuntimeDataPlane(TypeDPDK)` short-circuit before the
   `EffectiveType` rewrite?** Currently it normalizes empty→userspace
   first, then dispatches. The plan adds a `dpType == TypeDPDK` check
   after normalization. If empty config still defaults to userspace
   (which it should), this is fine. But if a future caller passes
   `TypeDPDK` directly, does the order of operations matter? Default
   plan: check after `EffectiveType` so the empty-default path is
   unaffected.

5. **Does this PR need to land before or after #1526?** RESOLVED:
   #1526 must land first. Codex plan review (task-mpkqsgf5-j2yag1)
   correctly showed that today's behavior is `slog.Warn` + config-
   only fallback, while this PR makes the same config fatal at
   daemon startup. Without Chain A landing first, an existing
   `system dataplane-type dpdk` config would kill the daemon on
   next restart.

6. **The `-tags dpdk` build path: leave it as zombie code or
   actively break it?** Removing the `init()` means `-tags dpdk`
   builds still link the DPDK CGo code but the daemon won't invoke
   it. Should this PR also gate the CGo code behind an additional
   compile error to force Chain C to clean it up? Default plan: no
   — leave it as dead code for Chain C to delete in one batch.

7. **Is the package-local test `TestDPDKConstructorsReturnRetirementError`
   actually exercising real behavior, or is it just a tautology?**
   After this PR, the only consumer of `TypeDPDK` going through
   `NewDataPlane` is that test. Without the test, the entire
   retirement-error code path is unreached. The test prevents a
   future maintainer from silently weakening the error to "unknown
   dataplane type". That seems worth keeping; reviewer may disagree.

8. **Should the retirement error be `errors.Is`-comparable or just a
   formatted string?** Plan uses `errors.New` so callers can
   `errors.Is(err, dataplane.ErrDPDKBackendRetired)`. If Chain A
   (#1526) wants to wrap this at the config layer, sentinel-error
   shape is the right choice.
