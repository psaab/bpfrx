# #1473 Closeout Plan: Retire userspace shim dependency on `xdp_main_prog`

Status: closeout. The runtime decouple, link-cycle test coverage, counter
rename, and boundary canary work for #1473 already landed on master at
`da103d81` via prior PRs (#1493, #1498, #1512, #1513, #1514). This plan
walks each acceptance criterion to its concrete proof point on master,
identifies any residual gap, and defines the closeout deliverables.

## Acceptance Criteria, Per-AC Evidence

### AC1 — No runtime dependency on `xdp_main_prog` or legacy fallback prog array

Required: the retained userspace XDP shim has no runtime dependency on
`xdp_main_prog` or `userspace_fallback_progs`.

Proof on master at `da103d81`:

- `userspace-xdp/src/lib.rs` has no `ProgramArray`, `.tail_call(`, or
  `bpf_tail_call`; the retained shim no longer carries the legacy
  fallback prog array (`userspace_fallback_progs`).
  - Allowlist of retained Rust maps:
    `pkg/dataplane/retirement_boundary_canary_test.go:99-114` —
    `userspace_fallback_progs` is **not** in the allowlist; the
    allowlist explicitly accepts only `userspace_fallback_stats`
    (Array; kept as the pinned-map compatibility name per #1514).
  - Forbidden tail-call tokens are pinned at
    `pkg/dataplane/retirement_boundary_canary_test.go:405-409`.
- `pkg/dataplane/userspace/manager.go:495-500` carries the contract
  comment: "Do not swap to `xdp_main_prog` for unsupported
  capabilities or failed XSK liveness." The compile path selects
  `xdp_userspace_prog` via `SelectUserspaceXDPShimEntryProgram()`.
- `pkg/dataplane/userspace/maps_sync.go` no longer requires
  `userspace_fallback_progs` or `xdp_main_prog`. The current liveness
  / ctrl-disabled paths fail closed instead of swapping back to the
  legacy entry program.
- `pkg/dataplane/userspace/process.go` link-cycle paths
  (`PrepareLinkCycle`, `NotifyLinkCycle`) leave the userspace shim
  attached, disable `userspace_ctrl`, and drive `stop_workers` /
  `rebind` against the helper without touching `xdp_main_prog`.
- Search confirmation:
  - `rg -n "userspace_fallback_progs|fallback_to_main"
    --type rust --type go --type c` returns no runtime hits; only
    historical / archived docs reference the old name.
  - `rg -n "xdp_main_prog" pkg/dataplane/userspace/` shows a single
    explanatory comment at `manager.go:498`, no live call.

### AC2 — Compat/strict behavior explicitly defined and tested

Required: helper-down, XSK-liveness-failure, ctrl-disabled, and
link-cycle paths have explicit behavior under strict and compat modes,
with tests. Default for these conditions is strict fail-closed with
`XDP_DROP`, tracked under the `degraded_path` counter family.

Proof on master:

- Behavior contract in `userspace-xdp/src/lib.rs`:
  - Ctrl-disabled / non-local transit: `XDP_DROP` plus
    `incr_fallback_stat(USERSPACE_FALLBACK_REASON_TRANSIT_DROP)` /
    `USERSPACE_FALLBACK_REASON_STRICT_DROP` (lib.rs:940-943).
  - Local/control IP traffic: `cpumap_or_pass` to the kernel
    (lib.rs degraded helper section).
  - ARP/LLDP and other non-IP local L2: explicit `XDP_PASS` from the
    shim, counted under degraded buckets.
- Tests in `pkg/dataplane/userspace`:
  - `xdp_shim_decouple_test.go` (534 lines) — ctrl-disabled transit
    drop, local/control pass, binding-not-ready transit drop, XSK
    liveness failure keeping the userspace shim selected.
  - `link_cycle_test.go` (412 lines, landed in #1513) —
    `PrepareLinkCycle()` and `NotifyLinkCycle()` paths under strict
    and compat modes; verifies `stop_workers`, `rebind`, liveness
    reset, helper status reapply, and that no `xdp_main_prog` swap is
    invoked.
- Counter family rename to `degraded_path_*` landed in #1514:
  - Go-side primary status surface is `degraded_path_counters`
    (`pkg/dataplane/userspace/protocol.go` / `maps_sync.go`).
  - Legacy `fallback_counters` JSON key is emitted as a temporary
    alias for rolling-upgrade status readers (#1514 contract).

### AC3 — Fallback counter naming no longer implies legacy fallback

Required: any remaining "fallback" counter naming is renamed or
redefined so it no longer implies fallback to the legacy eBPF
dataplane.

Proof on master:

- Primary operator-facing field is `degraded_path_counters`. The
  pinned BPF map path `userspace_fallback_stats` remains a documented
  pinned-map compatibility exception (#1514 contract); it is named
  in `docs/pr/1381-dataplane-interface-split/plan.md:389` and
  carried in the allowlist at
  `pkg/dataplane/retirement_boundary_canary_test.go:104`.
- Reason names align Rust and Go tables across all 16 retained-shim
  degraded buckets, including `strict_drop`, `pass_to_kernel`,
  `transit_drop`, redirect/error reasons.
- Active docs no longer describe the counters as legacy fallback:
  - `docs/xpf-userspace-fw-deploy-verification.md`,
    `docs/userspace-dataplane-architecture.md`, and
    `docs/userspace-xdp-pass-bootstrap-and-ipv6.md` were updated by
    #1514 to use degraded-path wording for the operator-facing
    counters.
  - Archived audit docs under `docs/archived/` retain the old name
    intentionally as historical context.

Residual nit (does not block #1473 closeout): the BPF map symbol
itself is still named `userspace_fallback_stats` because of mixed-
version pin compatibility. The #1514 contract documents this as an
internal exception, not an operator surface.

### AC4 — `go generate` / `make generate` can build retained shim standalone

Required: the retained shim's bpf2go directive should NOT pull in
`bpf/xdp/xdp_main.c` etc. `make generate-userspace-xdp` builds the
retained shim without invoking legacy XDP/TC bpf2go.

Proof on master:

- `Makefile:32-33` defines `generate-userspace-xdp`:
  - `$(GO) generate -run '^//go:generate bash build-userspace-xdp\.sh$$' ./pkg/dataplane`
  - Selects only the Rust shim build script; does not invoke any
    legacy `bpf2go` directive.
- The Rust shim build script (`pkg/dataplane/build-userspace-xdp.sh`)
  invokes only `cargo` against `userspace-xdp/`; no `clang`, `bpf2go`,
  or legacy header invocation.
- Canaries pin the contract:
  - `TestUserspaceXDPGenerateTargetStaysDecoupledFromLegacyBPF`
    (`pkg/dataplane/retirement_boundary_canary_test.go:265`) parses
    the `generate-userspace-xdp` Makefile target and rejects any
    `bpf2go` token or any legacy XDP/TC source path in its recipe.
  - `TestUserspaceXDPGoGenerateRunSelectsOnlyShim`
    (`pkg/dataplane/retirement_boundary_canary_test.go:301`) verifies
    that running the same `-run` filter selects exactly the shim
    build directive.

### AC5 — Regression tests cover strict, compat, helper stop, link-cycle

Proof on master (test inventory, all in `pkg/dataplane/userspace`):

- `xdp_shim_decouple_test.go` — strict/compat ctrl-disabled and
  binding-not-ready paths.
- `link_cycle_test.go` — helper stop (`PrepareLinkCycle`), rebind
  (`NotifyLinkCycle`), strict-mode fail-closed flags, liveness reset,
  helper-status projection, and shim-stays-attached invariants
  (#1513).
- `shim_loader_boundary_test.go` — userspace startup uses
  `LoadUserspaceShim()` / `CompileUserspaceShim()` with no legacy
  loader tokens.
- `manager_coupling_test.go` and the broader
  `retirement_boundary_canary_test.go` suite forbid reintroducing
  positional `dataplane.Manager` literals carrying `xdp_main_prog`,
  reintroducing `xdp_main_prog` as a direct string in the userspace
  link-cycle code path, or calling `SwapXDPEntryProg("xdp_main_prog")`
  from any userspace control plane site.

## Itemized references that prove "no legacy fallback dependency"

`rg -n "xdp_main_prog" pkg/dataplane/` shows only:

- `pkg/dataplane/loader.go:21` — `defaultXDPEntryProg` constant,
  consumed by the legacy eBPF backend only.
- `pkg/dataplane/userspace/manager.go:498` — explanatory comment in
  the userspace compile path stating the userspace runtime must not
  require the legacy main XDP pipeline.
- `pkg/dataplane/retirement_boundary_canary_test.go` —
  literal-fixture sites that drive the canary itself (these are the
  forbidden tokens the canary is searching for).
- `pkg/dataplane/userspace/shim_loader_boundary_test.go:69` —
  literal token list driving the userspace shim loader boundary
  canary (forbidden tokens).

`rg -n "userspace_fallback_progs|fallback_to_main"
--type rust --type go --type c` returns zero runtime hits across the
repo. Only `docs/archived/`, `docs/issues/`, and historical
`testing-docs/` carry the old names as history.

## Risk Review

- Tests that previously relied on the fallback tail-call landing in
  `xdp_main_prog` have already been retargeted to the fail-closed
  contract (`xdp_shim_decouple_test.go`, `link_cycle_test.go`). No
  remaining test asserts a tail call to `xdp_main_prog` from the
  retained shim.
- Operator surfaces:
  - `degraded_path_counters` is the primary status key; older
    consumers still see `fallback_counters` as the temporary alias.
    No CLI/Prometheus path has been observed to describe the shim
    behavior as "fallback to legacy eBPF" on master.
  - `userspace_fallback_stats` survives only as a pinned BPF map
    name for mixed-version compatibility (#1514 contract).

## Closeout Deliverables in This PR

1. Add `docs/pr/1473-xdp-shim-decouple/plan.md` (this file) so the
   #1473 evidence trail lives next to its sibling plans.
2. Update `docs/pr/1373-retire-ebpf-dataplane/README.md` to mark
   `#1473` as Closed in the Current Removal Work table, with the
   evidence trail pointing at the canaries and tests cited above.
3. Run the targeted regression set
   (`pkg/dataplane` + `pkg/dataplane/userspace` userspace and
   canary tests) and append the result to `_Log.md`.
4. Run cluster smoke on the `loss:xpf-userspace-fw0/fw1` userspace
   cluster (v4+v6 push/-R, CoS off + CoS on) and attach the artifact
   path to the PR body, per project rule "Smoke loss userspace only"
   and "Smoke v4+v6 push/reverse + CoS-on/off".
5. Do NOT auto-merge. Open the PR, dispatch Codex + Antigravity
   adversarial code review + wait for Copilot, return verdicts.

## Out of Scope

- Source removal of `bpf/xdp/xdp_main.c` and friends. That is #1476,
  which depends on this closeout plus the rest of the #1373 chain.
- Removing `userspace_fallback_stats` as a pinned BPF map symbol;
  that is a future mixed-version cleanup, not #1473.
- Cleaning archived/historical docs that still describe the legacy
  fallback path. Archived docs are intentionally historical.

## Validation Commands

```bash
GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./pkg/dataplane \
  -run 'TestUserspaceXDPGenerateTargetStaysDecoupledFromLegacyBPF|TestUserspaceXDPGoGenerateRunSelectsOnlyShim|TestUserspaceXDPShimSourceMatchesRetainedObjectAllowlist|TestUserspaceXDPShimObjectMatchesRetainedCollectionAllowlist|TestUserspaceManagerSelectsOnlyUserspaceXDPEntryProgram|TestBPFShimEntryProgramStateIsNotJSONMutable|TestUserspaceXDPEntryProgramConstantNamesRetainedShim|TestOperatorPackagesOnlyUseDocumentedLegacyDataplaneImports|TestRetirementBoundaryDocsMentionLegacyImportAllowlist' \
  -count=1

GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./pkg/dataplane/userspace \
  -run 'TestUserspaceStartupUsesShimLoaderBoundary|TestUserspaceShimLoaderDoesNotReferenceLegacyObjects|TestProgramBootstrapMapsDoesNotRequireLegacyFallbackProgram|TestXSKLivenessFailureRestoresUserspaceShimEntry|TestUserspaceXDPDegradedCtrlDisabledDropsTransit|TestUserspaceXDPDegradedCtrlDisabledPassesLocalControl|TestUserspaceXDPBindingNotReadyDropsTransitButPassesLocalControl|TestPrepareLinkCycle|TestNotifyLinkCycle' \
  -count=1
```

## References

- Issue: https://github.com/psaab/xpf/issues/1473
- Parent retirement umbrella: https://github.com/psaab/xpf/issues/1373
- Prior PRs that landed the runtime split and tests:
  - PR #1493 — split userspace shim loader/bootstrap from legacy load
  - PR #1498 — userspace: split shim loader from legacy BPF load
  - PR #1512 — dataplane: harden userspace shim boundary canary
  - PR #1513 — test: cover userspace link-cycle control plane
  - PR #1514 — status: rename retained-shim degraded counters
