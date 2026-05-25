# #1476 — eBPF Retirement: Mechanical Source Removal

**Status:** DRAFT v2 — addresses Codex r1b PLAN-NEEDS-MAJOR (6 findings)
and AGY r1 PLAN-NEEDS-MINOR (2 findings). The #1373 umbrella's
mechanical-deletion phase. Blocked-on-merge by #1516 (grpcapi
migration) and #1521 (userspace maps_sync decouple), both sub-issues
of #1451. #1473, #1493, #1494, #1518, #1522 already merged.

This plan is staged while the in-flight blockers close so review can
happen in parallel with #1451 completion. Phase B (implementation)
rebases onto master once `gh issue view 1451 --json state` returns
`CLOSED`.

## v2 changes from v1

- **§4.1 Option A clarified — `Manager.Load()` kept as retirement
  stub**: Both reviewers caught that the `DataPlane` interface at
  `pkg/dataplane/dataplane.go:209` requires `Load()` AND
  `Manager.Start()` at `pkg/dataplane/apply.go:208` calls
  `m.Load()`. The compile-time interface assertion at
  `pkg/dataplane/dataplane.go:29` (`var _ DataPlane =
  (*Manager)(nil)`) would break under v1's outright deletion. Plan
  v2 keeps `Manager.Load()` as a method that returns
  `ErrEBPFBackendRetired` directly (Option C-shape, with Option A
  retirement-error semantics). The interface stays bit-identical;
  `Manager.Start()` keeps calling `m.Load()` and propagates the
  retirement sentinel up to `daemon_run.go:247`-style soft-fallback
  consumers.
- **§4.3 Makefile clean narrowed**: Both reviewers flagged
  `Makefile:66-67` `rm -f pkg/dataplane/*_bpfel.go
  pkg/dataplane/*_bpfeb.go` + `*_bpfel.o`/`*_bpfeb.o` would delete
  the retained `pkg/dataplane/userspace_xdp_bpfel.o` (embedded by
  `userspace_xdp_rust.go:11`). v2 narrows globs to
  `pkg/dataplane/xpf*_bpfel.{go,o}` so the retained shim object is
  never matched.
- **§4.3 `dataplane_boot_test.go` rewrite required**: AGY r1 +
  Codex F8 both caught that
  `TestBuildRuntimeDataPlaneEBPFRoutesToLegacyManager` at
  `pkg/daemon/dataplane_boot_test.go:48-61` (added in #1520)
  explicitly asserts `*dataplane.Manager` is returned for
  `TypeEBPF`. Under Option A it must be rewritten to assert
  `ErrEBPFBackendRetired`, mirroring
  `TestBuildRuntimeDataPlaneDPDKReturnsRetired` at the same file.
- **§4.3 other `TypeEBPF` tests classified per reviewer**: AGY r1
  empirically verified `vip_readiness_test.go:352`,
  `per_rg_test.go:126`, `tunnel_anchor_test.go:57` are Go-level
  struct-logic tests that only need `cfg.System.DataplaneType !=
  TypeUserspace` to exercise their branch — they keep `TypeEBPF`
  as a token (still exported under Option A). Codex F8 was more
  cautious; v2 takes AGY's empirical reading after re-reading each
  test's assertion block (none boot a Manager or call
  `NewRuntimeDataPlane`). If implementation reveals an unexpected
  failure, plan v3 will rewrite per-test.
- **§4.8 retained shim helpers fully enumerated**: Codex F3 caught
  v1 under-listed retained dependencies. AGY r1 provided the
  verified full enumeration. v2 incorporates AGY's list:
  `validateUserspaceShimSpec`, `userspacePinnedShimMaps`,
  `userspaceRequiredShimPins`, `userspaceShimSharedMapSpecs`,
  `loadUserspaceShimSharedMaps`, `closeUniqueMaps`,
  `loadOrCreatePinnedShimMap`, `loadOrCreatePinnedShimMapWith`,
  `userspaceShimMapLoader`, `hashMapSpec`, `perCPUHashMapSpec`,
  `arrayMapSpec`, `perCPUArrayMapSpec`, `sizeOf`,
  `ensureUserspaceMapPinned`. None pull legacy `xpfXdp*`/`xpfTc*`
  types — clean extraction verified.
- **§5 invariant 7 — `pinnedMaps` corrected**: Codex F4 + AGY r1
  both caught `nat_port_counters` is NOT legacy-only. It is created
  by `userspaceShimSharedMapSpecs()` at `loader_ebpf.go:712`,
  consumed by `Manager.ReadNATPortCounter()` at `maps.go:1569` and
  `SeedNATPortCounters()` at `maps.go:1589`, AND pinned by the
  boundary canary at
  `pkg/dataplane/retirement_boundary_canary_test.go:383`. v2 keeps
  `nat_port_counters` in the retained pin set. Stale legacy pins
  are `xdp_progs`, `tc_progs`, `policer_states` only.
- **§4.4 canary surgery extended to `loader_stub.go` + docs
  tokens**: Codex F5 caught that `loader_stub.go` appears in
  `retainedShimBoundaryBuildTagAllowlist` at
  `retirement_boundary_canary_test.go:106` AND in the docs-pinned
  tokens at `retirement_boundary_canary_test.go:1823`. v2 deletes
  the allowlist entry AND the docs-pinned token in lockstep with
  the file deletion.
- **§4.4 manifest test count corrected**: Codex F6 noted there are
  five `TestLegacyBPFRemovalManifest*` tests, not four (lines 28,
  71, 108, 133, 161 of `legacy_bpf_manifest_canary_test.go`). v2
  corrects the count and walks all five.
- **§4.6 `rewriteRetiredDataplaneType` clarified as net-new
  helper**: Codex F9 noted current master `Store.Load()` has no
  rewrite hook before `compileTree` (`pkg/configstore/store.go:83`).
  v2 adds the helper as net-new code in this PR, not as an
  extension of a #1528 deliverable. If #1528 lands first with its
  own helper, this PR extends it to handle `ebpf` too; otherwise
  this PR adds the helper fresh and a future cleanup PR consolidates
  the dpdk + ebpf rewrite logic.

---

## 1. Issue framing

#1476 is the mechanical-deletion phase of the #1373 eBPF retirement
umbrella. Earlier phases (#1374-#1381, #1451, #1473, #1493, #1494,
#1522) closed feature gaps, split the userspace shim loader, locked
the retirement boundary with canaries, and (in flight via #1516 +
#1521) shrunk the legacy `dataplane.DataPlane` surface to the point
where source deletion does not break userspace startup.

What remains is the actual deletion of:

- `bpf/xdp/*.c` (9 XDP ingress programs, ~8,000 LOC)
- `bpf/tc/*.c` (5 TC egress programs, ~1,000 LOC)
- `bpf/xdp/README.md`, `bpf/tc/README.md`, `bpf/README.md`
- 14 generated bpf2go pairs `pkg/dataplane/xpf{Xdp,Tc}*_x86_bpfel.{go,o}`
- 14 legacy bpf2go `//go:generate` directives in
  `pkg/dataplane/loader.go`
- `pkg/dataplane/loader_ebpf.go` (957 LOC of legacy loader graph that
  depends on the deleted bpf2go types)
- `pkg/dataplane/loader_stub.go` (the `//go:build ignore` placeholder
  whose only purpose is to document a no-generated-files build that
  no longer exists)
- Legacy `Makefile` targets and variables that only feed the deleted
  bpf2go batch (`generate-legacy-bpf`)
- Active docs that still describe the deleted XDP/TC build path as
  normal workflow

Retained (NOT deleted by this PR):

- `bpf/headers/*.h` — shared C struct/constant headers consumed by
  the userspace XDP shim's Rust build and by userspace-dp parity
  tests. The retirement manifest (already merged via #1494) lists
  these explicitly under "Retain".
- `userspace-xdp/` — Rust source for the retained AF_XDP shim
- `pkg/dataplane/userspace_xdp_bpfel.o` — compiled Rust shim object
- `pkg/dataplane/userspace_xdp_rust.go` — Go embed/load wrapper
- `pkg/dataplane/build-userspace-xdp.sh` — shim-only build script
  invoked by the retained `bash build-userspace-xdp.sh`
  `//go:generate` directive
- `test/xsk-repro/` — XSK lab tooling, unrelated to legacy forwarding
- `pkg/dataplane/userspace/` — userspace manager, map sync, shim
  tests
- `pkg/dataplane/runtime/` (and runtime-domain types in
  `pkg/dataplane/`) — runtime-facing contracts independent of BPF
  artifacts

This is a deletion-only refactor. No new functionality, no behavior
change, no architectural rearrangement (except the unavoidable
narrowing of `Manager.Load()` to a userspace-shim-only entry point —
see §4).

## 2. Honest scope / value framing

Deleting this much code is high-value but operationally low-risk if
the deletion lines up exactly with what the userspace dataplane no
longer touches. The risk surfaces are:

1. The `Manager` struct in `pkg/dataplane/loader.go` is still
   consumed by non-userspace operator surfaces (CLI, gRPC, REST,
   metrics, cluster, conntrack GC, daemon). The retirement-boundary
   canary's `legacyDataplaneImportAllowlist` enumerates 35+ files
   that still import `pkg/dataplane`. **Manager and DataPlane
   interface stay**; only the bpf2go-backed `loadAllObjects()`
   bootstrap graph goes.
2. `Manager.Load()` currently calls `loadAllObjects()`. After this PR
   it must either be deleted (preferred) or stubbed to return an
   error directing the operator to use `LoadUserspaceShim()`. The
   `TypeEBPF` enum value still exists in `pkg/dataplane/dataplane.go`
   and is still selectable via `system dataplane-type ebpf` at the
   config layer. After deletion, `TypeEBPF` is functionally a
   retirement-error token like `TypeDPDK` became in #1525/#1528.
3. The retirement-boundary canary (`legacy_bpf_manifest_canary_test.go`,
   `retirement_boundary_canary_test.go`) is pre-loaded with the exact
   deletion manifest at
   `docs/pr/1373-retire-ebpf-dataplane/source-removal-manifest-1476.md`.
   The deletion PR must satisfy all four `TestLegacyBPFRemovalManifest*`
   tests after the deletion (they police drift in both directions).
4. The `retainedShimBoundaryBuildTagAllowlist` map in
   `retirement_boundary_canary_test.go` is keyed by 14
   `pkg/dataplane/xpf{Tc,Xdp}*_x86_bpfel.go` paths that will no longer
   exist. Allowlist entries for deleted paths must be removed in
   lockstep with the path deletions or the canary fails.

## 3. What is already shipped

- **#1373 Phase 0**: deprecation notice in `CLAUDE.md`, userspace-dp
  declared primary target, gap-audit refresh.
- **#1374-#1381**: feature parity blockers all closed.
- **#1473**: userspace XDP shim split from `xdp_main_prog` fallback.
- **#1493**: `Manager.LoadUserspaceShim()` no longer calls
  `loadAllObjects()`; the userspace shim bootstrap path is independent.
- **#1494**: retainedShim boundary canaries pin which files cross the
  legacy → retained-shim boundary.
- **#1522**: legacy doc-drift sweep before final source removal.
- **#1525 + #1526 + #1527 + #1528**: DPDK retirement (parallel umbrella)
  serves as the precedent template — same shape, smaller scope.
- **#1451 sub-issues**: #1518 (cluster session-sync migration) closed.
  #1516 (grpcapi migration) and #1521 (userspace maps_sync decouple)
  in flight; both must close before Phase B begins.

## 4. Concrete design

### 4.1 The `Manager.Load()` and `TypeEBPF` decision

The deletion has to choose between three approaches for the lingering
`TypeEBPF` enum and the `Manager.Load()` legacy entrypoint.

**Option A — Mirror #1528 (Phase 1 reject preservation). RECOMMENDED.**

- Keep `dataplane.TypeEBPF = "ebpf"` as a token.
- Keep `config.dataplaneTypeEBPF = "ebpf"` and the
  `validDataplaneType("ebpf")` arm so old configs parse cleanly.
- Add a commit-time strict-validator
  (`validateDataplaneTypeStrictEBPF`) that rejects
  `set system dataplane-type ebpf` with a verbatim retirement message:
  `"the legacy eBPF dataplane backend has been retired; use 'set
  system dataplane-type userspace' (see #1373)"`.
- `NewDataPlane(TypeEBPF)` and `NewRuntimeDataPlane(TypeEBPF)` return
  a new sentinel `ErrEBPFBackendRetired`.
- **Keep `Manager.Load()` as a retirement stub** that returns
  `ErrEBPFBackendRetired` directly. v1 incorrectly proposed deleting
  it; the `DataPlane` interface at `pkg/dataplane/dataplane.go:209`
  requires `Load()` (compile-time asserted at line 29 via
  `var _ DataPlane = (*Manager)(nil)`), and `Manager.Start()` at
  `pkg/dataplane/apply.go:208` calls `m.Load()`. Both stay. The
  userspace path continues to use `LoadUserspaceShim()` (separate
  method, no contract impact). Operational result: any caller that
  reaches `Manager.Load()` after this PR gets the retirement
  sentinel, identical to the factory rejection.
- Add a `daemon_run.go` soft-fallback branch that catches
  `ErrEBPFBackendRetired` (parallel to the existing
  `ErrDPDKBackendRetired` branch at `pkg/daemon/daemon_run.go:247`).
- Add a stored-config rewrite at `Store.Load()` for `dataplane-type
  ebpf` → empty (defaults to userspace) — same pattern as #1528's
  §4.6 fix for the inherited bootstrap-loop bug. v2 ships this as
  net-new code in this PR (see §4.6); does not assume #1528 has
  shipped the helper.

**Option B — Hard removal of `TypeEBPF`.**

- Delete `TypeEBPF`, `dataplaneTypeEBPF`, the
  `validDataplaneType("ebpf")` arm, and all rejection plumbing.
- Operators with persisted `dataplane-type ebpf` get a "unknown
  dataplane-type" parser error at Load.
- Requires `validDataplaneType` test rewrites and operator-facing
  documentation changes.
- Net cost: more deletions, less operator-friendly, no observable
  benefit over Option A given the one-release-cycle migration
  window.

**Option C — Keep `Manager.Load()` as a no-op stub.**

- `Manager.Load()` returns `ErrEBPFBackendRetired` directly.
- `loadAllObjects()` is deleted with the bpf2go types.
- No deletion of `TypeEBPF`.
- Equivalent to Option A but skips the strict-validator and stored-
  config rewrite. Would leave stored-config rolling-upgrade
  blackout open. Rejected.

**Recommendation: Option A.** Rationale:

1. Operator-friendly retirement message at commit time, mirroring
   the DPDK retirement template (#1528) verbatim. Reviewers already
   audited that pattern.
2. Stored-config rolling-upgrade safety: a node booting with
   `dataplane-type ebpf` persisted (a likely state for production
   nodes mid-migration) must come up so the operator can fix the
   config from CLI. Without the rewrite-at-Load + soft-fallback,
   the daemon strands itself with no recourse.
3. `TypeEBPF` and `dataplaneTypeEBPF` deletion is deferred to the
   same "after release cycle" cleanup PR that will delete
   `TypeDPDK`. Coordinating both deletions in one future PR is
   cleaner than scattering the cleanup across two retirement
   chains.

Plan-review reviewers asked to validate this. If reviewers prefer
Option B, plan revises before any code moves.

### 4.2 Files deleted entirely

| Path | Why | Notes |
|---|---|---|
| `bpf/xdp/xdp_conntrack.c` | Legacy ingress conntrack | manifest §Delete |
| `bpf/xdp/xdp_cpumap.c` | Legacy cpumap entry | manifest §Delete |
| `bpf/xdp/xdp_forward.c` | Legacy forward stage | manifest §Delete |
| `bpf/xdp/xdp_main.c` | Legacy XDP main entry | manifest §Delete |
| `bpf/xdp/xdp_nat.c` | Legacy NAT stage | manifest §Delete |
| `bpf/xdp/xdp_nat64.c` | Legacy NAT64 stage | manifest §Delete |
| `bpf/xdp/xdp_policy.c` | Legacy policy stage | manifest §Delete |
| `bpf/xdp/xdp_screen.c` | Legacy screen/IDS | manifest §Delete |
| `bpf/xdp/xdp_zone.c` | Legacy zone + pre-routing | manifest §Delete |
| `bpf/xdp/README.md` | Legacy XDP tree readme | manifest §Delete |
| `bpf/tc/tc_conntrack.c` | Legacy egress conntrack | manifest §Delete |
| `bpf/tc/tc_forward.c` | Legacy egress forward | manifest §Delete |
| `bpf/tc/tc_main.c` | Legacy TC main entry | manifest §Delete |
| `bpf/tc/tc_nat.c` | Legacy egress NAT | manifest §Delete |
| `bpf/tc/tc_screen_egress.c` | Legacy egress screen | manifest §Delete |
| `bpf/tc/README.md` | Legacy TC tree readme | manifest §Delete |
| `bpf/README.md` | Legacy root BPF readme | manifest §Delete |
| `pkg/dataplane/xpftcconntrack_x86_bpfel.go` | Generated bpf2go | manifest §Delete |
| `pkg/dataplane/xpftcconntrack_x86_bpfel.o` | Embedded BPF object | manifest §Delete |
| `pkg/dataplane/xpftcforward_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpftcmain_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpftcnat_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpftcscreenegress_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpfxdpconntrack_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpfxdpcpumap_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpfxdpforward_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpfxdpmain_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpfxdpnat_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpfxdpnat64_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpfxdppolicy_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpfxdpscreen_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/xpfxdpzone_x86_bpfel.{go,o}` | Generated | manifest §Delete |
| `pkg/dataplane/loader_ebpf.go` | 957 LOC legacy loader graph; depends entirely on deleted bpf2go types | every function references `loadXpfXdp*`/`loadXpfTc*` or `*Objects` structs |
| `pkg/dataplane/loader_stub.go` | `//go:build ignore` placeholder that documents a no-generated-files build no longer relevant | not in any active build |

### 4.3 Files edited

| Path | Edit |
|---|---|
| `pkg/dataplane/loader.go` | Delete the 14 legacy `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ...` directives (lines 31, 33-45). KEEP the `//go:generate bash build-userspace-xdp.sh` directive (line 32). **Keep `Manager.Load()` (lines 112-126) and rewrite its body to `return ErrEBPFBackendRetired`** — both the `DataPlane` interface assertion at `dataplane.go:29` and `Manager.Start()` at `apply.go:208` depend on the method existing. Adjust file header comment to reflect retained shim path only. |
| `pkg/dataplane/dataplane.go` | Add `ErrEBPFBackendRetired` sentinel mirroring `ErrDPDKBackendRetired`. In `NewDataPlane` (line ~152), change the `case TypeEBPF: return New(), nil` arm to `case TypeEBPF: return nil, ErrEBPFBackendRetired`. Same in `NewRuntimeDataPlane` (line ~176). Keep `TypeEBPF` const. |
| `pkg/config/compiler.go` | Add `validateDataplaneTypeStrictEBPF` mirroring `validateDataplaneTypeStrict` (DPDK), wired into the existing strict-validator stack at line ~241. Add `ErrEBPFDataplaneRetired` sentinel. Keep `dataplaneTypeEBPF` const and `validDataplaneType` arm. Verbatim retirement message: `"the legacy eBPF dataplane backend has been retired; use 'set system dataplane-type userspace' (see #1373)"`. |
| `pkg/config/compiler.go:437` | The `if cfg.System.DataplaneType == dataplaneTypeEBPF { ... }` block. Audit what it does (BPF-specific compile step?) and either delete it (if it produces BPF-only output) or guard with retirement reject. **Plan reviewers asked to validate.** |
| `pkg/config/compiler_system.go:243` | The `case dataplaneTypeEBPF:` arm in the `dataplane` switch. Delete the case body if it produces BPF-only state; fall through to retirement reject. |
| `pkg/configstore/store.go` | Add `rewriteRetiredDataplaneType` invocation at `Load()` before `compileTree` for `dataplane-type ebpf` (mirror #1528's §4.6 fix; the helper from #1528 will already handle `dpdk` — extend it or add a parallel helper for `ebpf`). |
| `pkg/configstore/dataplane_retire.go` (or extend if it exists from #1528) | Helper that walks the persisted AST tree and rewrites both `dataplane-type dpdk` and `dataplane-type ebpf` to empty, with `slog.Warn` for each rewrite. |
| `pkg/daemon/daemon_run.go:247` | Extend the existing `errors.Is(err, dataplane.ErrDPDKBackendRetired)` soft-fallback to also catch `ErrEBPFBackendRetired`. |
| `Makefile` | Delete `generate-legacy-bpf` target (lines 27-29). Remove `generate-legacy-bpf` from `.PHONY:` (line 16). Update the header comment for `generate:` target (lines 20-23) so it no longer references "legacy XDP/TC bpf2go outputs". **Narrow the `clean:` recipe globs (lines 66-67)** from `pkg/dataplane/*_bpfel.{go,o}` + `pkg/dataplane/*_bpfeb.{go,o}` to `pkg/dataplane/xpf*_bpfel.{go,o}` + `pkg/dataplane/xpf*_bpfeb.{go,o}` so `make clean` cannot delete the retained `pkg/dataplane/userspace_xdp_bpfel.o` (embedded by `userspace_xdp_rust.go:11`). The narrowed glob is harmless after deletion (no `xpf*_bpfel.*` files remain) but stays in tree as a defence-in-depth pattern. |
| `pkg/dataplane/retirement_boundary_canary_test.go` | Delete the `retainedShimBoundaryBuildTagAllowlist` entries for the 14 deleted bpf2go `_x86_bpfel.go` paths (lines pinning `//go:build 386 \|\| amd64`). **Also delete the `pkg/dataplane/loader_stub.go` entry at line 106** — the file is removed by this PR (Codex F5). **Also delete the docs-pinned token block at line 1823** that hard-requires `loader_stub.go` and the legacy build-tag text (Codex F5). Other entries (for `userspace_xdp_rust.go`, etc.) stay. Update or delete `userspaceXDPEntryProgForCanary = "xdp_userspace_prog"` references if they only test the deleted entry-program path; check carefully. |
| `pkg/dataplane/legacy_bpf_manifest_canary_test.go` | This canary is the deletion-readiness gate. It must continue to pass AFTER deletion. Verify all 4 `TestLegacyBPFRemovalManifest*` tests pass on a post-delete tree by running them locally before commit. May need adjustments if a manifest entry no longer matches a tracked file (e.g. if a retained header gets moved). |
| `pkg/dataplane/userspace_shim_loader_test.go` | Audit. If it tests a code path that uses deleted legacy types, simplify. |
| `pkg/dataplane/watchdog_test.go` | Audit. The watchdog test was historically wired into the legacy BPF map; verify it still passes with userspace-only paths or rewrite. |
| `pkg/dataplane/apply_test.go`, `compiler_test.go`, `constants_test.go`, `default_test.go`, `nptv6_test.go`, `persistent_nat_test.go`, `session_store_test.go` | Audit each. Tests exercising legacy BPF maps directly need rewriting. Tests on shared structs (constants, NAT, session domain) stay. |
| `pkg/daemon/dataplane_boot_test.go` | **Rewrite `TestBuildRuntimeDataPlaneEBPFRoutesToLegacyManager` (lines 48-61)** to `TestBuildRuntimeDataPlaneEBPFReturnsRetired` asserting `errors.Is(err, dataplane.ErrEBPFBackendRetired)` and `dp == nil`. Pattern identical to `TestBuildRuntimeDataPlaneDPDKReturnsRetired` at lines 67-80. AGY r1 + Codex F8 both required this. |
| `pkg/daemon/tunnel_anchor_test.go`, `pkg/daemon/vip_readiness_test.go`, `pkg/daemon/per_rg_test.go` | AGY r1 empirically verified: each only sets `cfg.System.DataplaneType = dataplane.TypeEBPF` as a non-userspace token for Go-level struct-logic branches; none call `NewRuntimeDataPlane` or boot a `Manager`. Under Option A, `TypeEBPF` stays exported, so these tests still compile and execute the same branch. **Plan: leave them unchanged.** If implementation reveals any test now hits a retirement-rejected path, plan v3 rewrites it to a parameterized non-userspace token (e.g. a fixed test-only sentinel). |
| `docs/development-workflow.md` line 24 | Remove the "`make generate-legacy-bpf` runs the legacy XDP/TC bpf2go directives" line. |
| `docs/refactoring-audit.md` lines 20, 83 | Remove references to `bpf/xdp/*.c`, `bpf/tc/*.c` as live source paths. Trim or move to historical section. |
| `docs/userspace-master-merge-20260310.md` lines 40-46 | Historical doc; convert to past-tense or move to `docs/archived/`. |
| `docs/userspace-native-gre-plan.md` line 116, `docs/userspace-icmp-te-debugging.md` line 104 | Rewrite to reference userspace-dp/userspace-xdp source paths or mark as historical context. |
| `docs/active-active-new-connections.md` lines 481-482, `docs/fabric-cross-chassis-fwd.md` lines 46, 82 | Historical narrative of legacy XDP design. Re-frame as "legacy XDP design (deleted in #1476)" or move to archived. |
| `docs/services-application-identification.md` line 51, `docs/userspace-performance-plan.md` line 258 | Rewrite to reference userspace-dp equivalents or mark historical. |
| `docs/bugs.md` lines referencing `bpf/xdp/*.c` or `bpf/tc/*.c` | These are historical bug records pointing at the legacy source. Add a note "(source deleted in #1476)" at the top of the bugs.md file or per-entry; do NOT delete the records — they are historical evidence. |
| `CLAUDE.md` (project) | "BPF Pipeline (14 programs, tail calls)" section — rewrite to past tense and point at userspace-dp/userspace-xdp as the sole source-of-truth. Remove the "bpf/xdp/*.c" and "bpf/tc/*.c" rows from the Code Layout table. |
| `pkg/dataplane/README.md` | Drop mentions of legacy XDP/TC bpf2go generation as a build step. Keep references to retained shim. |
| `docs/pr/1373-retire-ebpf-dataplane/README.md` | Update the "Current Removal Trackers" table — mark #1476 status as in-flight then merged. |
| `docs/pr/1373-retire-ebpf-dataplane/source-removal-manifest-1476.md` | After deletion, prune the `### Generated Legacy bpf2go Artifacts` list of paths that no longer exist in git (the canary test verifies this). Update the "Proof Required" section to reference this PR's evidence. |

### 4.4 Canary test surgery (highest-risk edit)

The two canary files in `pkg/dataplane/` are the deletion gate:

1. **`legacy_bpf_manifest_canary_test.go`** — five tests (Codex F6
   corrected v1's count of four; tests live at lines 28, 71, 108,
   133, 161 of the file):
   - `TestLegacyBPFRemovalManifestCoversTrackedGeneratedArtifacts`:
     verifies every tracked `pkg/dataplane/*_bpfel.{go,o}` is either
     in the manifest's `## Delete Manifest` section OR listed as a
     retained shim path. After deletion, no legacy bpf2go files
     remain tracked; the manifest's delete list still references
     them by name (matches by markdown code-span scan). The test
     requires that the listed paths actually exist as tracked files
     — i.e., the manifest entry MUST be deleted in lockstep with the
     git-tracked file. **Impl detail: delete the path from manifest
     AND `git rm` the file in the same commit.**
   - `TestLegacyBPFRemovalManifestCoversTrackedBPFSourceTree`: every
     tracked `bpf/**` file must be in either the delete or retain
     section, exactly once. After deletion, only `bpf/headers/*.h`
     remain tracked; they are in the retain section. Pass after
     deletion as long as the delete entries for `bpf/xdp/*.c` and
     `bpf/tc/*.c` are removed from the manifest.
   - `TestLegacyBPFRemovalManifestEntriesResolveToTrackedFiles`:
     manifest entries must reference real tracked files. After
     deletion, deleted entries must be removed from the manifest in
     the same PR.
   - `TestLegacyBPFRemovalManifestKeepsRetainedShimOutOfDeleteScope`:
     verifies the retained shim list never appears in the delete
     section. Unchanged by this PR (retained list stays exactly as-is).
   - `TestLegacyBPFRemovalManifestDocumentsDependencyOrder`: verifies
     the dependency-order section names #1494, #1493, #1451, #1476,
     #1477. Unchanged.

2. **`retirement_boundary_canary_test.go`** —
   - `legacyDataplaneImportAllowlist` (lines 22-58): 35+ entries
     enumerating files that import `pkg/dataplane`. The deletion PR
     leaves the allowlist alone — those files still import the
     remaining `pkg/dataplane` Manager/types after this PR (their
     migration is #1451's job, complete via #1516+#1521 before Phase B
     starts).
   - `retainedShimBoundaryBuildTagAllowlist` (lines ~74-106): 14
     entries for `pkg/dataplane/xpf{Xdp,Tc}*_x86_bpfel.go` build-tag
     allowance PLUS one entry for `pkg/dataplane/loader_stub.go` at
     line 106. ALL 14 bpf2go entries AND the `loader_stub.go` entry
     delete in lockstep with the deleted files (Codex F5).
   - Docs-pinned token block at line 1823 referencing
     `loader_stub.go` and the legacy `//go:build ignore` text:
     **delete** in lockstep with `loader_stub.go` removal (Codex F5).
   - `userspaceXDPEntryProgForCanary = "xdp_userspace_prog"` — verify
     this constant is still meaningful after deletion. The entry
     program name refers to the retained Rust shim, not legacy XDP
     entry — confirm at impl time by reading the Rust shim source.

### 4.5 Test plan

**Pre-merge gates (Go-side, run before push):**

```bash
# 1. Generate runs only the retained shim
make generate 2>&1 | tee /tmp/generate.log
grep -E "bpf2go.*xpf(Xdp|Tc)" /tmp/generate.log && exit 1  # MUST be empty

# 2. Re-verify only one go:generate directive remains
grep -n "//go:generate" pkg/dataplane/loader.go
# Expected: exactly one line: //go:generate bash build-userspace-xdp.sh

# 3. Full build
GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go build ./... 2>&1 | tail -5

# 4. Full test suite
GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./... 2>&1 \
  | grep -v "^ok\|^?" | tail -30

# 5. Retirement canary tests (5× to flake-check)
for i in 1 2 3 4 5; do
  GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm \
    go test -run "Test.*Manifest|Test.*Boundary|Test.*UserspaceXDP" \
    ./pkg/dataplane/ -count=1 2>&1 | grep -E "PASS|FAIL|ok " | tail
done

# 6. Generate manifest matches reality
go generate -n -run '^//go:generate bash build-userspace-xdp\.sh$' \
  ./pkg/dataplane 2>&1
# Expected: prints the single bash command, nothing else

# 7. Grep proof — no production reference to deleted symbols
grep -rn "xpfXdp\|xpfTc\|loadXpfXdp\|loadXpfTc\|loadAllObjects" \
  --include="*.go" pkg/ cmd/ 2>&1
# Expected: zero hits (or only in archived docs, NOT in *.go)

# 8. Grep proof — no remaining bpf/xdp or bpf/tc references
grep -rn "bpf/xdp\|bpf/tc" --include="*.go" --include="*.sh" \
  --include="Makefile" pkg/ cmd/ Makefile 2>&1
# Expected: zero hits (except bpf/headers, which stays)

# 9. Build the retained shim from scratch
make build-userspace-xdp 2>&1 | tail -5

# 10. Make build (no -tags ebpf or similar)
make build 2>&1 | tail -5
make build-userspace-dp 2>&1 | tail -5
```

**Per-iteration 5× flake-check on retirement-reject tests:**

```bash
for i in 1 2 3 4 5; do
  GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm \
    go test -run TestDataplaneTypeEBPFRejectedAtCommit \
    ./pkg/config/ -count=1 2>&1 | grep -E "PASS|FAIL|ok " | tail -1
done
for i in 1 2 3 4 5; do
  GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm \
    go test -run TestLoad_RewritesPersistedEBPFDataplaneType \
    ./pkg/configstore/ -count=1 2>&1 | grep -E "PASS|FAIL|ok " | tail -1
done
```

**Smoke matrix (delegated to singleton smoke-runner via the
`<!-- AWAITING-SMOKE -->` marker per `feedback_smoke_serialized_single_agent`):**

- Pass A (CoS-off, best-effort): v4 + v6 × push + reverse + 12-stream `-R`
- Pass B (CoS-on): per-class 5201-5206 v4 + v6 × push + reverse

Smoke gate references `docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md`.

### 4.6 Stored-config-tolerant Load path (mirror of #1528 §4.6)

The same bootstrap-loop bug class applies to `dataplane-type ebpf`:

1. Persisted active config has `system dataplane-type ebpf` from
   before this PR landed.
2. On boot, `Store.Load()` → `compileTree` → `compileExpanded` →
   `validateDataplaneTypeStrictEBPF` returns `ErrEBPFDataplaneRetired`.
3. Error is swallowed at `daemon_run.go:87` (existing warn-and-continue).
4. `ActiveConfig()` returns nil; daemon bootstraps from text-config
   file or starts with empty config — operational blackout if the
   text config also says `ebpf`.
5. The factory-call soft-fallback at `daemon_run.go:247` is
   unreachable for the stored-config path.

**Fix** (Option A2-fix-Rewrite from #1528): at `Store.Load()`,
before `compileTree`, walk the active tree and rewrite any
`dataplane-type ebpf` (and `dataplane-type dpdk`, if not already
handled by #1528) to empty, with a loud `slog.Warn`. The candidate
config inherits the rewrite; a subsequent `commit` persists the
cleanup.

If #1528's `rewriteRetiredDataplaneType` helper is already in tree,
extend it to handle `ebpf` as well. Otherwise add a parallel helper
or a shared one in `pkg/configstore/dataplane_retire.go`.

The HA-sync edge case noted in #1528 §4.6 Q11 applies symmetrically:
two HA nodes booting with `ebpf` persisted both rewrite locally;
if one node is un-upgraded and re-pushes the legacy config,
the upgraded peer re-rewrites on each push and logs at WARN. Same
"loud-log, defer deeper handling" stance.

### 4.7 Public API preservation

Option A path:

| Symbol | Status |
|---|---|
| `dataplane.TypeEBPF` (const) | **Preserved** as retirement-error token |
| `dataplane.ErrEBPFBackendRetired` (sentinel, new) | **Added** |
| `dataplane.NewDataPlane(TypeEBPF)` returns `ErrEBPFBackendRetired` | **Changed** from `New(), nil` |
| `dataplane.NewRuntimeDataPlane(TypeEBPF)` returns `ErrEBPFBackendRetired` | **Changed** |
| `dataplane.New()` (the `Manager` constructor) | **Preserved** — many callers still need it for accessors, even if `Load()` no longer attaches BPF programs |
| `Manager.Load()` | **Deleted** under Option A. Existing callers either migrate to `LoadUserspaceShim()` or no longer call this method (all current production callers go through `NewRuntimeDataPlane` → userspace) |
| `Manager.LoadUserspaceShim()` | **Preserved** unchanged |
| `Manager.IsLoaded()`, `Manager.Close()`, `Manager.Teardown()` | **Preserved** |
| `Manager.AttachXDP/DetachXDP/AttachTC/DetachTC` | **Preserved** — both userspace path (XDP) and operator surfaces still call these accessors |
| `Manager.Map(name)`, `Manager.Program(name)` | **Preserved** — operator surfaces still query |
| `Manager.loadAllObjects()` (internal) | **Deleted** with `loader_ebpf.go` |
| `Manager.loadUserspaceShimObjects()` and helpers | **Moved out of `loader_ebpf.go`** into `loader.go` or a new `loader_userspace_shim.go` file. Carry the function bodies forward, drop only the legacy graph |
| `Manager.loadCPUMapPrograms` | **Deleted** with `loader_ebpf.go` (legacy cpumap dispatch) |
| `config.dataplaneTypeEBPF` (const) | **Preserved** (commit-validator key) |
| `config.ErrEBPFDataplaneRetired` (sentinel, new) | **Added** |
| `config.validateDataplaneTypeStrictEBPF()` (new) | **Added** |
| `config.validDataplaneType("ebpf")` returns true | **Preserved** |

### 4.8 Moving `loadUserspaceShimObjects` out of `loader_ebpf.go`

`loader_ebpf.go` is being deleted, but it contains
`loadUserspaceShimObjects()` and `loadUserspaceShimObjectsOnce()`
that are part of the RETAINED shim path. These functions must be
moved to a kept file (e.g., `pkg/dataplane/loader_userspace_shim.go`
or appended to `loader.go`) before `loader_ebpf.go` is deleted.

**Full retained-graph enumeration (AGY r1 verified, Codex F3
required the explicit list):**

- `loadUserspaceShimObjects(...)` (loader_ebpf.go:478)
- `loadUserspaceShimObjectsOnce(...)` (loader_ebpf.go:489) —
  including the Rust shim spec load, the drift-guard for
  `MAX_INTERFACES`, the `userspace_bindings` cap check, and the
  `userspace_xsk_map` / xsk socket setup
- `validateUserspaceShimSpec(...)` (loader_ebpf.go:558)
- `userspacePinnedShimMaps()` (loader_ebpf.go:599)
- `userspaceRequiredShimPins()` (loader_ebpf.go:618)
- `loadUserspaceShimSharedMaps(...)` (loader_ebpf.go:642)
- `loadOrCreatePinnedShimMap(...)` (loader_ebpf.go:655)
- `loadOrCreatePinnedShimMapWith(...)` (loader_ebpf.go:661)
- `userspaceShimMapLoader` type (loader_ebpf.go:659)
- `closeUniqueMaps(...)` (loader_ebpf.go:681)
- `userspaceShimSharedMapSpecs()` (loader_ebpf.go:695)
- `hashMapSpec(...)` (loader_ebpf.go:723)
- `perCPUHashMapSpec(...)` (loader_ebpf.go:734)
- `arrayMapSpec(...)` (loader_ebpf.go:745)
- `perCPUArrayMapSpec(...)` (loader_ebpf.go:755)
- `sizeOf[T any]()` (loader_ebpf.go:765)
- `ensureUserspaceMapPinned(...)` (loader_ebpf.go:770)
- `pinnedMaps` map (loader_ebpf.go:~30) — narrowed to retained
  entries only. See §5 invariant 7 — `nat_port_counters` IS
  retained shim state; only `xdp_progs`, `tc_progs`, and
  `policer_states` drop.
- `bpfPinPath` constant and the shim-relevant constants from
  loader_ebpf.go:18-22 (`userspaceShimGenerateRemediation`,
  `userspaceBindingsMapName`, `userspaceIngressIfacesMapName`,
  `userspaceShimCompatibilityDNATName`)

**Verified clean**: none of the retained helpers transitively
references any `xpfXdp*` or `xpfTc*` type. The legacy graph
(`loadAllObjects` at loader_ebpf.go:72, `loadCPUMapPrograms` at
loader_ebpf.go:793, and the per-stage program loaders) is
self-contained and disposable.

Audit of `loader_ebpf.go` content to be DELETED:

- `loadAllObjects()` and the full legacy XDP/TC dispatch graph
- `loadCPUMapPrograms`
- All references to `xpf{Xdp,Tc}*Objects` types

This split is mechanical — copy the retained functions into a new
file (suggested: `pkg/dataplane/loader_userspace_shim.go`), delete
`loader_ebpf.go`, then verify `go build ./...`. The new file gets a
header comment explaining its purpose ("retained Rust AF_XDP shim
loader; legacy bpf2go graph removed in #1476").

**Manager.Load() retention (v2)**: `Manager.Load()` itself stays in
`pkg/dataplane/loader.go` with its body rewritten to
`return ErrEBPFBackendRetired`. The interface contract requires the
method exists; the body is a sentinel return. `Manager.LoadUserspaceShim()`
remains the userspace entry point.

## 5. Hidden invariants the change must preserve

1. **Userspace startup parity.** `Manager.LoadUserspaceShim()` must
   behave bit-identically after the split. Existing tests in
   `pkg/dataplane/userspace_shim_loader_test.go` and
   `pkg/dataplane/userspace/shim_loader_boundary_test.go` are the
   contract.

2. **MAX_INTERFACES drift guard.** `loadUserspaceShimObjectsOnce`
   compares the embedded shim's `BINDING_ARRAY_MAX_ENTRIES` against
   the Go-side `MaxInterfaces * BindingQueuesPerIface`. The build
   script threads `MAX_INTERFACES` from `bpf/headers/xpf_common.h`
   through an env var. The drift guard fires at runtime if they
   disagree. **Header retention is non-negotiable** for this guard.

3. **Stored-config rolling upgrade.** A node booting with
   `dataplane-type ebpf` persisted must come up to userspace
   default. §4.6 covers this with a Load-time rewrite.

4. **`load merge` / `load override` parse path.** The parser must
   still accept `system dataplane-type ebpf` as a valid leaf;
   `validDataplaneType("ebpf")` returning true preserves this. The
   commit validator rejects.

5. **Canary coverage of #1451.** Deleting bpf2go files does NOT
   weaken `legacyDataplaneImportAllowlist` — the allowlist polices
   importers of `pkg/dataplane`, not importers of the deleted
   bpf2go types. The 35+ allowlist entries stay.

6. **Side-effect ordering at compile.**
   `validateDataplaneTypeStrictEBPF` and `validateDataplaneTypeStrict`
   (DPDK) must both fire before any compile step touches
   dataplane-specific fields. Order verified in `compileExpanded`.

7. **Map-pinning expectations (v2 corrected).** Codex F4 + AGY r1
   both caught v1's misclassification of `nat_port_counters`. The
   retained `pinnedMaps` set after this PR is:
   - **Retained as userspace-shared**: `sessions`, `sessions_v6`,
     `dnat_table`, `dnat_table_v6`, `nat64_state`,
     `nat_port_counters`. The last is created by
     `userspaceShimSharedMapSpecs()` at `loader_ebpf.go:712`,
     consumed by `Manager.ReadNATPortCounter()` at `maps.go:1569`
     and `SeedNATPortCounters()` at `maps.go:1589`, and pinned by
     the boundary canary at
     `pkg/dataplane/retirement_boundary_canary_test.go:383`.
   - **Drop as legacy-only**: `xdp_progs`, `tc_progs`,
     `policer_states`. After deletion, these kernel pins no longer
     exist because no legacy program loads them.
     `Manager.LoadUserspaceShim()` already has cleanup logic
     (`cleanupUserspaceShimLegacyOnlyMapPins` at `loader.go:240`)
     that removes the pins on startup if they survive from a
     pre-upgrade run. Verify this cleanup remains correct after
     the v2 narrowing.

8. **#1494 boundary canaries.** `pkg/dataplane/userspace/`
   shim_loader_boundary tests verify the shim does not regrow
   legacy fallbacks. These pass unchanged because the legacy code
   they pinned is gone, leaving the boundary trivially correct.

9. **xpfd binary size.** Expected ~3-5 MB reduction (depending on
   strip level) because 14 embedded `.o` byte arrays disappear from
   the Go binary. Smoke pass A must confirm the binary still boots
   and attaches the retained shim.

## 6. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | All retained paths bit-identical; deleted code has zero production callers after #1451 closes |
| Loader refactor (split) | MED | `loadUserspaceShimObjects` move must be byte-for-byte equivalent. Easy to verify with `gofmt` and side-by-side diff |
| Build-system breakage | MED | `Makefile generate-legacy-bpf` deletion must be atomic with `.PHONY:` line edit. Mismatched edits produce a make warning. Verify `make generate && make build` clean |
| Test breakage | MED | 4 retirement-manifest canaries + retirement-boundary canary + every test that touches deleted bpf2go types. Audit list in §4.3 |
| Canary surgery | MED | `retainedShimBoundaryBuildTagAllowlist` has 14 keys; missing one fails the canary |
| Architectural mismatch | LOW | Mechanical deletion only; no architectural premise to fail |
| Stored-config rolling upgrade | LOW under Option A; MED under Option B | See §4.6 |
| Documentation drift | LOW | #1522 already swept most active docs; this PR catches the remainder + canary text pins |
| Smoke regression | LOW | Userspace path untouched; smoke validates retained shim still loads. If smoke fails, deletion missed a userspace-shared dependency (most likely a missing function move from `loader_ebpf.go`) |

## 7. Out of scope (explicitly)

1. **Deleting `TypeEBPF`, `ErrEBPFBackendRetired`, the strict
   validator, and the parser's `validDataplaneType("ebpf")` arm.**
   Deferred to the same future cleanup PR that deletes `TypeDPDK`.
2. **Migrating `legacyDataplaneImportAllowlist` entries off the
   `pkg/dataplane` import.** That is #1451's job. The list stays
   intact through this PR. Allowlist entries get removed in the PRs
   that migrate the underlying files.
3. **Deleting `bpf/headers/*.h`.** Future PR after the userspace
   shim's Rust build internalizes `MAX_INTERFACES` and the
   userspace-dp parity tests adopt a userspace-owned schema source.
4. **CHANGELOG / release-note entry.** Project does not maintain a
   CHANGELOG file at the repo root; release notes are PR descriptions.
5. **`docs/archived/`** — historical docs are not edited; only
   `docs/*.md` active workflow refs are rewritten.
6. **#1539 AST leakage canary (PR #1553).** Separate in-flight PR
   handling a different schema field. Coordinates by rebase.
7. **Performance measurement.** Deletion-only refactor; no
   perf claim. Binary-size reduction is the only quantitative
   observation, and a casual `ls -la cmd/xpfd/xpfd` before/after
   suffices.

## 8. Open questions for adversarial plan review

These are real PLAN-KILL / PLAN-NEEDS-MAJOR surfaces. Each is asked
because a "wrong" answer is sufficient to PLAN-KILL the plan or
demand a major revision.

1. **Option A vs Option B vs Option C (`Manager.Load()` and
   `TypeEBPF` decision).** Plan chooses Option A. Reviewers asked
   to validate, especially the stored-config rolling-upgrade
   reasoning. PLAN-KILL if a reviewer can show Option A leaves a
   boot blackout.

2. **`Manager.Load()` deletion safety.** Currently `Manager.Load()`
   is the entry point for the legacy `dataplane-type ebpf` mode
   (and is consumed in tests via `dataplane.TypeEBPF`). After this
   PR, `NewDataPlane(TypeEBPF)` returns `ErrEBPFBackendRetired`
   directly, so `Manager.Load()` becomes unreachable from production.
   But test files (`tunnel_anchor_test.go`, `vip_readiness_test.go`,
   `per_rg_test.go`, `dataplane_boot_test.go`) construct a Manager
   directly and may call `.Load()`. Plan migrates those tests to
   `LoadUserspaceShim()` OR rewrites them to use a different setup
   path. Reviewer to verify the test-side migration is exhaustive.

3. **`loadUserspaceShimObjects` extraction correctness.** The
   plan splits `loader_ebpf.go` into "retained shim load" + "legacy
   graph load (deleted)". The retained side must come out without
   leaking unrelated helpers. Reviewer to confirm by reading the
   pre-deletion `loader_ebpf.go` end-to-end and listing exactly
   which functions cross the boundary. Plan-time list:
   `loadUserspaceShimObjects`, `loadUserspaceShimObjectsOnce`,
   `userspaceShimMapLoader`, `pinnedMaps` (narrowed),
   `bpfPinPath` const. Reviewer to confirm nothing else is needed
   by the retained path.

4. **`pkg/dataplane/legacy_bpf_manifest_canary_test.go` post-delete
   behavior.** The test scans `pkg/dataplane/*_bpfel.{go,o}` git-
   tracked files and demands each is in the manifest's delete
   section. After deletion, no such tracked files remain (except
   `userspace_xdp_bpfel.o`). The manifest's `## Delete Manifest`
   still lists the deleted paths by name. The third test
   (`TestLegacyBPFRemovalManifestEntriesResolveToTrackedFiles`)
   fails if the manifest references paths not tracked at HEAD.
   **So the manifest's path list MUST be pruned of deleted paths
   in lockstep with the file deletions in the same commit.**
   Reviewer to verify the commit ordering plan is correct.

5. **`pkg/config/compiler.go:437` block deletion safety.** The
   `if cfg.System.DataplaneType == dataplaneTypeEBPF { ... }`
   block does something BPF-specific. Plan §4.3 says "audit and
   delete if it produces BPF-only output". Reviewer to read the
   block, confirm it produces no userspace-relevant state, and
   confirm deletion is safe. PLAN-NEEDS-MAJOR if it produces
   shared state.

6. **`compiler_system.go:243` arm deletion.** Same question for
   the `case dataplaneTypeEBPF:` arm in the dataplane switch. Plan
   §4.3 deletes the case body. Reviewer to confirm.

7. **Test migration: `tunnel_anchor_test.go`, `vip_readiness_test.go`,
   `per_rg_test.go`, `dataplane_boot_test.go`.** All four set
   `cfg.System.DataplaneType = dataplane.TypeEBPF` to exercise a
   legacy path. After this PR `TypeEBPF` returns a retirement
   error from the factories. Plan must rewrite these tests. Choice
   per file:
   - Rewrite to use `TypeUserspace` (default) — most likely correct
     for behavior tests that don't care which dataplane.
   - Rewrite to assert the retirement-rejection behavior — only if
     the test's intent was specifically "the legacy path works".
   Reviewer to validate the per-test choice. PLAN-NEEDS-MAJOR if
   a test's intent cannot be preserved under either option.

8. **Map-pin cleanup ordering.** After deletion, kernel-level pins
   for `xdp_progs`, `tc_progs`, `policer_states`, `nat_port_counters`
   remain on disk on existing nodes from the prior boot. The
   userspace shim's `cleanupUserspaceShimLegacyOnlyMapPins`
   already removes them on startup. Verify this still works after
   the source deletion (since the cleanup function uses string
   names, not bpf2go types, it should be unaffected).

9. **`pkg/dataplane/dpdk/manager.go` dependency.** The
   retirement-boundary canary's `dpdkEBPFImportAllowlist` (the
   parallel allowlist for DPDK-on-EBPF-types) has one entry for
   `pkg/dataplane/dpdk/manager.go`. Is this file still in tree at
   the time of #1476's merge? If #1528 has merged, the file is
   gone and the allowlist entry is stale (and the canary fails on
   load). #1528 plan says it deletes this file. Verify ordering —
   either #1528 lands first (this PR's plan is fine) or this PR
   lands first (this PR must also prune the
   `dpdkEBPFImportAllowlist`). **Plan reviewers to check current
   #1528 PR state at impl time.**

10. **#1539 AST leakage canary (PR #1553).** PR #1553 adds a
    canary for DPDK-schema leakage. After #1528 lands, the canary
    is dead. #1476 does not touch the same code, but might
    coincidentally land before/after #1553 — verify no merge
    conflict on `pkg/config/types.go` (where DPDK fields live).
    Plan reviewer to confirm.

11. **HA-sync interaction for stored-config rewrite.** If only one
    HA node has this PR's Load-time rewrite, the un-upgraded peer
    will keep re-pushing `dataplane-type ebpf`. The upgraded peer
    re-rewrites on each push and logs at WARN. Same
    "loud-log-defer" stance as #1528. Reviewer asked to confirm
    this is acceptable for a one-release-cycle migration.

12. **`Makefile clean` target safety (v2 resolved).** Codex F2 +
    AGY CRITICAL both flagged that `Makefile:66-67` greedy globs
    `rm -f pkg/dataplane/*_bpfel.{go,o}` + `*_bpfeb.{go,o}` would
    delete the retained `pkg/dataplane/userspace_xdp_bpfel.o`. v2
    narrows the globs to `pkg/dataplane/xpf*_bpfel.{go,o}` +
    `pkg/dataplane/xpf*_bpfeb.{go,o}` (§4.3) so the
    `userspace_xdp_bpfel.o` (which does not start with `xpf`) is
    protected by name. The narrowed pattern is harmless post-
    deletion (no `xpf*_bpfel.*` tracked files remain) but stays as
    defence-in-depth against a future re-introduction.

## 9. Reviewer dispatch contract

This plan dispatches Codex + Antigravity in parallel using the
canonical companion CLIs. Both reviewers receive the same hostile
prompt with explicit verdict options (PLAN-READY / PLAN-NEEDS-MAJOR
/ PLAN-NEEDS-MINOR / PLAN-KILL).

Verdict aggregation:

- **Both PLAN-KILL** → close issue with rationale; no PR.
- **One PLAN-KILL, one not** → iterate v2 addressing the KILL
  findings; converge or PLAN-KILL at v3.
- **Both PLAN-NEEDS-MAJOR / NEEDS-MINOR** → iterate plan.
- **Both PLAN-READY** → Phase A complete; proceed to Phase B once
  #1451 closes (#1516 + #1521 merged).

Codex sandbox failures retry up to 3× per
`feedback_codex_infra_must_retry`. Antigravity hallucinations
cross-checked against actual source per
`feedback_agy_verify_showstoppers`.

## 10. Dependency order and blocker state

Per the retirement manifest's `## Dependency Order`:

1. #1494 (merged): retained shim boundary canaries.
2. #1493 (merged): userspace shim loader split from `loadAllObjects()`.
3. #1451 (in flight): #1518 closed; #1516 + #1521 still open.
4. **#1476 (this PR)**: blocked on #1451 closing.
5. #1477 (queued): final userspace-only validation artifacts.

Phase B (implementation) waits for `gh issue view 1451 --json
state` to return `CLOSED`. Polling pattern uses `ScheduleWakeup` at
1500s intervals, mirroring the task spec.

## 11. Manifest discipline

The retirement manifest at
`docs/pr/1373-retire-ebpf-dataplane/source-removal-manifest-1476.md`
is the SOURCE OF TRUTH for deletion vs retention. Phase B's first
implementation step is to verify the manifest's delete list matches
the actual tracked file set on master; if drift is detected, the
manifest is updated FIRST in a separate commit, then deletions
proceed. The four `TestLegacyBPFRemovalManifest*` canaries enforce
this discipline.

After deletion, the manifest's `## Delete Manifest` section gets
pruned of paths that no longer exist (since
`TestLegacyBPFRemovalManifestEntriesResolveToTrackedFiles` fails
otherwise). The `## Retain Manifest` section is unchanged.

---

**End of plan v1.** Awaiting Codex + AGY plan-review verdicts.
