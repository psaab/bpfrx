# #1540 — Modularize REST API handlers and Prometheus collectors

**Status:** v2 PLAN-READY — Codex + AGY both returned PLAN-NEEDS-MINOR on v1; all required minors folded into implementation

## Plan-review log

- **v1 (commit `5ed3fdd3`)**: dispatched to Codex and AGY for hostile plan review.
- **AGY review** (job `review-mpmuqzeo-dgl1z7`): **PLAN-NEEDS-MINOR**.
  Required adjustments:
  1. `config_handlers.go` → `config.go` (consistency with `nat.go`, `routing.go`, etc.) — applied.
  2. `matchPolicy*` helpers belong in `security.go`, not `api.go` — already correct in implementation.
  3. `newCollector` (~600 LOC) → `metrics_descriptors.go` so `metrics.go` is truly slim — applied.
  4. `parseMemInfoKB` → `metrics_system.go` (only caller is `collectSystemMetrics`) — applied.
  5. Mandate `go build` after every individual file extraction, not "every 2-3 files" — applied (single atomic move per source monolith, build after).
- **Codex review** (foreground task on commit `5ed3fdd3`): **PLAN-NEEDS-MINOR**.
  Required adjustments:
  1. Same `config_handlers.go` → `config.go` rename — applied.
  2. Same `newCollector` → `metrics_descriptors.go`, `parseMemInfoKB` → `metrics_system.go` — applied.
  3. Tighten `api.go` scope so it doesn't become a junk drawer:
     `policyActionStr`/`screenChecks` → `security.go`; `protoName` →
     `sessions.go`; `configCommitResponse`/`commitResponseFromConfig` →
     `config.go` — applied.
  4. Fix mechanical procedure around imports — applied (atomic move per
     source monolith with `goimports -w pkg/api/*.go` + `go build`
     immediately after, not interleaved partial moves).

Both reviewers explicitly note that the flat-package shape is correct
(subpackage cannot define methods on `api.Server` without restructuring),
that test compilation is unchanged (method-receiver calls), and that
public API (Server/NewServer/Config/Run) is preserved.

**Status changed to PLAN-READY for implementation** with all required
minors folded in.



## Issue framing

`pkg/api/handlers.go` (2223 LOC, 67 functions) and `pkg/api/metrics.go`
(2033 LOC, 33 functions) are unreviewable monoliths. The issue
(#1540) asks to:

- Split handlers by operational domain (system, sessions, NAT,
  security, interfaces, config).
- Split the Prometheus collector by domain (descriptors, userspace
  status, counters, sessions, NAT, CoS, system).
- Preserve wire/output behavior across REST, gRPC, CLI.
- Keep one userspace helper `Status()` fetch per scrape and fan it
  out to domain emitters.

The parent wave-1 instructions override the issue's
`pkg/api/handlers/` subdirectory suggestion: the agreed shape for
this PR is **sibling `pkg/api/<aspect>.go` files in the same flat
`package api`**. Subdirectory promotion (with its own internal API
boundary, exported types, and import-cycle surface) is explicitly
out of scope for this step.

`api_sessions.go`-style underscore prefix sprawl is forbidden by
the parent instructions.

## Honest scope/value framing

This is pure code motion. There is no claimed runtime perf win, no
allocation reduction, no algorithm change. The value is:

- Bringing `handlers.go` and `metrics.go` from ~2k LOC each down to
  files in the 100-700 LOC band that review tools and humans can
  actually load into a context.
- Making future cross-PR changes (e.g. shared session/NAT projection
  helpers, the `Status()` fanout the issue body calls for) tractable
  by giving each domain a stable home file.

There is no runtime perf gate other than "do not regress." REST
handlers are control-plane; Prometheus collectors execute under
the scrape RPC (typically every 10-30s), not on the packet path.
The scrape-time `apiRuntimeDataPlane` calls (map iterators,
counter reads) and the per-scrape userspace `Status()` fetch are
unchanged.

If reviewers conclude this PR introduces architectural risk
(e.g. accidental allocations in `Collect` paths, cross-file
init-order coupling, public-API drift) without delivering a real
modularity win, **PLAN-KILL is an acceptable verdict.**

## What's already shipped / partially batched

- `pkg/api/handlers_sessions.go` (316 LOC) already exists as the
  `feature_foo.go` antipattern the parent instructions want gone
  (still in flat package). This PR **renames** it to `sessions.go`
  to land on the agreed shape.
- `pkg/api/sse.go`, `pkg/api/auth.go`, `pkg/api/server.go`,
  `pkg/api/types.go` are already sibling-domain files. They are
  not touched.
- The `apiRuntimeDataPlane` narrowing interface
  (`handlers.go:25-44`) is unchanged. The follow-up issue work
  (shared session projection, narrower scrape interface) is
  explicitly out of scope.

## Concrete design

### Target file layout (post-PR, `pkg/api/` flat package)

Existing (unchanged):
- `auth.go`, `auth_test.go`
- `server.go` (NewServer + Run + mux routes + TLS cert)
- `types.go` (DTOs)
- `sse.go` (eventStreamHandler + logStreamHandler + helpers)
- `README.md`
- Test files (`*_test.go`) untouched.

Renamed:
- `handlers_sessions.go` → `sessions.go` (also receives `protoName`
  helper moved from `handlers.go` since `protoName` is only used by
  the session presenter path).

New files split out of `handlers.go` (which is deleted):
- `api.go` — package-level helpers shared across handler files:
  `writeJSON`, `writeOK`, `writeError`, `queryInt`, `queryUint16`,
  `allInterfaceNames`, and the `applyResult` adapter on `*Server`.
  Also the `apiRuntimeDataPlane` interface (the narrow runtime
  surface declared at the top of the former `handlers.go`).
- `health.go` — `healthHandler`, `statusHandler`.
- `stats.go` — `globalStatsHandler`, `ifaceStatsHandler`,
  `zoneStatsHandler`, `clearCountersHandler`.
- `security.go` — `zonesHandler`, `policiesHandler`,
  `screenHandler`, `eventsHandler`, `matchPoliciesHandler`,
  `matchPolicyAddr`, `matchPolicyAddrSet`, `matchPolicyApp`,
  `matchSingleApp`, plus the `policyActionStr` and `screenChecks`
  helpers (only consumed by this domain).
- `nat.go` — `natSourceHandler`, `natDestHandler`,
  `natPoolStatsHandler`, `natRuleStatsHandler`.
- `interfaces.go` — `interfacesHandler`,
  `interfacesDetailHandler`, `writeInterfacesTerse`,
  `writeInterfacesDetail`.
- `routing.go` — `routesHandler`, `ospfHandler`, `bgpHandler`.
- `dhcp.go` — `dhcpLeasesHandler`, `dhcpIdentifiersHandler`,
  `clearDHCPIdentifiersHandler`.
- `ipsec.go` — `ipsecSAHandler`.
- `vrrp.go` — `vrrpHandler`.
- `system.go` — `systemInfoHandler`, `systemBuffersHandler`,
  `systemActionHandler`, `pingHandler`, `tracerouteHandler`.
- `config.go` — `configHandler`, `configEnterHandler`,
  `configExitHandler`, `configStatusHandler`, `configSetHandler`,
  `configDeleteHandler`, `configLoadHandler`,
  `configCommitHandler`, `configCommitCheckHandler`,
  `configCommitConfirmedHandler`, `configConfirmHandler`,
  `configRollbackHandler`, `configShowHandler`,
  `configExportHandler`, `configShowRollbackHandler`,
  `configCompareHandler`, `configHistoryHandler`,
  `configSearchHandler`, `configAnnotateHandler`. Also the
  `configCommitResponse` type and `commitResponseFromConfig`
  helper (only used by the config-mode handlers).
- `show_text.go` — `showTextHandler` (the largest single function
  at ~300 LOC; isolating it makes the rest of `system.go` smaller).

New files split out of `metrics.go`:
- `metrics.go` — slim entry: `xpfCollector` struct, `Describe`,
  `Collect`, and the small helpers used across emitters
  (`emitHistogram`, `bucketUpperBoundNs`, `policyCounterID`).
- `metrics_descriptors.go` — `newCollector` constructor (~600 LOC
  of descriptor allocations carved out so `metrics.go` is truly
  slim per Codex + AGY round-1 PLAN-NEEDS-MINOR findings).
- `metrics_userspace.go` — all `emit*` methods that consume
  `dpuserspace.ProcessStatus`:
  `collectUserspaceStatus`, `emitThreeColorPolicerCounters`,
  `emitUserspaceSourceNATPoolMetrics`,
  `emitUserspaceDynamicBufferMetrics`,
  `emitBindingActiveFlowCount`,
  `emitBindingTXCompletionTelemetry`,
  `emitCoSActiveFlowCount`,
  `emitFairnessRSSGauges`,
  `configuredFairnessRSSExpectations`,
  `emitFairnessRSSExpectationGauges`,
  `emitFairnessThroughputGauges`,
  `emitFairnessEqualFlowEstimateGauges`,
  `emitWorkerRuntime`,
  `emitUserspaceEventStream`,
  `emitCoSOwnerProfile`,
  `emitCoSDrainPhaseTelemetry`,
  `emitCoSEqualFlowEnforcement`.
- `metrics_counters.go` — legacy `apiRuntimeDataPlane` map-scrape
  collectors: `collectGlobalCounters`,
  `collectInterfaceCounters`, `collectZoneCounters`,
  `collectPolicyCounters`, `collectFilterCounters`.
- `metrics_sessions.go` — `collectSessionGauges`.
- `metrics_nat.go` — `collectNATPoolMetrics`.
- `metrics_system.go` — `collectDHCPMetrics`,
  `collectSystemMetrics`, plus the `parseMemInfoKB` helper
  (only consumed by `collectSystemMetrics`).

### Mechanical procedure

1. `git mv pkg/api/handlers_sessions.go pkg/api/sessions.go` (pure
   rename; the `protoName` helper gets appended later when the
   helpers are domain-tightened).
2. Split `handlers.go` into all 13 target sibling files in a single
   atomic pass: parse the source into function/type blocks, assign
   each to its target file by domain, and write each new file with
   a `package api` header. Run `goimports -w pkg/api/*.go` and
   `go build ./pkg/api/...` immediately after to verify per-file
   import sets and compilation. Delete `handlers.go` in the same
   commit.
3. Split `metrics.go` the same way: emit blocks to the slim
   `metrics.go`, `metrics_descriptors.go`, `metrics_userspace.go`,
   `metrics_counters.go`, `metrics_sessions.go`, `metrics_nat.go`,
   `metrics_system.go`. Run `goimports -w` and `go build` again.
4. Tighten `api.go` scope per Codex round-1 finding: move
   `policyActionStr` + `screenChecks` to `security.go`,
   `protoName` to `sessions.go`, `configCommitResponse` +
   `commitResponseFromConfig` to `config.go`. Re-run goimports +
   build + tests.
5. Update `pkg/dataplane/retirement_boundary_canary_test.go`
   `legacyDataplaneImportAllowlist` and the matching table in
   `docs/pr/1373-retire-ebpf-dataplane/README.md` to enumerate the
   new sibling files that still cross the legacy dataplane import.

### What this PR is NOT

- Not a behavioral change. No handler logic edits, no signature
  changes, no new helpers (other than what the move implies for
  `package`-private helper reachability — see below).
- Not introducing the `pkg/api/handlers/` or `pkg/api/metrics/`
  subdirectories. The follow-up issue may promote to
  subdirectories once the per-file boundaries are stable and the
  shared projection helpers have been extracted.
- Not extracting shared session/NAT projection helpers across
  REST/gRPC/CLI. That's a separate cross-package design problem.
- Not narrowing `apiRuntimeDataPlane`. Same interface, same call
  sites.
- Not changing the per-scrape `Status()` fetch pattern. Today's
  pattern (`Collect` calls `s.dp.Status()` once and passes it
  through to each emitter) is preserved verbatim.

## Public API preservation

The following symbols are all `package api` private. No exported
API surface is touched:

- `Server`, `Config`, `NewServer`, `Run` — defined in `server.go`,
  unchanged.
- All `*_test.go` files reference handlers by method-receiver on
  `*Server` (e.g. `s.healthHandler`). Method receivers don't care
  which file the method body lives in. Tests should compile
  without edit.
- `apiRuntimeDataPlane` and `xpfCollector` — unexported, only
  reachable inside `package api`. Moves are file-level only.

## Hidden invariants the change must preserve

1. **Side-effect ordering.** No handler is reordered relative to
   another. Each handler is independent (HTTP-routed); the only
   cross-handler state is via `*Server`, which is unchanged.
2. **Allocation rules.** No new allocations in any `Collect` path.
   `emitHistogram`, `bucketUpperBoundNs`, and `policyCounterID`
   stay in slim `metrics.go` so emit files inherit them via
   package scope. Per the issue's "make high-frequency metrics
   scrape behavior explicit" note, no new allocations land in
   any `c.collect*` or `c.emit*` method.
3. **HA sync portability.** None of these handlers run on the HA
   sync path. The `apiRuntimeDataPlane.IterateSessions`/`V6` paths
   continue to use the existing dataplane interface.
4. **Stale-handle hazards.** N/A — pure code motion, no new types,
   no new lifetimes.
5. **Lifetime / borrow-checker shape.** N/A — Go, not Rust.
   `*Server` is the receiver across all methods and that doesn't
   change.
6. **Mux route ordering.** `server.go`'s `mux.HandleFunc(...)`
   block in `NewServer` is the single source of truth. This PR
   does not edit `server.go`.
7. **Import set hygiene.** Each new file gets only the imports it
   uses. Unused imports in `handlers.go` after a partial split
   would fail Go compilation, so the procedure is to move
   "category at a time" and run `go build` after each category.

## Risk assessment

| Class | Verdict | Reason |
|-------|---------|--------|
| Behavioral regression | LOW | No logic edits; tests compile unchanged; mux routes untouched. |
| Lifetime / borrow-checker | N/A | Go, not Rust. |
| Performance regression | LOW | No `Collect` path allocations added. Same `Status()` fanout shape. |
| Architectural mismatch (#946-Phase-2 / #961 dead-end) | LOW | Pure code motion. No architectural premise to be wrong. Issue body's subdirectory preference is explicitly overridden by parent's flat-package mandate; if reviewers disagree they can KILL on that basis. |

The only architectural call this PR makes is the **flat-package
vs subdirectory** decision. The issue prefers subdirectory; the
parent wave-1 instructions prefer flat sibling files. Both have
merit:

- Subdirectory: stronger encapsulation, smaller per-file import
  cone, easier to spot domain boundaries in the file tree.
- Flat siblings: zero exported-API churn, no new internal package
  for the test suite to import, no risk of import cycles between
  `pkg/api/handlers/` and `pkg/api/metrics/` if they need shared
  projection helpers later.

If reviewers prefer the subdirectory shape and want this PR
re-cut, **PLAN-KILL with rationale** is the right call. The
follow-up could land subdirectory promotion as a second step
after this first split is stable.

## Test plan

- `go build ./pkg/api/...` — clean, no compile errors.
- `go test ./pkg/api/...` — all existing tests pass (auth,
  config_commit, health, metrics, nat_stats, policy_counters,
  sse, system_buffers).
- `go test ./pkg/grpcapi/... ./pkg/cli/...` — covers the
  acceptance criterion in the issue body about wire-output parity
  across REST/gRPC/CLI.
- `go test ./...` — full suite.
- **No per-PR smoke** — this is wave-1; AWAITING-BATCH-MERGE
  applies after 4-of-4 reviewer attestation.

## Out of scope (explicitly)

- Subdirectory promotion (`pkg/api/handlers/`, `pkg/api/metrics/`).
- Shared session/NAT/security projection helpers across
  REST/gRPC/CLI.
- Narrowing `apiRuntimeDataPlane`.
- Restructuring the per-scrape `Status()` fanout.
- Behavioral change to any handler.
- Renaming `xpfCollector` or making any collector method
  externally callable.
- Changes to `server.go`, `sse.go`, `auth.go`, `types.go`,
  or any `*_test.go`.

## Open questions for adversarial review — resolutions

The seven open questions raised by plan v1 were all addressed during
plan-review rounds (Codex + AGY), and the resolutions are reflected in
the final landed shape:

1. **Flat-package vs subdirectory shape.** Both reviewers ratified
   flat-package. Subdirectories would force exported wrappers because
   subpackages cannot define methods on `api.Server`; that's
   architectural restructuring, not the wave-1 scope. Issue body's
   subdirectory preference is therefore overridden for this PR. A
   later step can still promote to subdirectories once boundaries
   are stable.

2. **`apiRuntimeDataPlane` interface placement.** Both reviewers
   ratified placing it in `api.go` alongside the JSON/HTTP helpers.
   `interfaces.go` belongs to the interface-handler family;
   `dataplane.go` was suggested as an alternative but not required.

3. **`metrics.go` slim-core composition.** Both reviewers required
   `newCollector` (~600 LOC) to move out to `metrics_descriptors.go`.
   Applied. `metrics.go` is now 354 LOC: struct + Describe + Collect
   + emitHistogram + bucketUpperBoundNs + policyCounterID only.

4. **`show_text.go` carve-out.** Ratified as kept. The 300-LOC
   generic dispatcher legitimately stands alone.

5. **`config_handlers.go` filename.** Both reviewers required rename
   to `config.go` for consistency with `nat.go`/`routing.go`/etc.
   Applied.

6. **File-internal references after the move.** Codex required
   tightening `api.go` scope: `policyActionStr` + `screenChecks` →
   `security.go`, `protoName` → `sessions.go`, `configCommitResponse`
   + `commitResponseFromConfig` → `config.go`. Applied.
   `queryInt`/`queryUint16`/`allInterfaceNames` stayed in `api.go`
   as genuinely cross-cutting helpers.

7. **Per-class CoS smoke applicability.** Ratified: control-plane
   only, no dataplane code touched, AWAITING-BATCH-MERGE after
   4-of-4 attestation is the right gate.
