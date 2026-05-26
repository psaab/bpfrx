# #1540 — Modularize REST API handlers and Prometheus collectors

**Status:** DRAFT v1 — pending adversarial plan review

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
- `handlers_sessions.go` → `sessions.go` (no content change)

New files split out of `handlers.go` (which is deleted):
- `api.go` — package-level helpers shared across handler files:
  `writeJSON`, `writeOK`, `writeError`, `commitResponseFromConfig`,
  `queryInt`, `queryUint16`, `allInterfaceNames`, `policyActionStr`,
  `protoName`, `screenChecks`, `applyResult`. Also the
  `apiRuntimeDataPlane` interface and any package-internal type
  decls currently at the top of `handlers.go`.
- `health.go` — `healthHandler`, `statusHandler`.
- `stats.go` — `globalStatsHandler`, `ifaceStatsHandler`,
  `zoneStatsHandler`, `clearCountersHandler`.
- `security.go` — `zonesHandler`, `policiesHandler`,
  `screenHandler`, `eventsHandler`, `matchPoliciesHandler`,
  `matchPolicyAddr`, `matchPolicyAddrSet`, `matchPolicyApp`,
  `matchSingleApp`.
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
- `config_handlers.go` — `configHandler`, `configEnterHandler`,
  `configExitHandler`, `configStatusHandler`, `configSetHandler`,
  `configDeleteHandler`, `configLoadHandler`,
  `configCommitHandler`, `configCommitCheckHandler`,
  `configCommitConfirmedHandler`, `configConfirmHandler`,
  `configRollbackHandler`, `configShowHandler`,
  `configExportHandler`, `configShowRollbackHandler`,
  `configCompareHandler`, `configHistoryHandler`,
  `configSearchHandler`, `configAnnotateHandler`.
- `show_text.go` — `showTextHandler` (the largest single function
  at ~300 LOC; isolating it makes the rest of `system.go` smaller).

New files split out of `metrics.go`:
- `metrics.go` — slim entry: `xpfCollector` struct, `newCollector`
  (the constructor with all descriptor allocations), `Describe`,
  `Collect`, and the small helpers used across emitters
  (`emitHistogram`, `bucketUpperBoundNs`, `policyCounterID`,
  `parseMemInfoKB`).
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
  `collectSystemMetrics`.

### Mechanical procedure

1. `git mv pkg/api/handlers_sessions.go pkg/api/sessions.go` (no
   content change; pure rename).
2. For each new file: create the file with the same `package api`
   header and the minimal import list it needs. Move the function
   bodies verbatim from `handlers.go` / `metrics.go`. Keep
   comments and section-divider banners attached to their
   functions.
3. Once `handlers.go` is empty of moved content, delete the file.
   `metrics.go` is **not** deleted; it retains the collector
   struct + ctor + Describe + Collect + cross-cut helpers.
4. Run `goimports -w pkg/api/*.go` to clean up per-file import
   sets after the move.
5. `go build ./pkg/api/...` and `go test ./pkg/api/...` after each
   logical move (e.g. after every 2-3 files) so a regression is
   localized.

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

## Open questions for adversarial review

1. **Is the flat-package shape acceptable, or does this PR need to
   ship subdirectories per the issue body?** Parent's wave-1
   instruction is explicit ("split `pkg/api/` monolith into
   sibling `pkg/api/<aspect>.go` files in the same package")
   and forbids `api_sessions.go` underscore prefix. Both
   instructions can be satisfied with flat sibling files. But
   the issue body explicitly says "Do not replace a monolith
   with files named `handlers_nat.go` in the same flat
   package if a directory-level domain boundary is practical."
   Reviewers: which mandate wins? PLAN-KILL is acceptable if
   you conclude this PR is shipping the wrong shape.

2. **Should `apiRuntimeDataPlane` move out of the slim entry
   into its own `interfaces.go`-style file?** It's currently
   at `handlers.go:25-44` (44 LOC). Moving it to a new
   `interfaces.go` would collide with the interface-handler
   `interfaces.go` filename. The plan puts it in `api.go`
   alongside `writeJSON`/`writeError`/etc. Reviewers: better
   home? `runtime.go`? Or split into `interfaces_handler.go`
   to free up `interfaces.go` for the type?

3. **Is `xpfCollector` plus `newCollector` plus
   `Describe`+`Collect` the right slim core for `metrics.go`,
   or should `newCollector` (which spans ~600 LOC of
   descriptor allocations) move to a separate
   `metrics_descriptors.go`?** The descriptor block is the
   single largest function in metrics.go. Splitting it would
   make `metrics.go` truly slim (<200 LOC). Counter-argument:
   the descriptor block is logically tied to the struct
   definition; separating them adds a navigation hop without
   reducing the largest file substantially.

4. **Does the `show_text.go` carve-out (~300 LOC) make sense,
   or should `showTextHandler` live with `system.go`?**
   Argument for separate file: it's a generic dispatcher that
   touches every domain. Argument against: it's invoked under
   `GET /api/v1/show-text` which is conceptually a system /
   operational command.

5. **Does the `config_handlers.go` filename clash with
   `pkg/config/`?** Go imports `package config`, file naming
   within `pkg/api` doesn't conflict with that, but reviewers
   may prefer `configmode.go` or `config_mode.go` for
   clarity. (The issue body suggests `config.go` for the
   config-mode handlers.) Trade-off: `pkg/api/config.go`
   would conflict in human readers' minds with `pkg/config`
   (the parser). Plan picks `config_handlers.go` — is that
   wrong?

6. **Test coverage for the move.** Every existing test should
   pass unchanged. Are there file-internal references
   (unexported function references across files) that the
   move could subtly break? `policyActionStr`, `protoName`,
   `screenChecks`, `queryInt`, `queryUint16`,
   `allInterfaceNames`, `applyResult`, `commitResponseFromConfig`
   are all package-private. They must land in a file that
   stays compiled (e.g. `api.go`) so callers in other split
   files keep resolving them.

7. **Per-class CoS smoke applicability.** This PR is
   control-plane only; no dataplane code is touched. The
   wave-1 parent instructions say "No per-PR smoke" for this
   PR; AWAITING-BATCH-MERGE after 4-of-4. Reviewers: agree
   smoke can be deferred to the batch?
