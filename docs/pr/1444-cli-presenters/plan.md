# #1444 De-monolithize `pkg/cli/cli.go` into Logical Operational Presenters

## Status
DRAFT v1 — pending adversarial plan review.

## Issue framing
The issue points out that `pkg/cli/cli.go` is a 1999-line monolith mixing:
- The `CLI` struct definition + constructor + setters (legitimate entry-point glue).
- Readline completion engine (`cliCompleter.Do`, `completeConfigWithDesc`, prefix
  resolution helpers).
- The interactive `Run()` loop.
- A grab-bag of `handleShow*` dispatcher methods for security, screen, NAT,
  route, protocols, class-of-service, services that should live in the
  domain-named sibling files.
- Domain utilities (`sessionFilter`, builtin-app table, protocol name lookups,
  address resolution, app-name resolution, address/port splitter, link-speed
  reads, chrony rendering, monotonic-seconds helper, etc.).
- Cluster-aware peer plumbing (`dialPeer`, `requestPeerSystemAction`,
  `fetchPeerSessions`, `fetchPeerSessionSummary`, `readFabricRedirectCounters`,
  `clusterPrefix`).
- Daemon-side glue (`applyToDataplane`, `reloadSyslog`, prompt builders).

The Wave-1 goal is **pure code motion** to relocate non-core concerns into
sibling `pkg/cli/<aspect>.go` files in the same package, so cli.go shrinks to
just the struct, constructor, setters, completer wiring, and the `Run()`
loop. Public API does not change; the package layout already uses
multi-file composition.

## Honest scope / value framing
This is a maintainability refactor on the Go control-plane CLI. It is NOT
on the hot dataplane path. Win is qualitative:
- cli.go drops from ~1999 LOC to roughly 600-700 LOC (struct + setters +
  `Run` loop + completer entry-point only).
- New presenter files inherit the existing `cli_show_*.go` naming convention
  rather than introducing a third style.
- Sibling files become the canonical home for `handleShowX` dispatchers,
  matching where the worker `showX` methods already live.

**If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.** (Perf gain here is zero by design; the
justification is code organization. A reviewer rejecting on grounds that
"reorganization without a hot-path win is not worth the churn" is fair, but
the issue tracks this work specifically.)

## What's already shipped / partially batched
The codebase has already split most operational presenters into siblings:
- `cli_show.go` — top-level `handleShow` router.
- `cli_show_chassis.go`, `cli_show_cluster.go`, `cli_show_flow.go`,
  `cli_show_interfaces.go`, `cli_show_nat.go`, `cli_show_routing.go`,
  `cli_show_security.go`, `cli_show_services.go`, `cli_show_system.go` —
  domain worker methods.
- `cli_show_shared.go` — cross-domain help text.
- `cli_config.go`, `cli_clear.go`, `cli_request.go`, `cli_dispatch.go`,
  `cli_helpers.go` — non-show commands and dispatcher.
- `completion.go` — supporting completion helpers.
- `runtime.go`, `monitor.go`, `monitor_interface.go`, `session_display.go` —
  ancillary subsystems.

What's left in cli.go is the residue: glue + a few stragger `handleShow*`
dispatchers that were never moved when their worker methods migrated.

## Concrete design

Wave-1 splits cli.go into the following sibling files. Naming follows the
existing `cli_` prefix used by every other file in this directory (the
user-supplied "no `cli_` prefix" guidance conflicts with the established
convention; we keep the convention to avoid mixed naming. **Open question for
reviewers below.**)

### Target file layout

| File | Symbols moved from cli.go | Lines |
|------|---------------------------|-------|
| `cli.go` (stays) | `CLI` struct, `New`, `applyResult`, `dataplaneLoaded`, `SetForwardingSampler`, `SetRPMResultsFn`, `SetFeedsFn`, `SetLLDPNeighborsFn`, `SetVersion`, `SetUserClass`, `SetVRRPManager`, `SetApplyConfigFn`, `SetCommitFns`, `SetFabricPeer`, prompt helpers (`refreshPrompt`, `operationalPrompt`, `configPrompt`, `clusterPrefix`), `Run()` loop | ~700 |
| `cli_completion.go` (new) | `completionNode` alias, `operationalTree`, `configTopLevel`, `cliCompleter` type, `cliCompleter.Do`, `completeConfigWithDesc`, `resolveCommand`, `formatAmbiguousMatches` | ~270 |
| `cli_peer.go` (new) | `fabricRedirectCounters` type, `readFabricRedirectCounters`, `dialPeer`, `requestPeerSystemAction`, `fetchPeerSessions`, `fetchPeerSessionSummary` | ~150 |
| `cli_permissions.go` (new) | `checkPermission` | ~50 |
| `cli_apply.go` (new) | `applyToDataplane`, `reloadSyslog` | ~150 |
| `cli_session_filter.go` (new) | `sessionFilter` type, `parseSessionFilter`, `matchesV4`, `matchesV6`, `hasFilter`, `ifaceMatches`, `resolveEgressIface`, `topTalkerEntry` | ~290 |
| `cli_app_resolve.go` (new) | `builtinApp` type, `builtinApps` map, `resolveAppName`, `printAppDetail`, `parsePolicyZoneFilter`, `resolveAddress`, `resolveAddressDetail` | ~130 |
| `cli_link.go` (new) | `readLinkSpeed`, `readLinkDuplex`, `formatSpeed`, `formatDuplex`, `dhcpLease` | ~50 |
| `cli_chrony.go` (new) | `printChronyTracking` | ~50 |
| `cli_proto.go` (new) | `protoNameFromNum`, `protoNameToID`, `splitAddrPort`, `uint32ToIP`, `sessionStateName`, `ntohs`, `monotonicSeconds`, `enabledStr`, `capitalizeFirst` | ~130 |
| `cli_show_security.go` (extend) | `handleShowSecurity`, `handleShowScreen` (move from cli.go; worker methods already live here) | +280 |
| `cli_show_nat.go` (extend) | `handleShowNAT` | +35 |
| `cli_show_routing.go` (extend) | `handleShowRoute`, `handleShowProtocols` | +60 |
| `cli_show_services.go` (extend) | `handleShowClassOfService`, `handleShowServices` | +25 |

After the split, cli.go contains roughly:
- Lines 1-45: imports trimmed to what only the residual symbols need.
- Lines 46-105: the `CLI` struct definition.
- Lines 108-238: `New`, `applyResult`, `dataplaneLoaded`, all `Set*` methods.
- Lines 1119-1133, 1931-1953: prompt helpers (`refreshPrompt`,
  `clusterPrefix`, `operationalPrompt`, `configPrompt`).
- Lines 566-749: the `Run()` interactive loop.

All other code blocks are excised in their entirety and pasted unchanged
into the target file (modulo `package cli` header + appropriate import
list).

### Mechanical method

1. For each target file, write the `package cli` header + a doc comment
   noting the file's scope.
2. Move blocks one-by-one, preserving every line of the moved function
   verbatim (no signature changes, no logic edits, no inlining).
3. After each move, run `goimports -w` on both the source and destination
   files to maintain a minimal, sorted import set per file.
4. Rebuild + test after each batch.

### Import scope per file

Each target file imports only what the moved symbols need. The
`cli_peer.go` file inherits the gRPC client imports; `cli_apply.go`
inherits dataplane + frr + ipsec + routing imports; `cli_completion.go`
inherits the readline + cmdtree imports; everything else is a small
domain set.

## Public API preservation

The only externally consumed symbols are (verified via
`grep -rln 'psaab/xpf/pkg/cli\"'`):

- `cli.New(store, dp, eventBuf, eventReader, rm, fm, im, dm, dr, cm) *CLI`
- `(*CLI).SetVersion(string)`
- `(*CLI).SetForwardingSampler(*fwdstatus.Sampler)`
- `(*CLI).SetApplyConfigFn(func(*config.Config))`
- `(*CLI).SetCommitFns(...)`
- `(*CLI).SetRPMResultsFn(func() []*rpm.ProbeResult)`
- `(*CLI).SetFeedsFn(func() map[string]feeds.FeedInfo)`
- `(*CLI).SetLLDPNeighborsFn(func() []*lldp.Neighbor)`
- `(*CLI).SetVRRPManager(*vrrp.Manager)`
- `(*CLI).SetFabricPeer(func() []string, string)`
- `(*CLI).SetUserClass(string)`
- `(*CLI).Run() error`

These all stay in `cli.go` (the slim entry point). No signature changes.

The single external consumer (`pkg/daemon/daemon_run.go`) compiles
unchanged.

## Hidden invariants the change must preserve

1. **Side-effect ordering inside `Run()`** — the readline init, completer
   wiring, terminal mode setup, signal handling, and prompt refresh order
   in `Run()` is unchanged.
2. **Completer state ownership** — `cliCompleter` carries the `*CLI`
   pointer; moving it to `cli_completion.go` does not change ownership.
3. **Allocation rules** — no new allocations on any path; method bodies
   move verbatim.
4. **`sessionFilter` lifetime** — the type is allocated by
   `parseSessionFilter` and consumed by `fetchPeerSessions`,
   `handleShowFlow`, and the matcher methods. All callers live in the
   same package, so moving the type to `cli_session_filter.go` does not
   change visibility.
5. **`builtinApps` initialization order** — Go package-level `var` blocks
   initialize in lexical filename order within the package, but builtin
   apps is only consumed by `resolveAppName`, which moves with it.
6. **Test file expectations** — none of the existing `*_test.go` files
   import any package-private symbol that wouldn't remain in scope after
   the split (verified by walking the test files in Step 5 of the
   review).
7. **No new init() functions** — only the existing top-level `var`
   declarations.

## Risk assessment

| Risk class | Level | Notes |
|------------|-------|-------|
| Behavioral regression | LOW | Pure code motion. No logic edits, no signature changes. Go tooling enforces compile-time soundness of the move. |
| Borrow / lifetime | N/A | Go has GC; no borrow checker. |
| Performance regression | NIL | Go control-plane CLI, not the dataplane hot path. |
| Architectural mismatch | LOW | The codebase already uses this multi-file pattern (`cli_show_*.go`, `cli_config.go`, `cli_clear.go`, etc.); this PR completes a partially-done split rather than introducing a new pattern. |
| Naming convention churn | OPEN | The user supplied wave-1 rules saying "avoid `cli_` prefix"; the repo's existing files use it. **See open question 1.** |
| Test coverage | LOW | The existing 14 `*_test.go` files cover the moved symbols via their public callers; they keep passing after move because Go test package scope is per-package, not per-file. |

## Test plan

1. `go build ./...` clean (covers all packages, surfaces unused-import
   errors instantly).
2. `go test ./pkg/cli/...` — 14 test files; all must pass.
3. `go test ./cmd/cli/...` — remote CLI client uses its own dispatcher,
   not pkg/cli, but the build must stay clean.
4. `go test ./...` — full Go suite (640+ tests across 20+ packages).
5. `grep -rln 'psaab/xpf/pkg/cli\"' --include='*.go'` should still resolve
   to one consumer (`pkg/daemon/daemon_run.go`) and compile.
6. `wc -l pkg/cli/cli.go` to confirm the file shrinks to ~700 lines.
7. No dataplane smoke required (per Wave-1 rules: "No per-PR smoke.
   AWAITING-BATCH-MERGE after 4-of-4."). The Go test suite covers all
   moved code paths.

## Out of scope (explicitly)

- Renaming existing `cli_show_*.go` files to drop the `cli_` prefix. The
  user's Wave-1 guidance to "avoid `cli_` prefix" conflicts with the
  established repo convention; resolving that one way or the other is a
  separate cosmetic PR. We follow the existing convention for new files
  to keep the directory consistent.
- Extracting a `presenter` interface or `pkg/cli/shell/` subpackage as
  the issue suggests. The Wave-1 rules explicitly say "Split into sibling
  `pkg/cli/<aspect>.go` files inside the same `pkg/cli/` package" — no
  subpackage hierarchy. Issue suggestion 3 (`pkg/cli/shell/`) is
  intentionally NOT followed; if a future PR wants it, that's a separate
  scope.
- Refactoring the `handleShowX` dispatchers (e.g. switch-table cleanup,
  argument parsing consolidation). Pure motion only.
- Touching `cmd/cli/` — it has its own dispatcher and does not import
  pkg/cli.

## Open questions for adversarial review

1. **`cli_` prefix vs bare prefix.** The user's Wave-1 rules say "AVOID:
   `pkg/cli/cli_show.go` (the `cli_` prefix is redundant when already in
   pkg/cli/). Use bare aspect names." But the existing repo has 19 files
   already using the `cli_` prefix. New files should match existing
   convention for consistency. If reviewers prefer a renaming sweep,
   that's a much bigger churn (touches blame for 30+ files); we propose
   doing it as a follow-up. **Is this the right call?**

2. **Should `handleShowSecurity` move whole, or be split by feature?**
   It's 250 lines and handles policies/zones/applications/screen/IPsec/IKE
   /firewall/address-book/dynamic-address in one switch. Wave-1 says
   pure motion → move whole into `cli_show_security.go`. A future PR
   could split the dispatcher by subdomain; out of scope here.

3. **Should `sessionFilter` go to `session_display.go` instead of a new
   `cli_session_filter.go`?** It's tied to session display but is more
   about filtering than rendering. Argument either way; we picked a new
   file because session_display.go is rendering-only today and adding
   the filter type changes its character.

4. **Should `protoNameFromNum`/`protoNameToID`/`sessionStateName` live
   under `session_display.go`?** They're consumed there. We chose
   `cli_proto.go` to keep `session_display.go` rendering-focused, but a
   reviewer might reasonably argue these belong with their primary
   consumer.

5. **Is the residual `cli.go` still too monolithic at ~700 lines?**
   It contains the struct (~60 LOC), `New` (~30 LOC), 12 setters
   (~80 LOC), prompt helpers (~30 LOC), and `Run` (~190 LOC). The
   remainder is import block + comments. We argue this is a coherent
   "entry-point" file. Reviewer can disagree and demand `Run()` move to
   its own file; that's a trivial follow-up.

6. **Are there any package-private symbols in test files that this move
   breaks?** None found by inspection. Per-file accept verification at
   PR time via `go test ./pkg/cli/...` covering all test files.

7. **Is the import-set per file going to grow because some helpers
   reach into the daemon-side struct?** Several moved methods receive
   `*CLI` and reach into `c.routing`, `c.frr`, `c.ipsec`, `c.dataplane`,
   etc.; the per-file import set will reflect that. Verifier check: run
   `goimports -l pkg/cli/*.go` after the move and expect zero
   recommendations. Any extra imports indicate either a stale block or
   a missing one.
