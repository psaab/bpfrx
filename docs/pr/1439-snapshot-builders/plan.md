# #1439 — De-monolithize pkg/dataplane/userspace/snapshot.go

**Status:** IMPLEMENTED v3.1 — plan-review converged after 3
rounds (Codex + Gemini + Antigravity); implementation shipped in
PR #1592 at HEAD bd6e83a6. Code-review round 2 reached MERGE-READY
across all three reviewers + Copilot doc-comment hygiene fixes
applied. This plan doc is preserved as a historical record of the
3-round plan-review convergence; see PR #1592 for the final shipped
state and commit history.

Plan-review history:
- Round 1 (v1, 9 files): Codex PLAN-NEEDS-MAJOR, Gemini
  PLAN-NEEDS-MINOR, Antigravity PLAN-NEEDS-MINOR.
- Round 2 (v2, 14 files but said "12"): Codex PLAN-NEEDS-MAJOR
  on count arithmetic, Gemini PLAN-NEEDS-MAJOR on count
  arithmetic, Antigravity PLAN-READY.
- Round 3 (v3, count corrected): Codex PLAN-NEEDS-MINOR (stale
  v2 narrative), Gemini PLAN-READY, Antigravity PLAN-READY.
- v3.1 nits fixed; implementation began.

Round 2 findings (Codex + Gemini both MAJOR):

- "12 sibling files" appears in three places, but the inventory lists
  14: builder, interfaces, fabric, mirrors, tunnels, zones, routes,
  neighbors, nat, screens, flow, filters, cos, policies.
- interfaces.go header says "11 functions", text body says "15",
  bullet list has 16. Correct count: 16 → adjusts the total to 63
  exactly (was the bogus 62-with-off-by-one).
- "interfaces.go ~430 LOC" claim was made against a 16-function
  count; actual span sums to ~470 LOC, comfortably under the
  acceptable ~500 LOC cap (the original v1 limit; not the v2
  artificial ~430 claim).

v3 fixes all of the above. No design change; only mechanical
corrections to inventory and arithmetic.

## Issue framing

`pkg/dataplane/userspace/snapshot.go` is 2,404 LOC and 63 functions.
It is the single Go source compiling the dataplane control-plane snapshot
on every config commit: interfaces, zones, fabrics, tunnel endpoints,
neighbors, routes, NAT (source/static/destination/NAT64/Nptv6), screens,
SYN cookie key derivation, flow/flow-export, firewall filters, policers
(single + three-color), class of service, mirror configs, and policies.

The issue (#1439) asks for a code-motion split into modular subsystem
builder files inside the **same** package. No package-boundary change,
no behaviour change, no public API regression.

User mandate (Wave 4 standing rules):

- Sibling `.go` files in the same package (`pkg/dataplane/userspace/`).
- **Bare aspect names, NO `snapshot_` prefix.** New files are
  domain-named, not prefix-clustered.
- Public API preserved verbatim. No new allocations on the
  steady-state no-op snapshot path.

Precedent: PR #1587 (#1547 `pkg/frr/frr.go` split into 5 siblings).

## Honest scope/value framing

This is **pure code motion**. No bug fix, no perf delta, no
behavioural change. The win is:

- Cognitive load: 2,404-LOC monolith → 14 domain-named files, the
  largest (`interfaces.go`) approximately 470 LOC.
- Merge-conflict surface: Round-1 reviewers verified empirically.
  `git log --since='3 months ago' pkg/dataplane/userspace/snapshot.go`
  returns **31-32 commits** in 90 days (Codex: 31, Gemini: 32). The
  monolith is a verified conflict magnet.
- Test-isolation: existing `snapshot_neighbors_1197_test.go` and
  `snapshot_allowlist_test.go` already demonstrate aspect-focused
  tests work — production code split mirrors that.

*If reviewers conclude this churn is not worth the wash, PLAN-KILL is
an acceptable verdict.* Round-1 reviewers all three judged the
merge-conflict claim was real and the design risk was low; none
returned PLAN-KILL.

## Round-1 reviewer findings (preserved verbatim)

### Codex (PLAN-NEEDS-MAJOR)

> **Major: the right-sizing premise is false.** The plan claims every
> new file is under ~500 LOC and interfaces.go is about 470 LOC, but
> the proposed grouping is about **732 source lines before imports**
> with **21 functions**. Split at least fabric.go, mirrors.go, and
> tunnels.go out of interfaces.go.

> **Major: plan inventory/counts are not mechanically credible.** nat.go
> says 9 but lists 8; flow_and_filters.go says 7 but lists 6; routes.go
> says 12 but depends on a helper not in snapshot.go.

> **Major/minor boundary: filterPublishableNeighbors is misdescribed.**
> The plan says it lives in routes.go, but it currently lives in
> manager.go:959. No compile break, but the plan must say so.

> **Minor: import inventory is wrong.** flow_and_filters.go needs
> strconv and pkg/dataplane; routes.go needs fmt; builder.go needs
> pkg/dataplane for userspaceMapPins.

> **flow_and_filters.go**: awkward. Prefer flow.go plus filters.go.

### Gemini (PLAN-NEEDS-MINOR)

> 5. snapshotContentHash dependency: filterPublishableNeighbors is
>    actually already defined in manager.go:959. Same package,
>    no broken dependency.

> 6. MonitoredInterfaceLinkIndexes call-site in daemon_neighbor_listener.go
>    is a **comment**, not a call. Actual caller is manager.go:1117.

> 10. flow_and_filters.go violates "bare aspect names" — split into
>     flow.go and filters.go.

### Antigravity (PLAN-NEEDS-MINOR)

> 1. routes.go is overloaded (12 functions). Split into routes.go
>    and neighbors.go. MonitoredInterfaceLinkIndexes belongs in
>    neighbors.go.

> 2. Split flow_and_filters.go into flow.go and filters.go.

> Empirical: **31 commits** touched snapshot.go in last 90 days
> (~2.5/week). Merge-conflict claim verified.

## Plan v2 — applied changes

1. **interfaces.go decomposed** per Codex: split out `fabric.go`,
   `mirrors.go`, `tunnels.go` as sibling files. `interfaces.go`
   keeps only the interface-snapshot and link-helper functions.

2. **routes.go decomposed** per Antigravity + Gemini: split out
   `neighbors.go`. `MonitoredInterfaceLinkIndexes` moves to
   `neighbors.go` (it filters neighbor-update keyspace).

3. **flow_and_filters.go dropped** per all three reviewers: split
   into `flow.go` and `filters.go`.

4. **filterPublishableNeighbors stays in manager.go** — explicitly
   documented as a cross-file dependency. No move needed; same
   package.

5. **Import inventory deferred to `goimports -w`** — plan no longer
   asserts per-file import lists. `goimports` produces canonical
   imports; the plan only requires that `go build ./...` and
   `go vet ./...` succeed after the move.

6. **Function counts** recomputed from `grep -nE '^func ' snapshot.go`
   (63 total). Each new file's count is now exact, with the actual
   function names listed.

Result: **14 sibling files** (was 9), each focused on a single
domain. Listed below in inventory.

## Concrete design — file inventory (v2)

All files land in `pkg/dataplane/userspace/`. Function counts are
exact, taken from `grep -nE '^func ' snapshot.go` at HEAD.

### `builder.go` — top-level orchestration (4 functions)
- `buildSnapshot` (line 23)
- `buildSnapshotWithSchedulerState` (line 27) — calls every
  subsystem builder
- `snapshotContentHash` (line 282) — depends on
  `filterPublishableNeighbors` which lives in **manager.go:959**
  (cross-file, same package, no compile break)
- `userspaceMapPins` (line 545)

Approx LOC: 23-82 + 282-301 + 545-560 = ~100 LOC.

### `interfaces.go` — interface snapshots + link helpers (16 functions)
- `syntheticLogicalIfindex` + ifindex range constants (line 173, 164-171)
- `shouldUseLogicalOnlyParentBoundRethVLAN` (line 205)
- **`UserspaceBoundLinuxInterfaces` (line 234) — PUBLIC API**
- `buildInterfaceSnapshots` (line 562)
- `coSUnitShapingRate` (line 694)
- `coSUnitBurstSize` (line 701)
- `coSUnitSchedulerMap` (line 708)
- `coSUnitDSCPClassifier` (line 715)
- `coSUnitIEEE8021Classifier` (line 722)
- `coSUnitDSCPRewriteRule` (line 729)
- `snapshotLinuxName` (line 898)
- `buildLinkSnapshot` (line 929)
- `buildConfiguredAddressSnapshots` (line 946)
- `mergeInterfaceAddressSnapshots` (line 976)
- `buildInterfaceAddressSnapshots` (line 1010)
- `userspaceRXQueueCount` (line 1042)

That's **16 functions** (Codex's round-1 21 included
fabric/mirror/tunnel which now move out as separate files).
Approx LOC = ~470 (under the ~500 LOC cap).

Reviewers agreed: `coSUnit*` accessors stay here because their only
call site is `buildInterfaceSnapshots`.

### `fabric.go` — fabric snapshots (2 functions)
- `buildFabricSnapshots` (line 462)
- `buildFabricPeerMAC` (line 518)

Approx LOC = ~85.

### `mirrors.go` — port-mirroring snapshots (2 functions)
- `buildMirrorConfigSnapshotsFailClosed` (line 84)
- `buildMirrorConfigSnapshots` (line 96)

Approx LOC = ~80.

### `tunnels.go` — tunnel endpoint snapshots (1 function)
- `buildTunnelEndpointSnapshots` (line 736)

Approx LOC = ~120.

### `zones.go` — zone snapshots + interface→zone map (2 functions)
- `buildZoneSnapshots` (line 443)
- `buildInterfaceZoneMap` (line 855)

Approx LOC = ~60.

### `routes.go` — route snapshots (4 functions)
- `buildRouteSnapshots` (line 1062)
- `buildInterfaceRouteTables` (line 1196)
- `connectedPrefixesForInterface` (line 1217)
- `normalizeRouteSnapshotFamily` (line 1249)

Approx LOC = ~210.

### `neighbors.go` — neighbor snapshots + publishable filter (6 functions)
- `neighborsEqual` (line 304)
- `neighborsEqualForwarding` (line 327)
- `neighborSnapshotPublishable` (line 373)
- **`MonitoredInterfaceLinkIndexes` (line 402) — PUBLIC API**
- `buildNeighborSnapshots` (line 2290)
- `neighborStateString` (line 2374)

Approx LOC = ~210.

`filterPublishableNeighbors` itself remains in `manager.go` (NOT moved
this PR — it's used from manager + process + the test file already, and
moving it would expand scope unnecessarily). Documented.

### `nat.go` — source/static/destination/NAT64/Nptv6 NAT (8 functions)
- `buildSourceNATSnapshots` (line 1271)
- `sourceNATPoolPortRange` (line 1360)
- `buildStaticNATSnapshots` (line 1378)
- `appPortsFromSpec` (line 1404)
- `buildDestinationNATSnapshots` (line 1434)
- `buildNAT64Snapshots` (line 1537)
- `buildNptv6Snapshots` (line 1564)
- `hasNonNptv6StaticNAT` (line 1590)

Approx LOC = ~340.

### `screens.go` — screen profiles + SYN cookie keys (5 functions)
- `buildScreenSnapshots` (line 1607)
- `buildSYNCookieMasterKey` (line 1668)
- `synCookieSecretMaterial` (line 1712)
- `userspaceSynCookieProtectionActive` (line 1722)
- `userspaceSupportsScreenProfiles` (line 1743)

Approx LOC = ~150.

### `flow.go` — flow + flow export (2 functions)
- `buildFlowSnapshot` (line 1753)
- `buildFlowExportSnapshot` (line 1772)

Approx LOC = ~70.

### `filters.go` — firewall filters + policers (4 functions)
- `buildFirewallFilterSnapshots` (line 1820)
- `buildFilterTermSnapshots` (line 1864)
- `buildPolicerSnapshots` (line 1917)
- `buildThreeColorPolicerSnapshots` (line 1945)

Approx LOC = ~160.

### `cos.go` — class of service builder (1 function)
- `buildClassOfServiceSnapshot` (line 1980)

Approx LOC = ~170.

### `policies.go` — security policies + scheduler-state (6 functions)
- `buildPolicySnapshots` (line 2150)
- `buildPolicySnapshotsWithSchedulerState` (line 2154)
- `stablePolicyRuleID` (line 2241)
- `userspacePolicyRuleExpansionCount` (line 2245)
- `policyRuleInactive` (line 2268)
- `policyActionString` (line 2279)

Approx LOC = ~140.

### Total function tally

| File | Functions | Approx LOC |
|---|---:|---:|
| builder.go | 4 | ~100 |
| interfaces.go | 16 | ~470 |
| fabric.go | 2 | ~85 |
| mirrors.go | 2 | ~80 |
| tunnels.go | 1 | ~120 |
| zones.go | 2 | ~60 |
| routes.go | 4 | ~210 |
| neighbors.go | 6 | ~210 |
| nat.go | 8 | ~340 |
| screens.go | 5 | ~150 |
| flow.go | 2 | ~70 |
| filters.go | 4 | ~160 |
| cos.go | 1 | ~170 |
| policies.go | 6 | ~140 |
| **Total** | **63** | ~2,365 |

`snapshot.go` HEAD has exactly 63 `^func ` matches per
`grep -nE '^func ' pkg/dataplane/userspace/snapshot.go | wc -l`.
The 63 functions distribute exactly: 4 + 16 + 2 + 2 + 1 + 2 + 4 +
6 + 8 + 5 + 2 + 4 + 1 + 6 = 63. No off-by-one. The grep oracle
must produce zero matches against `snapshot.go` after the move
(file is deleted) and **63 total `^func ` matches across the 14
new files combined**. Implementation walks the grep list to
guarantee no orphans.

### `snapshot.go` deletion

After the moves, `snapshot.go` becomes empty (just `package userspace`
and any orphaned imports) and is **deleted** via `git rm`. Verified
by `git status` showing `D pkg/dataplane/userspace/snapshot.go` and
by `grep -nE '^func ' pkg/dataplane/userspace/snapshot.go` returning
file-not-found.

### Imports per file

Deferred to `goimports -w pkg/dataplane/userspace/*.go`. Plan no
longer asserts per-file import lists — `goimports` produces canonical
imports automatically, and the build gate (`go build ./...`) catches
any miss.

## Public API preservation

Exported symbols that must remain accessible to importers:

- `UserspaceBoundLinuxInterfaces(cfg *config.Config) []string`
  → `interfaces.go`. Callers: `pkg/daemon/daemon_apply.go:1020`,
  `pkg/daemon/daemon_run.go:178`. Daemon imports unchanged.
- `MonitoredInterfaceLinkIndexes(cfg *config.Config) map[int]struct{}`
  → `neighbors.go`. Callers: `pkg/dataplane/userspace/manager.go:1117`
  (internal package call). `daemon_neighbor_listener.go:227` is a
  **comment** referencing the historical call site, not a current
  call — confirmed by reviewers. Same-package call site stays valid.

Unexported helpers used by sibling test files in `package userspace`:
- `buildSnapshot`, `buildSnapshotWithSchedulerState`,
  `buildNeighborSnapshots`, `neighborSnapshotPublishable`,
  `neighborsEqual`, `neighborsEqualForwarding` — all stay in
  `package userspace`, so `snapshot_neighbors_1197_test.go` and
  `snapshot_allowlist_test.go` compile without edits.

## Hidden invariants the change must preserve

1. **Function ordering vs init/build call graph.** Each file is
   internally ordered top-of-graph first (entry points before
   private helpers).

2. **No new package-level vars or init().** `syntheticInterfaceIfindexMin/Max`
   constants move WITH `syntheticLogicalIfindex` into `interfaces.go`.

3. **Allocation behaviour identical.** Each builder still returns
   `nil` when its config sub-tree is empty. `buildSnapshot` on a nil
   cfg still allocates the same 7-field shallow struct. No new
   no-op-path allocation: the moves are pure declaration relocation.

4. **JSON content-hash stability.** `snapshotContentHash` reads
   `tmp.Neighbors = filterPublishableNeighbors(snap.Neighbors)`.
   `filterPublishableNeighbors` lives in `manager.go:959` (NOT moved).
   `builder.go` and `manager.go` are in the same package so the call
   resolves. Hash output across the no-op same-cfg commit MUST be
   byte-identical before and after the refactor; the manager dedup
   test exercises this.

5. **No struct/type definitions move.** All `*Snapshot` types live in
   `protocol.go`. NOT touched.

6. **goimports canonical imports.** Each new file's import block is
   produced by `goimports -w` after the move. `go build ./...` and
   `go vet ./...` clean.

7. **Test files unchanged.** Existing tests reference unexported
   helpers from `package userspace` directly. New files are still in
   `package userspace`, so tests compile without edits.

8. **snapshot.go deletion.** After moves, the file is empty and gets
   `git rm`'d. Final file count: **14 new sibling files + 0 monolith.**

## Risk assessment (unchanged from v1)

| Risk class | Level | Notes |
|---|---|---|
| Behavioural regression | LOW | Pure code motion. No call-site change, no compile-time interface change. |
| Lifetime / borrow-checker | N/A | Go, not Rust. |
| Performance regression | LOW | No inlining boundary moved across packages (still one package). Same machine code. |
| Architectural mismatch | LOW | Direct precedent in PR #1587 (#1547 frr.go split). |
| Merge conflict surface during the refactor itself | MED | snapshot.go has 31-32 commits in 90 days. Mitigated by branching from `origin/master` HEAD and finishing in one PR. |
| Test discoverability | LOW | Production code moves; existing aspect-named test files stay. |

## Test plan

1. `goimports -w pkg/dataplane/userspace/*.go`
2. `go vet ./pkg/dataplane/userspace/...` — clean.
3. `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./pkg/dataplane/userspace/... -count=1` — all pass.
4. `go test ./...` — full Go suite clean.
5. 5× flake check on `snapshot_neighbors_1197_test.go` and `snapshot_allowlist_test.go`.
6. `make build` — daemon binary builds.
7. Wave 4: `<!-- AWAITING-BATCH-MERGE -->` (no per-PR smoke).

## Out of scope (explicitly deferred)

- `SnapshotBuilder` interface introduction. Issue mentions
  "Standardized Interfaces"; precedent (#1587 v2) shows adding an
  interface in the same PR draws PLAN-KILL pressure. Follow-up
  issue.
- `filterPublishableNeighbors` move from `manager.go`. Used from
  4 manager.go call sites + 1 process.go + 1 snapshot.go
  (snapshotContentHash) + 1 test. Moving it expands scope and
  rewrites all callers for no win. Cross-file dependency within
  the same package is fine; the only consumer that lands in a new
  sibling file is `snapshotContentHash` in builder.go, and that
  resolves at compile time without any import change.
- Test file moves/renames. Existing aspect-named tests stay.
- Sub-package extraction. Breaks unexported helper sharing.
- Type definition moves. `protocol.go` is untouched.

## Open questions for adversarial review (v3)

1. Is 14 files the right count, or still off? Evolution: round-1
   proposed 9; round-1 reviewers converged on 11 (Antigravity +
   Gemini); v2 went to 14 by additionally splitting fabric.go,
   mirrors.go, tunnels.go out of interfaces.go per Codex.
   Reviewer may prefer the 13-file collapse (tunnels back into
   interfaces). Defended: tunnels are a distinct config sub-tree
   (`unit.Tunnel`, `iface.Tunnel`) and the function is ~120 LOC
   standalone; merging tunnels back into interfaces.go would push
   interfaces.go past the ~500 LOC cap reviewers asked us to
   defend.

2. Should `neighbors.go` also absorb `filterPublishableNeighbors`
   from `manager.go`? Plan says no (out of scope), but the
   counter-argument is that the publishable predicate
   (`neighborSnapshotPublishable`) and the filter
   (`filterPublishableNeighbors`) are the same logic — splitting
   them is a minor smell. Reviewer call.

3. `builder.go` filename: bare `builder.go` is generic. Alternatives:
   `compile.go`, `compose.go`. Reviewer call.

4. Is moving `userspaceMapPins` to `builder.go` correct, or does it
   belong in `interfaces.go` (since the pins are interface-adjacent
   in concept)? Plan keeps it in `builder.go` because the orchestrator
   uses it.

5. Worth merging at all? Round-1 empirical check returned 31-32
   commits in 90 days — verified merge-conflict premise. Reviewers
   judged the win is real.

## Reviewer task IDs

Recorded in `docs/pr/1439-snapshot-builders/reviewer-ids.md`.
- Round 1: Codex `task-mpn5xksb-unj08f`, Gemini `task-mpn5y4dq-yydg6k`,
  Antigravity `review-mpn5yls7-nbyi2u`.
- Round 2: Codex `task-mpn67k1p-5jeu4s`, Gemini `task-mpn680k0-o6i3zb`,
  Antigravity `review-mpn6800x-lpplct`.
