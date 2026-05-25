# #1521 — eBPF retirement: decouple userspace maps_sync from legacy BPF map names (sub-#1451 S6)

## Status

PLAN-READY v2 — Codex r1 + Antigravity r1 both addressed.
Codex r1: 5 ACCEPT (HIGH-1 call-site recount, HIGH-2 AST canary,
MEDIUM-1 reframe boundary, MEDIUM-2 loader parity, MEDIUM-3 hard-fail
on read err) + 1 DEFER (LOW-1 shared mapnames package).
AGY r1: PLAN-NEEDS-MAJOR with two actionable items — AST canary
(same as Codex HIGH-2, addressed Step 3) + factual correction on
"public-API constant" wording (now corrected to "package-private"
in Step 2). AGY confirmed: package-private choice correct, no
collision with #1520, rename drift detected via cap test + injected-
literal unit tests. Ready to implement.

## Issue framing

`pkg/dataplane/userspace/maps_sync.go` (~1561 LOC) reaches into the
BPF map collection by string literal for eleven distinct map names
that were originally chosen under the legacy eBPF pipeline naming
convention. The maps themselves are owned by the AF_XDP userspace
shim (`userspace-xdp/`), not the legacy XDP/TC pipeline, but the
shared pin-path and loader code that materializes them still lives
in legacy `pkg/dataplane/` and therefore the same string literals
appear in two places: the userspace-side consumer
(`pkg/dataplane/userspace/maps_sync.go` + adjacent
`process.go`/`manager_ha.go`) and the legacy loader
(`pkg/dataplane/loader_ebpf.go` + `pkg/dataplane/dataplane.go`).

The #1451 decomposition document (`docs/pr/1451-migration-scope/scope.md`)
assigns this slice **S6** to decouple the userspace control-plane
side: define the map names as constants owned by the userspace
package, route every userspace-side consumer through the constants,
and add a regression canary so a future literal reintroduction
fails CI. The legacy loader keeps its string literals for now —
#1476 will retire the pinning itself once #1473 (XDP shim split)
has moved map ownership off the legacy loader.

This PR is **strictly the userspace-side decouple**. It does not
move any map ownership, does not rename any BPF map, does not
change pin paths, and does not modify the wire format. It is pure
code motion plus one regression canary.

## Honest scope/value framing

The win at absolute scale is **zero runtime impact**. There is no
hot-path code being touched. The maps are looked up once at config
apply, snapshot push, helper bringup, and HA failover boundaries —
all cold paths.

The win is **structural**: it lets #1476 retire the legacy pinning
without grep-and-pray across 1500+ LOC of userspace control-plane
code. Without S6, #1476 has to land a much larger mechanical churn
under the legacy-retirement banner, mixing "rename map name" with
"remove pinning" in the same PR. Splitting that out here makes the
#1476 diff legible and the #1473 shim-split tractable.

**If reviewers conclude the structural value is too small to justify
the churn, PLAN-KILL is an acceptable verdict.** The status quo
works; this is hygiene for the staged retirement.

## What's already shipped / partially batched

- **PR #1514** (Refs #1509): renamed the operator-facing surface for
  the retained-shim degraded-path counters from "fallback" to
  "degraded path", but explicitly kept the **pinned BPF map name
  `userspace_fallback_stats`** stable as a documented internal
  mixed-version compatibility exception. That exception is encoded
  in `pkg/dataplane/userspace/maps_sync.go:705` as:
  ```go
  const userspaceShimDegradedStatsMapName = "userspace_fallback_stats"
  ```
  and pinned by `maps_sync_cap_test.go:44` with a hard equality
  assertion against the literal string. **This plan preserves that
  exception verbatim**: the constant becomes part of the new
  registry but its string value does not change, and the cap test
  is updated only to point at the new symbol name.

- **Sibling S5 / S4 PRs (#1520, #1519, #1518, #1517, #1516)** are
  decomposing other slices of the same `pkg/dataplane/userspace/`
  surface. **Coordination touch surface**: this PR only modifies
  `maps_sync.go`, `process.go`, `manager_ha.go`, adds one new file
  (`maps.go`), and updates the cap-test reference. If #1520 (boot
  path) extracts any map-load code path, we rebase on master and
  re-grep before merge.

- The legacy `pkg/dataplane/loader_ebpf.go` (line 236+, 602+)
  enumerates the same eleven map names in its pinning rosters.
  **This PR does NOT touch loader_ebpf.go** — it is legacy and
  scheduled for deletion under #1476. Decoupling the consumer side
  without touching the loader side is the entire point.

## Concrete design

### Step 1: new file `pkg/dataplane/userspace/maps.go`

A tiny registry file (estimated ~80 LOC) that holds the eleven map
names as unexported package-level constants. The registry is a
**Go-side single source of truth for the userspace package** — it
turns *new* literal reintroductions inside `pkg/dataplane/userspace/`
into a CI failure via the Step 3 AST canary. It does **not** prevent
drift against the Rust helper's BPF object names or the legacy
loader's literals (those remain runtime failure modes); the Step 3b
parity canary closes the loader-side gap during the #1476 window.

```go
// Package userspace map-name registry.
//
// These constants enumerate every BPF map name consumed by the
// userspace control plane (maps_sync.go, process.go,
// manager_ha.go) so map-name drift between the Rust helper
// (userspace-xdp/) and the Go control plane is a compile-time
// failure rather than a runtime "map not loaded" error.
//
// The legacy loader at pkg/dataplane/loader_ebpf.go still
// enumerates these names by literal. Once #1476 retires legacy
// pinning, those literals go away with the loader; this file
// becomes the sole source of truth.
package userspace

const (
    // Control / liveness maps consumed at helper bringup.
    mapNameUserspaceCtrl       = "userspace_ctrl"
    mapNameUserspaceBindings   = "userspace_bindings"
    mapNameUserspaceHeartbeat  = "userspace_heartbeat"
    mapNameUserspaceXSK        = "userspace_xsk_map"
    mapNameUserspaceCPUMap     = "userspace_cpumap"
    mapNameUserspaceSessions   = "userspace_sessions"

    // Per-interface address + NAT maps consumed at snapshot apply.
    mapNameUserspaceIngressIfaces  = "userspace_ingress_ifaces"
    mapNameUserspaceLocalV4        = "userspace_local_v4"
    mapNameUserspaceLocalV6        = "userspace_local_v6"
    mapNameUserspaceInterfaceNATv4 = "userspace_interface_nat_v4"
    mapNameUserspaceInterfaceNATv6 = "userspace_interface_nat_v6"

    // Pinned BPF map name retained as a documented mixed-version
    // compatibility exception per PR #1514 (Refs #1509). Operator-
    // facing terminology is "degraded path" but the pinned map
    // name stays stable to preserve the rolling-upgrade window
    // until the canary alias retires.
    mapNameUserspaceShimDegradedStats = "userspace_fallback_stats"
)
```

All constants are unexported (`mapName...`) because the legacy
loader at `pkg/dataplane/loader_ebpf.go` lives in a different Go
package (`dataplane` vs `dataplane/userspace`) and would create an
import cycle if it tried to consume them. The legacy side keeps
its own literals until #1476 deletes it; the userspace side gains
a single source of truth. This is intentional: the constants are
package-private to enforce the boundary the issue is creating.

### Step 2: rewrite consumers

**`pkg/dataplane/userspace/maps_sync.go`** — **16** `bpfShim.Map("userspace_<name>")`
call sites (lines 65, 69, 73, 129, 195, 238, 261, 265, 275, 480, 785,
816, 820, 919, 923, 1068) rewritten to `m.bpfShim.Map(mapName...)`.
The existing unexported (package-private) constant
`userspaceShimDegradedStatsMapName` at `maps_sync.go:705` is renamed
to `mapNameUserspaceShimDegradedStats` and moved into the new
`maps.go` registry; its call site at line 736 follows the rename.
(AGY r1 noted v1 wording incorrectly called it "public-API" — it is
package-private; the value is what's pinned for mixed-version
compatibility, not the symbol name.)

The `errors.New(...)` / `fmt.Errorf(...)` messages around these call
sites keep their existing literal-prose strings (e.g.
`"userspace_ctrl map not loaded"`, `"update userspace_local_v4 %08x:
%w"`) because they are operator-facing log content that ops greps
against journald output. The AST-semantic canary (Step 3, revised)
distinguishes lookup keys from log prose explicitly.

**`pkg/dataplane/userspace/process.go`** — 3 references at lines
66, 911, 929 rewritten the same way (`userspace_xsk_map`,
`userspace_ctrl`, `userspace_ctrl`).

**`pkg/dataplane/userspace/manager_ha.go`** — 1 reference at line
215 is a comment only (`// Startup settle and XSK bring-up are now
controlled by userspace_ctrl`). The comment is updated to refer
to the constant by name so future readers find the registry, but
the literal string in the comment is also left as a backup
breadcrumb.

### Step 3: regression canary — AST-semantic

New unit test in `pkg/dataplane/userspace/maps_decouple_test.go`
that walks the package source tree using `go/parser` + `go/ast` and
fails if any `.go` file other than `maps.go` contains a `Map(<basic
string literal>)` call where the string starts with `"userspace_"`.
This is AST-semantic — it only inspects actual call expressions, so
operator-facing log prose like `"update userspace_local_v4 %08x:
%w"` is not flagged. It also catches any *new* literal a future PR
introduces, even if it's a map name not currently in the registry.

Implementation sketch (full implementation in PR):

```go
func TestNoLiteralMapNamesOutsideRegistry(t *testing.T) {
    fset := token.NewFileSet()
    pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
        // Walk all .go files including tests; tests may legitimately
        // reference the names by literal for assertion clarity, but
        // they must NOT invoke .Map(<literal>) in non-test code.
        return true
    }, parser.ParseComments)
    if err != nil {
        t.Fatalf("parse dir: %v", err)
    }
    var violations []string
    for _, pkg := range pkgs {
        for path, file := range pkg.Files {
            if filepath.Base(path) == "maps.go" {
                continue // registry owns the literals
            }
            isTest := strings.HasSuffix(path, "_test.go")
            ast.Inspect(file, func(n ast.Node) bool {
                call, ok := n.(*ast.CallExpr)
                if !ok {
                    return true
                }
                sel, ok := call.Fun.(*ast.SelectorExpr)
                if !ok || sel.Sel.Name != "Map" {
                    return true
                }
                if len(call.Args) != 1 {
                    return true
                }
                lit, ok := call.Args[0].(*ast.BasicLit)
                if !ok || lit.Kind != token.STRING {
                    return true
                }
                // Strip the surrounding quotes.
                s, err := strconv.Unquote(lit.Value)
                if err != nil || !strings.HasPrefix(s, "userspace_") {
                    return true
                }
                pos := fset.Position(lit.Pos())
                if isTest {
                    // _test.go files are allowed to reference the literal
                    // in assertion helpers (e.g. cap test); skip.
                    return true
                }
                violations = append(violations,
                    fmt.Sprintf("%s:%d: forbidden literal map name %q in .Map() call outside registry",
                        pos.Filename, pos.Line, s))
                return true
            })
        }
    }
    if len(violations) > 0 {
        t.Fatalf("AST canary violations:\n  %s", strings.Join(violations, "\n  "))
    }
}
```

Notes:
- AST-semantic, so it precisely catches `Map(<literal>)` and ignores
  string literals in `errors.New`, `fmt.Errorf`, comments, or other
  log-prose contexts. This responds directly to Codex r1 HIGH-2.
- Catches reintroductions via raw string literals (`` `userspace_x` ``)
  because `strconv.Unquote` handles both quoted forms.
- Catches names not yet in the registry too — any new `Map("userspace_*")`
  literal fails CI, forcing the author to add a registry entry first.
- Test files are skipped on the `.Map()` rule but the cap test
  (`maps_sync_cap_test.go`) is unaffected because its assertion is
  a literal-equality compare, not a `.Map()` call.
- File discovery uses `parser.ParseDir(".")`, which fails hard on
  read/parse errors (vs the v1 sketch's silent error swallowing —
  Codex r1 MEDIUM-3).

### Step 3b: duplicated-name parity canary (Codex r1 MEDIUM-2)

A second unit test in the same file pins the eleven (+1 retained)
constants against the literal strings the legacy loader at
`pkg/dataplane/loader_ebpf.go` currently uses. The test reads the
loader file from a known relative path (`../loader_ebpf.go`) and
parses it for `Pin: "userspace_..."` / `bpfMap{Name: "userspace_..."}`
constructs; for each registry constant the test asserts that the
literal string appears at least once in the loader source. This is a
short-lived consistency canary that goes away with #1476 (loader
deletion) but in the meantime prevents one side renaming a map and
silently breaking bringup.

Implementation sketch:

```go
func TestRegistryParityWithLegacyLoader(t *testing.T) {
    loaderPath := "../loader_ebpf.go"
    body, err := os.ReadFile(loaderPath)
    if err != nil {
        // Loader deleted by #1476 — parity check no longer needed.
        t.Skipf("loader_ebpf.go absent (#1476 retired the loader?): %v", err)
        return
    }
    for _, name := range []string{
        mapNameUserspaceCtrl, mapNameUserspaceBindings,
        mapNameUserspaceHeartbeat, mapNameUserspaceXSK,
        mapNameUserspaceCPUMap, mapNameUserspaceSessions,
        mapNameUserspaceIngressIfaces, mapNameUserspaceLocalV4,
        mapNameUserspaceLocalV6, mapNameUserspaceInterfaceNATv4,
        mapNameUserspaceInterfaceNATv6, mapNameUserspaceShimDegradedStats,
    } {
        if !bytes.Contains(body, []byte(`"`+name+`"`)) {
            t.Errorf("registry constant %q not found in legacy loader %s — "+
                "parity broken (either rename both sides or update this canary)",
                name, loaderPath)
        }
    }
}
```

The test `Skip`s if `loader_ebpf.go` is deleted (i.e. #1476 lands),
so it self-retires cleanly.

### Step 4: cap-test pointer update

`pkg/dataplane/userspace/maps_sync_cap_test.go:44` currently:

```go
if got := userspaceShimDegradedStatsMapName; got != "userspace_fallback_stats" {
```

becomes:

```go
if got := mapNameUserspaceShimDegradedStats; got != "userspace_fallback_stats" {
```

The hard equality assertion against the literal string is
**preserved verbatim** to keep PR #1514's mixed-version
compatibility lock in place. The only change is the symbol name on
the left side.

## Public API preservation

- No public Go API changes. All registry constants are unexported.
- No exported function signatures change.
- No exported types change.
- No protobuf or wire-format changes.
- No JSON field renames (PR #1514 already owned the
  `degraded_path_counters` rename).
- No CLI command tree changes.
- No Prometheus metric name changes.

## Hidden invariants the change must preserve

1. **`userspace_fallback_stats` pinned map name stays stable.**
   This is the documented mixed-version compatibility exception
   from PR #1514. The constant value is preserved verbatim and
   the cap test still asserts equality against the literal
   string. Rolling-upgrade window across the #1509 → #1521
   transition is not narrowed.

2. **Side-effect ordering preserved.** All consumer sites are
   pure `Map(name)` lookups followed by `Lookup`/`Update`/`Delete`
   calls. Replacing the name argument with a constant is identity
   at runtime. No `init()` ordering is introduced.

3. **No new allocations on hot paths.** Constants are compile-time
   string headers; the lookup signature `Map(string)` is unchanged.
   No hot path runs through any of these call sites anyway, but
   the no-alloc invariant is preserved trivially.

4. **HA sync portability.** The Rust helper consumes the same
   map names from its BPF object via `bpf2go`-derived bindings.
   This PR does not touch the Rust side, does not rename the BPF
   map, and does not change the pin path. HA peers running mixed
   versions across this change continue to share map state via
   identical pinned names.

5. **Legacy loader compatibility.** `pkg/dataplane/loader_ebpf.go`
   still enumerates the eleven names by literal in its pin-creation
   roster. Both sides agree on the strings because both reference
   the same wire constants; this PR introduces a Go-side single
   source of truth on the userspace package boundary only. Until
   #1476 deletes the legacy loader, the strings exist twice. **This
   duplication is intentional** to keep the legacy loader self-
   contained for its eventual mechanical deletion.

6. **No GC / iter / shared-map state churn.** Nothing about the
   maps' lifecycle changes.

7. **Build-time invariant.** If a future PR adds a `Map("...")`
   call with a forgotten literal, the canary test fails with a
   precise file:line pointer.

## Risk assessment

| Class | Risk |
|---|---|
| Behavioral regression | **LOW.** Pure code motion. String constants substituted for string literals; identical runtime semantics. |
| Lifetime / borrow-checker | **N/A.** Go, not Rust. No new ownership boundaries introduced. |
| Performance regression | **NONE.** No hot path touched. Constants are not allocated. |
| Architectural mismatch | **LOW-MEDIUM.** The classic #946-Phase-2 / #961 dead-end pattern is "rearrange a hot path that turns out to be order-coupled and can't actually batch". This PR rearranges no hot path and introduces no batching. The only architectural question is "is the unexported package-private registry the right boundary, or should it be a public sub-package consumed by the legacy loader too?" The plan picks unexported because consuming the constants from `pkg/dataplane/loader_ebpf.go` would create an import cycle (`dataplane` already imports `dataplane/userspace`-adjacent types via `pkg/dataplane`'s shared interface). Reviewers are explicitly invited to argue the public-sub-package shape if they think the duplication during the #1476 window is worse than the cycle risk. |
| Mixed-version rolling upgrade | **NONE,** by virtue of the cap-test pin. |

## Test plan

1. `go vet ./...` — clean.
2. `go test ./pkg/dataplane/...` — green, including the new canary
   test and the existing `maps_sync_cap_test.go`.
3. `go test ./pkg/dataplane/userspace/... -run TestNoStringLiteralMapNamesOutsideRegistry -count=5` — 5/5 pass.
4. Full Go suite `go test ./...` — all 30 packages green.
5. Deploy to loss userspace cluster:
   `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./test/incus/cluster-setup.sh deploy all`
6. **Cold start verification** (the issue's required smoke evidence):
   stop xpfd on both nodes, clear any pinned maps, restart, verify
   that map bringup succeeds and HA peering converges. The issue
   text calls this out explicitly because map-name drift would
   silently break bringup.
7. Smoke matrix on loss userspace cluster:
   - **Pass A — CoS disabled** (best-effort fast path):
     - v4 push + reverse against 172.16.80.200
     - v6 push + reverse against 2001:559:8585:80::200
     - `-P 12 -t 10 -R` multi-stream reverse on both — line rate, 0 retrans
   - **Pass B — CoS enabled** (per-class):
     - `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0`
     - v4 + v6 × push + reverse × 6 ports (5201–5206) = 24 cells
8. (Optional) perf measurement to confirm zero hot-path impact. The
   change is structurally non-hot so this is skip-able if reviewers
   agree.

## Out of scope (explicitly)

- **Legacy loader cleanup** (`pkg/dataplane/loader_ebpf.go` literals).
  Owned by #1476 once the loader itself retires.
- **Rust helper / `userspace-xdp/` side.** The BPF map names live
  in the BPF object; this PR does not touch the Rust side.
- **Renaming `userspace_fallback_stats`.** Pinned for mixed-version
  compatibility per PR #1514.
- **Public sub-package extraction.** If a future PR wants to share
  the registry with the legacy loader, the constants can be
  uppercased and re-exported. For now they are package-private to
  prevent the duplication discussion from sprawling.
- **Moving map ownership off the legacy loader.** Owned by #1473.

## Open questions for adversarial review

1. **Is the package-private constants choice correct?** The
   alternative is a public sub-package
   (`pkg/dataplane/userspace/mapnames/`) that the legacy loader
   also consumes, eliminating the duplication for the #1476
   window. Arguments against: it requires changing the legacy
   loader (out of scope per issue text), it introduces an import
   dependency in code that is scheduled for deletion, and a
   compile-time cycle between `dataplane` and `dataplane/userspace`
   may exist depending on how `pkg/dataplane`'s shared dataplane
   interface is wired. **PLAN-KILL invitation**: if reviewers
   judge the duplication during the #1476 window worse than the
   sub-package risk, kill this plan.

2. **Is the canary regex correct?** The plan uses quoted-string
   matching to spare operator-facing format strings like `"update
   userspace_local_v4 %08x: %w"`. Reviewers should check whether
   any legitimate `Map(...)` call in the package uses a
   computed/concatenated string that would slip past the canary.
   I read all 13 + 3 + 1 sites; all are bare string literals.

3. **Is `maps_sync_cap_test.go`'s preserved literal-equality
   assertion still load-bearing?** The test pins
   `userspace_fallback_stats` to its exact string value to detect
   a future rename. After this PR, the assertion compares
   `mapNameUserspaceShimDegradedStats == "userspace_fallback_stats"`
   — same semantic, different symbol. Is that drift-detection still
   as load-bearing, or should the cap test instead reference a
   *different* registry-internal value to prove the registry
   exists?

4. **Does the issue's "cold-start of xpfd on both nodes" smoke
   requirement need a specific test harness?** I read the issue
   as "deploy + restart + verify HA peering converges" which the
   loss userspace cluster does naturally. Is there a sharper test
   I should run that proves cold-start specifically against this
   change?

5. **Should the constants enumerate more than the eleven map
   names?** I limited the registry to names referenced from
   `pkg/dataplane/userspace/*.go`. The legacy
   `loader_ebpf.go:236-247` and `:602-614` rosters add
   `userspace_trace` and `userspace_fallback_progs` (the latter
   from the issue body's example list) which are loader-only
   today. Should the registry preemptively cover those, even
   though no userspace consumer references them yet, to make
   #1476's eventual cutover a one-liner? Or does that violate
   "minimize change footprint" and tee up a #1473-side
   surprise?

6. **Coordination collision with #1520.** Sibling agent on #1520
   may extract boot-path map-load code paths. If #1520 lands
   first and migrates any of the lookup call sites into a new
   file, this PR's grep targets shift. Plan is "rebase + re-grep
   before merge", but reviewers should flag if they see a known
   call site #1520 is about to move.

7. **Sufficiency of the smoke matrix for a non-hot-path change.**
   The full 30-cell smoke matrix exists to catch shaper /
   classifier / TX-path regressions. This PR touches none of
   those code paths. Is the full matrix overkill, or is it
   load-bearing as a "we did not break cold-start" sanity
   gate per the issue's smoke requirement?
