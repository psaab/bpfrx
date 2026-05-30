# #1687 — Shared NAT presentation seam (re-scoped)

**Status:** PLAN-READY v3 — round-2 converged (AGY PLAN-READY; Codex
PLAN-NEEDS-MINOR, both minors folded in below). Universal
shared-presentation package KILLED; bounded shared NAT renderer
(`pkg/natshow`) APPROVED for implementation.

## Round-2 verdicts

- **AGY (adversarial-review-mpsgrpyp-6vmsdo): PLAN-READY.** Reversed its
  round-1 misread after reading the leaf bodies directly; verified all
  six leaf renderers byte-identical under sink normalization, the
  `Reader` interface exact, and zero import-cycle risk.
- **Codex (task-mpsgrdwm-mvt55w): PLAN-NEEDS-MINOR**, two items now
  folded in:
  1. **`nat-dest-rule-detail` leaf precondition.** The gRPC leaf
     guards `cfg == nil || cfg.Security.NAT.Destination == nil ||
     len(...RuleSets) == 0` and emits `"No destination NAT rules
     configured\n"` (server_show_nat.go:195-199). The CLI leaf
     (`showNATDestinationRuleDetail`, cli_show_nat.go:904) assumes its
     dispatcher (`showNATDestination`, cli_show_nat.go:551-554) already
     guarded `cfg == nil || Destination == nil` (emitting the
     period-suffixed dispatcher message). **Resolution:** the shared
     `RenderDestRuleDetail` adopts the **gRPC full guard verbatim**
     (the gRPC behavior is the contract under test). The CLI dispatcher
     keeps its existing pre-guard unchanged; for the non-empty path it
     reaches the shared func which renders identically. The CLI golden
     test asserts the dispatcher path is byte-identical to master.
  2. **#1451 retirement-boundary canary.** `pkg/natshow` importing root
     `pkg/dataplane` (unavoidable — the session-iteration callbacks use
     `dataplane.SessionKey/Value`, and `ReadNATRuleCounter`/
     `GetPersistentNAT` return `dataplane.CounterValue`/
     `*dataplane.PersistentNATTable`) is flagged by
     `TestOperatorPackagesOnlyUseDocumentedLegacyDataplaneImports`
     (retirement_boundary_canary_test.go:118) unless added to
     `legacyDataplaneImportAllowlist` (line 31) AND the #1451 docs table
     in `docs/pr/1373-retire-ebpf-dataplane/README.md:251`.
     **Resolution:** add `pkg/natshow/*.go` files that import dataplane
     to both, with the explicit design reason: "shared NAT presenter
     extracted from server_show_nat.go + cli_show_nat.go (#1687); still
     names root pkg/dataplane session/counter types until those move to
     a domain package — net-neutral, consolidates two pre-existing
     allowlisted surfaces." This is not #1451 regressing: the renderers
     already lived in two allowlisted files; the import moves with them.

## Round-1 verdicts and resolution

- **Codex (task-mpsghlr7-3p2gg5): PLAN-NEEDS-MAJOR.** "Kill the
  universal shared renderer (security topics genuinely diverge), but
  the kill is over-broad — there is a real, clean shared seam for the
  NAT/status subset. The non-trivial walk (session counting + zoneByID)
  is duplicated and *identical* between gRPC and CLI."
- **AGY (adversarial-review-mpsgi8ie-81h4g8): PLAN-KILL.** Agreed the
  security topics diverge, but dismissed the NAT subset as having "a
  complex dispatcher hierarchy (summary/pool/rule-set/rule/detail)."

**Resolution (evidence, not vote-count):** AGY's NAT dismissal is wrong.
It conflated the CLI *dispatcher wrapper* (`showNATSource`'s
sub-command router, which sends `summary`/`pool`/`rule-set`/`detail` to
*different leaf functions*) with the *leaf renderer*
`showNATSourceRuleDetail` itself. I diffed the leaf bodies after
normalizing only the output sink (`fmt.Fprintf(buf,…)` vs
`fmt.Printf(…)`) and the `return`/`return nil` wrapper:

| Topic | gRPC | CLI | Rendering body |
|-------|------|-----|----------------|
| `nat-source-rule-detail` | server_show_nat.go:99 | cli_show_nat.go:455 | **byte-identical** |
| `nat-dest-rule-detail` | server_show_nat.go:195 | cli_show_nat.go:904 | **byte-identical** |
| `persistent-nat-detail` | server_show_nat.go:279 | cli_show_nat.go:1062 | **byte-identical** |

The *only* diffs are: (1) the receiver/sink in the signature — exactly
what a shared `Render(w io.Writer, …)` abstracts; (2) `return` vs
`return nil`; (3) reworded doc-comments describing identical code; (4)
`Fprintf(buf,"…%d\n\n")` vs `Printf("…%d\n")+Println()`, which emit
identical bytes. Zero divergence in emitted strings or in the
session/zone walk. This is sink-only duplicate rendering — a real seam,
NOT the #961/#1544 dead-end. Codex's verdict stands; this plan adopts
it. (Memory: AGY is documented low-signal on file-motion refactors —
feedback_gemini_low_signal_on_refactor; the dispatcher-vs-leaf misread
is that pattern.)

The simpler NAT tables (`nat-static`, `nat-nptv6`, `persistent-nat`)
ALSO diff only by sink + wrapper, but their bodies are short (~15-25
lines each) and they form a coherent family with the detail renderers,
so they are included for a clean per-topic seam.

## Final scope (what this PR does)

**KILL** the universal "shared security/NAT/flow presentation package"
premise. Security topics (`alg`, `address-book`, `applications`,
`screen-ids-option`, `ike`, `security-log`, `dynamic-address`) are
genuinely divergent operator contracts (different headers, column
widths, field syntax, feature sets, sub-commands, runtime sources) and
are explicitly PRESERVED as-is. The byte-identical invariant the issue
states is already false for those topics on master; forcing them into a
shared renderer would regress one consumer (the #961 pattern). This is
documented and NOT attempted.

**BUILD** a bounded shared NAT renderer package, `pkg/natshow/`, with
sink-only `Render*` functions for the six byte-identical NAT topics.
Both consumers rewire onto it; output is proven byte-identical
before/after by golden tests on BOTH the gRPC `ShowText` path and the
CLI show path.

### Package shape (module-dir layout)

`pkg/natshow/` — files by aspect:
- `natshow.go` — package doc + the narrow `Reader` interface + shared
  helpers (`zoneByID`, session-count walks).
- `static.go` — `RenderStatic`, `RenderNPTv6`.
- `source.go` — `RenderSourceRuleDetail`.
- `dest.go` — `RenderDestRuleDetail`.
- `persistent.go` — `RenderPersistent`, `RenderPersistentDetail`.

### Narrow reader interface (both runtimes already satisfy it)

```go
// pkg/natshow/natshow.go
type Reader interface {
    IsLoaded() bool
    IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
    IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
    ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error)
    GetPersistentNAT() *dataplane.PersistentNATTable
}
```

Verified: `grpcRuntime` (pkg/grpcapi/runtime.go:12) and `cliRuntime`
(pkg/cli/runtime.go:28) both declare every method above, so both `dp`
fields satisfy `natshow.Reader` structurally. `*dataplane.ApplyResult`
and `*config.Config` are the same concrete types on both sides
(apply_result.go:5, cli.go:122).

### Function signatures (sink = io.Writer)

```go
func RenderSourceRuleDetail(w io.Writer, cfg *config.Config, dp Reader, cr *dataplane.ApplyResult)
func RenderDestRuleDetail(w io.Writer, cfg *config.Config, dp Reader, cr *dataplane.ApplyResult)
func RenderPersistentDetail(w io.Writer, dp Reader)
func RenderPersistent(w io.Writer, dp Reader)
func RenderStatic(w io.Writer, cfg *config.Config)
func RenderNPTv6(w io.Writer, cfg *config.Config)
```

A nil `dp`/`cr` reproduces the existing "not loaded" branches. The
gRPC side passes `&buf` (a `*strings.Builder` is an `io.Writer`); the
CLI side passes `os.Stdout` (or `c.out` if present) — preserving the
exact stdout behavior. The trailing-newline shape is normalized to the
gRPC form (`…\n\n`), which is byte-identical to the CLI's
`Printf("…\n")+Println()`.

### Rewiring

- gRPC `server_show_nat.go`: each `(s *Server) showNATxxx(... buf)`
  becomes a one-line `natshow.RenderXxx(buf, cfg, s.dp, s.applyResult())`.
- CLI `cli_show_nat.go`: each `(c *CLI) showNATxxx(...)` becomes
  `natshow.RenderXxx(c.out, cfg, c.dp, c.applyResult()); return nil`
  (the CLI dispatcher sub-command routing in `showNATSource`/
  `showNATDestination` is UNCHANGED — only the leaf renderer bodies move).

## Commit increments (no monolithic add; true merge commit)

1. `pkg/natshow/` package + narrow Reader interface + shared helpers
   (builds clean, no consumers yet).
2. Rewire `pkg/grpcapi/server_show_nat.go` onto `natshow`.
3. Rewire `pkg/cli/cli_show_nat.go` onto `natshow`.
4. Golden tests: gRPC `ShowText` + CLI show path, byte-identical
   assertions for all six topics, captured against master output.
5. Regen `docs/refactoring-audit-current.txt`; doc updates.

## Public API preservation

No exported gRPC RPC or CLI command signature changes. Only unexported
renderer bodies move to a new package. `ShowText` topic strings and CLI
command grammar unchanged.

## Hidden invariants

- Output of every rewired topic on BOTH consumers must be
  byte-identical to master (golden tests enforce).
- CLI prints to its writer; gRPC accumulates into `*strings.Builder`.
  Shared funcs take `io.Writer` — both satisfied.
- Session-count walk semantics (forward-only `IsReverse==0`,
  `SessFlagSNAT`/`SessFlagDNAT`, zone-by-ID mapping, v4+v6) preserved
  verbatim — moved, not rewritten.

## Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | **LOW** | Pure sink-parameterized code motion of byte-identical bodies; golden tests on both consumers gate it. |
| Lifetime / aliasing (Go) | LOW | No new shared mutable state; `dp`/`cr` read-only. |
| Performance | N/A | Control-plane show path. |
| Architectural mismatch (#961/#1544) | **LOW** | Verified byte-identical bodies + narrow interface both runtimes already satisfy; not a branch-everywhere fork. Security topics correctly excluded. |

## Test plan

- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — all green.
- New golden tests in `pkg/grpcapi` and `pkg/cli` asserting the six NAT
  topics' output is byte-identical to a master-captured fixture, on
  both consumers.
- `make audit-check` green on rebased branch; regen
  `docs/refactoring-audit-current.txt` (server_show_nat.go and
  cli_show_nat.go both shrink).
- **No cluster smoke** — this is pure control-plane gRPC/CLI
  presentation, no dataplane / per-packet path. Stated explicitly in
  the PR so the smoke-runner does not block.

## Out of scope (explicitly)

- Security/flow topics (`alg`, `address-book`, `applications`,
  `screen-*`, `ike`, `security-log`, `dynamic-address`) — divergent
  contracts, PRESERVED as-is.
- Any unification of CLI vs gRPC output for divergent topics (behavior
  change; needs its own issue + operator sign-off).
- The broader grpcapi package restructure (#1661 addendum-4/9).
- `filterTermExpansionCount` dedup — below noise floor, not touched
  unless a firewall renderer seam is opened (it is not, here).
- #1686 (dataplane/maps.go) — disjoint scope.

## Open questions for round-2 adversarial review

1. Is `pkg/natshow/` the right home, or should the shared renderer live
   under an existing neutral package to avoid a new top-level import
   edge? (It must not import `grpcapi` or `cli` — only `config` +
   `dataplane`.)
2. Are the six NAT topics the complete byte-identical set, or did I
   miss one (e.g. `nat64`)? Diff any candidate before claiming it.
3. Does normalizing the trailing-newline to the gRPC `\n\n` form change
   ANY consumer's bytes? (Claim: no — `Printf("…\n")+Println()` ==
   `Fprintf("…\n\n")`. Refute with a counter-example if wrong.)
4. Is the narrow `Reader` interface correct, or does any renderer touch
   a `dp` method not in it (e.g. `ReadNATPortCounter`,
   `ReadGlobalCounter`)? Verify against both function bodies.
5. Does excluding the security topics leave #1687 meaningfully
   addressed, or should the issue be partially closed with a follow-up
   for the divergent topics?

## Pre-resolved before round 2 (author verification)

- **Q2/Q4 resolved.** The six in-scope gRPC renderers (server_show_nat.go
  lines 22-355) call exactly: `GetPersistentNAT`, `IsLoaded`,
  `IterateSessions`, `IterateSessionsV6`, `ReadNATRuleCounter` — the
  `Reader` interface above is exact (no `ReadNATPortCounter` /
  `ReadGlobalCounter` in scope; those belong to *other* CLI NAT
  functions like the summary/pool views that stay put).
- **`nat64` is NOT byte-identical and is EXCLUDED:** gRPC emits
  `"No NAT64 rule-sets configured\n"` (server_show_nat.go:358) while CLI
  emits `"No NAT64 rule-sets configured."` (cli_show_nat.go:1017) — a
  trailing-period divergence. The six topics are the complete
  byte-identical set.
