# #1517 — Migrate pkg/cli off legacy `dataplane.DataPlane` (sub-#1451 S2)

**Status:** DRAFT v1 — pending adversarial plan review.

Refs: #1517 (this), #1451 (parent), #1373 (eBPF retirement). Sub-issue
scope doc: `docs/pr/1451-migration-scope/scope.md`. Parallels sub-#1516
(grpcapi) — sibling agent driving that PR in parallel; this branch
touches **only** `pkg/cli/`.

## 1. Issue framing

`pkg/cli/cli.go` stores `cli.dp dataplane.DataPlane` and `New(...)`
takes a `dataplane.DataPlane` parameter. The interactive Junos CLI is
the second of two large operator surfaces still importing the full
legacy interface directly (the first is `pkg/grpcapi`, sub-#1516).

Per #1451 scope doc, the standard migration target is: replace the
`dataplane.DataPlane` parameter/field with a narrow, domain-specific
interface declared inside the consumer package, mirroring the pattern
already shipped by `pkg/api` (`apiRuntimeDataPlane`),
`pkg/fwdstatus` (`DataPlaneAccessor`), `pkg/monitoriface`
(`RuntimeDataPlane`), and `pkg/conntrack` (`RuntimeDomainProvider`).

Once this lands and S1/S3 are done, the daemon's `legacyDP()`
accessor can shrink to the narrowest union and ultimately be removed
when the legacy adapter goes away (S4/S7).

## 2. Honest scope/value framing

This is a **pure decoupling refactor**. There is no perf delta and no
new feature. The value is structural:

- `pkg/cli` stops importing `dataplane.DataPlane` as a field type, so
  the eBPF retirement removal phases (#1476/#1477) no longer have
  `pkg/cli` as a blocker.
- The migrated `cliRuntime` interface documents exactly what the CLI
  uses of the dataplane (25 named methods + a handful of provider
  probes), so future map/program retirements can prove which CLI
  paths they break.
- Daemon `d.legacyDP()` no longer needs to satisfy the entire
  legacy interface to feed the CLI; it satisfies only `cliRuntime`.

**Cost**: ~25 method signatures copied into a new `runtime.go`,
five inline `interface{...}` provider probes consolidated into named
interfaces, ~7 production files touched, no behaviour change. About
the same scope as `pkg/api`'s prior `apiRuntimeDataPlane` extraction
(~45 LOC of interface decl + sed-style replacement of `dp dataplane.DataPlane`
→ `dp cliRuntime` at field sites).

If reviewers conclude this churn is not worth it because some other
plan (e.g. delete `pkg/cli` entirely now that remote CLI exists) is
preferable, **PLAN-KILL is an acceptable verdict**. The prior shipped
migrations on `pkg/api`/`pkg/fwdstatus`/`pkg/monitoriface`/`pkg/conntrack`
plus the explicit acceptance criteria in #1517 are the rationale for
proceeding; if Codex or Antigravity sees a flaw in that rationale,
say so.

## 3. What's already shipped / partially batched

Pre-existing, in master @ `fcd53beb`:

- **`pkg/api`** uses `apiRuntimeDataPlane` (`pkg/api/handlers.go:25-44`)
  — the canonical pattern to copy. 13 methods total. CLI's set is
  a superset (25 methods plus 5 provider probes — see below).
- **`pkg/fwdstatus`** uses `DataPlaneAccessor` (`builder.go:35`).
- **`pkg/monitoriface`** uses `RuntimeDataPlane` (`monitor.go:30`).
- **`pkg/conntrack`** uses `RuntimeDomainProvider` (already migrated
  off `DataPlane`).
- **`pkg/dataplane/userspace/legacy_dataplane.go`** is the
  compatibility adapter (`LegacyDataPlaneAdapter`) that satisfies the
  full `dataplane.DataPlane` interface and forwards to the userspace
  manager. The daemon's `legacyDP()` returns this on the userspace
  path. **Important**: this adapter already implements every method
  the CLI uses, so the migration cannot break the userspace path as
  long as `cliRuntime` is a strict subset of `dataplane.DataPlane`.
- **`docs/pr/1451-migration-scope/scope.md`** §S2 lists this work
  with target interface name `cliRuntime` and target file
  `pkg/cli/runtime.go`.

## 4. Concrete design

### 4.1 New file: `pkg/cli/runtime.go`

```go
// Package cli — runtime interface used by the interactive Junos CLI.
package cli

import (
    "github.com/psaab/xpf/pkg/config"
    "github.com/psaab/xpf/pkg/dataplane"
    dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// cliRuntime is the narrow, CLI-specific view of the dataplane.
// It lists exactly the methods called via cli.dp.*; do NOT widen it
// without a callsite reason.
//
// All concrete dataplanes (legacy eBPF Manager, LegacyDataPlaneAdapter
// over the userspace manager, DPDK manager) already satisfy this
// because it is a strict subset of dataplane.DataPlane.
type cliRuntime interface {
    // Lifecycle / health
    IsLoaded() bool

    // Compilation (used by candidate-config "show | compare" preview path)
    Compile(cfg *config.Config) (*dataplane.CompileResult, error)

    // Counters
    ReadGlobalCounter(idx uint32) (uint64, error)
    ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error)
    ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error)
    ReadPolicyCounters(ruleID uint32) (dataplane.CounterValue, error)
    ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error)
    ReadFilterCounters(filterID uint32) (dataplane.CounterValue, error)
    ReadFloodCounters(zoneID uint16) (dataplane.FloodCounters, error)
    ReadNATPortCounter(id uint32) (uint64, error)
    ReadNATRuleCounter(id uint32) (dataplane.CounterValue, error)

    // Sessions
    SessionCount() (v4, v6 int)
    IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
    IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
    DeleteSession(key dataplane.SessionKey) error
    DeleteSessionV6(key dataplane.SessionKeyV6) error

    // DNAT static entry delete (used by filtered clear)
    DeleteDNATEntry(key dataplane.DNATKey) error
    DeleteDNATEntryV6(key dataplane.DNATKeyV6) error

    // Clear-counter / clear-session bulk ops
    ClearAllCounters() error
    ClearAllSessions() (v4, v6 int, err error)
    ClearFilterCounters() error
    ClearNATRuleCounters() error
    ClearPolicyCounters() error

    // Map stats + persistent NAT table (used by show + clear NAT bindings)
    GetMapStats() []dataplane.MapStats
    GetPersistentNAT() *dataplane.PersistentNATTable
}

// Provider probes — small, named interfaces that replace the inline
// `c.dp.(interface{...})` type assertions in cli_helpers.go,
// cli_show_chassis.go, and cli_show_system.go. The intent is unchanged
// (these are userspace-only capabilities); naming them makes the
// surface searchable and lets the daemon pass a single capability-
// rich object.

// cliUserspaceStatusProvider is implemented by dataplanes that expose
// the userspace helper's `ProcessStatus` snapshot (queue/binding/CoS).
type cliUserspaceStatusProvider interface {
    Status() (dpuserspace.ProcessStatus, error)
}

// cliUserspaceControlProvider extends the status provider with the
// mutating control operations used by `request security flow ...`
// and similar diag commands.
type cliUserspaceControlProvider interface {
    cliUserspaceStatusProvider
    SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
    SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
    SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
    InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
}
```

### 4.2 Field + constructor rewrite in `pkg/cli/cli.go`

```go
type CLI struct {
    ...
    dp              cliRuntime   // was: dataplane.DataPlane
    ...
}

func New(store *configstore.Store, dp cliRuntime, ...) *CLI {
    ...
}
```

All other `c.dp.*` call sites compile unchanged because every method
they call is in `cliRuntime`. The five inline provider probes change
shape:

```go
// cli_helpers.go (was: inline anonymous interface)
provider, ok := c.dp.(cliUserspaceStatusProvider)
...
provider, ok := c.dp.(cliUserspaceControlProvider)
...

// cli_show_chassis.go (was: inline anonymous interface, status-only)
if _, ok := c.dp.(cliUserspaceStatusProvider); ok { ... }

// cli_show_system.go (two sites — both status-only)
if provider, ok := c.dp.(cliUserspaceStatusProvider); ok { ... }
```

Behaviour is bit-identical: Go interface satisfaction by structural
matching means anything that satisfied the inline interface still
satisfies the named one.

### 4.3 Daemon callsite

`pkg/daemon/daemon_run.go:849`:

```go
// before:
shell := cli.New(d.store, d.legacyDP(), eventBuf, er, ...)
// after:
shell := cli.New(d.store, d.legacyDP(), eventBuf, er, ...)
```

Source line is **unchanged**; the daemon still passes the same
adapter. Type assignment compiles because `d.legacyDP()` returns
`dataplane.DataPlane`, which is a strict superset of `cliRuntime`,
and Go assigns interface→interface freely when the source contains
all required methods.

(After S1 + S3 + S4 land, the daemon can have a typed
`d.cliRuntime()` accessor that returns a narrower object. That is
out of scope for this PR.)

## 5. Public API preservation

- `cli.New` signature changes only the type of its second parameter:
  `dataplane.DataPlane` → `cliRuntime`. Both interfaces are
  satisfied by every concrete dataplane (legacy eBPF, userspace
  adapter, DPDK) in the tree today, so every caller compiles.
- The only `cli.New` caller in the tree is `pkg/daemon/daemon_run.go`;
  it passes `d.legacyDP()` which still works (see §4.3).
- `cli.CLI` is unexported field-wise; the type alias for `c.dp` is
  package-internal. No other package depends on the type of `c.dp`.
- All `(*CLI).Show*`/`Clear*`/`Handle*` exported methods keep their
  signatures.

## 6. Hidden invariants the change must preserve

1. **Provider probe semantics.** The five inline `c.dp.(interface{...})`
   probes detect whether the underlying dataplane is the userspace
   path. Replacing them with named interfaces must preserve the same
   structural method set bit-for-bit (no widening, no narrowing) or
   a previously-supported dataplane will silently lose the capability
   probe. Verify by reading the existing inline interface vs the new
   named interface side by side; method count + signatures must
   match.
2. **Nil-safety.** Every existing `if c.dp == nil` and
   `if c.dp != nil && c.dp.IsLoaded()` guard must keep working. Since
   `cliRuntime` is an interface and the daemon already passes a
   non-nil interface value, `c.dp == nil` still does the right thing.
   (Subtle: if `d.legacyDP()` returned a typed nil pointer wrapped in
   an interface, the comparison would not work; but `d.legacyDP()`
   returns either a non-nil adapter or interface-nil today — verified
   by reading `pkg/daemon/daemon.go:345-`.)
3. **`dataplane.LastApplyResultOf(c.dp)` in `applyResult()`**
   (`cli.go:139`) takes a `dataplane.DataPlane`. After the field
   becomes `cliRuntime` this won't compile. Two options:
   - **Option A (preferred):** widen `LastApplyResultOf` to take
     `any` and runtime-detect. But that touches `pkg/dataplane`, out
     of scope.
   - **Option B (chosen):** keep `c.dp` typed as `cliRuntime`, but
     **also** keep a `c.dpLegacy dataplane.DataPlane` field for the
     one call site that needs it. Pass both at `New()`. This is a
     pragmatic interim — `LastApplyResultOf` is itself slated for
     refactor in S4 (`docs/pr/1451-migration-scope/scope.md`
     identifies the legacy accessor cleanup as the same step).
   - **Option C (alternative):** add `LastApplyResult() *ApplyResult`
     to `cliRuntime`. The legacy DataPlane has this method (verify);
     this is the cleanest fix. **Open question for review** —
     §11 Q3.
4. **HA paths.** The CLI does not touch session-sync or HA itself.
   `cluster.Manager` is a separate field (`cli.cluster`). The
   `request chassis cluster failover` paths use `cm.*` not `dp.*`,
   so no HA invariant is at risk from this PR.
5. **Test files (`*_test.go`).** Tests under `pkg/cli/` that
   construct fake dataplanes do so via a minimal interface or via
   nil — count and fix any test whose fake implements only the
   minimal set. See §9.
6. **Pure refactor — no behavioural change.** The CLI must produce
   bit-identical output for every supported command. Smoke (§9)
   covers interactive bring-up + the specific show/clear paths
   listed in #1517 acceptance criteria.

## 7. Risk assessment

| Class | Risk | Mitigation |
|---|---|---|
| Behavioural regression | LOW | Pure type rename; interface is strict subset. `make test ./pkg/cli/...` + smoke covers all touched commands. |
| Lifetime / borrow-checker | N/A | Go, not Rust. Interface satisfaction is structural and checked at compile time. |
| Performance regression | NONE | Adds one virtual call indirection at the same spot it already exists. Operator-path code, not hot path. |
| Architectural mismatch (#961 / #946 Phase 2 pattern) | LOW | Pattern shipped four times already on this codebase (`pkg/api`, `pkg/fwdstatus`, `pkg/monitoriface`, `pkg/conntrack`). Scope doc explicitly endorses it. No data-flow inversion, no batch-boundary churn. |

## 8. What the PR does NOT do (out of scope)

- **No daemon `legacyDP()` shrinkage.** That is S4. After this PR
  lands, `d.legacyDP()` still returns the full legacy interface; it
  just gets implicitly downcast to `cliRuntime` at the CLI boundary.
- **No shared `pkg/dpiface` extraction.** The scope doc mentions it as
  a possible follow-up if S1 + S2 land in tight succession. Sibling
  agent on #1516 is migrating `pkg/grpcapi` in parallel — neither PR
  should try to extract a shared package; do that **after** both land
  in a separate PR with both consumers visible.
- **No removal of `dataplane.DataPlane` import from `pkg/cli`.** The
  package still imports `dataplane` for type names
  (`dataplane.SessionKey`, `dataplane.SessionValue`,
  `dataplane.CounterValue`, etc.) and for `dataplane.LastApplyResultOf`.
  The goal is only to stop treating `dataplane.DataPlane` as a field
  type / parameter type.
- **No changes to `pkg/grpcapi`, `pkg/daemon`, `pkg/cluster`, or any
  file outside `pkg/cli/`** — sibling agents own those.
- **No README/doc updates outside `pkg/cli/`** if doc text in other
  packages still mentions the old shape; that's an unrelated drift.

## 9. Test plan

1. `make build` — daemon + CLI compile.
2. `make build-ctl` — remote CLI compiles.
3. `make test ./pkg/cli/...` — all CLI unit tests pass.
4. `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — full Go
   suite passes (30+ packages).
5. **5× flake check** on `pkg/cli` package tests
   (`go test -count=1 ./pkg/cli/...` 5×).
6. Smoke matrix on **loss userspace cluster only** (per CLAUDE.md):
   - Pass A (CoS disabled): v4 + v6, push + reverse, plus 12-stream
     `-P 12 -R` reproducer.
   - Pass B (CoS enabled): 24-cell per-class smoke
     (ports 5201–5206 × v4/v6 × push/reverse).
7. **Interactive CLI smoke** per #1517 acceptance criteria:
   - `cli` boots cleanly.
   - `show flow session brief` returns sessions seen by smoke.
   - `show security flow statistics` returns counters.
   - `clear security flow session all` clears sessions.
   - Tab completion, `?` help, pipe filters work.
8. **No failover smoke required** — CLI does not touch session sync,
   VRRP, or RG state. `cluster.Manager` is a separate field. The
   scope doc and #1517 do not list `make test-failover` for S2.
   (#1517 Smoke evidence section asks for the loss userspace cluster
   smoke matrix only.)

## 10. Open questions for adversarial review

Each question is invitable to a **PLAN-KILL** verdict if the answer
exposes a wrong-target architecture.

1. **Q1: Is `Option C` (add `LastApplyResult()` to `cliRuntime`)
   actually viable?** The CLI calls `dataplane.LastApplyResultOf(c.dp)`
   in `applyResult()`. Either we add `LastApplyResult()` to
   `cliRuntime` (clean — verify the underlying types expose it as a
   method, not as a top-level free function), or we keep a
   `c.dpLegacy dataplane.DataPlane` shadow field for that one call
   site (ugly but localised). **Reviewers, please pick one before
   PLAN-READY.**
2. **Q2: Is dropping the inline provider probes in favour of named
   interfaces actually behaviour-preserving?** Specifically: the
   `cli_show_chassis.go:108` probe is `Status() (...)` only, while
   `cli_helpers.go:183` probe is `Status + SetForwardingArmed +
   SetQueueState + SetBindingState + InjectPacket`. The plan proposes
   `cliUserspaceStatusProvider` for the first and
   `cliUserspaceControlProvider` (extending the first) for the
   second. **Verify by reading both inline interfaces and confirming
   no method is added or dropped silently.** A subtle drift (e.g.,
   forgetting `InjectPacket`) would silently disable a CLI command on
   the userspace path.
3. **Q3: Should we wait for #1516 to land first and extract a shared
   `pkg/dpiface`?** The scope doc says "if both land in close
   succession, extract a shared `pkg/dataplane/runtime` package."
   Doing both in parallel risks merge conflicts on the shared
   interface. Plan picks "two independent interfaces now, factor
   later" — is that right, or should this PR block on #1516?
4. **Q4: Are there CLI callsites that pass `c.dp` to a function
   typed `dataplane.DataPlane`?** Beyond `LastApplyResultOf`, find
   any helper that takes the full interface and would now reject a
   `cliRuntime`. `grep -n 'dataplane\.DataPlane' pkg/cli/*.go`.
5. **Q5: Is the test plan adequate?** The CLI has many code paths
   (`show flow session`, `show security policies`, `show interfaces
   extensive`, `show system buffers`, etc.). Smoke covers interactive
   bring-up + the three commands #1517 names. Should the test plan
   require additional commands (e.g. `show chassis forwarding`,
   `show system buffers`, `show security flow status`) to exercise
   each `c.dp.(interface{...})` probe path? Recommend yes; explicit
   smoke commands are added in §9 step 7 — confirm or expand.
6. **Q6: Does the `c.dp == nil` guard still work?** With
   `cliRuntime` as an interface, a typed-nil concrete pointer
   wrapped in `cliRuntime` would not equal `nil`. Verify the
   daemon's `legacyDP()` never returns a typed-nil and add a test
   if needed.
7. **Q7 (architectural-kill candidate): Is there a reason to
   consolidate `pkg/cli` and `pkg/grpcapi` *before* the migration —
   e.g., is there a plan to delete `pkg/cli` once remote CLI is
   feature-complete?** If so, this migration is wasted work.
   #1517's existence and #1451 scope doc both presuppose `pkg/cli`
   stays. Confirm.

---

End of plan v1.
