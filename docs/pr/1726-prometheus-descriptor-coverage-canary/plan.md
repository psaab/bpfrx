# #1726 — Prometheus descriptor-coverage canary test

Status: DRAFT v1 — pending adversarial plan review

## Issue framing

#1635 shipped cold-path histogram descriptors that `Collect()` emitted
but the collector's `Describe()` never registered. `xpfCollector` is a
*checked* collector, so an emitted-but-undeclared `*prometheus.Desc`
makes `prometheus.Gather()` return an error on every scrape (and a
`HTTPErrorOnError` registry returns HTTP 500). The cluster smoke MASKED
this because the daemon's own registry was effectively tolerant of the
inconsistency at the scrape layer. #1726 (promoted from #1661
addendum-12 P5) asks for a Go canary in `pkg/api` that guards this whole
class of bug across the ENTIRE collector, not just the cold-path family.

There is already a narrow guard — `TestColdPathDescriptorsAreDescribed`
in `metrics_cold_path_test.go` — but it only drives `emitWorkerColdPath`
and only covers the cold-path descriptor family. It does NOT cover the
~130 other descriptors emitted by the global/interface/zone/policy/
filter/session/NAT/DHCP/system/userspace collect paths. A descriptor
added to any of those `Collect()` paths without a matching `Describe()`
line is exactly the #1635 bug and is currently unguarded.

## Honest scope/value framing

Test-only, control-plane, ~1 file. The value is a regression guard that
fires at `go test ./pkg/api/...` time instead of at scrape time in
production. The win is small in LOC but high in blast-radius coverage:
it converts a silently-masked 500-on-scrape into a red unit test.

If reviewers conclude the guard is redundant with the existing
cold-path test or otherwise not worth the churn, PLAN-KILL is an
acceptable verdict. (Counter-argument the reviewers should weigh: the
existing test covers ~17 of ~150 descriptors and only the one emit
function; the #1635 regression could just as easily land in
`collectGlobalCounters` or a new `emit*` under `collectUserspaceStatus`
and go uncaught.)

## What's already shipped / partially relevant

- `TestColdPathDescriptorsAreDescribed` (metrics_cold_path_test.go:540)
  — drives `emitWorkerColdPath` directly, captures `Describe()` into a
  desc set, asserts every emitted desc is declared, and asserts an exact
  cold-path desc count of 17. This is the model; #1726 generalizes it to
  the whole `Collect()`.
- Fake-DP pattern: tests embed `*dataplane.Manager` (satisfies the bulk
  of `apiRuntimeDataPlane` returning zero values) and override
  `IsLoaded()`, `Status()`, `LastApplyResult()` as needed
  (`systemBuffersAPIUserspaceDP`, `natApplyResultAPIDP`,
  `schedulerCounterAPIDP`).
- `configstore.New(path)` + `EnterConfigure` + `LoadOverride` + `Commit`
  builds a real active config (newSchedulerCounterMetricsStore).
- `conntrack.NewGC(nil, time.Minute)` returns a usable GC whose
  `Stats()` returns zeros (no real session store needed).
- `dhcp.New(t.TempDir(), nil)` returns a usable empty `*dhcp.Manager`.

## Concrete design

New file `pkg/api/metrics_descriptor_coverage_test.go`.

### Fake DP

```go
type descriptorCoverageDP struct {
    *dataplane.Manager // zero-value reads for all apiRuntimeDataPlane methods
    status dpuserspace.ProcessStatus
    apply  *dataplane.ApplyResult
}

func (d *descriptorCoverageDP) IsLoaded() bool { return true }
func (d *descriptorCoverageDP) Status() (dpuserspace.ProcessStatus, error) {
    return d.status, nil
}
func (d *descriptorCoverageDP) LastApplyResult() *dataplane.ApplyResult {
    return d.apply
}
```

`*dataplane.Manager` (via `dataplane.New()`) supplies `IterateSessions`,
`IterateSessionsV6`, `ReadGlobalCounter`, `ReadInterfaceCounters`,
`ReadZoneCounters`, `ReadPolicyCounters`, `ReadFilterConfig`,
`ReadFilterCounters`, `ReadNATRuleCounter`, `ReadNATPortCounter`,
`GetMapStats`, `ClearAll*` — all returning zero/empty, which is fine:
the canary asserts no UNDECLARED desc is emitted, not that every desc
fires.

### Populated ProcessStatus

The `status` field is populated so EVERY `emit*` path under
`collectUserspaceStatus` produces at least one metric. This is the path
where the #1635 desc families (cold-path v1/v3/scalars) live, plus
CoS owner-profile, drain-phase, waterfill, equal-flow, worker runtime,
event stream, binding active-flow, binding TX-completion, CoS
active-flow, three-color policer, source-NAT pool, fairness RSS,
fairness throughput, and neighbor-warm families. Concretely:

- `WorkerRuntime`: three workers — one v3 (populated active arrays +
  overflow + tsc clock source), one unknown-version (99), one v1 (dense
  hist + samples + sumNS + aliasSeen) — so all cold-path desc families
  fire (mirrors the existing cold-path test fixture).
- `CoSInterfaces`: one interface, one queue with `OwnerWorkerID` set,
  `EqualFlowEnforcement=true`, non-MaxUint64 `WaterfillMinEpochsPerWorker`,
  populated drain/waterfill/equal-flow fields.
- `CoSActiveFlowCounts`, `Bindings`, `ThreeColorPolicerCounters`,
  `SourceNATPools`, `EventStream`, `NeighborWarm*`, session-table +
  flow-cache capacity fields — one populated row each.
- Fairness throughput: `emitFairnessThroughputGauges` builds a window on
  first call; a single status update yields summaries only across a time
  delta, so the equal-flow estimate gauges may or may not fire on a
  single scrape — that's fine for the canary (their descs are declared
  regardless). The RSS expectation gauges fire from config.

### Server / config

```go
store := <real configstore with interfaces, zones, policies (incl.
         global + count), and firewall filters inet + inet6>
gc    := conntrack.NewGC(nil, time.Minute)
dhcpM := dhcp.New(t.TempDir(), nil)
srv   := &Server{store: store, gc: gc, dhcp: dhcpM, startTime: time.Now()}
dp    := &descriptorCoverageDP{Manager: dataplane.New(),
         status: <populated>, apply: &dataplane.ApplyResult{
            ZoneIDs:   map[string]uint16{"trust":1,"untrust":2},
            FilterIDs: map[string]uint32{"inet:f":0,"inet6:f":100},
         }}
srv.dp = dp
```

`collectInterfaceCounters` resolves Junos→kernel names and calls
`net.InterfaceByName`; those won't exist in the test env so it returns
early per-iface. That is harmless — iface descriptors are always in
`Describe()`, and the canary does not require them to be emitted.

### The assertion (issue's cleanest formulation)

```go
reg := prometheus.NewRegistry()       // NOT ContinueOnError
reg.MustRegister(newCollector(srv))   // the REAL collector
mfs, err := reg.Gather()
if err != nil {
    t.Fatalf("Gather() returned an error — a metric was emitted whose "+
        "descriptor is not declared in Describe() (the #1635 class): %v", err)
}
if len(mfs) == 0 {
    t.Fatal("collector emitted no metrics — fixture/dp not wired")
}
```

`reg.Gather()` is the exact production path: `client_golang` validates
every collected metric's desc against the `Describe()` set and returns a
non-nil error for any emitted-but-undeclared desc. The `len(mfs) == 0`
guard prevents a vacuous pass if `Collect()` returns early (dp nil / not
loaded / fixture unwired).

### Non-vacuity proof (mandatory, done live during implementation)

A test that passes trivially is worthless. During implementation I will:
1. Temporarily delete one `ch <- c.<someDesc>` line from `Describe()`
   (e.g. `c.neighborWarmDropsTotal`) — a desc the fixture guarantees is
   emitted via `emitNeighborWarmCounters` (unconditional).
2. Run the canary; confirm it FAILS with a Gather error naming that
   metric.
3. Restore `Describe()`; confirm it PASSES.
This is recorded in the PR test plan; the committed test does not depend
on the manual edit.

## Public API preservation

No production API change. If implementation surfaces a CURRENT real gap
(a desc emitted today but missing from `Describe()`), that is a real
#1635-class bug → fix `Describe()` (one-line additions) and note it.
Expectation from reading `Describe()` end-to-end: it is currently
complete (the #1635 fix declared the whole cold-path family at
metrics.go:319-335), so the test should be a pure regression guard.

## Hidden invariants the change must preserve

- Side-effect ordering: none — test-only, reads through the public
  `prometheus.Collector` contract.
- Allocation rules: N/A (control-plane test).
- `emitFairnessThroughputGauges` takes `c.mu` and lazily builds the
  throughput window; calling `Collect()` once is safe (the existing
  daemon does exactly this per scrape).
- Determinism: `collectSystemMetrics` reads `/proc/*`; those reads emit
  declared descs (sysCPU*, sysMem*, daemon*) and never an undeclared
  one, so they cannot make the canary flaky. If `/proc` is unreadable
  the descs simply don't emit — still no undeclared desc.
- `Gather()` also enforces label-consistency and dup-metric rules; the
  fixture must not emit two metrics with identical desc+label sets
  (would be a DIFFERENT Gather error, a fixture bug not a #1635 bug).
  Mitigation: single-row collections per family; if a dup-label collision
  surfaces it is a fixture defect to fix, and is itself a useful signal.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | NONE | test-only, no production code (unless a real Describe() gap is found) |
| Lifetime / borrow | N/A | Go, no unsafe |
| Performance regression | NONE | test path only |
| Architectural mismatch | LOW | guards a real, demonstrated bug class; not a speculative rearchitecture |

The one real risk is a VACUOUS test (passes without exercising the
contract) — mitigated by the `len(mfs)==0` guard plus the mandatory
live non-vacuity proof (drop-a-desc → fail → restore).

## Test plan

- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./pkg/api/...` green.
- New canary green; 5× flake loop on the canary.
- Live non-vacuity proof: drop `neighborWarmDropsTotal` from
  `Describe()` → canary FAILS with a Gather error → restore → PASSES.
- Full `go test ./...` (pre-existing `pkg/dataplane/userspace` sandbox
  failures proven pre-existing on clean master).
- NO cluster smoke — test-only control-plane change.

## Out of scope (explicitly)

- Deleting or merging the existing `TestColdPathDescriptorsAreDescribed`
  (it stays; the new canary is broader and complementary).
- Asserting an exact total descriptor count (brittle as families grow;
  the `Gather()`-error check is the durable contract). The cold-path
  test already pins its family count for the narrow case.
- Any change to the metric set, labels, or `Collect()` behavior.

## Open questions for adversarial review

1. Is the whole-collector `reg.Gather()` formulation strictly stronger
   than the existing cold-path test, or does `Gather()` short-circuit /
   sample in a way that lets an undeclared desc slip through? (I claim
   client_golang validates EVERY collected metric's desc; verify against
   the vendored client_golang version.)
2. Can a single `Collect()` call deadlock or hang given
   `emitFairnessThroughputGauges` mutex + lazy window construction?
   (Daemon calls it per scrape; should be safe — confirm.)
3. Does the fixture risk a DUP-metric Gather error (two metrics with
   identical desc+labels) that would mask or be confused with the
   #1635 desc-coverage error? How should the test disambiguate the two
   error classes?
4. Is `conntrack.NewGC(nil, …)` + `dhcp.New(tmp, nil)` safe to call in a
   unit test with no goroutines started? (We never call `Start()`.)
5. Is there a CURRENT real `Describe()` gap (run the test first)? If so,
   is the one-line `Describe()` fix in-scope for this PR or should it be
   a separate fix PR referenced from here?
6. PLAN-KILL invitation: given `TestColdPathDescriptorsAreDescribed`
   already exists, is the marginal coverage of the other ~130
   descriptors worth a second ~150-line fixture? Argue both sides.
