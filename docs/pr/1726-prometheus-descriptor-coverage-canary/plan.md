# #1726 — Prometheus descriptor-coverage canary test

Status: PLAN-READY v2 — Codex + AGY + Claude-SMR converged

Plan-review convergence (round 1):
- Codex (task codex-1726-plan): PLAN-KILL-as-written → salvageable;
  core finding `NewRegistry()` does not check desc coverage (use
  `NewPedanticRegistry()`); fake-DP must override error-returning read
  paths; live proof must assert the specific `unregistered descriptor`
  error; verified 139 emitted == 139 described, no gap on master.
- AGY (adversarial-review-mptva9tt-j9hv62): PLAN-NEEDS-MINOR — same
  `NewPedanticRegistry()` critical fix; assert `"with unregistered
  descriptor"` substring to disambiguate from dup-metric errors;
  confirmed NewGC(nil)/dhcp.New(tmp,nil) nil-safe, no deadlock in
  emitFairnessThroughputGauges, no latent gap on master, value approved.
- Claude-SMR: concur. Independently verified the pedantic-registry
  behavior against client_golang@v1.23.2 registry.go:67/85/442/711-715.
All minor findings are folded into v2 below and implemented.

## v2 changelog (Codex round-1, task codex-1726-plan)

Codex returned PLAN-KILL-as-written with a dispositive, verified core
finding plus a clear salvage path. v2 adopts the salvage in full:

1. **CORE FIX — use `prometheus.NewPedanticRegistry()`, NOT
   `NewRegistry()`.** Verified independently against the vendored
   `client_golang@v1.23.2/prometheus/registry.go`: `NewRegistry()`
   (line 67) does NOT set `pedanticChecksEnabled`; only
   `NewPedanticRegistry()` (line 85) does. The "collected metric … with
   unregistered descriptor" error (line 711-715) is gated on
   `registeredDescIDs != nil`, which is populated only under pedantic
   checks (line 442). A plain `NewRegistry().Gather()` therefore does
   NOT catch an emitted-but-undeclared desc — the v1 premise was wrong.
   Note: production `server.go:115` uses plain `NewRegistry()`, so this
   error never surfaces via Gather in production; #1635 surfaced through
   promhttp's checked-collector logging. The pedantic registry is the
   correct TEST instrument for asserting the Describe()⊇Collect()
   contract regardless of the production registry mode.
2. **Fake-DP must override the error-returning read paths.** Codex
   verified `dataplane.New()` returns map-missing ERRORS (not zero
   values) for `ReadZoneCounters` (maps_counters.go:83),
   `ReadPolicyCounters` (maps_policy.go:284), `ReadFilterConfig`
   (maps_filter.go:53), `ReadFilterCounters`, `ReadNATPortCounter`
   (maps_nat.go:387), `ReadInterfaceCounters` (returns nil only on
   ErrKeyNotExist, error otherwise). Those collectors `continue` on
   error, so a bare embed would NOT exercise the zone/policy/filter/NAT
   descriptor families. The fake DP overrides each to return a
   zero-value + nil error so those families actually emit and are
   covered. (`ReadGlobalCounter` error is IGNORED by the collector —
   `v, _ := …` — so global counters emit regardless; that is why
   `len(mfs) > 0` alone is weak.)
3. **Non-vacuity strengthened.** `len(mfs) == 0` only catches the
   nil/unloaded-DP early return. v2 adds positive sentinel assertions
   that representative families from EACH collect path are present in
   the gathered output (global, zone, policy, filter, NAT-pool, session,
   DHCP, system, and the userspace cold-path/CoS/fairness/worker
   families), so a future change that silently drops a whole family
   fails the canary too.
4. **Live non-vacuity proof asserts the SPECIFIC error.** Dropping a
   desc from `Describe()` must make `Gather()` return an error whose
   text contains `unregistered descriptor` — NOT just "an error". This
   disambiguates the desc-coverage failure from the DUP-metric error
   (`registry.go:917/941`, which fires BEFORE the pedantic desc check
   and would otherwise be mistaken for it). The fixture uses one row per
   family to avoid dup-metric collisions.
5. **dhcp.New returns `(*Manager, error)`** — handle the error and
   `defer Close()` (Codex: opens a netlink handle at dhcp.go:105;
   `Leases()` at :430 is nil-safe). `conntrack.NewGC(nil, time.Minute)`
   confirmed safe (gc.go:104 nil-provider branch; `Stats()` at :189 just
   locks+returns). Fairness throughput single-collect confirmed NOT a
   deadlock (mutex local, unlock before emission, metrics_userspace.go:352).
6. **No current Describe() gap.** Codex's static scan: 139 emitted desc
   fields == 139 described fields, no gap on this commit; the existing
   `TestColdPathDescriptorsAreDescribed` passes. The new canary is a
   pure regression guard (no production `Describe()` fix needed) and is
   NOT redundant with the cold-path-only guard (it covers the other
   ~122 descriptors and every collect path).

---

Status: DRAFT v1 — superseded by v2 above

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

// v2: override the read paths that dataplane.New() answers with a
// map-missing ERROR (the collectors `continue` on error and would skip
// the family otherwise). Return zero value + nil error so the family
// emits and is covered.
func (d *descriptorCoverageDP) ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error) {
    return dataplane.InterfaceCounterValue{}, nil
}
func (d *descriptorCoverageDP) ReadZoneCounters(uint16, int) (dataplane.CounterValue, error) {
    return dataplane.CounterValue{}, nil
}
func (d *descriptorCoverageDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
    return dataplane.CounterValue{}, nil
}
func (d *descriptorCoverageDP) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
    return dataplane.FilterConfig{}, nil
}
func (d *descriptorCoverageDP) ReadFilterCounters(uint32) (dataplane.CounterValue, error) {
    return dataplane.CounterValue{}, nil
}
func (d *descriptorCoverageDP) ReadNATPortCounter(uint32) (uint64, error) {
    return 0, nil
}
```

`*dataplane.Manager` (via `dataplane.New()`) still supplies
`IterateSessions`, `IterateSessionsV6`, `ReadGlobalCounter` (error
ignored by the collector), `ReadNATRuleCounter`, `GetMapStats`,
`ClearAll*`. The canary asserts no UNDECLARED desc is emitted AND (v2)
that representative families from each path ARE emitted.

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

### The assertion (v2 — pedantic registry)

```go
reg := prometheus.NewPedanticRegistry() // MUST be pedantic; plain
                                         // NewRegistry() does NOT check
                                         // collected-desc ⊆ described-desc
reg.MustRegister(newCollector(srv))      // the REAL collector
mfs, err := reg.Gather()
if err != nil {
    // The #1635 class: a metric emitted by Collect() whose Desc is not
    // in Describe() yields "... with unregistered descriptor ...".
    t.Fatalf("pedantic Gather() error (likely an emitted metric whose "+
        "descriptor is not declared in Describe() — the #1635 class): %v", err)
}
if len(mfs) == 0 {
    t.Fatal("collector emitted no metrics — fixture/dp not wired")
}
// v2 positive sentinels: assert representative families from each
// collect path are present, so dropping a whole family also fails.
mustHave(t, mfs,
    "xpf_packets_total",                 // collectGlobalCounters
    "xpf_zone_packets_total",            // collectZoneCounters
    "xpf_policy_hits_total",             // collectPolicyCounters
    "xpf_filter_hits_total",             // collectFilterCounters
    "xpf_nat_pool_total_ports",          // collectNATPoolMetrics
    "xpf_sessions_active",               // collectSessionGauges
    "xpf_dhcp_leases_active",            // collectDHCPMetrics
    "xpf_daemon_uptime_seconds",         // collectSystemMetrics
    "xpf_userspace_worker_cold_path_samples_v3_total", // userspace cold-path v3
    "xpf_userspace_worker_dead",         // emitWorkerRuntime
    "xpf_fairness_cstruct",              // emitFairnessRSSGauges
)
```

`NewPedanticRegistry().Gather()` validates every collected metric's desc
against the `Describe()` set and returns a non-nil error containing
`unregistered descriptor` for any emitted-but-undeclared desc
(`registry.go:711-715`, gated on the pedantic-only `registeredDescIDs`).
The `len(mfs)==0` guard plus the `mustHave` sentinels prevent a vacuous
pass.

### Non-vacuity proof (mandatory, done live during implementation)

A test that passes trivially is worthless. During implementation:
1. Temporarily delete one `ch <- c.neighborWarmDropsTotal` line from
   `Describe()` — a desc the fixture guarantees is emitted via
   `emitNeighborWarmCounters` (unconditional).
2. Run the canary; confirm it FAILS and the error text contains
   `unregistered descriptor` (NOT a dup-metric error — disambiguation
   matters per Codex).
3. Restore `Describe()`; confirm it PASSES.
Recorded in the PR test plan; the committed test does not depend on the
manual edit.

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
