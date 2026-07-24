# Claude SMR — HOSTILE plan review r3 — #2114 residual

Reviewer: Claude (kimi-k3, in-conversation SMR pass).
Plan under review: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` v3 @
`f0c1605cd`. External r3 inputs: Codex NEEDS-REVISION (3 MAJOR, 3 MINOR,
fold ledger 5 FOLDED / 4 PARTIAL); AGY PLAN-READY-WITH-NITS (0 MAJOR, 1
MINOR, all 3 of its r2 findings FOLDED).

**VERDICT: NEEDS-REVISION** (1 BLOCKER, 2 MAJOR, 2 MINOR) — convergence is
close: nothing left is architectural. The blocker is a genuine test-design
flaw (Codex M1) that would have shipped a regression test incapable of
failing pre-fix. I verified every Codex r3 claim against source before
folding; all stand.

## BLOCKER

### B1. The v3 real-sampler barrier happens-before-orders the conflicting accesses — the test cannot fail pre-fix (Codex r3 M1, verified)
Control-flow check of my own v3 spec: the daemon adapter's `CachedStatus`
calls `userspaceDataplaneCachedStatus()`, which loads `d.dataplane()`
(`daemon_forwarding_status.go:108`) and only THEN invokes the provider's
`CachedStatus()` — the blocking fake signals "entered" AFTER the `d.dp`
read completed. The v3 barrier therefore imposes
`read(d.dp) → entered → test wakes → writer nils d.dp`: a channel-mediated
happens-before edge between the exact two accesses the test exists to race.
On the pre-fix plain field this stays race-CLEAN — the test would pass on
broken code (silent green), and on the fixed code it proves nothing. This
is precisely the class of bug the hostile pass exists to catch, and my v2
SMR's "deterministic" claim for this test was wrong.

Corrected design (folds Codex's sketch, verified against `sampler.go:92-139`
and `sampler.go:64-67`):
- The gate must sit BEFORE the `d.dp` access on BOTH sides, with no channel
  between the two conflicting accesses:
  - Reader side: block in the fake `ProcReader.ReadSelfStat`
    (`sampler.sample()` calls it before touching the adapter, `sampler.go:93`)
    — signal `readerEntered`, wait on a shared `release` channel.
  - Writer side: the failing fake dataplane's `Start()` signals
    `writerEntered` and waits on the same `release` BEFORE returning its
    error (the `setDataplane(nil)` store happens after `Start` returns in
    `armBootstrapExitDataplane`).
  - Test: `go fwdSampler.Start(ctx)` (Start MUST be on a goroutine — its
    prime sample is synchronous); `go d.armBootstrapExitDataplane(nodeID)`;
    wait for BOTH `readerEntered` and `writerEntered`; `close(release)`.
    Now the adapter's `d.dp` load and the writer's store proceed with NO
    happens-before edge between them — on the plain field the race detector
    fires (no HB edge needed, only absence of one); on the atomic cell it is
    clean. Deterministic as a memory-model proposition, not a timing one.
- Teardown: the sampler loop exposes no join handle (`Start` returns
  nothing) — cancel `ctx` and quiesce-poll the fake `ReadSelfStat` call
  counter (stops increasing) instead of "join".

## MAJOR

### M1. Audit-table prose count and per-row classifications (Codex r3 M2, verified)
Recount with a correct full-line-comment filter: **163 greppable lines − 29
comment lines = 134 executable references = 5 writers + 129 readers**. My
v3's "133 / 5+128" was wrong (my filter stripped one code line carrying a
trailing comment); the v3 TABLE itself enumerates all 134 correctly (I
diffed table lines vs the executable list — exact match), so only the prose
numbers (§1, §2, §5.4 header) change. Classification corrections to fold:
- `daemon_forwarding_status.go:21,24,36,39,97,100` sit in methods the
  narrowing DELETES (`IsLoaded`/`GetMapStats`/`Status`) — mark
  "removed by the narrowing", not "converted".
- `daemon_run_servers.go:255,256` (apiDataPlane capture) precede HTTP
  serving (function-local setup before the listener starts) → BOOT-SYNC;
  only the gRPC captures `:117,118` are the post-server micro-window.
- `daemon_natpoolalarm.go:101` is the start gate (boot block +
  `runBootstrapExitStartup` under applySem) → APPLY/BOOT-SYNC, not
  CONCURRENT.
- `daemon_run_shutdown.go:161,167,173` are the HA-only rg_active clear
  (require a cluster config) → RACE-2-unreachable via the four-link
  exclusion; `:214-229` (final stats/Close/Teardown) remain the
  RACE-2-exposed shutdown reads.
- `daemon_system.go:41`, `daemon.go:1012` — boot AND apply callers.

### M2. RACE-1 reachability is watcher-only (Codex r3 M3, verified with function-boundary map)
`watchClusterEvents` starts in `initManagers` (`daemon_run_bringup.go:203`,
BEFORE the :469 publication); everything else HA starts post-publication
(PHASE 5: `startClusterComms` `daemon_run.go:396`, VRRP watcher :578,
reconcile :582). Function-boundary map of `daemon_ha.go`: the
RACE-1-exposed reads are exactly the event-handler chain
`:297,299,337,348,362,367`. The rest — `:542,549,578,583`
(`watchVRRPEvents`, :511-604), `:813,826,842` (`reconcileRGState`,
:707-1039), `:1521,1531,1545` (`warmNeighborCache`, :1520) — are
post-publication goroutine-start HB-safe, as are ALL `daemon_ha_sync.go`,
`daemon_ha_fabric.go`, `daemon_ha_userspace_readiness.go`, and
`daemon_health.go:141` readers (session-sync trigger constructed
post-setup, `daemon_ha_sync.go:790`). v4 must scope RACE-1 to the watcher
chain and label the rest "converted for uniformity, not reachability". The
boot-publication race remains real — `UpdateConfig`'s synchronous election
(`daemon_run_bringup.go:181`) can enqueue the initial transition inside the
window — but it is ONE reader chain, not every HA reader.

## MINOR

### m1. Broaden the typed-nil kind-gate (Codex r3 MINOR 1 + AGY r3 MINOR 1 — both reviewers, fold)
Pointer-only gating misses typed-nil named Chan/Func/Map/Slice kinds (named
slice-with-methods precedent in-repo: `wire_uint8list.go:32`). Guard all
nillable kinds (`Chan`, `Func`, `Map`, `Pointer`, `Slice`, `UnsafePointer`;
`Interface` is harmless). Production backends are pointers — this is
hardening; the test matrix keeps the two fake shapes + adds a named-slice
typed-nil case.

### m2. Option D and stale-comment sweep (Codex r3 MINOR 2/3, verified)
- Option D: drop "future republish tears" (violates D's own write-once
  premise) and "identity lost" (backwards — the immutable owner RETAINS
  identity; A1's nil-slot discards it; D's post-clear introspection is a
  genuine D advantage). Reject D honestly on: per-reader flag-then-load
  ordering discipline with no compiler help, no future backend replacement
  by construction, deviation from the #2116 precedent.
- Additional stale comments to reword at /engineer time: `daemon.go:901`,
  `bootstrap.go:276`, `bootstrap.go:303` (lifetime claims contradicting the
  rollback recurrence), and `cluster_topology_preflight.go:117`'s stale
  `daemon_run.go:1868` cite (now `daemon_run_bringup.go:164`).

## Disposition required for v4

1. Replace the real-sampler barrier with the two-sided gate design (B1),
   including the goroutine-Start and cancel+quiesce-poll teardown.
2. Correct prose counts to 134 = 5 writers + 129 readers; fold the M1
   classification notes into the table.
3. Scope RACE-1 to the watcher chain; relabel all other HA readers
   "uniformity, not reachability" (M2).
4. Broaden the kind-gate; restate Option D; extend the comment sweep (m1,
   m2).

No architectural change. If v4 lands these, my r4 verdict is PLAN-READY.
