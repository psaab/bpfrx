# Claude SMR — HOSTILE plan review r1 — #2114 residual

Reviewer: Claude (kimi-k3, in-conversation SMR pass per
`feedback_triple_review_includes_claude_smr` — hostile, not synthesizer).
Plan under review: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` v1 @
`1d62be758`.

**VERDICT: NEEDS-REVISION** (4 BLOCKER, 3 MAJOR, 4 MINOR)

This is NOT a soft pass. Independent verification of the plan's own evidence
found the plan's central safety claims are FALSE in three places, its fallback
option is incoherent, and it breaks an existing architecture canary it never
mentions. Both external reviewers (Codex NEEDS-REVISION 7M/6m; AGY
PLAN-READY-WITH-NITS 1M/3m) independently confirmed parts of this; where they
disagree with each other I adjudicate below with code evidence. The core
recommendation (Option A1, atomic publication cell + compiler-enforced full
conversion) SURVIVES review — the errors are in the plan's analysis, scope
statements, and test design, not in the chosen architecture.

## BLOCKER

### B1. The "boot writers happen-before background goroutines" claim is false
Plan §4-A1/§7.2 asserts the four boot-time `d.dp` writes are ordered before any
concurrent reader by goroutine-start happens-before. Verified false:
`initManagers` constructs the cluster manager and launches
`go d.watchClusterEvents(d.daemonCtx)` at `daemon_run_bringup.go:203`, and
`d.cluster.UpdateConfig(cc)` at :181 runs an election that can synchronously
enqueue the initial transition — while `setupDataplaneAndInitialConfig`
(assigning `d.dp` at :448/:469/:497) runs AFTER `initManagers` (its own doc
comment, `daemon_run_bringup.go:407-413`). The watcher handler reads `d.dp` at
`daemon_ha.go:297` with no synchronization. On an HA boot this is a genuine
unsynchronized read/write pair on the interface field with no happens-before
edge — no bootstrap window required. (Codex MAJOR 1, verified against source.)
Consequence: the plan's §5.4 class-B ("boot-only, safe by ordering") reasoning
is invalid for every reader on a cluster-capable boot; A1's full conversion is
the only option on the table that fixes this (A2 and B do not reach it).

### B2. The bootstrap/HA mutual-exclusion invariant is false as stated
Plan §3/§5.4 class D claims `nodeIDPresent → bootClassNormal` makes
cluster-goroutine readers unreachable by the bootstrap-exit writer. Verified
false: `computeBootClass` checks `configCompileFailed` FIRST
(`bootstrap.go:233-235`, comment "This overrides EVEN the HA-node guard") —
an HA node whose committed config no longer compiles ENTERS bootstrap. Codex
MINOR 2 counters that this path has no active config so `d.cluster` is never
constructed (`daemon_run_bringup.go:161` requires `cfg.Chassis.Cluster !=
nil`). Codex is right about the FIRST exit on that node — but not about the
rollback recurrence: a commit that supplies a cluster config starts cluster
comms; a first-`commit confirmed` timeout runs `enterBootstrapMode` (which
keeps the dataplane object, `bootstrap.go:470-476`, and does NOT stop cluster
comms); a corrected re-commit re-enters `runBootstrapExitStartup`, and an arm
failure there writes `d.dp = nil` while the HA watchdog/sync/event goroutines
are live readers. (AGY MAJOR 1 upheld against Codex's rebuttal, via the
rollback path both of them under-analyzed.) Consequence: class D does not
exist as a safe class; every `daemon_ha*.go` reader must be treated as
potentially concurrent with the writer. A1 covers them; the plan text must
stop claiming the exclusion.

### B3. Option A2 is incoherent as written and must be removed or redefined
The plan's fallback says "same accessor/writers, racy-readers-only conversion,
raw field retained." With the field retyped to `atomic.Pointer[dpSlot]` there
IS no raw field; keeping one means either dual-writing (two sources of truth,
the race preserved) or a second unspecified synchronization scheme. And a
stale raw field is FUNCTIONALLY wrong, not merely racy: the apply path treats
`d.dp == nil` as "skip dataplane apply" (`daemon_apply_dataplane.go:137-141`).
(Codex MAJOR 7, verified.) The honest fork is: A1 (uniform accessor, full
conversion) vs PLAN-KILL / fwdstatus-only band-aid. Remove A2; if a
smaller-diff variant is wanted for the record, describe it as A1-with-a-lint
rather than a dual-representation.

### B4. The plan breaks `TestDaemonRuntimeEntryPointUsesRuntimeDataPlane` and never mentions it
`pkg/dataplane/retirement_boundary_canary_test.go:1711-1723` calls
`assertDaemonDPFieldIsRuntimeDataPlane` (:3314-3348), which requires a Daemon
field NAMED `dp` whose AST type is exactly `dataplane.RuntimeDataPlane`.
Retyping to `dpCell atomic.Pointer[dpSlot]` fails `make test-go` on master
today. The canary's expression renderer also cannot represent the generic
type (:3352). The plan's "compiler-enforced completeness" claim is therefore
incomplete: conversion REQUIRES a deliberate canary redesign (assert the
cell's element type stores `dataplane.RuntimeDataPlane`, e.g. match
`dpSlot{v dataplane.RuntimeDataPlane}` + `atomic.Pointer[dpSlot]` field), and
the plan should add a NEW canary forbidding direct `d.dpCell` access outside
the accessor definitions (otherwise a future package-local `d.dpCell.Load()`
silently bypasses the contract — the retype only kills OLD references).
(Codex MAJOR 6, verified against the canary source.)

## MAJOR

### M1. §5.4 audit table is neither exhaustive nor correctly classified
Verified errors in the plan's own table (issue requirement #4 deliverable):
- `daemon_run.go:312,324` classified B (boot-only): FALSE. Those reads are
  inside the `er.AddCallback` closure (`daemon_run.go:288-329`) executing per
  SESSION_OPEN event on the event-reader goroutine for the daemon's lifetime.
  Gated on `getSessionSync() != nil` (:288), i.e. cluster-only in practice —
  but the code shape is a hot per-event background reader. (My own finding;
  neither external reviewer caught it.)
- `daemon_ha_userspace_stream.go:122` classified D (cluster-only): FALSE.
  `runUserspaceEventStream` is launched when `d.cluster == nil`
  (`daemon_run.go:365`) — it is the STANDALONE event consumer. On a bootstrap
  node with a non-nil dataplane it reads `d.dp` on a background goroutine,
  genuinely racy vs the writer. (Codex MAJOR 2, verified.)
- `daemon_run_shutdown.go:161,214` classified "B-ish": wrong. Shutdown
  releases applySem immediately (`daemon_run_shutdown.go:50`) and its timeout
  deliberately tolerates a surviving apply; an in-flight bootstrap-exit apply
  can hold the writer while shutdown reads `d.dp`. Class C. (Codex, verified.)
- `daemon_policy_invalidate.go:286-290` classified "A/C callers vary": FALSE.
  The file documents "Caller must hold d.applySem" (:114-116) and all three
  wrappers chain from commit/sync/rollback (`daemon_apply_commit.go:270` et
  al.). Class A. (AGY MINOR 3 + Codex MINOR 3 + my F2 — three-way agreement.)
- `daemon_health.go:141` "C/D border": D — the production trigger is
  session-sync (`daemon_ha_sync.go:970`); standalone short-circuits on
  `d.cluster == nil` before reading `d.dp`. (Codex MINOR 3, verified.)
- `daemon_run.go:611-614` CLI probe: gRPC starts at :598, so a remote commit
  can already be in flight when the probe reads `d.dp` — micro-window, but it
  is not "boot-only" as tabled. (Codex, verified.)
- Omitted sites: `daemon_run_naming.go:230` (writer-site nil-check read),
  `daemon_natpoolalarm.go:101` (gate read), `daemon_apply_dataplane.go:455`,
  `daemon_ha_sync.go:1164` (`ss.SetRuntime(d.dp)`), `daemon_ha_sync.go:1286`
  (fence), `daemon_ha.go:1521` (warmNeighborCache). (Codex, verified — I
  spot-checked each.) The table must be regenerated mechanically (the grep
  output exists; group by file, list every line).

### M2. The singleton fwdstatus adapter is NOT observably equivalent through `Build`; scope it sampler-only
Plan §4-A1 claims blanket observable equivalence. Verified false in general:
`fwdstatus.Build` detects the backend by the PRESENCE of a `Status()` method
(`builder.go:116-123` `isUserspace`), skips map utilization when present
(:125), and maps a `Status()` error to `StateUnknown` (:219). A universal
adapter that always HAS `Status()` (returning an error on nil/non-userspace)
flips every Build consumer onto the userspace path — different rendered state
than today's base wrapper. The ONLY reason the plan's claim holds in
production is that the daemon adapter is never fed to Build: its sole
consumer is the `fwdstatus.Sampler` (which calls only `CachedStatus`,
sampler.go:113-125; missing-method and `ok=false` are equivalent there), and
the gRPC/CLI Build paths use their OWN adapters re-selected per request from
boot-captured probes (`server_show_forwarding.go:21-22`,
`cli_show_chassis.go:59-60`). The plan must: (a) scope the equivalence claim
to the sampler path explicitly; (b) state that `IsLoaded`/`GetMapStats`/
`Status` on the daemon adapter are interface-satisfaction with no production
caller today; (c) keep grpcapi/cli adapters untouched (their per-request
re-selection against an immutable captured object has no divergence);
(d) add a test pinning the sampler-path equivalence. (Codex MAJOR 4,
verified; also corrects my plan's own overstatement — SMR F3 converges.)

### M3. "Load-once per site" is underspecified; define per-site snapshot boundaries
Mechanical "load once" is wrong at behaviorally important sites (AGY MINOR 1
+ Codex MAJOR 3 + my F5 — three-way agreement). The plan must enumerate:
- HA watchdog (`daemon_ha_sync.go:733,750`): ONE load per tick, shared across
  the RG loop — not a lifetime capture, not a per-RG load.
- Shutdown (`daemon_run_shutdown.go:161,214-229`): one snapshot for the
  HA-clear block; a separate snapshot for final-stats + Close/Teardown.
- Neighbor enumeration (`daemon_neighbor_listener.go:469-476`): provider and
  `indexEnumerator` assertions must derive from ONE load (today it reads
  `d.dp` twice — the canonical example the plan should quote).
- Bootstrap-exit writer (`daemon_run_naming.go:230-248`): ONE local for
  nil-check + `Start` + seeding; `setDataplane(nil)` only after failed Start.
- Fence (`daemon_ha_sync.go:1286+`) / warmNeighborCache (`daemon_ha.go:1521+`):
  one snapshot per operation.
- Capture-once loops (GC `daemon_gc.go:22`, event-stream provider/drainer
  captures) keep exactly one load at goroutine start (current semantics).

## MINOR

### m1. Test plan gaps (Codex MAJOR 5 + my F6, verified)
- No `-race` in `make test-go` (Makefile:81-86, no race target, no CI
  workflow). The revert-guard needs a scoped race target (e.g.
  `go test -race ./pkg/daemon/ -run '<new tests + NATPoolAlarm>' -count=2`)
  wired into `make test-go` or the plan is decorative in CI. Decide at
  /engineer time; plan must commit to one.
- `runBootstrapExitStartup` touches netlink naming + `/proc/sys` writes
  (`daemon_run_naming.go:221-226`, `daemon_run_bringup.go:548-569`). The race
  test must not drive the whole function: extract the arm block
  (naming:228-249: Start + seeder + maybeStartNATPoolAlarm + nil-on-failure)
  into a helper (`armBootstrapExitDataplane`) and drive THAT. (My F6 +
  Codex.)
- Backend-transition test direction is backwards: today's wrapper ALREADY
  re-probes per call, so userspace→nil→non-userspace passes pre-fix too. The
  fail-on-revert direction is nil/non-userspace→userspace (old code: accessor
  selected as base wrapper at construction, Status permanently absent).
  (Codex, verified against `daemon_forwarding_status_test.go:162-238`.)
- Add: cluster-start publication race test (B1), full
  success→`enterBootstrapMode`→second-failing-exit recurrence driving the
  REAL writer path (B2), and the sampler-tick seam decision (drive adapter
  methods directly — the sampler loop is pkg/fwdstatus and out of scope).

### m2. Migration size understated: 79 `Daemon{dp: ...}` test initializers
The plan counts 159 prod + 32 test selector references. Codex found ~79
keyed-literal test initializers (e.g. `configsync_invalidate_5564_test.go:115`)
that also break under the retype. Restate as ~159 prod selectors + ~110 test
sites; provide a test-helper (`newDaemonWithDP(fake)` or direct
`d.setDataplane` in tests) to keep the diff mechanical. (Verified the pattern
exists; count accepted from Codex with a spot check.)

### m3. Docs scope understated (Codex MINOR 6, verified)
- The accessor contract belongs in `pkg/daemon/README.md`'s architecture
  section (:13), not only the bootstrap bullets.
- The plan's "no other module docs name `d.dp`" is false:
  `docs/ha-failover-status.md:279`, `docs/ha-no-hitless-restart.md:22`,
  `docs/rib-group-route-leaking.md:94` mention it (spot-checked the first).
  The /engineer pass must grep `docs/` for `d\.dp` and update or justify each.
- `_Log.md` entries are required for implementation edits (CLAUDE.md logging
  rules).

### m4. Options-section corrections (Codex MINOR 5, verified)
- Option C's deadlock argument is overstated: a mutex accessor can copy the
  interface under RLock and unlock before returning — no hold-across-call is
  forced. Keep C as viable-but-not-chosen on precedent grounds (#2116
  atomic.Pointer), not on a false deadlock claim.
- Option B's premise ("write once before goroutines") is already false per B1.
- Sixth option worth one paragraph (immutable owner + atomic presence flag):
  weaker than A1 (two-atomic tearing across a future republish; identity and
  presence decoupled) — documented, rejected.

## Disposition required for v2

1. Rewrite §3/§5.4: delete the bootstrap/HA exclusion and boot happens-before
   claims; regenerate the audit table mechanically with correct classes;
   class D eliminated (all HA readers treated as potentially concurrent).
2. Delete Option A2; restate the fork as A1 vs PLAN-KILL.
3. Add the canary redesign (fix + new dpCell-access canary) as an explicit
   work item with the AST-matcher sketch.
4. Scope the fwdstatus singleton as sampler-only per M2 (a-d).
5. Enumerate per-site snapshot boundaries per M3.
6. Test plan: arm-helper extraction, reversed transition direction,
   cluster-start publication test, rollback-recurrence real-writer test,
   scoped `-race` make target decision.
7. Correct migration size + docs scope (+ `_Log.md`).
8. Options-section corrections per m4; typed-nil: add the reflect guard
   (AGY MINOR 2; cheap, once-per-store) — resolves OQ7.
