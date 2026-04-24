# PR: #877 cli — `show chassis forwarding`

## Goal

Add a one-screen forwarding-daemon health CLI. Issue #877 shows a
Junos-style layout; this plan follows the shape but uses honest xpf
terminology for the fields so operators don't infer Junos-specific
semantics that don't apply here.

Target output (single-node MVP):

```
FWDD status:
  State                                 Online
  Daemon CPU utilization                4 percent (cumulative since start)
  Worker threads CPU utilization        0 percent (cumulative since start)
  Heap utilization                     72 percent
  Buffer utilization                   83 percent
  Uptime:                               5 days, 12 hours, 50 minutes, 35 seconds
```

## Approach

### Scope (MVP — this PR)

Ships **local-node only** — no cluster peer query, no new gRPC RPC,
no proto changes. Cluster mode (node0/node1 blocks) is a follow-up.
Files touched stay under the narrow-scope bar from
`docs/engineering-style.md`.

- New CLI leaf `show chassis forwarding` in `pkg/cmdtree/tree.go`.
- New handler in `pkg/cli/cli_show_chassis.go` (new file, adjacent to
  `cli_show_cluster.go`).
- New formatter in `pkg/cli/statusfmt_chassis.go` that renders a
  local-derived `ForwardingStatus` struct.
- In cluster mode: a single local block with a `note:` line that peer
  query is follow-up work (cross-reference the follow-up issue).

### Field derivation — honest labels

Deliberately not reusing Junos-specific labels (Microkernel / Real-time
threads), because those terms carry vSRX-specific semantics we don't
implement. See rejected alternative 1 below.

| Field | Label | Source | Notes |
|---|---|---|---|
| State | `State` | local backend liveness check | **Tri-state contract:** `WorkerHeartbeats []time.Time` in `pkg/dataplane/userspace/protocol.go:421` is one entry per spawned worker, so `len(WorkerHeartbeats)` IS the expected worker set — no separate count needed. **`dp == nil` or `dp.IsLoaded() == false`** → `Unknown` (daemon is up — it's answering gRPC — but the dataplane attach failed or was torn down; cf `pkg/daemon/daemon.go:609-613, 1057-1060` where `d.dp` can be nil while gRPC keeps serving). **`Online`** when `dp.IsLoaded()` is true AND every entry in `WorkerHeartbeats` is within 2s of now (eBPF path has no worker heartbeats; `Online` iff `IsLoaded()` returns true). **`Degraded`** when `IsLoaded()` is true but one or more `WorkerHeartbeats` entries are stale (>2s). **`Unknown`** also applies when the userspace `Status()` type assertion succeeds but returns an error, or `/proc/self/stat` / `statm` reads fail. (`GetMapStats()` has no error return — it always succeeds or returns an empty slice, so it cannot trigger `Unknown`.) Never `Offline` in local-render — if gRPC fails, the command errors before the formatter runs. |
| Daemon CPU % | `Daemon CPU utilization` | `ProcReader.ReadSelfStat` (utime, stime, starttime — all in USER_HZ clock ticks) + `ProcReader.ReadStat` (btime, Unix seconds when kernel booted). **USER_HZ** on Linux is 100 on every mainline kernel config we ship (CONFIG_HZ_100=y / CONFIG_HZ=100). Hardcoded as `const userHZ = 100` with a comment citing the kernel config. `golang.org/x/sys/unix` does not expose `Sysconf`/`_SC_CLK_TCK`; calling libc `sysconf()` would require cgo, which this package avoids. The hardcode is documented at the constant and a single-line sanity assertion at package init checks that `/proc/self/stat` starttime parses to a plausible value (< 1e12 ticks), catching the pathological case of a custom kernel with a different HZ. Tick → ns conversion: `ns = ticks * 1_000_000_000 / userHZ`. CPU % = `(utime_ns + stime_ns) / wall_ns_since_pid_start * 100 / runtime.NumCPU()`. `wall_ns_since_pid_start = time.Since(time.Unix(btime + starttime/USER_HZ, 0)).Nanoseconds()`. No `/proc/uptime` read required. | Uptime and CPU rows share the PID-start anchor (btime + starttime). In-memory `startTime` fallback (if /proc fails) differs by a few ms; acceptable at coarse display. Returns `cumulative since start`. Labeled `(cumulative since start)`. Recent-window rate deferred. |
| Worker threads CPU % | `Worker threads CPU utilization` | Userspace-dp: `WorkerRuntimeStatus.thread_cpu_ns` divided by `wall_ns`, summed across workers. eBPF path: row renders as `0 percent (N/A — eBPF path has no worker threads)` because packet processing on the eBPF path runs in kernel XDP/TC hooks, not user-space worker threads. | Reuses #869 telemetry on userspace-dp. eBPF fallback is explicit in the label so operators don't misread zero as "idle". Same `(cumulative since start)` label when the value is meaningful. |
| Heap % | `Heap utilization` | `/proc/self/statm` RSS vs cgroup `memory.max` (or `/proc/meminfo MemTotal` fallback) | Clamped 0-100. |
| Buffer % | `Buffer utilization` | eBPF: `dp.GetMapStats()` max across maps (signature is `[]MapStats`, no error return). userspace-dp: print `unknown (see #<follow-up>)` | Publishing BPF-map occupancy as "Buffer%" for userspace-dp is misleading because the authoritative signal there is UMEM/ring fill. File a follow-up issue to add UMEM telemetry; reference its number in the output. |
| Uptime | `Uptime:` | Primary: `/proc/self/stat` starttime converted via `/proc/stat` btime — same anchor the CPU row uses. Fallback (if /proc reads fail): in-memory daemon start time — gRPC handler passes `s.startTime` (`pkg/grpcapi/server.go:78`, already captured at `NewServer` line 138); local TTY passes a new `daemonStartTime time.Time` field on the CLI struct, populated at `pkg/cli/cli.New()` from `pkg/daemon/daemon.go:388`. → `time.Since` formatted "N days, N hours, N minutes, N seconds" | Sharing the PID-start anchor with the CPU row keeps the two numbers consistent. The in-memory fallback is only exercised if /proc is unreadable, which also triggers `State = Unknown`. Existing CLI field `c.startTime` (CLI-session start) is left untouched. |

### Sampling — no blocking sleep

Rejecting the previous plan's "two snapshots 1s apart" approach.
Rationale:

- Hostile to shell scripts that poll the command in a loop.
- Unnecessarily stateful-feeling for a shell command.
- The #869 worker runtime telemetry is already cumulative-since-start;
  that's the data we have, and it's honest to show it labeled as such.

Current-rate display is a separate feature. File a follow-up issue
"add recent-window rate sampling for `show chassis forwarding`" that
enhances the worker publish path to maintain `last_delta_ns` alongside
cumulative, so a reader gets rate without round-tripping.

### Cluster peer rendering — stubbed

Cluster-mode detection signal: the gRPC handler checks `s.cluster !=
nil && s.cluster.IsClusterEnabled()` (the same predicate
`showChassisCluster` uses to decide whether to render the per-node
`states` slice). When true, the MVP appends a single trailing line:

```
Note: peer-node rendering deferred to <follow-up issue #N>.
```

For the local TTY handler, use `c.cluster != nil && c.cluster
.IsClusterEnabled()` with the same rule. `fwdstatus.Build` takes a
`clusterMode bool` argument (see Files touched) and `Format` renders
the note when true. No peer data is fetched. This keeps the MVP free of new
gRPC surface and new HA sync traffic; follow-up PR wires cluster
rendering through the existing `show chassis cluster` peer-query
layer, not a new RPC.

### Files touched

Three code paths must reach the handler:

1. **Local TTY** (`xpfd` interactive) — dispatcher in `pkg/cli/cli_show_cluster.go::showChassis()` (line 19-30, switch on `args[0]`). Existing branches directly call local render functions (e.g. `showChassisHardware()`) that read `/proc/*` and daemon state inline. Add a `case "forwarding"` branch calling a new `c.showChassisForwarding()`.

2. **Remote CLI one-shot** (`cli -c "show chassis forwarding"`) and **remote CLI interactive** — both go through `cmd/cli/show.go`, which switches on `args[0]="chassis"` / `args[1]` and dispatches to `c.showText("chassis-*")` gRPC topics. Add a `case "forwarding": return c.showText("chassis-forwarding")` under the existing `chassis` branch.

3. **gRPC `ShowText`** (`pkg/grpcapi/server_show.go`, `ShowText()` at line 1274, topic switch at line 1954) — add a new case `"chassis-forwarding"` that builds + formats.

Topic string is **`chassis-forwarding`** (hyphenated, consistent with existing `chassis-cluster-*`, `chassis-environment`, `chassis-hardware`). Used identically in `cmd/cli/show.go`'s `showText()` call and the gRPC handler's case label.

To avoid circular imports (neither `pkg/cli` nor `pkg/grpcapi` currently imports the other), the shared struct + formatter live in a new small package `pkg/fwdstatus/`.

| File | Change |
|---|---|
| `pkg/cmdtree/tree.go` | Add `forwarding` leaf under `show → chassis`. Auto-propagates to `?` help and tab completion in both CLIs. |
| `pkg/fwdstatus/fwdstatus.go` (new) | Defines `type ForwardingStatus struct { ... }` and `Format(*ForwardingStatus) string` — pure formatter, no I/O. No dependencies on cli or grpcapi. |
| `pkg/fwdstatus/fwdstatus_test.go` (new) | Semantic table tests on `Format`. |
| `pkg/fwdstatus/builder.go` (new) | `Build(dp DataPlaneAccessor, proc ProcReader, startTime time.Time, clusterMode bool) (*ForwardingStatus, error)` — data gather. **`DataPlaneAccessor`** is a small local interface containing only `IsLoaded() bool` and `GetMapStats() []MapStats` (both present on `pkg/dataplane.DataPlane`); userspace-specific `Status()` is handled via a type assertion inside `Build` (`if us, ok := dp.(interface{ Status() (userspace.ProcessStatus, error) }); ok { ... }`), not part of the interface. `Build` accepts `dp == nil` without panic and sets `State = Unknown`. **`ProcReader`** is an interface with five methods: `ReadSelfStat() (ProcSelfStat, error)` (utime, stime, starttime), `ReadSelfStatm() (ProcSelfStatm, error)` (rss pages), `ReadStat() (ProcStat, error)` (btime), `ReadMemInfo() (ProcMemInfo, error)` (MemTotal for fallback), and `ReadCgroupMemoryMax() (uint64, error)` (returns 0 + nil error if not in a memory-capped cgroup). Package exports a default `OSProcReader{}` that reads real `/proc/*`. Tests use a fake `ProcReader` injecting success / os.ErrNotExist / malformed-content scenarios deterministically. **`clusterMode`** controls whether `Format` appends the deferred-peer note. |
| `pkg/grpcapi/server_show.go` | New case `"chassis-forwarding"` in the topic switch. Calls `fwdstatus.Build(s.dp, fwdstatus.OSProcReader{}, s.startTime, s.cluster != nil && s.cluster.IsClusterEnabled())` then `fwdstatus.Format(fs)`. Returns the string. |
| `pkg/cli/cli_show_chassis.go` (new) | `showChassisForwarding()` — calls `fwdstatus.Build(c.dp, fwdstatus.OSProcReader{}, c.daemonStartTime, c.cluster != nil && c.cluster.IsClusterEnabled())` + `fwdstatus.Format` directly (local TTY runs in daemon process so `c.dp`, `c.cluster`, and the daemon-start-time value are accessible). Requires injecting daemon start time into CLI constructor: add a `daemonStartTime time.Time` field to `pkg/cli/cli.go`'s CLI struct, populated at `New()` from `pkg/daemon/daemon.go:388`. |
| `pkg/cli/cli_show_cluster.go` | Add `case "forwarding": return c.showChassisForwarding()` to the `showChassis()` switch. |
| `cmd/cli/show.go` | Add `case "forwarding": return c.showText("chassis-forwarding")` under the existing `chassis` branch. |

No proto changes. No new RPC. The existing `ShowText` RPC's topic switch is the extension point.

### Test strategy

Dropped byte-for-byte golden comparison in favour of semantic checks
(per Codex round-1 feedback: golden strings are whitespace-brittle and
a maintenance burden):

1. **Label + value table test**: feed the formatter canned
   `ForwardingStatus` structs representing (online, degraded, unknown)
   × (eBPF, userspace-dp) scenarios. Assert that each expected label
   appears in the output, that the numeric value next to each label
   parses back to the input, and that label order is stable.
2. **Buffer honesty test**: for userspace-dp input, assert output
   contains "unknown" and a `#N` follow-up reference; for eBPF input,
   assert a `\d+ percent` value.
3. **State-transition test**: assert `State` reads `Online` with fresh
   heartbeats, `Degraded` with stale heartbeats, `Unknown` when
   `dp == nil` or `IsLoaded()` is false or userspace `Status()`
   returns an error or `/proc/self/stat` is unreadable or
   `/proc/self/statm` is unreadable. Each of these five `Unknown`
   triggers gets a named subtest so a regression that narrows the
   rule for one of them is caught.
4. **OSProcReader parser test**: separate test file
   `pkg/fwdstatus/osprocreader_test.go` exercises the real parser
   against checked-in fixtures under `pkg/fwdstatus/testdata/`:
   - well-formed + malformed `/proc/self/stat` (missing fields →
     parse error)
   - well-formed + malformed `/proc/self/statm` (non-numeric RSS →
     parse error)
   - well-formed + malformed `/proc/stat` (missing `btime` line →
     parse error)
   - well-formed + malformed `/proc/meminfo` (missing `MemTotal` →
     parse error)
   
   The malformed-case for each file asserts a non-nil error, not a
   silent zero. Covers the path the fake ProcReader deliberately
   skips.

One small end-to-end smoke test asserts the required labels are present
in a fully-rendered block and that their order matches the planned
layout. No byte-for-byte assertion.

### Deploy + feature validation

Per workflow step 8:

- **Deploy:** `make test-deploy` (standalone) AND `make cluster-deploy`.
- **Forwarding baseline:** ping + `iperf3 -P 16 -t 30 -p 5203` →
  172.16.80.200. Target ≥ 23 Gbit/s, no regression.
- **New command exercise:** `cli -c "show chassis forwarding"` on both
  xpf-fw and xpf-userspace-fw0. Verify all 6 rows render
  (State, Daemon CPU, Worker threads CPU, Heap, Buffer, Uptime);
  Buffer reads `unknown (#N)` on userspace-dp and `N percent` on
  eBPF; State reads `Online` on healthy daemon; Uptime parses as a
  non-zero duration.
- **CoS lane:** skipped — PR does not touch admission/DSCP/scheduler.
  Declared in PR body.
- **HA lane:** skipped — no failover/sync changes. Declared in PR body.

## Alternatives rejected

1. **Keep Junos labels (Microkernel / Real-time threads).** Rejected
   because those names carry vSRX-specific semantics (uKernel =
   control/OAM, real-time = PFE forwarding) we don't implement.
   Publishing them would mislead operators with vSRX background.
   Honest labels per first-principle #4.

2. **Two-snapshot 1s-sleep for rate display.** Rejected (Codex round-1
   feedback): blocks every invocation, hostile to scripted polling,
   unnecessary when cumulative data is honest and already available.
   Rate-over-recent-window is a separate feature; file follow-up.

3. **New gRPC `GetForwardingStatus` RPC.** Rejected: duplicates the
   existing status surface with a bespoke proto. Local-node data is
   already accessible without a new RPC. Cluster peer rendering
   belongs in a separate PR that reuses the existing peer-query path.

4. **Buffer% = max BPF map on userspace-dp too.** Rejected: dishonest.
   Userspace-dp's authoritative pressure signal is UMEM/ring fill,
   not BPF map occupancy. Print `unknown` with a follow-up reference
   until UMEM telemetry lands.

5. **Golden-string unit test.** Rejected: whitespace-brittle,
   maintenance burden. Semantic table tests pin the contract without
   pinning cosmetics.

## Follow-ups (to file before this PR lands)

- **Rate sampling**: daemon maintains `last_delta_ns` in the worker
  publish path so readers get recent-window CPU rate without blocking.
- **UMEM telemetry for userspace-dp**: expose per-worker UMEM frames
  in flight and total; use as Buffer% source for userspace-dp.
- **Cluster peer rendering**: wire `node0:` / `node1:` blocks through
  the existing peer-query layer used by `show chassis cluster`.

## Refs

- Closes #877 (local-node MVP; three follow-ups cover cluster peer,
  recent-window rate, and UMEM telemetry — see above).
- Builds on #869 / #874 (WorkerRuntimeStatus).
- Follows workflow from `docs/engineering-style.md` (merged via #876).
