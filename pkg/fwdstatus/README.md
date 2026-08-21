# pkg/fwdstatus

Builds and renders the single-screen forwarding-daemon health view
displayed by `show chassis forwarding`. Computes 5 s / 1 m / 5 m CPU
windows from a sampled time series and pretty-prints a Junos-style
fixed-width table.

## Entry points

- `ForwardingStatus` — `fwdstatus.go`. Flat status struct.
- `Format(fs *ForwardingStatus) string` — `fwdstatus.go`. Junos-style
  one-screen render.
- `State` — `fwdstatus.go`. Online / Degraded / Unknown.
- `CPUMode` — `fwdstatus.go`. Workers vs. eBPF.

## Callers

`pkg/grpcapi` (show command), `pkg/daemon` (status sampling).

## Dependencies

`pkg/dataplane/userspace` for userspace-helper status. Callers adapt
their runtime dataplane map telemetry into the package-local
`MapStats` shape; `pkg/fwdstatus` deliberately avoids importing the
root `pkg/dataplane` package, `pkg/cli`, or `pkg/grpcapi`.

## Gotchas

- CPU samples are collected by `Sampler` (`sampler.go`), which owns
  its own ring buffer and timer goroutine started via
  `Sampler.Start(ctx)`. The renderer consumes already-windowed
  values from the Sampler.
- The Sampler reads worker telemetry off the **cached** ProcessStatus
  (`CachedStatusProvider.CachedStatus()` — the Sampler's dataplane
  surface narrowed to exactly that one method in #2114, so the
  daemon-side adapter re-probes the currently published dataplane every
  tick and can never be misrouted into a `Build` path, which keys
  backend identity on `Status()` presence), NOT its own `Status()` call
  (#3970). The userspace manager's primary 1 Hz status poll
  (`statusLoop`) already fetches full `ProcessStatus` over the shared
  control socket every second and caches it; the Sampler consumes that
  cache so it adds **zero** control-socket traffic. A second periodic
  `Status()` here would double the status rate (2/s) on the socket
  shared with session installs and starve them during bulk sync
  (CLAUDE.md "Control socket contention"). On a cache miss (helper not
  yet polled) the worker counters hold at their previous values,
  preserving series monotonicity. `Build()` (on-demand `show chassis
  forwarding`) still calls `Status()` directly — that is a rare CLI
  diagnostic, not a periodic poller, so it is not a rate violation.
- The eBPF mode renders the worker-thread row as `N/A — eBPF path
  has no worker threads`. Don't add code that fakes a worker entry
  there; the N/A is informative.
- Daemon CPU is per-core percent (can exceed 100 on a multi-core
  daemon); worker CPU is computed as `Σ(thread_cpu_ns) / Σ(wall_ns)`,
  i.e. a per-worker average effectively bounded around 100%, not a
  multi-core sum.
- Windows shorter than the daemon uptime render as `-` to avoid lying
  about a 5 m average that hasn't elapsed yet.
- **Online requires positive, in-window heartbeat evidence (#4875).**
  On the userspace path `State` is `Online` only when the helper
  reported at least one worker heartbeat AND every heartbeat lands in
  the `[0, 2s]` age window (`heartbeatsHealthy` in `builder.go`). An
  empty/omitted heartbeat set (worker startup, or a wire-version
  mismatch that drops the field) and a future-dated heartbeat (a
  malformed/torn clock conversion — heartbeats share the host clock, so
  a heartbeat ahead of `now` is never real liveness) both read as
  `Degraded`, never `Online`. The old `allHeartbeatsFresh` treated an
  empty slice and a future timestamp as "trivially fresh" and fell
  straight through to `Online`, giving operators and failover
  automation a false-green forwarding state.
