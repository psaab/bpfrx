# pkg/api

HTTP REST API on `127.0.0.1:8080`. Read-only access to system state plus
operational commands (clear, ping, traceroute). Health probes for
liveness/readiness. Prometheus metrics endpoint. SSE event streams.

## Entry points

- `Server` — `server.go`
- `NewServer(cfg Config) *Server` — `server.go`.
- `Config` — `server.go`. All dependencies (configstore, dataplane, frr,
  vrrp, etc.) injected here; the package has no global state.

## Surface

- `GET /health` — liveness/readiness. `CompileHealthFn` (#758) lets the
  daemon downgrade `/health` to 503 when a recent compile failed
  silently; without the callback it defaults to 200.
  `ConfigPersistDegradedFn` (#1799, same injection pattern) downgrades
  `/health` to 503 while the running active config failed to persist to
  disk (HA config-sync or commit-confirmed auto-rollback hit a write
  error and the configstore's background retry has not yet succeeded —
  a restart would load a stale config). The same state is exported as
  the `xpf_daemon_config_persist_degraded` 0/1 gauge, emitted even when
  the dataplane is not loaded.
- `GET /metrics` — Prometheus exposition.
- `GET /api/v1/...` — REST mirrors of the gRPC API: sessions, routes,
  NAT, DHCP, IPsec, VRRP, OSPF, BGP, etc.
- `GET /api/v1/events/stream` — Server-Sent Events stream of dataplane
  events. Backed by the `pkg/logging` event ring buffer; long-lived
  consumers must drain.

## Callers

`cmd/xpfd` builds the `Server` from its assembled dependencies and runs it
under the daemon's errgroup. Nothing else imports this package.

## Dependencies

`config`, `configstore`, `conntrack`, `dataplane`, `dhcp`, `frr`, `ipsec`,
`logging`, `routing`, `vrrp`.

## Gotchas

- The status-poll path (1 Hz) shares the userspace dataplane control socket
  with HA sync, session installs, snapshot sync, and forwarding sync.
  Adding a new caller at >1 Hz here will starve session installs during
  bulk sync (per CLAUDE.md control-socket rules).
- Userspace CoS metrics are emitted from a single `Status()` snapshot per
  scrape. Queue-scoped drain-phase counters
  (`xpf_userspace_cos_drain_{guarantee,surplus}_sent_bytes_total` and
  `xpf_userspace_cos_drain_nonexact_sent_bytes_while_exact_backlogged_total`)
  deliberately include non-exact queues so best-effort/exact contention can be
  diagnosed. Exact-backlog cross-binding visibility uses per-binding
  cacheline-padded atomic slots (`SharedCoSExactBacklog`) written from the
  enqueue and completion paths; metric collection still reads from a single
  `Status()` snapshot per scrape rather than instrumenting the scrape path
  itself.
- Per-queue park-reason counters
  (`xpf_userspace_cos_root_token_starvation_parks_total`,
  `xpf_userspace_cos_queue_token_starvation_parks_total`,
  `xpf_userspace_cos_drain_park_root_tokens_total`,
  `xpf_userspace_cos_drain_park_queue_tokens_total`) attribute *why* a CoS
  queue stalled (#1642/#760, exported for #1359). A rising
  `root_token_starvation_parks` delta on a best-effort / mouse queue while a
  surplus-sharing borrower drains is the fingerprint of root-surplus
  arbitration — the borrower is holding the shared root tokens — and pins a
  surplus-sharing mouse-latency tail to *that* cause rather than this queue's
  own per-queue cap (`queue_token_*`) or worker scheduling. The Rust helper
  already carried these on the CoS snapshot; #1359 surfaced them to
  Prometheus. The `root_token_starvation_parks` / `queue_token_starvation_parks`
  pair is shaper-side; the `drain_park_root_tokens` / `drain_park_queue_tokens`
  pair counts the per-batch drain-loop decision (see
  `docs/cos-validation-notes.md`).
- The SSE handler reads from `pkg/logging.EventBuffer`. The buffer is
  bounded; if a consumer stops reading, events are dropped silently — by
  design.
- `CompileHealthFn` may be `nil` when the daemon is in `-no-dataplane`
  mode. All readyz code paths null-check it.
- Request-path external commands must be time-bounded (#1805): the
  deferred reboot/halt power actions go through `runTimeout` in
  `exec_timeout.go` (15s timeout + 5s WaitDelay, mirroring the
  apply-path contract in `pkg/daemon/exec_timeout.go`, #1794 — not
  importable here because pkg/daemon imports this package; the
  Output/CombinedOutput variants live in the pkg/grpcapi sibling copy).
  Power actions take `context.Background()` — client disconnect must
  not cancel a confirmed reboot — and keep ignoring errors. The
  ping/traceroute handlers keep their own request-ctx bounds but set
  `WaitDelay` so an inherited pipe cannot block past the kill; their
  budgets are request-sized (#1819) via `pingExecTimeout` (count × 1s +
  15s slack, 30s floor) and `diagTracerouteTimeout` (60s), capped at the
  150s `diagExecCeiling` and mirrored in `pkg/grpcapi/exec_timeout.go`.
  Do not add raw `exec.Command` calls in handlers: a wedged binary pins
  the handler goroutine and its HTTP connection.
