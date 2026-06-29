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
  `RollbackHistoryDegradedFn` (#3441, same injection pattern) reports
  whether the most recent commit failed to durably persist its text
  rollback-history files. UNLIKE the two above it does NOT downgrade
  `/health` to 503 — the commit succeeded and the active config is
  durable, so a forwarding firewall must not be pulled from rotation over
  a degraded recovery aid; it is surfaced as the non-fatal
  `rollback_history_degraded` field plus the
  `xpf_config_rollback_persist_degraded` 0/1 gauge (also emitted even
  when the dataplane is not loaded) for alerting.
- `GET /metrics` — Prometheus exposition.
- `GET /api/v1/...` — REST mirrors of the gRPC API: sessions, routes,
  NAT, DHCP, IPsec, VRRP, OSPF, BGP, etc.
  - `GET /api/v1/security/policies` enumerates zone-pair policies AND
    global policies (#3045). Global rules are emitted as a single
    trailing `PolicyInfo` row with `from_zone="*"`/`to_zone="*"`,
    matching gRPC `GetPolicies` and the Prometheus collector. Global
    counter IDs follow the zone-pair policy-set count (the `policySetID`
    continues from the zone-pair loop), so per-policy hit counters stay
    aligned with the dataplane when `policy-stats system-wide enable` is
    set. A scoped global policy (#3148 `match from-zone`/`to-zone`)
    carries its narrowing on the per-rule `match_from_zone` /
    `match_to_zone` fields (#3286), omitted when empty; the group row
    stays `*`/`*` (the all-zones tier). Before #3286 these were absent,
    so a scoped global looked all-zones to automation. The Prometheus
    `xpf_policy_hits_total` collector (metrics_counters.go) likewise emits
    the scoped global's real zones on its `from_zone`/`to_zone` labels
    (#3286) — an unscoped global keeps `*`/`*` — so counter-based
    validation is unambiguous on the canonical metrics surface.
  - `GET /api/v1/statistics/global` — global dataplane counters
    (`GlobalStats`, types.go). The field set mirrors the gRPC
    `GetGlobalStats` reader: as of #3426 it includes `nat64_translations`
    (`GlobalCtrNAT64Xlate`) and `host_inbound_allowed`
    (`GlobalCtrHostInbound`) alongside the long-standing
    `host_inbound_denies`. Before #3426 REST omitted both, so an automation
    client reading only REST could not see NAT64 translation volume or the
    host-inbound allow count even though gRPC and Prometheus
    (`xpf_nat64_translations_total`) exposed them. A counter read failure
    returns HTTP 500 (#3345), not a clean zero.
- `GET /api/v1/events/stream` — Server-Sent Events stream of dataplane
  events. Backed by the `pkg/logging` event ring buffer; long-lived
  consumers must drain. `?category=` (and `?severity=` on
  `/api/v1/logs/stream`) is fail-closed (#3383): an unrecognized token is
  rejected with `400` BEFORE the connection switches to event-stream, so a
  typo cannot silently widen the live feed to everything. A `SCREEN_DROP`
  with `action=permit` (the scan-table-pressure alarm — the packet still
  forwards) is classified `notice`, not `error`, mirroring the canonical
  `logging.eventSeverity`; an unknown event type fails closed under a
  narrow category mask.

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
- Session-view read paths must NOT publish a partial scan as success
  (#2469). A backend session-iterator error (e.g. helper restart
  mid-scan) makes `IterateSessions`/`IterateSessionsV6` return non-nil.
  The REST session handlers (`/sessions`, `/sessions/summary`,
  `/sessions/zone-pair`, interface-mode NAT pool stats) return HTTP 500
  on that error instead of an HTTP 200 with a partial/zero body. The
  Prometheus session-breakdown collector emits
  `xpf_sessions_breakdown_scrape_ok` (1 = full scan, 0 = truncated) and
  OMITS the `xpf_sessions_{ipv4,ipv6,snat,dnat}` gauges when the scan
  failed, so an alert fires rather than a graph silently dropping to
  zero. The gRPC `GetSessions` (legacy + cursor) and `GetSessionSummary`
  return `codes.Internal` on the same error. The contract is pinned by
  `sessions_iterator_error_test.go` in this package and in `pkg/grpcapi`
  / `pkg/cli` (CLI top-talkers fails the command; NAT summaries print a
  stderr warning).
- Dataplane counter read failures get a uniform observability-integrity
  treatment (#3345 global; #3408 per-zone / per-policy / screen-flood /
  filter): a failed counter read is no longer swallowed to `0`, because a
  degraded counter bridge must not be indistinguishable from "no events"
  on a security appliance. The fix covers EVERY global, per-zone,
  per-policy, screen-flood, and filter read surface:
  - **Structured APIs** return an explicit failure instead of clean-zero
    counter fields. REST `/stats/global` (global), `/security/zones`
    (per-zone), and `/security/policies` (per-policy) return HTTP 500 on
    a read error; gRPC `GetGlobalStats`, `GetZones`, and `GetPolicies`
    return `codes.Internal`. The error is checked AFTER the full response
    is built, so a failure on a late read (e.g. `RxPackets` after the
    screen-detail loop, or any policy/zone in the loop) is covered.
  - **Prometheus** (`metrics_counters.go`) OMITS the affected sample
    (rather than emitting a misleading `0`) for global, per-zone,
    per-policy, and per-filter reads, and bumps the monotonic
    `xpf_counter_read_errors_total` scrape-error counter, always emitted
    (0 when healthy) for alerting.
  - **Text commands** print a `warning: ... counter read failed ...` line
    instead of a clean zero: `show security screen` / `show security
    alarms` / `show security flow statistics` / `show chassis cluster
    fabric statistics` / `show security nat source` (global + flood), and
    `show security policies hit-count` + brief (per-policy), `show
    security zones` (per-zone), `show security screen statistics` (flood),
    and `show firewall filter` (filter) — across both the CLI and the gRPC
    text mirrors.
  - **Ordering invariant**: in every multi-read renderer the `readErr`
    check runs AFTER all counter reads in the function (incl. the detail /
    per-type screen-breakdown and per-policy/per-zone loops), so a failure
    on a LATE read is surfaced rather than printing a stale `0` under an
    earlier passed check. The structured APIs follow the same rule (check
    after the full response is built).
  - **Out of scope**: per-interface and NAT-rule/port counters are not
    security counters and keep their existing per-read handling.

  Pinned by `stats_counter_error_test.go` +
  `zones_policies_counter_error_test.go` (REST + Prometheus),
  `pkg/grpcapi/global_stats_counter_error_test.go` (incl. the late-read
  ordering case) + `flow_cluster_counter_error_test.go` +
  `zones_policies_counter_error_test.go`, and
  `pkg/cli/show_security_counter_error_test.go` (incl. late-read ordering
  cases that fail if a warn is moved before the per-type screen-breakdown
  loop). This resolves both #3345 and #3408.
- Named source-NAT pool stats are sourced from the userspace helper's
  LIVE runtime status, not config text (#2938). `natPoolStatsHandler`
  (`/security/nat/source/pools`) reads `s.runtimeSourceNATPools()` — the
  helper's `ProcessStatus.SourceNATPools` (`SourceNATPoolStatus`),
  deduplicated by pool name (rules sharing a pool reference the same
  `Arc<PortAllocatorShared>` and report identical occupancy, so one entry
  per pool is kept, never summed — same contract as
  `pkg/dataplane/userspace/applied_nat_view.go`). The reported
  `AddressCount`, port window (`PortLow`/`PortHigh`), and `UsedPorts` come
  from that runtime view; `TotalPorts` = `(PortHigh-PortLow+1) *
  AddressCount`. The helper is authoritative because it rejects malformed
  addresses, splits pools by IP family, shares allocator state across
  rules, and reports actual used ports — config text + the retired-eBPF
  `ReadNATPortCounter` could over-report capacity or report a dead-map
  count under the AF_XDP dataplane. The config-derived window +
  `ReadNATPortCounter` path remains ONLY as a fallback when the helper has
  no runtime entry for a pool (helper not running / before the first
  apply lands). Pinned by `TestNATPoolStatsHandlerUsesRuntimeStatus`
  (fail-on-revert) in `nat_stats_test.go`. The gRPC `GetNATPoolStats`,
  CLI `show security nat source pool`, and the Prometheus
  `xpf_nat_pool_total_ports` / `xpf_nat_pool_used_ports` collector
  (`metrics_nat.go`) still derive named-pool capacity/used from config +
  the legacy counter and are the follow-up SSOT surfaces (the Prometheus
  `xpf_userspace_snat_pool_*` family in `metrics_userspace.go` already
  exposes the runtime per-pool view).
- Query-filter parsing fails CLOSED, matching the gRPC contract
  (#2934/#2935/#2939). A filter sentinel of `0`/`""` means "no filter",
  so a *malformed* filter value must error rather than silently fall
  through to no-filter (which widens the query to everything — a
  cross-zone observability leak). `queryUint16Strict`/`queryIntStrict`
  (`api.go`) return `(0, false)` on a malformed non-empty value; the
  sessions/events `zone` filter and the policy-match `dst_port`/`src_port`
  return HTTP 400 instead of zeroing the predicate. The session `protocol`
  filter (`sessions.go` `protoFilterMatches`) is case-insensitive AND
  accepts a numeric IP protocol number (`tcp`/`TCP`/`6` all match TCP),
  mirroring gRPC (`pkg/grpcapi` `protoFilterMatches`) and CLI. The event
  filter (`pkg/logging` `EventFilter.matches`) matches protocol/action
  EXACTLY (case-insensitive), not by substring — `protocol=C` no longer
  over-matches TCP/ICMP/ICMPv6. These contracts are pinned by
  `rest_filter_failclosed_test.go` in this package.
- `GET /api/v1/security/match` (`matchPoliciesHandler`) is a THIN adapter
  over the single shared policy simulator `pkg/policymatch` (#3042). It only
  validates/parses inputs (400 on a malformed IP/port) and renders the
  verdict; all matching logic lives in `policymatch.Match`, which replicates
  the runtime evaluator (`userspace-dp/src/policy.rs`): zone-pair → global →
  configured `default-policy` (NOT a hard-coded deny), predefined apps,
  multi-level application-sets, literal CIDRs, `any-ipv4`/`any-ipv6`,
  source/destination exclusion, and the live feed-prefix overlay
  (`FeedOverlayFn`). The pre-#3042 hand-written matcher scanned only
  zone-pair policies, hard-coded `deny (default)`, and missed predefined
  apps / literal CIDRs — so the diagnostic could report the OPPOSITE of what
  the dataplane enforces. #3104: the handler also threads live per-scheduler
  active-state (`PolicySchedulerActiveStateFn`, wired from the daemon-local
  `Manager.PolicySchedulerActiveState`) into `policymatch.Query.PolicyInactiveFn`,
  so a scheduler-inactive policy is SKIPPED exactly like the runtime
  (`policy.rs try_match_rule`) and the verdict falls through to the next active
  rule / default-policy. When live state is unavailable (no dataplane) the
  simulator evaluates scheduled policies as-if-active (the #3062 display
  fallback) — a non-scheduled policy is unaffected either way.
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
  The argv builders (`buildPingArgv`/`buildTracerouteArgv`) place the
  user-supplied target after a `--` end-of-options separator so a
  `-`-prefixed target is an operand, not a flag (option-confusion
  hardening, #2084).
  Do not add raw `exec.Command` calls in handlers: a wedged binary pins
  the handler goroutine and its HTTP connection.
