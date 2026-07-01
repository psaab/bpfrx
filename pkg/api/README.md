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
    validation is unambiguous on the canonical metrics surface. Each rule
    also carries the runtime `policy_id` (the RT_FLOW/session-table join
    key, #3336). #3623: `policy_id` is emitted ALWAYS (no `omitempty`).
    The first rule of the first zone-pair set legitimately has runtime id
    0 (`policySetID*MaxRulesPerPolicy + ruleIndex = 0`), and since #3057
    the implicit default policy uses a distinct sentinel (`0xFFFFFFFF`),
    so id 0 is UNAMBIGUOUSLY a real policy; `omitempty` previously dropped
    it, so a consumer joining an RT_FLOW event (`policy_id=0`) to the
    inventory found no row for the highest-priority rule. The gRPC
    `PolicyRule.policy_id` mirror is `optional uint32` (proto3 explicit
    presence) for the same reason. Each rule also carries `scheduler_name`
    and `inactive` (#3624) — the structured sibling of the #3062 TEXT
    policy-detail surface (`State: inactive` + `Scheduler:` lines).
    `scheduler_name` is the policy's configured `scheduler-name` (empty /
    omitted for an always-on rule); `inactive` is true when the policy is
    bound to a scheduler that is currently runtime-inactive — the dataplane
    is skipping the rule right now. Both are populated for zone-pair AND
    global policies from the same live-state provider the text surface uses
    (`Server.policySchedActiveFn` / gRPC `policySchedulerActiveState`), and
    like that surface they FAIL OPEN on the display: when live scheduler
    state cannot be queried (accessor not wired, early boot, NoDataplane)
    `inactive` stays false, so the output is unchanged for existing
    consumers — this differs deliberately from the `match-policies`
    simulator, which fails CLOSED (#3414). Without these an audit read a
    time-gated, currently-dormant permit/deny as an active allow/deny, so
    the structured API disagreed with effective dataplane behavior. The
    gRPC mirror is `PolicyRule.scheduler_name` (19) / `inactive` (20).
    A final synthetic `PolicyInfo` row with `from_zone="-"`/`to_zone="-"`
    carries a single rule named `default-policy` (#3363) — the implicit
    catch-all — with `policy_id` set to the reserved sentinel
    (`0xFFFFFFFF`) and, when `policy-stats system-wide enable` is set, the
    live hit counter read through the `DefaultPolicySentinelID` handle.
    This row reflects the configured `default-policy` action and, since
    #3670, its own RT_FLOW log intent: `log` / `log_session_init` /
    `log_session_close` are populated from `default-policy-log
    session-init`/`session-close` (compiled to
    `Security.DefaultPolicyLogSessionInit`/`Close`, threaded to the
    dataplane via `ConfigSnapshot.DefaultLogSessionInit`/`Close`, #3534) —
    the same log fields the configured rows expose (#3336). Before #3670
    the synthetic row omitted these, so audit tooling read the
    default-deny/permit boundary — the most security-relevant fallback —
    as unlogged while the dataplane was emitting default-verdict
    session-init/close records. The gRPC `GetPolicies` default row is
    identical (`PolicyRule.log` / `log_session_init` / `log_session_close`).
  - `GET /api/v1/security/zones` enumerates security zones (`ZoneInfo`,
    types.go). The host-inbound admission set is surfaced distinctly
    (#3328): `host_inbound_configured` is the dataplane posture bit
    (mirrors `ZoneSnapshot.HostInboundConfigured`, #3070/#3362/#3405).
    Post-#3405 EVERY configured security zone is host-inbound ENFORCING
    (Junos default-deny parity), so this bit is `true` for every zone the
    endpoint returns — it reports the dataplane truth, not config shape.
    A zone with NO `host-inbound-traffic` stanza default-DENIES host-bound
    traffic exactly like an explicit empty stanza; there is no admit-all
    posture for a configured zone. The admitted set lives in
    `host_inbound_system_services` and `host_inbound_protocols` (empty =
    deny-all; kept split so a system-service such as ssh/ping/dhcp is
    distinguishable from a routing protocol such as ospf/bgp), plus any
    `interface_host_inbound` per-interface override (#3362, omitted when
    none; the effective set for an interface is the union of the zone-level
    set and its override). The legacy flattened `host_inbound_services`
    (services + protocols concatenated) is retained as a back-compat alias.
    Before #3653 the bit was re-derived from config shape and reported
    `false` for a no-stanza zone — the pre-#3405 "false = admit-all"
    reading, the OPPOSITE of the runtime default-deny, so an auditor read
    the management plane as open when it is fail-closed. (Global
    ICMP/ND/PMTUD accepts and lifeline interfaces fxp0/em0/fab* still
    bypass the per-zone host-inbound deny.) Before #3328 REST exposed only
    the flattened list and no `configured` flag at all.
  - `GET /api/v1/security/screen` enumerates the configured screen
    profiles. Each `ScreenInfo` carries the profile `name`, a `checks`
    string list, and a `thresholds` map (keyed by check name). The
    `checks` list and the shared helper are the single source of truth
    with gRPC `GetScreen` (`config.ScreenChecks` /
    `config.ScreenThresholds`, #3327) — before #3327 each API carried a
    byte-identical copy that omitted `port-scan`, `ip-sweep`,
    `limit-session-source`, `limit-session-destination`, and
    `icmp-fragment` even though the compiler and userspace dataplane
    (`pkg/dataplane/userspace/screens.go`) fully enforce them, so an
    operator reading structured state saw active protection as absent.
    The `checks` set is kept a superset of the dataplane-enforced set.
    `thresholds` surfaces the configured numeric values (icmp/udp/syn
    flood, port-scan, ip-sweep, session limits) — only explicitly-set
    positive values appear, so a consumer can tell a default threshold
    from an intentionally tight or accidentally clamped one. The
    SYN-flood profile's several sub-thresholds are keyed individually
    (`syn-flood-attack-threshold`, `-alarm-`, `-source-`,
    `-destination-`, `-timeout`).
  - `GET /api/v1/statistics/global` — global dataplane counters
    (`GlobalStats`, types.go). The field set mirrors the gRPC
    `GetGlobalStats` reader: as of #3426 it includes `nat64_translations`
    (`GlobalCtrNAT64Xlate`) and `host_inbound_allowed`
    (`GlobalCtrHostInbound`) alongside the long-standing
    `host_inbound_denies`. Before #3426 REST omitted both, so an automation
    client reading only REST could not see NAT64 translation volume or the
    host-inbound allow count even though gRPC and Prometheus
    (`xpf_nat64_translations_total`) exposed them. A userspace-dp global
    counter read failure returns HTTP 500 (#3345), not a clean zero.
    The kernel nftables host-inbound DROP counters (the PRIMARY
    host-inbound enforcement signal — `host_inbound_kernel_denies`, its
    per-zone/family `host_inbound_kernel_deny_detail`, and the
    `host_inbound_kernel_denies_unavailable` marker) are handled on a path
    that mirrors the Prometheus collector rather than the userspace-dp
    counters (#3681):
    - **H04 (read before the gate):** the `inet xpf_hostinbound` chain is
      installed by the daemon INDEPENDENT of dataplane load and keeps
      dropping control-plane traffic on a config-only / degraded boot, so
      these counters are read BEFORE the `dataplane not loaded` check —
      matching `metrics_counters.go collectHostInboundKernelDenies`, which
      runs before its own dataplane gate. On an unloaded dataplane the
      endpoint returns a PARTIAL 200 with `dataplane_degraded: true` and the
      kernel host-inbound counters populated, instead of the old blanket
      503 that hid the host-inbound signal exactly when management-plane
      exposure matters most. The 503 gate is now scoped to the
      genuinely dataplane-dependent userspace counters.
    - **H05 (unavailable != zero):** a netlink read failure sets
      `host_inbound_kernel_denies_unavailable: true` (leaving the aggregate
      and detail at their zero values but marked non-authoritative) rather
      than silently reporting a misleading "0 denies" — the REST analogue of
      the Prometheus skip-the-series + `xpf_counter_read_errors_total` bump,
      and the same `Unavailable` idiom as per-interface counters (#3464). An
      absent chain (no host-inbound stanza enforced) reads as a clean 0 with
      no marker.
    - **L03 (zone/family split):** `host_inbound_kernel_deny_detail` carries
      the per-`{zone, family}` breakdown the aggregate scalar collapses,
      matching the `xpf_host_inbound_kernel_denies_total` labels.
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
- `GET /api/v1/security/events` (and the SSE event stream) return the full
  RT_FLOW forensic `EventEntry` (#3337). Both surfaces share one mapper,
  `eventEntryFromRecord`, so they never drift: beyond the 5-tuple they carry
  the resolved ingress/egress zone names, policy name, application name,
  ingress interface, close reason / policy reason, the reverse
  (server→client) packet/byte counters, the post-NAT source/destination
  tuples, session ID, elapsed/created time (with `created_nanos` sub-second
  remainder), ingress/egress SNMP ifIndex, IP TOS, and the OR of the TCP
  control bits. These mirror the gRPC `EventEntry`
  (`pkg/grpcapi` `GetEvents`) and the CLI RT_FLOW line. All forensic fields
  are `omitempty`, so a non-close event (or an unNAT'd / screen-drop record)
  omits the ones it does not carry. The machine APIs format timestamps with
  `RFC3339Nano` (sub-second), so high-rate events keep ordering/burst
  fidelity for cross-system correlation; the CLI keeps human-friendly
  whole-second output.

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
  per-policy, screen-flood, and filter read surface (NOTE: per-zone traffic +
  per-zone flood counters were later HIDE'd as "not available" by #3643 — a
  structural not-populated state is no longer treated as a read error; the
  genuine-error handling below still applies to the other surfaces — see the
  #3643 bullet):
  - **Structured APIs** return an explicit failure instead of clean-zero
    counter fields. REST `/stats/global` (global), `/security/zones`
    (per-zone), and `/security/policies` (per-policy) return HTTP 500 on
    a read error; gRPC `GetGlobalStats`, `GetZones`, and `GetPolicies`
    return `codes.Internal`. The error is checked AFTER the full response
    is built, so a failure on a late read (e.g. `RxPackets` after the
    screen-detail loop, or any policy/zone in the loop) is covered. The
    kernel-nftables host-inbound counters on `/stats/global` are the one
    exception: because they are dataplane-INDEPENDENT and read before the
    load gate (#3681), a read failure there does NOT 500 the whole response
    (which would hide the good userspace counters) — it sets the
    `host_inbound_kernel_denies_unavailable` marker, the same non-authoritative
    idiom as per-interface `unavailable` (#3464).
  - **Prometheus** (`metrics_counters.go`) OMITS the affected sample
    (rather than emitting a misleading `0`) for global, per-zone,
    per-policy, and per-filter reads, and bumps the monotonic
    `xpf_counter_read_errors_total` scrape-error counter, always emitted
    (0 when healthy) for alerting. The same counter is ALSO bumped by the
    pre-gate kernel-nftables host-inbound collector (`#3361`) when its
    netlink read fails, so the descriptor Help text names every read surface
    that increments it — global, zone, policy, and filter dataplane reads
    PLUS the kernel-nftables host-inbound read (#3463), not global-only, so
    it matches this contract. The error-counter SAMPLE is emitted LAST in
    `Collect` (`emitCounterReadErrors`), AFTER the global/zone/policy/filter
    sub-collectors (and the pre-gate host-inbound collector) have run, so a
    read failure in any of them is reflected in THIS scrape's value rather
    than lagging one scrape behind (#3462). The per-filter collector also
    merges the userspace-dp helper-published `filter_term_counters` into
    `xpf_filter_hits_total` (the same `BuildFirewallFilterTermCounterIndex`
    the CLI/gRPC text paths use), so the canonical metrics path does not
    report 0/stale while `show firewall filter` shows real hits (#3461); the
    per-term counter-slot stride is the shared
    `config.FilterTermExpansionCount` SSOT (#3459).
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
  - **Out of scope**: NAT-rule/port counters are not security counters and
    keep their existing per-read handling. Per-interface counters are also
    out of the SECURITY-counter contract, but they now carry their OWN
    uniform unavailable/error contract (#3464, below) so a degraded
    interface-counter bridge is no longer handled divergently across surfaces.

  Pinned by `stats_counter_error_test.go` +
  `zones_policies_counter_error_test.go` (REST + Prometheus),
  `pkg/grpcapi/global_stats_counter_error_test.go` (incl. the late-read
  ordering case) + `flow_cluster_counter_error_test.go` +
  `zones_policies_counter_error_test.go`, and
  `pkg/cli/show_security_counter_error_test.go` (incl. late-read ordering
  cases that fail if a warn is moved before the per-type screen-breakdown
  loop). This resolves both #3345 and #3408.
- **#3643 — per-zone traffic + flood counters are HIDE'd ("not available"),
  not errored.** The per-zone traffic counters (`zone_counters`) and per-zone
  flood counters (`flood_counters`) were never populated in the userspace era
  (the eBPF writers were deleted in #1476) AND, worse, zone ids are stable
  name-hashes in `[1,65533]` (#3075) while the backing BPF arrays are dense
  `MaxZones*2` / `MaxZones`-entry arrays, so every read of a stable-hash id `>=
  MaxZones` OOB'd the bounded `Lookup` and surfaced as a HARD failure — REST
  `/security/zones` returned **HTTP 500** for essentially every real config, and
  the Prometheus per-zone collector bumped `xpf_counter_read_errors_total` once
  per zone per scrape (a permanent FALSE #3345 alert). The HIDE fix:
  `dataplane.ReadZoneCounters`/`ReadFloodCounters` now key a Go-side sparse
  offset map and NEVER index the dense array (the #2255 `nat_rule_counters`
  treatment), returning the distinct `dataplane.ErrCounterNotPopulated`
  sentinel while unpopulated. The read surfaces recognize that sentinel and
  render an explicit **"not available"** — REST `/security/zones` returns 200
  with `per_zone_counters_available:false` (counts unset, not a misleading 0);
  `show security zones` and `show security screen ids-option statistics` print a
  "not available" line; and the always-erroring `xpf_zone_packets_total` /
  `xpf_zone_bytes_total` Prometheus metrics were **dropped** (there is no
  per-zone flood Prometheus/REST surface to remove). The #3345/#3408
  genuine-error contract is UNCHANGED for every other surface (global, policy,
  filter, interface, host-inbound): a real read failure — anything other than
  `ErrCounterNotPopulated` — still 500s / warns / bumps
  `xpf_counter_read_errors_total`. The per-zone POPULATE path (sourcing real
  per-zone volume + flood-event counts from the Rust helper) is DEFERRED; the
  sparse offset map's setters are the populate hook. See
  `docs/research/3643-dead-counters/plan.md` (§5A POPULATE spec, §5B HIDE) and
  the follow-up enhancement issue. Pinned by
  `pkg/dataplane/zone_flood_counters_hide_test.go`,
  `pkg/api/zone_counters_hide_test.go`,
  `pkg/cli/zone_flood_counters_hide_test.go`, and
  `pkg/grpcapi/zone_flood_counters_hide_test.go`.
- Per-interface counter read failures get a uniform unavailable/error
  contract across all four interface-counter surfaces (#3464). Interface
  counters are intentionally out of the #3345 SECURITY-counter contract
  (above), but they used to be handled DIVERGENTLY on a failed
  `ReadInterfaceCounters`: REST `/stats/interfaces` dropped the whole row
  (the interface vanished), REST `/interfaces` and gRPC `GetInterfaces` left
  a clean `0` (indistinguishable from a real idle interface), and the
  Prometheus collector silently omitted the sample with no error metric. An
  operator could not tell "interface idle" from "counter bridge unavailable".
  The uniform contract:
  - **Structured APIs** KEEP the interface row and set an explicit
    `unavailable` flag (`InterfaceStats.unavailable` on REST `/stats/interfaces`
    + `/interfaces`; `InterfaceInfo.unavailable` on gRPC `GetInterfaces`). The
    counter fields stay `0` but are not authoritative — a real idle `0` is
    distinguishable from a degraded read. `/stats/interfaces` no longer drops
    the row (the old `continue`). A read failure does NOT escalate to HTTP 500
    / `codes.Internal` (unlike the security counters): interface counters are
    operability telemetry, not a security signal, so per-row degradation is
    preferred over failing the whole inventory.
  - **Prometheus** (`metrics_counters.go`) still OMITS the affected
    `xpf_interface_{packets,bytes}_total` sample (rather than emitting a
    misleading `0`) and bumps the dedicated
    `xpf_interface_counter_read_errors_total` monotonic counter — SEPARATE
    from `xpf_counter_read_errors_total` so interface-counter degradation is
    alertable without conflating it with security-counter health. The sample
    is always emitted (0 when healthy) and emitted AFTER
    `collectInterfaceCounters` (`emitInterfaceCounterReadErrors`) so a failure
    this scrape is reflected this scrape.
  - The kernel-link `net.InterfaceByName` "not present" case (a different
    axis — interface absent from the kernel, not a counter-bridge failure)
    keeps each surface's existing handling and is NOT flagged `unavailable`.

  Pinned by `interface_counter_error_test.go` (REST + Prometheus) and
  `pkg/grpcapi/interface_counter_error_test.go` (gRPC). This resolves #3464.
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
- Interface-mode source-NAT rows (`source-nat interface`, no named pool)
  report `UsedPorts` as the count of forward SNAT sessions that traversed
  THAT rule set's own from/to zone pair — not the firewall-wide SNAT total
  (#3417). `natPoolStatsHandler` iterates sessions once, keying the count by
  the session's ingress/egress zone (mapped to names via the apply result's
  `ZoneIDs`), and each `<from>-><to>` row reads only its own bucket. Without
  the zone map (no apply result yet) attribution is impossible, so rows
  report 0 rather than a wrong aggregate. The #2469 fail-closed behavior is
  preserved: a partial session scan returns HTTP 500 rather than a
  healthy-but-low figure. The gRPC `GetNATPoolStats` mirrors this, setting
  each interface row from `counts.ruleSetSessions[{from,to}]` (the same
  per-rule-set breakdown it already surfaces in `RuleSetSessions`); CLI `show
  security nat source pool` renders the gRPC value directly. Pinned by
  `TestNATPoolStatsHandlerInterfaceModePerRuleSet` (REST) and
  `TestGetNATPoolStatsInterfaceModePerRuleSet` (gRPC), both fail-on-revert.
- Query-filter parsing fails CLOSED, matching the gRPC contract
  (#2934/#2935/#2939). A filter sentinel of `0`/`""` means "no filter",
  so a *malformed* filter value must error rather than silently fall
  through to no-filter (which widens the query to everything — a
  cross-zone observability leak). `queryUint16Strict`/`queryIntStrict`
  (`api.go`) return `(0, false)` on a malformed non-empty value; the
  sessions/events `zone` filter and the policy-match `dst_port`/`src_port`
  return HTTP 400 instead of zeroing the predicate. #3679: `queryIntStrict`
  parses via `config.ParseCanonicalUint` rather than `strconv.Atoi`, so a
  signed/non-canonical spelling (`dst_port=+80`, which `Atoi` accepted as `80`)
  is rejected here exactly as the #3606 commit-time and dataplane port parsers
  reject it — no commit-vs-diagnostic split. The session `protocol`
  filter (`sessions.go` `protoFilterMatches`) is case-insensitive AND
  accepts a numeric IP protocol number (`tcp`/`TCP`/`6` all match TCP),
  mirroring gRPC (`pkg/grpcapi` `protoFilterMatches`) and CLI. The event
  filter (`pkg/logging` `EventFilter.matches`) matches protocol/action
  EXACTLY (case-insensitive), not by substring — `protocol=C` no longer
  over-matches TCP/ICMP/ICMPv6. These contracts are pinned by
  `rest_filter_failclosed_test.go` in this package.
- The `GET /api/v1/security/sessions` view mirrors the gRPC `GetSessions`
  session contract (#3419). The REST `SessionEntry` previously diverged from
  gRPC — `age_seconds` carried IDLE time (now-LastSeen) instead of wall age,
  a session with both SNAT and DNAT lost the SNAT part (the DNAT branch
  overwrote the single `nat` string), the reverse entry's counters were not
  merged into the forward entry, and the application/interface/policy-name/
  zone-name/session-id/ha-active fields were absent. The handler now:
  - splits `age_seconds` (now-`Created`) from `idle_seconds` (now-`LastSeen`);
  - joins BOTH NAT parts in `nat` and exposes structured `nat_src_addr/port`
    and `nat_dst_addr/port`;
  - merges the companion reverse entry's counters via `GetSessionV4/V6`
    (added to `apiRuntimeDataPlane`) so top-talkers/accounting report full
    bidirectional volume;
  - resolves `application` (`appid.ResolveSessionName`), `ingress_interface`/
    `egress_interface` (FIB ifindex+VLAN → unit name), `policy_name`,
    `ingress_zone_name`/`egress_zone_name`, `session_id`, and `ha_active`
    (wired from the daemon via `HAActiveFn`, default true standalone).

  It also accepts the gRPC filter set: `application=`, `interface=`,
  `nat_only=true`, and `source_nat_pool=<pool>` (an unresolved pool fails
  CLOSED with HTTP 400, like the gRPC `sessionFilter.validate`). The numeric
  `policy_id`/`ingress_zone`/`egress_zone` fields are retained for
  compatibility. Pinned by `sessions_parity_test.go`.
- HA scope on the session list/summary (#3423 M5). The REST list and summary
  report the LOCAL node's table only; previously they carried no node identity
  and no way to include the peer, so a dashboard polling one node could not
  tell WHICH node it observed and understated total cluster session state. Both
  now always carry `node_id` (this node's cluster id, 0 standalone; wired from
  the daemon via `NodeIDFn` → `cluster.NodeID()`), and both accept
  `include_peer=true` (a malformed value fails CLOSED with HTTP 400). When set,
  the handler delegates the PEER fetch to the live gRPC server through the
  `ClusterSessionFn`/`ClusterSessionService` seam and attaches the peer node's
  list/summary under a nested `peer` field (mirroring gRPC `GetSessions`/
  `GetSessionSummary` `include_peer`). The peer's FULL table is attached only on
  the FIRST page — in BOTH pagination modes (cursor mode's first page has no
  `page_token`; offset mode's first window has `offset==0`). A non-first page
  must not re-attach the whole peer table or a client summing `peer.sessions`
  across pages would OVER-COUNT the peer; the offset path never sets a
  `page_token`, so the `sessionFirstPage` guard checks `offset==0` too. A
  standalone node or unreachable peer leaves `peer` absent. Pinned by
  `sessions_ha_scope_3423_test.go`.
- The zone-pair summary (`GET /api/v1/security/sessions/summary/zone-pairs`,
  `sessionZonePairHandler`) is the same SUMMARY class and carries `node_id` —
  the response shape changed from a bare array to
  `ZonePairSummaryResponse {node_id, zone_pairs:[...]}` so it can (#3423 M5). It
  now also supports `include_peer=true` cross-node fan-out (#3592), matching its
  `/sessions/summary` sibling. A malformed `include_peer` value fails CLOSED with
  HTTP 400 before any work. When set, the handler forwards to the new gRPC
  `GetZonePairSummary` RPC through the `ClusterSessionFn`/`ClusterSessionService`
  seam (`IncludePeer` set) and attaches the cluster peer's OWN zone-pair
  breakdown under a nested `peer` field (`ZonePairSummaryResponse.Peer`, carrying
  the peer's own `node_id`). Unlike the session LIST there is no first-page gate
  — the breakdown is a summary, not a paginated list, so the whole peer breakdown
  attaches whenever `include_peer` is set (just as `/sessions/summary` attaches
  the whole peer summary). The gRPC RPC computes the peer's breakdown locally and
  uses the `x-peer-forwarded` metadata recursion guard so A→B never recurses back
  into A; a standalone node, an unreachable peer, or a failed peer RPC leaves
  `peer` absent (a read summary degrades gracefully). Pinned by
  `sessions_ha_scope_3423_test.go` (node_id), `sessions_zonepair_peer_3592_test.go`
  (REST fan-out + fail-closed), and `zonepair_summary_3592_test.go` (gRPC RPC +
  recursion guard).
- Session list pagination and the remaining filter dimensions reach gRPC
  parity in #3421, folded into the SAME `sessionQuery` + `sessionView` +
  enriched `sessionEntryV4/V6` machinery above (one filter type, not two).
  Added filters: `source_prefix`, `destination_prefix`, `source_port`,
  `destination_port` (prefixes accept a CIDR or a bare IP; mirror the gRPC
  `matchV4`/`matchV6` predicates), each parsing FAIL-CLOSED — a malformed
  prefix/port returns HTTP 400 instead of zeroing the predicate and widening
  the query (#3421 M2). Pagination has two modes: the default best-effort
  `limit`/`offset` window (now parsed strict — malformed/negative → 400,
  #3421 M8), and a stable cursor mode selected by `page_size>0`. Cursor mode
  iterates v4 then v6 from an opaque `page_token`, returning up to
  `page_size` rows plus a `next_page_token` that resumes exactly after the
  last row (no skip/duplicate across map mutation, the offset path's hazard);
  an empty `next_page_token` marks the last page. Both modes share the
  reverse-counter merge + enrichment, so they report IDENTICAL rows and
  counters. The token codec mirrors the gRPC page-token format and encodes
  node-local session-map keys (opaque to clients); when the runtime
  dataplane lacks cursor iteration the handler falls back to the offset path.
  Pinned by `sessions_pagination_test.go`.
- Session clear (`POST /api/v1/security/sessions/clear`) clears ALL local
  sessions and accepts NO parameters: a non-empty query string
  (`r.URL.RawQuery`) or request body returns HTTP 400 rather than silently
  ignoring filter parameters and wiping the whole table (#3421 H6).
- HA fan-out on the clear (#3423 H5). In a chassis cluster the clear MUST also
  reach the peer: a local-only clear left the peer/synced sessions, which could
  reappear as active state on failover, with no indication to the operator that
  the clear was local-only. When the HA-aware session service is wired (the
  daemon's `ClusterSessionFn` → live gRPC server), the handler now delegates the
  clear-all to it, sharing the SAME service-layer path gRPC uses: local clear +
  peer propagation (`clearPeerSessions`, the `x-peer-forwarded` recursion guard)
  + partial-failure summary. The `ClearSessionsResult` carries `node_id` (which
  node served it) and `failures`/`failure_summary` — a non-zero `failures` with
  a `peer clear:` summary (now naming the PEER NODE, e.g. `dial peer node 1`,
  so it is operator-actionable) means the local clear succeeded but the peer's
  sessions were NOT cleared. **Partial-failure status:** when the local clear
  succeeds but the peer clear fails the endpoint still returns **HTTP 200** —
  the project uses no `207 Multi-Status` anywhere, so the failure is surfaced in
  the body, NOT the status line. **Clients MUST inspect `failures` /
  `failure_summary`; a status-only check will read a peer-clear failure as
  success.** A hard LOCAL clear failure still returns HTTP 500. A standalone
  node (no service wired) falls back to the local-only `ClearAllSessions` — the
  pre-#3423 behavior. Pinned by `sessions_ha_scope_3423_test.go`. The
  gRPC-parity FILTERED REST clear (clear a narrowed subset) remains a separate,
  unimplemented follow-up.
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
  rule / default-policy. #3414: when live state is unavailable (no dataplane /
  early boot) the handler binds the predicate to a nil state map, which
  `PolicyInactiveFn` treats as fail-closed — scheduled policies are simulated
  as INACTIVE, matching the snapshot builder (nil scheduler state => dropped)
  rather than certifying an as-if-active verdict the dataplane is skipping. A
  non-scheduled policy is unaffected either way. On a MATCH the response
  carries the matched policy's runtime `policy_id` (#3331 scope/id
  disambiguation). #3623: this field is a `*uint32` — set (present, even at
  0) ONLY on a match, omitted otherwise. The first zone-pair set's first
  rule has runtime id 0; a plain `uint32`+`omitempty` dropped it, so a
  matched-first-policy answer was indistinguishable from an unmatched one
  (both encoded as absent). The gRPC `MatchPoliciesResponse.policy_id`
  mirror is `optional uint32` for the same reason. #3627 M06: the response
  ALSO echoes the queried zone pair on `queried_from_zone`/`queried_to_zone`
  on EVERY answer — positive match, no-match/default, and host-inbound — so a
  stored JSON diagnostic for a default-deny or host-inbound verdict proves
  which zone pair produced it without a separate copy of the request URL.
  These are the query context and are DISTINCT from `from_zone`/`to_zone`
  (the matched policy's declared SCOPE, #3331, set only on a positive match):
  for a wildcard-zone or global match the two can differ. The gRPC
  `MatchPoliciesResponse.queried_from_zone`/`queried_to_zone` (fields 13/14)
  mirror this. #3668: on a MATCH the response also carries
  `source_address_excluded`/`destination_address_excluded` and the stable
  `rule_id`. The exclusion flags report whether the matched policy carries Junos
  `source-address-excluded`/`destination-address-excluded` — the rule matches
  every address EXCEPT those in `src_addresses`/`dst_addresses`. The shared
  matcher already inverts the address test correctly; without the flags a
  positive verdict against a source OUTSIDE an excluded set printed the excluded
  list as if it were the reason for the match (backwards for an audit tool). The
  renderers annotate the exclusion as `Source addresses (except): ...`. `rule_id`
  is the stable `<from>-><to>/<name>` identity the inventory (`GetPolicies`), the
  snapshot, and the event path carry (`dpuserspace.StablePolicyRuleID`), so a
  simulator hit joins to the inventory row / logs / tests even after a policy
  reorder shifts the numeric `policy_id`; a matched global policy uses the
  `junos-global->junos-global/<name>` form, matching the inventory global rows.
  All three are additive and set only on a positive match. The gRPC
  `MatchPoliciesResponse.source_address_excluded`/`destination_address_excluded`
  (fields 15/16) and `rule_id` (field 17) mirror this. #3685 M05/M06: on a MATCH
  the response also carries the policy `description` and the scheduler binding.
  `description` (M05) is the matched policy's `description` text — the same field
  the inventory (`GetPolicies`) and the local `show security match-policies`
  result carry over the SAME `policymatch.Result`; descriptions often hold
  ticket / change-control context, so a match verdict without it was weaker than
  the inventory / CLI answer. `scheduler_name`/`scheduler_active` (M06) name the
  time-gate: `scheduler_name` is the policy's `scheduler-name` binding
  (mirroring the inventory `PolicyRule` field, #3624), and `scheduler_active` is
  the explicit effective-active flag. A positive match is by construction
  currently active — the handler always threads a fail-closed
  `PolicyInactiveFn` (#3414) that SKIPS a scheduler-inactive rule before it can
  match — so a matched scheduled policy always reports `scheduler_active=true`;
  it names the gate admitting the rule right now, not a rule that is gated off.
  All three are additive and set only on a positive match; both scheduler fields
  are omitted for a non-scheduled (always-on) policy. The gRPC
  `MatchPoliciesResponse.description` (field 18), `scheduler_name` (field 19),
  and `scheduler_active` (field 20) mirror these.
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
