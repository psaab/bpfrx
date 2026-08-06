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
  **Redaction (#5031):** `/health` is unconditionally unauthenticated
  (`authMiddleware` exempts it), so it exposes only status, counters,
  timestamps, and stable reason codes — never the raw compile/bootstrap
  error strings. `compile_last_error` and `bootstrap_import_error` are NOT
  emitted (those strings are copied verbatim from the parser/compiler and
  can carry file paths, config internals, or a secret echoed by a schema
  validator). The failure is still signalled by `compile_failure_count` /
  `compile_last_error_unix` and `bootstrap_import_status` /
  `bootstrap_import_failed` / `bootstrap_import_unix`; the full detail
  stays in the journal (compile WARN/ERROR) and the authenticated in-band
  `BOOTSTRAP_IMPORT_FAILED` event (event stream / ring buffer).
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
    #3965: both this endpoint and the `xpf_policy_hits_total` collector read
    the WHOLE policy set from ONE dataplane snapshot rather than calling
    `ReadPolicyCounters` once per policy. The per-policy read rebuilt the
    ruleID->counter index and rescanned the config UNDER the dataplane's
    policy mutex on every call, so a scrape of P policies was `O(P*(P+C))`
    with the mutex held the entire time — periodically stalling the scrape
    AND starving commit/apply and session classification on a firewall with
    many policies. `dpuserspace.NewPolicyCounterReader` now builds the index
    ONCE (`O(P+C)`) from a snapshot taken under a single brief lock (the
    userspace `Manager.ReadAllPolicyCounters`), then resolves outside the
    lock; a dataplane without the bulk snapshot (test fakes / retired eBPF)
    transparently falls back to the per-policy read, and the skip-and-bump
    (#3345/#3408) / HTTP-500 degraded-read contracts are unchanged.
    #4344: the migration is now complete across EVERY policy-counter display
    surface — this endpoint's default-policy row (which had bypassed the
    reader with a standalone sentinel read, M02), the CLI `show security
    policies hit-count` / `brief` tables, and the gRPC `show security
    policies hit-count` / `detail` text renderers plus the structured
    `GetPolicies` RPC all read through the same `NewPolicyCounterReader`
    snapshot. The returned counter values are identical to the per-policy
    read (`ReadAllPolicyCounters` is a batching layer, not a semantic
    change — pinned by `TestReadAllPolicyCountersMatchesPerPolicy`); a
    per-surface static canary forbids a new show surface from regressing to
    a direct per-rule `ReadPolicyCounters` call.
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
  consumers must drain. Concurrent SSE subscribers are BOUNDED (#4484 L-2):
  both stream handlers subscribe via `EventBuffer.TrySubscribe`, which
  returns nil once the live subscriber count reaches the cap
  (`defaultMaxSubscribers`, 64) — the handler then responds `503` BEFORE
  switching to event-stream. This mirrors `metricsMaxInFlight` (#4162): each
  event `Add` fans out O(N) over the subscriber set and each subscription
  holds a buffered channel, so an unbounded set is a memory + per-event-CPU
  DoS vector on this untrusted surface. Trusted internal consumers (gRPC
  event stream, CLI monitor) use `Subscribe`, which never fails but still
  counts toward the cap. `?category=` (and `?severity=` on
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

- **Management-plane DoS hardening (#4150).** Both `http.Server` literals in
  `NewServer` carry read-side timeouts and a header cap — `ReadHeaderTimeout`
  (`apiReadHeaderTimeout`, 10s), `ReadTimeout` (`apiReadTimeout`, 30s),
  `IdleTimeout` (`apiIdleTimeout`, 120s), and `MaxHeaderBytes`
  (`apiMaxHeaderBytes`, 1 MiB). Header reads happen BEFORE `authMiddleware`, so
  without these a pre-auth slowloris (dribbled headers/body) could pin a
  goroutine/socket per connection once web-management binds a non-loopback
  interface. `WriteTimeout` is deliberately left UNSET (0/unlimited): the SSE
  event/log streams (`/api/v1/events/stream`, `/api/v1/logs/stream`) are
  long-lived and a full metrics/session-table scrape is a large slow response —
  a `WriteTimeout` would sever them; the response side is bounded by per-handler
  context deadlines instead. Separately, every REST MUTATION handler decodes its
  body through `decodeJSONBody`, which wraps `r.Body` in
  `http.MaxBytesReader(maxRequestBodyBytes)` (16 MiB) and returns **HTTP 413** on
  overflow instead of buffering a multi-gigabyte POST to an OOM-kill (config
  `set`/`delete`/`activate`/`deactivate`/`load`/`rollback`/`commit-confirmed`/
  `annotate`, `system/action`, `ping`/`traceroute`, `dhcp/identifiers/clear`).
  Read-only GET handlers do not read a body and are out of scope. Add a new
  mutation handler via `decodeJSONBody`, not a bare `json.NewDecoder(r.Body)`,
  so the cap and 413 are inherited. Pinned by `http_dos_hardening_4150_test.go`.
- **Constant-time credential comparison (#4157).** `authMiddleware` /
  `checkAuthorization` (`auth.go`) validate every credential in constant
  time to avoid a network-timing side channel. API keys and Bearer tokens
  go through `constantTimeAPIKeyMatch`, which compares the presented token
  against EVERY configured key with `subtle.ConstantTimeCompare` and OR-s
  the results — it never short-circuits on the first match (so *which* key
  matched does not leak either) and never uses the old `cfg.APIKeys[token]`
  map lookup (whose latency varied with hash-bucket collisions / presence).
  Basic-auth passwords already used `ConstantTimeCompare`; the username path
  no longer early-returns on `!exists` — it always runs the password compare
  and AND-s with existence, so a known vs. unknown username is not
  distinguishable by response timing. `ConstantTimeCompare` returns 0 on a
  length mismatch (reveals length, not content — acceptable). Pinned by
  `auth_consttime_4157_test.go`, including an AST regression guard that fails
  if any auth path reverts to a bare `cfg.APIKeys[...]` lookup.
- **Day-2 listener + auth reconcile (#5866).** The management server used to be
  constructed ONCE at daemon startup and never reconciled, so a committed
  web-management change (bind address / port / TLS on/off / api-auth) reported
  success while the process kept enforcing the old policy until a restart —
  revoked or tightened credentials stayed usable, a bind removal left the API on
  the old address. Two mechanisms close this:
  - The authentication snapshot is a live `atomic.Pointer[AuthConfig]` (`s.auth`)
    read per request by `dynamicAuthMiddleware`; `ReplaceAuth` swaps it, so a
    revoked/tightened credential is rejected on the NEXT request with no listener
    bounce and no restart. The `authCheck` core is shared with the static
    `authMiddleware`, so the swap enforces byte-identical semantics (the #4157
    constant-time + #5636 empty-secret guards, `/health` + loopback-`/metrics`
    exemptions).
  - The HTTP and HTTPS listeners run in INDEPENDENT legs (`listener.go`), each
    make-before-break: `ReconcileHTTP(addr)` rebinds only the HTTP leg and
    `ReconcileHTTPS(tls, addr)` enables / disables / rebinds only the HTTPS leg —
    neither touches the sibling. This is the fix for the earlier whole-server
    rebuild: enabling TLS keeps the HTTP bind, so re-binding the whole server
    re-bound the still-held HTTP socket and failed `EADDRINUSE` (Go sets
    `SO_REUSEADDR`, not `SO_REUSEPORT`), and the TLS change could never converge
    without a restart — the same collision hit an HTTP-addr change that left the
    HTTPS bind unchanged. Each leg binds the new socket and serves it BEFORE
    retiring the old (no unreachable window on that plane, no double-bind of an
    unchanged socket); a bind (or HTTPS cert) failure fail-closes to the retained
    previous leg. `Start(ctx)` binds HTTP synchronously (fail-closed if it fails)
    and HTTPS best-effort (a boot HTTPS failure leaves HTTP up, retried next
    commit). `Wait()` joins every live + retiring leg goroutine on shutdown.
    Listeners bind via `Config.ListenFunc` (default `net.Listen`) so tests inject
    a fake factory that models `EADDRINUSE`. Pinned by
    `server_authswap_5866_test.go` (live auth swap) +
    `pkg/daemon/management_5866_test.go` (HTTP-bind change, TLS enable/disable/
    re-enable, HTTPS-bind-only change, HTTP-change-keeps-HTTPS, auth swap,
    bind-failure retain-old). `Run`/`serveBound` remain the single-lifecycle test
    entry point.
  - `EffectiveHTTPAddr()` (#6385/#6401) returns the live HTTP leg's ACTUAL bound
    address (`httpLeg.ln.Addr()`) — an ephemeral `:0` request resolves to its
    concrete port, a wildcard/hostname bind is normalized — or `""` when no HTTP
    leg is serving OR the live leg's serve loop exited UNEXPECTEDLY (the serve
    goroutine marks the leg `dead` — an ATOMIC store, NOT under `lifeMu`, so a
    serve-exit racing a shutdown `Wait()` cannot deadlock: the goroutine still
    holds its `wg` count when it marks dead and `Wait()` holds `lifeMu` across
    `wg.Wait()`, so a lifeMu-guarded marker would form a lock-ordering cycle; a
    requested shutdown via `stopLegLocked`/`rootCtx` does NOT mark dead). The
    daemon's `show system services`
    effective-listener snapshot reads it
    (`managementReconciler.effectiveHTTPListener`) and renders a dead leg
    `Failed`, symmetric with the gRPC serve-exit clear.
  - The auto-generated HTTPS cert (`generateSelfSignedCertAt`, used when no
    operator cert is provisioned) carries Subject Alternative Names, not just a
    CommonName (#5719, codex-review-182 C-API TLS hygiene). Every modern TLS
    client (Go's own client since 1.15, browsers, curl) rejects a SAN-less
    cert for hostname verification, so a CN-only cert broke `curl
    https://localhost:8443` / health probes even though the bind succeeded.
    What the SANs cover, precisely:
    - **Always present:** the loopback IP SANs `127.0.0.1` / `::1` and the DNS
      SAN `localhost` — so a **loopback-bound** HTTPS API (the default) always
      verifies. These can never fail to encode.
    - **Best-effort:** the kernel hostname. A valid ASCII hostname is added as
      a DNS SAN; an IP-literal hostname is added to the IP SANs (a DNS SAN of
      an IP never verifies as an IP). A **non-ASCII / malformed** hostname
      (e.g. a `café` kernel hostname) is DROPPED, not appended — x509 marshals
      DNS SANs as an IA5String and HARD-FAILS on non-ASCII, which under the
      #5058 all-or-nothing management-server lifecycle would abort cert
      generation and tear down the entire HTTP+HTTPS server. The cert degrades
      to loopback-only SANs (`isDNSSANSafeHostname` guard) instead of failing.
    - **HTTPS bind host (#5719 C001 residual, now closed):** the listener's
      bind host is threaded from the resolved `web-management https interface`
      address into cert generation (`buildHTTPSServer` → `net.SplitHostPort` →
      `certGen(bindHost)`). A non-loopback management IP lands in the IP SANs
      and a DNS-safe bind hostname in the DNS SANs, so
      remote-verification-by-mgmt-IP (`https://<mgmt-ip>:8443` with strict
      verification) succeeds. A loopback / unspecified (`0.0.0.0`/`::`) /
      wildcard (`:8443` → empty) / non-encodable bind host is skipped, and a
      value already present is coalesced. Like the hostname path this only ever
      ADDS an encodable SAN, so it never aborts generation.
    - **Re-mint STILL deferred, but no longer SILENT (#5719 C001 residual):** a
      later `set system host-name` (or a bind-address change) does NOT re-mint
      an already-persisted cert, so its DNS/IP SANs can go stale. Re-minting is
      deferred (it needs a mint-ordering / invalidation hook and a decision on
      churning the durable TOFU pin). What WAS a silent failure is now
      diagnosed: on the load-success path `generateSelfSignedCertAt` parses the
      loaded leaf and, when the current bind host is a concrete non-loopback
      management host (`bindHostWarnable`) that the leaf's SANs do NOT cover
      (`certCoversHost` — the same strict check a remote client applies), emits
      a `slog.Warn` naming the bind host and the cert's SANs, so an operator
      re-mints (remove `/etc/xpf/tls`) instead of chasing a silent
      verification failure.
    An already-persisted cert is NOT auto-regenerated — the #1916 D6
    durable-cert contract keeps the on-disk pair stable so remote clients' TOFU
    pins survive a power loss; only freshly generated certs gain SANs (delete
    `cert.pem`/`key.pem` to force a regenerate). Pinned by
    `tls_san_5719_test.go` (SAN presence, hostname classification, the
    non-ASCII no-abort guard, the bind-host mgmt-IP/DNS threading +
    `buildHTTPSServer` host-extraction, and the stale-cert-on-rebind
    mismatch warning), fail-on-revert.
- The status-poll path (1 Hz) shares the userspace dataplane control socket
  with HA sync, session installs, snapshot sync, and forwarding sync.
  Adding a new caller at >1 Hz here will starve session installs during
  bulk sync (per CLAUDE.md control-socket rules).
- A `/metrics` scrape performs at most ONE control-socket `Status()` round
  trip. `Collect` fetches the `ProcessStatus` once (`fetchUserspaceStatus`,
  after the dataplane gate) and shares the snapshot with BOTH the filter-term
  hit merge (`collectFilterCounters`) and the userspace-status families
  (`collectUserspaceStatus`). Before #5317 those two collectors each issued
  their own `Status()`, so one scrape did two serialized `status` RPCs on the
  contention-critical control socket (and read two A/B-skewed snapshots). On a
  Status() failure the shared fetch returns nil once and is NOT retried — the
  filter merge falls back to the map path and the userspace families emit
  nothing, exactly as each collector degraded before.
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
  OMITS the `xpf_sessions_{active,established,ipv4,ipv6,snat,dnat}` gauges
  when the scan failed, so an alert fires rather than a graph silently
  dropping to zero. The gRPC `GetSessions` (legacy + cursor) and
  `GetSessionSummary` return `codes.Internal` on the same error. The
  contract is pinned by `sessions_iterator_error_test.go` in this package
  and in `pkg/grpcapi` / `pkg/cli` (CLI top-talkers fails the command; NAT
  summaries print a stderr warning).
- The static-route `/routing/routes` handler (`routesHandler`, `routing.go`)
  renders one `RouteInfo` per next-hop for a normal route. A route with no
  forwarding next-hop instead carries a `disposition` label distinguishing
  `reject` (FRR `RTN_UNREACHABLE`, drop + ICMP unreachable), `discard` (FRR
  `Null0`/`RTN_BLACKHOLE`, silent drop), and `connected` (no gateway). This
  mirrors the `reject`/`discard` labels the CLI/gRPC `show route` text already
  renders, closing the #5410 gap where a first-class `reject` route (#5298)
  was lumped into the same unlabeled no-next-hop branch as `discard`. The
  `disposition` field is additive and `omitempty`, so a route with a real
  next-hop or a `next_table` leaks nothing new and existing consumers reading
  `destination`/`next_hop`/`interface`/`preference`/`next_table` are
  unaffected. Pinned by `routes_disposition_5410_test.go`.
- The same handler covers the FULL static-route set the CLI/gRPC `show route`
  iterate, not just the global inet.0 table (#5439). It walks
  `RoutingOptions.StaticRoutes` (inet.0), `RoutingOptions.Inet6StaticRoutes`
  (inet6.0), AND every routing-instance's per-VRF `StaticRoutes` /
  `Inet6StaticRoutes`, tagging each `RouteInfo` with its `family` (`inet` /
  `inet6`) and Junos RIB `table` name (`inet.0` / `inet6.0`, or
  `<instance>.inet.0` / `<instance>.inet6.0` for a VRF). Before #5439 it
  iterated ONLY inet.0, so the REST view silently omitted every IPv6 static
  route and every per-VRF static route — not even their destination — while
  the CLI/gRPC rendered both families and every VRF. The disposition labeling
  above applies uniformly across all four sources (an `appendStaticRoutes`
  helper renders each table). The `family` / `table` fields are additive and
  `omitempty`, the inet.0 rows still lead in their original order, so a legacy
  consumer reading the pre-#5439 inet.0 subset positionally is unaffected.
  Pinned by `routes_ipv6_vrf_5439_test.go`.
- Long full-table read handlers must ABORT when the client disconnects
  (#5232/#5233). The REST server cancels `r.Context()` on disconnect, so a
  handler that walks a large structure has to sample `r.Context().Err()`
  periodically and stop rather than run to completion for a response nobody
  will read. `bgpHandler` (`/routing/bgp?type=routes`) checks once per
  1024-route chunk in its streaming loop and returns — a full internet table
  (900k+ routes) otherwise keeps formatting + JSON-escaping every remaining
  route and writing to a dead connection (CPU/GC waste, #5232). That check now
  runs inside a `frr.StreamBGPRoutes` callback: the UPSTREAM RIB is streamed
  too, not buffered (#5056). Previously the handler called `GetBGPRoutes`,
  which ran `vtysh "show bgp ipv4 unicast"` and buffered the ENTIRE stdout
  into one string plus a parsed `[]BGPRoute` before the first byte went out —
  hundreds of MB for a full table, and the client-cancel check could not stop
  the already-completed vtysh work. `StreamBGPRoutes` scans vtysh stdout one
  line at a time (bounded `bufio.Scanner`), delivers each route to the
  callback, and cancels the vtysh process on `r.Context()` cancellation or a
  downstream write failure, so peak memory is O(1) in table size regardless of
  RIB size. The rendered output is capped at `maxBGPRoutes` (100000); when the
  cap trips a trailing `... table truncated at N routes` notice is appended to
  the `output` string (envelope shape unchanged) and the client is pointed at
  the CLI for the complete table. Operators needing the full RIB use
  `show route protocol bgp`. The cap/truncation contract is pinned by
  `bgp_routes_cap_5056_test.go`; the streaming/non-buffering + wire-format
  invariants by `bgp_routes_stream_4708_test.go`. The session
  handlers (`/sessions`, `/sessions/summary`, `/sessions/zone-pair`) share a
  per-batch sampler (`newRequestCancelSampler`, `sessionWalkCancelInterval`
  = 1024): each `IterateSessions`/`IterateSessionsV6` callback returns
  `false` once the context is cancelled, breaking the conntrack map walk and
  releasing the per-bucket BPF-map lock back to the live dataplane
  session-sync path (#5233) instead of holding it for a discarded scan. The
  sampler probes `ctx.Err()` once per batch (not per session) so the check
  adds no per-entry cost, and it never fires on the normal path — output and
  ordering are unchanged. The `/sessions` CURSOR path (`page_size>0`,
  `sessionsCursor` over `IterateSessionsFrom`/`IterateSessionsV6From`) uses the
  SAME sampler in both cursor callbacks — a selective/no-match query never
  fills the page, so without it the callback would walk the rest of the table —
  PLUS a direct `r.Context().Err()` check at each phase boundary: it does not
  start the second (v6) full walk after a cancelled v4 phase, and does not emit
  a misleading terminal `next_page_token`/partial-page envelope (nor the
  `include_peer` fan-out inside `writeSessionList`) to a dead connection. A full
  page is still emitted normally — it is a complete, valid result. Pinned by
  `api_ctx_cancel_5232_5233_test.go` (`TestSessionsCursorAbortsWalkOnCanceledContext_5233`
  for the cursor path). This is the REST analog of the gRPC `streamDiagCmd`
  cancellation cleanup (#5060).
- Session-count metrics come from the LIVE dataplane session table, not
  the BPF GC sweep stats (#3929). `collectSessionGauges`
  (`metrics_sessions.go`) derives `xpf_sessions_active` (forward entries)
  and `xpf_sessions_established` (forward entries in the ESTABLISHED
  state) from the SAME `IterateSessions`/`IterateSessionsV6` scan that
  backs the type breakdown, so all session gauges share one scan (no new
  periodic scan; the #333 GC-skip optimization stands) and one
  fail-loud `scrape_ok` gate. The REST `/status` and gRPC `GetStatus`
  `SessionCount` read `dp.SessionCount()` (forward-only live total).
  Before #3929 all three read `gc.Stats().TotalEntries` /
  `EstablishedSessions`, which are permanently 0 on the userspace
  dataplane (the only live forwarding path) because the BPF GC sweep is
  skipped (#333) — so active-session metrics/dashboards read a constant 0
  regardless of real load. `xpf_gc_sweep_duration_seconds` still reflects
  the (skipped, 0) BPF sweep and is orthogonal.
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
    it matches this contract. The error-counter SAMPLE is emitted via a
    `defer c.emitCounterReadErrors(ch)` established at the TOP of `Collect`
    (#5045), so it runs at function exit — AFTER the global/zone/policy/filter
    sub-collectors (and the pre-gate host-inbound collector) have run — on
    EVERY return path. A read failure in any collector is reflected in THIS
    scrape's value rather than lagging one scrape behind (#3462). Crucially the
    deferred emit also covers the `dp == nil || !dp.IsLoaded()` early return: a
    config-only / degraded boot with a failing pre-gate nft read previously
    skipped the only (post-gate) emit site and carried NEITHER the data series
    NOR the error sample — a clean absence that broke the omit-plus-error
    contract in exactly the degraded state the pre-gate collectors observe
    (#5045). The per-filter collector also
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
  `xpf_counter_read_errors_total`. See
  `docs/research/3643-dead-counters/plan.md` (§5A POPULATE spec, §5B HIDE).
  Pinned by `pkg/dataplane/zone_flood_counters_hide_test.go`,
  `pkg/cli/zone_flood_counters_hide_test.go`, and
  `pkg/grpcapi/zone_flood_counters_hide_test.go`.
- **Per-zone TRAFFIC counters are populated again, and the Prometheus family is
  back (#3651).** The reason #3643 dropped the metrics — nothing populated them
  — no longer holds: the Rust helper accounts per-zone ingress/egress
  packet+byte volume on the forward path
  (`userspace-dp/src/afxdp/zone_counters.rs`), publishes it in
  `ProcessStatus.zone_traffic_counters`, and the Go status poll mirrors each row
  into the sparse offset map via `Manager.ReplaceZoneCounterOffsets`. `show security
  zones` and REST `/security/zones` picked that up immediately;
  `xpf_zone_packets_total` / `xpf_zone_bytes_total` (labels `zone`,
  `direction` ∈ `{ingress,egress}` — unchanged from the pre-#3643 family, so
  existing dashboards keep working) were restored separately in #3651, since
  Prometheus is the surface an operator actually alerts on.
  `collectZoneCounters` reads ONLY `ReadZoneCounters`, i.e. the sparse offset
  map, so it cannot reintroduce the dense-array OOB read-error storm above.
  Its three-way disposition:
  - **populated** → emit ingress/egress packets and bytes.
  - **`ErrCounterNotPopulated`** → **omit** all four samples and count the zone
    into the `xpf_zone_counters_unpopulated_zones` gauge; do NOT bump
    `xpf_counter_read_errors_total`. Unpopulated is a legitimate steady state,
    and treating it as an error is exactly the per-scrape false alert #3643
    removed the family to stop. The samples are omitted rather than published
    as `0` because the helper's status snapshot is sparse and drops all-zero
    rows, so this sentinel cannot distinguish a pre-#3651 helper, a zone past
    the helper's 63 assignable hot-path slots (whose traffic really is
    uncounted), and a merely idle zone — a `0` would be an authoritative zero
    over an unknown. The gauge is always emitted (0 when healthy) and counts
    exactly the zones REST reports `per_zone_counters_available:false` for.

    **Emitted ABOVE the dataplane-loaded gate (#6843 R1), which widens the
    membership set beyond the sentinel's.** The gauge is contractually always
    emitted so `> 0` is alertable and its absence is not confusable with a
    scrape that failed to run — which means it must also be emitted on a
    degraded / config-only boot, where per-zone volume is least available. So
    `collectZoneCounters` runs before the `dp == nil || !dp.IsLoaded()` early
    return, alongside `collectPBRStatus` and the host-inbound families.

    Consequence: **the gauge's cause set is strictly wider than
    `ErrCounterNotPopulated`'s.** The sentinel has exactly three meanings; the
    gauge has those plus every pre-read membership branch. The authoritative
    enumeration is the metric's own HELP in
    `pkg/api/metrics_descriptors_zone.go`, and **this document deliberately
    states no count** — the count is the part that rots, and it rotted right
    here: this paragraph claimed "a fourth reason" and "three causes none of
    which applies" while the Go comment it mirrors had already grown past four.

    Two causes are worth naming here because an operator is least likely to
    guess them, and both follow from the config store being promoted BEFORE the
    dataplane apply: the dataplane is **loaded but has no apply result yet**
    (shim loaded, first apply pending or failed), and a zone is **in the active
    config but absent from the last apply result** (a commit whose apply failed
    leaves the store ahead of the dataplane). Neither produces the sentinel —
    the collector increments and `continue`s before it ever calls
    `ReadZoneCounters` — so do not read the HELP list as a list of sentinel
    meanings.

    All of this is named in the HELP because there is no `xpf_dataplane_loaded`
    series to disambiguate against, so an operator paging on `> 0` would
    otherwise triage toward causes none of which applies.

    **Retention (#6843).** "Not populated" must also be reachable *backwards* —
    a zone that WAS reporting and stops. The helper's store outlives its slot
    map: config apply carries the store forward and retains every
    still-configured zone, so a zone pushed past the hot-path slot capacity by a
    later config keeps its accumulated totals while no longer being counted. Two
    guards keep that from becoming a frozen counter. The helper publishes a row
    only when the zone is configured **and** holds a live slot
    (`publishable_zone_rows`), and the Go status mirror **replaces** the whole
    offset map from each snapshot rather than merging into it
    (`Manager.ReplaceZoneCounterOffsets`). Both are required: without the first
    the stale row keeps being published; without the second a row that stops
    being published leaves its last value stranded. Either way the metric would
    emit a total that can never advance — worse than an omission, because a
    frozen counter looks alive.
  - **any other error** → omit the samples and bump
    `xpf_counter_read_errors_total` (the #3345/#3408 skip-and-bump contract is
    intact — a degraded counter bridge stays alertable).

  The per-zone FLOOD half remains DEFERRED (use the #3343 aggregate
  `xpf_screen_drops_total` by reason); the flood offset map's setters remain
  the populate hook for it. Pinned by `pkg/api/zone_counters_metrics_test.go`,
  which replaced the `pkg/api` HIDE pin.
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
- NAT-stats telemetry read failures fail CLOSED as *unavailable*, never as a
  healthy zero (#5046, the #3345 counter-error contract). A read is a
  *failure* only when the id resolves and the telemetry call errors (a
  missing apply-id / absent runtime entry is a legitimate "no counter" and
  is NOT flagged). On such a failure:
  - **REST** (`nat.go`) returns HTTP 500: `runtimeSourceNATPools()` now
    returns `(map, error)` and propagates a `Status()` read failure (instead
    of the old bare `nil`, indistinguishable from provider-absent);
    `natPoolStatsHandler` also 500s on a fallback `ReadNATPortCounter`
    failure, and `natRuleStatsHandler` 500s on a `ReadNATRuleCounter`
    failure — rather than emitting `used_ports`/`hit_packets` = 0 with 200.
  - **gRPC** (`server_nat.go`) returns `codes.Internal`: `GetNATPoolStats`
    on a `NATPortCounter` failure and `GetNATRuleStats` on a `NATRuleCounter`
    failure (the `readCounter` helper now returns an error), matching the
    `GetZones`/`GetPolicies` #3408 contract.
  - **Prometheus** (`metrics_nat.go`) OMITS the affected
    `xpf_nat_pool_used_ports` sample (never a fake `0`) and bumps the shared
    `xpf_counter_read_errors_total`; `collectNATPoolMetrics` now runs BEFORE
    `emitCounterReadErrors` so the bump is reflected in the same scrape
    (#3462 ordering). Pinned by `nat_counter_error_test.go` (REST +
    Prometheus) and `pkg/grpcapi/nat_counter_error_test.go` (gRPC),
    fail-on-revert.
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
- The gRPC `GetNATRuleStats` `nat_type` selector fails CLOSED (#5719,
  codex-review-182 C-API). Only `""` (default = source), `"source"`, and
  `"destination"` select a rule family; any other value (a typo like `"src"`
  or `"static"`) is rejected with `codes.InvalidArgument` rather than falling
  through both branches to an empty "no NAT rules" response — a false-empty
  diagnostic indistinguishable from a firewall with no rules. Same discipline
  as the show routing/zones/firewall unknown-selector diagnostics. Pinned by
  `TestGetNATRuleStatsRejectsUnknownSelector` (gRPC), fail-on-revert.
- Query-filter parsing fails CLOSED, matching the gRPC contract
  (#2934/#2935/#2939). A filter sentinel of `0`/`""` means "no filter",
  so a *malformed* filter value must error rather than silently fall
  through to no-filter (which widens the query to everything — a
  cross-zone observability leak). `queryUint16Strict`/`queryIntStrict`
  (`api.go`) return `(0, false)` on a malformed non-empty value; the
  sessions/events `zone` filter and the policy-match `dst_port`/`src_port`
  return HTTP 400 instead of zeroing the predicate. #4926: the
  security-events `limit` parameter is likewise parsed strict — a
  present-but-malformed/negative value (`limit=abc`, `limit=-1`), a
  non-canonical spelling (`limit=+5`), or a value past the 10000 upper cap
  (`limit=10001`) returns HTTP 400 instead of silently defaulting to 50 or
  clamping (a fail-open that mirrored the lenient `queryInt` and could
  under-report the requested event window). An absent/empty `limit` still
  defaults to 50, matching the zone filter's "absent = no constraint"
  semantics; a valid `limit` in `[0..10000]` is used as-is. #3679:
  `queryIntStrict`
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
  `rest_filter_failclosed_test.go` (and, for the events `limit`,
  `rest_events_limit_failclosed_4926_test.go`) in this package.
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
  `GetSessionSummary` `include_peer`). The peer's table is attached only on
  the FIRST page — in BOTH pagination modes (cursor mode's first page has no
  `page_token`; offset mode's first window has `offset==0`). A non-first page
  must not re-attach the peer table or a client summing `peer.sessions`
  across pages would OVER-COUNT the peer; the offset path never sets a
  `page_token`, so the `sessionFirstPage` guard checks `offset==0` too. The peer
  fetch honors the SAME page bound the local list did: `peerSessionsRequest`
  forwards offset-mode `limit` AND cursor-mode `page_size` to the peer gRPC
  request (#4920). Before that fix a cursor-mode caller (`page_size` without
  `limit`) sent the peer `Limit==0` AND `PageSize==0`, so `getSessionsLegacy`
  defaulted the peer list to 100 sessions and the first REST page silently
  undercounted a peer holding >100 sessions. `page_token` is intentionally NOT
  forwarded — tokens encode node-local map keys and the peer fetch only runs on
  the first page. A standalone node or unreachable peer leaves `peer` absent.
  Pinned by `sessions_ha_scope_3423_test.go`.
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
- Bounded pagination walk + admission gate (#5318, connected-client residual
  after the #5237 disconnect-abort). Two hardenings on `GET /security/sessions`
  so a small paginated read cannot force unbounded full-table work per page:
  - **Admission bound.** A session list is a full conntrack-table walk that
    contends with the live session-sync path for per-bucket BPF-map locks. The
    handler now acquires a slot from `sessionWalkLimiter`
    (an alias of the process-wide `diagcmd.SessionWalkLimiter`, capacity
    `diagcmd.MaxConcurrentSessionWalks` = 4, the SAME fail-fast
    counting-semaphore idiom the diagnostic ping/traceroute handlers use, #5057)
    BEFORE the walk and the peer fan-out, releasing on every exit path. Over-cap
    requests are rejected immediately with **HTTP 429** (`session list
    concurrency limit reached; retry shortly`) rather than each driving its own
    simultaneous walk — a scrape flood can no longer multiply lock contention.
    The #5237 disconnect-abort bounds a SINGLE client's walk once ITS connection
    drops; this bounds how many CONNECTED clients walk at once, which the
    disconnect-abort does not. **#5433 extends the SAME gate to the aggregation
    siblings** `GET /security/sessions/summary` and
    `GET /security/sessions/summary/zone-pairs`, which drive the identical full
    v4+v6 walk. All three share ONE `sessionWalkLimiter` so the bound is on the
    AGGREGATE walk concurrency across the scan endpoints, not one budget per
    endpoint (they contend for the same locks). The aggregation handlers compute
    an EXACT summary / zone-pair breakdown, so `sessionCountCap` is NOT applied —
    an exact aggregate genuinely needs the full walk and a cap would change the
    response contract; the admission gate alone is the fix (no response-shape
    change). Over-cap aggregation requests return **HTTP 429** (`session scan
    concurrency limit reached; retry shortly`). Pinned by
    `sessions_aggregation_bound_5433_test.go` (per-handler concurrency bound +
    shared-limiter cross-endpoint 429 + permit-release, RED-on-revert).
    **#5708 hoists this limiter to `diagcmd.SessionWalkLimiter`** so the SAME
    aggregate budget also covers the gRPC session-scan paths
    (`GetSessions`, `GetSessionSummary`, and `GetZonePairSummary` in
    `pkg/grpcapi/server_sessions.go`, plus the `ShowText` `sessions-top:*`
    scan in `server_show_flow.go` — gRPC-only, no REST twin), which drive the
    identical full v4+v6 walk and previously bypassed the REST bound
    (codex-review-182 M35). The `sessions-top` scan's #5319 bounded top-K caps
    only the OUTPUT (K survivors), not the full-table WALK. The gRPC
    zone-pair RPC was a particularly clear gap — its REST twin
    (`GET /security/sessions/summary/zone-pairs`) was already gated, so
    zone-pairs was bounded on REST but unbounded on gRPC. A gRPC caller can no
    longer issue unbounded full-table scans; over-cap gRPC scans return
    `codes.ResourceExhausted`. A mix of REST + gRPC scrapers cannot collectively
    exceed `diagcmd.MaxConcurrentSessionWalks`.
    **#6216 extends the SAME gate to `natPoolStatsHandler`
    (`GET /security/nat/source/pools`)**, whose interface-mode `UsedPorts`
    accounting (#3417 above) drives the identical full conntrack walk via
    `IterateSessions` and previously bypassed the aggregate bound entirely — a
    scrape flood of the NAT-pool-stats endpoint could each drive a concurrent
    unbounded walk, contending with session installs on the shared control
    socket. The handler now `AcquireCtx`es a slot BEFORE the walk (429 on
    over-cap: `nat pool stats concurrency limit reached; retry shortly`),
    honors the returned admission-lease context inside the `IterateSessions`
    callback (stops early on client disconnect), and releases on every exit
    path. Pinned by `nat_pool_stats_walk_limiter_6216_test.go` (RED-on-revert).
    Note: only the interface-mode session-walk arm is gated; the pool-mode rows
    read the helper's live `SourceNATPoolStatus` (no table walk) and need no
    admission slot.
    **#5880 makes the shared limiter request-graph-aware to fix a reentrant
    double-acquire.** A REST list/summary/zone-pair handler acquires a slot and
    then delegates IN-PROCESS to the gRPC session service for `include_peer`
    fan-out; that service acquired the SAME limiter AGAIN, double-charging one
    logical operation and self-rejecting at capacity (`include_peer` failed under
    load). The fix is an unforgeable **in-process admission lease** carried on
    `context.Context` (`diagcmd.Limiter.AcquireCtx`, keyed by the private
    `leaseKey{*Limiter}` — never derivable from any external header): the FIRST
    handler to admit at the external trust boundary stamps the lease on the
    context it delegates on (REST re-stamps the request via `r.WithContext`), and
    the nested gRPC entry point REUSES that slot instead of re-acquiring. The
    lease is **per-request-graph, not global**: two DISTINCT external requests
    each acquire independently (the per-node bound is preserved), and the lease
    never crosses a process/network boundary, so a peer node's own gRPC entry
    acquires its own local slot (remote admission unchanged). Release stays
    idempotent + cancellation-safe (a real slot via `sync.Once`; the lease-reuse
    path is a no-op). Pinned by `TestAcquireCtx_5880` (mechanism),
    `TestGetSessions_InProcessLeaseReuse_5880` (gRPC reuse at cap 1), and
    `TestRESTIncludePeerReusesLease_5880` (REST include_peer succeeds at cap 1),
    each RED on revert. The BROADER redesign #5880 also asks for — structural
    per-surface admission via a registration/source-level test, weighted cost for
    local+peer/cursor/clear, and a separate remote budget — is deferred to a
    follow-up.
    **#5779 extends the SAME shared bound to the session-CLEAR (mutation)
    path**, which was the remaining uncovered full-table walk: `ClearAllSessions`
    is a chunked full-table scan+delete (not O(1)), and the gRPC `ClearSessions`
    filtered path (`clearFilteredSessionsV4/V6`, cursor or rescan) walks the
    whole table too. The gRPC `ClearSessions` handler now acquires one shared
    slot covering both its clear-all and filtered branches (over-cap →
    `codes.ResourceExhausted`); this REST clear endpoint's local-only fallback
    (`s.dp.ClearAllSessions()`) acquires the same shared limiter (over-cap →
    HTTP 429). The HA-delegated REST clear path is gated by the gRPC handler it
    forwards to, so it is not double-charged. A keyed single-session delete (no
    walk) is a different operation and is not gated.
  - **Bounded Total.** The offset mode's exact `total` previously forced a FULL
    v4+v6 table scan on EVERY 100-row page (O(table) per page, repeated per
    poll) just to count. The walk now caps the count at `sessionCountCap`
    (`defaultSessionCountCap` = 1,000,000) matching rows: `countCap` is
    `max(sessionCountCap, offset+limit)` so an explicitly requested deep window
    still fills to `limit`. UNDER the cap `total` is EXACT and the response is
    **byte-identical** to before (`total_approximate` is `omitempty`, so it is
    absent for normal-sized tables). PAST the cap the walk stops and `total`
    becomes a bounded LOWER BOUND with `total_approximate: true` — only the
    multi-million-session case degrades, and it degrades gracefully rather than
    re-walking the whole table per page. Cursor mode (`page_size>0`) is already
    bounded (it stops at `page_size` and reports no `total`) and is unchanged.
    A fuller keyset/cursor-default redesign of the offset contract is a possible
    follow-up; this fix is the minimal bounded one. Pinned by
    `sessions_pagination_bound_5318_test.go` (RED-on-revert: the bounded-walk and
    admission assertions both fail if either hardening is removed).
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
- #3627 B1a: a `to-zone junos-host` query also carries the structured
  `host_inbound` object — WHICH host-inbound-traffic system-service / protocol
  token admits the host-bound tuple, or that the box denies / globally accepts /
  cannot classify it. It is the REST projection of the shared
  `policymatch.Result.HostInbound` (`dataplane/userspace.HostInboundAdmission`),
  the SAME classifier the local CLI `show security match-policies` host-inbound
  line renders (the merged #4352) and the gRPC `host_inbound` message (field 21)
  carries, so the three surfaces cannot drift (#3375). Fields: `status`
  (`token-admit` / `global-accept` / `denied` / `indeterminate`), `token` and
  `kind` (`system-services` / `protocols`, set only for `token-admit`), and
  `description` (the one-line CLI explanation, so a JSON client renders the same
  sentence without re-deriving it). The classifier reads the same structured
  token->tuple SSOT the kernel-nft builder renders from
  (`config.HostInboundServiceMatch` / `HostInboundProtocolMatch`), so a reported
  token can never claim a port the box does not open. Present ONLY for a
  host-bound query — on both the `host_inbound_unmatched` verdict and a matched
  `to-zone junos-host` policy (the host-inbound gate is a separate admission
  stage); OMITTED for every transit / global / default / content-rejected
  verdict, which has no host-inbound gate. It is additional context and never
  changes `matched` / `host_inbound_unmatched`.
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
  `POST /api/v1/system/action` handler (`systemActionHandler`) journals
  reboot/halt to the configstore audit journal (`s.logSystemAction` →
  `Store.LogSystemAction`) BEFORE scheduling the power action, mirroring
  the gRPC `SystemAction` handler (#4108 F8 / #4484 L-1) — the REST path
  previously left NO durable attributable trail. The power action itself is
  invoked through the `apiSchedulePowerAction` package-var seam so a test can
  assert the journal wiring without taking the host down. The handler also
  serves the non-destructive `clear-config-lock` verb (parity with gRPC):
  it force-exits a wedged candidate-config lock (`Store.ForceExitConfigure`)
  so an operator can self-recover from an H-3/#4476 lock wedge over REST. The
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
  A per-job deadline is necessary but NOT sufficient: without an
  aggregate bound a request flood holds hundreds of processes/FDs/
  goroutines at once and starves the control plane. So each handler first
  takes a slot from the process-wide `diagcmd.DefaultLimiter`
  (`MaxConcurrentDiagnostics = 4`) via the `diagLimiter` package var —
  SHARED with the gRPC Ping/Traceroute RPCs, so one aggregate cap covers
  BOTH surfaces (a diagnostic admitted over REST and one over gRPC draw
  from the same budget, #5057). Acquire is fail-fast: when the cap is
  reached the handler returns **HTTP 429** immediately (no queue, no
  wait) rather than piling up work, and the slot is released via `defer`
  on every path (success, exec error, ctx timeout/cancel, panic). The
  child is spawned through the `diagRun` package-var seam so a test can
  inject a fake slow diagnostic and assert the cap without real
  subprocesses.
