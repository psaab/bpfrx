# pkg/dhcpserver

Manages Kea DHCPv4/v6 server config and lifecycle. Generates
`/etc/kea/kea-dhcp{4,6}.conf` from the typed config and reloads the
`kea-dhcp{4,6}-server` units via systemd. Config writes are
AtomicGeneratedConfig (#1894): `fsatomic.WriteFileAtomic` — Kea never
parses a torn file, no fsync on the apply path.

## Entry points

- `Manager` — `dhcpserver.go`.
- `New()` — `dhcpserver.go`.
- `Apply(cfg *config.DHCPServerConfig) error` — `dhcpserver.go`.
  Authoritative reconcile (#1778): for each configured family it
  regenerates the Kea config and restarts the unit; for each
  unconfigured family (including `cfg == nil`) it stops the unit if
  `systemctl is-active` reports it active — even if a PREVIOUS xpfd
  instance started it — and removes the generated config.
  **Fail-closed:** restart failures (and failures to stop an active
  unit that left the config) are returned, so a commit surfaces
  "DHCP server failed" instead of silently succeeding with no
  service.
- `ApplyAsync(cfg, reason)` — `dhcpserver.go`. Enqueues an `Apply` to
  a single lazily started worker via a 1-slot latest-wins mailbox and
  returns immediately (#1835 F2). Used by the VRRP transition
  callbacks in `pkg/daemon` so the event loop never waits behind a
  15s-bounded systemctl. Every applier — sync `Apply`,
  `ApplyClusterCommit`, and `ApplyAsync` — allocates a monotonic
  generation at call entry; the shared apply body skips requests
  superseded by a newer generation, so a queued async request is
  never applied over a later synchronous commit, and the mailbox slot
  is only overwritten by a higher generation (no ABA between racing
  producers). Coalescing is correct because `Apply` is an idempotent
  reconcile to desired state: intermediate states may be skipped but
  the newest desired state always wins. `cfg == nil` is the
  authoritative clear. Errors are logged with `reason`; the commit
  path keeps synchronous `Apply` (fail-closed; a superseded sync
  applier returns nil — being outraced is not a failure).
- `ApplyClusterCommit(cfg) error` — `dhcpserver.go`. Cluster-commit
  reconcile (#1835 F3): always regenerates configs for configured
  families but restarts only units that are currently active; clears
  unconfigured families like `Apply`. Fail-closed.
- `Clear()` — `dhcpserver.go`. Stops both Kea units if systemd
  reports them active and removes config files. Void signature for
  the VRRP-transition callers (`pkg/daemon` HA path); stop failures
  are logged at Warn. Commit-path callers use `Apply(nil)` to get the
  error.
- `IsRunning()` — `dhcpserver.go`. Queries systemd unit state
  (authoritative; survives daemon restarts).
- `Lease` — `dhcpserver.go`. Surfaced to the CLI for `show dhcp
  server leases`.
- `NewManagerForTesting(...)` — `test_seams.go`. Injectable
  `systemctl` seams + config paths, per the `pkg/dhcp/test_seams.go`
  convention.

## Dynamic DNS (DDNS) — #1387, increment 1

Opt-in publishing of forward (`A`/`AAAA`) and reverse (`PTR`) DNS records
for active DHCP leases, with stale-record cleanup on expire / release /
decline / reclaim / reassign. Default OFF — an absent `dynamic-dns` block
is byte-for-byte today's behaviour. This is the FIRST increment of the
multi-increment plan in `docs/research/1387-dhcp-ddns/plan.md`
(recommended Path C: a pluggable `DNSUpdater` backend, RFC 2136 first).

What increment 1 ships (the fully unit-testable, lab-free slice):

- **Config model** — `config.DHCPDynamicDNSConfig` (a nilable field on
  `DHCPServerConfig`), compiled from both AST shapes by
  `compileDHCPDynamicDNS` (`pkg/config/compiler_services.go`), typed
  schema leaves under `dhcp-local-server`/`dhcpv6-local-server`
  (`pkg/config/schema_system.go`). TSIG secret is redacted in
  `DHCPDynamicDNSConfig.String()`.
- **State-aware lease parser** — `parseActiveLeases4/6` (`ddns_leases.go`)
  honors Kea's `state` column (default/declined/expired-reclaimed), the
  `expire` epoch, and the `fqdn_fwd` split between host-name and
  client-supplied FQDN, and extracts the v6 DUID/IAID identity. SEPARATE
  from the display-only `parseLeaseCSV` (reusing that would publish/retain
  stale records — the exact bug this feature fixes). Header columns are
  matched CASE-INSENSITIVELY (both the header keys AND the lookup name are
  lower-cased in `leaseColumnValue`; field values are data and stay
  verbatim). The header is VALIDATED against a FAMILY-SPECIFIC
  `requiredLeaseColumns` set: any column whose absence would silently change
  whether a lease is published (naming), how it is keyed for ownership
  (identity), or whether it is active (state) is REQUIRED, because a mangled
  header parses with no error and the reconciler then deletes/churns owned
  records on the basis of an empty or wrongly-keyed desired set. If any
  required column is missing/renamed the parser returns an ERROR, so
  `Reconcile` marks the family untrusted and SKIPS the destructive diff —
  never mass-delete or record-loss on an unrecognizable header. Required:
  `address`, `state`, `hostname` (both families) + `client_id`,`hwaddr`
  (v4 identity) / `duid`,`iaid` (v6 identity). Deliberately OPTIONAL
  (absence degrades safely, no record loss): `fqdn_fwd` (defaults to
  host-name semantics), `expire` (no expiry tombstoning — `state` still
  gates active/tombstone; over-retain, not delete), `subnet_id` (pure
  metadata, not compared by `recordsEqual`). An empty FILE (no data rows)
  is still a legitimate zero-lease, no-error case; a present-but-mangled
  header IS an error. The fail direction (over-mark-untrusted for an exotic
  header → no publish/clean, operator-visible) is SAFE; silent
  mass-delete/record-loss is not.
- **Hostname normalization** — `deriveFQDN` / `finalizeFQDN`
  (`ddns_hostname.go`) ALWAYS contains the published name in the configured
  zone: the client picks the host part, the firewall picks the domain. A
  client-offered dotted name (e.g. `host.attacker.tld`, a trailing-dot or
  double-dot escape) that is not already within the configured domain is
  relabeled to `<first-label>.<domain>`; a name already inside the zone is
  kept verbatim. With no configured domain, only the first label is kept. A
  client can never publish outside the configured zone.
- **`DNSUpdater` interface** (`ddns_dns.go`) + the pure record/PTR-name
  construction. PTR names are built from the TEXTUAL address (reversed
  octets / nibbles), NOT the dataplane native-endian `__be32` convention. A
  nil updater (the increment-1 default — the live backend is deferred) is
  substituted with a `nopUpdater`: every upsert/delete is a LOGGED no-op,
  never a panic, and a no-op upsert does NOT record phantom ownership (so a
  later real backend still publishes the record).
- **Reconciler core** — `DDNSManager.reconcileOnceLocked` (`ddns.go`):
  build-desired / diff-owned / add-move-reassign-expire transitions,
  cleaning the old owner before the new one, with bounded retry that never
  wedges the loop. FAIL-SAFE: when a lease family's CSV cannot be
  read/parsed, that family is marked untrusted and its destructive diff is
  SKIPPED this cycle (a transient malformed CSV can never mass-delete a
  family's owned records); the parse error is surfaced to the caller.
- **Ownership state store** — `ddns_state.go`, JSON via
  `fsatomic.WriteFileDurable` (fsync-on-write; slow-path). This is the
  PROTECTION BOUNDARY for never-delete-a-record-xpf-did-not-create:
  `deleteOwnedLocked` re-derives the EXACT (name, type, address) from the
  store and is the sole delete authority. A corrupt store fails OPEN
  (reset to empty + log), never blocking commit/boot/DHCP serving.
- **Counters** via `DDNSManager.Stats()` (the future `show ... dynamic-dns`
  + Prometheus surface reads this).

DELIBERATELY DEFERRED to later increments (see plan §12):

- The LIVE rfc2136 `DNSUpdater` backend — lab-gated (needs a throwaway
  authoritative BIND/Knot + TSIG; no such fixture exists in CI yet). The
  `backend` leaf (and `update-server` / TSIG leaves) are PARSED and
  VALIDATED in this increment but NOT yet wired to a live updater — nothing
  is published to DNS. Enabling DDNS emits a commit-time warning
  (`config.ValidateConfig` → `validateDDNSDeferredBackendWarnings`), stronger
  when an `update-server` / TSIG is configured, so the operator is not
  surprised by the absence of records.
- HA ownership coupling to the per-RG VRRP MASTER/BACKUP gate — must pass
  `make test-failover`. The deterministic owner-id watermark
  (`ownerWatermark`) is laid down now so the state store is
  forward-compatible.
- The Kea D2 backend (reserved `backend kea-d2` enum; D2 is not in the
  image, `bake.py`).
- The daemon reconcile loop + `show ... dynamic-dns` CLI/gRPC plumbing +
  Prometheus emission. (The API collector is a CHECKED collector — a
  declared descriptor MUST be emitted or the descriptor-coverage canary
  fails — so counters live in `DDNSManager` until increment 2 wires a
  value source on the server.)

Net behaviour change for existing users in increment 1: zero.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`. (The `DDNSManager` reconcile loop
is wired into `pkg/daemon` in increment 2; increment 1 is library-level.)

## Dependencies

`pkg/config` and `pkg/fsatomic` (the latter for the Kea config writes and
the #1387 DDNS ownership state store).

## Gotchas

- Config is regenerated fully on every `Apply()` (no diff). The Kea config
  schema is JSON-based, so this is cheap.
- If the typed config drops the DHCP server entirely, `Apply()` stops the
  service and removes the config file. Running Kea processes are not
  killed via SIGKILL — systemd manages the lifecycle.
- The manager keeps NO process-local running state (#1778). All
  start/stop decisions reconcile against `systemctl is-active`, so a
  stale Kea left over from a previous daemon is stopped on the first
  `Apply`/`Clear` after restart. Every `systemctl` shell-out is
  bounded by a 15s timeout (#1794).
- Commit semantics: in standalone mode `pkg/daemon` calls `Apply`
  unconditionally on every config apply and surfaces its error
  through the commit (fail-closed); the boot path logs the error and
  continues, so an unavailable Kea binary cannot brick daemon boot.
  In cluster mode the commit path calls `ApplyClusterCommit`
  (#1835 F3) with the master-RG-filtered config: configs are always
  regenerated, but units restart only if currently active (this node
  is serving) — also fail-closed. VRRP MASTER/BACKUP transitions own
  start/stop via `ApplyAsync`.
- Lease queries read Kea's CSV lease backends directly:
  `/var/lib/kea/kea-leases4.csv` and `kea-leases6.csv`. No control
  channel / socket call. Missing files yield an empty list, not an
  error. Parsing uses `encoding/csv` (#1778) so quoted fields with
  embedded commas don't shift columns.
- Per-subnet interface binding (#1778): Kea allows at most ONE
  interface per subnet. Single-interface groups bind explicitly;
  multi-interface groups omit the binding so Kea uses address-based
  subnet selection (the pre-#1778 renderer silently bound only the
  first interface). All group interfaces are always listed in
  `interfaces-config`.
