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

## Static host reservations — #2243

Fixed / reserved address bindings let an operator pin a client (by
hardware address) to a stable address served by the DHCP server, e.g. a
printer, NAS, or appliance. Junos shape, scoped to a pool's subnet:

```
set system services dhcp-local-server group lan pool office \
    static-binding 00:11:22:33:44:55 fixed-address 10.0.1.50
set system services dhcp-local-server group lan pool office \
    static-binding 00:11:22:33:44:55 host-name printer
```

(The `dhcpv6-local-server` hierarchy takes the same `static-binding`
subtree with an IPv6 `fixed-address`.)

- **Config model:** `DHCPPool.StaticBindings []*DHCPStaticBinding`
  (`pkg/config/types_system.go`); each carries `MACAddress`,
  `FixedAddress`, optional `HostName`. The schema subtree is
  `dhcpStaticBindingSchema()` (`pkg/config/schema_system.go`), a
  MAC-keyed named-instance container (`keyValidator: ValidateMAC`) with a
  typed `fixed-address` leaf (`ValidateIPAddress`) and a free-form
  `host-name`. Compile is the `static-binding` case in
  `compileDHCPLocalServer` (`pkg/config/compiler_services.go`), handling
  both AST shapes via `namedInstances`.
- **Commit validation (strict/lenient split):**
  `validateDHCPStaticBindingsStrict`
  (`pkg/config/compiler_validate_strict.go`) rejects a missing/malformed
  fixed-address, a family-mismatched literal, an address outside the pool
  subnet (Kea would silently drop it), and a duplicate MAC identity or
  duplicate fixed-address within the same pool. The strict commit /
  commit-check path (`CompileConfig`) hard-rejects; the tolerant load /
  peer-sync paths (`CompileConfigLenient` / `CompileConfigForNodeLenient`,
  flag `lenientDHCPStaticBindings`) DOWNGRADE the violation to a
  `cfg.Warnings` entry so an already-persisted or peer-synced config
  carrying a bad binding still BOOTS (#1960 no-brick) — the validator runs
  AFTER the strict accumulator (mirroring `validatePolicyMatchAddressesStrict`),
  not inside it, so it no longer hard-rejects the whole config-load like
  the original #2243 placement did.
- **Kea render:** `generateKea4Config`/`generateKea6Config` emit a
  per-subnet `reservations` array — v4 `hw-address` → `ip-address`, v6
  `hw-address` → `ip-addresses[]`, plus optional `hostname`. The MAC is
  canonicalized to Kea's accepted colon-lowercase form
  (`aa:bb:cc:dd:ee:ff`) via `canonicalMAC` (`net.ParseMAC().String()`) at
  BOTH render sites: `ValidateMAC`/`net.ParseMAC` accept the Cisco
  dotted-triplet (`0011.2233.4455`) and uppercase, but Kea's hw-address
  parser REJECTS the dotted form, so a config that commits clean would
  otherwise break the entire Kea Dhcp4/6 reconfigure. A binding whose MAC
  fails to parse at render (not expected after commit-time validation) is
  skipped with a warning rather than emitted malformed. A pool with no
  bindings emits no `reservations` key (`omitempty`), byte-for-byte
  identical to pre-#2243 output.
- **HA:** reservations derive entirely from committed config, which the
  cluster config-sync already replicates, so both nodes serve identical
  reservations and the reserved client gets the same address regardless
  of which node is MASTER — reservation-consistent by construction, no
  per-lease replication. (Dynamic-lease HA sync across failover is the
  separate companion gap, #2239.) ISC Kea handles static reservations
  entirely in the config file, independent of its HA hook.

## Expired-lease reclamation — #1387 (stale-lease-cleanup slice / Path S)

The "stale lease cleanup" half of #1387. Kea keeps an expired / released /
declined lease ROW in its memfile (`kea-leases4.csv` / `kea-leases6.csv`)
as an appended record until its reclamation cycle removes it; the defaults
are conservative. Without tuning, expired rows accumulate — they bloat the
memfile, slow startup re-load, and delay Kea's internal reclamation/reuse
of the expired address. (They do NOT make `show dhcp-server` lie: since
#2085 the lease display already filters non-active / expired rows, so the
display is truthful today. This slice makes the *source* truthful by
actually removing the rows Kea would otherwise keep.) This is the
DHCP-lease-database layer — entirely distinct from the DDNS stale-*record*
cleanup below (the reconciler withdrawing A/AAAA/PTR when a lease leaves
the active set).

Opt-in, per family, Junos-shaped — the keys map to Kea's per-`Dhcp4` /
per-`Dhcp6` `expired-leases-processing` block:

```
set system services dhcp-local-server expired-leases-processing enable
set system services dhcp-local-server expired-leases-processing reclaim-timer 10
set system services dhcp-local-server expired-leases-processing flush-timer 25
set system services dhcp-local-server expired-leases-processing hold-time 600
set system services dhcp-local-server expired-leases-processing max-leases 100
set system services dhcp-local-server expired-leases-processing max-time 250
set system services dhcp-local-server expired-leases-processing unwarned-cycles 5
```

(The `dhcpv6-local-server` hierarchy takes the same subtree; v4 and v6 are
tuned independently because Kea renders the block once per family.)

- **Reclamation is GLOBAL per family, NOT per pool.** Kea's
  `expired-leases-processing` is a top-level `Dhcp4`/`Dhcp6` block — there
  is no per-subnet reclamation. The config model therefore attaches to the
  per-family `DHCPLocalServerConfig.ExpiredLeases`
  (`pkg/config/types_system.go`), never to `DHCPPool` (invariant H3).
- **Reclamation is ORTHOGONAL to lease-time (invariant H4).** `valid-lifetime`
  / per-pool `lease-time` set how long a lease stays VALID;
  `expired-leases-processing` sets how aggressively Kea REMOVES leases that
  have ALREADY expired. This slice does NOT touch lease-time — do not
  conflate the two.
- **Config model:** `DHCPExpiredLeasesConfig` carries `Enabled` plus the six
  Kea knobs. The two CAP knobs (`max-leases` → `max-reclaim-leases`,
  `max-time` → `max-reclaim-time`) carry a companion `*Set bool` because in
  Kea **0 means UNLIMITED** there — a value distinct from "omit the key and
  inherit Kea's default" (invariant H2). The model tracks set-vs-unset so an
  operator can express `max-leases 0` (unlimited) distinctly from not
  configuring it; a naive `if x > 0` render would make 0 un-expressible. The
  schema is `dhcpExpiredLeasesSchema()` (`pkg/config/schema_system.go`),
  returned fresh per call so the two parents do not alias a mutable map.
- **Schema floor split (fail-safe):** the three TIMERS (`reclaim-timer`,
  `flush-timer`, `hold-time`) use `ValidateIntegerMin(1)` because a 0 some
  Kea versions reject would take DHCP DOWN on the fail-closed restart; the
  two CAP knobs use `ValidateIntegerMin(0)` (0 = unlimited is documented Kea
  behaviour) and `unwarned-cycles` is `Min(0)`. No schema-only upper cap
  (Kea documents no hard ceiling; min-only validation per the
  `docs/config-schema.md` range policy).
- **Compile:** `compileDHCPExpiredLeases` (`pkg/config/compiler_services.go`),
  handling both the hierarchical and flat-set AST shapes (walk +
  first-value-wins, mirroring `compileDHCPDynamicDNS`); a truly empty /
  garbage block returns nil (no block forced on, nothing rendered —
  closing the empty-tree-compiles-non-nil trap). It runs inside the shared
  `compileExpanded` core, so it lands on BOTH the strict commit and the
  tolerant load / peer-sync compile sites — a peer-synced or stored config
  carrying the block compiles on both (invariant R4); the typed-leaf schema
  gate hard-rejects on commit but downgrades to a warning on Load /
  SyncApply (boot/HA safety, invariant H7).
- **Kea render:** `keaExpiredLeasesMap` (`pkg/dhcpserver/dhcpserver.go`)
  renders the per-family `expired-leases-processing` JSON, or nil when the
  block is absent OR disabled (UNCONDITIONAL omit → byte-identical to
  pre-#1387 output, the cardinal invariant H1). Each numeric field emits
  only when set (an operator tunes one knob without pinning the rest); the
  two cap knobs emit on their `*Set` bool so `max-reclaim-leases: 0`
  (unlimited) is rendered distinctly. `Enabled` with no knobs renders a
  present empty `{}` (Kea reads it as "reclaim with built-in defaults"; the
  block surfaces that the feature is on).
- **No service-lifecycle / HA change.** The block is read by Kea on the
  existing (re)start / reconfigure path exactly like every other generated
  key — no new `systemctl` call, no extra daemon. It is in the
  MASTER-filtered config each node already renders, so it is HA-neutral by
  construction.

**Validation status:** fully unit-tested (golden render for v4/v6,
disabled/absent omit, `max-leases 0` vs unset, per-family independence,
dual-AST compile, schema completion + commit-check floor split, stored /
peer-sync lenient tolerance). End-to-end reclamation against a live Kea
(hand a lease, let it expire, confirm the row is removed within
`reclaim-timer + flush-timer + hold-time`) is lab-deferred — the unit
golden is the binding gate; a `kea-dhcp4 -t <generated.json>` acceptance
check on deploy confirms Kea parses the rendered block.

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
  `DHCPDynamicDNSConfig.String()`. The block can appear under BOTH
  families; the typed model carries a single config, and the two blocks are
  MERGED field-by-field (`mergeDHCPDynamicDNS`) — a field set in either
  family wins, `enable` latches on — so a partial second-family block never
  clears the first family's settings (a whole-struct overwrite would
  silently disable DDNS).
- **State-aware lease parser** — `parseActiveLeases4/6` (`ddns_leases.go`)
  honors Kea's `state` column (default/declined/expired-reclaimed), the
  `expire` epoch, and the `fqdn_fwd` split between host-name and
  client-supplied FQDN, and extracts the v6 DUID/IAID identity. SEPARATE
  from the display-only `parseLeaseCSV` — NOT because the display parser
  is unfiltered (since #2085 it also filters non-active state + expired
  rows and dedups per address), but because the two have opposite
  failure postures: the DDNS parser is **destructive** (its empty result
  authorizes deleting owned DNS records), so it must hard-error on a
  mangled / duplicate-column / ragged header; the display parser is
  **non-destructive and lenient** — an exotic or short row must degrade
  to showing what it can, never blank the whole `show`. That leniency is
  enforced at BOTH layers: #2085 made the per-record SEMANTICS lenient
  (dedup/expire/state), and #2154 made the READ itself robust — the
  display parser reads the memfile record-by-record (`csv.Reader.Read`)
  and logs+SKIPS a malformed row (torn/concurrent Kea append, e.g. an
  unterminated quote on the in-progress last line) instead of `ReadAll`'s
  all-or-nothing abort, which used to blank `show dhcp server leases`
  exactly when lease churn was highest. (`FieldsPerRecord = -1` makes a
  short concurrent line a non-event, and `csv.Read` recovers after a
  `*csv.ParseError`, so the skip loop terminates naturally.) The DDNS
  parser keeps the opposite posture by design: there a torn/short row is
  delete-UNSAFE, so it is rejected, not skipped. Merging the two parsers
  would force one posture onto the other (re-opening the #1387
  mass-delete, or blanking the display on one bad row). Header columns are
  matched CASE-INSENSITIVELY (both the header keys AND the lookup name are
  lower-cased in `leaseColumnValue`; field values are data and stay
  verbatim). A header maps to columns UNAMBIGUOUSLY: a DUPLICATE column name
  (case-insensitive) is rejected with an error (Codex r5) — a healthy Kea
  memfile has all-unique columns, and a duplicate would otherwise overwrite
  the earlier index with the last occurrence, so a lookup could resolve to
  the wrong/empty column → wrong desired set → destructive delete. We reject
  ANY duplicate (not just duplicate required columns). Extra/unknown columns
  and a reordered header are TOLERATED (lookups are by name, not position).
  The header is VALIDATED against a FAMILY-SPECIFIC
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
  metadata, not compared by `recordsEqual`). The header is validated BEFORE
  the zero-data-row early return (Codex r4), so the trusted-empty result —
  which is what PERMITS `Reconcile` to clear a family's owned records — is
  returned ONLY when the lease set is provably empty: the file is genuinely
  MISSING (`os.IsNotExist`, "no leases yet"), OR the header is present AND
  valid AND there are simply no active data rows (a genuinely-drained Kea).
  A present-but-mangled header errors WITH OR WITHOUT data rows (so a
  header-only mangled file cannot short-circuit to trusted-empty), and a
  0-record EXISTING file (no header at all — anomalous, mid-write/corrupt)
  fails SAFE as an error rather than trusted-empty. Per-ROW conformance
  (Codex r6) complements the header-schema check: a DATA ROW too short to
  supply every required column (a torn/truncated memfile append — the CSV
  reader allows ragged rows) would otherwise read a required column as ""
  (bounds-safe via `leaseColumnValue`'s `idx < len(fields)`, but NOT
  delete-safe — the lease silently drops and its owned record is deleted).
  So a row with `len(fields) <= maxRequiredIdx` (the max index among the
  family's required columns) is a hard parse error → the whole family's
  source is untrusted → the destructive diff is skipped; we do NOT silently
  skip just the row (we cannot know which lease it is, and skipping still
  drops its record). A row with MORE fields than the header is tolerated
  (extra trailing fields ignored by name-based lookup). The fail direction
  (over-mark-untrusted for an exotic/unreadable file → no publish/clean,
  operator-visible) is SAFE; silent mass-delete/record-loss is not. The
  destructive-delete class is now closed at BOTH the header level (required
  columns present, each once, no duplicates) and the row level (every data
  row long enough to supply every required column).
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
  (reset to empty + log), never blocking commit/boot/DHCP serving. The
  stored `version` is validated on load: an unknown (future) non-zero
  version is treated like a corrupt store (fail-open to empty + warn), so a
  later format bump cannot be mis-decoded into wrong-tuple deletes. (A
  fail-open store may LEAK previously-owned records — they stay in DNS until
  authoritatively removed; record TTL is resolver caching, not removal — but
  never deletes records xpf did not create.)
- **Counters** via `DDNSManager.Stats()` (the `show ... dynamic-dns`
  + Prometheus surface reads this).

Net behaviour change for existing users in increment 1: zero.

## Dynamic DNS (DDNS) — #1387, increment 2 (live backend + loop + HA gate)

Increment 2 (`docs/research/1387-inc2-ddns-backend/plan.md`) turns the
lights on: a LIVE RFC 2136 backend, a daemon reconcile loop driving it from
real Kea lease events, a NODE-LEVEL HA single-writer gate, and the
Prometheus + `show` observability surface. The increment-1 reconciler core,
ownership store, and `DNSUpdater` interface are UNCHANGED — Inc-2 only wires
a real updater behind them and a real loop in front.

What increment 2 ships (the feasible, CI-testable slice):

- **Live RFC 2136 backend** — `rfc2136Updater` (`ddns_rfc2136.go`),
  implementing the existing `DNSUpdater` interface with `github.com/miekg/dns`.
  An UpsertLease is an idempotent EXACT-RR ADD of the A/AAAA forward record
  + the PTR reverse record; a DeleteLease is the symmetric EXACT-RR delete
  (RFC 2136 §2.5.4, TTL=0 / CLASS=NONE). The backend NEVER issues a
  delete-RRset or delete-name, so a manually-added co-resident record on the
  same name is never collateral — the R1 cardinal-sin boundary holds on the
  wire. TSIG (when a key is configured) is signed via `TSIGSecret.Reveal()`
  with a supported HMAC algorithm (sha1/224/256/384/512; hmac-md5 rejected as
  insecure; default hmac-sha256). UDP-first with a TCP retry on truncation
  that is derived from the CALLER's context (so a canceled/deadline'd reconcile
  pass cancels the in-flight retry), a bounded per-call timeout, and
  conflict-policy handling (replace-owned =
  bare add; skip-existing = no-RRset prerequisite, skip on collision;
  strict-fail = error on collision). The backend is STATELESS beyond its
  config — all ownership lives in the unchanged state store.
- **Zone surface** (plan §11 Q1): the forward zone is the configured
  `Domain` ONLY when the lease's FQDN is actually under it (an out-of-domain
  `ClientFQDN` derives its own parent zone instead of being misrouted into the
  domain, which the authoritative server would reject NOTAUTH); the reverse
  zone is the canonical in-addr.arpa/ip6.arpa derived from the PTR name. A
  reverse-zone NOTAUTH/REFUSED (a reverse zone we do not own, e.g. delegated to
  an ISP) is a COUNTED SKIP
  (`skipped_total{reason="ptr-notauth"}`), NOT a blocking error — the forward
  add still succeeds and the lease's reconcile is not failed (plan §11 Q6).
  The zone-resolution helpers take an optional explicit zone list (always
  empty in Inc-2) so explicit `forward-zone`/`reverse-zone` leaves are a
  purely additive follow-up.
- **Resolve-per-Reconcile** (plan §6 fork 1): the always-on production
  manager (`NewProductionDDNSManager`) rebuilds the live backend from the
  current policy at the START of each Reconcile, so a commit-time
  backend-config change takes effect on the next cycle with no swap race, and
  the SAME manager serves both the disabled (nopUpdater) and enabled states —
  an enabled→disabled commit (keeping the backend config) still resolves a
  live backend and runs `withdrawAllLocked` through it.
- **Withdraw never goes through the nop while records are owned**: removing the
  WHOLE `dynamic-dns` stanza leaves no update-server/TSIG to build the live
  backend from, so the per-Reconcile factory resolves a `nopUpdater`. Reconcile
  must NOT replace a still-live updater with that nop before withdrawing —
  doing so would drop the ownership entries while sending NO real DNS delete,
  orphaning the published records. The guard in `Reconcile` keeps the existing
  live updater for the withdraw cycle when the newly-resolved updater is a nop
  AND records are still owned; the swap to nop happens on the next cycle once
  nothing is owned.
- **Daemon reconcile loop** (`pkg/daemon/daemon_ddns.go`,
  `runDDNSReconcileLoop`): an ALWAYS-ON guarded background goroutine modeled
  on the neighbor periodic loop. It ticks on a 30s poll AND is nudged for an
  immediate pass on config commit and on VRRP MASTER takeover. Each pass runs
  in a guarded skip-if-in-flight goroutine with a per-pass context timeout, so
  a hung DNS server can never wedge the loop or starve the nudge channel. It
  does FILE I/O (the Kea memfile CSVs) + DNS network ONLY — it NEVER touches
  the userspace-helper control socket, so it cannot starve session installs
  (CLAUDE.md control-socket rule).
- **NODE-LEVEL HA single-writer gate** (`ddnsWriterGateOpen`, plan §4.3): this
  node reconciles DDNS from its own Kea memfile(s) IFF it is MASTER for ≥1 RG
  (standalone is always the writer). This is SOUND without any per-lease RG
  attribution because the Kea config each node serves is rendered
  MASTER-FILTERED (`filterDHCPConfigForMasterRGs`), so a node's memfile holds
  ONLY its own MASTER-RG leases — the two nodes' input sets are disjoint by RG
  ownership, so dueling writers are impossible. The gate reads
  `snapshotRethMasterState` ONLY (the same source the Kea manager uses), never
  the map-order-assigned, per-render-unstable `subnet_id`. A BACKUP-for-all
  node STOPS WRITING — it does NOT withdraw valid records (the peer MASTER
  owns them; deletion is lease-state / config-removal driven only). The
  async-takeover ordering (Kea `ApplyAsync` may lag the DDNS nudge) is benign:
  the reconcile is store-driven and add-only-from-current-leases, so a
  too-early pass against a not-yet-repopulated memfile issues ZERO deletes.
- **Observability** — `xpf_dhcp_ddns_*` metrics through the CHECKED API
  collector (`collectDDNSMetrics`, `pkg/api/metrics_system.go`):
  `upserts_total{result}`, `deletes_total{result}`,
  `reconcile_runs_total{result}`, `skipped_total{reason}`, `owned_records`,
  `last_reconcile_timestamp_seconds`, `last_reconcile_leases`. Label
  cardinality is CLOSED: `result` ∈ {ok,fail}; `reason` ∈
  {no-name,no-backend,conflict,ptr-notauth}. `show system services
  dhcp-server dynamic-dns [detail]` renders the config summary + counters
  (and, in detail, the owned records) via the in-process CLI and the gRPC
  `ShowText` topic.
- **Retired the deferred-backend commit warning** and replaced it with live
  WARN-only validation (`validateDDNSBackendWarnings`, `pkg/config/compiler.go`):
  enabled rfc2136 with no update-server, a malformed update-server, an
  unsupported TSIG algorithm, and the still-deferred kea-d2 backend each WARN
  (never error, so a previously-inert malformed value cannot brick a boot —
  plan §7 Q-C).

LAB-GATED (NOT in this PR — flagged for the merge gate, plan §9.2/§9.3):

- Live Kea→DNS end-to-end on the loss cluster (a real kea-dhcp{4,6}-server
  handing a real lease, publishing to a throwaway authoritative BIND/Knot,
  `dig` resolving the A + PTR, then expiry/reassign removing them).
- `make test-failover` WITH DDNS enabled — the mandatory cluster gate
  (CLAUDE.md: any change touching the HA/VRRP transition path). The
  in-process responder proves the wire format + single-writer correctness;
  the lab proves the no-dueling-writes + reconcile-on-takeover timing.

Still deferred (Inc-3+):

- The Kea D2 backend (reserved `backend kea-d2` enum; D2 is not in the
  image, `bake.py`) — still WARN-deferred.
- Explicit `forward-zone`/`reverse-zone` + `publish-ptr` config leaves — an
  additive follow-up; the zone-resolution helpers already take the optional
  list so the follow-up wires straight in.

## HA lease synchronization (#2239) — `lease_sync.go`

This package owns the KEA side of #2239 cross-chassis DHCP-server lease sync
(PATH C). The cluster wire + standby-hold + takeover orchestration live in
`pkg/cluster` + `pkg/daemon`; here:

- `SetLeaseSyncEnabled(bool)` — when set (the daemon flips it from the cluster
  `dhcp-lease-synchronization` knob before an apply), `generateKea{4,6}Config`
  injects a unix `control-socket` + the `libdhcp_lease_cmds.so` hook
  (`addLeaseSyncStanza`). Knob-off / standalone renders bit-identical to
  pre-#2239 (no socket, no hook). `memfile` stays `persist=true`.
- `GetSyncLeases{4,6}(ctx, now)` — read the active lease set, preferring the
  control socket (`lease{4,6}-get-all`) and falling back to the
  destructive-safe memfile parser (`parseActiveLeases`) when the socket is not
  up. Each `SyncLease` carries REMAINING LIFETIME (`expire - now` on the
  reader's clock), never an absolute epoch — the clock-skew-immunity invariant.
  Expired / non-active leases are dropped at read time. The v6 fallback
  PRESERVES the lease kind: it reads the memfile `lease_type` (0=IA_NA,
  1=IA_TA, 2=IA_PD) and `prefix_len` columns and maps them to
  `SyncLease.LeaseType` / `PrefixLen` exactly as the socket path does, so an
  IA_PD prefix-delegation lease read during the socket-down window is no longer
  mis-seeded as an IA_NA address lease (#2262). A present-but-unparseable
  `lease_type` is fail-closed: the row is skipped (logged), never defaulted to
  IA_NA. An absent/empty column (old memfile, v4) stays IA_NA-equivalent.
- `SeedSyncLeases{4,6}(ctx, leases, now)` — write held peer leases into a
  just-started Kea via `lease{4,6}-add` (→ `lease{4,6}-update` on collision,
  idempotent), re-anchoring `expire = now + remaining` on the LOCAL clock.
  Faithful v6 identity (DUID/IAID/`type`/`prefix-len`, so IA_PD is synced).
- `PreSeedMemfile{4,6}(leases, now)` — write the held leases into the Kea
  memfile CSV (canonical header) BEFORE Kea start so it loads the in-use
  bindings at boot and can never hand an in-use address to a different client
  even in the pre-`lease-add` window (the duplicate-allocation-window closer).
  Durable (`fsatomic.WriteFileDurable`). **Chowned to the Kea runtime user
  (#2450):** xpfd runs as root but distro Kea runs unprivileged (`_kea` on
  Debian/Ubuntu, `kea` on RHEL-family) and opens its memfile lease DB for
  READ+WRITE at startup; a root-owned 0640 pre-seed would be unreadable by Kea
  → it fails to start (EACCES) on the node that just took over → DHCP outage at
  failover. The pre-seed therefore resolves the Kea user once (cached) and
  installs the file already owned by it (0640 + owner=_kea ⇒ owner RW). The
  chown rides on the `fsatomic` temp fd (`fsatomic.WithOwner` fchowns BEFORE
  the rename), so the FINAL renamed inode is _kea-owned atomically — no
  post-rename root-owned window and no orphaned root-owned temp. Best-effort
  when the Kea user is absent (dev host / Kea not installed): one warning is
  logged (once per process, in the cached owner resolution — not per pre-seed,
  so an absent-user takeover does not warn twice for v4+v6 or again on every
  later takeover), the file is written without the owner override, and
  **takeover is never aborted**. Both the v4 and v6 memfiles are covered.
  The v6 WRITE side (memfile pre-seed AND `lease6-add`) encodes the lease kind
  SYMMETRICALLY with the read side: `stringToKeaLeaseType` is the exact total
  inverse of the read path's `keaLeaseTypeToString`, so IA_NA / IA_TA / IA_PD
  all round-trip (read IA_TA → write `lease_type=1`, not a downgrade to IA_NA).
  Both write callers go through this one inverse so the read↔write mapping
  cannot drift to re-introduce the #2268 IA_TA downgrade. Only IA_PD carries a
  delegated `prefix_len`; IA_NA and IA_TA are full `/128` address bindings, so
  their `prefix_len` column is 128. An unknown lease-type string falls back to
  IA_NA (logged), never silently mis-typed.
- `WaitControlSocket{4,6}(ctx, within)` — bounded readiness wait before the
  post-start seed.

All of these talk ONLY to KEA's own unix control socket (or the memfile) —
NEVER the userspace-helper control socket (CLAUDE.md rule), so they cannot
starve session installs. All seed/read errors are fail-open (logged + counted
by the daemon; serving is never blocked). Test seams:
`SetLeaseSyncSeamsForTesting` injects a stub dialer + paths.

## Callers

`pkg/daemon` (constructs the always-on `DDNSManager`, runs the reconcile
loop, owns the node-level HA gate, exposes `DDNSStats`/`OwnedDDNSRecords` to
the API/CLI; for #2239 it sets `SetLeaseSyncEnabled`, runs the lease-sync push
loop, and drives the pre-seed + takeover seed), `pkg/cluster` (#2239 holds the
peer `SyncLease` set), `pkg/cli`, `pkg/grpcapi`, `pkg/api`.

## Dependencies

`pkg/config` and `pkg/fsatomic` (the latter for the Kea config writes and
the #1387 DDNS ownership state store). The #1387 inc-2 live RFC 2136 backend
adds `github.com/miekg/dns` (DNS UPDATE construction + TSIG signing).

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
  embedded commas don't shift columns. Kea's memfile is **append-only**
  between lease-file-cleanup (LFC) compactions — every renewal,
  re-allocation, release, decline, and expiry-reclaim is a new row — so
  `parseLeaseCSV` (#2085) collapses the append log to one row per
  address (the last/newest row wins), drops non-active rows
  (`state != 0` — declined / expired-reclaimed, which can still carry a
  future `expire`, so state is filtered before expire) and lapsed rows
  (`expire <= now`), and emits in first-appearance order. The clock is
  injected (`parseLeaseCSV(path, now)`) for deterministic tests. The
  filter is lenient: an absent or unparseable `state` / `expire` column
  degrades to "treat the row as active", preserving the pre-#2085
  behaviour for older Kea or exotic headers.
- Per-subnet interface binding (#1778): Kea allows at most ONE
  interface per subnet. Single-interface groups bind explicitly;
  multi-interface groups omit the binding so Kea uses address-based
  subnet selection (the pre-#1778 renderer silently bound only the
  first interface). All group interfaces are always listed in
  `interfaces-config`.
