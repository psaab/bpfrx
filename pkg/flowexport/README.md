# pkg/flowexport

NetFlow v9 and IPFIX (NetFlow v10) exporters. Both ship session-close
events to remote collectors with per-zone direction filters and 1-in-N
session sampling. Wired off `pkg/logging.EventReader` SESSION_CLOSE
events in `pkg/daemon/daemon_flowexport.go`, not the conntrack GC
delete callback. No per-packet sampling path.

Flow record *assembly* is **entirely control-plane**: the userspace
dataplane does NOT build/format NetFlow/IPFIX records — flow records are
assembled in this package from SESSION_CLOSE `logging.EventRecord`s. The
Rust dataplane carried a dead `FlowExporter` and a write-only
`flow_export_config` field that emitted nothing; both were removed in
#2130. (The Go→Rust `flow_export` snapshot wire field is retained as
reserved/ignored to preserve the #1977 decode-safety tests.)

**#2460 — the SESSION_CLOSE events ARE now produced in userspace mode.**
Before #2460, the userspace dataplane emitted a session close ONLY as a
minimal `MSG_SESSION_CLOSE` (type 2) HA session-sync delta on the
SessionDeltaInfo channel (`handleEventStreamDelta`), never as an RT_FLOW
`SESSION_CLOSE` event on the raw dataplane-event channel that these
exporters consume — so the NetFlow/IPFIX session-close callbacks never
fired and userspace session-close export was silently non-functional
(per-packet deny/screen/filter RT_FLOW export already worked). The helper
now emits, on every session close, an ADDITIONAL RT_FLOW SESSION_CLOSE
frame (`EventFrameTypeSessionClose`, type 14) carrying the canonical
136-byte `dataplane.Event` payload on the raw channel. The daemon decodes
it into a `Type:"SESSION_CLOSE"` `EventRecord` via
`eventReader.ProcessRawEvent`, which fires the callbacks below. The type-2
HA delta is unchanged and emitted as a 1:1 pair with the type-14 frame —
the RT_FLOW frame is additive, not a replacement, so HA session sync is
unaffected. The record carries the real 5-tuple, NAT translated tuple,
zones, and protocol; the byte/packet volume counters are 0 because the
AF_XDP forwarding path does not yet maintain per-session accounting — that
is the follow-up tracked in **#2501**. The exported flow duration is
derived from the packet count (`estimateSessionDuration(SessionPkts)`),
not the close record's `created`/`ElapsedTime` field, so it is also 0
until #2501 populates the counters.

## File layout

The package is split by responsibility (#1988):

- `manager.go` — resolved export config (`ExportConfig`,
  `CollectorConfig`, `SamplingDir`), the sampling scheduler
  (`ShouldExport`), the shared `FlowRecord`/`SessionCloseData` shapes,
  and the `BuildExportConfig` / `BuildIPFIXExportConfig` /
  `BuildSamplingZones` config resolvers.
- `netflow.go` — NetFlow v9 template/record encoding and the `Exporter`
  that drives it.
- `ipfix.go` — IPFIX (v10) template/record encoding and the
  `IPFIXExporter` that drives it.
- `transport.go` — shared collector connection management
  (`collectorConns`: dial / fan-out write / close) and the per-family
  batch accumulator (`flowBatch`) used by both exporters. `dialCollectors`
  surfaces any `SourceAddress`/destination resolve error (a misconfigured
  source-address is never silently dropped to an OS-chosen bind) and, on
  any mid-loop resolve or dial failure, closes the connections opened
  earlier in the loop before returning — no descriptor leak on partial
  failure.

## Per-collector write-health (#2464)

Flow export is forensics/compliance data; a collector going unreachable
used to be invisible — every failed UDP write in `writeAll` was
`slog.Debug`-logged and dropped while the exporter kept counting
"exported", so an operator got no warning that records were being lost.
Each `collectorConn` now tracks `WriteAttempts`, `WriteFailures`,
`LastError`/`LastErrorTime`, `LastFailureTime`, `LastSuccessTime`, and a
`Healthy` flag (atomic counters + a mutex-guarded snapshot, race-safe
against a concurrent status reader). The export DATA path is unchanged:
writes are still attempted to every collector and failures are still
non-fatal — this is additive observability.

`writeAll` emits a state-change log ONLY on the
unhealthy↔healthy edge (a `slog.Warn` when a healthy collector first
fails, a `slog.Info` when it recovers), never once per failed write —
`writeAll` runs on the 100ms batch ticker plus each template refresh, so
a per-write warn would flood the journal (project logging rule: no
Warn/Info in a per-tick loop). The per-write `slog.Debug` line is kept
for deep tracing.

The snapshot is surfaced through `Exporter.CollectorHealth()` /
`IPFIXExporter.CollectorHealth()` → `Daemon.FlowCollectorHealth()`
(annotated with protocol / instance / template via
`ExporterCollectorHealth`) on four surfaces:
- **Prometheus** — `xpf_flow_export_collector_{write_attempts_total,
  write_failures_total,healthy,last_success_timestamp_seconds,
  last_failure_timestamp_seconds}`, labeled `{protocol,collector}`
  (emitted before the dataplane gate — exporters are control-plane).
- **REST** — `GET /api/v1/services/flow-exporters`.
- **gRPC / CLI show** — `show flow-monitoring statistics` (gRPC ShowText
  topic `flow-monitoring-statistics`; both the remote `cli` binary and
  the in-daemon interactive CLI).

## Entry points

NetFlow v9:
- `Exporter` — `netflow.go`.
- `NewExporter(cfg *ExportConfig) (*Exporter, error)` — `netflow.go`.
  Takes `*ExportConfig` (never a value copy): `ExportConfig` embeds the
  live 1-in-N `sampleCounter` (`atomic.Uint64`), and copying it would
  fork the counter (a go-vet "copies lock value" failure) — see #2224.
- `Run(ctx context.Context)` — `netflow.go`. Main export loop.
- `Exporter.ExportSessionClose(rec, evt)` — emit one record.

IPFIX:
- `IPFIXExporter` — `ipfix.go`.
- `NewIPFIXExporter(cfg *ExportConfig) (*IPFIXExporter, error)` — `ipfix.go`.
  Also takes `*ExportConfig` (never a value copy) for the same #2224
  reason as `NewExporter`.
- `IPFIXExporter.Run(ctx context.Context)` — `ipfix.go`.
- `IPFIXExporter.ExportSessionClose(rec, evt)` — emit one record.

Shared:
- `ExportConfig` — `manager.go`. Resolved per-template-group config: the
  collectors that referenced one template, that template's timeouts /
  field options, plus the family-shared sampling state (#2461 — see
  "Per-flow-server template binding" below).
- `ResolveV9TemplateGroups(...) []*ExportConfig` /
  `ResolveIPFIXTemplateGroups(...)` — `manager.go`. The per-template-group
  resolvers the daemon uses (#2461).
- `BuildExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig` — `manager.go`.
  Returns nil (no v9 exporter) unless BOTH `forwarding-options sampling`
  has a flow-server AND `services flow-monitoring version9` is configured
  (#2129). This mirrors the `BuildIPFIXExportConfig` `version-ipfix` gate.
  Before #2129 the v9 exporter started on sampling alone, emitting an
  unrequested v9 stream to an IPFIX-only operator's collector. Its
  collector set now contains ONLY the flow-servers bound to v9 (#2136 —
  see "Per-flow-server export-version binding" below).
- `BuildIPFIXExportConfig(...)` / `BuildSamplingZones(...)` — `manager.go`.
- `SamplingDir` — `manager.go`. Direction enum.
- `SessionCloseData` — `manager.go`. Wire shape built from
  `logging.EventReader` SESSION_CLOSE records (in
  `pkg/daemon/daemon_flow.go`).

## Per-flow-server export-version binding (#2136)

Junos binds each `flow-server` to exactly one export version + template.
`BuildExportConfig` (v9) and `BuildIPFIXExportConfig` (IPFIX) therefore
no longer flatten every flow-server into both collector sets — they each
take only the flow-servers resolved to their own version, via the shared
`collectVersionCollectors` / `resolveFlowServerVersion` helpers in
`manager.go`. A given collector address:port appears in at most one of
the two sets, so it never receives both a NetFlow v9 (version 9) AND an
IPFIX (v10) datagram for the same flow.

Before #2136 both builders returned every flow-server, and the daemon
started both exporters against the same collector socket — each with its
own SESSION_CLOSE callback and its own independent 1-in-N counter — so a
flow-server reachable under both global version stanzas was exported
twice with mismatched sampling.

Resolution order for one flow-server (`resolveFlowServerVersion`):

1. **Explicit per-server selector wins.** A flow-server configured with
   `version9 { template … }` / `version9-template …` binds to v9; one
   configured with `version-ipfix { template … }` /
   `version-ipfix-template …` binds to IPFIX (parsed by
   `compiler_services.go` into `FlowServer.Version`). It is then bound to
   that version *only if* the matching global `services flow-monitoring`
   stanza exists (the global stanza supplies template timeouts/fields); a
   server bound to a version whose global stanza is absent exports
   nothing and does NOT silently fall back to the other version.
2. **Unbound server inherits the single configured global version.**
3. **Unbound server with BOTH global versions configured → IPFIX**
   (documented precedence). IPFIX (v10) is the IETF-standard superset of
   NetFlow v9, so an operator who enabled both but did not pin the
   collector gets the modern protocol — and, critically, exactly ONE
   datagram stream rather than the pre-#2136 double-export. To send v9 to
   such a collector, pin it explicitly with a per-server `version9`
   selector.

## Per-flow-server template binding (#2461)

After #2136 routes each flow-server to the right *version*, #2461 routes
it to the right *template*. Junos binds each flow-server to one template
under its version; before #2461 the resolver ignored that reference
entirely — it built ONE export config from the FIRST Go-map-iteration
template and broadcast it (timeouts, `flow-dir` export-extension) to every
collector of the version. A collector that asked for a specific template
silently received whichever the map yielded first, and that choice flipped
across process restarts (map order is not an operator contract).

The resolver now groups collectors by the template they referenced and
emits one `*ExportConfig` per group:

- **`ResolveV9TemplateGroups` / `ResolveIPFIXTemplateGroups`** (`manager.go`)
  return `[]*ExportConfig`, one per referenced template. The group key is
  `(version, template_name)`; **source-address is a deterministic sort
  tiebreak, NOT part of the grouping key** — collectors that share a
  template but pin different source-addresses share ONE group and each
  still receives its own source-pinned UDP connection (via
  `dialCollectors`). Each group carries the timeouts / `V9TemplateOpts` of
  the template its collectors referenced. A collector that referenced no
  template lands in the default (`TemplateName == ""`) group, which inherits
  the lone template's parameters when exactly one is configured (the common
  single-template case — unchanged) and otherwise the built-in defaults.
- **Determinism.** Groups are sorted by template name and each group's
  collectors by address, so process restarts produce identical exporter
  wiring — the map-iteration nondeterminism is gone.
- **Validation.** A flow-server referencing an UNDEFINED template is
  hard-rejected at commit / commit-check by
  `validateFlowServerTemplateReferencesStrict` (`pkg/config`). The tolerant
  load / peer-sync path downgrades it to a warning (#1960) and the resolver
  DROPS that group, so a leniently-loaded bad config exports nothing for
  that collector rather than the wrong template.
- **Per-instance sampling.** 1-in-N sampling is a sampling-INSTANCE
  property (#2462). The template groups of ONE instance share that
  instance's `sampleCounter` (a pointer); two different instances each get
  their own counter. The daemon evaluates `ShouldExport` exactly once per
  instance per SESSION_CLOSE and fans the record out to that instance's
  groups.
- `BuildExportConfig` / `BuildIPFIXExportConfig` (singular) are retained
  for single-aggregate callers and now return the first resolved group.

## Multi-sampling-instance isolation (#2462)

`forwarding-options` can define several `sampling instance <name>` blocks,
each with its own input rate, families, and flow-servers. Before #2462 the
resolver flattened EVERY instance into one global export policy:
`collectVersionCollectors` merged all instances' flow-servers into one
collector set, `samplingRate()` returned the first-nonzero `InputRate` in
Go map order, and one `sampleCounter` was shared by the whole family. Flows
from instance A exported to instance B's collectors and the effective rate
depended on map-iteration order.

The resolver now treats each instance as a first-class export policy. The
grouping key is `(instance, version, template)`:

- **Own collectors.** `collectInstanceVersionCollectors` walks ONE
  instance's flow-servers, so instance A's collectors never receive
  instance B's flows.
- **Own rate.** Each instance's `ExportConfig.SamplingRate` is its own
  `InputRate` — the first-nonzero map-order global rate is gone.
- **Own 1-in-N counter.** Each instance gets a distinct `sampleCounter`, so
  1-in-N is independent per instance (and still shared across that
  instance's template groups, the #2461 invariant scoped to one instance).
- **Attribution by family.** The only per-flow instance selector available
  is the address family: the interface `family inet { sampling { input; } }`
  stanza is a plain boolean and there is **no per-interface
  sampling-instance selector** in the config model. So `ServesInet` /
  `ServesInet6` record which families an instance configured a collector
  for, and `ExportConfig.ServesFamily(isIPv6)` gates a record — an
  inet-only instance never exports an IPv6 flow. The daemon callback walks
  the contiguous per-instance run of groups, applies the family gate + the
  single per-instance sampling decision, then fans to that instance's
  groups.
- **Determinism.** Instances are resolved in lexical name order
  (`sortedInstanceNames`), so restarts produce identical wiring.

### Supported vs rejected matrix

| Configuration | Result |
|---|---|
| Single sampling instance (any rate / families / collectors) | **Supported** — unchanged from pre-#2462 (the common case) |
| Two instances, different families (A: inet, B: inet6) | **Supported** — attributed by flow family |
| Two instances, different export versions (A: version9, B: version-ipfix) on the same family | **Supported** — distinct datagram streams |
| Two instances both exporting the same `(version, family)` pair | **Rejected at commit** — no per-flow instance selector exists, so the runtime cannot attribute a flow to one instance |

The reject is `validateSamplingInstanceConflictsStrict` (`pkg/config`):
strict on commit / commit-check (hard reject so the operator sees it),
lenient on load / peer-sync (downgraded to a warning via
`opts.lenientSamplingInstanceConflicts` so an already-persisted or
peer-synced config still boots — #1960; the resolver still emits both
instances' independent `ExportConfig`s, duplicating eligible flows to both
rather than bricking the load).

### Daemon wiring (one exporter per (instance, template) group)

`reconcileFlowExporters` starts **N exporters per family** — one per
`(instance, template)` group — instead of a single exporter.
`d.flowExporters` / `d.ipfixExporters` are slices; the atomic `flowBundle`
/ `ipfixBundlePtr` carry the group set; the once-registered session-close
callback walks each contiguous per-instance run, applies the family gate +
the single per-instance sampling decision, and exports to that instance's
groups. The per-family config-hash gate, transient-create-failure retry (no
hash recorded), and shutdown teardown all operate over the slice.

## Callers

`pkg/daemon/daemon_flowexport.go::reconcileFlowExporters` owns the
exporter lifecycle (#2075). It runs at boot (after the EventReader
exists) AND on every config commit from `applyConfigLocked`, and is
config-hash-gated per family so an unrelated commit never bounces a
healthy exporter (preserving its template-refresh cadence and 1-in-N
sampling counter). A commit that changes `forwarding-options sampling`
/ `services flow-monitoring` — or that ADDS / REMOVES flow export
entirely — therefore takes effect immediately, without a daemon
restart (before #2075 the exporters were started only at boot and
stopped only at shutdown).

Because the `EventReader` callback list is append-only (clear-all only,
no per-callback removal), the reconcile registers ONE stable
indirection callback per family exactly once
(`flowCBOnce`/`ipfixCBOnce`) that reads the live `(exporter, config)`
pair lock-free from an `atomic.Pointer` bundle; reconcile swaps the
bundle atomically. The callback calls `Exporter.ExportSessionClose()`
(NetFlow v9) / `IPFIXExporter.ExportSessionClose()` (IPFIX) from the
`logging.EventReader` SESSION_CLOSE event. The resolved `*ExportConfig`
is shared by pointer everywhere — in the bundle, by the callback's
`ShouldExport`, AND inside the exporter — so there is exactly ONE live
1-in-N `sampleCounter` (`atomic.Uint64`) per sampling INSTANCE (#2462;
shared across that instance's template groups, distinct between
instances). `ExportConfig` is
never copied by value: doing so would fork the atomic counter (a go-vet
"copies lock value" failure) and silently re-seed the modulo cadence the
moment any caller sampled off the copy (#2224).
`stopFlowExporter`/`stopIPFIXExporter` drain the exporter at shutdown.

## Dependencies

`pkg/config`, `pkg/logging`.

## Gotchas

- 1-in-N sampling uses a monotonic counter on `ExportConfig`. With small
  N a burst of close events can sample several consecutive flows; that's
  expected.
- NetFlow v9 templates refresh every 60 s. If a collector restarts and
  misses a refresh it sees opaque records until the next cycle —
  configure the collector to handle template re-resolution.
- Two batches are maintained inside `flowBatch` (`v4` and `v6`, split
  by family, not by zone — `transport.go`). Both flush on a 100 ms
  ticker or on shutdown.
- `BuildSamplingZones` resolves a zone's interface references
  (`parseIfaceRef`, `manager.go`) into (physical-name, unit) pairs to
  decide which zones have sampling enabled. The unit suffix is parsed
  strictly (#2463): a bare reference with no dot is the implicit unit 0
  (a legitimate config form), but a reference WITH a dot must carry a
  clean unsigned decimal unit after the FINAL dot — `strconv.Atoi`, no
  sign, space, empty suffix, or trailing junk. A malformed reference
  (`ge-0/0/0.1abc2`, `ge-0/0/0.foo`, `ge-0/0/0.-1`, `ge-0/0/0.`) is
  WARNED once and SKIPPED, not silently coerced. The previous
  digit-accumulation scan accepted them all — `1abc2` became unit 12,
  `foo` and an empty suffix became unit 0, `-1` became unit 1 — so
  sampling could be enabled on the wrong unit or silently on unit 0,
  diverging from the operator's interface list.
- `ExportSessionClose` builds the flow record synchronously from the
  event-reader callback. The export goroutine (started in `Run(ctx)`)
  is what actually transmits and refreshes templates; record assembly
  itself isn't offloaded.
- Collector destination and source-bind addresses are built with
  `net.JoinHostPort` (`manager.go` / `transport.go`), so an IPv6
  flow-server or `source-address` is bracketed (`[2001:db8::9]:4739`)
  and parses under `net.ResolveUDPAddr` / `net.Dial`. A plain
  `"%s:%d"` / `addr+":0"` left an IPv6 literal unbracketed and
  unparseable, so IPv6 collectors silently never dialed (#2183). IPv4
  addresses are unaffected.
