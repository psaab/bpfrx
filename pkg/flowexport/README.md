# pkg/flowexport

NetFlow v9 and IPFIX (NetFlow v10) exporters. Both ship session-close
events to remote collectors with per-zone direction filters and 1-in-N
session sampling. Wired off `pkg/logging.EventReader` SESSION_CLOSE
events in `pkg/daemon/daemon_flowexport.go`, not the conntrack GC
delete callback. No per-packet sampling path.

Flow export is **entirely control-plane**. The userspace dataplane
(`userspace-dp`) does NOT emit flow records — it never has. Flow records
are assembled in this package from SESSION_CLOSE events. The Rust
dataplane carried a dead `FlowExporter` and a write-only
`flow_export_config` field that emitted nothing; both were removed in
#2130. (The Go→Rust `flow_export` snapshot wire field is retained as
reserved/ignored to preserve the #1977 decode-safety tests.)

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

## Entry points

NetFlow v9:
- `Exporter` — `netflow.go`.
- `NewExporter(cfg ExportConfig) (*Exporter, error)` — `netflow.go`.
- `Run(ctx context.Context)` — `netflow.go`. Main export loop.
- `Exporter.ExportSessionClose(rec, evt)` — emit one record.

IPFIX:
- `IPFIXExporter` — `ipfix.go`.
- `NewIPFIXExporter(cfg ExportConfig) (*IPFIXExporter, error)` — `ipfix.go`.
- `IPFIXExporter.Run(ctx context.Context)` — `ipfix.go`.
- `IPFIXExporter.ExportSessionClose(rec, evt)` — emit one record.

Shared:
- `ExportConfig` — `manager.go`. Resolved per-collector config.
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
`logging.EventReader` SESSION_CLOSE event. The daemon-held
`*ExportConfig` is the sole 1-in-N counter owner (the exporter never
reads `sampleCounter`), so it is held by pointer in the bundle.
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
- `ExportSessionClose` builds the flow record synchronously from the
  event-reader callback. The export goroutine (started in `Run(ctx)`)
  is what actually transmits and refreshes templates; record assembly
  itself isn't offloaded.
