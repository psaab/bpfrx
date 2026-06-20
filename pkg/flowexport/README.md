# pkg/flowexport

NetFlow v9 and IPFIX (NetFlow v10) exporters. Both ship session-close
events to remote collectors with per-zone direction filters and 1-in-N
session sampling. Wired off `pkg/logging.EventReader` SESSION_CLOSE
events in `pkg/daemon/daemon_flowexport.go`, not the conntrack GC
delete callback. No per-packet sampling path.

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
- `BuildIPFIXExportConfig(...)` / `BuildSamplingZones(...)` — `manager.go`.
- `SamplingDir` — `manager.go`. Direction enum.
- `SessionCloseData` — `manager.go`. Wire shape built from
  `logging.EventReader` SESSION_CLOSE records (in
  `pkg/daemon/daemon_flow.go`).

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
