package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initFlowExportDescriptors() {
	// #2464: per-collector flow-export write-health.
	c.flowExportCollectorWriteAttemptsTotal = prometheus.NewDesc(
		"xpf_flow_export_collector_write_attempts_total",
		"Total NetFlow v9 / IPFIX UDP write attempts per collector. Labeled by instance and template as well as collector and source, so two template groups / family-disjoint instances that share one collector address stay distinct series (#3741).",
		[]string{"protocol", "instance", "template", "collector", "source"}, nil,
	)
	c.flowExportCollectorWriteFailuresTotal = prometheus.NewDesc(
		"xpf_flow_export_collector_write_failures_total",
		"Total NetFlow v9 / IPFIX UDP write failures per collector (a climbing value while attempts climb means the collector is unreachable and flow records are being silently dropped). Labeled by instance and template as well as collector and source, so a failing template group sharing a collector address is attributable, not hidden (#3741).",
		[]string{"protocol", "instance", "template", "collector", "source"}, nil,
	)
	c.flowExportCollectorWriteSkippedTotal = prometheus.NewDesc(
		"xpf_flow_export_collector_write_skipped_total",
		"Total NetFlow v9 / IPFIX writes SKIPPED per collector because it was unhealthy and still inside its probe-backoff window (#4423). A climbing value (while attempts/failures hold) means a persistently-dead collector is being skipped between probes rather than re-attempted every flush — the deliberate steady-state cost cap for a dead collector. Same label set as attempts/failures.",
		[]string{"protocol", "instance", "template", "collector", "source"}, nil,
	)
	c.flowExportCollectorHealthy = prometheus.NewDesc(
		"xpf_flow_export_collector_healthy",
		"1 when the last write to this flow-export collector succeeded, 0 when the last write failed. Labeled by instance and template as well as collector and source (#3741).",
		[]string{"protocol", "instance", "template", "collector", "source"}, nil,
	)
	c.flowExportCollectorLastSuccessSeconds = prometheus.NewDesc(
		"xpf_flow_export_collector_last_success_timestamp_seconds",
		"Unix timestamp of the last successful write to this flow-export collector (0 if none yet). Labeled by instance and template as well as collector and source (#3741).",
		[]string{"protocol", "instance", "template", "collector", "source"}, nil,
	)
	c.flowExportCollectorLastFailureSeconds = prometheus.NewDesc(
		"xpf_flow_export_collector_last_failure_timestamp_seconds",
		"Unix timestamp of the last failed write to this flow-export collector (0 if none yet). Labeled by instance and template as well as collector and source (#3741).",
		[]string{"protocol", "instance", "template", "collector", "source"}, nil,
	)

	// #3747: per-exporter pending-batch queue observability.
	c.flowExportBatchDepth = prometheus.NewDesc(
		"xpf_flow_export_batch_depth",
		"Current number of flow records pending in the export batch for this group (both families combined). Normally near 0 — the exporter drains every 100ms; a sustained nonzero value means the drain cannot keep up (stalled export goroutine, slow/unreachable collector, or a SESSION_CLOSE storm) (#3747).",
		[]string{"protocol", "instance", "template"}, nil,
	)
	c.flowExportBatchMaxDepth = prometheus.NewDesc(
		"xpf_flow_export_batch_max_depth",
		"High-water mark of the pending export batch depth for this group since the exporter started. Captures a transient backlog even after a later drain empties the queue (#3747).",
		[]string{"protocol", "instance", "template"}, nil,
	)
	c.flowExportBatchDroppedTotal = prometheus.NewDesc(
		"xpf_flow_export_batch_dropped_total",
		"Total flow records dropped because the pending export batch was at its per-family capacity (#3747). Before #3747 the batch was unbounded and a stalled/overrun drain grew memory without bound; it now drops (drop-newest) and counts. A climbing value means export records are being lost to a drain that cannot keep up.",
		[]string{"protocol", "instance", "template"}, nil,
	)
}
