package format

import (
	"fmt"
	"strings"

	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// This file holds the `show system buffers` renderers. The row/taxonomy model
// they consume lives in buffers_model.go; both the CLI/gRPC text formatter
// (FormatSystemBuffers) and the REST/structured exporter
// (StructuredSystemBufferRows) build a systemBufferModel via
// buildSystemBufferModel so they can never disagree about which rows exist
// (#4661 CLI/gRPC/REST parity). The section titles below are render-scope; the
// row-name labels are the model's taxonomy (buffers_model.go).
const (
	systemBufferUtilizationHeading = "Userspace Buffer Utilization:"
	systemBufferCountersHeading    = "Userspace Status Counters:"
)

// SystemBufferUtilizationRow is a bounded userspace buffer row suitable for
// non-text renderers such as REST. It intentionally excludes dynamic counters
// that do not have helper-published capacity denominators.
type SystemBufferUtilizationRow struct {
	Name         string
	Scope        string
	Capacity     uint64
	Used         uint64
	UsagePercent float64
	Status       string
}

// SystemBufferCounterRow is an unbounded userspace pressure/status counter.
// These rows deliberately have no capacity denominator and must not be
// rendered as fill percentages.
type SystemBufferCounterRow struct {
	Name  string
	Scope string
	Value uint64
}

// SystemBufferRows contains all structured userspace buffer/status rows that
// non-text renderers need to mirror FormatSystemBuffers.
type SystemBufferRows struct {
	Utilization       []SystemBufferUtilizationRow
	Counters          []SystemBufferCounterRow
	KnownUMEMBindings int
	KnownTXRings      int
}

// SystemBufferUtilizationRows returns the same bounded helper-status capacity
// rows used by FormatSystemBuffers. Missing helper capacity fields produce no
// synthetic fill rows rather than falling back to BPF map statistics.
func SystemBufferUtilizationRows(status userspace.ProcessStatus, detail bool) []SystemBufferUtilizationRow {
	return StructuredSystemBufferRows(status, detail).Utilization
}

// StructuredSystemBufferRows returns helper-backed userspace buffer rows and
// unbounded status counters using the same sampling and fallback logic as the
// CLI/gRPC text formatter.
func StructuredSystemBufferRows(status userspace.ProcessStatus, detail bool) SystemBufferRows {
	model := buildSystemBufferModel(status, detail)
	return SystemBufferRows{
		Utilization:       exportedSystemBufferRows(model.rows),
		Counters:          exportedSystemBufferCounterRows(model.counterRows),
		KnownUMEMBindings: model.knownUMEM,
		KnownTXRings:      model.knownTX,
	}
}

func exportedSystemBufferRows(rows []systemBufferRow) []SystemBufferUtilizationRow {
	out := make([]SystemBufferUtilizationRow, 0, len(rows))
	for _, row := range rows {
		usage, state := systemBufferUsage(row)
		out = append(out, SystemBufferUtilizationRow{
			Name:         row.Name,
			Scope:        row.Scope,
			Capacity:     row.Capacity,
			Used:         row.Used,
			UsagePercent: usage,
			Status:       state,
		})
	}
	return out
}

func exportedSystemBufferCounterRows(rows []systemBufferCounterRow) []SystemBufferCounterRow {
	out := make([]SystemBufferCounterRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, SystemBufferCounterRow{
			Name:  row.Name,
			Scope: row.Scope,
			Value: row.Value,
		})
	}
	return out
}

// FormatSystemBuffers renders userspace dataplane buffer capacity telemetry for
// `show system buffers`. Capacity rows only use bounded gauges published in
// helper status; unbounded helper counters/gauges render in a separate section
// so missing denominators are not mistaken for real fill percentages.
func FormatSystemBuffers(status userspace.ProcessStatus, detail bool) string {
	model := buildSystemBufferModel(status, detail)

	var b strings.Builder
	writeSystemBufferUtilizationSection(&b, model)
	writeSystemBufferCountersSection(&b, model)
	return b.String()
}

// writeSystemBufferUtilizationSection renders the bounded buffer utilization
// table (or the "unavailable" hint when no bounded gauges were published) plus
// the trailing high-utilization warning count.
func writeSystemBufferUtilizationSection(b *strings.Builder, model systemBufferModel) {
	b.WriteString(systemBufferUtilizationHeading + "\n")
	if len(model.rows) == 0 {
		b.WriteString("  unavailable: helper status does not include bounded userspace capacity gauges\n")
		b.WriteString("  required status fields: per_binding[].umem_total_frames, per_binding[].umem_inflight_frames, per_binding[].tx_ring_capacity, per_binding[].outstanding_tx\n")
		b.WriteString("  dynamic status fields: session_table_entries/max_sessions, per_binding[].flow_cache_capacity, neighbor_cache_capacity\n")
		b.WriteString("  bindings[] mirrors with the same fields are also accepted\n")
		return
	}
	if model.knownUMEM == 0 && model.knownTX == 0 {
		b.WriteString("  AF_XDP unavailable: helper status does not include bounded capacity gauges\n")
	}
	fmt.Fprintf(b, "%-24s %-24s %12s %12s %8s %s\n", "Buffer", "Scope", "Capacity", "Used", "Usage%", "Status")
	b.WriteString(strings.Repeat("-", 92) + "\n")
	warnings := 0
	for _, row := range model.rows {
		pct, status := systemBufferUsage(row)
		if status != "OK" {
			warnings++
		}
		fmt.Fprintf(b, "%-24s %-24s %12d %12d %7.1f%% %s\n",
			row.Name, row.Scope, row.Capacity, row.Used, pct, status)
	}
	if warnings > 0 {
		fmt.Fprintf(b, "\n%d userspace buffer row(s) at high utilization\n", warnings)
	}
}

// writeSystemBufferCountersSection renders the unbounded status/pressure
// counter table. It is omitted entirely when no counters are present, and its
// leading blank-line spacing matches the pre-split renderer.
func writeSystemBufferCountersSection(b *strings.Builder, model systemBufferModel) {
	if len(model.counterRows) == 0 {
		return
	}
	if !strings.HasSuffix(b.String(), "\n\n") {
		b.WriteString("\n")
	}
	b.WriteString(systemBufferCountersHeading + "\n")
	fmt.Fprintf(b, "%-32s %-24s %12s\n", "Counter", "Scope", "Value")
	b.WriteString(strings.Repeat("-", 70) + "\n")
	for _, row := range model.counterRows {
		fmt.Fprintf(b, "%-32s %-24s %12d\n", row.Name, row.Scope, row.Value)
	}
}
