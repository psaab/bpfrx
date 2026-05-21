package userspace

import (
	"fmt"
	"sort"
	"strings"
)

const (
	systemBufferUtilizationHeading = "Userspace Buffer Utilization:"
	systemBufferCountersHeading    = "Userspace Status Counters:"

	systemBufferLabelAFXDPUMEMFrames        = "AF_XDP UMEM frames"
	systemBufferLabelAFXDPTXRing            = "AF_XDP TX ring"
	systemBufferLabelCoSQueueBytes          = "CoS queue bytes"
	systemBufferLabelSessionTableEntries    = "Session table entries"
	systemBufferLabelNeighborCacheEntries   = "Neighbor cache entries"
	systemBufferLabelFlowCacheActiveFlows   = "Flow cache active flows"
	systemBufferLabelFlowCacheEvictions     = "Flow cache collision evict"
	systemBufferLabelPendingFillFrames      = "Pending fill frames"
	systemBufferLabelSpareFillFrames        = "Spare fill frames"
	systemBufferLabelPendingTXPrepared      = "Pending TX prepared"
	systemBufferLabelPendingTXLocal         = "Pending TX local"
	systemBufferLabelTXRingFullEvents       = "TX ring full events"
	systemBufferLabelSendtoENOBUFS          = "sendto ENOBUFS"
	systemBufferLabelBoundPendingOverflow   = "Bound pending overflow"
	systemBufferLabelCoSQueueOverflow       = "CoS queue overflow"
	systemBufferLabelRXFillRingEmptyDescs   = "RX fill-ring empty descs"
	systemBufferLabelRedirectInboxOverflow  = "Redirect inbox overflow"
	systemBufferLabelPendingTXLocalOver     = "Pending TX local overflow"
	systemBufferLabelTXSubmitErrorDrops     = "TX submit error drops"
	systemBufferLabelSYNCookieChallenges    = "SYN-cookie challenges"
	systemBufferLabelSYNCookieSecretUnavail = "SYN-cookie secret unavailable"
	systemBufferLabelSYNCookieSynAckSent    = "SYN-cookie SYN-ACK sent"
	systemBufferLabelSYNCookieAckRstSent    = "SYN-cookie ACK RST sent"
	systemBufferLabelSYNCookieBudgetDrops   = "SYN-cookie budget drops"
	systemBufferLabelSYNCookieAckValid      = "SYN-cookie ACK valid"
	systemBufferLabelSYNCookieAckInvalid    = "SYN-cookie ACK invalid"
	systemBufferLabelSYNCookieBypass        = "SYN-cookie bypass"
)

type systemBufferSample struct {
	Slot                        uint32
	HasSlot                     bool
	WorkerID                    uint32
	QueueID                     uint32
	Ifindex                     int
	Interface                   string
	UMEMCap                     uint32
	UMEMUsed                    uint32
	TXRingCap                   uint32
	TXRingUsed                  uint32
	ActiveFlowCount             uint32
	FlowCacheCapacity           uint32
	FlowCacheCollisionEvictions uint64
	DebugPendingFillFrames      uint32
	DebugSpareFillFrames        uint32
	DebugPendingTXPrepared      uint32
	DebugPendingTXLocal         uint32
	DbgTxRingFull               uint64
	DbgSendtoENOBUFS            uint64
	DbgBoundPendingOverflow     uint64
	DbgCoSQueueOverflow         uint64
	RxFillRingEmptyDescs        uint64
	RedirectInboxOverflowDrops  uint64
	PendingTXLocalOverflowDrops uint64
	TxSubmitErrorDrops          uint64
	SYNCookieChallenges         uint64
	SYNCookieSecretUnavailable  uint64
	SYNCookieSynAckSent         uint64
	SYNCookieAckRstSent         uint64
	SYNCookieReplyBudgetDrops   uint64
	SYNCookieAckValid           uint64
	SYNCookieAckInvalid         uint64
	SYNCookieBypass             uint64
}

type systemBufferRow struct {
	Name     string
	Scope    string
	Capacity uint64
	Used     uint64
}

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

type systemBufferCounterRow struct {
	Name  string
	Scope string
	Value uint64
}

// SystemBufferUtilizationRows returns the same bounded helper-status capacity
// rows used by FormatSystemBuffers. Missing helper capacity fields produce no
// synthetic fill rows rather than falling back to BPF map statistics.
func SystemBufferUtilizationRows(status ProcessStatus, detail bool) []SystemBufferUtilizationRow {
	return StructuredSystemBufferRows(status, detail).Utilization
}

// StructuredSystemBufferRows returns helper-backed userspace buffer rows and
// unbounded status counters using the same sampling and fallback logic as the
// CLI/gRPC text formatter.
func StructuredSystemBufferRows(status ProcessStatus, detail bool) SystemBufferRows {
	samples := systemBufferSamples(status)
	rows, knownUMEM, knownTX := systemBufferRows(status, samples, detail)
	counterRows := systemBufferCounterRows(status, samples, detail)
	return SystemBufferRows{
		Utilization:       exportedSystemBufferRows(rows),
		Counters:          exportedSystemBufferCounterRows(counterRows),
		KnownUMEMBindings: knownUMEM,
		KnownTXRings:      knownTX,
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
func FormatSystemBuffers(status ProcessStatus, detail bool) string {
	samples := systemBufferSamples(status)
	rows, knownUMEM, knownTX := systemBufferRows(status, samples, detail)
	counterRows := systemBufferCounterRows(status, samples, detail)

	var b strings.Builder
	b.WriteString(systemBufferUtilizationHeading + "\n")
	if len(rows) == 0 {
		b.WriteString("  unavailable: helper status does not include bounded userspace capacity gauges\n")
		b.WriteString("  required status fields: per_binding[].umem_total_frames, per_binding[].umem_inflight_frames, per_binding[].tx_ring_capacity, per_binding[].outstanding_tx\n")
		b.WriteString("  dynamic status fields: session_table_entries/max_sessions, per_binding[].flow_cache_capacity, neighbor_cache_capacity\n")
		b.WriteString("  bindings[] mirrors with the same fields are also accepted\n")
	} else {
		if knownUMEM == 0 && knownTX == 0 {
			b.WriteString("  AF_XDP unavailable: helper status does not include bounded capacity gauges\n")
		}
		fmt.Fprintf(&b, "%-24s %-24s %12s %12s %8s %s\n", "Buffer", "Scope", "Capacity", "Used", "Usage%", "Status")
		b.WriteString(strings.Repeat("-", 92) + "\n")
		warnings := 0
		for _, row := range rows {
			pct, status := systemBufferUsage(row)
			if status != "OK" {
				warnings++
			}
			fmt.Fprintf(&b, "%-24s %-24s %12d %12d %7.1f%% %s\n",
				row.Name, row.Scope, row.Capacity, row.Used, pct, status)
		}
		if warnings > 0 {
			fmt.Fprintf(&b, "\n%d userspace buffer row(s) at high utilization\n", warnings)
		}
	}
	if len(counterRows) > 0 {
		if !strings.HasSuffix(b.String(), "\n\n") {
			b.WriteString("\n")
		}
		b.WriteString(systemBufferCountersHeading + "\n")
		fmt.Fprintf(&b, "%-32s %-24s %12s\n", "Counter", "Scope", "Value")
		b.WriteString(strings.Repeat("-", 70) + "\n")
		for _, row := range counterRows {
			fmt.Fprintf(&b, "%-32s %-24s %12d\n", row.Name, row.Scope, row.Value)
		}
	}
	return b.String()
}

func systemBufferRows(
	status ProcessStatus,
	samples []systemBufferSample,
	detail bool,
) ([]systemBufferRow, int, int) {
	var umemCap, umemUsed, txCap, txUsed uint64
	var knownUMEM, knownTX int
	for _, sample := range samples {
		if sample.UMEMCap > 0 {
			knownUMEM++
			umemCap += uint64(sample.UMEMCap)
			umemUsed += uint64(sample.UMEMUsed)
		}
		if sample.TXRingCap > 0 {
			knownTX++
			txCap += uint64(sample.TXRingCap)
			txUsed += uint64(sample.TXRingUsed)
		}
	}

	var rows []systemBufferRow
	if knownUMEM > 0 {
		rows = append(rows, systemBufferRow{
			Name:     systemBufferLabelAFXDPUMEMFrames,
			Scope:    fmt.Sprintf("aggregate/%d", knownUMEM),
			Capacity: umemCap,
			Used:     umemUsed,
		})
	}
	if knownTX > 0 {
		rows = append(rows, systemBufferRow{
			Name:     systemBufferLabelAFXDPTXRing,
			Scope:    fmt.Sprintf("aggregate/%d", knownTX),
			Capacity: txCap,
			Used:     txUsed,
		})
	}
	rows = append(rows, systemBufferCoSRows(status, detail)...)
	if status.MaxSessions > 0 {
		rows = append(rows, systemBufferRow{
			Name:     systemBufferLabelSessionTableEntries,
			Scope:    "aggregate",
			Capacity: status.MaxSessions,
			Used:     status.SessionTableEntries,
		})
	}
	if flowUsed, flowCap, flowKnown := systemBufferFlowCacheAggregate(status, samples); flowCap > 0 {
		scope := "aggregate"
		if flowKnown > 0 {
			scope = fmt.Sprintf("aggregate/%d", flowKnown)
		}
		rows = append(rows, systemBufferRow{
			Name:     systemBufferLabelFlowCacheActiveFlows,
			Scope:    scope,
			Capacity: flowCap,
			Used:     flowUsed,
		})
	}
	if status.NeighborCacheCapacity > 0 {
		rows = append(rows, systemBufferRow{
			Name:     systemBufferLabelNeighborCacheEntries,
			Scope:    "dynamic",
			Capacity: status.NeighborCacheCapacity,
			Used:     uint64(status.NeighborEntries),
		})
	}
	if detail {
		for _, sample := range samples {
			scope := systemBufferSampleScope(sample)
			if sample.UMEMCap > 0 {
				rows = append(rows, systemBufferRow{
					Name:     systemBufferLabelAFXDPUMEMFrames,
					Scope:    scope,
					Capacity: uint64(sample.UMEMCap),
					Used:     uint64(sample.UMEMUsed),
				})
			}
			if sample.TXRingCap > 0 {
				rows = append(rows, systemBufferRow{
					Name:     systemBufferLabelAFXDPTXRing,
					Scope:    scope,
					Capacity: uint64(sample.TXRingCap),
					Used:     uint64(sample.TXRingUsed),
				})
			}
			if sample.FlowCacheCapacity > 0 {
				rows = append(rows, systemBufferRow{
					Name:     systemBufferLabelFlowCacheActiveFlows,
					Scope:    scope,
					Capacity: uint64(sample.FlowCacheCapacity),
					Used:     uint64(sample.ActiveFlowCount),
				})
			}
		}
	}
	return rows, knownUMEM, knownTX
}

func systemBufferFlowCacheAggregate(
	status ProcessStatus,
	samples []systemBufferSample,
) (uint64, uint64, int) {
	var used, capacity uint64
	var known int
	for _, sample := range samples {
		if sample.FlowCacheCapacity == 0 {
			continue
		}
		known++
		used += uint64(sample.ActiveFlowCount)
		capacity += uint64(sample.FlowCacheCapacity)
	}
	if capacity > 0 {
		return used, capacity, known
	}
	if status.FlowCacheCapacity == 0 {
		return 0, 0, 0
	}
	for _, sample := range samples {
		used += uint64(sample.ActiveFlowCount)
	}
	return used, status.FlowCacheCapacity, 0
}

func systemBufferUsage(row systemBufferRow) (float64, string) {
	pct := 0.0
	if row.Capacity > 0 {
		pct = float64(row.Used) * 100.0 / float64(row.Capacity)
	}
	switch {
	case pct >= 90.0:
		return pct, "CRITICAL"
	case pct >= 80.0:
		return pct, "WARNING"
	default:
		return pct, "OK"
	}
}

func systemBufferCoSRows(status ProcessStatus, detail bool) []systemBufferRow {
	var rows []systemBufferRow
	var aggregateCap, aggregateUsed uint64
	var queueCount int
	for _, iface := range status.CoSInterfaces {
		for _, queue := range iface.Queues {
			if queue.BufferBytes == 0 {
				continue
			}
			queueCount++
			aggregateCap += queue.BufferBytes
			aggregateUsed += queue.QueuedBytes
		}
	}
	if queueCount == 0 {
		return rows
	}
	rows = append(rows, systemBufferRow{
		Name:     systemBufferLabelCoSQueueBytes,
		Scope:    fmt.Sprintf("aggregate/%d", queueCount),
		Capacity: aggregateCap,
		Used:     aggregateUsed,
	})
	if !detail {
		return rows
	}
	for _, iface := range status.CoSInterfaces {
		for _, queue := range iface.Queues {
			if queue.BufferBytes == 0 {
				continue
			}
			rows = append(rows, systemBufferRow{
				Name:     systemBufferLabelCoSQueueBytes,
				Scope:    systemBufferCoSQueueScope(iface, queue),
				Capacity: queue.BufferBytes,
				Used:     queue.QueuedBytes,
			})
		}
	}
	return rows
}

func systemBufferCounterRows(status ProcessStatus, samples []systemBufferSample, detail bool) []systemBufferCounterRow {
	var activeFlowCount uint64
	var flowCacheCollisionEvictions uint64
	var debugPendingFillFrames uint64
	var debugSpareFillFrames uint64
	var debugPendingTXPrepared uint64
	var debugPendingTXLocal uint64
	var dbgTxRingFull uint64
	var dbgSendtoENOBUFS uint64
	var dbgBoundPendingOverflow uint64
	var dbgCoSQueueOverflow uint64
	var rxFillRingEmptyDescs uint64
	var redirectInboxOverflowDrops uint64
	var pendingTXLocalOverflowDrops uint64
	var txSubmitErrorDrops uint64
	var synCookieChallenges uint64
	var synCookieSecretUnavailable uint64
	var synCookieSynAckSent uint64
	var synCookieAckRstSent uint64
	var synCookieReplyBudgetDrops uint64
	var synCookieAckValid uint64
	var synCookieAckInvalid uint64
	var synCookieBypass uint64
	for _, sample := range samples {
		activeFlowCount += uint64(sample.ActiveFlowCount)
		flowCacheCollisionEvictions += sample.FlowCacheCollisionEvictions
		debugPendingFillFrames += uint64(sample.DebugPendingFillFrames)
		debugSpareFillFrames += uint64(sample.DebugSpareFillFrames)
		debugPendingTXPrepared += uint64(sample.DebugPendingTXPrepared)
		debugPendingTXLocal += uint64(sample.DebugPendingTXLocal)
		dbgTxRingFull += sample.DbgTxRingFull
		dbgSendtoENOBUFS += sample.DbgSendtoENOBUFS
		dbgBoundPendingOverflow += sample.DbgBoundPendingOverflow
		dbgCoSQueueOverflow += sample.DbgCoSQueueOverflow
		rxFillRingEmptyDescs += sample.RxFillRingEmptyDescs
		redirectInboxOverflowDrops += sample.RedirectInboxOverflowDrops
		pendingTXLocalOverflowDrops += sample.PendingTXLocalOverflowDrops
		txSubmitErrorDrops += sample.TxSubmitErrorDrops
		synCookieChallenges += sample.SYNCookieChallenges
		synCookieSecretUnavailable += sample.SYNCookieSecretUnavailable
		synCookieSynAckSent += sample.SYNCookieSynAckSent
		synCookieAckRstSent += sample.SYNCookieAckRstSent
		synCookieReplyBudgetDrops += sample.SYNCookieReplyBudgetDrops
		synCookieAckValid += sample.SYNCookieAckValid
		synCookieAckInvalid += sample.SYNCookieAckInvalid
		synCookieBypass += sample.SYNCookieBypass
	}

	var rows []systemBufferCounterRow
	appendCounter := func(name, scope string, value uint64) {
		if value > 0 {
			rows = append(rows, systemBufferCounterRow{Name: name, Scope: scope, Value: value})
		}
	}
	if status.MaxSessions == 0 {
		appendCounter(systemBufferLabelSessionTableEntries, "aggregate", status.SessionTableEntries)
	}
	if status.NeighborCacheCapacity == 0 {
		appendCounter(systemBufferLabelNeighborCacheEntries, "dynamic", uint64(status.NeighborEntries))
	}
	if _, flowCap, _ := systemBufferFlowCacheAggregate(status, samples); flowCap == 0 {
		appendCounter(systemBufferLabelFlowCacheActiveFlows, "active window", activeFlowCount)
	}
	appendCounter(systemBufferLabelFlowCacheEvictions, "aggregate", flowCacheCollisionEvictions)
	appendCounter(systemBufferLabelPendingFillFrames, "aggregate", debugPendingFillFrames)
	appendCounter(systemBufferLabelSpareFillFrames, "aggregate", debugSpareFillFrames)
	appendCounter(systemBufferLabelPendingTXPrepared, "aggregate", debugPendingTXPrepared)
	appendCounter(systemBufferLabelPendingTXLocal, "aggregate", debugPendingTXLocal)
	appendCounter(systemBufferLabelTXRingFullEvents, "aggregate", dbgTxRingFull)
	appendCounter(systemBufferLabelSendtoENOBUFS, "aggregate", dbgSendtoENOBUFS)
	appendCounter(systemBufferLabelBoundPendingOverflow, "aggregate", dbgBoundPendingOverflow)
	appendCounter(systemBufferLabelCoSQueueOverflow, "aggregate", dbgCoSQueueOverflow)
	appendCounter(systemBufferLabelRXFillRingEmptyDescs, "aggregate", rxFillRingEmptyDescs)
	appendCounter(systemBufferLabelRedirectInboxOverflow, "aggregate", redirectInboxOverflowDrops)
	appendCounter(systemBufferLabelPendingTXLocalOver, "aggregate", pendingTXLocalOverflowDrops)
	appendCounter(systemBufferLabelTXSubmitErrorDrops, "aggregate", txSubmitErrorDrops)
	appendCounter(systemBufferLabelSYNCookieChallenges, "aggregate", synCookieChallenges)
	appendCounter(systemBufferLabelSYNCookieSecretUnavail, "aggregate", synCookieSecretUnavailable)
	appendCounter(systemBufferLabelSYNCookieSynAckSent, "aggregate", synCookieSynAckSent)
	appendCounter(systemBufferLabelSYNCookieAckRstSent, "aggregate", synCookieAckRstSent)
	appendCounter(systemBufferLabelSYNCookieBudgetDrops, "aggregate", synCookieReplyBudgetDrops)
	appendCounter(systemBufferLabelSYNCookieAckValid, "aggregate", synCookieAckValid)
	appendCounter(systemBufferLabelSYNCookieAckInvalid, "aggregate", synCookieAckInvalid)
	appendCounter(systemBufferLabelSYNCookieBypass, "aggregate", synCookieBypass)

	if !detail {
		return rows
	}
	for _, sample := range samples {
		scope := systemBufferSampleScope(sample)
		if sample.FlowCacheCapacity == 0 {
			appendCounter(systemBufferLabelFlowCacheActiveFlows, scope, uint64(sample.ActiveFlowCount))
		}
		appendCounter(systemBufferLabelFlowCacheEvictions, scope, sample.FlowCacheCollisionEvictions)
		appendCounter(systemBufferLabelPendingFillFrames, scope, uint64(sample.DebugPendingFillFrames))
		appendCounter(systemBufferLabelSpareFillFrames, scope, uint64(sample.DebugSpareFillFrames))
		appendCounter(systemBufferLabelPendingTXPrepared, scope, uint64(sample.DebugPendingTXPrepared))
		appendCounter(systemBufferLabelPendingTXLocal, scope, uint64(sample.DebugPendingTXLocal))
		appendCounter(systemBufferLabelTXRingFullEvents, scope, sample.DbgTxRingFull)
		appendCounter(systemBufferLabelSendtoENOBUFS, scope, sample.DbgSendtoENOBUFS)
		appendCounter(systemBufferLabelBoundPendingOverflow, scope, sample.DbgBoundPendingOverflow)
		appendCounter(systemBufferLabelCoSQueueOverflow, scope, sample.DbgCoSQueueOverflow)
		appendCounter(systemBufferLabelRXFillRingEmptyDescs, scope, sample.RxFillRingEmptyDescs)
		appendCounter(systemBufferLabelRedirectInboxOverflow, scope, sample.RedirectInboxOverflowDrops)
		appendCounter(systemBufferLabelPendingTXLocalOver, scope, sample.PendingTXLocalOverflowDrops)
		appendCounter(systemBufferLabelTXSubmitErrorDrops, scope, sample.TxSubmitErrorDrops)
		appendCounter(systemBufferLabelSYNCookieChallenges, scope, sample.SYNCookieChallenges)
		appendCounter(systemBufferLabelSYNCookieSecretUnavail, scope, sample.SYNCookieSecretUnavailable)
		appendCounter(systemBufferLabelSYNCookieSynAckSent, scope, sample.SYNCookieSynAckSent)
		appendCounter(systemBufferLabelSYNCookieAckRstSent, scope, sample.SYNCookieAckRstSent)
		appendCounter(systemBufferLabelSYNCookieBudgetDrops, scope, sample.SYNCookieReplyBudgetDrops)
		appendCounter(systemBufferLabelSYNCookieAckValid, scope, sample.SYNCookieAckValid)
		appendCounter(systemBufferLabelSYNCookieAckInvalid, scope, sample.SYNCookieAckInvalid)
		appendCounter(systemBufferLabelSYNCookieBypass, scope, sample.SYNCookieBypass)
	}
	return rows
}

func systemBufferSamples(status ProcessStatus) []systemBufferSample {
	bindings := make(map[systemBufferBindingKey]BindingStatus, len(status.Bindings))
	for _, binding := range status.Bindings {
		bindings[systemBufferBindingKey{
			WorkerID: binding.WorkerID,
			QueueID:  binding.QueueID,
			Ifindex:  binding.Ifindex,
		}] = binding
	}

	var samples []systemBufferSample
	seen := make(map[systemBufferBindingKey]struct{}, len(status.PerBinding))
	if len(status.PerBinding) > 0 {
		for _, binding := range status.PerBinding {
			key := systemBufferBindingKey{
				WorkerID: binding.WorkerID,
				QueueID:  binding.QueueID,
				Ifindex:  binding.Ifindex,
			}
			seen[key] = struct{}{}
			sample := systemBufferSample{
				WorkerID:                    binding.WorkerID,
				QueueID:                     binding.QueueID,
				Ifindex:                     binding.Ifindex,
				UMEMCap:                     binding.UmemTotalFrames,
				UMEMUsed:                    binding.UmemInflightFrames,
				TXRingCap:                   binding.TxRingCapacity,
				TXRingUsed:                  binding.OutstandingTX,
				ActiveFlowCount:             binding.ActiveFlowCount,
				FlowCacheCapacity:           binding.FlowCacheCapacity,
				FlowCacheCollisionEvictions: binding.FlowCacheCollisionEvictions,
				DbgTxRingFull:               binding.DbgTxRingFull,
				DbgSendtoENOBUFS:            binding.DbgSendtoENOBUFS,
				DbgBoundPendingOverflow:     binding.DbgBoundPendingOverflow,
				DbgCoSQueueOverflow:         binding.DbgCoSQueueOverflow,
				RxFillRingEmptyDescs:        binding.RxFillRingEmptyDescs,
				PendingTXLocalOverflowDrops: binding.PendingTxLocalOverflowDrops,
				TxSubmitErrorDrops:          binding.TxSubmitErrorDrops,
			}
			if full, ok := bindings[key]; ok {
				sample.Slot = full.Slot
				sample.HasSlot = true
				sample.Interface = full.Interface
				if binding.UmemTotalFrames == 0 {
					sample.UMEMCap = full.UmemTotalFrames
					sample.UMEMUsed = full.UmemInflightFrames
				}
				if binding.TxRingCapacity == 0 {
					sample.TXRingCap = full.TxRingCapacity
					sample.TXRingUsed = full.OutstandingTX
				}
				if binding.FlowCacheCapacity == 0 {
					sample.FlowCacheCapacity = full.FlowCacheCapacity
				}
				sample.applyBindingStatusFallback(full)
			}
			samples = append(samples, sample)
		}
	}
	for _, binding := range status.Bindings {
		key := systemBufferBindingKey{
			WorkerID: binding.WorkerID,
			QueueID:  binding.QueueID,
			Ifindex:  binding.Ifindex,
		}
		if _, ok := seen[key]; ok {
			continue
		}
		samples = append(samples, systemBufferSample{
			Slot:                        binding.Slot,
			HasSlot:                     true,
			WorkerID:                    binding.WorkerID,
			QueueID:                     binding.QueueID,
			Ifindex:                     binding.Ifindex,
			Interface:                   binding.Interface,
			UMEMCap:                     binding.UmemTotalFrames,
			UMEMUsed:                    binding.UmemInflightFrames,
			TXRingCap:                   binding.TxRingCapacity,
			TXRingUsed:                  binding.OutstandingTX,
			ActiveFlowCount:             binding.ActiveFlowCount,
			FlowCacheCapacity:           binding.FlowCacheCapacity,
			FlowCacheCollisionEvictions: binding.FlowCacheCollisionEvictions,
			DebugPendingFillFrames:      binding.DebugPendingFillFrames,
			DebugSpareFillFrames:        binding.DebugSpareFillFrames,
			DebugPendingTXPrepared:      binding.DebugPendingTXPrepared,
			DebugPendingTXLocal:         binding.DebugPendingTXLocal,
			DbgTxRingFull:               binding.DbgTxRingFull,
			DbgSendtoENOBUFS:            binding.DbgSendtoENOBUFS,
			DbgBoundPendingOverflow:     binding.DbgBoundPendingOverflow,
			DbgCoSQueueOverflow:         binding.DbgCoSQueueOverflow,
			RxFillRingEmptyDescs:        binding.RxFillRingEmptyDescs,
			RedirectInboxOverflowDrops:  binding.RedirectInboxOverflowDrops,
			PendingTXLocalOverflowDrops: binding.PendingTXLocalOverflowDrops,
			TxSubmitErrorDrops:          binding.TxSubmitErrorDrops,
			SYNCookieChallenges:         binding.SYNCookieChallenges,
			SYNCookieSecretUnavailable:  binding.SYNCookieSecretUnavailable,
			SYNCookieSynAckSent:         binding.SYNCookieSynAckSent,
			SYNCookieAckRstSent:         binding.SYNCookieAckRstSent,
			SYNCookieReplyBudgetDrops:   binding.SYNCookieReplyBudgetDrops,
			SYNCookieAckValid:           binding.SYNCookieAckValid,
			SYNCookieAckInvalid:         binding.SYNCookieAckInvalid,
			SYNCookieBypass:             binding.SYNCookieBypass,
		})
	}
	sort.Slice(samples, func(i, j int) bool {
		a, b := samples[i], samples[j]
		if a.WorkerID != b.WorkerID {
			return a.WorkerID < b.WorkerID
		}
		if a.QueueID != b.QueueID {
			return a.QueueID < b.QueueID
		}
		if a.Ifindex != b.Ifindex {
			return a.Ifindex < b.Ifindex
		}
		if a.HasSlot != b.HasSlot {
			return a.HasSlot
		}
		return a.Slot < b.Slot
	})
	return samples
}

func (sample *systemBufferSample) applyBindingStatusFallback(binding BindingStatus) {
	if sample.ActiveFlowCount == 0 {
		sample.ActiveFlowCount = binding.ActiveFlowCount
	}
	if sample.FlowCacheCapacity == 0 {
		sample.FlowCacheCapacity = binding.FlowCacheCapacity
	}
	if sample.FlowCacheCollisionEvictions == 0 {
		sample.FlowCacheCollisionEvictions = binding.FlowCacheCollisionEvictions
	}
	if sample.DebugPendingFillFrames == 0 {
		sample.DebugPendingFillFrames = binding.DebugPendingFillFrames
	}
	if sample.DebugSpareFillFrames == 0 {
		sample.DebugSpareFillFrames = binding.DebugSpareFillFrames
	}
	if sample.DebugPendingTXPrepared == 0 {
		sample.DebugPendingTXPrepared = binding.DebugPendingTXPrepared
	}
	if sample.DebugPendingTXLocal == 0 {
		sample.DebugPendingTXLocal = binding.DebugPendingTXLocal
	}
	if sample.DbgTxRingFull == 0 {
		sample.DbgTxRingFull = binding.DbgTxRingFull
	}
	if sample.DbgSendtoENOBUFS == 0 {
		sample.DbgSendtoENOBUFS = binding.DbgSendtoENOBUFS
	}
	if sample.DbgBoundPendingOverflow == 0 {
		sample.DbgBoundPendingOverflow = binding.DbgBoundPendingOverflow
	}
	if sample.DbgCoSQueueOverflow == 0 {
		sample.DbgCoSQueueOverflow = binding.DbgCoSQueueOverflow
	}
	if sample.RxFillRingEmptyDescs == 0 {
		sample.RxFillRingEmptyDescs = binding.RxFillRingEmptyDescs
	}
	if sample.RedirectInboxOverflowDrops == 0 {
		sample.RedirectInboxOverflowDrops = binding.RedirectInboxOverflowDrops
	}
	if sample.PendingTXLocalOverflowDrops == 0 {
		sample.PendingTXLocalOverflowDrops = binding.PendingTXLocalOverflowDrops
	}
	if sample.TxSubmitErrorDrops == 0 {
		sample.TxSubmitErrorDrops = binding.TxSubmitErrorDrops
	}
	if sample.SYNCookieChallenges == 0 {
		sample.SYNCookieChallenges = binding.SYNCookieChallenges
	}
	if sample.SYNCookieSecretUnavailable == 0 {
		sample.SYNCookieSecretUnavailable = binding.SYNCookieSecretUnavailable
	}
	if sample.SYNCookieSynAckSent == 0 {
		sample.SYNCookieSynAckSent = binding.SYNCookieSynAckSent
	}
	if sample.SYNCookieAckRstSent == 0 {
		sample.SYNCookieAckRstSent = binding.SYNCookieAckRstSent
	}
	if sample.SYNCookieReplyBudgetDrops == 0 {
		sample.SYNCookieReplyBudgetDrops = binding.SYNCookieReplyBudgetDrops
	}
	if sample.SYNCookieAckValid == 0 {
		sample.SYNCookieAckValid = binding.SYNCookieAckValid
	}
	if sample.SYNCookieAckInvalid == 0 {
		sample.SYNCookieAckInvalid = binding.SYNCookieAckInvalid
	}
	if sample.SYNCookieBypass == 0 {
		sample.SYNCookieBypass = binding.SYNCookieBypass
	}
}

type systemBufferBindingKey struct {
	WorkerID uint32
	QueueID  uint32
	Ifindex  int
}

func systemBufferSampleScope(sample systemBufferSample) string {
	parts := []string{
		fmt.Sprintf("worker %d", sample.WorkerID),
		fmt.Sprintf("queue %d", sample.QueueID),
	}
	if sample.HasSlot {
		parts = append(parts, fmt.Sprintf("slot %d", sample.Slot))
	}
	if sample.Interface != "" {
		parts = append(parts, sample.Interface)
	} else if sample.Ifindex != 0 {
		parts = append(parts, fmt.Sprintf("ifindex %d", sample.Ifindex))
	}
	return strings.Join(parts, "/")
}

func systemBufferCoSQueueScope(iface CoSInterfaceStatus, queue CoSQueueStatus) string {
	var parts []string
	if iface.InterfaceName != "" {
		parts = append(parts, iface.InterfaceName)
	} else if iface.Ifindex != 0 {
		parts = append(parts, fmt.Sprintf("ifindex %d", iface.Ifindex))
	}
	parts = append(parts, fmt.Sprintf("queue %d", queue.QueueID))
	if queue.ForwardingClass != "" {
		parts = append(parts, queue.ForwardingClass)
	}
	if queue.OwnerWorkerID != nil {
		parts = append(parts, fmt.Sprintf("worker %d", *queue.OwnerWorkerID))
	}
	return strings.Join(parts, "/")
}
