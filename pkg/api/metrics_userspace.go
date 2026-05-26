package api

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #709 + #869: single Status() call per scrape, then dispatch to
// CoS owner profile + worker runtime collectors.  Both features need
// the same ProcessStatus; calling Status() twice per scrape is
// wasteful on the userspace-dp control socket.
func (c *xpfCollector) collectUserspaceStatus(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	provider, ok := dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return
	}
	status, err := provider.Status()
	if err != nil {
		return
	}
	c.emitCoSOwnerProfile(ch, status)
	c.emitCoSDrainPhaseTelemetry(ch, status)
	c.emitCoSEqualFlowEnforcement(ch, status)
	c.emitWorkerRuntime(ch, status)
	c.emitUserspaceDynamicBufferMetrics(ch, status)
	c.emitUserspaceEventStream(ch, status)
	c.emitBindingActiveFlowCount(ch, status)
	c.emitBindingTXCompletionTelemetry(ch, status)
	c.emitCoSActiveFlowCount(ch, status)
	c.emitThreeColorPolicerCounters(ch, status)
	c.emitUserspaceSourceNATPoolMetrics(ch, status)
	c.emitFairnessRSSGauges(ch, status)
	c.emitFairnessThroughputGauges(ch, status)
}

func (c *xpfCollector) emitThreeColorPolicerCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, p := range status.ThreeColorPolicerCounters {
		emitColor := func(color string, packets, bytes uint64) {
			ch <- prometheus.MustNewConstMetric(
				c.threeColorPolicerPacketsTotal,
				prometheus.CounterValue,
				float64(packets),
				p.Name,
				color,
			)
			ch <- prometheus.MustNewConstMetric(
				c.threeColorPolicerBytesTotal,
				prometheus.CounterValue,
				float64(bytes),
				p.Name,
				color,
			)
		}
		emitColor("green", p.GreenPackets, p.GreenBytes)
		emitColor("yellow", p.YellowPackets, p.YellowBytes)
		emitColor("red", p.RedPackets, p.RedBytes)
		ch <- prometheus.MustNewConstMetric(
			c.threeColorPolicerDropsTotal,
			prometheus.CounterValue,
			float64(p.DropPackets),
			p.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.threeColorPolicerDropBytes,
			prometheus.CounterValue,
			float64(p.DropBytes),
			p.Name,
		)
	}
}

func (c *xpfCollector) emitUserspaceSourceNATPoolMetrics(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, pool := range status.SourceNATPools {
		labels := []string{pool.PoolName, pool.RuleName}
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolLiveFlows,
			prometheus.GaugeValue,
			float64(pool.LiveFlows),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolUsedPorts,
			prometheus.GaugeValue,
			float64(pool.UsedPorts),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolPersistentLeases,
			prometheus.GaugeValue,
			float64(pool.PersistentLeases),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolAllocationsTotal,
			prometheus.CounterValue,
			float64(pool.AllocationsTotal),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolReusesTotal,
			prometheus.CounterValue,
			float64(pool.ReusesTotal),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolExhaustionsTotal,
			prometheus.CounterValue,
			float64(pool.ExhaustionTotal),
			labels...,
		)
	}
}

func (c *xpfCollector) emitUserspaceDynamicBufferMetrics(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	if status.MaxSessions > 0 {
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSessionTableEntries,
			prometheus.GaugeValue,
			float64(status.SessionTableEntries),
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSessionTableCapacity,
			prometheus.GaugeValue,
			float64(status.MaxSessions),
		)
	}

	var activeFlows, flowCapacity uint64
	for _, b := range status.Bindings {
		activeFlows += uint64(b.ActiveFlowCount)
		flowCapacity += uint64(b.FlowCacheCapacity)
		if b.FlowCacheCapacity == 0 {
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			c.bindingFlowCacheCapacity,
			prometheus.GaugeValue,
			float64(b.FlowCacheCapacity),
			strconv.FormatUint(uint64(b.Slot), 10),
			strconv.FormatUint(uint64(b.QueueID), 10),
			strconv.FormatUint(uint64(b.WorkerID), 10),
			b.Interface,
		)
	}
	if flowCapacity == 0 {
		flowCapacity = status.FlowCacheCapacity
	}
	if flowCapacity > 0 {
		ch <- prometheus.MustNewConstMetric(
			c.userspaceFlowCacheActiveFlows,
			prometheus.GaugeValue,
			float64(activeFlows),
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceFlowCacheCapacity,
			prometheus.GaugeValue,
			float64(flowCapacity),
		)
	}
}

// #1219: emit per-binding distinct active flow count for the fairness
// harness. Reads BindingStatus.ActiveFlowCount populated by the
// helper's ~65ms debug-state tick (see plan §3.2-3.3).
func (c *xpfCollector) emitBindingActiveFlowCount(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		ch <- prometheus.MustNewConstMetric(
			c.bindingActiveFlowCount,
			prometheus.GaugeValue,
			float64(b.ActiveFlowCount),
			strconv.FormatUint(uint64(b.Slot), 10),
			strconv.FormatUint(uint64(b.QueueID), 10),
			strconv.FormatUint(uint64(b.WorkerID), 10),
			b.Interface,
		)
	}
}

// #1241: emit per-binding AF_XDP TX completion service telemetry for
// flow-fairness qualification runs. `tx_completions_total` gives the
// per-queue completion rate via Prometheus `rate()`. The two gauges
// expose latest and peak completion-ring backlog observed by the owner
// worker before drain, without introducing a hot-path shared counter.
func (c *xpfCollector) emitBindingTXCompletionTelemetry(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		slot := strconv.FormatUint(uint64(b.Slot), 10)
		queueID := strconv.FormatUint(uint64(b.QueueID), 10)
		workerID := strconv.FormatUint(uint64(b.WorkerID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.bindingTXCompletions,
			prometheus.CounterValue,
			float64(b.TXCompletions),
			slot, queueID, workerID, b.Interface,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingTXCompletionRingAvailable,
			prometheus.GaugeValue,
			float64(b.TXCompletionRingAvailable),
			slot, queueID, workerID, b.Interface,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingTXCompletionRingAvailableMax,
			prometheus.GaugeValue,
			float64(b.TXCompletionRingAvailableMax),
			slot, queueID, workerID, b.Interface,
		)
	}
}

// #1248: emit class-specific active flow counts for each egress CoS
// `(ifindex, queue_id, worker_id)` tuple. This is intentionally a
// gauge snapshot from userspace-dp's debug cadence, not a line-rate
// packet counter.
func (c *xpfCollector) emitCoSActiveFlowCount(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, row := range status.CoSActiveFlowCounts {
		ch <- prometheus.MustNewConstMetric(
			c.cosActiveFlowCount,
			prometheus.GaugeValue,
			float64(row.ActiveFlowCount),
			strconv.Itoa(row.Ifindex),
			strconv.FormatUint(uint64(row.QueueID), 10),
			strconv.FormatUint(uint64(row.WorkerID), 10),
		)
	}
}

// #1247: expose production RSS/workload health gauges from the same
// per-CoS active-flow distribution used by the fairness harness. This
// remains a status-snapshot calculation; it does not feed scheduling and
// does not add packet-path shared state.
func (c *xpfCollector) emitFairnessRSSGauges(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	truncated := 0.0
	if status.CoSActiveFlowCountsTruncated {
		truncated = 1.0
	}
	ch <- prometheus.MustNewConstMetric(
		c.fairnessCoSCountsTruncated,
		prometheus.GaugeValue,
		truncated,
	)

	for _, row := range dpuserspace.CoSFairnessRSSSummaries(status) {
		ifindexLabel := strconv.Itoa(row.Ifindex)
		queueLabel := strconv.FormatUint(uint64(row.QueueID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessCstruct,
			prometheus.GaugeValue,
			row.Cstruct,
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessActiveWorkers,
			prometheus.GaugeValue,
			float64(row.ActiveWorkers),
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessActiveFlows,
			prometheus.GaugeValue,
			float64(row.ActiveFlows),
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessMaxWorkerFlowShare,
			prometheus.GaugeValue,
			row.MaxWorkerFlowShare,
			ifindexLabel,
			queueLabel,
		)
	}
	c.emitFairnessRSSExpectationGauges(ch, status, c.configuredFairnessRSSExpectations())
}

func (c *xpfCollector) configuredFairnessRSSExpectations() []dpuserspace.FairnessRSSExpectation {
	if c == nil || c.srv == nil || c.srv.store == nil {
		return nil
	}
	return dpuserspace.FairnessRSSExpectationsFromConfig(c.srv.store.ActiveConfig())
}

func (c *xpfCollector) emitFairnessRSSExpectationGauges(
	ch chan<- prometheus.Metric,
	status dpuserspace.ProcessStatus,
	expectations []dpuserspace.FairnessRSSExpectation,
) {
	for _, result := range dpuserspace.EvaluateFairnessRSSExpectations(status, expectations) {
		ifindexLabel := strconv.Itoa(result.Ifindex)
		queueLabel := strconv.FormatUint(uint64(result.QueueID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessRSSExpectation,
			prometheus.GaugeValue,
			1,
			ifindexLabel,
			queueLabel,
			result.ExpectationKind,
		)
		if result.HasExpectationValue {
			ch <- prometheus.MustNewConstMetric(
				c.fairnessRSSExpectationValue,
				prometheus.GaugeValue,
				result.ExpectationValue,
				ifindexLabel,
				queueLabel,
				result.ExpectationKind,
			)
		}
		violation := 1.0
		if result.Pass {
			violation = 0
		}
		ch <- prometheus.MustNewConstMetric(
			c.fairnessRSSSkewViolation,
			prometheus.GaugeValue,
			violation,
			ifindexLabel,
			queueLabel,
			result.ExpectationKind,
		)
	}
}

func (c *xpfCollector) emitFairnessThroughputGauges(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	c.mu.Lock()
	if c.fairnessThroughputWindow == nil {
		c.fairnessThroughputWindow = dpuserspace.NewFairnessThroughputWindow(30 * time.Second)
	}
	summaries := c.fairnessThroughputWindow.Update(time.Now(), status)
	c.mu.Unlock()

	for _, row := range summaries {
		if row.SourceTruncated || row.FlowCount == 0 || row.WindowSeconds <= 0 {
			continue
		}
		ifindexLabel := strconv.Itoa(row.Ifindex)
		queueLabel := strconv.FormatUint(uint64(row.QueueID), 10)
		saturated := 0.0
		if row.Saturated {
			saturated = 1
		}
		ch <- prometheus.MustNewConstMetric(
			c.fairnessSaturated,
			prometheus.GaugeValue,
			saturated,
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessObservedCoV,
			prometheus.GaugeValue,
			row.ObservedCoV,
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessStarvedFlows,
			prometheus.CounterValue,
			float64(row.StarvedFlowsTotal),
			ifindexLabel,
			queueLabel,
		)
		c.emitFairnessEqualFlowEstimateGauges(ch, row, ifindexLabel, queueLabel)
	}
}

func (c *xpfCollector) emitFairnessEqualFlowEstimateGauges(
	ch chan<- prometheus.Metric,
	row dpuserspace.FairnessThroughputSummary,
	ifindexLabel string,
	queueLabel string,
) {
	estimate := row.EqualFlowEstimate
	if estimate.ActiveWorkers == 0 {
		return
	}
	valid := 0.0
	if estimate.Valid {
		valid = 1
	}
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowEstimateValid,
		prometheus.GaugeValue,
		valid,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowSampledActiveWorkers,
		prometheus.GaugeValue,
		float64(estimate.SampledActiveWorkers),
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowUnsampledActiveWorkers,
		prometheus.GaugeValue,
		float64(estimate.UnsampledActiveWorkers),
		ifindexLabel,
		queueLabel,
	)
	if !estimate.Valid {
		return
	}
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowTargetPerFlowBPS,
		prometheus.GaugeValue,
		estimate.TargetPerFlowBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowObservedBPS,
		prometheus.GaugeValue,
		estimate.ObservedBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowCappedBPS,
		prometheus.GaugeValue,
		estimate.CappedBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowSuppressedBPS,
		prometheus.GaugeValue,
		estimate.SuppressedBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowThroughputLossRatio,
		prometheus.GaugeValue,
		estimate.ThroughputLossRatio,
		ifindexLabel,
		queueLabel,
	)
	for _, worker := range estimate.Workers {
		workerLabel := strconv.FormatUint(uint64(worker.WorkerID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerObservedBPS,
			prometheus.GaugeValue,
			worker.ObservedBPS,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerObservedPerFlowBPS,
			prometheus.GaugeValue,
			worker.ObservedPerFlow,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerCapBPS,
			prometheus.GaugeValue,
			worker.CapBPS,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerSuppressedBPS,
			prometheus.GaugeValue,
			worker.SuppressedBPS,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
	}
}

// #869: emit per-worker busy/idle runtime counters from a cached
// ProcessStatus snapshot.
func (c *xpfCollector) emitWorkerRuntime(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, w := range status.WorkerRuntime {
		label := strconv.FormatUint(uint64(w.WorkerID), 10)
		toSecs := func(ns uint64) float64 { return float64(ns) / 1e9 }
		ch <- prometheus.MustNewConstMetric(c.workerWallSecs,
			prometheus.CounterValue, toSecs(w.WallNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerActiveSecs,
			prometheus.CounterValue, toSecs(w.ActiveNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerIdleSpinSecs,
			prometheus.CounterValue, toSecs(w.IdleSpinNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerIdleBlockSecs,
			prometheus.CounterValue, toSecs(w.IdleBlockNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerThreadCPUSecs,
			prometheus.CounterValue, toSecs(w.ThreadCPUNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerThreadCPUSecsLast60s,
			prometheus.GaugeValue, toSecs(w.ThreadCPUNS60s), label)
		ch <- prometheus.MustNewConstMetric(c.workerThreadCPUWindowSecs,
			prometheus.GaugeValue, toSecs(w.WindowNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerWorkLoops,
			prometheus.CounterValue, float64(w.WorkLoops), label)
		ch <- prometheus.MustNewConstMetric(c.workerIdleLoops,
			prometheus.CounterValue, float64(w.IdleLoops), label)
		ch <- prometheus.MustNewConstMetric(c.workerCoSQueueLeaseAcquireV8Calls,
			prometheus.CounterValue, float64(w.CoSQueueLeaseAcquireV8Calls), label)
		ch <- prometheus.MustNewConstMetric(c.workerCoSQueueLeaseAcquireV8GrantedBytes,
			prometheus.CounterValue, float64(w.CoSQueueLeaseAcquireV8GrantedBytes), label)
		ch <- prometheus.MustNewConstMetric(c.workerSessionTableEntries,
			prometheus.GaugeValue, float64(w.SessionTableEntries), label)
		ch <- prometheus.MustNewConstMetric(c.workerSessionTableCapacity,
			prometheus.GaugeValue, float64(w.MaxSessions), label)
		var deadValue float64
		if w.Dead {
			deadValue = 1
		}
		ch <- prometheus.MustNewConstMetric(c.workerDead,
			prometheus.GaugeValue, deadValue, label)
	}
}

func (c *xpfCollector) emitUserspaceEventStream(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	if status.EventStream == nil {
		return
	}
	es := status.EventStream
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamFramesTotal,
		prometheus.CounterValue, float64(es.FramesRead), "read")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamFramesTotal,
		prometheus.CounterValue, float64(es.FramesWritten), "written")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamSent), "sent")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamDropped), "dropped")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamDecodeErrorsTotal,
		prometheus.CounterValue, float64(es.DecodeErrors))
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamSequenceGapsTotal,
		prometheus.CounterValue, float64(es.SeqGaps))

	for _, item := range []struct {
		label string
		count uint64
	}{
		{"policy_deny", es.PolicyDenyEvents},
		{"screen_drop", es.ScreenDropEvents},
		{"filter_log", es.FilterLogEvents},
	} {
		ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamDataplaneEventsTotal,
			prometheus.CounterValue, float64(item.count), item.label)
	}
	for _, item := range []struct {
		label string
		count uint64
	}{
		{"policy_deny", es.PolicyDenyDrops},
		{"screen_drop", es.ScreenDropDrops},
		{"filter_log", es.FilterLogDrops},
	} {
		ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamDataplaneDropsTotal,
			prometheus.CounterValue, float64(item.count), item.label)
	}
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamUnknownDropsTotal,
		prometheus.CounterValue, float64(es.UnknownFrameDrops))
}

// #709: export owner-profile telemetry when the dataplane is the
// userspace-dp helper. The eBPF-only build path doesn't have this
// shape (it has no CoS scheduler), so we type-assert on the optional
// `Status() (dpuserspace.ProcessStatus, error)` interface — if the
// assertion fails we skip silently (not an error).
func (c *xpfCollector) emitCoSOwnerProfile(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, iface := range status.CoSInterfaces {
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for _, queue := range iface.Queues {
			// Only exact queues with a named owner worker have
			// meaningful owner-profile telemetry. See cosfmt.go for
			// the same gating on the CLI side.
			if queue.OwnerWorkerID == nil {
				continue
			}
			queueLabel := strconv.Itoa(queue.QueueID)
			emitHistogram(ch, c.cosDrainLatencyBucket,
				queue.DrainLatencyHist, ifindexLabel, queueLabel)
			emitHistogram(ch, c.cosRedirectAcquireBucket,
				queue.RedirectAcquireHist, ifindexLabel, queueLabel)
			ch <- prometheus.MustNewConstMetric(c.cosDrainInvocationsTotal,
				prometheus.CounterValue, float64(queue.DrainInvocations),
				ifindexLabel, queueLabel)
			ch <- prometheus.MustNewConstMetric(c.cosOwnerPPS,
				prometheus.GaugeValue, float64(queue.OwnerPPS),
				ifindexLabel, queueLabel)
			ch <- prometheus.MustNewConstMetric(c.cosPeerPPS,
				prometheus.GaugeValue, float64(queue.PeerPPS),
				ifindexLabel, queueLabel)
		}
	}
}

// #1369: queue-scoped drain-phase bytes for exact-vs-best-effort
// contention diagnosis. These counters are intentionally not gated on
// OwnerWorkerID: non-exact queues are the critical source for
// `*_while_exact_backlogged`, and shared-exact queues still produce a
// truthful guarantee/surplus phase split.
func (c *xpfCollector) emitCoSDrainPhaseTelemetry(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, iface := range status.CoSInterfaces {
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for _, queue := range iface.Queues {
			queueLabel := strconv.Itoa(queue.QueueID)
			ch <- prometheus.MustNewConstMetric(
				c.cosDrainGuaranteeSentBytes,
				prometheus.CounterValue,
				float64(queue.DrainGuaranteeSentBytes),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosDrainSurplusSentBytes,
				prometheus.CounterValue,
				float64(queue.DrainSurplusSentBytes),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosDrainNonExactSentBytesWhileExactBacklogged,
				prometheus.CounterValue,
				float64(queue.DrainNonExactSentBytesWhileExactBacklogged),
				ifindexLabel, queueLabel,
			)
		}
	}
}

func (c *xpfCollector) emitCoSEqualFlowEnforcement(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, iface := range status.CoSInterfaces {
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for _, queue := range iface.Queues {
			if !queue.EqualFlowEnforcement {
				continue
			}
			queueLabel := strconv.Itoa(queue.QueueID)
			enforced := 0.0
			if queue.EqualFlowEnforced {
				enforced = 1.0
			}
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowEnforcementEnabled,
				prometheus.GaugeValue,
				1,
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowEnforced,
				prometheus.GaugeValue,
				enforced,
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowTargetPerFlowBPS,
				prometheus.GaugeValue,
				float64(queue.EqualFlowTargetPerFlowBPS),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowMaxWorkerCapBytes,
				prometheus.GaugeValue,
				float64(queue.EqualFlowMaxWorkerCapBytes),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowCapHitEvents,
				prometheus.CounterValue,
				float64(queue.EqualFlowCapHitEvents),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowSuppressedGrantBytes,
				prometheus.CounterValue,
				float64(queue.EqualFlowSuppressedGrantBytes),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowStaleOrTagMismatchEvents,
				prometheus.CounterValue,
				float64(queue.EqualFlowStaleOrTagMismatchEvents),
				ifindexLabel, queueLabel,
			)
			reason := queue.EqualFlowFailOpenReason
			if reason == "" {
				reason = "none"
			}
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowFailOpen,
				prometheus.GaugeValue,
				1,
				ifindexLabel, queueLabel, reason,
			)
		}
	}
}
