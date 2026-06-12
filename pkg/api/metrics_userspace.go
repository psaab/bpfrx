package api

import (
	"math"
	"strconv"
	"strings"
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
	c.emitCoSWaterfillTelemetry(ch, status)
	c.emitCoSLeaseClaimFlow(ch, status)
	c.emitCoSEqualFlowEnforcement(ch, status)
	c.emitCoSSojourn(ch, status)
	c.emitCoSFlowFairOccupancy(ch, status)
	c.emitWorkerRuntime(ch, status)
	c.emitUserspaceDynamicBufferMetrics(ch, status)
	c.emitUserspaceEventStream(ch, status)
	c.emitBindingActiveFlowCount(ch, status)
	c.emitBindingTXCompletionTelemetry(ch, status)
	c.emitBindingVMinThrottleCounters(ch, status)
	c.emitCoSActiveFlowCount(ch, status)
	c.emitThreeColorPolicerCounters(ch, status)
	c.emitUserspaceSourceNATPoolMetrics(ch, status)
	c.emitFairnessRSSGauges(ch, status)
	c.emitFairnessThroughputGauges(ch, status)
	c.emitNeighborWarmCounters(ch, status)
	c.emitNeighborColdStartCapture(ch, status)
	c.emitWireguardTelemetry(ch, status)
}

// emitWireguardTelemetry exposes the #1865 per-WG-tunnel telemetry
// rows. Every counter series is emitted unconditionally per configured
// tunnel — a 0 is a real "no drops" signal, not an absent series
// (matching the #1771 §2.6 convention) — EXCEPT the last-handshake
// gauge, which is absent until the first handshake completes (0 is the
// in-band "never" sentinel on the wire). The tunnel label is the
// tunnel NAME: stable across commits, unlike the positional
// tunnel_endpoint_id (#1873).
func (c *xpfCollector) emitWireguardTelemetry(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, t := range status.WgTunnels {
		counter := func(desc *prometheus.Desc, v uint64, labels ...string) {
			ch <- prometheus.MustNewConstMetric(
				desc, prometheus.CounterValue, float64(v), labels...)
		}
		// Completions by role: role=responder is the helper's
		// hs_responses_created (the single responder-completion
		// increment site — session installed at msg2 creation).
		counter(c.wgHandshakesCompletedTotal, t.HsCompletionsInitiator, t.Tunnel, "initiator")
		counter(c.wgHandshakesCompletedTotal, t.HsResponsesCreated, t.Tunnel, "responder")
		counter(c.wgHandshakeInitiationsCreatedTotal, t.HsInitiationsCreated, t.Tunnel)
		counter(c.wgHandshakeInitiationBuildFailuresTotal, t.HsInitiationBuildFailures, t.Tunnel)
		counter(c.wgHandshakeRequestsArmedTotal, t.HsRequestsArmed, t.Tunnel)

		for _, r := range []struct {
			reason string
			v      uint64
		}{
			{"mac1_mismatch", t.HsRxDropsMac1Mismatch},
			{"malformed", t.HsRxDropsMalformed},
			{"crypto", t.HsRxDropsCrypto},
			{"unknown_peer", t.HsRxDropsUnknownPeer},
			{"stale_response", t.HsRxDropsStaleResponse},
			{"index_exhausted", t.HsRxDropsIndexExhausted},
			{"cookie_unsupported", t.HsRxCookieUnsupported},
			{"unknown_type", t.RxUnknownType},
		} {
			counter(c.wgHandshakeRxDropsTotal, r.v, t.Tunnel, r.reason)
		}

		counter(c.wgTransportPacketsTotal, t.EncapPackets, t.Tunnel, "encap")
		counter(c.wgTransportPacketsTotal, t.DecapPackets, t.Tunnel, "decap")
		counter(c.wgTransportBytesTotal, t.EncapBytes, t.Tunnel, "encap")
		counter(c.wgTransportBytesTotal, t.DecapBytes, t.Tunnel, "decap")
		counter(c.wgKeepalivesReceivedTotal, t.DecapKeepalives, t.Tunnel)

		for _, r := range []struct {
			reason string
			v      uint64
		}{
			{"malformed_header", t.DecapDropsMalformedHeader},
			{"unknown_session", t.DecapDropsUnknownSession},
			{"counter_ceiling", t.DecapDropsCounterCeiling},
			{"crypto", t.DecapDropsCrypto},
			{"replay", t.DecapDropsReplay},
			{"allowed_ips", t.DecapDropsAllowedIPs},
			{"malformed_inner", t.DecapDropsMalformedInner},
			{"buffer", t.DecapDropsBuffer},
			{"expired", t.DecapDropsExpired},
		} {
			counter(c.wgTransportDropsTotal, r.v, t.Tunnel, "decap", r.reason)
		}
		for _, r := range []struct {
			reason string
			v      uint64
		}{
			{"no_session", t.EncapDropsNoSession},
			{"unconfirmed", t.EncapDropsUnconfirmed},
			{"rekey_required", t.EncapDropsRekeyRequired},
			{"mtu", t.EncapMtuDrops},
			{"other", t.EncapDropsOther},
			{"expired", t.EncapDropsExpired},
		} {
			counter(c.wgTransportDropsTotal, r.v, t.Tunnel, "encap", r.reason)
		}

		for _, k := range []struct {
			kind string
			v    uint64
		}{
			{"handshake", t.HsSendErrors},
			{"transport", t.TransportSendErrors},
			{"tun_write", t.TunWriteErrors},
			{"tun_rx_no_endpoint", t.TunRxDropsNoEndpoint},
		} {
			counter(c.wgSendErrorsTotal, k.v, t.Tunnel, k.kind)
		}

		// #1888 S5 timer telemetry.
		counter(c.wgRekeysInitiatedTotal, t.RekeysInitiatedAge, t.Tunnel, "age")
		counter(c.wgRekeysInitiatedTotal, t.RekeysInitiatedDeadPeer, t.Tunnel, "dead_peer")
		counter(c.wgRekeysInitiatedTotal, t.RekeysInitiatedKeepaliveNoSession, t.Tunnel, "keepalive_no_session")
		counter(c.wgKeepalivesSentTotal, t.KeepalivesTxPassive, t.Tunnel, "passive")
		counter(c.wgKeepalivesSentTotal, t.KeepalivesTxPersistent, t.Tunnel, "persistent")
		counter(c.wgSessionsExpiredTotal, t.SessionsExpired, t.Tunnel)
		counter(c.wgHandshakeAttemptsAbortedTotal, t.PendingAbortedAttemptWindow, t.Tunnel)

		confirmed := 0.0
		if t.SessionConfirmed {
			confirmed = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.wgSessionConfirmed, prometheus.GaugeValue, confirmed, t.Tunnel)
		if t.LastHandshakeUnixSecs > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.wgLastHandshakeTimeSeconds,
				prometheus.GaugeValue,
				float64(t.LastHandshakeUnixSecs),
				t.Tunnel,
			)
		}
	}
}

// emitNeighborColdStartCapture exposes the #1782 cold-start capture
// instrumentation: the per-worker-summed neg-neigh fast-fail counter
// (H1 amplifier), the pending_neigh key-already-pending duplicate-drop
// counter (H5 sibling drop), and a per-key presence gauge dumped from
// the helper's dynamic_neighbors mirror so the capture harness can grep
// the pre-connect t0' next-hop membership (the H2 absence fingerprint).
// All three are read straight off the single per-scrape ProcessStatus;
// no extra control-socket round trip.
func (c *xpfCollector) emitNeighborColdStartCapture(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	ch <- prometheus.MustNewConstMetric(
		c.negNeighFastFailTotal,
		prometheus.CounterValue,
		float64(status.NegNeighFastFailTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.pendingNeighDuplicateDropsTotal,
		prometheus.CounterValue,
		float64(status.PendingNeighDuplicateDropsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.pendingNeighDecapDropsTotal,
		prometheus.CounterValue,
		float64(status.PendingNeighDecapDropsTotal),
	)
	for _, key := range status.DynamicNeighborKeys {
		// Each key is rendered "ifindex ip" by the helper. Split on the
		// single space into the two gauge labels; skip a malformed entry
		// rather than emit a partial-label series.
		ifindex, ip, ok := strings.Cut(key, " ")
		if !ok || ifindex == "" || ip == "" {
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			c.dynamicNeighborPresent,
			prometheus.GaugeValue,
			1,
			ifindex,
			ip,
		)
	}
}

// emitNeighborWarmCounters exposes the #1636 proactive-neighbor-warm
// telemetry. These are the only operator-visible signal for the warmer
// in production builds (the per-key debug eprintln is gated on the
// debug-log feature). A non-zero `disconnected` series means the warmer
// worker died and proactive warming is off until daemon restart.
func (c *xpfCollector) emitNeighborWarmCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	ch <- prometheus.MustNewConstMetric(
		c.neighborWarmDropsTotal,
		prometheus.CounterValue,
		float64(status.NeighborWarmDropsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborWarmDisconnectedTotal,
		prometheus.CounterValue,
		float64(status.NeighborWarmDisconnectedTotal),
	)
	// #1769: on-demand neighbor-resolver telemetry.
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverQueueDepth,
		prometheus.GaugeValue,
		float64(status.NeighborResolverQueueDepth),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverEnqueueDropsTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverEnqueueDropsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverDisconnectedTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverDisconnectedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverGetAttemptsTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverGetAttemptsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverGetResolvedTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverGetResolvedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverProbeOnStaleTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverProbeOnStaleTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverGetFailuresTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverGetFailuresTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverEpochRejectsTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverEpochRejectsTotal),
	)
	// #1771 §2.6: backoff-retry GETs, the §2.5 ENOBUFS/re-dump
	// self-heal counters, and the pending/negative key gauges. All
	// emitted unconditionally so a 0 is a real signal (no ENOBUFS, no
	// parked packets) rather than an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.neighborResolverGetBackoffAttemptsTotal,
		prometheus.CounterValue,
		float64(status.NeighborResolverGetBackoffAttemptsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborNetlinkEnobufsTotal,
		prometheus.CounterValue,
		float64(status.NeighborNetlinkEnobufsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborNetlinkRedumpsTotal,
		prometheus.CounterValue,
		float64(status.NeighborNetlinkRedumpsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborNetlinkRedumpUpsertsTotal,
		prometheus.CounterValue,
		float64(status.NeighborNetlinkRedumpUpsertsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborPendingKeys,
		prometheus.GaugeValue,
		float64(status.NeighborPendingKeys),
	)
	ch <- prometheus.MustNewConstMetric(
		c.negNeighKeys,
		prometheus.GaugeValue,
		float64(status.NegNeighKeys),
	)
	// #1772: neighbor/ARP resolution LATENCY telemetry.
	c.emitNeighborLatencyHistograms(ch, status)
}

// neighLatencyBucketCount mirrors the Rust NEIGH_LATENCY_BUCKETS (16):
// 15 finite pow2-ns buckets + 1 +Inf saturate.
const neighLatencyBucketCount = 16

// neighLatencyBucketUpperSeconds returns the inclusive upper bound (in
// SECONDS, for the Prometheus `le` label) of finite bucket i, mirroring
// the Rust `neigh_latency_bucket_upper_ns`: bucket i upper bound is
// 2^(16+i) ns. The final bucket (15) is +Inf and is NOT emitted as an
// explicit `le` boundary — prometheus.MustNewConstHistogram appends the
// implicit +Inf bucket from the total count.
func neighLatencyBucketUpperSeconds(i int) float64 {
	return float64(uint64(1)<<(16+uint(i))) / 1e9
}

// neighLatencyCumulativeBuckets converts the dataplane's NON-cumulative
// per-bucket sample counts into the cumulative `le`→count map Prometheus
// histograms require. Defensive against a short/absent slice (a peer on
// an older protocol that does not send the buckets yields an empty map +
// the count/sum we do have).
func neighLatencyCumulativeBuckets(buckets []uint64) map[float64]uint64 {
	out := make(map[float64]uint64, neighLatencyBucketCount-1)
	var cum uint64
	// Only the 15 finite buckets get an explicit `le`; the 16th (+Inf)
	// is implicit in the histogram's total count.
	for i := 0; i < neighLatencyBucketCount-1; i++ {
		if i < len(buckets) {
			cum += buckets[i]
		}
		out[neighLatencyBucketUpperSeconds(i)] = cum
	}
	return out
}

// emitNeighborLatencyHistograms exposes the #1772 neighbor/ARP
// resolution LATENCY metrics: the pending-buffer dwell and resolver
// GETNEIGH RTT histograms, plus the pending timeout-drop counter and the
// pending queue-depth high-water gauge. The histograms localize where an
// intermittent slow new connection spends its time (pending dwell vs
// kernel GETNEIGH RTT).
func (c *xpfCollector) emitNeighborLatencyHistograms(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	ch <- prometheus.MustNewConstHistogram(
		c.neighborPendingDwellSeconds,
		status.NeighborPendingDwellCount,
		float64(status.NeighborPendingDwellSumNs)/1e9,
		neighLatencyCumulativeBuckets(status.NeighborPendingDwellBuckets),
	)
	ch <- prometheus.MustNewConstHistogram(
		c.neighborResolverGetRttSeconds,
		status.NeighborResolverGetRttCount,
		float64(status.NeighborResolverGetRttSumNs)/1e9,
		neighLatencyCumulativeBuckets(status.NeighborResolverGetRttBuckets),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborPendingTimeoutDropsTotal,
		prometheus.CounterValue,
		float64(status.NeighborPendingTimeoutDropsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.neighborPendingMaxDepth,
		prometheus.GaugeValue,
		float64(status.NeighborPendingMaxDepth),
	)
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

	// #1760: NAT reverse-key 1:N collision displacement counter. Emitted
	// unconditionally (cumulative CounterValue, not gated on a session-
	// table denominator) so a 0 is a real published "no collisions" signal
	// rather than an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceNatReverseKeyCollisions,
		prometheus.CounterValue,
		float64(status.NatReverseKeyCollisions),
	)

	// #1861: install-refusal trio. Emitted unconditionally (cumulative
	// CounterValue) so a 0 is a real "no refusals" signal rather than an
	// absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionCreateDrops,
		prometheus.CounterValue,
		float64(status.SessionCreateDrops),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionInstallAdmissionRefused,
		prometheus.CounterValue,
		float64(status.SessionInstallAdmissionRefused),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionInstallPartial,
		prometheus.CounterValue,
		float64(status.SessionInstallPartial),
	)

	// #1789: failed USERSPACE_SESSIONS BPF-map publishes. Also emitted
	// unconditionally so a 0 is a real "no publish failures" signal
	// rather than an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionPublishErrors,
		prometheus.CounterValue,
		float64(status.SessionPublishErrorsTotal),
	)

	// #1760 W3': shared-map NAT reverse-key displacement events. Emitted
	// unconditionally so a 0 is a real "no collisions" signal rather
	// than an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceNatReverseKeySharedDisplacements,
		prometheus.CounterValue,
		float64(status.NatReverseKeySharedDisplacementsTotal),
	)

	// #1807: worker-command-queue poison recoveries. Also emitted
	// unconditionally so a 0 is a real "no worker panics" signal rather
	// than an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceWorkerCommandQueuePoisonRecoveries,
		prometheus.CounterValue,
		float64(status.WorkerCommandQueuePoisonRecoveries),
	)

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

// #1831 (follow-up to #1766): emit the per-binding V_min
// fairness-throttle counters (#941 work item D / #943). Both have been
// on the BindingStatus wire since #941/#943 (flushed from per-queue
// scratch fields at the helper's ~65ms debug tick) but were never
// exported. Emitted unconditionally per binding so a 0 is a real
// "brake never fired" signal rather than an absent series.
func (c *xpfCollector) emitBindingVMinThrottleCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		slot := strconv.FormatUint(uint64(b.Slot), 10)
		queueID := strconv.FormatUint(uint64(b.QueueID), 10)
		workerID := strconv.FormatUint(uint64(b.WorkerID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.bindingVMinThrottles,
			prometheus.CounterValue,
			float64(b.VMinThrottles),
			slot, queueID, workerID, b.Interface,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingVMinThrottleHardCapOverrides,
			prometheus.CounterValue,
			float64(b.VMinThrottleHardCapOverrides),
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
		// #1782 Step-1 cold-start CoS instruments. The wheel counters are
		// emitted unconditionally (always-present series keep rate() and
		// absence-alerts honest); the max is a monotonic high-water mark,
		// hence a gauge. The under-grant family emits all six causes per
		// worker so a cause appearing for the first time has a zero
		// baseline sample to rate() against.
		ch <- prometheus.MustNewConstMetric(c.workerCoSWheelTicksAdvancedTotal,
			prometheus.CounterValue, float64(w.CoSWheelTicksAdvancedTotal), label)
		ch <- prometheus.MustNewConstMetric(c.workerCoSWheelTicksAdvancedMax,
			prometheus.GaugeValue, float64(w.CoSWheelTicksAdvancedMax), label)
		for _, uc := range []struct {
			cause string
			value uint64
		}{
			{"seqlock_give_up", w.CoSQueueLeaseUndergrantSeqlockGiveUp},
			{"cap_zero", w.CoSQueueLeaseUndergrantCapZero},
			{"epoch_rotated", w.CoSQueueLeaseUndergrantEpochRotated},
			{"share_exhausted", w.CoSQueueLeaseUndergrantShareExhausted},
			{"class_cap", w.CoSQueueLeaseUndergrantClassCap},
			{"outstanding_cap", w.CoSQueueLeaseUndergrantOutstandingCap},
		} {
			ch <- prometheus.MustNewConstMetric(c.workerCoSQueueLeaseUndergrant,
				prometheus.CounterValue, float64(uc.value), label, uc.cause)
		}
		ch <- prometheus.MustNewConstMetric(c.workerSessionTableEntries,
			prometheus.GaugeValue, float64(w.SessionTableEntries), label)
		ch <- prometheus.MustNewConstMetric(c.workerSessionTableCapacity,
			prometheus.GaugeValue, float64(w.MaxSessions), label)
		ch <- prometheus.MustNewConstMetric(c.workerNatReverseKeyCollisions,
			prometheus.CounterValue, float64(w.NatReverseKeyCollisions), label)
		// #1861: per-worker install-refusal trio.
		ch <- prometheus.MustNewConstMetric(c.workerSessionCreateDrops,
			prometheus.CounterValue, float64(w.SessionCreateDrops), label)
		ch <- prometheus.MustNewConstMetric(c.workerSessionInstallAdmissionRefused,
			prometheus.CounterValue, float64(w.SessionInstallAdmissionRefused), label)
		ch <- prometheus.MustNewConstMetric(c.workerSessionInstallPartial,
			prometheus.CounterValue, float64(w.SessionInstallPartial), label)
		var deadValue float64
		if w.Dead {
			deadValue = 1
		}
		ch <- prometheus.MustNewConstMetric(c.workerDead,
			prometheus.GaugeValue, deadValue, label)
		// #1621: cold-path histogram surface (#1612 step-3).
		c.emitWorkerColdPath(ch, label, w)
	}
}

// #1621: emit the cold-path histogram metric families for one worker.
//
// Per plan v2:
//   - bucket counter family with PromQL `le` label so
//     histogram_quantile() works natively (Codex r1 F3 + AGY r1 F6 +
//     Claude SMR F5).
//   - sum_ns + samples counters per (worker, slot).
//   - alias_seen gauge per (worker, slot).
//   - per-worker scalars: sample_phase + wrapper_underflow (counters);
//     wrapper_ns_baseline + ns_per_tsc_q32 (gauges).
//   - clock_source gauge always emitted (Claude SMR r1 F4) so
//     dashboards distinguish "tsc active" from "no data this scrape".
//   - snapshot_failed_total counter (AGY r1 F3 + Codex r1 F5) so
//     operators detect publish-contention starvation.
func (c *xpfCollector) emitWorkerColdPath(
	ch chan<- prometheus.Metric,
	label string,
	w dpuserspace.WorkerRuntimeStatus,
) {
	// #1635: branch on the wire layout version. 0 (or absent) = either
	// no data this scrape OR a pre-#1635 daemon emitting the v1 dense
	// fields; 3 = sparse log-linear per-zone-pair encoding; anything
	// else = forward-compat unknown.
	switch w.ColdPathLayoutVersion {
	case 0, 1:
		c.emitColdPathV1(ch, label, w)
	case 3:
		c.emitColdPathV3(ch, label, w)
		ch <- prometheus.MustNewConstMetric(c.workerColdPathLayoutVersion,
			prometheus.GaugeValue, 1.0, label, "3")
	default:
		ch <- prometheus.MustNewConstMetric(c.workerColdPathLayoutUnknownTotal,
			prometheus.GaugeValue, 1.0, label,
			strconv.FormatUint(uint64(w.ColdPathLayoutVersion), 10))
	}
	c.emitWorkerColdPathScalars(ch, label, w)
}

// emitColdPathV1 emits the legacy 24-bucket pow-2 per-slot metrics from
// the dense v1 fields. Reached only when paired with a pre-#1635 Rust
// daemon (current daemons leave the dense fields empty and emit v3).
func (c *xpfCollector) emitColdPathV1(
	ch chan<- prometheus.Metric,
	label string,
	w dpuserspace.WorkerRuntimeStatus,
) {
	// 24-bucket power-of-two histogram. Bucket 0 covers [0, 1024) ns;
	// bucket i ∈ [1, 22] covers [2^(9+i), 2^(10+i)) ns; bucket 23
	// saturates at any ns ≥ 2^32.
	bucketLe := func(idx int) string {
		if idx == 0 {
			return "1023"
		}
		if idx >= 23 || (10+idx) >= 64 {
			return "+Inf"
		}
		return strconv.FormatUint((uint64(1)<<uint(10+idx))-1, 10)
	}
	for slot := 0; slot < len(w.ColdPathHist); slot++ {
		slotLabel := strconv.Itoa(slot)
		var running uint64
		for b := 0; b < len(w.ColdPathHist[slot]); b++ {
			running += w.ColdPathHist[slot][b]
			ch <- prometheus.MustNewConstMetric(c.workerColdPathBucket,
				prometheus.CounterValue,
				float64(running),
				label, slotLabel, bucketLe(b))
		}
	}
	for slot, samples := range w.ColdPathSamples {
		slotLabel := strconv.Itoa(slot)
		ch <- prometheus.MustNewConstMetric(c.workerColdPathSamples,
			prometheus.CounterValue, float64(samples), label, slotLabel)
		if slot < len(w.ColdPathSumNS) {
			ch <- prometheus.MustNewConstMetric(c.workerColdPathSumNS,
				prometheus.CounterValue,
				float64(w.ColdPathSumNS[slot]),
				label, slotLabel)
		}
		if slot < len(w.ColdPathAliasSeen) {
			alias := 0.0
			if w.ColdPathAliasSeen[slot] {
				alias = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.workerColdPathAliasSeen,
				prometheus.GaugeValue, alias, label, slotLabel)
		}
	}
}

// emitColdPathV3 emits the #1635 sparse per-zone-pair metrics. The
// payload is parallel arrays (one entry per active zone-pair); the
// `from_zone` / `to_zone` labels carry the zone-ids so every active
// pair publishes a SEPARABLE latency distribution with no collision
// exclusion (fixes #1622 F2 + F3). `le` boundaries follow the
// 48-bucket log-linear layout (bucketLeV3).
func (c *xpfCollector) emitColdPathV3(
	ch chan<- prometheus.Metric,
	label string,
	w dpuserspace.WorkerRuntimeStatus,
) {
	n := len(w.ColdPathActiveSamples)
	for i := 0; i < n; i++ {
		fromZone := zoneIDLabel(w.ColdPathActiveZoneFrom, i)
		toZone := zoneIDLabel(w.ColdPathActiveZoneTo, i)
		// Cumulative bucket counts for histogram_quantile().
		if i < len(w.ColdPathActiveBuckets) {
			var running uint64
			buckets := w.ColdPathActiveBuckets[i]
			for b := 0; b < len(buckets); b++ {
				running += buckets[b]
				ch <- prometheus.MustNewConstMetric(c.workerColdPathBucketV3,
					prometheus.CounterValue, float64(running),
					label, fromZone, toZone, bucketLeV3(b))
			}
		}
		ch <- prometheus.MustNewConstMetric(c.workerColdPathSamplesV3,
			prometheus.CounterValue, float64(w.ColdPathActiveSamples[i]),
			label, fromZone, toZone)
		if i < len(w.ColdPathActiveSumNS) {
			ch <- prometheus.MustNewConstMetric(c.workerColdPathSumNSV3,
				prometheus.CounterValue, float64(w.ColdPathActiveSumNS[i]),
				label, fromZone, toZone)
		}
		if i < len(w.ColdPathActiveBuilderCollision) {
			col := 0.0
			if w.ColdPathActiveBuilderCollision[i] {
				col = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.workerColdPathBuilderCollisionV3,
				prometheus.GaugeValue, col, label, fromZone, toZone)
		}
	}
	overflow := 0.0
	if w.ColdPathOverflowActive {
		overflow = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.workerColdPathOverflowActive,
		prometheus.GaugeValue, overflow, label)
}

// emitWorkerColdPathScalars emits the per-worker scalar families shared
// across all layout versions.
func (c *xpfCollector) emitWorkerColdPathScalars(
	ch chan<- prometheus.Metric,
	label string,
	w dpuserspace.WorkerRuntimeStatus,
) {
	// Per-worker scalars.
	ch <- prometheus.MustNewConstMetric(c.workerColdPathSamplePhase,
		prometheus.CounterValue,
		float64(w.ColdPathSamplePhase), label)
	ch <- prometheus.MustNewConstMetric(c.workerColdPathWrapperUnderflow,
		prometheus.CounterValue,
		float64(w.ColdPathWrapperUnderflowCount), label)
	ch <- prometheus.MustNewConstMetric(c.workerColdPathWrapperNSBaseline,
		prometheus.GaugeValue,
		float64(w.ColdPathWrapperNSBaseline), label)
	ch <- prometheus.MustNewConstMetric(c.workerColdPathNSPerTSCQ32,
		prometheus.GaugeValue,
		float64(w.ColdPathNSPerTSCQ32), label)
	// clock_source gauge ALWAYS emitted (Claude SMR r1 F4): even
	// when the worker is uncalibrated (source == ""), so dashboards
	// can distinguish "tsc active" from "no data this scrape".
	src := w.ColdPathClockSource
	if src == "" {
		src = "unset"
	}
	ch <- prometheus.MustNewConstMetric(c.workerColdPathClockSource,
		prometheus.GaugeValue, 1.0, label, src)
	// snapshot_failed counter always emitted so operators can detect
	// transient publish-contention starvation.
	ch <- prometheus.MustNewConstMetric(c.workerColdPathSnapshotFailedTotal,
		prometheus.CounterValue,
		float64(w.ColdPathSnapshotFailed), label)
}

// bucketLeV3 returns the inclusive upper boundary (Prometheus `le`
// label) for #1635 48-bucket log-linear histogram bucket idx:
//   - idx < 32        → (idx+1)*16 - 1   (15, 31, …, 511) — linear band.
//   - 32 ≤ idx ≤ 46   → 2^(10+idx-32) - 1 (1023, 2047, …) — exp band.
//   - idx ≥ 47        → "+Inf"            — saturate band.
//
// Mirrors bucket_upper_bound_ns_48 / bucket_index_for_ns_48 on the Rust
// side; the two MUST agree or histogram_quantile() reads wrong values.
func bucketLeV3(idx int) string {
	const linear = 32
	if idx < linear {
		return strconv.FormatUint(uint64((idx+1)*16-1), 10)
	}
	if idx >= 47 {
		return "+Inf"
	}
	return strconv.FormatUint((uint64(1)<<uint(10+idx-linear))-1, 10)
}

// zoneIDLabel renders the i-th zone-id of a parallel sparse array as a
// label string, or "unknown" if the array is too short (defensive
// against a truncated/mismatched payload).
func zoneIDLabel(ids []uint32, i int) string {
	if i >= len(ids) {
		return "unknown"
	}
	return strconv.FormatUint(uint64(ids[i]), 10)
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

// #1628: per-class waterfill-selector trace counters. Per-queue
// admissions/visits plus per-interface epochs/breaks (counters) and the
// min-epochs-per-worker stalled-core flag (gauge). Diagnostic only —
// these never feed a scheduling decision; they exist to make the
// #1630-verified Phase-2 lock-in + queue-ownership fragmentation
// empirically visible. Zero on the Proportional (legacy RR) selector
// path. Not gated on OwnerWorkerID: a queue's row is owner-attributed
// already, and the per-interface MIN is computed coordinator-side.
func (c *xpfCollector) emitCoSWaterfillTelemetry(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, iface := range status.CoSInterfaces {
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		ch <- prometheus.MustNewConstMetric(
			c.cosWaterfillEpochs,
			prometheus.CounterValue,
			float64(iface.WaterfillEpochs),
			ifindexLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.cosWaterfillPhase1BudgetBreaks,
			prometheus.CounterValue,
			float64(iface.WaterfillPhase1BudgetBreaks),
			ifindexLabel,
		)
		// #1628 (code-review r2): u64::MAX is the "no active-backlog
		// lock-in candidate" sentinel — suppress the gauge entirely for
		// idle interfaces so the emitted series is alertable: an emitted
		// value of 0 then unambiguously means a hard 0-epoch lock-in (a
		// backlogged binding that completed zero epochs), not "idle".
		if iface.WaterfillMinEpochsPerWorker != math.MaxUint64 {
			ch <- prometheus.MustNewConstMetric(
				c.cosWaterfillMinEpochsPerWorker,
				prometheus.GaugeValue,
				float64(iface.WaterfillMinEpochsPerWorker),
				ifindexLabel,
			)
		}
		for _, queue := range iface.Queues {
			queueLabel := strconv.Itoa(queue.QueueID)
			ch <- prometheus.MustNewConstMetric(
				c.cosWaterfillPhase1Admissions,
				prometheus.CounterValue,
				float64(queue.WaterfillPhase1Admissions),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosWaterfillPhase2Admissions,
				prometheus.CounterValue,
				float64(queue.WaterfillPhase2Admissions),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosWaterfillEligibleVisits,
				prometheus.CounterValue,
				float64(queue.WaterfillEligibleVisits),
				ifindexLabel, queueLabel,
			)
		}
	}
}

// #1863 Step-0: per-(queue, worker) v8 lease claim-flow counters +
// per-queue admission-path counters. The claim-flow pair is emitted
// only for queues whose status row carries the per-worker vectors
// (v8 leases; legacy/non-v8 rows have empty slices), so cardinality is
// bounded by exact-queue count x worker count. Admission counters are
// emitted per queue row unconditionally (they already exist on the
// wire; this surfaces them to Prometheus for drop-site attribution).
func (c *xpfCollector) emitCoSLeaseClaimFlow(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, iface := range status.CoSInterfaces {
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for _, queue := range iface.Queues {
			queueLabel := strconv.Itoa(queue.QueueID)
			for workerID, requested := range queue.LeaseV8WorkerRequestedBytes {
				ch <- prometheus.MustNewConstMetric(
					c.cosLeaseV8RequestedBytes,
					prometheus.CounterValue,
					float64(requested),
					ifindexLabel, queueLabel, strconv.Itoa(workerID),
				)
			}
			for workerID, granted := range queue.LeaseV8WorkerGrantedBytes {
				ch <- prometheus.MustNewConstMetric(
					c.cosLeaseV8GrantedBytes,
					prometheus.CounterValue,
					float64(granted),
					ifindexLabel, queueLabel, strconv.Itoa(workerID),
				)
			}
			ch <- prometheus.MustNewConstMetric(
				c.cosAdmissionFlowShareDrops,
				prometheus.CounterValue,
				float64(queue.AdmissionFlowShareDrops),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosAdmissionBufferDrops,
				prometheus.CounterValue,
				float64(queue.AdmissionBufferDrops),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosAdmissionEcnMarked,
				prometheus.CounterValue,
				float64(queue.AdmissionEcnMarked),
				ifindexLabel, queueLabel,
			)
		}
	}
}

// #1829 Phase 1: dequeue-time sojourn gauges, emitted unconditionally
// for every queue row (cardinality = interfaces x queues): a windowed
// min of 0 is a real "no standing queue in the last ~2 windows"
// signal — gating on non-zero would make the gate evidence's
// strongest negative result (queues never stand) invisible. All three
// are MAX-merged across worker instances and workers upstream (worst
// instance); see the AGGREGATION contract on the Rust CoSQueueStatus.
func (c *xpfCollector) emitCoSSojourn(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, iface := range status.CoSInterfaces {
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for _, queue := range iface.Queues {
			queueLabel := strconv.Itoa(queue.QueueID)
			ch <- prometheus.MustNewConstMetric(
				c.cosSojournEwmaNS,
				prometheus.GaugeValue,
				float64(queue.SojournEwmaNS),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosSojournPeakNS,
				prometheus.GaugeValue,
				float64(queue.SojournPeakNS),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosSojournWindowedMinNS,
				prometheus.GaugeValue,
				float64(queue.SojournWindowedMinNS),
				ifindexLabel, queueLabel,
			)
		}
	}
}

// #1830 (g): bucket-vs-flow occupancy gauges for collision-vs-demand
// unfairness diagnosis. Emitted unconditionally for every queue row
// (cardinality = interfaces x queues): a 0 is a real "idle / no
// flow-fair backlog" signal, and gating on FlowFair would hide the
// buckets==0 vs flows>0 idle shape the ratio caveat documents.
// FlowFairFlowsActive equals the sum over workers of the existing
// per-worker xpf_userspace_cos_active_flow_count (#1248), pre-aggregated
// to exactly match the buckets gauge's (ifindex, queue_id) grain.
func (c *xpfCollector) emitCoSFlowFairOccupancy(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, iface := range status.CoSInterfaces {
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for _, queue := range iface.Queues {
			queueLabel := strconv.Itoa(queue.QueueID)
			ch <- prometheus.MustNewConstMetric(
				c.cosFlowFairBucketsOccupied,
				prometheus.GaugeValue,
				float64(queue.FlowFairBucketsOccupied),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosFlowFairFlowsActive,
				prometheus.GaugeValue,
				float64(queue.FlowFairFlowsActive),
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
			// #1746: sibling info metric naming the active target
			// policy. The Rust status overlay always populates the
			// label for equal-flow leases; guard anyway so a
			// mixed-version helper (older Rust, empty label) emits no
			// empty-label series.
			if queue.EqualFlowTargetPolicy != "" {
				ch <- prometheus.MustNewConstMetric(
					c.cosEqualFlowTargetPolicy,
					prometheus.GaugeValue,
					1,
					ifindexLabel, queueLabel, queue.EqualFlowTargetPolicy,
				)
			}
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
