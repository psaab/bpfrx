package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initBindingDescriptors() {
	c.bindingActiveFlowCount = prometheus.NewDesc(
		"xpf_userspace_binding_active_flow_count",
		"Distinct active flows observed in this binding's flow_cache "+
			"in the last ~650ms (10 epoch ticks × ~65ms debug-state tick; "+
			"snapshot refreshed on each tick). Read by the fairness harness to "+
			"compute the structural CoV ceiling per docs/fairness-regimes.md (#1219).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingFlowCacheCapacity = prometheus.NewDesc(
		"xpf_userspace_binding_flow_cache_capacity",
		"Flow-cache capacity published by the userspace helper for this binding.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingTXCompletions = prometheus.NewDesc(
		"xpf_userspace_binding_tx_completions_total",
		"Cumulative AF_XDP TX completions reaped by this binding's owner worker (#1241).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingTXCompletionRingAvailable = prometheus.NewDesc(
		"xpf_userspace_binding_tx_completion_ring_available",
		"Last sampled AF_XDP TX completion-ring descriptors available before the owner worker drained completions (#1241).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingTXCompletionRingAvailableMax = prometheus.NewDesc(
		"xpf_userspace_binding_tx_completion_ring_available_max",
		"Maximum sampled AF_XDP TX completion-ring descriptors available in the last debug window (#1241).",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	// #1831 (follow-up to #1766): per-binding V_min fairness-throttle
	// counters (#941 work item D / #943), already carried in
	// BindingStatus on the wire but previously unexported.
	c.bindingVMinThrottles = prometheus.NewDesc(
		"xpf_userspace_binding_v_min_throttles_total",
		"V_min fairness-brake throttle decisions on this binding's "+
			"shared-exact CoS queues: a drain batch early-broke because the "+
			"queue's virtual time ran more than LAG_THRESHOLD ahead of the "+
			"slowest participating peer worker's V_min (#917/#943). Non-zero "+
			"under load confirms the cross-worker brake is engaged; the "+
			"hard-cap-overrides / throttles ratio is the diagnostic for "+
			"LAG_THRESHOLD tuned too tight.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
	c.bindingVMinThrottleHardCapOverrides = prometheus.NewDesc(
		"xpf_userspace_binding_v_min_throttle_hard_cap_overrides_total",
		"V_MIN_CONSECUTIVE_SKIP_HARD_CAP escape-hatch activations on this "+
			"binding: after that many back-to-back V_min throttle decisions "+
			"the drain force-continues and arms suspension — 'brake too "+
			"tight, escape hatch rescued throughput' (#941 work item D). "+
			"Counted distinctly from (not a subset of) "+
			"xpf_userspace_binding_v_min_throttles_total.",
		[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
	)
}
