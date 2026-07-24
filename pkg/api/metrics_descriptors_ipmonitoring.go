package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initIPMonitoringDescriptors() {
	c.ipmonPolicyFailed = prometheus.NewDesc(
		"xpf_ipmon_policy_failed",
		"1 while the services ip-monitoring policy is in FAIL state "+
			"(preferred routes injected); 0 while passing (#1827).",
		[]string{"policy"}, nil,
	)
	c.ipmonPolicyTransitions = prometheus.NewDesc(
		"xpf_ipmon_policy_transitions_total",
		"Total FAIL/recover state transitions of the services "+
			"ip-monitoring policy (#1827). A steadily climbing value "+
			"indicates a flapping uplink; consider a non-zero hold-down.",
		[]string{"policy"}, nil,
	)
	c.ipmonRoutesApplied = prometheus.NewDesc(
		"xpf_ipmon_routes_applied",
		"Number of ip-monitoring preferred routes ACTUALLY applied — "+
			"the size of the last CONVERGED actuation's overlay that is "+
			"live in both the kernel and userspace FIBs (#1827, #3761). "+
			"Diverges below xpf_ipmon_routes_desired while an actuation "+
			"is pending or the FRR/snapshot/FIB actuation keeps failing "+
			"(#3757): a persistent gap flags a failover that is desired "+
			"but not converged.",
		nil, nil,
	)
	c.ipmonRoutesDesired = prometheus.NewDesc(
		"xpf_ipmon_routes_desired",
		"Number of ip-monitoring preferred routes the engine WANTS "+
			"injected right now (winner-resolved overlay across FAILED "+
			"policies, #3761). Compare with xpf_ipmon_routes_applied: a "+
			"sustained desired>applied gap means the actuator has not "+
			"converged the failover routes.",
		nil, nil,
	)
	c.ipmonUnresolvedNextHops = prometheus.NewDesc(
		"xpf_ipmon_unresolved_next_hops",
		"Number of ip-monitoring interface-typed preferred routes of "+
			"FAILED policies currently skipped from the overlay "+
			"because the tracked interface unit has no DHCP-learned "+
			"gateway (#1844). Non-zero during a failover means the "+
			"backup uplink's lease is missing and the failover route "+
			"is NOT injected.",
		nil, nil,
	)
	c.ipmonActuationFailures = prometheus.NewDesc(
		"xpf_ipmon_actuation_failures_total",
		"Cumulative ip-monitoring route-overlay actuations that did "+
			"NOT converge — a hard FRR reload error, a snapshot-publish "+
			"failure, an unconfirmed FIB-generation bump (#3757), or a "+
			"bounded-timeout/shutdown abort (#3758, #4423). The engine "+
			"retries autonomously (throttle-paced), so a steadily "+
			"climbing value means ip-monitoring cannot commit its "+
			"overlay and failover protection is degraded — pair it with "+
			"a sustained xpf_ipmon_routes_desired > xpf_ipmon_routes_applied "+
			"gap.",
		nil, nil,
	)
}
