package api

import (
	"net"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (c *xpfCollector) collectNATPoolMetrics(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	cr := dataplane.LastApplyResultOf(dp)
	if cr == nil {
		return
	}

	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		totalPorts := (portHigh - portLow + 1) * len(pool.Addresses)
		ch <- prometheus.MustNewConstMetric(c.natPoolTotalPorts, prometheus.GaugeValue,
			float64(totalPorts), name)

		if id, ok := cr.PoolIDs[name]; ok {
			cnt, err := dp.ReadNATPortCounter(uint32(id))
			if err == nil {
				ch <- prometheus.MustNewConstMetric(c.natPoolUsedPorts, prometheus.GaugeValue,
					float64(cnt), name)
			}
		}

		if pool.Deterministic != nil {
			hostCount := 0
			if _, n, err := net.ParseCIDR(pool.Deterministic.HostAddress); err == nil {
				ones, bits := n.Mask.Size()
				hostCount = 1 << uint(bits-ones)
			}
			ch <- prometheus.MustNewConstMetric(c.natPoolDeterministicInfo, prometheus.GaugeValue,
				1.0, name,
				strconv.Itoa(pool.Deterministic.BlockSize),
				strconv.Itoa(hostCount))
		}
	}
}
