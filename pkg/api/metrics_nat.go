package api

import (
	"net"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
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
			ch <- prometheus.MustNewConstMetric(c.natPoolDeterministicInfo, prometheus.GaugeValue,
				1.0, name,
				strconv.Itoa(pool.Deterministic.BlockSize),
				strconv.Itoa(deterministicSubscriberCapacity(pool)))
		}
	}
}

// deterministicSubscriberCapacity returns the value reported in the
// natPoolDeterministicInfo `host_count` label for a deterministic CGNAT pool.
//
// For an IPv4 subscriber CIDR the capacity is the number of host addresses,
// 1<<(32-ones). For IPv6 (bits==128) that shift is >=64, which is 0 in Go
// (#4692) — so, mirroring the compiler_nat.go deterministic-capacity gate
// (which caps the IPv6 subscriber count by pool capacity rather than by the
// host CIDR), report the pool's block/subscriber capacity: blocksPerIP =
// portRange/blockSize, totalBlocks = len(addresses)*blocksPerIP. Returns 0
// when the host CIDR is unparseable or the block size is non-positive.
func deterministicSubscriberCapacity(pool *config.NATPool) int {
	if pool == nil || pool.Deterministic == nil {
		return 0
	}
	_, n, err := net.ParseCIDR(pool.Deterministic.HostAddress)
	if err != nil {
		return 0
	}
	ones, bits := n.Mask.Size()
	if bits != 128 {
		// IPv4 subscriber CIDR — host-address count.
		return 1 << uint(bits-ones)
	}
	// IPv6 — 1<<(128-ones) overflows Go's shift width. Report pool capacity.
	bs := pool.Deterministic.BlockSize
	if bs <= 0 {
		return 0
	}
	portLow := pool.PortLow
	if portLow == 0 {
		portLow = 1024
	}
	portHigh := pool.PortHigh
	if portHigh == 0 {
		portHigh = 65535
	}
	blocksPerIP := (portHigh - portLow + 1) / bs
	return len(pool.Addresses) * blocksPerIP
}
