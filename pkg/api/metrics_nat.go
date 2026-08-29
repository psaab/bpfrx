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

	// #7000: this gauge is the DENOMINATOR of pool-utilisation alerts, so
	// reporting a figure for a pool the dataplane refused is a monitoring-visible
	// contract break — the alert reads capacity for something that can allocate
	// nothing. Capacity now comes from the compiler's verdict.
	overBudget := config.SourceNATAggregateOverBudgetPools(cfg)
	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		ports, _ := config.SourceNATPoolReportablePorts(pool, name, portLow, portHigh, overBudget)
		totalPorts := int(ports)
		ch <- prometheus.MustNewConstMetric(c.natPoolTotalPorts, prometheus.GaugeValue,
			float64(totalPorts), name)

		if id, ok := cr.PoolIDs[name]; ok {
			cnt, err := dp.ReadNATPortCounter(uint32(id))
			if err != nil {
				// #5046: a port-counter read failure must not silently emit a
				// healthy sample nor vanish without a trace. Omit the used-ports
				// sample (never a fake 0) AND bump the shared scrape-error
				// counter so monitoring can see the read failed — the same
				// #3345/#3462 contract the zone/policy/filter collectors honor.
				c.counterReadErrors.Add(1)
			} else {
				ch <- prometheus.MustNewConstMetric(c.natPoolUsedPorts, prometheus.GaugeValue,
					float64(cnt), name)
			}
		}

		if pool.Deterministic != nil {
			ch <- prometheus.MustNewConstMetric(c.natPoolDeterministicInfo, prometheus.GaugeValue,
				1.0, name,
				strconv.Itoa(pool.Deterministic.BlockSize),
				strconv.Itoa(deterministicSubscriberCapacity(pool, name, overBudget)))

			// #4752: deterministic-pool block utilization. The pool-wide
			// used-ports counter is meaningless for a deterministic pool
			// (ports are pre-partitioned into fixed per-subscriber blocks),
			// so expose the block-occupancy numerator/denominator instead:
			//   total     = pool block capacity (numAddrs * blocksPerIP)
			//   allocated = provisioned subscriber blocks (one per subscriber)
			// An operator divides allocated/total for utilization and alarms
			// as it approaches 1.0. allocated is clamped to total so the ratio
			// never exceeds 1.0 (the compiler already rejects an over-provisioned
			// IPv4 pool; the clamp is defensive and also covers the IPv6 case
			// where every block is provisioned).
			totalBlocks := deterministicPoolBlockCapacity(pool, name, overBudget)
			if totalBlocks > 0 {
				allocated := deterministicSubscriberCapacity(pool, name, overBudget)
				if allocated > totalBlocks {
					allocated = totalBlocks
				}
				ch <- prometheus.MustNewConstMetric(c.natPoolDetBlocksTotal, prometheus.GaugeValue,
					float64(totalBlocks), name)
				ch <- prometheus.MustNewConstMetric(c.natPoolDetBlocksAllocated, prometheus.GaugeValue,
					float64(allocated), name)
			}
		}
	}
}

// deterministicPoolBlockCapacity returns the total per-subscriber port-block
// capacity of a deterministic CGNAT pool: len(addresses) * blocksPerIP, where
// blocksPerIP = portRange / block-size. This mirrors the totalBlocks value the
// compiler validates against the provisioned subscriber count
// (compiler_nat.go) and the dataplane NATPoolConfig.BlocksPerIP field. Returns
// 0 when the pool is not a valid deterministic pool (nil, non-positive block
// size, or block size larger than the port range).
func deterministicPoolBlockCapacity(pool *config.NATPool, poolName string, overBudget map[string]bool) int {
	if pool == nil || pool.Deterministic == nil {
		return 0
	}
	// #7000: a refused pool installs no allocator, so it has no blocks — and a
	// prefix member expands, so the address count is not `len(pool.Addresses)`.
	addrs, unusable := config.SourceNATPoolReportableAddresses(pool, poolName, overBudget)
	if unusable != "" {
		return 0
	}
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
	portRange := portHigh - portLow + 1
	if portRange <= 0 || bs > portRange {
		return 0
	}
	return addrs * (portRange / bs)
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
func deterministicSubscriberCapacity(pool *config.NATPool, poolName string, overBudget map[string]bool) int {
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
	// IPv6 — 1<<(128-ones) overflows Go's shift width. Mirror the compiler,
	// which caps the IPv6 subscriber count by pool block capacity.
	return deterministicPoolBlockCapacity(pool, poolName, overBudget)
}
