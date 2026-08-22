package config

// NATPoolTotalPorts is the SINGLE source of truth for a source-NAT pool's
// translation capacity: the size of its port window times its address count.
//
// It exists because the formula had been written out five times — the gRPC
// GetNATPoolStats handler, the REST natPoolStatsHandler, the Prometheus NAT
// collector, and both CLI `show security nat source pool` renders — and had
// already diverged. Only REST carried the portHigh >= portLow guard (#6553);
// the other four computed (portHigh - portLow + 1) directly, so a reversed
// window yields a NEGATIVE count that then flows into the availability and
// utilisation arithmetic. On the gRPC path clampInt32 saturates that to
// MinInt32 and the pool renders a large negative total with utilisation stuck
// at "0.0%".
//
// Reachability of a reversed window is deliberately not claimed here.
// parseSourcePoolPortRange fails closed on a reversed `port` leaf and
// validateSourceNATPoolStrict hard-rejects at commit (#5457), so the strict
// path should not produce one; the tolerant load / peer-sync path is the
// residual, and this guard is cheap regardless. What IS certain is that four
// surfaces disagreeing about one formula is a defect on its own terms — the
// point of centralising is that the next reader cannot reintroduce the
// divergence.
//
// Returns int64: (portHigh - portLow + 1) * addrCount can exceed int32 for a
// large pool (a /16 over the default 64512-port window is ~4.2e9). Callers
// storing into an int32 field must saturate rather than cast.
func NATPoolTotalPorts(portLow, portHigh, addrCount int) int64 {
	if portHigh < portLow || addrCount <= 0 {
		return 0
	}
	return int64(portHigh-portLow+1) * int64(addrCount)
}
