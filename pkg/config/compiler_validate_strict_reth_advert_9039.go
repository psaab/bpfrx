package config

import "fmt"

// #9039: bound `chassis cluster reth-advertise-interval` at the compiled-Config
// layer, the way #8483 bounds its seconds-valued sibling.
//
// THE ASYMMETRY THIS CLOSES. `vrrp-group <id> advertise-interval` (seconds) is
// gated by validateVRRPGroupTimersStrict. `chassis cluster
// reth-advertise-interval` (milliseconds) reaches the same 12-bit wire field by
// the same route and had no compiled-Config gate at all: admission is a bare
// `strconv.Atoi` in compiler_system.go and the only bound is the schema's
// ValidateInteger(10, 40959).
//
// A SCHEMA BOUND IS NOT THIS BOUND, and duration_bound_8642.go already says why
// in its own words: `Store.compileTreeLenient` downgrades a typed-leaf
// violation to a warning on the tolerant `Store.Load` / `Store.SyncApply`
// ingress — configs the operator did not just author. So the schema stops a
// commit and does not stop a config arriving from disk or from an HA peer.
// **The bound has to be at the conversion.**
//
// WHAT GOES WRONG WITHOUT IT. pkg/vrrp keeps the value for its LOCAL timer via
// MillisToDuration (bounded at ~9.2e12 ms, so 700000 really does advertise
// every 700 s) and narrows it for the WIRE with `uint16(advertMS/10)` under an
// 0x0FFF mask:
//
//	700000 ms -> 70000 cs -> uint16(70000) = 4464 -> & 0x0FFF = 368 cs = 3.68 s
//
// The instance advertises every 700 s while telling the peer to expect one
// every 3.68 s. The invariant is asserted two call sites earlier, on
// advertiseIntervalMS: "The wire field must carry what the peer will use to
// derive ITS master-down interval" — and then the value is narrowed into a
// cadence the instance is not sending at.
//
// WHY THE SEVERITY IS Low-to-Medium AND NOT High, stated so nobody re-derives
// it: the receiver has a floor. masterAdverFloor() is max(the RECEIVER's own
// configured interval, minLearnedMasterAdverInterval) (#4548), and 12-bit
// aliasing can only ever produce a value BELOW the configured one — the wire
// maximum is 4095 cs and aliasing needs >= 4096 cs. So on a config-synced pair,
// where both nodes hold the same interval, the receiver clamps the bogus value
// straight back and the two agree. What survives is the MISMATCHED-interval
// case, which is explicitly supported: there the alias turns a genuinely slow
// master — which #4061 says a backup must adopt unchanged — into a false fast
// one, and the backup's clamp to its own shorter interval still times out a
// master that is legitimately silent for far longer.
const (
	// MinRethAdvertiseInterval mirrors the schema's floor.
	MinRethAdvertiseInterval = 10
	// MaxRethAdvertiseInterval is the largest millisecond value that survives
	// the 12-bit centisecond field: 4095 cs. It is NOT the schema's 40959 —
	// that ceiling is one millisecond short of 4096 cs and encodes as 4095 cs
	// only because integer division truncates, so values in 40950..40959 all
	// land on the same wire value. Rounding the bound down to the last exact
	// multiple keeps "what you configured" and "what the peer is told" equal,
	// which is the property the whole gate exists for.
	MaxRethAdvertiseInterval = 40950
)

// validateRethAdvertiseIntervalStrict rejects a reth-advertise-interval that
// cannot be represented on the VRRPv3 wire.
//
// Returns nil when no chassis cluster is configured or the knob is absent — a
// zero means "unset", and pkg/vrrp substitutes its own default for it.
func validateRethAdvertiseIntervalStrict(cfg *Config) error {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	ms := cfg.Chassis.Cluster.RethAdvertiseInterval
	if ms == 0 {
		return nil
	}
	if ms < MinRethAdvertiseInterval || ms > MaxRethAdvertiseInterval {
		return fmt.Errorf(
			"chassis cluster reth-advertise-interval %d ms is outside %d..%d: the "+
				"VRRPv3 Max Advert Int field is 12 bits of centiseconds, so this "+
				"value is narrowed on the wire (%d ms advertises as %d ms) while "+
				"the local timer keeps the full value — the peer then derives its "+
				"master-down window from a cadence this node is not sending at",
			ms, MinRethAdvertiseInterval, MaxRethAdvertiseInterval,
			ms, (int(uint16(ms/10)&0x0FFF))*10)
	}
	if ms%10 != 0 {
		return fmt.Errorf(
			"chassis cluster reth-advertise-interval %d ms is not a whole number of "+
				"centiseconds: the VRRPv3 wire field carries centiseconds, so this "+
				"advertises as %d ms and the peer's master-down window is derived "+
				"from that rather than from what was configured",
			ms, (ms/10)*10)
	}
	return nil
}
