package userspace

import (
	"math"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #8377: how many UDP probes the NAPI bootstrap sends per interface.
//
// THE DEFECT THIS REPLACES was a mismatch between two rules stated four lines
// apart. The comment said "~2x the queue count"; the code sent a hard-coded 30.
// Neither is right, and the disagreement is the dangerous part: a future editor
// implementing the PROSE rule would have cut the count from 30 to 12 on a
// 6-queue NIC and made coverage worse.
//
// QUEUE SELECTION IS BY RSS HASH, so this is a coupon-collector problem, not a
// linear one. Covering n queues needs about n*(ln n + ln(1/eps)) draws for a
// miss probability of eps, not 2n. With the fixed 30:
//
//	queues  E[uncovered]  P(all covered)
//	     6         0.025           0.975
//	     8         0.146           0.864
//	    16         2.308           0.099
//	    32        12.345           0.000
//
// 30 was generous at the 6 queues the loss cluster's mlx5 VFs expose, which is
// why the shortfall never showed. #8374 raised the per-interface binding count
// from the global minimum across all interfaces to min(rx, BindingQueuesPerIface),
// so 16-queue interfaces are now routinely bound and 30 probes cover them about
// a tenth of the time.
//
// WHY COVERAGE IS A CORRECTNESS PROPERTY HERE, not a nicety. An earlier draft
// of this comment argued the opposite — that per-socket wake paths make the
// probes a mere latency optimisation — and it was wrong. The tree's own history
// measured it: `ffe0b5520` recorded the fill-ring consumer stuck at 0 after a
// restart WITH the `poll(POLLIN)` wake already present, `e0c01ac2b` added
// SO_BUSY_POLL because "ndo_xsk_wakeup's ICOSQ NOP mechanism fails when NAPI is
// already scheduled from other sources", and that same commit observed the
// exact failure on hardware: "The ARP/NDP reply for the egress next-hop may
// hash to an XSK queue that hasn't been bootstrapped yet." An uncovered queue
// is a queue that may not forward. See bootstrapNAPIQueuesLocked.
//
// This function therefore fixes a coverage shortfall, not a cosmetic one — but
// it does NOT claim to make coverage certain. Coupon-collector coverage is
// probabilistic by construction; raising P(all covered) from ~0.10 to >0.99 at
// 16 queues is the whole of what it buys, and real RSS hashing is not perfectly
// uniform, so the true coverage is likely somewhat worse than the model.
const (
	// napiProbeFloor is the historical fixed count. It is the FLOOR rather
	// than the answer, so no interface small enough to be well covered today
	// sends fewer probes than it did before this change: the derived count
	// only ever goes up. A queue count of 0 — an interface whose
	// /sys/class/net/<if>/queues could not be read — also lands here, which
	// is byte-identical to the pre-#8377 behaviour for that case.
	napiProbeFloor = 30

	// napiProbeBasePort is the first UDP destination port. The port is the
	// only term of the mlx5 UDP RSS hash (src, dst, sport, dport) that varies
	// across probes, so it is what spreads them over queues; the count and the
	// port span are therefore the same number.
	napiProbeBasePort = 40000

	// napiProbeCoverageLn is ln(1/eps) for a target miss probability of 1%.
	// Expressed as the log of the reciprocal so the target is readable: 100
	// means "one interface in a hundred leaves a queue uncovered".
	napiProbeCoverageTargetReciprocal = 100
)

// napiProbeCount returns the probe count for an interface with rxQueues
// hardware RX queues.
//
// The queue count is CLAMPED to dataplane.BindingQueuesPerIface before the
// rule is applied, because that is the most queues an interface can ever have
// bound (#8374) and the RSS indirection table is reshaped to feed only bound
// queues (#7497). Covering queues that can hold no binding buys nothing and
// would make a 64-queue NIC send ~500 packets at every bringup. The clamp is
// what bounds this function's output, so it is not a separate magic maximum.
func napiProbeCount(rxQueues int) int {
	n := rxQueues
	if n > int(dataplane.BindingQueuesPerIface) {
		n = int(dataplane.BindingQueuesPerIface)
	}
	if n <= 1 {
		// 0 = queue count unknown; 1 = every probe lands on the only queue.
		// Both take the floor, which is what this code sent before #8377.
		return napiProbeFloor
	}
	k := int(math.Ceil(float64(n) *
		(math.Log(float64(n)) + math.Log(napiProbeCoverageTargetReciprocal))))
	if k < napiProbeFloor {
		return napiProbeFloor
	}
	return k
}
