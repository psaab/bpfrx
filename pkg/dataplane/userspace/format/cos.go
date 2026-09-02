package format

import (
	"fmt"
	"math"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type cosInterfaceView struct {
	name string
	// ifName is the PHYSICAL interface the class-of-service stanza names, kept
	// alongside the rendered logical `name` so the #7065 advisory can quote the
	// operator's own `interfaces <ifName> unit <unit>` path rather than making
	// them re-derive it from "ge-9-9-9.0".
	ifName         string
	unit           int
	cosUnit        *config.CoSInterfaceUnit
	interfaceUnit  *config.InterfaceUnit
	interfaceState *userspace.CoSInterfaceStatus
}

type cosQueueView struct {
	queueID              int
	ownerWorker          *uint32
	forwardingClass      string
	priority             string
	exact                bool
	guaranteeEnabled     bool
	surplusSharing       bool // #915: only meaningful when exact == true
	equalFlowEnforcement bool
	equalFlowEnforced    bool
	transmitRate         uint64
	bufferBytes          uint64
	queuedPackets        uint64
	queuedBytes          uint64
	runnable             int
	parked               int
	nextWakeupTick       uint64
	surplusDeficit       uint64
	// #710/#718: admission-path counters sourced from runtime. Zero values
	// are still rendered — operators need to see the counter exists.
	admissionFlowShareDrops uint64
	admissionBufferDrops    uint64
	admissionEcnMarked      uint64
	// #709: owner-profile telemetry for exact queues with single
	// owner binding. When ownerWorker is set AND these fields are
	// non-default, the formatter renders a second indented line under
	// the Drops row. See docs/cos-validation-notes.md "Reading the
	// owner-profile counters".
	drainLatencyHist     []uint64
	drainInvocations     uint64
	drainNoopInvocations uint64
	redirectAcquireHist  []uint64
	ownerPPS             uint64
	peerPPS              uint64
	// #760/#1369 drain-shape instrumentation. drainSentBytes,
	// phase splits, exact-backlog steal bytes, and park counters are
	// queue-scoped.
	// postDrainBackupBytes is binding-scoped (one-per-binding Rust
	// attribution; summed across queues here for rendering).
	drainSentBytes                uint64
	drainGuaranteeSentBytes       uint64
	drainSurplusSentBytes         uint64
	drainNonExactWhileExactBytes  uint64
	drainParkRootTokens           uint64
	drainParkQueueTokens          uint64
	postDrainBackupBytes          uint64
	equalFlowTargetPerFlowBPS     uint64
	equalFlowMaxWorkerCapBytes    uint64
	equalFlowCapHitEvents         uint64
	equalFlowSuppressedGrantBytes uint64
	equalFlowFailOpenReason       string
	// #1746: active equal-flow target policy label; "" renders as the
	// byte-unchanged default "slowest".
	equalFlowTargetPolicy string
	// #1628 per-class waterfill trace counters (queue-scoped). Rendered
	// in the per-queue detail block only when non-zero.
	waterfillPhase1Admissions uint64
	waterfillPhase2Admissions uint64
	waterfillEligibleVisits   uint64
	// hb166 T-2: Phase-1 honored selections that made zero TX progress
	// (budget + honored bit refunded). Climbing here with flat
	// waterfillPhase1Admissions = TX-ring pressure eating a small class's
	// guarantee pass (#1630/#4256).
	waterfillPhase1SelectedNoProgress uint64
	// #1829 Phase 1: dequeue-time sojourn telemetry (queue-scoped,
	// MAX-merged across workers). Rendered only once the queue has
	// recorded at least one sample (peak > 0) so idle queues stay
	// clean. windowedMin is the standing-queue gate metric.
	sojournEwmaNS        uint64
	sojournPeakNS        uint64
	sojournWindowedMinNS uint64
}

// FormatCoSInterfaceSummary renders the `show class-of-service interface`
// summary. It joins the configured CoS/interface stanzas with the runtime
// snapshot into a per-interface view model (configuredCoSInterfaceViews +
// buildCoSQueueViews in cos_sections.go), then renders each interface via
// the writeCoSInterfaceHeader / renderBindingScopedTelemetry /
// writeCoSQueueTable section helpers. The queue view slice is built once
// per interface and shared between the binding-scoped telemetry line and
// the main queue table (Copilot flagged an earlier rev that built it
// twice, which doubled work and risked drift).
func FormatCoSInterfaceSummary(cfg *config.Config, status *userspace.ProcessStatus, selector string) string {
	if cfg == nil {
		return "No active configuration\n"
	}
	if cfg.ClassOfService == nil || len(cfg.ClassOfService.Interfaces) == 0 {
		return "No class-of-service interfaces configured\n"
	}

	views := configuredCoSInterfaceViews(cfg, status, selector)
	if len(views) == 0 {
		if selector == "" {
			return "No class-of-service interfaces configured\n"
		}
		return fmt.Sprintf("No class-of-service interface matches %s\n", selector)
	}

	var b strings.Builder
	for idx, view := range views {
		if idx > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Interface: %s\n", view.name)
		writeCoSInterfaceHeader(&b, view)
		// Build queue views once per interface and share the slice
		// between the binding-scoped telemetry render and the main
		// queue table below.
		queues := buildCoSQueueViews(cfg, view)
		// #732 / #751: binding-scoped telemetry rendered once per
		// interface instead of under every queue row. owner_pps /
		// peer_pps / redirect_p99 describe binding-wide arrivals
		// and redirects; producers don't know a target queue at
		// redirect time so these values are inherently per-binding.
		// Pre-#751 each queue row reported the same values, which
		// was the #732 symptom.
		renderBindingScopedTelemetry(&b, view, queues)
		if len(queues) == 0 {
			b.WriteString("  Queues:                   none\n")
			continue
		}
		b.WriteString("  Queues:\n")
		writeCoSQueueTable(&b, queues, view.interfaceState != nil)
	}
	return b.String()
}

func (q cosQueueView) hasDrainShapeTelemetry() bool {
	return q.drainSentBytes != 0 ||
		q.drainGuaranteeSentBytes != 0 ||
		q.drainSurplusSentBytes != 0 ||
		q.drainNonExactWhileExactBytes != 0 ||
		q.drainParkRootTokens != 0 ||
		q.drainParkQueueTokens != 0
}

// #1628: gate the per-queue waterfill trace row so a queue that never
// went through the guarantee-rate selector (Proportional mode, or never
// serviced) stays silent.
func (q cosQueueView) hasWaterfillTelemetry() bool {
	return q.waterfillPhase1Admissions != 0 ||
		q.waterfillPhase2Admissions != 0 ||
		q.waterfillEligibleVisits != 0 ||
		q.waterfillPhase1SelectedNoProgress != 0
}

// formatSchedulerTransmitRate renders a scheduler's configured transmit-rate
// in whichever of the three Junos forms it was authored.
//
// #6565 row 4 / #7422: this used to read TransmitRateBytes alone. The three
// forms are MUTUALLY EXCLUSIVE (validateClassOfServiceStrict), so a scheduler
// authored as `transmit-rate percent 30` has TransmitRateBytes == 0 and
// rendered as "-" — which reads as "no guarantee configured" for a queue that
// is in fact shaped.
//
// The dataplane resolves both non-absolute forms live: percent against the
// interface's shaping rate (cos_effective_transmit_rate_bytes, #4228 Gap 2)
// and remainder against the resolved sibling set (#6846's pre-pass). So the
// configured form is real, and rendering the AUTHORED form is honest here —
// the absolute value it resolves to depends on the interface and belongs on
// the interface view, not the scheduler table.
func formatSchedulerTransmitRate(sched *config.CoSScheduler) string {
	if sched == nil {
		return "-"
	}
	if sched.TransmitRateBytes > 0 {
		return formatCoSRate(sched.TransmitRateBytes)
	}
	if sched.TransmitRatePercent > 0 {
		return fmt.Sprintf("percent %g", sched.TransmitRatePercent)
	}
	if sched.TransmitRateRemainder {
		return "remainder"
	}
	return "-"
}

func formatCoSRate(bytesPerSecond uint64) string {
	if bytesPerSecond == 0 {
		return "-"
	}
	return formatBitsPerSecondFloat(float64(bytesPerSecond) * 8)
}

func cosUnitBurstPoolBytes(unit *config.CoSInterfaceUnit) uint64 {
	if unit == nil {
		return minCoSBurstBytes
	}
	if unit.BurstSizeBytes > 0 {
		return unit.BurstSizeBytes
	}
	return defaultCoSBurstBytes(unit.ShapingRateBytes)
}

const minCoSBurstBytes = 64 * 1500

func defaultCoSBurstBytes(rateBytes uint64) uint64 {
	burst := rateBytes / 100
	if burst < minCoSBurstBytes {
		return minCoSBurstBytes
	}
	return burst
}

func cosPercentBufferBytes(poolBytes uint64, percent float64) uint64 {
	if poolBytes == 0 || percent <= 0 || math.IsNaN(percent) || math.IsInf(percent, 0) {
		return 0
	}
	scaled := math.Ceil(float64(poolBytes) * percent / 100)
	if scaled < 1 {
		return 1
	}
	if scaled > float64(^uint64(0)) {
		return ^uint64(0)
	}
	return uint64(scaled)
}

func formatBitsPerSecond(bitsPerSecond uint64) string {
	if bitsPerSecond == 0 {
		return "-"
	}
	return formatBitsPerSecondFloat(float64(bitsPerSecond))
}

func formatBitsPerSecondFloat(value float64) string {
	units := []string{"b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"}
	unitIdx := 0
	for value >= 1000 && unitIdx < len(units)-1 {
		value /= 1000
		unitIdx++
	}
	return fmt.Sprintf("%.2f %s", value, units[unitIdx])
}

func formatOptionalWorkerID(workerID *uint32) string {
	if workerID == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *workerID)
}

func formatCoSBytes(bytes uint64) string {
	if bytes == 0 {
		return "-"
	}
	value := float64(bytes)
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	unitIdx := 0
	for value >= 1024 && unitIdx < len(units)-1 {
		value /= 1024
		unitIdx++
	}
	return fmt.Sprintf("%.2f %s", value, units[unitIdx])
}

func formatWakeTick(tick uint64) string {
	if tick == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", tick)
}

// formatSojournNS renders a nanosecond sojourn reading at operator
// scale: sub-microsecond values in ns, sub-millisecond in µs, else
// ms with one decimal (#1829).
func formatSojournNS(ns uint64) string {
	switch {
	case ns == 0:
		return "0"
	case ns < 1_000:
		return fmt.Sprintf("%dns", ns)
	case ns < 1_000_000:
		return fmt.Sprintf("%.1fus", float64(ns)/1_000)
	default:
		return fmt.Sprintf("%.1fms", float64(ns)/1_000_000)
	}
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
