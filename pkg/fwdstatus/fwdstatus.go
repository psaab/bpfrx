// Package fwdstatus builds and formats the one-screen forwarding-daemon
// health view surfaced via `show chassis forwarding` (#877).  The
// package has no dependency on pkg/cli or pkg/grpcapi so both the
// local TTY and gRPC paths can consume it without circular imports.
package fwdstatus

import (
	"fmt"
	"strings"
	"time"
)

// State is the tri-state liveness of the forwarding path.
type State string

const (
	StateOnline   State = "Online"
	StateDegraded State = "Degraded"
	StateUnknown  State = "Unknown"
)

// CPUMode distinguishes whether the worker-threads CPU row has a
// meaningful value (userspace-dp) or reads as N/A (eBPF path).
type CPUMode int

const (
	// CPUModeWorkers is the userspace-dp path; WorkerCPUPercent is
	// the summed per-worker cumulative CPU%.
	CPUModeWorkers CPUMode = iota
	// CPUModeEBPFNoWorkers is the eBPF path; packet processing runs
	// in XDP/TC hooks, not user-space workers.  The row renders an
	// explicit N/A label instead of a bare "0 percent".
	CPUModeEBPFNoWorkers
)

// ForwardingStatus is the flat struct passed to Format.  All fields
// are computed by Build; Format does not read /proc or call into the
// dataplane.
type ForwardingStatus struct {
	State             State
	DaemonCPUPercent  float64
	WorkerCPUMode     CPUMode
	WorkerCPUPercent  float64
	HeapPercent       float64
	BufferPercent     float64 // Only valid if BufferKnown.
	BufferKnown       bool    // False on userspace-dp until UMEM telemetry lands.
	BufferFollowupRef int     // GitHub issue number printed in place of buffer %.
	Uptime            time.Duration

	// ClusterMode = true causes Format to append a deferred-peer note.
	ClusterMode       bool
	ClusterFollowupRef int
}

// Format renders a ForwardingStatus in the Junos-style one-screen
// layout.  Labels, ordering, and spacing are the contract surface —
// do not rearrange without updating unit tests.
func Format(fs *ForwardingStatus) string {
	var b strings.Builder
	b.WriteString("FWDD status:\n")
	writeRow(&b, "State", string(fs.State))
	// CPU rows are per-core: 100 percent = one core saturated; a
	// multi-threaded daemon legitimately shows >100% (e.g. 250%
	// = 2.5 cores).  Do not clamp — suppressing >100% would hide
	// real load.  Clamp to a non-negative floor only.
	writeRow(&b, "Daemon CPU utilization",
		fmt.Sprintf("%.0f percent (cumulative since start)", floorZero(fs.DaemonCPUPercent)))

	switch fs.WorkerCPUMode {
	case CPUModeEBPFNoWorkers:
		writeRow(&b, "Worker threads CPU utilization",
			"0 percent (N/A — eBPF path has no worker threads)")
	default:
		writeRow(&b, "Worker threads CPU utilization",
			fmt.Sprintf("%.0f percent (cumulative since start)", floorZero(fs.WorkerCPUPercent)))
	}

	writeRow(&b, "Heap utilization",
		fmt.Sprintf("%.0f percent", clampPercent(fs.HeapPercent)))

	if fs.BufferKnown {
		writeRow(&b, "Buffer utilization",
			fmt.Sprintf("%.0f percent", clampPercent(fs.BufferPercent)))
	} else if fs.BufferFollowupRef != 0 {
		writeRow(&b, "Buffer utilization",
			fmt.Sprintf("unknown (see #%d)", fs.BufferFollowupRef))
	} else {
		writeRow(&b, "Buffer utilization", "unknown")
	}

	writeRow(&b, "Uptime:", formatUptime(fs.Uptime))

	if fs.ClusterMode {
		fmt.Fprintf(&b, "\nNote: peer-node rendering deferred to #%d.\n",
			fs.ClusterFollowupRef)
	}
	return b.String()
}

// writeRow writes a `  <label>   <value>\n` line with a fixed
// label column (34 chars, matching the widest label "Worker threads
// CPU utilization").
func writeRow(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "  %-34s %s\n", label, value)
}

// clampPercent clamps a percentage to [0, 100].  Used for Heap and
// Buffer (ratios that are bounded by construction — RSS/limit,
// used/max).  CPU rows use floorZero instead because multi-core
// daemons legitimately exceed 100%.
func clampPercent(p float64) float64 {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

// floorZero returns max(p, 0) with no upper bound.  Used for CPU
// rows where values > 100 are meaningful (per-core percent).
func floorZero(p float64) float64 {
	if p < 0 {
		return 0
	}
	return p
}

// formatUptime renders a duration as "N days, N hours, N minutes,
// N seconds" matching the Junos/vSRX layout in issue #877.
func formatUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int64(d / time.Second)
	days := total / 86400
	total -= days * 86400
	hours := total / 3600
	total -= hours * 3600
	minutes := total / 60
	seconds := total - minutes*60
	return fmt.Sprintf("%d days, %d hours, %d minutes, %d seconds",
		days, hours, minutes, seconds)
}
