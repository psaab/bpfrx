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
	State State

	// CPU windows (5s / 1m / 5m) — indexed by CPUWindow* constants.
	// DaemonCPUWindows is /proc/self/stat per-core % (can exceed
	// 100 on multi-core).  WorkerCPUWindows is per-worker-average
	// activity fraction in [0, 100] — time-weighted Σactive_ns /
	// Σwall_ns across all workers.  Parallel *Valid flags are
	// false when the ring doesn't have a sample ≥ W old yet
	// (short uptime); the formatter renders `-` for invalid cols.
	DaemonCPUWindows     [numCPUWindows]float64
	WorkerCPUWindows     [numCPUWindows]float64
	DaemonCPUWindowValid [numCPUWindows]bool
	WorkerCPUWindowValid [numCPUWindows]bool

	// WorkerCPUMode distinguishes the eBPF "no workers" path from
	// the userspace path — on eBPF the worker row prints the
	// explicit N/A label instead of window values, regardless of
	// WorkerCPUWindowValid.
	WorkerCPUMode CPUMode

	HeapPercent        float64
	BufferPercent      float64 // Only valid if BufferKnown.
	BufferKnown        bool    // False on userspace-dp until UMEM telemetry lands.
	BufferFollowupRef  int     // GitHub issue number printed in place of buffer %.
	Uptime             time.Duration
	ClusterMode        bool
	ClusterFollowupRef int
}

// Format renders a ForwardingStatus in the Junos-style one-screen
// layout.  Labels, ordering, and spacing are the contract surface —
// do not rearrange without updating unit tests.
func Format(fs *ForwardingStatus) string {
	var b strings.Builder
	b.WriteString("FWDD status:\n")
	writeRow(&b, "State", string(fs.State))
	// CPU rows: three sliding windows (5s / 1m / 5m).  Daemon row
	// is /proc/self/stat per-core % (can exceed 100 on multi-core;
	// no upper clamp).  Worker row is Σ(thread_cpu_ns) / Σ(wall_ns)
	// from CLOCK_THREAD_CPUTIME_ID — OS thread CPU, not dataplane
	// activity (see #883/#884; activity-based signal was tried and
	// empirically found broken at 25 Gbps).  Columns with insufficient
	// history (uptime < window) render `-`.  On eBPF, the worker row
	// prints the N/A label.
	writeRow(&b, "Daemon CPU utilization",
		formatWindowRow(fs.DaemonCPUWindows, fs.DaemonCPUWindowValid))

	if fs.WorkerCPUMode == CPUModeEBPFNoWorkers {
		writeRow(&b, "Worker threads CPU utilization",
			"N/A — eBPF path has no worker threads")
	} else {
		writeRow(&b, "Worker threads CPU utilization",
			formatWindowRow(fs.WorkerCPUWindows, fs.WorkerCPUWindowValid))
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

// formatWindowRow renders three windows as
// `NN% / NN% / NN%   (5s / 1m / 5m)`.  Invalid columns render `-`.
func formatWindowRow(pct [numCPUWindows]float64, valid [numCPUWindows]bool) string {
	cols := [numCPUWindows]string{}
	for i := 0; i < numCPUWindows; i++ {
		if valid[i] {
			cols[i] = fmt.Sprintf("%.0f%%", floorZero(pct[i]))
		} else {
			cols[i] = "-"
		}
	}
	return fmt.Sprintf("%-5s / %-5s / %-5s   (5s / 1m / 5m)", cols[0], cols[1], cols[2])
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
