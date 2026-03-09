package userspace

import (
	"fmt"
	"strings"
	"time"
)

func FormatStatusSummary(status ProcessStatus) string {
	var b strings.Builder
	now := time.Now()
	readyQueues := 0
	for _, q := range status.Queues {
		if q.Ready {
			readyQueues++
		}
	}
	readyBindings := 0
	boundBindings := 0
	xskBindings := 0
	var rxPackets uint64
	var validatedPackets uint64
	var forwardCandidates uint64
	var routeMisses uint64
	var neighborMisses uint64
	var exceptionPackets uint64
	for _, binding := range status.Bindings {
		if binding.Ready {
			readyBindings++
		}
		if binding.Bound {
			boundBindings++
		}
		if binding.XSKRegistered {
			xskBindings++
		}
		rxPackets += binding.RXPackets
		validatedPackets += binding.ValidatedPackets
		forwardCandidates += binding.ForwardCandidatePkts
		routeMisses += binding.RouteMissPackets
		neighborMisses += binding.NeighborMissPackets
		exceptionPackets += binding.ExceptionPackets
	}

	fmt.Fprintln(&b, "Userspace dataplane helper:")
	fmt.Fprintf(&b, "  PID:                       %d\n", status.PID)
	fmt.Fprintf(&b, "  Helper mode:               %s\n", status.HelperMode)
	fmt.Fprintf(&b, "  Enabled:                   %t\n", status.Enabled)
	fmt.Fprintf(&b, "  Workers:                   %d\n", status.Workers)
	fmt.Fprintf(&b, "  Ring entries:              %d\n", status.RingEntries)
	fmt.Fprintf(&b, "  Last snapshot generation:  %d\n", status.LastSnapshotGeneration)
	fmt.Fprintf(&b, "  Last FIB generation:       %d\n", status.LastFIBGeneration)
	if !status.LastSnapshotAt.IsZero() {
		fmt.Fprintf(&b, "  Last snapshot age:         %s\n", formatStatusAge(now.Sub(status.LastSnapshotAt)))
	}
	fmt.Fprintf(&b, "  Interface addresses:       %d\n", status.InterfaceAddresses)
	fmt.Fprintf(&b, "  Neighbor entries:          %d\n", status.NeighborEntries)
	fmt.Fprintf(&b, "  Route entries:             %d\n", status.RouteEntries)
	fmt.Fprintf(&b, "  Bound bindings:            %d/%d\n", boundBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  XSK-registered bindings:   %d/%d\n", xskBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  Ready queues:              %d/%d\n", readyQueues, len(status.Queues))
	fmt.Fprintf(&b, "  Ready bindings:            %d/%d\n", readyBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  RX packets:                %d\n", rxPackets)
	fmt.Fprintf(&b, "  Validated packets:         %d\n", validatedPackets)
	fmt.Fprintf(&b, "  Forward candidates:        %d\n", forwardCandidates)
	fmt.Fprintf(&b, "  Route misses:              %d\n", routeMisses)
	fmt.Fprintf(&b, "  Neighbor misses:           %d\n", neighborMisses)
	fmt.Fprintf(&b, "  Exception packets:         %d\n", exceptionPackets)
	fmt.Fprintf(&b, "  Recent exceptions:         %d\n", len(status.RecentExceptions))
	for i, hb := range status.WorkerHeartbeats {
		if hb.IsZero() {
			fmt.Fprintf(&b, "  Worker %d heartbeat age:    unknown\n", i)
			continue
		}
		fmt.Fprintf(&b, "  Worker %d heartbeat age:    %s\n", i, formatStatusAge(now.Sub(hb)))
	}
	return b.String()
}

func FormatBindings(status ProcessStatus) string {
	var b strings.Builder

	fmt.Fprintln(&b, "Userspace queues:")
	if len(status.Queues) == 0 {
		fmt.Fprintln(&b, "  none")
	} else {
		fmt.Fprintf(&b, "  %-7s %-8s %-10s %-7s %s\n", "Queue", "Worker", "Registered", "Ready", "Interfaces")
		for _, q := range status.Queues {
			fmt.Fprintf(&b, "  %-7d %-8d %-10t %-7t %s\n",
				q.QueueID, q.WorkerID, q.Registered, q.Ready, strings.Join(q.Interfaces, ","))
		}
	}
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "Userspace bindings:")
	if len(status.Bindings) == 0 {
		fmt.Fprintln(&b, "  none")
		return b.String()
	}
	fmt.Fprintf(&b, "  %-6s %-7s %-8s %-10s %-7s %-7s %-5s %-8s %-9s %-9s %-9s %-9s %s\n", "Slot", "Queue", "Worker", "Registered", "Ready", "Bound", "XSK", "Ifindex", "RXPkts", "FwdPkts", "RtMiss", "ExcPkts", "Interface")
	for _, binding := range status.Bindings {
		fmt.Fprintf(&b, "  %-6d %-7d %-8d %-10t %-7t %-7t %-5t %-8d %-9d %-9d %-9d %-9d %s",
			binding.Slot, binding.QueueID, binding.WorkerID, binding.Registered, binding.Ready, binding.Bound, binding.XSKRegistered, binding.Ifindex, binding.RXPackets, binding.ForwardCandidatePkts, binding.RouteMissPackets, binding.ExceptionPackets, binding.Interface)
		if binding.LastError != "" {
			fmt.Fprintf(&b, " (%s)", binding.LastError)
		}
		fmt.Fprintln(&b)
	}
	if len(status.RecentExceptions) == 0 {
		return b.String()
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Recent userspace exceptions:")
	for _, exc := range status.RecentExceptions {
		fmt.Fprintf(&b, "  %s slot=%d queue=%d if=%s reason=%s len=%d af=%d proto=%d",
			exc.Timestamp.Format(time.RFC3339), exc.Slot, exc.QueueID, exc.Interface, exc.Reason, exc.PacketLength, exc.AddrFamily, exc.Protocol)
		if exc.ConfigGeneration != 0 || exc.FIBGeneration != 0 {
			fmt.Fprintf(&b, " cfg=%d fib=%d", exc.ConfigGeneration, exc.FIBGeneration)
		}
		fmt.Fprintln(&b)
	}
	return b.String()
}

func formatStatusAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return d.Round(time.Second).String()
}
