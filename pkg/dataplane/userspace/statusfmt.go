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
	armedQueues := 0
	for _, q := range status.Queues {
		if q.Ready {
			readyQueues++
		}
		if q.Armed {
			armedQueues++
		}
	}
	readyBindings := 0
	armedBindings := 0
	boundBindings := 0
	xskBindings := 0
	var rxPackets uint64
	var validatedPackets uint64
	var forwardCandidates uint64
	var routeMisses uint64
	var neighborMisses uint64
	var exceptionPackets uint64
	var sessionHits uint64
	var sessionMisses uint64
	var sessionCreates uint64
	var sessionExpires uint64
	var sessionDeltaPending uint64
	var sessionDeltaGenerated uint64
	var sessionDeltaDropped uint64
	var sessionDeltaDrained uint64
	var policyDeniedPackets uint64
	var snatPackets uint64
	var dnatPackets uint64
	var txPackets uint64
	var txBytes uint64
	var txErrors uint64
	var slowPathPackets uint64
	var slowPathDrops uint64
	for _, binding := range status.Bindings {
		if binding.Ready {
			readyBindings++
		}
		if binding.Armed {
			armedBindings++
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
		sessionHits += binding.SessionHits
		sessionMisses += binding.SessionMisses
		sessionCreates += binding.SessionCreates
		sessionExpires += binding.SessionExpires
		sessionDeltaPending += binding.SessionDeltaPending
		sessionDeltaGenerated += binding.SessionDeltaGenerated
		sessionDeltaDropped += binding.SessionDeltaDropped
		sessionDeltaDrained += binding.SessionDeltaDrained
		policyDeniedPackets += binding.PolicyDeniedPackets
		snatPackets += binding.SNATPackets
		dnatPackets += binding.DNATPackets
		txPackets += binding.TXPackets
		txBytes += binding.TXBytes
		txErrors += binding.TXErrors
		slowPathPackets += binding.SlowPathPackets
		slowPathDrops += binding.SlowPathDrops
	}

	fmt.Fprintln(&b, "Userspace dataplane helper:")
	fmt.Fprintf(&b, "  PID:                       %d\n", status.PID)
	fmt.Fprintf(&b, "  Helper mode:               %s\n", status.HelperMode)
	fmt.Fprintf(&b, "  io_uring active:           %t\n", status.IOUringActive)
	if status.IOUringMode != "" {
		fmt.Fprintf(&b, "  io_uring mode:             %s\n", status.IOUringMode)
	}
	if status.IOUringLastError != "" {
		fmt.Fprintf(&b, "  io_uring last error:       %s\n", status.IOUringLastError)
	}
	fmt.Fprintf(&b, "  Enabled:                   %t\n", status.Enabled)
	fmt.Fprintf(&b, "  Forwarding armed:          %t\n", status.ForwardingArmed)
	fmt.Fprintf(&b, "  Forwarding supported:      %t\n", status.Capabilities.ForwardingSupported)
	if len(status.Capabilities.UnsupportedReasons) > 0 {
		fmt.Fprintf(&b, "  Forwarding blocked by:     %s\n", strings.Join(status.Capabilities.UnsupportedReasons, "; "))
	}
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
	if len(status.HAGroups) > 0 {
		parts := make([]string, 0, len(status.HAGroups))
		for _, group := range status.HAGroups {
			parts = append(parts, fmt.Sprintf("rg%d active=%t watchdog=%d", group.RGID, group.Active, group.WatchdogTimestamp))
		}
		fmt.Fprintf(&b, "  HA groups:                 %s\n", strings.Join(parts, "; "))
	}
	if status.LastResolution != nil {
		fmt.Fprintf(&b, "  Last resolution:           %s", status.LastResolution.Disposition)
		if status.LastResolution.LocalIfindex > 0 {
			fmt.Fprintf(&b, " local-ifindex=%d", status.LastResolution.LocalIfindex)
		}
		if status.LastResolution.EgressIfindex > 0 {
			fmt.Fprintf(&b, " egress-ifindex=%d", status.LastResolution.EgressIfindex)
		}
		if status.LastResolution.NextHop != "" {
			fmt.Fprintf(&b, " next-hop=%s", status.LastResolution.NextHop)
		}
		if status.LastResolution.NeighborMAC != "" {
			fmt.Fprintf(&b, " mac=%s", status.LastResolution.NeighborMAC)
		}
		fmt.Fprintln(&b)
	}
	fmt.Fprintf(&b, "  Bound bindings:            %d/%d\n", boundBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  XSK-registered bindings:   %d/%d\n", xskBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  Armed queues:              %d/%d\n", armedQueues, len(status.Queues))
	fmt.Fprintf(&b, "  Ready queues:              %d/%d\n", readyQueues, len(status.Queues))
	fmt.Fprintf(&b, "  Armed bindings:            %d/%d\n", armedBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  Ready bindings:            %d/%d\n", readyBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  RX packets:                %d\n", rxPackets)
	fmt.Fprintf(&b, "  Validated packets:         %d\n", validatedPackets)
	fmt.Fprintf(&b, "  Forward candidates:        %d\n", forwardCandidates)
	fmt.Fprintf(&b, "  Route misses:              %d\n", routeMisses)
	fmt.Fprintf(&b, "  Neighbor misses:           %d\n", neighborMisses)
	fmt.Fprintf(&b, "  Exception packets:         %d\n", exceptionPackets)
	fmt.Fprintf(&b, "  Session hits:              %d\n", sessionHits)
	fmt.Fprintf(&b, "  Session misses:            %d\n", sessionMisses)
	fmt.Fprintf(&b, "  Session creates:           %d\n", sessionCreates)
	fmt.Fprintf(&b, "  Session expires:           %d\n", sessionExpires)
	fmt.Fprintf(&b, "  Session delta pending:     %d\n", sessionDeltaPending)
	fmt.Fprintf(&b, "  Session delta generated:   %d\n", sessionDeltaGenerated)
	fmt.Fprintf(&b, "  Session delta dropped:     %d\n", sessionDeltaDropped)
	fmt.Fprintf(&b, "  Session delta drained:     %d\n", sessionDeltaDrained)
	fmt.Fprintf(&b, "  Policy denied packets:     %d\n", policyDeniedPackets)
	fmt.Fprintf(&b, "  SNAT packets:              %d\n", snatPackets)
	fmt.Fprintf(&b, "  DNAT packets:              %d\n", dnatPackets)
	fmt.Fprintf(&b, "  TX packets:                %d\n", txPackets)
	fmt.Fprintf(&b, "  TX bytes:                  %d\n", txBytes)
	fmt.Fprintf(&b, "  TX errors:                 %d\n", txErrors)
	fmt.Fprintf(&b, "  Slow path active:          %t\n", status.SlowPath.Active)
	if status.SlowPath.DeviceName != "" {
		fmt.Fprintf(&b, "  Slow path device:          %s\n", status.SlowPath.DeviceName)
	}
	if status.SlowPath.Mode != "" {
		fmt.Fprintf(&b, "  Slow path mode:            %s\n", status.SlowPath.Mode)
	}
	fmt.Fprintf(&b, "  Slow path queued:          %d\n", status.SlowPath.QueuedPackets)
	fmt.Fprintf(&b, "  Slow path injected:        %d pkts / %d bytes\n", status.SlowPath.InjectedPackets, status.SlowPath.InjectedBytes)
	fmt.Fprintf(&b, "  Slow path dropped:         %d pkts / %d bytes\n", status.SlowPath.DroppedPackets, status.SlowPath.DroppedBytes)
	fmt.Fprintf(&b, "  Slow path rate-limited:    %d\n", status.SlowPath.RateLimitedPackets)
	fmt.Fprintf(&b, "  Slow path queue-full:      %d\n", status.SlowPath.QueueFullPackets)
	fmt.Fprintf(&b, "  Slow path write errors:    %d\n", status.SlowPath.WriteErrors)
	if status.SlowPath.LastError != "" {
		fmt.Fprintf(&b, "  Slow path last error:      %s\n", status.SlowPath.LastError)
	}
	fmt.Fprintf(&b, "  Slow path per-binding:     %d pkts / %d drops\n", slowPathPackets, slowPathDrops)
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
		fmt.Fprintf(&b, "  %-7s %-8s %-10s %-7s %-7s %s\n", "Queue", "Worker", "Registered", "Armed", "Ready", "Interfaces")
		for _, q := range status.Queues {
			fmt.Fprintf(&b, "  %-7d %-8d %-10t %-7t %-7t %s\n",
				q.QueueID, q.WorkerID, q.Registered, q.Armed, q.Ready, strings.Join(q.Interfaces, ","))
		}
	}
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "Userspace bindings:")
	if len(status.Bindings) == 0 {
		fmt.Fprintln(&b, "  none")
		return b.String()
	}
	fmt.Fprintf(&b, "  %-6s %-7s %-8s %-10s %-7s %-7s %-7s %-5s %-8s %-9s %-9s %-9s %-9s %-9s %-9s %s\n", "Slot", "Queue", "Worker", "Registered", "Armed", "Ready", "Bound", "XSK", "Ifindex", "RXPkts", "TXPkts", "SessHit", "SlowPkts", "ExcPkts", "RtMiss", "Interface")
	for _, binding := range status.Bindings {
		fmt.Fprintf(&b, "  %-6d %-7d %-8d %-10t %-7t %-7t %-7t %-5t %-8d %-9d %-9d %-9d %-9d %-9d %-9d %s",
			binding.Slot, binding.QueueID, binding.WorkerID, binding.Registered, binding.Armed, binding.Ready, binding.Bound, binding.XSKRegistered, binding.Ifindex, binding.RXPackets, binding.TXPackets, binding.SessionHits, binding.SlowPathPackets, binding.ExceptionPackets, binding.RouteMissPackets, binding.Interface)
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
