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
	zeroCopyBindings := 0
	var rxPackets uint64
	var validatedPackets uint64
	var forwardCandidates uint64
	var routeMisses uint64
	var neighborMisses uint64
	var exceptionPackets uint64
	var flowCacheHits uint64
	var flowCacheMisses uint64
	var flowCacheEvictions uint64
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
	var txCompletions uint64
	var kernelRXDropped uint64
	var kernelRXInvalidDescs uint64
	var directTXPackets uint64
	var copyTXPackets uint64
	var inPlaceTXPackets uint64
	var directTXNoFrameFallbackPackets uint64
	var directTXBuildFallbackPackets uint64
	var directTXDisallowedFallbackPackets uint64
	var debugPendingFillFrames uint64
	var debugSpareFillFrames uint64
	var debugFreeTXFrames uint64
	var debugPendingTXPrepared uint64
	var debugPendingTXLocal uint64
	var debugOutstandingTX uint64
	var debugInFlightRecycles uint64
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
		if binding.ZeroCopy {
			zeroCopyBindings++
		}
		rxPackets += binding.RXPackets
		validatedPackets += binding.ValidatedPackets
		forwardCandidates += binding.ForwardCandidatePkts
		routeMisses += binding.RouteMissPackets
		neighborMisses += binding.NeighborMissPackets
		exceptionPackets += binding.ExceptionPackets
		flowCacheHits += binding.FlowCacheHits
		flowCacheMisses += binding.FlowCacheMisses
		flowCacheEvictions += binding.FlowCacheEvictions
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
		txCompletions += binding.TXCompletions
		kernelRXDropped += binding.KernelRXDropped
		kernelRXInvalidDescs += binding.KernelRXInvalidDescs
		directTXPackets += binding.DirectTXPackets
		copyTXPackets += binding.CopyTXPackets
		inPlaceTXPackets += binding.InPlaceTXPackets
		directTXNoFrameFallbackPackets += binding.DirectTXNoFrameFallbackPackets
		directTXBuildFallbackPackets += binding.DirectTXBuildFallbackPackets
		directTXDisallowedFallbackPackets += binding.DirectTXDisallowedFallbackPackets
		debugPendingFillFrames += uint64(binding.DebugPendingFillFrames)
		debugSpareFillFrames += uint64(binding.DebugSpareFillFrames)
		debugFreeTXFrames += uint64(binding.DebugFreeTXFrames)
		debugPendingTXPrepared += uint64(binding.DebugPendingTXPrepared)
		debugPendingTXLocal += uint64(binding.DebugPendingTXLocal)
		debugOutstandingTX += uint64(binding.DebugOutstandingTX)
		debugInFlightRecycles += uint64(binding.DebugInFlightRecycles)
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
	fmt.Fprintf(&b, "  Neighbor generation:       %d\n", status.NeighborGeneration)
	fmt.Fprintf(&b, "  Route entries:             %d\n", status.RouteEntries)
	if len(status.HAGroups) > 0 {
		parts := make([]string, 0, len(status.HAGroups))
		for _, group := range status.HAGroups {
			parts = append(parts, fmt.Sprintf("rg%d active=%t watchdog=%d", group.RGID, group.Active, group.WatchdogTimestamp))
		}
		fmt.Fprintf(&b, "  HA groups:                 %s\n", strings.Join(parts, "; "))
	}
	if len(status.Fabrics) > 0 {
		parts := make([]string, 0, len(status.Fabrics))
		for _, fabric := range status.Fabrics {
			part := fabric.Name
			if fabric.ParentLinuxName != "" {
				part += fmt.Sprintf(" parent=%s", fabric.ParentLinuxName)
			}
			if fabric.PeerAddress != "" {
				part += fmt.Sprintf(" peer=%s", fabric.PeerAddress)
			}
			parts = append(parts, part)
		}
		fmt.Fprintf(&b, "  Fabric links:              %s\n", strings.Join(parts, "; "))
	}
	if status.LastResolution != nil {
		fmt.Fprintf(&b, "  Last resolution:           %s", status.LastResolution.Disposition)
		if status.LastResolution.IngressIfindex > 0 {
			fmt.Fprintf(&b, " ingress-ifindex=%d", status.LastResolution.IngressIfindex)
		}
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
		if status.LastResolution.SrcIP != "" || status.LastResolution.DstIP != "" {
			fmt.Fprintf(&b, " flow=%s:%d->%s:%d",
				status.LastResolution.SrcIP,
				status.LastResolution.SrcPort,
				status.LastResolution.DstIP,
				status.LastResolution.DstPort,
			)
		}
		if status.LastResolution.FromZone != "" || status.LastResolution.ToZone != "" {
			fmt.Fprintf(&b, " zones=%s->%s", status.LastResolution.FromZone, status.LastResolution.ToZone)
		}
		fmt.Fprintln(&b)
	}
	fmt.Fprintf(&b, "  Bound bindings:            %d/%d\n", boundBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  XSK-registered bindings:   %d/%d\n", xskBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  Zerocopy bindings:         %d/%d\n", zeroCopyBindings, len(status.Bindings))
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
	fmt.Fprintf(&b, "  Flow cache hits:           %d\n", flowCacheHits)
	fmt.Fprintf(&b, "  Flow cache misses:         %d\n", flowCacheMisses)
	fmt.Fprintf(&b, "  Flow cache evictions:      %d\n", flowCacheEvictions)
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
	fmt.Fprintf(&b, "  TX completions:            %d\n", txCompletions)
	fmt.Fprintf(&b, "  Kernel RX dropped:         %d\n", kernelRXDropped)
	fmt.Fprintf(&b, "  Kernel RX invalid descs:   %d\n", kernelRXInvalidDescs)
	fmt.Fprintf(&b, "  Direct TX packets:         %d\n", directTXPackets)
	fmt.Fprintf(&b, "  Copy-path TX packets:      %d\n", copyTXPackets)
	fmt.Fprintf(&b, "  In-place TX packets:       %d\n", inPlaceTXPackets)
	fmt.Fprintf(&b, "  Direct TX no-frame fb:     %d\n", directTXNoFrameFallbackPackets)
	fmt.Fprintf(&b, "  Direct TX build-none fb:   %d\n", directTXBuildFallbackPackets)
	fmt.Fprintf(&b, "  Direct TX disallowed fb:   %d\n", directTXDisallowedFallbackPackets)
	fmt.Fprintf(&b, "  Pending fill frames:       %d\n", debugPendingFillFrames)
	fmt.Fprintf(&b, "  Spare fill frames:         %d\n", debugSpareFillFrames)
	fmt.Fprintf(&b, "  Free TX frames:            %d\n", debugFreeTXFrames)
	fmt.Fprintf(&b, "  Pending TX prepared:       %d\n", debugPendingTXPrepared)
	fmt.Fprintf(&b, "  Pending TX local:          %d\n", debugPendingTXLocal)
	fmt.Fprintf(&b, "  Outstanding TX:            %d\n", debugOutstandingTX)
	fmt.Fprintf(&b, "  In-flight recycles:        %d\n", debugInFlightRecycles)
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

	if len(status.Fabrics) > 0 {
		fmt.Fprintln(&b, "Userspace fabric links:")
		fmt.Fprintf(&b, "  %-8s %-16s %-8s %-16s %-8s %-7s %s\n", "Name", "Parent", "PIfidx", "Overlay", "OIfidx", "Queues", "Peer")
		for _, fabric := range status.Fabrics {
			fmt.Fprintf(&b, "  %-8s %-16s %-8d %-16s %-8d %-7d %s\n",
				fabric.Name,
				fabric.ParentLinuxName,
				fabric.ParentIfindex,
				fabric.OverlayLinux,
				fabric.OverlayIfindex,
				fabric.RXQueues,
				fabric.PeerAddress,
			)
		}
		fmt.Fprintln(&b)
	}

	fmt.Fprintln(&b, "Userspace bindings:")
	if len(status.Bindings) == 0 {
		fmt.Fprintln(&b, "  none")
		return b.String()
	}
	fmt.Fprintf(&b, "  %-6s %-7s %-8s %-10s %-7s %-7s %-7s %-5s %-8s %-8s %-9s %-9s %-8s %-8s %-8s %-9s %-9s %-9s %-9s %s\n", "Slot", "Queue", "Worker", "Registered", "Armed", "Ready", "Bound", "XSK", "Mode", "Ifindex", "RXPkts", "TXPkts", "DirTx", "CopyTx", "InPlTx", "SessHit", "SlowPkts", "ExcPkts", "RtMiss", "Interface")
	for _, binding := range status.Bindings {
		mode := binding.XSKBindMode
		if mode == "" {
			mode = "-"
		}
		fmt.Fprintf(&b, "  %-6d %-7d %-8d %-10t %-7t %-7t %-7t %-5t %-8s %-8d %-9d %-9d %-8d %-8d %-8d %-9d %-9d %-9d %-9d %s",
			binding.Slot, binding.QueueID, binding.WorkerID, binding.Registered, binding.Armed, binding.Ready, binding.Bound, binding.XSKRegistered, mode, binding.Ifindex, binding.RXPackets, binding.TXPackets, binding.DirectTXPackets, binding.CopyTXPackets, binding.InPlaceTXPackets, binding.SessionHits, binding.SlowPathPackets, binding.ExceptionPackets, binding.RouteMissPackets, binding.Interface)
		if binding.LastError != "" {
			fmt.Fprintf(&b, " (%s)", binding.LastError)
		}
		fmt.Fprintln(&b)
	}
	if len(status.RecentExceptions) == 0 && len(status.RecentSessionDeltas) == 0 {
		return b.String()
	}
	if len(status.RecentExceptions) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Recent userspace exceptions:")
		for _, exc := range status.RecentExceptions {
			fmt.Fprintf(&b, "  %s slot=%d queue=%d if=%s reason=%s len=%d af=%d proto=%d",
				exc.Timestamp.Format(time.RFC3339), exc.Slot, exc.QueueID, exc.Interface, exc.Reason, exc.PacketLength, exc.AddrFamily, exc.Protocol)
			if exc.IngressIfindex > 0 {
				fmt.Fprintf(&b, " ingress-ifindex=%d", exc.IngressIfindex)
			}
			if exc.SrcIP != "" || exc.DstIP != "" {
				fmt.Fprintf(&b, " flow=%s:%d->%s:%d", exc.SrcIP, exc.SrcPort, exc.DstIP, exc.DstPort)
			}
			if exc.FromZone != "" || exc.ToZone != "" {
				fmt.Fprintf(&b, " zones=%s->%s", exc.FromZone, exc.ToZone)
			}
			if exc.ConfigGeneration != 0 || exc.FIBGeneration != 0 {
				fmt.Fprintf(&b, " cfg=%d fib=%d", exc.ConfigGeneration, exc.FIBGeneration)
			}
			fmt.Fprintln(&b)
		}
	}
	if len(status.RecentSessionDeltas) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Recent userspace session deltas:")
		for _, delta := range status.RecentSessionDeltas {
			fmt.Fprintf(&b, "  %s slot=%d queue=%d if=%s event=%s af=%d proto=%d flow=%s:%d->%s:%d zones=%s->%s owner-rg=%d egress-if=%d",
				delta.Timestamp.Format(time.RFC3339), delta.Slot, delta.QueueID, delta.Interface, delta.Event, delta.AddrFamily, delta.Protocol, delta.SrcIP, delta.SrcPort, delta.DstIP, delta.DstPort, delta.IngressZone, delta.EgressZone, delta.OwnerRGID, delta.EgressIfindex)
			if delta.NextHop != "" {
				fmt.Fprintf(&b, " next-hop=%s", delta.NextHop)
			}
			if delta.NATSrcIP != "" || delta.NATDstIP != "" {
				fmt.Fprintf(&b, " nat=%s->%s", delta.NATSrcIP, delta.NATDstIP)
			}
			fmt.Fprintln(&b)
		}
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
