package cluster

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// FormatStatus returns a Junos-style status string for all RGs.
func (m *Manager) FormatStatus() string {
	states := m.GroupStates()
	m.mu.RLock()
	peerAlive := m.peerAlive
	peerNodeID := m.peerNodeID
	localVersion := m.localSoftwareVersion
	peerVersion := m.peerSoftwareVersion
	localProtocol := normalizeHAProtocolVersion(m.localHAProtocolVersion)
	peerProtocol := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
	peerGroups := make(map[int]PeerGroupState, len(m.peerGroups))
	for k, v := range m.peerGroups {
		peerGroups[k] = v
	}
	m.mu.RUnlock()

	var b strings.Builder
	fmt.Fprintln(&b, "Monitor Failure codes:")
	fmt.Fprintln(&b, "    CS  Cold Sync monitoring        FL  Fabric Connection monitoring")
	fmt.Fprintln(&b, "    IF  Interface monitoring        IP  IP monitoring")
	fmt.Fprintln(&b, "    CF  Config Sync monitoring")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Cluster ID: %d\n", m.clusterID)
	fmt.Fprintf(&b, "Node name: node%d\n\n", m.nodeID)
	if localVersion != "" {
		fmt.Fprintf(&b, "Software version: %s\n", localVersion)
	}
	fmt.Fprintf(&b, "HA protocol version: %d\n", localProtocol)
	if peerAlive {
		if peerVersion == "" {
			peerVersion = "unknown"
		}
		fmt.Fprintf(&b, "Peer software version: %s\n", peerVersion)
		fmt.Fprintf(&b, "Peer HA protocol version: %d\n", peerProtocol)
	}
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "%-6s %-8s %-14s %-8s %-8s %s\n",
		"Node", "Priority", "Status", "Preempt", "Manual", "Monitor-failures")
	fmt.Fprintln(&b)

	for _, rg := range states {
		fmt.Fprintf(&b, "Redundancy group: %d , Failover count: %d\n",
			rg.GroupID, rg.FailoverCount)
		preempt := "no"
		if rg.Preempt {
			preempt = "yes"
		}
		manual := "no"
		if rg.ManualFailover {
			manual = "yes"
		}
		monFails := "None"
		if len(rg.MonitorFails) > 0 {
			monFails = strings.Join(rg.MonitorFails, ", ")
		}
		readyStr := "yes"
		if !rg.Ready {
			readyStr = "no"
			if len(rg.ReadinessReasons) > 0 {
				readyStr = "no (" + strings.Join(rg.ReadinessReasons, ", ") + ")"
			}
		}
		transferReadyStr := "yes"
		if !rg.TransferReady {
			transferReadyStr = "no"
			if len(rg.TransferReadinessReasons) > 0 {
				transferReadyStr = "no (" + strings.Join(rg.TransferReadinessReasons, ", ") + ")"
			}
		}
		// Local node line.
		fmt.Fprintf(&b, "%-6s %-8d %-14s %-8s %-8s %s\n",
			fmt.Sprintf("node%d", m.nodeID),
			rg.LocalPriority, rg.State, preempt, manual, monFails)
		fmt.Fprintf(&b, "  Takeover ready: %s\n", readyStr)
		fmt.Fprintf(&b, "  Transfer ready: %s\n", transferReadyStr)
		// Peer node line (if alive).
		if peerAlive {
			if pg, ok := peerGroups[rg.GroupID]; ok {
				fmt.Fprintf(&b, "%-6s %-8d %-14s %-8s %-8s %s\n",
					fmt.Sprintf("node%d", peerNodeID),
					pg.Priority, pg.State, preempt, "no", "None")
			}
		}
		fmt.Fprintln(&b)
	}
	return b.String()
}

// FormatInformation returns detailed cluster information matching vSRX output.
func (m *Manager) FormatInformation() string {
	m.mu.RLock()
	peerAlive := m.peerAlive
	peerNodeID := m.peerNodeID
	localVersion := m.localSoftwareVersion
	peerVersion := m.peerSoftwareVersion
	localProtocol := normalizeHAProtocolVersion(m.localHAProtocolVersion)
	peerProtocol := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
	interval := m.hbInterval
	threshold := m.hbThreshold
	controlIface := m.controlInterface
	m.mu.RUnlock()

	states := m.GroupStates()

	var b strings.Builder

	// Redundancy mode.
	mode := "active-passive"
	if len(states) > 1 {
		// If different RGs have different primaries, it's active-active.
		primary0 := false
		secondary0 := false
		for _, rg := range states {
			if rg.State == StatePrimary {
				primary0 = true
			} else {
				secondary0 = true
			}
		}
		if primary0 && secondary0 {
			mode = "active-active"
		}
	}
	fmt.Fprintf(&b, "Redundancy mode: %s\n\n", mode)

	// Cluster configuration.
	fmt.Fprintln(&b, "Cluster configuration:")
	fmt.Fprintf(&b, "  Cluster ID: %d\n", m.clusterID)
	fmt.Fprintf(&b, "  Node ID: %d\n", m.nodeID)
	fmt.Fprintf(&b, "  Heartbeat interval: %d ms\n", interval.Milliseconds())
	fmt.Fprintf(&b, "  Heartbeat threshold: %d\n", threshold)
	if controlIface != "" {
		fmt.Fprintf(&b, "  Control interface: %s\n", controlIface)
	}
	if localVersion != "" {
		fmt.Fprintf(&b, "  Software version: %s\n", localVersion)
	}
	fmt.Fprintf(&b, "  HA protocol version: %d\n", localProtocol)
	if peerAlive {
		if peerVersion == "" {
			peerVersion = "unknown"
		}
		fmt.Fprintf(&b, "  Peer software version: %s\n", peerVersion)
		fmt.Fprintf(&b, "  Peer HA protocol version: %d\n", peerProtocol)
	}
	fmt.Fprintf(&b, "  Sync transport: %s\n", m.SyncTransport())
	fmt.Fprintln(&b)

	// Node health.
	localHealth := "healthy"
	for _, rg := range states {
		if len(rg.MonitorFails) > 0 || rg.Weight < 255 {
			localHealth = "degraded"
			break
		}
	}
	remoteHealth := "lost"
	if peerAlive {
		remoteHealth = fmt.Sprintf("healthy (node%d)", peerNodeID)
	}
	fmt.Fprintln(&b, "Node health:")
	fmt.Fprintf(&b, "  Local node: %s\n", localHealth)
	fmt.Fprintf(&b, "  Remote node: %s\n", remoteHealth)
	fmt.Fprintln(&b)

	// Per-RG details with event history.
	for _, rg := range states {
		fmt.Fprintf(&b, "Redundancy group %d:\n", rg.GroupID)
		fmt.Fprintf(&b, "  Local priority: %d\n", rg.LocalPriority)
		fmt.Fprintf(&b, "  Peer priority: %d\n", rg.PeerPriority)
		fmt.Fprintf(&b, "  Local state: %s\n", rg.State)
		fmt.Fprintf(&b, "  Weight: %d/255 (threshold: 0)\n", rg.Weight)
		fmt.Fprintf(&b, "  Effective priority: %d\n", EffectivePriority(rg.LocalPriority, rg.Weight))
		preempt := "no"
		if rg.Preempt {
			preempt = "yes"
		}
		fmt.Fprintf(&b, "  Preempt: %s\n", preempt)
		fmt.Fprintf(&b, "  Failover count: %d\n", rg.FailoverCount)
		if rg.Ready {
			fmt.Fprintf(&b, "  Takeover ready: yes (since %s)\n", rg.ReadySince.Format("15:04:05"))
		} else {
			reasons := "none"
			if len(rg.ReadinessReasons) > 0 {
				reasons = strings.Join(rg.ReadinessReasons, ", ")
			}
			fmt.Fprintf(&b, "  Takeover ready: no (%s)\n", reasons)
		}
		if rg.TransferReady {
			fmt.Fprintf(&b, "  Transfer ready: yes\n")
		} else {
			reasons := "none"
			if len(rg.TransferReadinessReasons) > 0 {
				reasons = strings.Join(rg.TransferReadinessReasons, ", ")
			}
			fmt.Fprintf(&b, "  Transfer ready: no (%s)\n", reasons)
		}
		if len(rg.MonitorFails) > 0 {
			fmt.Fprintf(&b, "  Monitor failures: %s\n", strings.Join(rg.MonitorFails, ", "))
		}

		// RG event history.
		rgEvents := m.history.Events(EventRG)
		var rgFiltered []HistoryEvent
		for _, ev := range rgEvents {
			if ev.GroupID == rg.GroupID {
				rgFiltered = append(rgFiltered, ev)
			}
		}
		if len(rgFiltered) > 0 {
			fmt.Fprintln(&b, "  Event history:")
			for _, ev := range rgFiltered {
				fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
			}
		}
		fmt.Fprintln(&b)
	}

	// Control link statistics.
	hbStats := m.HeartbeatStats()
	fmt.Fprintln(&b, "Control link statistics:")
	fmt.Fprintf(&b, "  Heartbeat packets sent:     %d\n", hbStats.Sent)
	fmt.Fprintf(&b, "  Heartbeat packets received: %d\n", hbStats.Received)
	fmt.Fprintf(&b, "  Heartbeat packet errors:    %d\n", hbStats.SendErrors+hbStats.RecvErrors)
	fmt.Fprintln(&b)

	// Sync link statistics.
	syncLabel := "Fabric link statistics:"
	if m.SyncTransport() == "control-link" {
		syncLabel = "Sync link statistics (control-link):"
	}
	fmt.Fprintln(&b, syncLabel)
	syncStats := m.GetSyncStats()
	if syncStats != nil {
		connected := "Down"
		if m.IsSyncConnected() {
			connected = "Up"
		}
		fmt.Fprintf(&b, "  Status: %s\n", connected)
		fmt.Fprintf(&b, "  Errors: %d\n", syncStats.Errors)
	} else {
		fmt.Fprintln(&b, "  Not configured")
	}
	fabEvents := m.history.Events(EventFabric)
	if len(fabEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range fabEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}
	fmt.Fprintln(&b)

	// Cold synchronization.
	fmt.Fprintln(&b, "Cold synchronization:")
	if syncStats != nil {
		startNano := syncStats.BulkSyncStartTime
		endNano := syncStats.BulkSyncEndTime
		bulkCount := syncStats.BulkSyncs
		if startNano > 0 {
			startTime := time.Unix(0, startNano)
			if endNano > 0 {
				endTime := time.Unix(0, endNano)
				dur := endTime.Sub(startTime)
				fmt.Fprintf(&b, "  Last bulk sync: %s (duration: %s, sessions: %d)\n",
					endTime.Format("Jan 02 15:04:05"), dur.Round(time.Millisecond), syncStats.BulkSyncSessions)
			} else {
				fmt.Fprintf(&b, "  Bulk sync in progress since %s (sessions: %d)\n",
					startTime.Format("Jan 02 15:04:05"), syncStats.BulkSyncSessions)
			}
		}
		fmt.Fprintf(&b, "  Bulk syncs completed: %d\n", bulkCount)
	} else {
		fmt.Fprintln(&b, "  Not configured")
	}
	coldEvents := m.history.Events(EventColdSync)
	if len(coldEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range coldEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}
	fmt.Fprintln(&b)

	// Install fence (barrier-based cutover).
	if syncStats != nil && syncStats.LastFenceSeq > 0 {
		fmt.Fprintln(&b, "Install fence:")
		fmt.Fprintf(&b, "  Last fence sequence: %d\n", syncStats.LastFenceSeq)
		if syncStats.LastFenceAckAt > 0 {
			ackTime := time.Unix(0, syncStats.LastFenceAckAt)
			fmt.Fprintf(&b, "  Last fence ack:      %s\n", ackTime.Format("Jan 02 15:04:05.000"))
		} else {
			fmt.Fprintln(&b, "  Last fence ack:      pending")
		}
		fmt.Fprintln(&b)
	}

	// Interface monitoring events.
	monEvents := m.history.Events(EventMonitor)
	if len(monEvents) > 0 {
		fmt.Fprintln(&b, "Interface monitoring events:")
		for _, ev := range monEvents {
			rgStr := ""
			if ev.GroupID >= 0 {
				rgStr = fmt.Sprintf(" (rg%d)", ev.GroupID)
			}
			fmt.Fprintf(&b, "  %s%s  %s\n", ev.Time.Format("Jan 02 15:04:05"), rgStr, ev.Message)
		}
		fmt.Fprintln(&b)
	}

	// Configuration synchronization.
	fmt.Fprintln(&b, "Configuration synchronization:")
	if syncStats != nil {
		configNano := syncStats.LastConfigSyncTime
		if configNano > 0 {
			configTime := time.Unix(0, configNano)
			fmt.Fprintf(&b, "  Last config sync: %s (size: %d bytes)\n",
				configTime.Format("Jan 02 15:04:05"), syncStats.LastConfigSyncSize)
		}
		fmt.Fprintf(&b, "  Configs sent:     %d\n", syncStats.ConfigsSent)
		fmt.Fprintf(&b, "  Configs received: %d\n", syncStats.ConfigsReceived)
	} else {
		fmt.Fprintln(&b, "  Not configured")
	}
	cfgEvents := m.history.Events(EventConfigSync)
	if len(cfgEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range cfgEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}

	// Heartbeat event history.
	hbEvents := m.history.Events(EventHeartbeat)
	if len(hbEvents) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Heartbeat events:")
		for _, ev := range hbEvents {
			fmt.Fprintf(&b, "  %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}

	return b.String()
}

// FormatStatistics returns cluster statistics matching vSRX output.
func (m *Manager) FormatStatistics() string {
	var b strings.Builder

	// Control link statistics.
	hbStats := m.HeartbeatStats()
	fmt.Fprintln(&b, "Control link statistics:")
	fmt.Fprintf(&b, "    Heartbeat packets sent:     %d\n", hbStats.Sent)
	fmt.Fprintf(&b, "    Heartbeat packets received: %d\n", hbStats.Received)
	fmt.Fprintf(&b, "    Heartbeat packet errors:    %d\n", hbStats.SendErrors+hbStats.RecvErrors)
	fmt.Fprintln(&b)

	// Services synchronized table.
	syncStats := m.GetSyncStats()
	if syncStats != nil {
		fmt.Fprintln(&b, "Services Synchronized:")
		fmt.Fprintf(&b, "    %-32s %-12s %s\n", "Service name", "Sent", "Received")
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session create",
			syncStats.SessionsSent, syncStats.SessionsReceived)
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session close",
			syncStats.DeletesSent, syncStats.DeletesReceived)
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Config",
			syncStats.ConfigsSent, syncStats.ConfigsReceived)
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "IPsec SA",
			syncStats.IPsecSASent, syncStats.IPsecSAReceived)
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Bulk syncs",
			syncStats.BulkSyncs, syncStats.BulkSyncs)
		fmt.Fprintf(&b, "    %-32s %-12s %d\n", "Sessions installed",
			"", syncStats.SessionsInstalled)
		fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Errors",
			syncStats.Errors, "")
		if syncStats.LastFenceSeq > 0 {
			fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Install fence seq",
				syncStats.LastFenceSeq, "")
		}
	} else {
		fmt.Fprintln(&b, "Session sync not configured")
	}

	return b.String()
}

// FormatControlPlaneStatistics returns control-plane (heartbeat) statistics.
func (m *Manager) FormatControlPlaneStatistics() string {
	var b strings.Builder
	hbStats := m.HeartbeatStats()
	fmt.Fprintln(&b, "Control link statistics:")
	fmt.Fprintf(&b, "    Heartbeat packets sent:     %d\n", hbStats.Sent)
	fmt.Fprintf(&b, "    Heartbeat packets received: %d\n", hbStats.Received)
	fmt.Fprintf(&b, "    Heartbeat send errors:      %d\n", hbStats.SendErrors)
	fmt.Fprintf(&b, "    Heartbeat receive errors:   %d\n", hbStats.RecvErrors)
	return b.String()
}

// FormatDataPlaneStatistics returns data-plane (session sync) statistics.
func (m *Manager) FormatDataPlaneStatistics() string {
	var b strings.Builder
	syncStats := m.GetSyncStats()
	if syncStats == nil {
		fmt.Fprintln(&b, "Session sync not configured")
		return b.String()
	}

	fmt.Fprintln(&b, "Services Synchronized:")
	fmt.Fprintf(&b, "    %-32s %-12s %s\n", "Service name", "Sent", "Received")
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session create",
		syncStats.SessionsSent, syncStats.SessionsReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session close",
		syncStats.DeletesSent, syncStats.DeletesReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Config",
		syncStats.ConfigsSent, syncStats.ConfigsReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "IPsec SA",
		syncStats.IPsecSASent, syncStats.IPsecSAReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Bulk syncs",
		syncStats.BulkSyncs, syncStats.BulkSyncs)
	fmt.Fprintf(&b, "    %-32s %-12s %d\n", "Sessions installed",
		"", syncStats.SessionsInstalled)
	fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Errors",
		syncStats.Errors, "")
	if syncStats.LastFenceSeq > 0 {
		fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Install fence seq",
			syncStats.LastFenceSeq, "")
	}
	return b.String()
}

// FormatDataPlaneInterfaces returns fabric interface status.
func (m *Manager) FormatDataPlaneInterfaces() string {
	var b strings.Builder
	if m.SyncTransport() == "control-link" {
		fmt.Fprintln(&b, "Sync link (control-link):")
	} else {
		fmt.Fprintln(&b, "Fabric link:")
	}
	if m.IsSyncConnected() {
		fmt.Fprintln(&b, "  Status: Up")
	} else {
		fmt.Fprintln(&b, "  Status: Down")
	}
	syncStats := m.GetSyncStats()
	if syncStats != nil {
		fmt.Fprintf(&b, "  Errors: %d\n", syncStats.Errors)
	}
	fabEvents := m.history.Events(EventFabric)
	if len(fabEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range fabEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}
	return b.String()
}

// FormatIPMonitoringStatus returns per-RG IP monitoring probe status.
func (m *Manager) FormatIPMonitoringStatus() string {
	m.mu.RLock()
	mon := m.monitor
	m.mu.RUnlock()

	states := m.GroupStates()
	var b strings.Builder
	fmt.Fprintln(&b, "IP monitoring status:")
	fmt.Fprintln(&b)

	hasIP := false
	for _, rg := range states {
		// Check for IP monitor failures (prefixed with "ip:").
		var ipFails []string
		for _, f := range rg.MonitorFails {
			if strings.HasPrefix(f, "ip:") {
				ipFails = append(ipFails, f)
			}
		}
		// Show IP monitor section regardless (config-driven).
		_ = mon // monitor has the config but we show from state
		if len(ipFails) > 0 || true {
			// We always show the section for each RG if any monitors are configured.
			fmt.Fprintf(&b, "Redundancy group %d:\n", rg.GroupID)
			if len(ipFails) > 0 {
				for _, f := range ipFails {
					addr := strings.TrimPrefix(f, "ip:")
					fmt.Fprintf(&b, "  %-20s Status: unreachable\n", addr)
				}
			} else {
				fmt.Fprintln(&b, "  No IP monitoring failures")
			}
			fmt.Fprintln(&b)
			hasIP = true
		}
	}

	if !hasIP {
		fmt.Fprintln(&b, "No IP monitoring configured")
	}

	// Events.
	monEvents := m.history.Events(EventMonitor)
	var ipEvents []HistoryEvent
	for _, ev := range monEvents {
		if strings.HasPrefix(ev.Message, "IP ") {
			ipEvents = append(ipEvents, ev)
		}
	}
	if len(ipEvents) > 0 {
		fmt.Fprintln(&b, "IP monitoring events:")
		for _, ev := range ipEvents {
			fmt.Fprintf(&b, "  %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}

	return b.String()
}

// InterfaceMonitorInfo holds per-interface monitor state for display.
type InterfaceMonitorInfo struct {
	Interface       string
	Weight          int
	Up              bool // physical link state
	RedundancyGroup int
}

// RethInfo holds RETH interface status for display.
type RethInfo struct {
	Name            string
	RedundancyGroup int
	Status          string // "Up" or "Down"
	Members         []string
}

// InterfacesInput provides the data needed to format cluster interfaces output.
type InterfacesInput struct {
	ControlInterface string
	FabricInterface  string
	FabricMembers    []string // bond member interfaces (e.g. fab0-m0, fab0-m1)
	Fabric1Interface string   // secondary fabric interface (e.g. "fab1")
	Fabric1Members   []string // secondary fabric bond members (if any)
	Reths            []RethInfo
	Monitors         []InterfaceMonitorInfo
	PeerMonitors     []InterfaceMonitorInfo
}

// FormatInterfaces returns cluster interface information matching vSRX output.
func (m *Manager) FormatInterfaces(input InterfacesInput) string {
	var b strings.Builder

	m.mu.RLock()
	peerAlive := m.peerAlive
	m.mu.RUnlock()

	// Control link status.
	controlStatus := "Up"
	if !peerAlive {
		controlStatus = "Down"
	}
	fmt.Fprintf(&b, "Control link status: %s\n", controlStatus)
	fmt.Fprintln(&b)

	// Control interfaces table.
	if input.ControlInterface != "" {
		fmt.Fprintln(&b, "Control interfaces:")
		fmt.Fprintf(&b, "    %-8s%-12s%-21s%-14s%s\n", "Index", "Interface", "Monitored-Status", "Internal-SA", "Security")
		monStatus := "Up"
		if !peerAlive {
			monStatus = "Down"
		}
		fmt.Fprintf(&b, "    %-8d%-12s%-21s%-14s%s\n", 0, input.ControlInterface, monStatus, "Disabled", "Disabled")
		fmt.Fprintln(&b)
	}

	// Sync link status.
	fabricUp := m.IsSyncConnected()
	fabricStatus := "Up"
	if !fabricUp {
		fabricStatus = "Down"
	}
	if m.SyncTransport() == "control-link" {
		fmt.Fprintf(&b, "Sync link status (control-link): %s\n", fabricStatus)
	} else {
		fmt.Fprintf(&b, "Fabric link status: %s\n", fabricStatus)
	}
	fmt.Fprintln(&b)

	// Fabric interfaces table.
	if input.FabricInterface != "" || input.Fabric1Interface != "" {
		fmt.Fprintln(&b, "Fabric interfaces:")
		fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", "Name", "Child-interface", "Status", "Security")
		fmt.Fprintf(&b, "    %-8s%-19s%s\n", "", "", "(Physical/Monitored)")
		physStatus := "Up"
		if !fabricUp {
			physStatus = "Down"
		}
		statusStr := fmt.Sprintf("%s  /  %s", physStatus, physStatus)
		if input.FabricInterface != "" {
			if len(input.FabricMembers) > 0 {
				for i, member := range input.FabricMembers {
					name := ""
					if i == 0 {
						name = input.FabricInterface
					}
					fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", name, member, statusStr, "Disabled")
				}
			} else {
				fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", input.FabricInterface, input.FabricInterface, statusStr, "Disabled")
			}
		}
		if input.Fabric1Interface != "" {
			if len(input.Fabric1Members) > 0 {
				for i, member := range input.Fabric1Members {
					name := ""
					if i == 0 {
						name = input.Fabric1Interface
					}
					fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", name, member, statusStr, "Disabled")
				}
			} else {
				fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", input.Fabric1Interface, input.Fabric1Interface, statusStr, "Disabled")
			}
		}
		fmt.Fprintln(&b)
	}

	// Redundant-ethernet Information.
	if len(input.Reths) > 0 {
		fmt.Fprintln(&b, "Redundant-ethernet Information:")
		fmt.Fprintf(&b, "    %-13s%-12s%s\n", "Name", "Status", "Redundancy-group")
		for _, r := range input.Reths {
			fmt.Fprintf(&b, "    %-13s%-12s%d\n", r.Name, r.Status, r.RedundancyGroup)
		}
		fmt.Fprintln(&b)
	}

	// Interface Monitoring — merge local + peer monitors and sort by RG then name.
	allMonitors := make([]InterfaceMonitorInfo, 0, len(input.Monitors)+len(input.PeerMonitors))
	allMonitors = append(allMonitors, input.Monitors...)
	allMonitors = append(allMonitors, input.PeerMonitors...)
	if len(allMonitors) > 0 {
		sort.Slice(allMonitors, func(i, j int) bool {
			if allMonitors[i].RedundancyGroup != allMonitors[j].RedundancyGroup {
				return allMonitors[i].RedundancyGroup < allMonitors[j].RedundancyGroup
			}
			return allMonitors[i].Interface < allMonitors[j].Interface
		})
		fmt.Fprintln(&b, "Interface Monitoring:")
		fmt.Fprintf(&b, "    %-18s%-10s%-26s%s\n", "Interface", "Weight", "Status", "Redundancy-group")
		fmt.Fprintf(&b, "    %-18s%-10s%s\n", "", "", "(Physical/Monitored)")
		for _, mon := range allMonitors {
			physStatus := "Up"
			if !mon.Up {
				physStatus = "Down"
			}
			// Physical and monitored status are the same (link-state based).
			statusStr := fmt.Sprintf("%s  /  %s", physStatus, physStatus)
			fmt.Fprintf(&b, "    %-18s%-10d%-26s%d\n",
				mon.Interface, mon.Weight, statusStr, mon.RedundancyGroup)
		}
	}

	return b.String()
}
