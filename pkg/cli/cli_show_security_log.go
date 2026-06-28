package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/natpoolalarm"
)

func (c *CLI) showSecurityLog(args []string) error {
	if c.eventBuf == nil {
		fmt.Println("no events (event buffer not initialized)")
		return nil
	}

	n := 50
	var filter logging.EventFilter
	cr := c.applyResult()

	// Parse arguments: [N] [zone <name>] [protocol <proto>] [action <act>]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 < len(args) {
				i++
				zoneName := args[i]
				if cr != nil {
					if zid, ok := cr.ZoneIDs[zoneName]; ok {
						filter.Zone = zid
					} else {
						return fmt.Errorf("zone %q not found", zoneName)
					}
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				filter.Protocol = args[i]
			}
		case "action":
			if i+1 < len(args) {
				i++
				filter.Action = args[i]
			}
		default:
			// Try parsing as count. Reject a non-positive count at the
			// boundary so `show security log -1` is a clean error rather
			// than a panic — defense in depth alongside the EventBuffer
			// guard (#3342). A bare non-numeric token is ignored, as
			// before.
			if v, err := strconv.Atoi(args[i]); err == nil {
				if v <= 0 {
					return fmt.Errorf("event count must be a positive integer, got %d", v)
				}
				n = v
			}
		}
	}

	var events []logging.EventRecord
	if !filter.IsEmpty() {
		events = c.eventBuf.LatestFiltered(n, filter)
	} else {
		events = c.eventBuf.Latest(n)
	}
	if len(events) == 0 {
		fmt.Println("no events recorded")
		return nil
	}

	// Build reverse zone ID → name map for event display
	evZoneNames := make(map[uint16]string)
	if cr != nil {
		for name, id := range cr.ZoneIDs {
			evZoneNames[id] = name
		}
	}
	zoneName := func(id uint16) string {
		if n, ok := evZoneNames[id]; ok {
			return n
		}
		return fmt.Sprintf("%d", id)
	}

	policyName := func(e logging.EventRecord) string {
		if e.PolicyName != "" {
			return e.PolicyName
		}
		return fmt.Sprintf("%d", e.PolicyID)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}

	for _, e := range events {
		ts := e.Time.Format("2006-01-02T15:04:05")

		// Parse source/destination address:port
		srcAddr, srcPort := splitAddrPort(e.SrcAddr)
		dstAddr, dstPort := splitAddrPort(e.DstAddr)
		natSrcAddr, natSrcPort := splitAddrPort(e.NATSrcAddr)
		natDstAddr, natDstPort := splitAddrPort(e.NATDstAddr)
		if natSrcAddr == "" {
			natSrcAddr = srcAddr
			natSrcPort = srcPort
		}
		if natDstAddr == "" {
			natDstAddr = dstAddr
			natDstPort = dstPort
		}

		inIface := e.IngressIface
		if inIface == "" {
			inIface = zoneName(e.InZone)
		}
		appName := e.AppName
		if appName == "" {
			appName = "UNKNOWN"
		}

		switch e.Type {
		case "SESSION_OPEN":
			fmt.Printf("%s %s RT_FLOW - RT_FLOW_SESSION_CREATE [source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" nat-source-address=\"%s\" nat-source-port=\"%s\" nat-destination-address=\"%s\" nat-destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" session-id-32=\"%d\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, srcAddr, srcPort, dstAddr, dstPort,
				natSrcAddr, natSrcPort, natDstAddr, natDstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZone), zoneName(e.OutZone),
				e.SessionID, appName, inIface)

		case "SESSION_CLOSE":
			reason := e.CloseReason
			if reason == "" {
				reason = "N/A"
			}
			fmt.Printf("%s %s RT_FLOW - RT_FLOW_SESSION_CLOSE [reason=\"%s\" source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" nat-source-address=\"%s\" nat-source-port=\"%s\" nat-destination-address=\"%s\" nat-destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" session-id-32=\"%d\" packets-from-client=\"%d\" bytes-from-client=\"%d\" packets-from-server=\"%d\" bytes-from-server=\"%d\" elapsed-time=\"%d\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, reason, srcAddr, srcPort, dstAddr, dstPort,
				natSrcAddr, natSrcPort, natDstAddr, natDstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZone), zoneName(e.OutZone),
				e.SessionID, e.SessionPkts, e.SessionBytes,
				e.RevSessionPkts, e.RevSessionBytes, e.ElapsedTime,
				appName, inIface)

		case "POLICY_DENY", "POLICY_REJECT":
			fmt.Printf("%s %s RT_FLOW - RT_FLOW_SESSION_DENY [source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, srcAddr, srcPort, dstAddr, dstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZone), zoneName(e.OutZone),
				appName, inIface)

		case "SCREEN_DROP":
			fmt.Printf("%s %s RT_IDS - RT_SCREEN_DROP [attack-name=\"%s\" source-address=\"%s\" destination-address=\"%s\" protocol-id=\"%s\" source-zone-name=\"%s\" action=\"%s\"]\n",
				ts, hostname, e.ScreenCheck, srcAddr, dstAddr,
				protoNameToID(e.Protocol), zoneName(e.InZone), e.Action)

		default:
			// Fallback for other event types
			fmt.Printf("%s %s RT_FLOW - %s [source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, e.Type, srcAddr, srcPort, dstAddr, dstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZone), zoneName(e.OutZone),
				appName, inIface)
		}
	}
	fmt.Printf("(%d events shown)\n", len(events))
	return nil
}

func (c *CLI) showSecurityAlarms(args []string) error {
	detail := len(args) >= 1 && args[0] == "detail"

	cfg := c.store.ActiveConfig()
	var alarmCount int

	// Config validation warnings
	if cfg != nil {
		warnings := config.ValidateConfig(cfg)
		for _, w := range warnings {
			alarmCount++
			if detail {
				fmt.Printf("Alarm %d:\n  Class: Configuration\n  Severity: Warning\n  Description: %s\n\n", alarmCount, w)
			}
		}
	}

	// Screen drop alarms — any non-zero screen counter indicates detected attacks
	if c.dp != nil && c.dp.IsLoaded() {
		readCtr := func(idx uint32) uint64 {
			v, _ := c.dp.ReadGlobalCounter(idx)
			return v
		}
		screenNames := []struct {
			idx  uint32
			name string
		}{
			{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
			{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
			{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
			{dataplane.GlobalCtrScreenLandAttack, "LAND attack"},
			{dataplane.GlobalCtrScreenPingOfDeath, "Ping of death"},
			{dataplane.GlobalCtrScreenTearDrop, "Tear-drop"},
			{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN+FIN"},
			{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no-flag"},
			{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN-no-ACK"},
			{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
			{dataplane.GlobalCtrScreenIPSrcRoute, "IP source-route"},
			{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
		}
		for _, s := range screenNames {
			val := readCtr(s.idx)
			if val > 0 {
				alarmCount++
				if detail {
					fmt.Printf("Alarm %d:\n  Class: IDS\n  Severity: Major\n  Description: %s attack detected (%d drops)\n\n", alarmCount, s.name, val)
				}
			}
		}
	}

	// #2079: NAT source pool-utilization alarms from the daemon monitor.
	if c.natPoolAlarmsFn != nil {
		alarmCount = natpoolalarm.RenderAlarms(os.Stdout, c.natPoolAlarmsFn(), alarmCount, detail)
	}

	if alarmCount == 0 {
		fmt.Println("No security alarms currently active")
	} else if !detail {
		fmt.Printf("%d security alarm(s) currently active\n", alarmCount)
		fmt.Println("  run 'show security alarms detail' for details")
	}

	return nil
}
