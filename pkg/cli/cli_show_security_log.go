package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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
	//
	// Argument parsing fails CLOSED (#3347): an unknown token or a filter
	// keyword with no value is a usage error, never silently ignored. A
	// typo (`show security log zon trust`) or a bare trailing keyword
	// (`show security log action`) used to fall through to an unfiltered
	// dump of every event — in incident response, silently widening a
	// scoped forensic query is worse than refusing it.
	const usage = "usage: show security log [<count>] [zone <name>] " +
		"[protocol <proto>] [action <action>]"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for %q\n%s", "zone", usage)
			}
			i++
			zoneName := args[i]
			// The "unknown"/"none"/"0" sentinels select zone 0 — the
			// unassigned/pre-classification zone carried by host-inbound and
			// emitted-before-zone-resolution events (#3338). Zone IDs are
			// 1-based, so this value can never collide with a configured zone
			// and does not need the apply result to resolve a name -> ID.
			switch strings.ToLower(zoneName) {
			case "unknown", "none", "0":
				filter.Zone = 0
				filter.HasZone = true
				continue
			}
			// A named zone filter is meaningless without the apply result that
			// maps zone name -> ID. Refuse rather than drop the filter and
			// widen to all events (M02): during early startup or after a
			// failed apply, cr == nil and silently honoring the request
			// would dump every zone's events.
			if cr == nil {
				return fmt.Errorf("cannot filter by zone %q: no active dataplane apply result "+
					"(zone IDs unavailable — retry after a successful commit)", zoneName)
			}
			zid, ok := cr.ZoneIDs[zoneName]
			if !ok {
				return fmt.Errorf("zone %q not found", zoneName)
			}
			filter.Zone = zid
			filter.HasZone = true
		case "protocol":
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for %q\n%s", "protocol", usage)
			}
			i++
			filter.Protocol = args[i]
		case "action":
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for %q\n%s", "action", usage)
			}
			i++
			filter.Action = args[i]
		default:
			// The only bare token accepted is the event count. Reject a
			// non-positive count at the boundary so `show security log -1`
			// is a clean error rather than a panic — defense in depth
			// alongside the EventBuffer guard (#3342). Any other unknown
			// token is a usage error (#3347), not a silently-ignored
			// fall-open to an unfiltered dump.
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return fmt.Errorf("unknown argument %q\n%s", args[i], usage)
			}
			if v <= 0 {
				return fmt.Errorf("event count must be a positive integer, got %d", v)
			}
			n = v
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

	// Build reverse zone ID → name map from the CURRENT config. This is only a
	// fallback for legacy records that lack a resolved-at-event-time name
	// (#3335): each EventRecord stores InZoneName/OutZoneName as resolved when
	// the event fired, so a later zone rename / delete / ID reuse (#3075) must
	// NOT retroactively rewrite an old event's zone name from the live config.
	// Prefer the stored name; consult this map (then a bare numeric fallback)
	// only when the record carries no resolved name.
	evZoneNames := make(map[uint16]string)
	if cr != nil {
		for name, id := range cr.ZoneIDs {
			evZoneNames[id] = name
		}
	}
	zoneName := func(stored string, id uint16) string {
		if stored != "" {
			return stored
		}
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
			inIface = zoneName(e.InZoneName, e.InZone)
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
				zoneName(e.InZoneName, e.InZone), zoneName(e.OutZoneName, e.OutZone),
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
				zoneName(e.InZoneName, e.InZone), zoneName(e.OutZoneName, e.OutZone),
				e.SessionID, e.SessionPkts, e.SessionBytes,
				e.RevSessionPkts, e.RevSessionBytes, e.ElapsedTime,
				appName, inIface)

		case "POLICY_DENY", "POLICY_REJECT":
			fmt.Printf("%s %s RT_FLOW - RT_FLOW_SESSION_DENY [source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, srcAddr, srcPort, dstAddr, dstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZoneName, e.InZone), zoneName(e.OutZoneName, e.OutZone),
				appName, inIface)

		case "SCREEN_DROP":
			fmt.Printf("%s %s RT_IDS - RT_SCREEN_DROP [attack-name=\"%s\" source-address=\"%s\" destination-address=\"%s\" protocol-id=\"%s\" source-zone-name=\"%s\" action=\"%s\"]\n",
				ts, hostname, e.ScreenCheck, srcAddr, dstAddr,
				protoNameToID(e.Protocol), zoneName(e.InZoneName, e.InZone), e.Action)

		default:
			// Fallback for other event types
			fmt.Printf("%s %s RT_FLOW - %s [source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, e.Type, srcAddr, srcPort, dstAddr, dstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZoneName, e.InZone), zoneName(e.OutZoneName, e.OutZone),
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
		// #3345: track a counter-read failure so a degraded counter bridge
		// is reported as a warning rather than masquerading as "no alarms".
		var readErr error
		readCtr := func(idx uint32) uint64 {
			v, err := c.dp.ReadGlobalCounter(idx)
			if err != nil && readErr == nil {
				readErr = err
			}
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
		if readErr != nil {
			fmt.Printf("warning: screen counter read failed (alarms may be incomplete): %v\n", readErr)
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
