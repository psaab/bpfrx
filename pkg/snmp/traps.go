package snmp

import (
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// SNMPv2-Trap PDU type (context-specific, constructed, tag 7).
const pduSNMPv2Trap = 0xa7

// Standard trap OIDs.
var (
	// snmpTrapOID.0: 1.3.6.1.6.3.1.1.4.1.0
	oidSnmpTrapOID = []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}

	// linkDown: 1.3.6.1.6.3.1.1.5.3
	oidLinkDown = []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 3}
	// linkUp: 1.3.6.1.6.3.1.1.5.4
	oidLinkUp = []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 4}

	// ifIndex column: 1.3.6.1.2.1.2.2.1.1
	oidIfIndex = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 1}
	// ifDescr column: 1.3.6.1.2.1.2.2.1.2
	oidIfDescr = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 2}
	// ifOperStatus column: 1.3.6.1.2.1.2.2.1.8
	oidIfOperStatus = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 8}
)

// buildLinkTrap builds an SNMPv2c trap PDU for a link up/down event.
func (a *Agent) buildLinkTrap(community string, linkUp bool, ifindex int, ifname string) []byte {
	// sysUpTime in hundredths of a second.
	uptime := int(time.Since(a.startTime).Milliseconds() / 10)

	// Choose the trap OID.
	trapOID := oidLinkDown
	operStatus := 2 // down
	if linkUp {
		trapOID = oidLinkUp
		operStatus = 1 // up
	}

	// Build varbinds:
	// 1. sysUpTime.0 — TimeTicks
	vb1OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oidSysUpTime))
	vb1Val := berEncodeTLV(tagTimeTicks, berEncodeTimeTicks(uptime))
	vb1 := berEncodeTLV(tagSequence, append(vb1OID, vb1Val...))

	// 2. snmpTrapOID.0 — OID of the trap type
	vb2OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oidSnmpTrapOID))
	vb2Val := berEncodeTLV(tagObjectIdentifier, berEncodeOID(trapOID))
	vb2 := berEncodeTLV(tagSequence, append(vb2OID, vb2Val...))

	// 3. ifIndex.<ifindex> — Integer
	ifIndexOID := append(append([]int{}, oidIfIndex...), ifindex)
	vb3OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(ifIndexOID))
	vb3Val := berEncodeIntegerTLV(ifindex)
	vb3 := berEncodeTLV(tagSequence, append(vb3OID, vb3Val...))

	// 4. ifDescr.<ifindex> — OctetString
	ifDescrOID := append(append([]int{}, oidIfDescr...), ifindex)
	vb4OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(ifDescrOID))
	vb4Val := berEncodeTLV(tagOctetString, []byte(ifname))
	vb4 := berEncodeTLV(tagSequence, append(vb4OID, vb4Val...))

	// 5. ifOperStatus.<ifindex> — Integer (1=up, 2=down)
	ifOperOID := append(append([]int{}, oidIfOperStatus...), ifindex)
	vb5OID := berEncodeTLV(tagObjectIdentifier, berEncodeOID(ifOperOID))
	vb5Val := berEncodeIntegerTLV(operStatus)
	vb5 := berEncodeTLV(tagSequence, append(vb5OID, vb5Val...))

	// Varbind list
	var vbList []byte
	vbList = append(vbList, vb1...)
	vbList = append(vbList, vb2...)
	vbList = append(vbList, vb3...)
	vbList = append(vbList, vb4...)
	vbList = append(vbList, vb5...)
	vbListEncoded := berEncodeTLV(tagSequence, vbList)

	// PDU body: request-id, error-status(0), error-index(0), varbinds
	requestID := rand.Int31()
	pduBody := berEncodeIntegerTLV(int(requestID))
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbListEncoded...)

	pduEncoded := berEncodeTLV(pduSNMPv2Trap, pduBody)

	// Message: version(v2c), community, PDU
	msgBody := berEncodeIntegerTLV(snmpVersion2c)
	msgBody = append(msgBody, berEncodeTLV(tagOctetString, []byte(community))...)
	msgBody = append(msgBody, pduEncoded...)

	return berEncodeTLV(tagSequence, msgBody)
}

// sendTrap sends a pre-built trap packet to a single target on port 162.
func sendTrap(target string, pkt []byte) error {
	// Ensure the target has a port.
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "162"
	}
	addr := net.JoinHostPort(host, port)

	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("write to %s: %w", addr, err)
	}
	return nil
}

// NotifyLinkDown sends an SNMPv2c linkDown trap to all configured trap targets.
func (a *Agent) NotifyLinkDown(ifindex int, ifname string) {
	a.sendLinkTraps(false, ifindex, ifname)
}

// NotifyLinkUp sends an SNMPv2c linkUp trap to all configured trap targets.
func (a *Agent) NotifyLinkUp(ifindex int, ifname string) {
	a.sendLinkTraps(true, ifindex, ifname)
}

// sendLinkTraps builds and sends link traps to all configured trap group targets.
func (a *Agent) sendLinkTraps(linkUp bool, ifindex int, ifname string) {
	// Read the live config under cfgMu — the same lock UpdateConfig swaps it
	// under — so a commit-time reconcile cannot race trap delivery.
	cfg := a.snapshotCfg()

	if cfg == nil || len(cfg.TrapGroups) == 0 {
		return
	}

	community := selectTrapCommunity(cfg)

	pkt := a.buildLinkTrap(community, linkUp, ifindex, ifname)

	direction := "down"
	if linkUp {
		direction = "up"
	}

	for _, tg := range sortedTrapGroups(cfg) {
		for _, target := range tg.Targets {
			if err := sendTrap(target, pkt); err != nil {
				slog.Warn("SNMP trap send failed",
					"target", target, "group", tg.Name,
					"event", "link"+direction, "iface", ifname, "err", err)
			} else {
				slog.Info("SNMP trap sent",
					"target", target, "group", tg.Name,
					"event", "link"+direction, "iface", ifname, "ifindex", ifindex)
			}
		}
	}
}

// selectTrapCommunity picks the v2c trap community deterministically (#2989).
// SNMPConfig.Communities is a Go map, whose iteration order is randomized, so
// ranging over it and breaking on the first entry produced a different
// community per process run when more than one community was configured —
// collectors that accept only one community saw flaky traps and a less
// privileged community could leak through the wrong credential boundary. We
// instead pick the lexicographically-first configured community, a stable and
// predictable selection. When no community is configured the v2c default
// "public" is used (the configured set authorizes the trap on the wire and an
// empty set has no on-wire credential to assert).
func selectTrapCommunity(cfg *config.SNMPConfig) string {
	if cfg == nil || len(cfg.Communities) == 0 {
		return "public"
	}
	names := make([]string, 0, len(cfg.Communities))
	for name := range cfg.Communities {
		names = append(names, name)
	}
	sort.Strings(names)
	return names[0]
}

// sortedTrapGroups returns the configured trap groups in deterministic
// (name-sorted) order. The TrapGroups map iteration order is randomized; a
// stable order keeps dispatch and log output reproducible.
func sortedTrapGroups(cfg *config.SNMPConfig) []*config.SNMPTrapGroup {
	if cfg == nil || len(cfg.TrapGroups) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.TrapGroups))
	for name := range cfg.TrapGroups {
		names = append(names, name)
	}
	sort.Strings(names)
	groups := make([]*config.SNMPTrapGroup, 0, len(names))
	for _, name := range names {
		groups = append(groups, cfg.TrapGroups[name])
	}
	return groups
}
