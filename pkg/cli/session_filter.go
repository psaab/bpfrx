// Session-table filter parsing and matching, plus the two peer-RPC
// fetchers that take a `sessionFilter` as their primary input. The
// fetchers translate filter fields to RPC request fields, so they are
// co-located with the filter type for cohesion.
package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// sessionFilter holds parsed filter criteria for session display.
type sessionFilter struct {
	zoneID   uint16 // 0 = any
	zoneName string // zone filter as typed (for peer forwarding)
	proto    uint8  // 0 = any
	srcNet   *net.IPNet
	dstNet   *net.IPNet
	srcPort  uint16         // 0 = any (host byte order; keys are network order)
	dstPort  uint16         // 0 = any (host byte order; keys are network order)
	natOnly  bool           // show only NAT sessions
	iface    string         // ingress/egress interface name filter
	summary  bool           // only show count
	brief    bool           // compact tabular view
	appName  string         // application name filter
	sortBy   string         // "bytes" or "packets" for top-talkers
	cfg      *config.Config // for application resolution
	appNames map[uint16]string

	// source-nat-pool filter (#1827 PR-3): match sessions whose
	// TRANSLATED source address was allocated from the named pool —
	// the operator handle for sessions pinned to a failed uplink's
	// SNAT binding after an ip-monitoring transition.
	snatPool     string       // pool name ("" = off)
	snatPoolNets []*net.IPNet // resolved pool address set
	snatPoolOK   bool         // pool name resolved to a configured source pool

	// Populated by populateIfaceMaps (show + clear paths) for
	// interface matching.
	zoneIfaces      map[uint16]string          // zone ID → first interface name
	egressIfacesMap map[sessionIfaceKey]string // {ifindex,vlanID} → interface name
}

func (c *CLI) parseSessionFilter(args []string) sessionFilter {
	var f sessionFilter
	f.cfg = c.store.ActiveConfig()
	cr := c.applyResult()
	if cr != nil {
		f.appNames = cr.AppNames
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 < len(args) {
				i++
				f.zoneName = args[i]
				if cr != nil {
					f.zoneID = cr.ZoneIDs[args[i]]
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				switch strings.ToLower(args[i]) {
				case "tcp":
					f.proto = 6
				case "udp":
					f.proto = 17
				case "icmp":
					f.proto = 1
				case "icmpv6":
					f.proto = dataplane.ProtoICMPv6
				}
			}
		case "source-prefix":
			if i+1 < len(args) {
				i++
				cidr := args[i]
				if !strings.Contains(cidr, "/") {
					if strings.Contains(cidr, ":") {
						cidr += "/128"
					} else {
						cidr += "/32"
					}
				}
				_, ipNet, err := net.ParseCIDR(cidr)
				if err == nil {
					f.srcNet = ipNet
				}
			}
		case "destination-prefix":
			if i+1 < len(args) {
				i++
				cidr := args[i]
				if !strings.Contains(cidr, "/") {
					if strings.Contains(cidr, ":") {
						cidr += "/128"
					} else {
						cidr += "/32"
					}
				}
				_, ipNet, err := net.ParseCIDR(cidr)
				if err == nil {
					f.dstNet = ipNet
				}
			}
		case "source-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					f.srcPort = uint16(v)
				}
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					f.dstPort = uint16(v)
				}
			}
		case "nat", "nat-only":
			f.natOnly = true
		case "interface":
			if i+1 < len(args) {
				i++
				f.iface = args[i]
			}
		case "source-nat-pool":
			if i+1 < len(args) {
				i++
				f.snatPool = args[i]
				if f.cfg != nil {
					f.snatPoolNets, f.snatPoolOK = config.SourceNATPoolNets(&f.cfg.Security.NAT, f.snatPool)
				}
			}
		case "application":
			if i+1 < len(args) {
				i++
				f.appName = args[i]
			}
		case "summary":
			f.summary = true
		case "brief":
			f.brief = true
		case "sort-by":
			if i+1 < len(args) {
				i++
				f.sortBy = args[i] // "bytes" or "packets"
			}
		}
	}
	return f
}

func (f *sessionFilter) matchesV4(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	if f.zoneID != 0 && val.IngressZone != f.zoneID && val.EgressZone != f.zoneID {
		return false
	}
	if f.iface != "" {
		inIf := f.zoneIfaces[val.IngressZone]
		outIf := f.resolveEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone)
		if !f.ifaceMatches(inIf) && !f.ifaceMatches(outIf) {
			return false
		}
	}
	if f.proto != 0 && key.Protocol != f.proto {
		return false
	}
	if f.srcNet != nil && !f.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if f.dstNet != nil && !f.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	// Key ports are network byte order; filter ports are host order.
	if f.srcPort != 0 && ntohs(key.SrcPort) != f.srcPort {
		return false
	}
	if f.dstPort != 0 && ntohs(key.DstPort) != f.dstPort {
		return false
	}
	if f.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
		return false
	}
	if f.snatPool != "" {
		if val.Flags&dataplane.SessFlagSNAT == 0 ||
			!config.IPInNets(uint32ToIP(val.NATSrcIP), f.snatPoolNets) {
			return false
		}
	}
	if f.appName != "" {
		if !appid.SessionMatches(f.appName, f.appNames, f.cfg,
			key.Protocol, ntohs(key.DstPort), val.AppID) {
			return false
		}
	}
	return true
}

func (f *sessionFilter) matchesV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
	if f.zoneID != 0 && val.IngressZone != f.zoneID && val.EgressZone != f.zoneID {
		return false
	}
	if f.iface != "" {
		inIf := f.zoneIfaces[val.IngressZone]
		outIf := f.resolveEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone)
		if !f.ifaceMatches(inIf) && !f.ifaceMatches(outIf) {
			return false
		}
	}
	if f.proto != 0 && key.Protocol != f.proto {
		return false
	}
	if f.srcNet != nil && !f.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if f.dstNet != nil && !f.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	// Key ports are network byte order; filter ports are host order.
	if f.srcPort != 0 && ntohs(key.SrcPort) != f.srcPort {
		return false
	}
	if f.dstPort != 0 && ntohs(key.DstPort) != f.dstPort {
		return false
	}
	if f.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
		return false
	}
	if f.snatPool != "" {
		if val.Flags&dataplane.SessFlagSNAT == 0 ||
			!config.IPInNets(net.IP(val.NATSrcIP[:]), f.snatPoolNets) {
			return false
		}
	}
	if f.appName != "" {
		if !appid.SessionMatches(f.appName, f.appNames, f.cfg,
			key.Protocol, ntohs(key.DstPort), val.AppID) {
			return false
		}
	}
	return true
}

func (f *sessionFilter) hasFilter() bool {
	return f.zoneID != 0 || f.zoneName != "" || f.proto != 0 || f.srcNet != nil || f.dstNet != nil ||
		f.srcPort != 0 || f.dstPort != 0 || f.natOnly || f.iface != "" || f.appName != "" ||
		f.snatPool != ""
}

// validate reports operator-input errors that must fail the command
// rather than silently match nothing — or, on the clear path, fall
// through to an unfiltered clear-all.
func (f *sessionFilter) validate() error {
	if f.snatPool != "" && !f.snatPoolOK {
		return fmt.Errorf("source NAT pool %q not found", f.snatPool)
	}
	if f.zoneName != "" && f.zoneID == 0 {
		return fmt.Errorf("zone %q not found", f.zoneName)
	}
	return nil
}

// populateIfaceMaps fills the zone→interface and {ifindex,vlan}→name
// maps that interface matching in matchesV4/V6 depends on. The show
// path builds these inline (it also needs zone/policy display maps);
// the clear path MUST call this before matching — historically it did
// not, so an interface-filtered clear matched nothing (#1827 PR-3).
func (f *sessionFilter) populateIfaceMaps(c *CLI) {
	zoneIfaces := make(map[uint16]string)
	if cr := c.applyResult(); cr != nil && f.cfg != nil {
		for zoneName, zone := range f.cfg.Security.Zones {
			if zid, ok := cr.ZoneIDs[zoneName]; ok && len(zone.Interfaces) > 0 {
				zoneIfaces[zid] = zone.Interfaces[0]
			}
		}
	}
	f.zoneIfaces = zoneIfaces
	f.egressIfacesMap = buildSessionEgressIfaces(f.cfg)
}

// ifaceMatches checks whether ifName matches the filter's interface name.
// It matches the exact name or the parent interface (e.g. filter "ge-0/0/0"
// matches session interface "ge-0/0/0.50").
func (f *sessionFilter) ifaceMatches(ifName string) bool {
	if ifName == "" {
		return false
	}
	return ifName == f.iface || strings.HasPrefix(ifName, f.iface+".")
}

// resolveEgressIface resolves a session's egress interface name from FIB
// lookup result, falling back to the zone's first interface.
func (f *sessionFilter) resolveEgressIface(fibIfindex uint32, fibVlanID uint16, egressZone uint16) string {
	if fibIfindex != 0 {
		if ifName, ok := f.egressIfacesMap[sessionIfaceKey{ifindex: fibIfindex, vlanID: fibVlanID}]; ok && ifName != "" {
			return ifName
		}
	}
	return f.zoneIfaces[egressZone]
}

func (c *CLI) fetchPeerSessions(f sessionFilter) *pb.GetSessionsResponse {
	conn := c.dialPeer()
	if conn == nil {
		return nil
	}
	defer conn.Close()

	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &pb.GetSessionsRequest{Limit: 10000}
	if f.zoneID != 0 {
		// Zone IDs are config-compile-derived and config is synced
		// across the cluster, so the peer resolves the same ID.
		req.Zone = uint32(f.zoneID)
	}
	if f.proto != 0 {
		req.Protocol = strings.ToUpper(protoNameFromNum(f.proto))
	}
	if f.srcNet != nil {
		req.SourcePrefix = f.srcNet.String()
	}
	if f.dstNet != nil {
		req.DestinationPrefix = f.dstNet.String()
	}
	if f.srcPort != 0 {
		req.SourcePort = uint32(f.srcPort)
	}
	if f.dstPort != 0 {
		req.DestinationPort = uint32(f.dstPort)
	}
	if f.natOnly {
		req.NatOnly = true
	}
	if f.appName != "" {
		req.Application = f.appName
	}
	if f.iface != "" {
		req.InterfaceFilter = f.iface
	}
	if f.snatPool != "" {
		req.SourceNatPool = f.snatPool
	}

	resp, err := client.GetSessions(ctx, req)
	if err != nil {
		slog.Warn("failed to fetch peer sessions", "err", err)
		return nil
	}
	return resp
}

// fetchPeerSessionSummary dials the cluster peer's gRPC and returns its session summary.
func (c *CLI) fetchPeerSessionSummary() *pb.GetSessionSummaryResponse {
	conn := c.dialPeer()
	if conn == nil {
		return nil
	}
	defer conn.Close()

	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := client.GetSessionSummary(ctx, &pb.GetSessionSummaryRequest{})
	if err != nil {
		slog.Warn("failed to fetch peer session summary", "err", err)
		return nil
	}
	return resp
}
