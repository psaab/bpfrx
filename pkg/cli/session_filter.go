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

	// parseErr records an operator-input error detected while
	// parsing filter tokens (unknown protocol, missing value,
	// unparseable prefix/port). It MUST fail the command via
	// validate(): a silently-dropped token leaves its predicate
	// inert, and on the clear path an all-tokens-dropped filter
	// makes hasFilter() false — i.e. clear-ALL.
	parseErr error

	// source-nat-pool filter (#1827 PR-3): match sessions whose
	// TRANSLATED source address was allocated from the named pool —
	// the operator handle for sessions pinned to a failed uplink's
	// SNAT binding after an ip-monitoring transition.
	snatPool     string       // pool name ("" = off)
	snatPoolNets []*net.IPNet // resolved pool address set
	snatPoolOK   bool         // pool name resolved to a configured source pool

	// Populated by populateIfaceMaps (show + clear paths) for
	// interface matching.
	//
	// #4792: zoneIfaces holds EVERY interface bound to a zone, not just
	// the first. A single-value map meant a session ingressing (or, via
	// the resolveEgressIfaces zone fallback, egressing) on the 2nd+
	// interface of a multi-interface zone was silently invisible to
	// `show security flow session interface <name>` / the matching
	// `clear` — the interface never matched anything, so a filtered show
	// undercounted and a filtered clear left sessions behind.
	zoneIfaces      map[uint16][]string        // zone ID → all bound interface names
	egressIfacesMap map[sessionIfaceKey]string // {ifindex,vlanID} → interface name
}

// parseSessionFilter parses session-selector and presentation tokens for
// the SHOW path, where display modifiers (summary/brief/sort-by) are
// legal.
func (c *CLI) parseSessionFilter(args []string) sessionFilter {
	return c.parseSessionFilterMode(args, false)
}

// parseClearSessionFilter parses session-selector tokens for the CLEAR
// path. Presentation-only modifiers (summary/brief/sort-by) are NOT clear
// predicates and MUST be rejected: the shared show/clear parser accepted
// them but hasFilter() excluded all three, so a pasted show-syntax token
// like `clear security flow session summary` fell through to
// ClearAllSessions plus an unfiltered peer clear — the most destructive
// path on both HA nodes (#5066). Rejecting them makes an EXACTLY-empty
// token list the only selector that means clear-all. (The remote CLI's
// clear parser in cmd/cli already rejects these; this brings the local
// interactive CLI to the same fail-closed posture.)
func (c *CLI) parseClearSessionFilter(args []string) sessionFilter {
	return c.parseSessionFilterMode(args, true)
}

// parseSessionFilterMode is the shared implementation. clearMode rejects
// presentation-only tokens (see parseClearSessionFilter); the show path
// passes clearMode=false and additionally validates the sort-by value.
func (c *CLI) parseSessionFilterMode(args []string, clearMode bool) sessionFilter {
	var f sessionFilter
	f.cfg = c.store.ActiveConfig()
	cr := c.applyResult()
	if cr != nil {
		f.appNames = cr.AppNames
	}
	// takeValue consumes the value token for a valued keyword. A
	// trailing keyword without a value is a parse error — historically
	// it was silently skipped, leaving the filter empty, which on the
	// clear path means clear-ALL.
	takeValue := func(i *int, kw string) (string, bool) {
		if *i+1 >= len(args) {
			f.setParseErr(fmt.Errorf("missing value for %q", kw))
			return "", false
		}
		*i++
		return args[*i], true
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if v, ok := takeValue(&i, "zone"); ok {
				f.zoneName = v
				if cr != nil {
					f.zoneID = cr.ZoneIDs[v]
				}
			}
		case "protocol":
			if v, ok := takeValue(&i, "protocol"); ok {
				switch strings.ToLower(v) {
				case "tcp":
					f.proto = 6
				case "udp":
					f.proto = 17
				case "icmp":
					f.proto = 1
				case "icmpv6":
					f.proto = dataplane.ProtoICMPv6
				default:
					// Numeric IP protocol (Junos accepts numbers);
					// anything else must error, not silently drop
					// the predicate.
					if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 256 {
						f.proto = uint8(n)
					} else {
						f.setParseErr(fmt.Errorf("unknown protocol %q", v))
					}
				}
			}
		case "source-prefix":
			if v, ok := takeValue(&i, "source-prefix"); ok {
				if !strings.Contains(v, "/") {
					if strings.Contains(v, ":") {
						v += "/128"
					} else {
						v += "/32"
					}
				}
				_, ipNet, err := net.ParseCIDR(v)
				if err != nil {
					f.setParseErr(fmt.Errorf("invalid source-prefix %q", v))
				} else {
					f.srcNet = ipNet
				}
			}
		case "destination-prefix":
			if v, ok := takeValue(&i, "destination-prefix"); ok {
				if !strings.Contains(v, "/") {
					if strings.Contains(v, ":") {
						v += "/128"
					} else {
						v += "/32"
					}
				}
				_, ipNet, err := net.ParseCIDR(v)
				if err != nil {
					f.setParseErr(fmt.Errorf("invalid destination-prefix %q", v))
				} else {
					f.dstNet = ipNet
				}
			}
		case "source-port":
			if v, ok := takeValue(&i, "source-port"); ok {
				if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
					f.srcPort = uint16(n)
				} else {
					f.setParseErr(fmt.Errorf("invalid source-port %q", v))
				}
			}
		case "destination-port":
			if v, ok := takeValue(&i, "destination-port"); ok {
				if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
					f.dstPort = uint16(n)
				} else {
					f.setParseErr(fmt.Errorf("invalid destination-port %q", v))
				}
			}
		case "nat", "nat-only":
			f.natOnly = true
		case "interface":
			if v, ok := takeValue(&i, "interface"); ok {
				f.iface = v
			}
		case "source-nat-pool":
			if v, ok := takeValue(&i, "source-nat-pool"); ok {
				f.snatPool = v
				if f.cfg != nil {
					f.snatPoolNets, f.snatPoolOK = config.SourceNATPoolNets(&f.cfg.Security.NAT, f.snatPool)
				}
			}
		case "application":
			if v, ok := takeValue(&i, "application"); ok {
				f.appName = v
			}
		case "summary":
			if clearMode {
				f.setParseErr(errDisplayModifierOnClear("summary"))
			} else {
				f.summary = true
			}
		case "brief":
			if clearMode {
				f.setParseErr(errDisplayModifierOnClear("brief"))
			} else {
				f.brief = true
			}
		case "sort-by":
			if v, ok := takeValue(&i, "sort-by"); ok {
				switch {
				case clearMode:
					f.setParseErr(errDisplayModifierOnClear("sort-by"))
				case v != "bytes" && v != "packets":
					// Validate the sort key on the show path: an unknown
					// value silently degraded to a plain session list
					// instead of the requested top-talkers view.
					f.setParseErr(fmt.Errorf("invalid sort-by %q (expected \"bytes\" or \"packets\")", v))
				default:
					f.sortBy = v
				}
			}
		default:
			f.setParseErr(fmt.Errorf("unknown session filter %q", args[i]))
		}
	}
	return f
}

// errDisplayModifierOnClear builds the parse error for a presentation-only
// token supplied on the clear path. These tokens are display modifiers
// (they change how sessions are rendered, not which sessions are
// selected), so accepting one on `clear security flow session` would
// leave the selector empty and clear the entire table (#5066).
func errDisplayModifierOnClear(tok string) error {
	return fmt.Errorf("%q is a display modifier, not valid for clear", tok)
}

// setParseErr records the first parse error (the first is the most
// useful to show the operator).
func (f *sessionFilter) setParseErr(err error) {
	if f.parseErr == nil {
		f.parseErr = err
	}
}

func (f *sessionFilter) matchesV4(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	if f.zoneID != 0 && val.IngressZone != f.zoneID && val.EgressZone != f.zoneID {
		return false
	}
	if f.iface != "" {
		inIfs := f.zoneIfaces[val.IngressZone]
		outIfs := f.resolveEgressIfaces(val.FibIfindex, val.FibVlanID, val.EgressZone)
		if !f.ifaceMatchesAny(inIfs) && !f.ifaceMatchesAny(outIfs) {
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
			key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID) {
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
		inIfs := f.zoneIfaces[val.IngressZone]
		outIfs := f.resolveEgressIfaces(val.FibIfindex, val.FibVlanID, val.EgressZone)
		if !f.ifaceMatchesAny(inIfs) && !f.ifaceMatchesAny(outIfs) {
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
			key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID) {
			return false
		}
	}
	return true
}

func (f *sessionFilter) hasFilter() bool {
	return f.parseErr != nil || f.zoneID != 0 || f.zoneName != "" || f.proto != 0 ||
		f.srcNet != nil || f.dstNet != nil || f.srcPort != 0 || f.dstPort != 0 ||
		f.natOnly || f.iface != "" || f.appName != "" || f.snatPool != ""
}

// validate reports operator-input errors that must fail the command
// rather than silently match nothing — or, on the clear path, fall
// through to an unfiltered clear-all.
func (f *sessionFilter) validate() error {
	if f.parseErr != nil {
		return f.parseErr
	}
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
	zoneIfaces := make(map[uint16][]string)
	if cr := c.applyResult(); cr != nil && f.cfg != nil {
		for zoneName, zone := range f.cfg.Security.Zones {
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			if zid, ok := cr.ZoneIDs[zoneName]; ok && len(zone.Interfaces) > 0 {
				// #4792: keep EVERY interface bound to the zone, not just
				// the first — a zone with multiple member interfaces
				// otherwise loses visibility into sessions on the 2nd+.
				zoneIfaces[zid] = append(zoneIfaces[zid], zone.Interfaces...)
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

// ifaceMatchesAny reports whether ANY of ifNames matches the filter's
// interface name (see ifaceMatches). Used against a zone's full interface
// list (#4792) instead of assuming a zone binds exactly one interface.
func (f *sessionFilter) ifaceMatchesAny(ifNames []string) bool {
	for _, ifName := range ifNames {
		if f.ifaceMatches(ifName) {
			return true
		}
	}
	return false
}

// resolveEgressIfaces resolves a session's candidate egress interface
// names: a precise single-element result from the FIB lookup when
// available, otherwise EVERY interface bound to the egress zone (#4792 —
// a zone can bind more than one interface, so a single fallback name
// silently missed sessions egressing on any interface but the first).
func (f *sessionFilter) resolveEgressIfaces(fibIfindex uint32, fibVlanID uint16, egressZone uint16) []string {
	if fibIfindex != 0 {
		if ifName, ok := f.egressIfacesMap[sessionIfaceKey{ifindex: fibIfindex, vlanID: fibVlanID}]; ok && ifName != "" {
			return []string{ifName}
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
	// #6851/#4626: the on-box CLI dials the peer DIRECTLY (dialPeer above), so
	// it never passes through the grpcapi fan-out that sanitizes reserved
	// policy ids — and it sets no IncludePeer, so the peer skips its own
	// fan-out too. Against a pre-#4626 peer the response therefore carries
	// that peer's FIRST CONFIGURED POLICY as the name for every session
	// stamped with reserved id 0 (host-inbound, fabric, tunnel, and its whole
	// table if it is in turn syncing from an older node), and `show security
	// flow session` printed it verbatim.
	//
	// Sanitizing HERE rather than at the render site is deliberate: this is the
	// CLI's own single ingress for peer sessions, so a future render site
	// cannot reintroduce the bypass by forgetting to call the helper.
	sanitizePeerSessionPolicyNames(resp)
	return resp
}

// sanitizePeerSessionPolicyNames rewrites the policy name of every peer session
// carrying a RESERVED id, in place (#6851).
//
// It mirrors grpcapi sanitizePeerPolicyNames — the two exist because the two
// surfaces reach the peer by different routes, not because they disagree. Both
// delegate the decision to dataplane.PeerSessionPolicyName, which is the single
// place that knows which ids are reserved; neither re-resolves an unreserved id
// against the LOCAL map, because the peer's own resolution is authoritative for
// the peer's sessions.
func sanitizePeerSessionPolicyNames(resp *pb.GetSessionsResponse) {
	if resp == nil {
		return
	}
	for _, e := range resp.GetSessions() {
		if e == nil {
			continue
		}
		e.PolicyName = dataplane.PeerSessionPolicyName(e.GetPolicyName(), e.GetPolicyId())
	}
	// A peer that itself fanned out would nest another response here. The CLI
	// does not request that (no IncludePeer), but guard it rather than rely on
	// an invariant that holds only for the current peer version.
	sanitizePeerSessionPolicyNames(resp.GetPeer())
}

// peerSessionsTotal returns the "Total sessions" count to render for a
// peer session-detail response.
//
// A CURRENT server (#5034 / C175-HC-073) returns the REAL filtered total in
// Total — an exact forward-only count of filter-matching sessions — which
// is rendered directly. It is deliberately preferred over len(resp.Sessions):
// the peer caps its returned list (limit 10000), so len() undercounts a
// large filtered set, whereas Total is the true count.
//
// The -1-sentinel fallback is RETAINED for mixed-version clusters (ISSU /
// rolling upgrade): a peer is a SEPARATE binary, and a pre-#5034 peer still
// emits Total=-1 for a filtered query. Rendering that raw would re-expose
// the #4908/#5033 "Total sessions: -1" display bug during the upgrade
// window, so a negative Total falls back to the returned-count exactly as
// #5033 did. Once both nodes run #5034+, Total is always non-negative and
// this branch is dead.
func peerSessionsTotal(resp *pb.GetSessionsResponse) int32 {
	if resp == nil {
		return 0
	}
	if t := resp.GetTotal(); t >= 0 {
		return t
	}
	return int32(len(resp.GetSessions()))
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
