package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// flowSessionAction marks a parsed-args terminal subcommand of
// `show security flow session` (summary / sort-by top-talkers), as
// distinct from the default per-session listing.
type flowSessionAction int

const (
	flowSessionList flowSessionAction = iota
	flowSessionSummary
	flowSessionSortBy
)

func flowSessionActionName(a flowSessionAction) string {
	switch a {
	case flowSessionSummary:
		return "summary"
	case flowSessionSortBy:
		return "sort-by"
	default:
		return "list"
	}
}

// flowSessionParse is the strict parse result for the remote
// `show security flow session` argument vector.
type flowSessionParse struct {
	req       *pb.GetSessionsRequest
	brief     bool
	action    flowSessionAction
	sortKey   string
	hasFilter bool // a traffic-filter predicate token was supplied
}

// parseFlowSessionArgs strictly parses the remote-CLI session filter
// tokens. Unlike the historical loop — which used `if ...; err == nil`
// with no else and had no default case — it surfaces operator-input
// errors instead of silently dropping the token: a dropped numeric
// value (e.g. `destination-port abc`) left the field zero (= wildcard)
// and silently WIDENED the inspected set, and an unknown token fell
// through and was ignored. This mirrors the strict local parser in
// pkg/cli/session_filter.go so the two CLI surfaces agree on identical
// command shapes (#3439 H5).
func parseFlowSessionArgs(args []string) (*flowSessionParse, error) {
	p := &flowSessionParse{req: &pb.GetSessionsRequest{Limit: 100, IncludePeer: true}}
	takeValue := func(i *int, kw string) (string, error) {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("missing value for %q", kw)
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			v, err := takeValue(&i, "zone")
			if err != nil {
				return nil, err
			}
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid zone %q", v)
			}
			p.req.Zone = uint32(n)
			p.hasFilter = true
		case "protocol":
			v, err := takeValue(&i, "protocol")
			if err != nil {
				return nil, err
			}
			// Lenient: accept any protocol NAME the system still
			// displays (e.g. "ipv6"=41) plus the strict name/numeric set,
			// so a displayable protocol is never rejected (#3439, #3393).
			if _, ok := appid.ProtocolNumberLenient(v); !ok {
				return nil, fmt.Errorf("unknown protocol %q", v)
			}
			p.req.Protocol = strings.ToUpper(v)
			p.hasFilter = true
		case "source-prefix":
			v, err := takeValue(&i, "source-prefix")
			if err != nil {
				return nil, err
			}
			p.req.SourcePrefix = v
			p.hasFilter = true
		case "destination-prefix":
			v, err := takeValue(&i, "destination-prefix")
			if err != nil {
				return nil, err
			}
			p.req.DestinationPrefix = v
			p.hasFilter = true
		case "source-port":
			v, err := takeValue(&i, "source-port")
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("invalid source-port %q", v)
			}
			p.req.SourcePort = uint32(n)
			p.hasFilter = true
		case "destination-port":
			v, err := takeValue(&i, "destination-port")
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("invalid destination-port %q", v)
			}
			p.req.DestinationPort = uint32(n)
			p.hasFilter = true
		case "nat", "nat-only":
			p.req.NatOnly = true
			p.hasFilter = true
		case "limit":
			v, err := takeValue(&i, "limit")
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return nil, fmt.Errorf("invalid limit %q", v)
			}
			p.req.Limit = int32(n)
		case "application":
			v, err := takeValue(&i, "application")
			if err != nil {
				return nil, err
			}
			p.req.Application = v
			p.hasFilter = true
		case "summary":
			p.action = flowSessionSummary
		case "brief":
			p.brief = true
		case "interface":
			v, err := takeValue(&i, "interface")
			if err != nil {
				return nil, err
			}
			p.req.InterfaceFilter = v
			p.hasFilter = true
		case "source-nat-pool":
			v, err := takeValue(&i, "source-nat-pool")
			if err != nil {
				return nil, err
			}
			p.req.SourceNatPool = v
			p.hasFilter = true
		case "sort-by":
			v, err := takeValue(&i, "sort-by")
			if err != nil {
				return nil, err
			}
			p.action = flowSessionSortBy
			p.sortKey = v
		default:
			return nil, fmt.Errorf("unknown session filter %q", args[i])
		}
	}
	// `summary` and `sort-by` are global aggregations on this remote
	// surface: the summary RPC (GetSessionSummary) takes no filter, and
	// the top-talkers path walks the whole table. Earlier they parsed a
	// filter and then SILENTLY ignored it — the #3439 silent-drop bug in
	// a different sub-path. Reject the combination with a clear error
	// instead of returning an unfiltered result the operator did not ask
	// for (use the filtered per-session listing for a narrowed view).
	if p.hasFilter && p.action != flowSessionList {
		return nil, fmt.Errorf("session filters cannot be combined with %q", flowSessionActionName(p.action))
	}
	return p, nil
}

func (c *ctl) showFlowSession(args []string) error {
	p, err := parseFlowSessionArgs(args)
	if err != nil {
		return err
	}
	if p.action == flowSessionSummary {
		return c.showSessionSummary()
	}
	if p.action == flowSessionSortBy {
		return c.showText("sessions-top:" + p.sortKey)
	}
	req := p.req
	brief := p.brief

	resp, err := c.client.GetSessions(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	hasPeer := resp.Peer != nil

	if hasPeer {
		printNodeSessionHeader(int(resp.NodeId))
	}
	printSessionEntries(resp, brief)

	if hasPeer {
		fmt.Println()
		printNodeSessionHeader(int(resp.Peer.NodeId))
		printSessionEntries(resp.Peer, brief)
	}
	return nil
}

func printNodeSessionHeader(nodeID int) {
	fmt.Printf("node%d:\n", nodeID)
	fmt.Println("--------------------------------------------------------------------------")
}

func printSessionEntries(resp *pb.GetSessionsResponse, brief bool) {
	if brief {
		fmt.Printf("%-5s %-22s %-22s %-5s %-20s %-3s %-5s %5s %s\n",
			"ID", "Source", "Destination", "Proto", "Zone", "NAT", "State", "Age", "Pkts(f/r)")
		for i, se := range resp.Sessions {
			inZone := se.IngressZoneName
			if inZone == "" {
				inZone = fmt.Sprintf("%d", se.IngressZone)
			}
			outZone := se.EgressZoneName
			if outZone == "" {
				outZone = fmt.Sprintf("%d", se.EgressZone)
			}
			natFlag := " "
			if se.Nat != "" {
				if strings.Contains(se.Nat, "SNAT") {
					natFlag = "S"
				}
				if strings.Contains(se.Nat, "DNAT") || strings.HasPrefix(se.Nat, "dst") {
					natFlag = "D"
				}
			}
			st := se.State
			if len(st) > 5 {
				st = st[:5]
			}
			sid := se.SessionId
			if sid == 0 {
				sid = uint64(resp.Offset) + uint64(i) + 1
			}
			fmt.Printf("%-5d %-22s %-22s %-5s %-20s %-3s %-5s %5d %d/%d\n",
				sid,
				fmt.Sprintf("%s/%d", se.SrcAddr, se.SrcPort),
				fmt.Sprintf("%s/%d", se.DstAddr, se.DstPort),
				se.Protocol, inZone+"->"+outZone, natFlag,
				st, se.AgeSeconds,
				se.FwdPackets, se.RevPackets)
		}
		fmt.Printf("Total sessions: %d\n", resp.Total)
		return
	}

	for i, se := range resp.Sessions {
		polDisplay := se.PolicyName
		if polDisplay == "" {
			polDisplay = fmt.Sprintf("%d", se.PolicyId)
		}
		sid := se.SessionId
		if sid == 0 {
			sid = uint64(resp.Offset) + uint64(i) + 1
		}

		haStr := ""
		if se.HaActive {
			haStr = "Active"
		} else {
			haStr = "Backup"
		}
		fmt.Printf("Session ID: %d, Policy name: %s/%d, HA State: %s, Timeout: %d, Session State: Valid\n",
			sid, polDisplay, se.PolicyId, haStr, se.TimeoutSeconds)

		inIf := se.IngressInterface
		if inIf == "" {
			inIf = se.IngressZoneName
		}
		inZone := se.IngressZoneName
		if inZone == "" {
			inZone = fmt.Sprintf("%d", se.IngressZone)
		}
		fmt.Printf("  In: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
			se.SrcAddr, se.SrcPort, se.DstAddr, se.DstPort,
			se.Protocol, inIf, inZone, se.FwdPackets, se.FwdBytes)

		outSrcAddr := se.DstAddr
		outSrcPort := se.DstPort
		outDstAddr := se.SrcAddr
		outDstPort := se.SrcPort
		if se.NatSrcAddr != "" {
			outDstAddr = se.NatSrcAddr
			outDstPort = se.NatSrcPort
		}
		if se.NatDstAddr != "" {
			outSrcAddr = se.NatDstAddr
			outSrcPort = se.NatDstPort
		}
		outIf := se.EgressInterface
		if outIf == "" {
			outIf = se.EgressZoneName
		}
		outZone := se.EgressZoneName
		if outZone == "" {
			outZone = fmt.Sprintf("%d", se.EgressZone)
		}
		fmt.Printf("  Out: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
			outSrcAddr, outSrcPort, outDstAddr, outDstPort,
			se.Protocol, outIf, outZone, se.RevPackets, se.RevBytes)
		fmt.Println()
	}
	fmt.Printf("Total sessions: %d\n", resp.Total)
}

func (c *ctl) showSessionSummary() error {
	resp, err := c.client.GetSessionSummary(c.ctx(), &pb.GetSessionSummaryRequest{IncludePeer: true})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	if resp.Peer != nil {
		printNodeSessionSummary(int(resp.NodeId), resp)
		fmt.Println()
		printNodeSessionSummary(int(resp.Peer.NodeId), resp.Peer)
	} else {
		printSessionSummaryBlock(resp)
	}
	return nil
}

func printNodeSessionSummary(nodeID int, resp *pb.GetSessionSummaryResponse) {
	fmt.Printf("node%d:\n", nodeID)
	fmt.Println("--------------------------------------------------------------------------")
	printSessionSummaryBlock(resp)
}

func printSessionSummaryBlock(resp *pb.GetSessionSummaryResponse) {
	unicast := resp.ForwardOnly
	fmt.Printf("Unicast-sessions: %d\n", unicast)
	fmt.Printf("Multicast-sessions: 0\n")
	fmt.Printf("Services-offload-sessions: 0\n")
	fmt.Printf("Failed-sessions: 0\n")
	fmt.Printf("Sessions-in-drop-flow: 0\n")
	fmt.Printf("Sessions-in-use: %d\n", unicast)
	fmt.Printf("  Valid sessions: %d\n", unicast)
	fmt.Printf("  Pending sessions: 0\n")
	fmt.Printf("  Invalidated sessions: 0\n")
	fmt.Printf("  Sessions in other states: 0\n")
	fmt.Printf("Maximum-sessions: 10000000\n")
}

func (c *ctl) showFlowStatistics() error {
	resp, err := c.client.GetGlobalStats(c.ctx(), &pb.GetGlobalStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	fmt.Println("Flow statistics:")
	fmt.Printf("  %-30s %d\n", "Current sessions:", resp.SessionsCreated-resp.SessionsClosed)
	fmt.Printf("  %-30s %d\n", "Sessions created:", resp.SessionsCreated)
	fmt.Printf("  %-30s %d\n", "Sessions closed:", resp.SessionsClosed)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Packets received:", resp.RxPackets)
	fmt.Printf("  %-30s %d\n", "Packets transmitted:", resp.TxPackets)
	fmt.Printf("  %-30s %d\n", "Packets dropped:", resp.Drops)
	fmt.Printf("  %-30s %d\n", "TC egress packets:", resp.TcEgressPackets)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Policy deny:", resp.PolicyDenies)
	fmt.Printf("  %-30s %d\n", "NAT allocation failures:", resp.NatAllocFailures)
	fmt.Printf("  %-30s %d\n", "NAT64 translations:", resp.Nat64Translations)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Host-inbound allowed:", resp.HostInboundAllowed)
	fmt.Printf("  %-30s %d\n", "Host-inbound denied:", resp.HostInboundDenies)

	if resp.ScreenDrops > 0 {
		fmt.Println()
		fmt.Printf("  %-30s %d\n", "Screen drops (total):", resp.ScreenDrops)
		for name, count := range resp.ScreenDropDetails {
			fmt.Printf("    %-28s %d\n", name+":", count)
		}
	}

	return nil
}
