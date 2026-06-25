package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/metadata"
)

func (c *CLI) handleClear(args []string) error {
	clearTree := operationalTree["clear"].Children
	showHelp := func() {
		fmt.Println("clear:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(clearTree))
	}
	if len(args) < 1 {
		showHelp()
		return nil
	}

	switch args[0] {
	case "arp":
		return c.handleClearArp()
	case "ipv6":
		return c.handleClearIPv6(args[1:])
	case "security":
		return c.handleClearSecurity(args[1:])
	case "firewall":
		return c.handleClearFirewall(args[1:])
	case "dhcp":
		return c.handleClearDHCP(args[1:])
	case "interfaces":
		return c.handleClearInterfaces(args[1:])
	case "system":
		return c.handleClearSystem(args[1:])
	default:
		showHelp()
		return nil
	}
}

func (c *CLI) handleClearSystem(args []string) error {
	if len(args) < 1 || args[0] != "config-lock" {
		cmdtree.PrintTreeHelp("clear system:", operationalTree, "clear", "system")
		return nil
	}
	holder, locked := c.store.ConfigHolder()
	if !locked {
		fmt.Println("No configuration lock held")
		return nil
	}
	c.store.ForceExitConfigure()
	fmt.Printf("Configuration lock cleared (was held by %s)\n", holder)
	return nil
}

func (c *CLI) handleClearInterfaces(args []string) error {
	if len(args) >= 1 && args[0] == "statistics" {
		fmt.Println("Interface statistics counters noted")
		fmt.Println("(kernel counters are cumulative and cannot be reset)")
		return nil
	}
	cmdtree.PrintTreeHelp("clear interfaces:", operationalTree, "clear", "interfaces")
	return nil
}

func (c *CLI) handleClearArp() error {
	out, err := exec.Command("ip", "-4", "neigh", "flush", "all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("flush ARP: %s", strings.TrimSpace(string(out)))
	}
	fmt.Println("ARP cache cleared")
	return nil
}

func (c *CLI) handleClearIPv6(args []string) error {
	if len(args) < 1 || args[0] != "neighbors" {
		cmdtree.PrintTreeHelp("clear ipv6:", operationalTree, "clear", "ipv6")
		return nil
	}
	out, err := exec.Command("ip", "-6", "neigh", "flush", "all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("flush IPv6 neighbors: %s", strings.TrimSpace(string(out)))
	}
	fmt.Println("IPv6 neighbor cache cleared")
	return nil
}

func (c *CLI) handleClearSecurity(args []string) error {
	if len(args) < 1 {
		fmt.Println("clear security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["clear"].Children["security"].Children))
		return nil
	}

	switch args[0] {
	case "nat":
		if len(args) >= 3 && args[1] == "source" && args[2] == "persistent-nat-table" {
			return c.clearPersistentNAT()
		}
		if len(args) >= 2 && args[1] == "statistics" {
			if c.dp == nil || !c.dp.IsLoaded() {
				fmt.Println("dataplane not loaded")
				return nil
			}
			if err := c.dp.ClearNATRuleCounters(); err != nil {
				return fmt.Errorf("clear NAT counters: %w", err)
			}
			fmt.Println("NAT translation statistics cleared")
			return nil
		}
		cmdtree.PrintTreeHelp("clear security nat:", operationalTree, "clear", "security", "nat")
		return nil
	case "flow":
		if len(args) < 2 || args[1] != "session" {
			return fmt.Errorf("usage: clear security flow session [filters...]")
		}
		if c.dp == nil || !c.dp.IsLoaded() {
			fmt.Println("dataplane not loaded")
			return nil
		}
		f := c.parseSessionFilter(args[2:])
		if f.hasFilter() {
			return c.clearFilteredSessions(f)
		}
		v4, v6, err := c.dp.ClearAllSessions()
		if err != nil {
			return fmt.Errorf("clear sessions: %w", err)
		}
		fmt.Printf("%d IPv4 and %d IPv6 session entries cleared\n", v4, v6)
		var agg sessionClearErrors
		agg.add("peer clear", c.clearPeerSessions(nil))
		agg.report()
		return nil

	case "policies":
		if len(args) >= 2 && args[1] == "hit-count" {
			if c.dp == nil || !c.dp.IsLoaded() {
				fmt.Println("dataplane not loaded")
				return nil
			}
			if err := c.dp.ClearPolicyCounters(); err != nil {
				return fmt.Errorf("clear policy counters: %w", err)
			}
			fmt.Println("policy hit counters cleared")
			return nil
		}
		return fmt.Errorf("usage: clear security policies hit-count")

	case "counters":
		if c.dp == nil || !c.dp.IsLoaded() {
			fmt.Println("dataplane not loaded")
			return nil
		}
		if err := c.dp.ClearAllCounters(); err != nil {
			return fmt.Errorf("clear counters: %w", err)
		}
		fmt.Println("all counters cleared")
		return nil

	default:
		cmdtree.PrintTreeHelp("clear security:", operationalTree, "clear", "security")
		return nil
	}
}

func (c *CLI) clearFilteredSessions(f sessionFilter) error {
	// Operator-input errors must fail the command: an unresolvable
	// zone or pool name would otherwise leave its predicate inert and
	// silently widen (or void) the clear.
	if err := f.validate(); err != nil {
		return err
	}
	// Interface matching needs the zone/egress interface maps; the
	// show path builds them inline, the clear path must do it too —
	// without this an interface-filtered clear matches nothing.
	f.populateIfaceMaps(c)

	v4Deleted := 0
	v6Deleted := 0
	var agg sessionClearErrors

	var v4Keys []dataplane.SessionKey
	var v4RevKeys []dataplane.SessionKey
	var snatDNATKeys []dataplane.DNATKey
	// Enumeration failure must be surfaced: a partial scan silently
	// skips sessions the operator asked to clear (#2468).
	agg.add("v4 iterate", c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !f.matchesV4(key, val) {
			return true
		}
		v4Keys = append(v4Keys, key)
		v4RevKeys = append(v4RevKeys, dataplane.SessionKey{
			Protocol: key.Protocol,
			SrcIP:    key.DstIP,
			DstIP:    key.SrcIP,
			SrcPort:  key.DstPort,
			DstPort:  key.SrcPort,
		})
		if val.Flags&dataplane.SessFlagSNAT != 0 &&
			val.Flags&dataplane.SessFlagStaticNAT == 0 {
			snatDNATKeys = append(snatDNATKeys, dataplane.DNATKey{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
			})
		}
		return true
	}))

	for _, key := range v4Keys {
		if err := c.dp.DeleteSession(key); err != nil {
			agg.add("v4 forward delete", err)
		} else {
			v4Deleted++
		}
	}
	for _, key := range v4RevKeys {
		agg.addExceptNotFound("v4 reverse delete", c.dp.DeleteSession(key))
	}
	for _, dk := range snatDNATKeys {
		agg.addExceptNotFound("v4 DNAT companion delete", c.dp.DeleteDNATEntry(dk))
	}

	var v6Keys []dataplane.SessionKeyV6
	var v6RevKeys []dataplane.SessionKeyV6
	var snatDNATKeysV6 []dataplane.DNATKeyV6
	agg.add("v6 iterate", c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !f.matchesV6(key, val) {
			return true
		}
		v6Keys = append(v6Keys, key)
		v6RevKeys = append(v6RevKeys, dataplane.SessionKeyV6{
			Protocol: key.Protocol,
			SrcIP:    key.DstIP,
			DstIP:    key.SrcIP,
			SrcPort:  key.DstPort,
			DstPort:  key.SrcPort,
		})
		if val.Flags&dataplane.SessFlagSNAT != 0 &&
			val.Flags&dataplane.SessFlagStaticNAT == 0 {
			snatDNATKeysV6 = append(snatDNATKeysV6, dataplane.DNATKeyV6{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
			})
		}
		return true
	}))

	for _, key := range v6Keys {
		if err := c.dp.DeleteSessionV6(key); err != nil {
			agg.add("v6 forward delete", err)
		} else {
			v6Deleted++
		}
	}
	for _, key := range v6RevKeys {
		agg.addExceptNotFound("v6 reverse delete", c.dp.DeleteSessionV6(key))
	}
	for _, dk := range snatDNATKeysV6 {
		agg.addExceptNotFound("v6 DNAT companion delete", c.dp.DeleteDNATEntryV6(dk))
	}

	fmt.Printf("%d IPv4 and %d IPv6 matching sessions cleared\n", v4Deleted, v6Deleted)
	agg.add("peer clear", c.clearPeerSessions(&f))
	agg.report()
	return nil
}

// sessionClearErrors accumulates per-operation failures during a CLI
// session clear (iterator, forward/reverse/companion deletes, and the
// HA peer-clear RPC) so the operator sees the full failure picture
// instead of a bare success line (#2468). nil errors are ignored.
type sessionClearErrors struct {
	count int
	parts []string
}

func (e *sessionClearErrors) add(op string, err error) {
	if err == nil {
		return
	}
	e.count++
	e.parts = append(e.parts, fmt.Sprintf("%s: %v", op, err))
}

// addExceptNotFound is add() for delete operations whose target key is
// COMPUTED, not enumerated — the reverse-session companion (a naive
// src/dst swap of the forward key) and the DNAT companion entry. For a
// NAT'd session those computed keys frequently do not exist (the real
// reverse companion is keyed on the TRANSLATED tuple val.ReverseKey, not
// the naive swap), so the dataplane returns ebpf.ErrKeyNotExist. That is
// a benign idempotent not-found, NOT a clear failure — counting it would
// make a fully-successful NAT'd-session clear spuriously report a
// failure (#2468). Any OTHER delete error (EIO/EINVAL/...) is a real
// failure and is aggregated. The forward delete uses add() unchanged: a
// forward key came from iteration, so a not-found there is a genuine
// anomaly worth reporting.
func (e *sessionClearErrors) addExceptNotFound(op string, err error) {
	if err == nil || dataplane.IsKeyNotFound(err) {
		return
	}
	e.add(op, err)
}

// report prints a warning line to stdout if any sub-operation failed.
// The cleared-count line is printed by the caller and stays accurate
// for the forward entries that were removed; this adds the honest
// failure tail.
func (e *sessionClearErrors) report() {
	if e.count == 0 {
		return
	}
	fmt.Printf("WARNING: %d clear operation(s) failed: %s\n", e.count, strings.Join(e.parts, "; "))
}

// clearPeerSessions forwards the clear to the HA peer. Returns a
// non-nil error when the peer is unreachable or its clear failed (or
// only partially succeeded) so the caller can report it to the operator
// rather than silently leaving the peer holding the sessions (#2468).
//
// A standalone node (no cluster manager) has no peer and returns nil —
// not a failure.
func (c *CLI) clearPeerSessions(f *sessionFilter) error {
	if c.cluster == nil {
		return nil
	}
	conn := c.dialPeer()
	if conn == nil {
		return fmt.Errorf("peer unreachable")
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := buildPeerClearRequest(f)
	ctx = metadata.AppendToOutgoingContext(ctx, "x-peer-forwarded", "1")
	resp, err := pb.NewBpfrxServiceClient(conn).ClearSessions(ctx, req)
	if err != nil {
		return err
	}
	// The peer reports its own partial-failure tally — propagate it so a
	// local operator learns the peer clear was incomplete.
	if resp != nil && resp.Failures > 0 {
		return fmt.Errorf("peer reported %d failure(s): %s", resp.Failures, resp.FailureSummary)
	}
	return nil
}

// buildPeerClearRequest translates a local session filter into the
// peer-forwarded ClearSessionsRequest. EVERY filter dimension must be
// carried: a dropped filter does not merely widen the peer clear — a
// request with no filters at all is interpreted by the peer as
// clear-all (historically `clear security flow session interface X`
// forwarded an empty request and wiped the peer's session table).
func buildPeerClearRequest(f *sessionFilter) *pb.ClearSessionsRequest {
	req := &pb.ClearSessionsRequest{}
	if f == nil {
		return req
	}
	if f.srcNet != nil {
		req.SourcePrefix = f.srcNet.String()
	}
	if f.dstNet != nil {
		req.DestinationPrefix = f.dstNet.String()
	}
	if f.proto != 0 {
		switch f.proto {
		case 6:
			req.Protocol = "tcp"
		case 17:
			req.Protocol = "udp"
		case 1:
			req.Protocol = "icmp"
		case dataplane.ProtoICMPv6:
			req.Protocol = "icmpv6"
		default:
			// Numeric protocols forward as numbers; the server matcher
			// accepts numeric protocol strings. NEVER leave Protocol
			// empty when f.proto is set — a protocol-only filter would
			// forward an empty request = peer clear-all (the icmpv6
			// case did exactly that before #1827 PR-3 r1).
			req.Protocol = strconv.Itoa(int(f.proto))
		}
	}
	req.SourcePort = uint32(f.srcPort)
	req.DestinationPort = uint32(f.dstPort)
	req.Application = f.appName
	req.Zone = f.zoneName
	req.Interface = f.iface
	req.NatOnly = f.natOnly
	req.SourceNatPool = f.snatPool
	return req
}

func (c *CLI) handleClearFirewall(args []string) error {
	if len(args) < 1 || args[0] != "all" {
		cmdtree.PrintTreeHelp("clear firewall:", operationalTree, "clear", "firewall")
		return nil
	}
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	if err := c.dp.ClearFilterCounters(); err != nil {
		return fmt.Errorf("clear filter counters: %w", err)
	}
	fmt.Println("Firewall filter counters cleared")
	return nil
}

func (c *CLI) handleClearDHCP(args []string) error {
	if len(args) < 1 || args[0] != "client-identifier" {
		cmdtree.PrintTreeHelp("clear dhcp:", operationalTree, "clear", "dhcp")
		return nil
	}

	if c.dhcp == nil {
		fmt.Println("No DHCP clients running")
		return nil
	}

	if len(args) >= 3 && args[1] == "interface" {
		ifName := args[2]
		if err := c.dhcp.ClearDUID(ifName); err != nil {
			return fmt.Errorf("clear DUID: %w", err)
		}
		fmt.Printf("DHCPv6 DUID cleared for %s\n", ifName)
		return nil
	}

	c.dhcp.ClearAllDUIDs()
	fmt.Println("All DHCPv6 DUIDs cleared")
	return nil
}

func (c *CLI) clearPersistentNAT() error {
	if c.dp == nil || c.dp.GetPersistentNAT() == nil {
		fmt.Println("Persistent NAT table not available")
		return nil
	}
	count := c.dp.GetPersistentNAT().Len()
	c.dp.GetPersistentNAT().Clear()
	fmt.Printf("Cleared %d persistent NAT bindings\n", count)
	return nil
}
