// Phase 9 of #1043: extract the four route-* ShowText case bodies into
// dedicated methods. Same methodology as Phases 1-8: semantic
// relocation, no behavior change. Each case body is moved verbatim
// apart from `&buf` references becoming `buf` (passed-in
// `*strings.Builder`). The methods return `error` because the
// originals had `return nil, status.Errorf(codes.Internal, …)` paths
// on routing/FRR fetch failure; the dispatcher rewraps via
// `if err := …; err != nil { return nil, err }` (same pattern as
// Phase 6 interfaces and Phase 7 commit-history).

package grpcapi

import (
	"fmt"
	"net"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/routing"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// showRouteAll renders the per-VRF route tables (main + each routing
// instance) using `routing.FormatAllRoutes`.
func (s *Server) showRouteAll(cfg *config.Config, buf *strings.Builder) error {
	if s.routing == nil {
		fmt.Fprintln(buf, "Routing manager not available")
		return nil
	}
	var instances []*config.RoutingInstanceConfig
	if cfg != nil {
		instances = cfg.RoutingInstances
	}
	allTables, err := s.routing.GetAllTableRoutes(instances)
	if err != nil {
		return status.Errorf(codes.Internal, "get routes: %v", err)
	}
	buf.WriteString(routing.FormatAllRoutes(allTables))
	return nil
}

// showRouteSummary renders the FRR-style route summary with
// router-ID extracted from OSPF or BGP config.
func (s *Server) showRouteSummary(cfg *config.Config, buf *strings.Builder) error {
	if s.routing == nil {
		fmt.Fprintln(buf, "Routing manager not available")
		return nil
	}
	var instances []*config.RoutingInstanceConfig
	if cfg != nil {
		instances = cfg.RoutingInstances
	}
	allTables, err := s.routing.GetAllTableRoutes(instances)
	if err != nil {
		return status.Errorf(codes.Internal, "get routes: %v", err)
	}
	routerID := ""
	if cfg != nil {
		if cfg.Protocols.OSPF != nil && cfg.Protocols.OSPF.RouterID != "" {
			routerID = cfg.Protocols.OSPF.RouterID
		} else if cfg.Protocols.BGP != nil && cfg.Protocols.BGP.RouterID != "" {
			routerID = cfg.Protocols.BGP.RouterID
		}
	}
	buf.WriteString(routing.FormatRouteSummary(allTables, routerID))
	return nil
}

// showRouteTerse renders the terse main-table route listing.
func (s *Server) showRouteTerse(buf *strings.Builder) error {
	if s.routing == nil {
		fmt.Fprintln(buf, "Routing manager not available")
		return nil
	}
	entries, err := s.routing.GetRoutes()
	if err != nil {
		return status.Errorf(codes.Internal, "get routes: %v", err)
	}
	buf.WriteString(routing.FormatRouteTerse(entries))
	return nil
}

// showRouteDetail renders the FRR JSON-backed detailed route view.
func (s *Server) showRouteDetail(buf *strings.Builder) error {
	if s.frr == nil {
		fmt.Fprintln(buf, "FRR manager not available")
		return nil
	}
	routes, err := s.frr.GetRouteDetailJSON()
	if err != nil {
		return status.Errorf(codes.Internal, "get route detail: %v", err)
	}
	if len(routes) == 0 {
		buf.WriteString("No routes\n")
		return nil
	}
	buf.WriteString(frr.FormatRouteDetail(routes))
	return nil
}

// --- #1700: residual ShowText routing branches ---

func (s *Server) showRouteTable(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	tableName := strings.TrimPrefix(req.Topic, "route-table:")
	if s.routing == nil {
		buf.WriteString("Routing manager not available\n")
	} else {
		entries, err := s.routing.GetTableRoutes(tableName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "get table routes: %v", err)
		}
		if len(entries) == 0 {
			fmt.Fprintf(buf, "No routes in table %s\n", tableName)
		} else {
			buf.WriteString(routing.FormatAllRoutes([]routing.TableRoutes{{Name: tableName, Entries: entries}}))
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

func (s *Server) showRouteProtocol(req *pb.ShowTextRequest, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	proto := strings.ToLower(strings.TrimPrefix(req.Topic, "route-protocol:"))
	if s.routing == nil {
		buf.WriteString("Routing manager not available\n")
	} else {
		entries, err := s.routing.GetRoutes()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "get routes: %v", err)
		}
		fmt.Fprintf(buf, "Routes matching protocol: %s\n", proto)
		fmt.Fprintf(buf, "  %-24s %-20s %-14s %-12s %s\n", "Destination", "Next-hop", "Interface", "Proto", "Pref")
		count := 0
		for _, e := range entries {
			if strings.ToLower(e.Protocol) == proto {
				fmt.Fprintf(buf, "  %-24s %-20s %-14s %-12s %d\n",
					e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
				count++
			}
		}
		if count == 0 {
			buf.WriteString("  (no routes)\n")
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

func (s *Server) showRoutePrefix(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	prefixAndMod := strings.TrimPrefix(req.Topic, "route-prefix:")
	prefix := prefixAndMod
	modifier := ""
	if idx := strings.LastIndex(prefixAndMod, " "); idx != -1 {
		candidate := prefixAndMod[idx+1:]
		switch candidate {
		case "exact", "longer", "orlonger":
			prefix = prefixAndMod[:idx]
			modifier = candidate
		}
	}
	if s.routing == nil {
		buf.WriteString("Routing manager not available\n")
	} else {
		var instances []*config.RoutingInstanceConfig
		if cfg != nil {
			instances = cfg.RoutingInstances
		}
		allTables, err := s.routing.GetAllTableRoutes(instances)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "get routes: %v", err)
		}
		buf.WriteString(routing.FormatRouteDestination(allTables, prefix, modifier))
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

func (s *Server) showTestRouting(req *pb.ShowTextRequest, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	params := strings.TrimPrefix(req.Topic, "test-routing:")
	var dest, instance string
	for _, kv := range strings.Split(params, ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "dest":
			dest = parts[1]
		case "instance":
			instance = parts[1]
		}
	}
	if s.routing == nil {
		buf.WriteString("Routing manager not available\n")
	} else if dest == "" {
		buf.WriteString("Missing dest parameter\n")
	} else {
		var entries []routing.RouteEntry
		var err error
		if instance != "" {
			entries, err = s.routing.GetVRFRoutes(instance)
		} else {
			entries, err = s.routing.GetRoutes()
		}
		if err != nil {
			return nil, status.Errorf(codes.Internal, "get routes: %v", err)
		}
		filterCIDR := dest
		if !strings.Contains(filterCIDR, "/") {
			if strings.Contains(filterCIDR, ":") {
				filterCIDR += "/128"
			} else {
				filterCIDR += "/32"
			}
		}
		filterIP, _, filterErr := net.ParseCIDR(filterCIDR)
		if filterErr != nil {
			filterIP = net.ParseIP(dest)
		}
		var best *routing.RouteEntry
		bestLen := -1
		for i := range entries {
			_, rNet, err := net.ParseCIDR(entries[i].Destination)
			if err != nil {
				continue
			}
			if filterIP != nil && rNet.Contains(filterIP) {
				ones, _ := rNet.Mask.Size()
				if ones > bestLen {
					bestLen = ones
					best = &entries[i]
				}
			}
		}
		if instance != "" {
			fmt.Fprintf(buf, "Routing lookup in instance %s for %s:\n", instance, dest)
		} else {
			fmt.Fprintf(buf, "Routing lookup for %s:\n", dest)
		}
		if best == nil {
			buf.WriteString("  No matching route found\n")
		} else {
			fmt.Fprintf(buf, "  Destination: %s\n", best.Destination)
			fmt.Fprintf(buf, "  Next-hop:    %s\n", best.NextHop)
			fmt.Fprintf(buf, "  Interface:   %s\n", best.Interface)
			fmt.Fprintf(buf, "  Protocol:    %s\n", best.Protocol)
			fmt.Fprintf(buf, "  Preference:  %d\n", best.Preference)
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

func (s *Server) showRoutingOptions(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else {
		ro := &cfg.RoutingOptions
		hasContent := false
		if ro.AutonomousSystem > 0 {
			fmt.Fprintf(buf, "Autonomous system: %d\n\n", ro.AutonomousSystem)
			hasContent = true
		}
		if ro.ForwardingTableExport != "" {
			fmt.Fprintf(buf, "Forwarding-table export: %s\n\n", ro.ForwardingTableExport)
			hasContent = true
		}
		if len(ro.StaticRoutes) > 0 {
			buf.WriteString("Static routes (inet.0):\n")
			fmt.Fprintf(buf, "  %-24s %-20s %s\n", "Destination", "Next-Hop", "Pref")
			for _, sr := range ro.StaticRoutes {
				if sr.Discard {
					fmt.Fprintf(buf, "  %-24s %-20s %s\n", sr.Destination, "discard", fmtPref(sr.Preference))
					continue
				}
				if sr.NextTable != "" {
					fmt.Fprintf(buf, "  %-24s %-20s %s\n", sr.Destination, "next-table "+sr.NextTable, fmtPref(sr.Preference))
					continue
				}
				for i, nh := range sr.NextHops {
					dest := sr.Destination
					if i > 0 {
						dest = ""
					}
					nhStr := nh.Address
					if nh.Interface != "" {
						nhStr += " via " + nh.Interface
					}
					fmt.Fprintf(buf, "  %-24s %-20s %s\n", dest, nhStr, fmtPref(sr.Preference))
				}
			}
			buf.WriteString("\n")
			hasContent = true
		}
		if len(ro.Inet6StaticRoutes) > 0 {
			buf.WriteString("Static routes (inet6.0):\n")
			fmt.Fprintf(buf, "  %-40s %-30s %s\n", "Destination", "Next-Hop", "Pref")
			for _, sr := range ro.Inet6StaticRoutes {
				if sr.Discard {
					fmt.Fprintf(buf, "  %-40s %-30s %s\n", sr.Destination, "discard", fmtPref(sr.Preference))
					continue
				}
				if sr.NextTable != "" {
					fmt.Fprintf(buf, "  %-40s %-30s %s\n", sr.Destination, "next-table "+sr.NextTable, fmtPref(sr.Preference))
					continue
				}
				for i, nh := range sr.NextHops {
					dest := sr.Destination
					if i > 0 {
						dest = ""
					}
					nhStr := nh.Address
					if nh.Interface != "" {
						nhStr += " via " + nh.Interface
					}
					fmt.Fprintf(buf, "  %-40s %-30s %s\n", dest, nhStr, fmtPref(sr.Preference))
				}
			}
			buf.WriteString("\n")
			hasContent = true
		}
		if len(ro.RibGroups) > 0 {
			buf.WriteString("RIB groups:\n")
			for name, rg := range ro.RibGroups {
				fmt.Fprintf(buf, "  %-20s import-rib: %s\n", name, strings.Join(rg.ImportRibs, ", "))
			}
			buf.WriteString("\n")
			hasContent = true
		}
		if !hasContent {
			buf.WriteString("No routing-options configured\n")
		}
	}
}

func (s *Server) showRoutingInstances(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.RoutingInstances) == 0 {
		buf.WriteString("No routing instances configured\n")
	} else {
		fmt.Fprintf(buf, "%-20s %-16s %-6s %s\n", "Instance", "Type", "Table", "Interfaces")
		for _, ri := range cfg.RoutingInstances {
			tableID := "-"
			if ri.TableID > 0 {
				tableID = fmt.Sprintf("%d", ri.TableID)
			}
			ifaces := "-"
			if len(ri.Interfaces) > 0 {
				ifaces = strings.Join(ri.Interfaces, ", ")
			}
			fmt.Fprintf(buf, "%-20s %-16s %-6s %s\n", ri.Name, ri.InstanceType, tableID, ifaces)
			if ri.Description != "" {
				fmt.Fprintf(buf, "  Description: %s\n", ri.Description)
			}
		}
	}
}

func (s *Server) showRoutingInstancesDetail(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.RoutingInstances) == 0 {
		buf.WriteString("No routing instances configured\n")
	} else {
		for _, ri := range cfg.RoutingInstances {
			fmt.Fprintf(buf, "Instance: %s\n", ri.Name)
			if ri.Description != "" {
				fmt.Fprintf(buf, "  Description: %s\n", ri.Description)
			}
			fmt.Fprintf(buf, "  Type: %s\n", ri.InstanceType)
			if ri.TableID > 0 {
				fmt.Fprintf(buf, "  Table ID: %d\n", ri.TableID)
			}
			if len(ri.Interfaces) > 0 {
				fmt.Fprintf(buf, "  Interfaces: %s\n", strings.Join(ri.Interfaces, ", "))
			}
			if ri.TableID > 0 && s.routing != nil {
				if routes, err := s.routing.GetRoutesForTable(ri.TableID); err == nil {
					fmt.Fprintf(buf, "  Route count: %d\n", len(routes))
				}
			}
			var protos []string
			if ri.OSPF != nil {
				protos = append(protos, "OSPF")
			}
			if ri.BGP != nil {
				protos = append(protos, "BGP")
			}
			if ri.RIP != nil {
				protos = append(protos, "RIP")
			}
			if ri.ISIS != nil {
				protos = append(protos, "IS-IS")
			}
			if len(protos) > 0 {
				fmt.Fprintf(buf, "  Protocols: %s\n", strings.Join(protos, ", "))
			}
			if len(ri.StaticRoutes) > 0 {
				fmt.Fprintf(buf, "  Static routes: %d\n", len(ri.StaticRoutes))
				for _, sr := range ri.StaticRoutes {
					if sr.Discard {
						fmt.Fprintf(buf, "    %s -> discard\n", sr.Destination)
						continue
					}
					for _, nh := range sr.NextHops {
						nhStr := nh.Address
						if nh.Interface != "" {
							nhStr += " via " + nh.Interface
						}
						fmt.Fprintf(buf, "    %s -> %s\n", sr.Destination, nhStr)
					}
				}
			}
			if ri.InterfaceRoutesRibGroup != "" {
				fmt.Fprintf(buf, "  Interface routes rib-group: %s\n", ri.InterfaceRoutesRibGroup)
			}
			buf.WriteString("\n")
		}
	}
}

func (s *Server) showRouteInstance(filter string, cfg *config.Config, buf *strings.Builder) {
	instanceName := filter
	if instanceName == "" {
		buf.WriteString("Usage: show route instance <name>\n")
		return
	}
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return
	}
	var tableID int
	found := false
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == instanceName {
			tableID = ri.TableID
			found = true
			break
		}
	}
	if !found {
		fmt.Fprintf(buf, "Routing instance %q not found\n", instanceName)
		return
	}
	if s.routing != nil {
		entries, err := s.routing.GetRoutesForTable(tableID)
		if err != nil {
			fmt.Fprintf(buf, "Error: %v\n", err)
			return
		}
		fmt.Fprintf(buf, "Routing table for instance %s (table %d):\n", instanceName, tableID)
		fmt.Fprintf(buf, "  %-24s %-20s %-14s %-12s %s\n",
			"Destination", "Next-hop", "Interface", "Proto", "Pref")
		for _, e := range entries {
			fmt.Fprintf(buf, "  %-24s %-20s %-14s %-12s %d\n",
				e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
		}
	} else {
		buf.WriteString("Routing manager not available\n")
	}
}

func (s *Server) showRouteMap(cfg *config.Config, buf *strings.Builder) error {
	if s.frr == nil {
		buf.WriteString("FRR not available\n")
	} else {
		output, err := s.frr.GetRouteMapList()
		if err != nil {
			return status.Errorf(codes.Internal, "route-map: %v", err)
		}
		if output == "" {
			buf.WriteString("No route-maps configured\n")
		} else {
			buf.WriteString(output)
		}
	}
	return nil
}

func (s *Server) showBFDPeers(buf *strings.Builder) error {
	if s.frr == nil {
		buf.WriteString("FRR not available\n")
	} else {
		output, err := s.frr.GetBFDPeers()
		if err != nil {
			return status.Errorf(codes.Internal, "BFD peers: %v", err)
		}
		if output == "" {
			buf.WriteString("No BFD peers\n")
		} else {
			buf.WriteString(output)
		}
	}
	return nil
}
