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
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
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
