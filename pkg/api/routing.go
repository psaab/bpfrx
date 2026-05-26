package api

import (
	"fmt"
	"net/http"
	"strings"
)

func (s *Server) routesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []RouteInfo{})
		return
	}

	var result []RouteInfo
	for _, r := range cfg.RoutingOptions.StaticRoutes {
		if r.NextTable != "" {
			result = append(result, RouteInfo{
				Destination: r.Destination,
				NextTable:   r.NextTable,
				Preference:  r.Preference,
			})
			continue
		}
		if r.Discard || len(r.NextHops) == 0 {
			result = append(result, RouteInfo{
				Destination: r.Destination,
				Preference:  r.Preference,
			})
			continue
		}
		for _, nh := range r.NextHops {
			result = append(result, RouteInfo{
				Destination: r.Destination,
				NextHop:     nh.Address,
				Interface:   nh.Interface,
				Preference:  r.Preference,
			})
		}
	}
	if result == nil {
		result = []RouteInfo{}
	}
	writeOK(w, result)
}

func (s *Server) ospfHandler(w http.ResponseWriter, r *http.Request) {
	if s.frr == nil {
		writeOK(w, TextResponse{Output: "FRR not available"})
		return
	}
	typ := r.URL.Query().Get("type")
	switch typ {
	case "database":
		output, err := s.frr.GetOSPFDatabase()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeOK(w, TextResponse{Output: output})
	default:
		neighbors, err := s.frr.GetOSPFNeighbors()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		var b strings.Builder
		for _, n := range neighbors {
			fmt.Fprintf(&b, "%-18s %-10s %-16s %-18s %s\n",
				n.NeighborID, n.Priority, n.State, n.Address, n.Interface)
		}
		writeOK(w, TextResponse{Output: b.String()})
	}
}

func (s *Server) bgpHandler(w http.ResponseWriter, r *http.Request) {
	if s.frr == nil {
		writeOK(w, TextResponse{Output: "FRR not available"})
		return
	}
	typ := r.URL.Query().Get("type")
	var b strings.Builder
	switch typ {
	case "routes":
		routes, err := s.frr.GetBGPRoutes()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, route := range routes {
			fmt.Fprintf(&b, "%-24s %-20s %s\n", route.Network, route.NextHop, route.Path)
		}
	default:
		peers, err := s.frr.GetBGPSummary()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, p := range peers {
			fmt.Fprintf(&b, "%-20s %-8s %-10s %-10s %-12s %s\n",
				p.Neighbor, p.AS, p.MsgRcvd, p.MsgSent, p.UpDown, p.State)
		}
	}
	writeOK(w, TextResponse{Output: b.String()})
}
