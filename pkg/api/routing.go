package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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
	switch typ {
	case "routes":
		routes, err := s.frr.GetBGPRoutes()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// A full internet BGP table (900k+ routes) would otherwise render
		// into one multi-hundred-MB strings.Builder and then get copied a
		// second time while json-encoding it — ~2x unbounded allocation on a
		// RAM-constrained firewall (#4708). Stream the exact same wire
		// envelope ({"success":true,"data":{"output":"<lines>"}}\n)
		// incrementally: each route line is formatted and JSON-escaped
		// through a fixed-size bufio buffer, so peak memory is bounded
		// regardless of table size. JSON string escaping is per-byte
		// independent, so escaping each line and concatenating yields exactly
		// the same bytes as escaping the joined string.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		bw := bufio.NewWriter(w)
		// Envelope prefix. Response{Success:true, Data: TextResponse{Output}}
		// with Error empty (omitempty) — matches encoding/json field order.
		io.WriteString(bw, `{"success":true,"data":{"output":"`)
		for i := range routes {
			route := &routes[i]
			writeJSONStringFragment(bw, fmt.Sprintf("%-24s %-20s %s\n",
				route.Network, route.NextHop, route.Path))
			// Periodically push bytes onto the wire so a very large table
			// streams out instead of parking in buffers.
			if (i+1)%1024 == 0 {
				// Abort if the client has disconnected: a full internet
				// table (900k+ routes) would otherwise keep formatting and
				// JSON-escaping every remaining route and writing to a dead
				// connection after r.Context() is cancelled — pure CPU/GC
				// waste on a RAM-constrained firewall (#5232). Checked once
				// per 1024-route chunk, so the abort is timely without any
				// per-route cost. The un-flushed bufio tail and closing
				// envelope are intentionally dropped: the connection is gone.
				if r.Context().Err() != nil {
					return
				}
				bw.Flush()
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}
		// json.Encoder appends a trailing newline; preserve it for
		// byte-equivalence with the previous buffered response.
		io.WriteString(bw, "\"}}\n")
		bw.Flush()
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	default:
		var b strings.Builder
		peers, err := s.frr.GetBGPSummary()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		fmt.Fprintf(&b, "%-20s %-13s %-8s %-9s %-9s %-11s %-12s %s\n",
			"Neighbor", "AF", "AS", "MsgRcvd", "MsgSent", "Up/Down", "State", "PfxRcd")
		for _, p := range peers {
			fmt.Fprintf(&b, "%-20s %-13s %-8s %-9s %-9s %-11s %-12s %s\n",
				p.Neighbor, p.AddressFamily, p.AS, p.MsgRcvd, p.MsgSent, p.UpDown, p.State, p.PfxRcd)
		}
		writeOK(w, TextResponse{Output: b.String()})
	}
}

// writeJSONStringFragment writes s to w with exactly the escaping
// encoding/json applies inside a JSON string literal (HTML-safe by default:
// the "<", ">" and "&" bytes are emitted as their \uXXXX escapes, the same as
// the default json.Encoder used by writeJSON), but without the surrounding
// quotes.
// Because encoding/json escapes strings byte-by-byte with no cross-byte state,
// concatenating the fragments is byte-for-byte identical to escaping the
// concatenated string. Used to stream a large response without materializing
// the whole escaped payload in memory. json.Marshal never fails for a string.
func writeJSONStringFragment(w io.Writer, s string) {
	esc, err := json.Marshal(s)
	if err != nil {
		return
	}
	// esc is `"...escaped..."`; drop the surrounding quotes.
	w.Write(esc[1 : len(esc)-1])
}
