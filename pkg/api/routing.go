package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/frr"
)

// maxBGPRoutes bounds how many BGP routes the REST
// /api/routing/bgp?type=routes endpoint renders into a single JSON response.
// StreamBGPRoutes already bounds the per-request memory (it scans vtysh stdout
// one route at a time — the #5056 upstream-materialization fix), but a full
// internet table (~1M IPv4 routes) still renders to a ~100 MB JSON string on
// the wire; capping the count bounds the response body (and the total
// format/escape work for a slow or hostile client) while still returning a
// large diagnostic sample. Operators who need the complete table use the CLI
// / vtysh. When the cap trips, a trailing truncation notice line is appended
// to the output so the client can tell the table was cut. It is a var (not a
// const) only so tests can drive the truncation path without synthesizing a
// million-route fixture.
var maxBGPRoutes = 100000

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
		// Routes with no forwarding next-hop carry a disposition label so
		// this view distinguishes reject (RTN_UNREACHABLE) from discard
		// (RTN_BLACKHOLE) from directly-connected, matching how the CLI/gRPC
		// `show route` text renders reject/discard (#5298/#5410). Reject and
		// Discard are mutually exclusive; check them before the no-next-hop
		// fallthrough since a reject/discard route also carries no NextHops.
		if r.Reject {
			result = append(result, RouteInfo{
				Destination: r.Destination,
				Disposition: "reject",
				Preference:  r.Preference,
			})
			continue
		}
		if r.Discard {
			result = append(result, RouteInfo{
				Destination: r.Destination,
				Disposition: "discard",
				Preference:  r.Preference,
			})
			continue
		}
		if len(r.NextHops) == 0 {
			result = append(result, RouteInfo{
				Destination: r.Destination,
				Disposition: "connected",
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
		// The upstream RIB is streamed, not buffered: StreamBGPRoutes scans
		// vtysh stdout one route at a time and hands each to the callback
		// below, so a full internet table (~1M routes) is never rendered into
		// one multi-hundred-MB string on either the FRR side or in this
		// handler (#5056, extending the downstream-only streaming of #4708).
		// Each route line is formatted and JSON-escaped through a fixed-size
		// bufio buffer, so peak memory is bounded regardless of table size.
		// JSON string escaping is per-byte independent, so escaping each line
		// and concatenating yields exactly the same bytes as escaping the
		// joined string. The output is capped at maxBGPRoutes with a trailing
		// truncation notice so the response body stays bounded even for a
		// pathologically large table.
		bw := bufio.NewWriter(w)
		emitted := 0
		started := false
		// emitPrefix lazily writes the 200 status + envelope prefix on the
		// first route (or on an empty/complete table). Deferring it lets an
		// upstream vtysh START failure — detected before any route is
		// delivered — surface as a clean 500 instead of a truncated 200.
		emitPrefix := func() {
			if started {
				return
			}
			started = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Response{Success:true, Data: TextResponse{Output}} with Error
			// empty (omitempty) — matches encoding/json field order.
			io.WriteString(bw, `{"success":true,"data":{"output":"`)
		}
		truncated, err := s.frr.StreamBGPRoutes(r.Context(), maxBGPRoutes, func(route frr.BGPRoute) error {
			emitPrefix()
			writeJSONStringFragment(bw, fmt.Sprintf("%-24s %-20s %s\n",
				route.Network, route.NextHop, route.Path))
			emitted++
			// Periodically push bytes onto the wire so a very large table
			// streams out instead of parking in buffers.
			if emitted%1024 == 0 {
				// Abort if the client has disconnected: continuing to format
				// and JSON-escape every remaining route and write to a dead
				// connection is pure CPU/GC waste (#5232). Returning an error
				// stops the scan and cancels vtysh upstream. The un-flushed
				// bufio tail and closing envelope are intentionally dropped:
				// the connection is gone.
				if cerr := r.Context().Err(); cerr != nil {
					return cerr
				}
				// A downstream write failure is also terminal: propagate it so
				// the scan stops and vtysh is cancelled instead of dumping the
				// rest of the table into a broken pipe.
				if ferr := bw.Flush(); ferr != nil {
					return ferr
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			return nil
		})
		if err != nil {
			if !started {
				// vtysh failed to start before any bytes were written — we can
				// still send a proper error status.
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			// Client disconnect or write failure mid-stream: headers + a
			// partial body are already on the wire, so we cannot switch to an
			// error status. The scan is aborted and vtysh cancelled; stop.
			return
		}
		// Empty or fully-drained table: emit the (possibly empty) envelope.
		emitPrefix()
		if truncated {
			// Bounded-response notice, inside the JSON string so the envelope
			// shape is unchanged; only present when the cap actually tripped.
			writeJSONStringFragment(bw, fmt.Sprintf(
				"... table truncated at %d routes; use the CLI 'show route protocol bgp' for the full table\n",
				maxBGPRoutes))
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
