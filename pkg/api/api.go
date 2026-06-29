package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// apiRuntimeDataPlane is the API server's legacy-compatible runtime surface.
// It intentionally stays narrower than dataplane.DataPlane while REST handlers
// still migrate one domain at a time.
type apiRuntimeDataPlane interface {
	IsLoaded() bool
	IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	// GetSessionV4/V6 look up a single session entry by key. The session
	// view uses them to merge the companion reverse entry's counters into
	// the forward entry, matching the gRPC enrichment (#3419 H3). Without
	// the merge, REST top-talkers/accounting under-report the reverse
	// direction's volume.
	GetSessionV4(dataplane.SessionKey) (dataplane.SessionValue, error)
	GetSessionV6(dataplane.SessionKeyV6) (dataplane.SessionValueV6, error)
	ClearAllSessions() (int, int, error)

	ReadGlobalCounter(uint32) (uint64, error)
	ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error)
	ReadZoneCounters(uint16, int) (dataplane.CounterValue, error)
	ReadPolicyCounters(uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(uint32) (dataplane.CounterValue, error)
	ReadNATRuleCounter(uint32) (dataplane.CounterValue, error)
	ReadNATPortCounter(uint32) (uint64, error)
	ClearAllCounters() error
	GetMapStats() []dataplane.MapStats
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, Response{Success: true, Data: data})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, Response{Success: false, Error: msg})
}

func (s *Server) applyResult() *dataplane.ApplyResult {
	if s.dp == nil {
		return nil
	}
	return dataplane.LastApplyResultOf(s.dp)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func queryUint16(r *http.Request, key string, def uint16) uint16 {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return def
	}
	return uint16(n)
}

// queryUint16Strict parses a uint16 query parameter and FAILS CLOSED on a
// malformed/out-of-range non-empty value. Filter sentinels such as
// zone=0 mean "no filter", so a typo'd value (zone=abc / zone=65536) must
// NOT silently fall through to the no-filter default — that widens the
// query to every session/event and is a cross-zone observability leak
// (#2934). An empty value returns (def, true); a bad value returns
// (0, false) so the caller can emit HTTP 400, mirroring the gRPC contract
// (pkg/grpcapi sessionFilter.validate → InvalidArgument).
func queryUint16Strict(r *http.Request, key string, def uint16) (uint16, bool) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def, true
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

// queryIntStrict parses a non-negative int query parameter and FAILS
// CLOSED on a malformed/negative non-empty value (#2934). An empty value
// returns (def, true); a bad value returns (0, false) so the caller can
// emit HTTP 400. Used for filter/predicate parameters (e.g. dst_port in
// the policy-match simulator) where a bad value silently becoming the
// default is a wildcard that yields a misleading verdict.
func queryIntStrict(r *http.Request, key string, def int) (int, bool) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// parseRefBaseUnit splits a Junos interface ref into its base name
// and unit number, returning ok=false for malformed (non-numeric)
// suffixes. A bare ref returns (ref, 0, true). This matches the
// stricter Atoi semantics used in (*Config).ResolveKernelIfName and
// avoids the partial-numeric-prefix bug fmt.Sscanf has
// (e.g. "80foo" parsing as 80).
func parseRefBaseUnit(ref string) (base string, unitNum int, ok bool) {
	parts := strings.SplitN(ref, ".", 2)
	base = parts[0]
	if len(parts) == 1 {
		return base, 0, true
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return base, 0, false
	}
	return base, n, true
}

// allInterfaceNames returns a deduplicated set of interface names from
// both the interfaces config and zone declarations.
func allInterfaceNames(cfg *config.Config) map[string]bool {
	names := make(map[string]bool)
	for ifName := range cfg.Interfaces.Interfaces {
		names[ifName] = true
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			names[ifName] = true
		}
	}
	return names
}
