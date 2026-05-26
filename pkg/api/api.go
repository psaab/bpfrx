package api

import (
	"encoding/json"
	"net/http"
	"strconv"

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

// allInterfaceNames returns a deduplicated set of interface names from
// both the interfaces config and zone declarations.
func allInterfaceNames(cfg *config.Config) map[string]bool {
	names := make(map[string]bool)
	for ifName := range cfg.Interfaces.Interfaces {
		names[ifName] = true
	}
	for _, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			names[ifName] = true
		}
	}
	return names
}
