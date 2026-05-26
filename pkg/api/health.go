package api

import (
	"net/http"
	"time"
)

// healthHandler surfaces dataplane compile health (#758) alongside the
// simple "ok" probe. When the dataplane compile has failed and has
// never succeeded since startup, return 503 with a structured "status:
// degraded" payload so operators scanning a probe can distinguish the
// catastrophic-silent-fail case from a healthy daemon.
func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{"status": "ok"}
	if s.compileHealthFn != nil {
		h := s.compileHealthFn()
		payload["compile_ever_succeeded"] = h.EverSucceeded
		payload["compile_failure_count"] = h.FailureCount
		if h.LastError != "" {
			payload["compile_last_error"] = h.LastError
		}
		if h.LastErrorUnixSec != 0 {
			payload["compile_last_error_unix"] = h.LastErrorUnixSec
		}
		if !h.EverSucceeded && h.FailureCount > 0 {
			payload["status"] = "degraded"
			writeJSON(w, http.StatusServiceUnavailable, Response{Success: false, Data: payload, Error: "dataplane compile has never succeeded"})
			return
		}
	}
	writeOK(w, payload)
}

func (s *Server) statusHandler(w http.ResponseWriter, _ *http.Request) {
	resp := StatusResponse{
		Uptime:          time.Since(s.startTime).Truncate(time.Second).String(),
		DataplaneLoaded: s.dp != nil && s.dp.IsLoaded(),
		ConfigLoaded:    s.store.ActiveConfig() != nil,
	}
	if cfg := s.store.ActiveConfig(); cfg != nil {
		resp.ZoneCount = len(cfg.Security.Zones)
	}
	if s.gc != nil {
		stats := s.gc.Stats()
		resp.SessionCount = stats.TotalEntries
	}
	writeOK(w, resp)
}
