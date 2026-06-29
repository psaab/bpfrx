package api

import (
	"net/http"
	"time"

	"github.com/psaab/xpf/pkg/flowexport"
)

// healthHandler surfaces dataplane compile health (#758) and config
// persistence health (#1799) alongside the simple "ok" probe. When the
// dataplane compile has failed and has never succeeded since startup,
// or the running active config failed to persist to disk (a restart
// would load a stale config), return 503 with a structured "status:
// degraded" payload so operators scanning a probe can distinguish the
// catastrophic-silent-fail cases from a healthy daemon.
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
	if s.configPersistDegradedFn != nil {
		degraded := s.configPersistDegradedFn()
		payload["config_persist_degraded"] = degraded
		if degraded {
			payload["status"] = "degraded"
			writeJSON(w, http.StatusServiceUnavailable, Response{Success: false, Data: payload, Error: "active configuration failed to persist to disk; restart would load stale config"})
			return
		}
	}
	// #3441: report rollback-history degradation as a non-fatal field. The
	// active config is durable (the commit succeeded via the #1799 path);
	// only the best-effort text rollback copies failed, so unlike
	// config_persist_degraded this does NOT force a 503 — a perfectly
	// forwarding firewall must not be pulled from rotation over a degraded
	// recovery aid. The xpf_config_rollback_persist_degraded gauge is the
	// alerting hook; this field gives a probe the same visibility.
	if s.rollbackHistoryDegradedFn != nil {
		payload["rollback_history_degraded"] = s.rollbackHistoryDegradedFn()
	}
	writeOK(w, payload)
}

// flowExportersHandler surfaces the per-collector NetFlow v9 / IPFIX
// write-health (#2464): for every configured collector, its write
// attempt/failure counters, the current healthy flag, and the last
// error / last success timestamps. Flow export is forensics/compliance
// data; a collector going silently unreachable used to be invisible
// (every failed UDP write was debug-logged and dropped while the
// exporter kept counting "exported"). The response payload mirrors the
// Prometheus xpf_flow_export_collector_* family. Empty when no flow
// export is configured.
func (s *Server) flowExportersHandler(w http.ResponseWriter, _ *http.Request) {
	var collectors []flowexport.ExporterCollectorHealth
	if s.flowCollectorHealthFn != nil {
		collectors = s.flowCollectorHealthFn()
	}
	writeOK(w, map[string]any{"collectors": collectors})
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
