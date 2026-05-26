package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

func (s *Server) configHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, nil)
		return
	}
	writeOK(w, cfg)
}

func (s *Server) configEnterHandler(w http.ResponseWriter, _ *http.Request) {
	if err := s.store.EnterConfigure(); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configExitHandler(w http.ResponseWriter, _ *http.Request) {
	s.store.ExitConfigure()
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configStatusHandler(w http.ResponseWriter, _ *http.Request) {
	writeOK(w, ConfigModeStatus{
		InConfigMode:   s.store.InConfigMode(),
		Dirty:          s.store.IsDirty(),
		ConfirmPending: s.store.IsConfirmPending(),
	})
}

func (s *Server) configSetHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	if err := s.store.SetFromInput(req.Input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configDeleteHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	if err := s.store.DeleteFromInput(req.Input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configCommitHandler(w http.ResponseWriter, r *http.Request) {
	if s.store.IsConfirmPending() {
		if err := s.store.ConfirmCommit(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeOK(w, map[string]string{"status": "ok"})
		return
	}

	if s.commitFn == nil {
		writeError(w, http.StatusInternalServerError, "commit handler not wired")
		return
	}
	compiled, err := s.commitFn(r.Context(), "")
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			writeError(w, http.StatusServiceUnavailable, "commit busy: "+err.Error())
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeOK(w, commitResponseFromConfig(compiled))
}

func (s *Server) configCommitCheckHandler(w http.ResponseWriter, _ *http.Request) {
	compiled, err := s.store.CommitCheck()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, commitResponseFromConfig(compiled))
}

func (s *Server) configRollbackHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigRollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.store.Rollback(req.N); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configShowHandler(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	target := r.URL.Query().Get("target")

	var output string
	switch {
	case target == "active" && format == "set":
		output = s.store.ShowActiveSet()
	case target == "active" && format == "json":
		output = s.store.ShowActiveJSON()
	case target == "active" && format == "xml":
		output = s.store.ShowActiveXML()
	case target == "active":
		output = s.store.ShowActive()
	case format == "set":
		output = s.store.ShowCandidateSet()
	case format == "json":
		output = s.store.ShowCandidateJSON()
	case format == "xml":
		output = s.store.ShowCandidateXML()
	default:
		output = s.store.ShowCandidate()
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) configExportHandler(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "set"
	}
	var output string
	switch format {
	case "set":
		output = s.store.ShowActiveSet()
	case "text":
		output = s.store.ShowActive()
	case "json":
		output = s.store.ShowActiveJSON()
	case "xml":
		output = s.store.ShowActiveXML()
	default:
		writeError(w, http.StatusBadRequest, "unsupported format: "+format+"; use set, text, json, or xml")
		return
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) configCompareHandler(w http.ResponseWriter, r *http.Request) {
	rollbackN := queryInt(r, "rollback", 0)
	if rollbackN > 0 {
		diff, err := s.store.ShowCompareRollback(rollbackN)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeOK(w, TextResponse{Output: diff})
		return
	}
	writeOK(w, TextResponse{Output: s.store.ShowCompare()})
}

func (s *Server) configHistoryHandler(w http.ResponseWriter, _ *http.Request) {
	entries := s.store.ListHistory()
	result := make([]HistoryEntry, len(entries))
	for i, e := range entries {
		result[i] = HistoryEntry{
			Index:     i + 1,
			Timestamp: e.Timestamp.Format("2006-01-02 15:04:05"),
		}
	}
	writeOK(w, result)
}

func (s *Server) configSearchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		writeError(w, http.StatusBadRequest, "missing q parameter")
		return
	}
	text := s.store.ShowActive()
	var results []ConfigSearchResult
	for i, line := range strings.Split(text, "\n") {
		if strings.Contains(line, query) {
			results = append(results, ConfigSearchResult{LineNumber: i + 1, Line: line})
		}
	}
	writeOK(w, results)
}

func (s *Server) configLoadHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigLoadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content required")
		return
	}

	switch req.Mode {
	case "override":
		if err := s.store.LoadOverride(req.Content); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	case "merge", "":
		if err := s.store.LoadMerge(req.Content); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown load mode: %s (use 'override' or 'merge')", req.Mode))
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configCommitConfirmedHandler(w http.ResponseWriter, r *http.Request) {
	var req CommitConfirmedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if s.commitConfirmedFn == nil {
		writeError(w, http.StatusInternalServerError, "commit-confirmed handler not wired")
		return
	}
	compiled, err := s.commitConfirmedFn(r.Context(), req.Minutes)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			writeError(w, http.StatusServiceUnavailable, "commit busy: "+err.Error())
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeOK(w, commitResponseFromConfig(compiled))
}

func (s *Server) configConfirmHandler(w http.ResponseWriter, _ *http.Request) {
	if err := s.store.ConfirmCommit(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configShowRollbackHandler(w http.ResponseWriter, r *http.Request) {
	n := queryInt(r, "n", 1)
	format := r.URL.Query().Get("format")

	var output string
	var err error
	if format == "set" {
		output, err = s.store.ShowRollbackSet(n)
	} else {
		output, err = s.store.ShowRollback(n)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) configAnnotateHandler(w http.ResponseWriter, r *http.Request) {
	var req AnnotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Error: err.Error()})
		return
	}
	if req.Path == "" || req.Comment == "" {
		writeJSON(w, http.StatusBadRequest, Response{Error: "path and comment are required"})
		return
	}
	pathParts := strings.Fields(req.Path)
	if err := s.store.Annotate(pathParts, req.Comment); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, Response{Success: true})
}

type configCommitResponse struct {
	Status   string   `json:"status"`
	Warnings []string `json:"warnings,omitempty"`
}

func commitResponseFromConfig(cfg *config.Config) configCommitResponse {
	resp := configCommitResponse{Status: "ok"}
	if cfg != nil && len(cfg.Warnings) > 0 {
		resp.Warnings = append([]string(nil), cfg.Warnings...)
	}
	return resp
}
