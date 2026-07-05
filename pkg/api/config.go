package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// maxConfigBodyBytes caps the REST config-load POST body (fable-review-164
// H-2). Without it the body is buffered unbounded and fed to the parser, which
// a sub-4 MiB pathological payload can crash. It is 2x
// configstore.MaxConfigSize (16 MiB) to leave headroom for JSON string
// escaping of the config content; the post-decode configstore size ceiling is
// the authoritative limit on the config itself.
const maxConfigBodyBytes = 2 * (16 << 20) // 32 MiB

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

// configDeactivateHandler marks a candidate node inactive (#2051), the REST
// equivalent of the interactive `deactivate <path>` verb. The request body's
// Input is the bare path (no verb), mirroring configSetHandler. It routes
// through DeactivateFromInput so the verb logic stays in the store's
// applyEditLine switch and the path is never mangled into a junk "set" node.
func (s *Server) configDeactivateHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	if err := s.store.DeactivateFromInput(req.Input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

// configActivateHandler clears the inactive marker on a candidate node
// (#2051), the REST equivalent of the interactive `activate <path>` verb.
func (s *Server) configActivateHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	if err := s.store.ActivateFromInput(req.Input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configCommitHandler(w http.ResponseWriter, r *http.Request) {
	// Bare commit during a pending commit-confirmed window (#4000). Confirm
	// the pending config only when the candidate is UNCHANGED; new staged
	// edits fall through to the normal commit below, where commitFn applies
	// them AND clears the timer (#3861), so they are committed rather than
	// silently dropped.
	if s.store.IsConfirmPending() && !s.store.IsDirty() {
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

	// Secrets are masked on every raw-AST render endpoint (#4051), matching
	// the #2053 typed-struct redaction; the cleartext Show* SSOT still backs
	// HA config sync, the DR archive and persistence.
	var output string
	switch {
	case target == "active" && format == "set":
		output = s.store.ShowActiveSetRedacted(nil)
	case target == "active" && format == "json":
		output = s.store.ShowActiveJSONRedacted(nil)
	case target == "active" && format == "xml":
		output = s.store.ShowActiveXMLRedacted(nil)
	case target == "active":
		output = s.store.ShowActiveRedacted(nil)
	case format == "set":
		output = s.store.ShowCandidateSetRedacted(nil)
	case format == "json":
		output = s.store.ShowCandidateJSONRedacted(nil)
	case format == "xml":
		output = s.store.ShowCandidateXMLRedacted(nil)
	default:
		output = s.store.ShowCandidateRedacted(nil)
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
		output = s.store.ShowActiveSetRedacted(nil)
	case "text":
		output = s.store.ShowActiveRedacted(nil)
	case "json":
		output = s.store.ShowActiveJSONRedacted(nil)
	case "xml":
		output = s.store.ShowActiveXMLRedacted(nil)
	default:
		writeError(w, http.StatusBadRequest, "unsupported format: "+format+"; use set, text, json, or xml")
		return
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) configCompareHandler(w http.ResponseWriter, r *http.Request) {
	// #3443: rollback is a change-control selector — fail closed on a
	// malformed/negative value instead of silently defaulting to 0
	// (candidate-vs-active), which would compare the wrong target. An
	// absent parameter keeps the documented default of 0.
	rollbackN, ok := queryIntStrict(r, "rollback", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid rollback parameter: must be a non-negative integer")
		return
	}
	if rollbackN > 0 {
		diff, err := s.store.ShowCompareRollbackRedacted(rollbackN)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeOK(w, TextResponse{Output: diff})
		return
	}
	writeOK(w, TextResponse{Output: s.store.ShowCompareRedacted()})
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
	// Search over the redacted render so a matching line never returns a
	// cleartext secret in its snippet (#4051).
	text := s.store.ShowActiveRedacted(nil)
	var results []ConfigSearchResult
	for i, line := range strings.Split(text, "\n") {
		if strings.Contains(line, query) {
			results = append(results, ConfigSearchResult{LineNumber: i + 1, Line: line})
		}
	}
	writeOK(w, results)
}

func (s *Server) configLoadHandler(w http.ResponseWriter, r *http.Request) {
	// Bound the request body so an oversized config-load payload is rejected
	// before it reaches the parser (H-2). configstore.LoadOverride/LoadMerge/
	// LoadSet re-check the decoded content against MaxConfigSize.
	r.Body = http.MaxBytesReader(w, r.Body, maxConfigBodyBytes)
	var req ConfigLoadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("config body exceeds %d bytes", maxConfigBodyBytes))
			return
		}
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
	case "set":
		// #2052: make `load set` a real service-mode op (REST). LoadSet
		// replays flat lines through applyEditLine so a body with
		// `deactivate <path>` lines round-trips to inactive nodes (#2008 H1).
		// Applied-count is log-only to keep the response shape stable.
		count, err := s.store.LoadSet(req.Content)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		slog.Info("load set applied", "commands", count)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown load mode: %s (use 'override', 'merge', or 'set')", req.Mode))
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
	// #3443: n selects a 1-based rollback slot. Fail closed on a
	// malformed/negative value instead of silently defaulting to slot 1,
	// which would show a different rollback than the operator asked for.
	n, ok := queryIntStrict(r, "n", 1)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid n parameter: must be a non-negative integer")
		return
	}
	format := r.URL.Query().Get("format")

	var output string
	var err error
	if format == "set" {
		output, err = s.store.ShowRollbackSetRedacted(n)
	} else {
		output, err = s.store.ShowRollbackRedacted(n)
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
