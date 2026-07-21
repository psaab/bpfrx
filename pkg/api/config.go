package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// restConfigSessionID is the fixed config-lock holder identity every REST
// config MUTATION runs under (#5870). REST is stateless across calls, so all
// REST config edits share ONE logical operator identity that PARTICIPATES in
// the shared-candidate holder lock, rather than passing the empty session ID
// that the store treats as its internal/system capability (daemon apply, HA
// sync, in-process CLI) and which BYPASSES the holder lock entirely.
//
// Consequences of routing every REST mutation through this non-empty identity:
//   - a REST set/delete/commit is REJECTED (ErrConfigLockedByOther) when a CLI
//     or gRPC configuration session owns the candidate, and symmetrically a
//     CLI/gRPC mutation is rejected while REST holds it — closing the exact
//     cross-session candidate-corruption / commit-smuggling hole in #5870.
//   - the store's sessionID=="" system-bypass semantics are untouched; only the
//     REST layer stops USING that bypass. Read-only REST endpoints are
//     unaffected.
//
// It is deliberately non-empty and constant. A gRPC config session is keyed by
// a random per-connection token / peer address (pkg/grpcapi connSessionID), so
// this literal never collides with a real peer session identity.
//
// Statelessness caveat: because REST carries no per-request session token, two
// concurrent REST clients share this one identity and are NOT mutually
// excluded from each other (only from CLI/gRPC). Giving each REST caller a
// distinct token is a REST API contract change (a product decision) tracked
// separately; this fix closes the cross-transport bypass without expanding
// scope.
const restConfigSessionID = "rest"

// writeConfigMutationError maps a config-store mutation error to an HTTP
// status. A holder-lock conflict (ErrConfigLockedByOther) — a REST mutation
// attempted while a CLI/gRPC session owns the shared candidate (#5870) — is a
// 409 Conflict, matching configEnterHandler's lock response; every other error
// (parse/validation/not-in-config-mode) stays a 400 Bad Request.
func writeConfigMutationError(w http.ResponseWriter, err error) {
	if errors.Is(err, configstore.ErrConfigLockedByOther) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func (s *Server) configHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, nil)
		return
	}
	writeOK(w, cfg)
}

func (s *Server) configEnterHandler(w http.ResponseWriter, _ *http.Request) {
	// #5870: acquire the candidate lock under the fixed REST identity so a REST
	// config session participates in holder enforcement (a concurrent CLI/gRPC
	// session that owns the candidate makes this return ErrConfigLocked → 409),
	// instead of the empty-session internal acquire that recorded no holder.
	if err := s.store.EnterConfigureSession(restConfigSessionID); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configExitHandler(w http.ResponseWriter, _ *http.Request) {
	// #5870: release ONLY the REST-held lock. Session-scoped exit is a no-op
	// when a CLI/gRPC session owns the candidate, so a REST /config/exit can no
	// longer force-clear another session's in-progress candidate (the previous
	// unconditional ExitConfigure was itself a facet of the bypass). A wedged
	// REST lock is still reclaimed by the #4476 idle-lease reaper.
	s.store.ExitConfigureSession(restConfigSessionID)
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
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	if err := s.store.SetFromInputAs(restConfigSessionID, req.Input); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configDeleteHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	if err := s.store.DeleteFromInputAs(restConfigSessionID, req.Input); err != nil {
		writeConfigMutationError(w, err)
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
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	if err := s.store.DeactivateFromInputAs(restConfigSessionID, req.Input); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

// configActivateHandler clears the inactive marker on a candidate node
// (#2051), the REST equivalent of the interactive `activate <path>` verb.
func (s *Server) configActivateHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	if err := s.store.ActivateFromInputAs(restConfigSessionID, req.Input); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configCommitHandler(w http.ResponseWriter, r *http.Request) {
	// #5870: only the config-lock holder may commit the shared candidate. Reject
	// a REST commit before it can confirm/apply another (CLI/gRPC) session's
	// pending work — the empty-session commit path previously let a stateless
	// REST caller smuggle another operator's staged edits into an applied
	// commit. Mirrors the gRPC Commit gate (pkg/grpcapi/server_config.go).
	if err := s.store.EnsureConfigHolder(restConfigSessionID); err != nil {
		writeConfigMutationError(w, err)
		return
	}

	// Bare commit during a pending commit-confirmed window (#4000). Confirm
	// the pending config only when the candidate is UNCHANGED; new staged
	// edits fall through to the normal commit below, where commitFn applies
	// them AND clears the timer (#3861), so they are committed rather than
	// silently dropped.
	if s.store.IsConfirmPending() && !s.store.IsDirty() {
		if err := s.store.ConfirmCommitAs(restConfigSessionID); err != nil {
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
	if !decodeJSONBody(w, r, &req) {
		return
	}
	// #4589 A8-01: mirror the gRPC Rollback guard. n==0 = revert to active
	// (valid); a negative n reaches history.Get(<0) and surfaces the opaque
	// "history position -1 out of range" store error. Reject up front.
	if req.N < 0 {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("invalid n %d: rollback index must be non-negative (0 = revert to active)", req.N))
		return
	}
	// #5870: rollback replaces the candidate, so it runs under the REST holder
	// identity and is rejected when a CLI/gRPC session owns the candidate.
	if err := s.store.RollbackAs(restConfigSessionID, req.N); err != nil {
		writeConfigMutationError(w, err)
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
	// Bound the request body (M-7 shared decoder, 16 MiB -> 413) so an
	// oversized config-load payload is rejected at the transport before it
	// reaches the parser (H-2). configstore.LoadOverride/LoadMerge/LoadSet
	// re-check the decoded content against MaxConfigSize (also 16 MiB), the
	// transport-independent parser-layer ceiling.
	var req ConfigLoadRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content required")
		return
	}

	// #5870: load* is a candidate mutation, so it runs under the REST holder
	// identity and is rejected when a CLI/gRPC session owns the candidate.
	switch req.Mode {
	case "override":
		if err := s.store.LoadOverrideAs(restConfigSessionID, req.Content); err != nil {
			writeConfigMutationError(w, err)
			return
		}
	case "merge", "":
		if err := s.store.LoadMergeAs(restConfigSessionID, req.Content); err != nil {
			writeConfigMutationError(w, err)
			return
		}
	case "set":
		// #2052: make `load set` a real service-mode op (REST). LoadSet
		// replays flat lines through applyEditLine so a body with
		// `deactivate <path>` lines round-trips to inactive nodes (#2008 H1).
		// Applied-count is log-only to keep the response shape stable.
		count, err := s.store.LoadSetAs(restConfigSessionID, req.Content)
		if err != nil {
			writeConfigMutationError(w, err)
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
	if !decodeJSONBody(w, r, &req) {
		return
	}
	// #5870: only the config-lock holder may commit the shared candidate.
	// Mirrors the gRPC CommitConfirmed gate.
	if err := s.store.EnsureConfigHolder(restConfigSessionID); err != nil {
		writeConfigMutationError(w, err)
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
	// #5870: confirming a pending commit-confirmed is a holder-scoped op — only
	// the REST-held candidate may be confirmed from REST; a CLI/gRPC holder's
	// pending window is rejected (ErrConfigLockedByOther → 409).
	if err := s.store.ConfirmCommitAs(restConfigSessionID); err != nil {
		writeConfigMutationError(w, err)
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
	// #4556 M-01: n selects a 1-based rollback slot. 0 is a canonical
	// non-negative uint that clears queryIntStrict but then maps to
	// history.Get(n-1) = history.Get(-1) → the opaque store error
	// "history position -1 out of range". Reject n<=0 up front with a
	// clear positive-integer message (queryIntStrict already fails a
	// negative literal, so in practice this catches n=0), mirroring the
	// gRPC ShowRollback leg and the ShowCompare rollback_n guard.
	if n <= 0 {
		writeError(w, http.StatusBadRequest, "invalid n parameter: rollback index must be a positive integer")
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
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Path == "" || req.Comment == "" {
		writeJSON(w, http.StatusBadRequest, Response{Error: "path and comment are required"})
		return
	}
	pathParts := strings.Fields(req.Path)
	// #5870: annotate mutates the candidate, so it runs under the REST holder
	// identity and is rejected when a CLI/gRPC session owns the candidate. A
	// holder conflict maps to 409 Conflict; other errors stay 400.
	if err := s.store.AnnotateAs(restConfigSessionID, pathParts, req.Comment); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, configstore.ErrConfigLockedByOther) {
			status = http.StatusConflict
		}
		writeJSON(w, status, Response{Error: err.Error()})
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
