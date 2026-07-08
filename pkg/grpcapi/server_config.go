package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- Config lifecycle RPCs ---

func (s *Server) EnterConfigure(ctx context.Context, req *pb.EnterConfigureRequest) (*pb.EnterConfigureResponse, error) {
	// Block configure mode on secondary node — config changes must
	// be made on the primary (RG0 is config authority).
	if s.cluster != nil && !s.cluster.IsLocalPrimary(0) {
		return nil, status.Errorf(codes.FailedPrecondition, "node is not primary for RG0, configure on the primary node")
	}
	sessionID := peerSessionID(ctx)
	var err error
	if req.Exclusive {
		err = s.store.EnterConfigureExclusive(sessionID)
	} else {
		err = s.store.EnterConfigureSession(sessionID)
	}
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return &pb.EnterConfigureResponse{}, nil
}

func (s *Server) ExitConfigure(ctx context.Context, _ *pb.ExitConfigureRequest) (*pb.ExitConfigureResponse, error) {
	sessionID := peerSessionID(ctx)
	s.store.ExitConfigureSession(sessionID)
	return &pb.ExitConfigureResponse{}, nil
}

func (s *Server) GetConfigModeStatus(_ context.Context, _ *pb.GetConfigModeStatusRequest) (*pb.GetConfigModeStatusResponse, error) {
	return &pb.GetConfigModeStatusResponse{
		InConfigMode:   s.store.InConfigMode(),
		Dirty:          s.store.IsDirty(),
		ConfirmPending: s.store.IsConfirmPending(),
	}, nil
}

func (s *Server) Set(_ context.Context, req *pb.SetRequest) (*pb.SetResponse, error) {
	input := req.Input
	if strings.HasPrefix(input, "copy ") || strings.HasPrefix(input, "rename ") {
		return s.handleCopyRename(input)
	}
	if strings.HasPrefix(input, "insert ") {
		return s.handleInsert(input)
	}
	// #2051: the remote CLI rides the Set RPC for activate/deactivate (no
	// dedicated RPC). Prefix-route the verb to the store wrapper BEFORE the
	// SetFromInput fall-through — otherwise the generic fall-through builds
	// the junk path "set deactivate <path>" (a config node named after the
	// verb) and the node is never marked inactive. The store wrappers strip
	// the verb and route through applyEditLine (the centralized verb switch).
	// Match the verb as the first whitespace-delimited token (not just an
	// exact "deactivate "/"activate " prefix) so a tab separator or extra
	// spaces still route, and a bare verb with no path returns an error
	// instead of falling through to SetFromInput and creating a junk
	// "deactivate"/"activate" node.
	if fields := strings.Fields(input); len(fields) > 0 &&
		(fields[0] == "deactivate" || fields[0] == "activate") {
		verb := fields[0]
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(input), verb))
		if rest == "" {
			return nil, status.Errorf(codes.InvalidArgument,
				"%s requires a configuration path", verb)
		}
		var err error
		if verb == "deactivate" {
			err = s.store.DeactivateFromInput(rest)
		} else {
			err = s.store.ActivateFromInput(rest)
		}
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return &pb.SetResponse{}, nil
	}
	if err := s.store.SetFromInput(input); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.SetResponse{}, nil
}

func (s *Server) handleCopyRename(input string) (*pb.SetResponse, error) {
	parts := strings.Fields(input)
	isRename := parts[0] == "rename"
	toIdx := -1
	for i, p := range parts {
		if p == "to" {
			toIdx = i
			break
		}
	}
	if toIdx < 2 || toIdx >= len(parts)-1 {
		return nil, status.Errorf(codes.InvalidArgument, "usage: %s <src> to <dst>", parts[0])
	}
	srcPath := parts[1:toIdx]
	dstPath := parts[toIdx+1:]
	var err error
	if isRename {
		err = s.store.Rename(srcPath, dstPath)
	} else {
		err = s.store.Copy(srcPath, dstPath)
	}
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.SetResponse{}, nil
}

func (s *Server) handleInsert(input string) (*pb.SetResponse, error) {
	parts := strings.Fields(input)
	kwIdx := -1
	isBefore := false
	for i, p := range parts {
		if p == "before" {
			kwIdx = i
			isBefore = true
			break
		}
		if p == "after" {
			kwIdx = i
			break
		}
	}
	if kwIdx < 2 || kwIdx >= len(parts)-1 {
		return nil, status.Errorf(codes.InvalidArgument, "usage: insert <element-path> before|after <ref-identifier>")
	}
	elemPath := parts[1:kwIdx]
	refTokens := parts[kwIdx+1:]
	if len(refTokens) > len(elemPath) {
		return nil, status.Errorf(codes.InvalidArgument, "reference identifier is longer than element path")
	}
	parentPath := elemPath[:len(elemPath)-len(refTokens)]
	refPath := append(append([]string{}, parentPath...), refTokens...)
	if err := s.store.Insert(elemPath, refPath, isBefore); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.SetResponse{}, nil
}

func (s *Server) Delete(_ context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error) {
	if err := s.store.DeleteFromInput(req.Input); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.DeleteResponse{}, nil
}

func (s *Server) Load(_ context.Context, req *pb.LoadRequest) (*pb.LoadResponse, error) {
	switch req.Mode {
	case "override":
		if err := s.store.LoadOverride(req.Content); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	case "merge", "":
		if err := s.store.LoadMerge(req.Content); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	case "set":
		// #2052: make `load set` a real service-mode op. LoadSet replays the
		// flat command lines through applyEditLine, so a body containing
		// `deactivate <path>` lines (emitted by `show | display set` for
		// inactive nodes, #2008 H1) round-trips back to an inactive node.
		// The applied-count is log-only (LoadResponse has no count field).
		count, err := s.store.LoadSet(req.Content)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		slog.Info("load set applied", "commands", count)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown load mode: %s (use 'override', 'merge', or 'set')", req.Mode)
	}
	return &pb.LoadResponse{}, nil
}

func (s *Server) Commit(ctx context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	// Bare commit during a pending commit-confirmed window (#4000). Confirm
	// the pending config only when the candidate is UNCHANGED; new staged
	// edits fall through to the normal commit below, where the daemon commitFn
	// (CommitWithDescription, #3861) applies them AND clears the timer, so the
	// edits are committed rather than silently dropped.
	if s.store.IsConfirmPending() && !s.store.IsDirty() {
		if err := s.store.ConfirmCommit(); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.CommitResponse{}, nil
	}

	// Capture diff summary before commit (active will change)
	summary := s.store.CommitDiffSummary()

	if s.commitFn == nil {
		return nil, status.Errorf(codes.Internal, "commit handler not wired")
	}
	compiled, err := s.commitFn(ctx, req.Comment)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return nil, status.Errorf(codes.Canceled, "commit busy: %v", err)
		case errors.Is(err, context.DeadlineExceeded):
			return nil, status.Errorf(codes.DeadlineExceeded, "commit busy: %v", err)
		default:
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	}
	return &pb.CommitResponse{Summary: summary, Warnings: configWarnings(compiled)}, nil
}

func (s *Server) CommitCheck(_ context.Context, _ *pb.CommitCheckRequest) (*pb.CommitCheckResponse, error) {
	compiled, err := s.store.CommitCheck()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.CommitCheckResponse{Warnings: configWarnings(compiled)}, nil
}

func (s *Server) CommitConfirmed(ctx context.Context, req *pb.CommitConfirmedRequest) (*pb.CommitConfirmedResponse, error) {
	if s.commitConfirmedFn == nil {
		return nil, status.Errorf(codes.Internal, "commit-confirmed handler not wired")
	}
	compiled, err := s.commitConfirmedFn(ctx, int(req.Minutes))
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return nil, status.Errorf(codes.Canceled, "commit busy: %v", err)
		case errors.Is(err, context.DeadlineExceeded):
			return nil, status.Errorf(codes.DeadlineExceeded, "commit busy: %v", err)
		default:
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	}
	return &pb.CommitConfirmedResponse{Warnings: configWarnings(compiled)}, nil
}

func (s *Server) ConfirmCommit(_ context.Context, _ *pb.ConfirmCommitRequest) (*pb.ConfirmCommitResponse, error) {
	if err := s.store.ConfirmCommit(); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return &pb.ConfirmCommitResponse{}, nil
}

func (s *Server) Rollback(_ context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
	// #4589 A8-01: n==0 is the valid Junos `rollback 0` (revert to active);
	// n>=1 selects history slot n. A negative n maps to history.Get(n-1) =
	// history.Get(<-1>) → the opaque store error "history position -1 out of
	// range". Reject it up front with a clear message. Unlike ShowRollback
	// (#4556, n<=0) the mutation RPC keeps n==0 valid, so only n<0 is
	// rejected. Fail-closed either way — no wrong rollback target.
	if req.N < 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid n %d: rollback index must be non-negative (0 = revert to active)", req.N)
	}
	if err := s.store.Rollback(int(req.N)); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.RollbackResponse{}, nil
}

func configWarnings(cfg *config.Config) []string {
	if cfg == nil || len(cfg.Warnings) == 0 {
		return nil
	}
	return append([]string(nil), cfg.Warnings...)
}

func (s *Server) ShowConfig(_ context.Context, req *pb.ShowConfigRequest) (*pb.ShowConfigResponse, error) {
	// Secrets are masked on this raw-AST render RPC (#4051), matching the
	// #2053 typed-struct redaction. The redacted renderers take the path
	// directly (nil/empty selects the whole tree) and mirror the cleartext
	// siblings' nil-source defaults; the cleartext Show* SSOT still backs HA
	// config sync, the DR archive and persistence.
	var path []string
	if len(req.Path) > 0 {
		path = req.Path
	}
	var output string
	switch {
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_JSON:
		output = s.store.ShowActiveJSONRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_SET:
		output = s.store.ShowActiveSetRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_XML:
		output = s.store.ShowActiveXMLRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_INHERITANCE:
		output = s.store.ShowActiveInheritanceRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE:
		output = s.store.ShowActiveRedacted(path)
	case req.Format == pb.ConfigFormat_JSON:
		output = s.store.ShowCandidateJSONRedacted(path)
	case req.Format == pb.ConfigFormat_SET:
		output = s.store.ShowCandidateSetRedacted(path)
	case req.Format == pb.ConfigFormat_XML:
		output = s.store.ShowCandidateXMLRedacted(path)
	case req.Format == pb.ConfigFormat_INHERITANCE:
		output = s.store.ShowCandidateInheritanceRedacted(path)
	default:
		output = s.store.ShowCandidateRedacted(path)
	}
	return &pb.ShowConfigResponse{Output: output}, nil
}

func (s *Server) ShowCompare(_ context.Context, req *pb.ShowCompareRequest) (*pb.ShowCompareResponse, error) {
	// rollback_n is a change-control selector: 0 reserves candidate-vs-active,
	// positive values select a 1-based rollback slot. A negative value used to
	// fall through to the candidate-vs-active compare with a success response
	// (#3443 M6), silently comparing the wrong target. Reject it.
	if req.RollbackN < 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid rollback_n %d: must be non-negative (0 = candidate vs active)", req.RollbackN)
	}
	if req.RollbackN > 0 {
		diff, err := s.store.ShowCompareRollbackRedacted(int(req.RollbackN))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return &pb.ShowCompareResponse{Output: diff}, nil
	}
	return &pb.ShowCompareResponse{Output: s.store.ShowCompareRedacted()}, nil
}

func (s *Server) ShowRollback(_ context.Context, req *pb.ShowRollbackRequest) (*pb.ShowRollbackResponse, error) {
	// #4556 M-01: n selects a 1-based rollback slot. A non-positive n
	// (0 or a negative wire value) maps to history.Get(n-1) =
	// history.Get(<0) → the opaque store error "history position -1 out
	// of range". Reject it up front with a clear positive-integer
	// message, mirroring the REST show-rollback leg and the ShowCompare
	// rollback_n guard (#3443 M6).
	if req.N <= 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid n %d: rollback index must be a positive integer", req.N)
	}
	var output string
	var err error
	if req.Format == pb.ConfigFormat_SET {
		output, err = s.store.ShowRollbackSetRedacted(int(req.N))
	} else {
		output, err = s.store.ShowRollbackRedacted(int(req.N))
	}
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.ShowRollbackResponse{Output: output}, nil
}

func (s *Server) ListHistory(_ context.Context, _ *pb.ListHistoryRequest) (*pb.ListHistoryResponse, error) {
	entries := s.store.ListHistory()
	resp := &pb.ListHistoryResponse{}
	for i, e := range entries {
		resp.Entries = append(resp.Entries, &pb.HistoryEntry{
			Index:     int32(i + 1),
			Timestamp: e.Timestamp.Format("2006-01-02 15:04:05"),
		})
	}
	return resp, nil
}
