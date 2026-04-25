package grpcapi

import (
	"context"
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
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown load mode: %s (use 'override' or 'merge')", req.Mode)
	}
	return &pb.LoadResponse{}, nil
}

func (s *Server) Commit(ctx context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	// If a confirmed commit is pending, confirm it
	if s.store.IsConfirmPending() {
		if err := s.store.ConfirmCommit(); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.CommitResponse{}, nil
	}

	// Capture diff summary before commit (active will change)
	summary := s.store.CommitDiffSummary()

	var compiled *config.Config
	var err error
	if req.Comment != "" {
		compiled, err = s.store.CommitWithDescription(req.Comment)
	} else {
		compiled, err = s.store.Commit()
	}
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// #846: prefer context-aware ApplyFnCtx when available so client
	// cancel/timeout doesn't queue an apply behind a long FRR reload.
	if s.applyFnCtx != nil {
		if err := s.applyFnCtx(ctx, compiled); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return nil, status.Errorf(codes.DeadlineExceeded, "apply: %v", err)
			}
			return nil, status.Errorf(codes.Canceled, "apply: %v", err)
		}
	} else if s.applyFn != nil {
		s.applyFn(compiled)
	}
	return &pb.CommitResponse{Summary: summary}, nil
}

func (s *Server) CommitCheck(_ context.Context, _ *pb.CommitCheckRequest) (*pb.CommitCheckResponse, error) {
	if _, err := s.store.CommitCheck(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.CommitCheckResponse{}, nil
}

func (s *Server) CommitConfirmed(ctx context.Context, req *pb.CommitConfirmedRequest) (*pb.CommitConfirmedResponse, error) {
	compiled, err := s.store.CommitConfirmed(int(req.Minutes))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if s.applyFnCtx != nil {
		if err := s.applyFnCtx(ctx, compiled); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return nil, status.Errorf(codes.DeadlineExceeded, "apply: %v", err)
			}
			return nil, status.Errorf(codes.Canceled, "apply: %v", err)
		}
	} else if s.applyFn != nil {
		s.applyFn(compiled)
	}
	return &pb.CommitConfirmedResponse{}, nil
}

func (s *Server) ConfirmCommit(_ context.Context, _ *pb.ConfirmCommitRequest) (*pb.ConfirmCommitResponse, error) {
	if err := s.store.ConfirmCommit(); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return &pb.ConfirmCommitResponse{}, nil
}

func (s *Server) Rollback(_ context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
	if err := s.store.Rollback(int(req.N)); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.RollbackResponse{}, nil
}

func (s *Server) ShowConfig(_ context.Context, req *pb.ShowConfigRequest) (*pb.ShowConfigResponse, error) {
	var output string
	hasPath := len(req.Path) > 0
	switch {
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_JSON:
		if hasPath {
			output = s.store.ShowActivePathJSON(req.Path)
		} else {
			output = s.store.ShowActiveJSON()
		}
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_SET:
		if hasPath {
			output = s.store.ShowActivePathSet(req.Path)
		} else {
			output = s.store.ShowActiveSet()
		}
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_XML:
		if hasPath {
			output = s.store.ShowActivePathXML(req.Path)
		} else {
			output = s.store.ShowActiveXML()
		}
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_INHERITANCE:
		if hasPath {
			output = s.store.ShowActivePathInheritance(req.Path)
		} else {
			output = s.store.ShowActiveInheritance()
		}
	case req.Target == pb.ConfigTarget_ACTIVE:
		if hasPath {
			output = s.store.ShowActivePath(req.Path)
		} else {
			output = s.store.ShowActive()
		}
	case req.Format == pb.ConfigFormat_JSON:
		if hasPath {
			output = s.store.ShowCandidatePathJSON(req.Path)
		} else {
			output = s.store.ShowCandidateJSON()
		}
	case req.Format == pb.ConfigFormat_SET:
		if hasPath {
			output = s.store.ShowCandidatePathSet(req.Path)
		} else {
			output = s.store.ShowCandidateSet()
		}
	case req.Format == pb.ConfigFormat_XML:
		if hasPath {
			output = s.store.ShowCandidatePathXML(req.Path)
		} else {
			output = s.store.ShowCandidateXML()
		}
	case req.Format == pb.ConfigFormat_INHERITANCE:
		if hasPath {
			output = s.store.ShowCandidatePathInheritance(req.Path)
		} else {
			output = s.store.ShowCandidateInheritance()
		}
	default:
		if hasPath {
			output = s.store.ShowCandidatePath(req.Path)
		} else {
			output = s.store.ShowCandidate()
		}
	}
	return &pb.ShowConfigResponse{Output: output}, nil
}

func (s *Server) ShowCompare(_ context.Context, req *pb.ShowCompareRequest) (*pb.ShowCompareResponse, error) {
	if req.RollbackN > 0 {
		diff, err := s.store.ShowCompareRollback(int(req.RollbackN))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return &pb.ShowCompareResponse{Output: diff}, nil
	}
	return &pb.ShowCompareResponse{Output: s.store.ShowCompare()}, nil
}

func (s *Server) ShowRollback(_ context.Context, req *pb.ShowRollbackRequest) (*pb.ShowRollbackResponse, error) {
	var output string
	var err error
	if req.Format == pb.ConfigFormat_SET {
		output, err = s.store.ShowRollbackSet(int(req.N))
	} else {
		output, err = s.store.ShowRollback(int(req.N))
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
