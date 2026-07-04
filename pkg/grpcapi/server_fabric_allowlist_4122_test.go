package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #4122: the cluster fabric gRPC listener is the only network-exposed gRPC
// surface (the loopback Run() listener binds 127.0.0.1). It must fail-close to
// the exact set of read/monitor RPCs the peer actually proxies; every other
// method — Commit/Delete/Rollback, the config-mode surface, and
// SystemAction{zeroize,reboot,halt,power-off} — must be rejected with
// PermissionDenied before the handler runs. These tests exercise the fabric
// interceptors directly; on revert (interceptors removed / SystemAction
// admitted / a destructive method added to the allowlist) they go RED because
// the full service — including zeroize — becomes reachable on the fabric IP.

// sentinelHandler records whether the unary handler was reached.
type unaryCallProbe struct{ called bool }

func (p *unaryCallProbe) handler(ctx context.Context, req interface{}) (interface{}, error) {
	p.called = true
	return "ok", nil
}

func TestFabricAllowlistUnary_AllowsProxiedReadMonitorRPCs(t *testing.T) {
	s := &Server{}
	allowed := []string{
		pb.BpfrxService_GetStatus_FullMethodName,
		pb.BpfrxService_GetSessions_FullMethodName,
		pb.BpfrxService_GetSessionSummary_FullMethodName,
		pb.BpfrxService_GetZonePairSummary_FullMethodName,
		pb.BpfrxService_ShowText_FullMethodName,
		pb.BpfrxService_ClearSessions_FullMethodName,
	}
	for _, method := range allowed {
		probe := &unaryCallProbe{}
		info := &grpc.UnaryServerInfo{FullMethod: method}
		resp, err := s.fabricAllowlistUnaryInterceptor(context.Background(), nil, info, probe.handler)
		if err != nil {
			t.Errorf("method %s: expected allow, got err %v", method, err)
		}
		if !probe.called {
			t.Errorf("method %s: handler was not invoked", method)
		}
		if resp != "ok" {
			t.Errorf("method %s: expected handler response passthrough, got %v", method, resp)
		}
	}
}

func TestFabricAllowlistUnary_DeniesDestructiveAndUnknownMethods(t *testing.T) {
	s := &Server{}
	denied := []string{
		pb.BpfrxService_Commit_FullMethodName,
		pb.BpfrxService_CommitConfirmed_FullMethodName,
		pb.BpfrxService_Delete_FullMethodName,
		pb.BpfrxService_Rollback_FullMethodName,
		pb.BpfrxService_Load_FullMethodName,
		pb.BpfrxService_Set_FullMethodName,
		pb.BpfrxService_EnterConfigure_FullMethodName,
		"/xpf.v1.BpfrxService/DoesNotExist", // unknown method
	}
	for _, method := range denied {
		probe := &unaryCallProbe{}
		info := &grpc.UnaryServerInfo{FullMethod: method}
		_, err := s.fabricAllowlistUnaryInterceptor(context.Background(), nil, info, probe.handler)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("method %s: expected PermissionDenied, got %v", method, err)
		}
		if probe.called {
			t.Errorf("method %s: handler was invoked on a denied method", method)
		}
	}
}

// TestFabricAllowlistUnary_SystemActionNestedGate verifies the nested-action
// decision: SystemAction is admitted on the fabric ONLY for the two proxied
// cross-node cluster-failover forms; every destructive / local-only action is
// denied. On revert (SystemAction added to the plain allowlist, or the nested
// gate removed) the zeroize case goes RED — a factory-reset wipe becomes
// reachable unauth on the fabric IP.
func TestFabricAllowlistUnary_SystemActionNestedGate(t *testing.T) {
	s := &Server{}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_SystemAction_FullMethodName}

	deniedActions := []string{
		"zeroize",
		"reboot",
		"halt",
		"power-off",
		"clear-config-lock",
		"cluster-failover-reset:1", // local-only, never proxied
		"cluster-failover:1",       // no node suffix -> local-only, never proxied
	}
	for _, action := range deniedActions {
		probe := &unaryCallProbe{}
		req := &pb.SystemActionRequest{Action: action}
		_, err := s.fabricAllowlistUnaryInterceptor(context.Background(), req, info, probe.handler)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("SystemAction %q: expected PermissionDenied on fabric, got %v", action, err)
		}
		if probe.called {
			t.Errorf("SystemAction %q: handler was invoked on the fabric listener", action)
		}
	}

	allowedActions := []string{
		"cluster-failover-data:node0",
		"cluster-failover-data:node1",
		"cluster-failover:1:node0",
		"cluster-failover:2:node1",
	}
	for _, action := range allowedActions {
		probe := &unaryCallProbe{}
		req := &pb.SystemActionRequest{Action: action}
		_, err := s.fabricAllowlistUnaryInterceptor(context.Background(), req, info, probe.handler)
		if err != nil {
			t.Errorf("SystemAction %q: expected allow (cross-node failover proxy), got %v", action, err)
		}
		if !probe.called {
			t.Errorf("SystemAction %q: handler was not invoked", action)
		}
	}

	// A SystemAction with the wrong request type must not be admitted (defensive:
	// isFabricSafeSystemAction returns false rather than panicking).
	probe := &unaryCallProbe{}
	_, err := s.fabricAllowlistUnaryInterceptor(context.Background(), &pb.GetStatusRequest{}, info, probe.handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("SystemAction with wrong req type: expected PermissionDenied, got %v", err)
	}
	if probe.called {
		t.Error("SystemAction with wrong req type: handler was invoked")
	}
}

func TestFabricAllowlistStream_AllowsOnlyMonitorInterface(t *testing.T) {
	s := &Server{}

	// MonitorInterface (the only proxied stream) is allowed.
	streamCalled := false
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		streamCalled = true
		return nil
	}
	info := &grpc.StreamServerInfo{FullMethod: pb.BpfrxService_MonitorInterface_FullMethodName}
	if err := s.fabricAllowlistStreamInterceptor(nil, nil, info, handler); err != nil {
		t.Errorf("MonitorInterface stream: expected allow, got %v", err)
	}
	if !streamCalled {
		t.Error("MonitorInterface stream: handler was not invoked")
	}

	// A non-allowlisted stream (MonitorPacketDrop) is denied.
	streamCalled = false
	info = &grpc.StreamServerInfo{FullMethod: pb.BpfrxService_MonitorPacketDrop_FullMethodName}
	err := s.fabricAllowlistStreamInterceptor(nil, nil, info, handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("MonitorPacketDrop stream: expected PermissionDenied, got %v", err)
	}
	if streamCalled {
		t.Error("MonitorPacketDrop stream: handler was invoked on a denied stream")
	}
}

// TestFabricAllowlistExcludesDestructiveMethods guards the allowlist SETS so a
// future edit cannot silently add a destructive / config-mutating method (or
// SystemAction, which multiplexes zeroize) to the fabric surface.
func TestFabricAllowlistExcludesDestructiveMethods(t *testing.T) {
	mustNotBeAllowed := []string{
		pb.BpfrxService_Commit_FullMethodName,
		pb.BpfrxService_CommitConfirmed_FullMethodName,
		pb.BpfrxService_ConfirmCommit_FullMethodName,
		pb.BpfrxService_Delete_FullMethodName,
		pb.BpfrxService_Rollback_FullMethodName,
		pb.BpfrxService_Load_FullMethodName,
		pb.BpfrxService_Set_FullMethodName,
		pb.BpfrxService_EnterConfigure_FullMethodName,
		pb.BpfrxService_SystemAction_FullMethodName, // gated by action, never blanket-allowed
	}
	for _, method := range mustNotBeAllowed {
		if fabricAllowedUnaryMethods[method] {
			t.Errorf("%s must NOT be in fabricAllowedUnaryMethods", method)
		}
		if fabricAllowedStreamMethods[method] {
			t.Errorf("%s must NOT be in fabricAllowedStreamMethods", method)
		}
	}
}

// TestLoopbackListenerUnaffected proves the loopback (Run) path is unchanged:
// its only interceptor, configLockInterceptor, admits every method (including
// the destructive ones the fabric listener denies). On a non-cancelled context
// it simply invokes the handler and never touches s.store, so a zero-value
// Server is sufficient. This is the #4122 invariant that the allowlist is
// applied to the fabric surface ONLY.
func TestLoopbackListenerUnaffected(t *testing.T) {
	s := &Server{}
	for _, method := range []string{
		pb.BpfrxService_Commit_FullMethodName,
		pb.BpfrxService_Delete_FullMethodName,
		pb.BpfrxService_Rollback_FullMethodName,
		pb.BpfrxService_SystemAction_FullMethodName,
	} {
		probe := &unaryCallProbe{}
		info := &grpc.UnaryServerInfo{FullMethod: method}
		resp, err := s.configLockInterceptor(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}, info, probe.handler)
		if err != nil {
			t.Errorf("loopback configLockInterceptor denied %s: %v", method, err)
		}
		if !probe.called {
			t.Errorf("loopback configLockInterceptor did not invoke handler for %s", method)
		}
		if resp != "ok" {
			t.Errorf("loopback configLockInterceptor did not pass through response for %s", method)
		}
	}
}
