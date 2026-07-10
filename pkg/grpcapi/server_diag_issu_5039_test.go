package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestSystemActionISSUNoCluster: the ISSU SystemAction arm rejects with
// Unavailable when no cluster manager is wired.
func TestSystemActionISSUNoCluster(t *testing.T) {
	s := NewServer("", Config{})
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "in-service-upgrade"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("SystemAction(in-service-upgrade) code = %v, want Unavailable", status.Code(err))
	}
}

// TestSystemActionISSUGatesOnDrainStart proves the handler still gates the
// operator report on a successful ForceSecondary: with no live peer the drain
// cannot start, so the RPC must return an error and NOT a "drained" success
// message (#5039 — never certify a drain that did not begin).
func TestSystemActionISSUGatesOnDrainStart(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "in-service-upgrade"})
	if err == nil {
		t.Fatalf("expected error when peer not alive, got response %q", resp.GetMessage())
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("SystemAction(in-service-upgrade) code = %v, want FailedPrecondition", status.Code(err))
	}
	if !strings.Contains(err.Error(), "ISSU:") {
		t.Fatalf("error = %q, want it to mention ISSU", err.Error())
	}
}

// TestSystemActionISSUWireFormat pins the exact operator text the ISSU RPC
// emits for both handoff outcomes: the response is the shared, #5039-honest
// report joined by newlines. This guards the gRPC surface's wire format against
// a revert to the old unconditional "Traffic has been drained to peer" string.
func TestSystemActionISSUWireFormat(t *testing.T) {
	confirmed := strings.Join(cluster.UpgradeDrainReport(true), "\n")
	if !strings.Contains(confirmed, "traffic drained to peer") ||
		!strings.Contains(confirmed, "systemctl stop xpfd") {
		t.Errorf("confirmed ISSU wire message not honest:\n%s", confirmed)
	}
	unconfirmed := strings.Join(cluster.UpgradeDrainReport(false), "\n")
	if strings.Contains(unconfirmed, "has been drained to peer") ||
		strings.Contains(unconfirmed, "traffic drained to peer") {
		t.Errorf("unconfirmed ISSU wire message must NOT certify the drain:\n%s", unconfirmed)
	}
	if !strings.Contains(unconfirmed, "Do NOT stop xpfd yet") {
		t.Errorf("unconfirmed ISSU wire message must warn against stopping:\n%s", unconfirmed)
	}
}
