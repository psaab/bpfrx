package grpcapi

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/frr"
)

// frrStatusErr maps an FRR operational-read failure onto a gRPC status (#9143).
//
// frr.ErrVtyshBusy means the process-wide vtysh admission bound
// (diagcmd.VtyshLimiter) refused the shell-out: the FRR daemons are healthy and
// we declined to ask. That is codes.ResourceExhausted, the same code every other
// admission refusal in this process uses (diagcmd.ErrBusy on ping/traceroute,
// the session-walk limiter on the session RPCs) and the code the REST side
// renders as 429 for the same event. Reporting it as codes.Internal would send
// an operator debugging FRR after a load condition — the mistake #9142 fixed on
// the session-clear surface, and the one peerFetchErrorStatus (#7294/#8308)
// exists to avoid on the peer surfaces.
//
// Any other error keeps codes.Internal, including a non-FRR error handed to it,
// because errors.Is is false for those. prefix "" emits the bare error, matching
// the historical `status.Errorf(codes.Internal, "%v", err)` message verbatim.
func frrStatusErr(prefix string, err error) error {
	code := codes.Internal
	if errors.Is(err, frr.ErrVtyshBusy) {
		code = codes.ResourceExhausted
	}
	if prefix == "" {
		return status.Errorf(code, "%v", err)
	}
	return status.Errorf(code, "%s: %v", prefix, err)
}
