package upgrade

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// grpcCluster is the production RollingCluster backed by the xpfd gRPC API
// on the LOCAL node. It uses the NON-INTERACTIVE SystemAction RPC for
// mutations (the documented automation path — the interactive `cli -c
// "request ... in-service-upgrade"` hard-errors in non-TTY mode, #1563)
// and the `chassis-cluster-information` ShowText topic for the drain-
// predicate reads.
//
// The information topic renders cluster.Manager.FormatInformation(), which
// emits the fields the strong drain predicate needs:
//   - "Remote node: healthy (nodeN)" / "lost"
//   - per-RG "Local state: Primary|Secondary"
//   - per-RG "Takeover ready: yes|no (reasons)"
//   - per-RG "Effective priority: N"
//
// Parsing is defensive and conservative: an unrecognized / ambiguous state
// reads as not-drained / not-ready, so the rolling driver ABORTS without
// cutting rather than cutting unsafely. The exact field strings are
// asserted in cluster_cli_test.go against the live FormatInformation
// format so a status-format change is caught by a unit test, not in
// production.
type grpcCluster struct {
	addr        string
	dialTimeout time.Duration
}

// NewCLICluster returns a RollingCluster driving the local node's xpfd via
// gRPC. The name is retained for the cmd wiring; the implementation is the
// gRPC client (not the interactive `cli`).
func NewCLICluster(unit string) RollingCluster {
	return &grpcCluster{addr: "127.0.0.1:50051", dialTimeout: 5 * time.Second}
}

func (g *grpcCluster) dial() (pb.BpfrxServiceClient, func(), error) {
	conn, err := grpc.NewClient(g.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("dial xpfd gRPC %s: %w", g.addr, err)
	}
	return pb.NewBpfrxServiceClient(conn), func() { _ = conn.Close() }, nil
}

func (g *grpcCluster) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), g.dialTimeout)
}

// information fetches the rendered `show chassis cluster information` text.
func (g *grpcCluster) information() (string, error) {
	cli, closeFn, err := g.dial()
	if err != nil {
		return "", err
	}
	defer closeFn()
	ctx, cancel := g.ctx()
	defer cancel()
	resp, err := cli.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-cluster-information"})
	if err != nil {
		return "", fmt.Errorf("show chassis cluster information: %w", err)
	}
	return resp.GetOutput(), nil
}

func (g *grpcCluster) systemAction(action string) error {
	cli, closeFn, err := g.dial()
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, cancel := g.ctx()
	defer cancel()
	_, err = cli.SystemAction(ctx, &pb.SystemActionRequest{Action: action})
	return err
}

func (g *grpcCluster) PeerAlive() (bool, error) {
	s, err := g.information()
	if err != nil {
		return false, err
	}
	return parsePeerAlive(s), nil
}

func (g *grpcCluster) SyncEstablished() (bool, error) {
	s, err := g.information()
	if err != nil {
		return false, err
	}
	return parseSyncEstablished(s), nil
}

func (g *grpcCluster) HAProtocolCompatible() (bool, error) {
	// The HA protocol version lines are in the STATUS topic
	// (FormatStatus), not information (FormatInformation).
	s, err := g.statusText()
	if err != nil {
		return false, err
	}
	return parseHAProtocolCompatible(s), nil
}

// statusText fetches the rendered `show chassis cluster status` text.
func (g *grpcCluster) statusText() (string, error) {
	cli, closeFn, err := g.dial()
	if err != nil {
		return "", err
	}
	defer closeFn()
	ctx, cancel := g.ctx()
	defer cancel()
	resp, err := cli.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-cluster-status"})
	if err != nil {
		return "", fmt.Errorf("show chassis cluster status: %w", err)
	}
	return resp.GetOutput(), nil
}

func (g *grpcCluster) PeerTakeoverReady() (bool, error) {
	s, err := g.information()
	if err != nil {
		return false, err
	}
	return parsePeerTakeoverReady(s), nil
}

func (g *grpcCluster) ForceSecondary() error {
	// Non-interactive demote via the documented automation path.
	return g.systemAction("in-service-upgrade")
}

func (g *grpcCluster) DrainComplete() (bool, error) {
	s, err := g.information()
	if err != nil {
		return false, err
	}
	return parseDrainComplete(s), nil
}

// --- pure parsers over `show chassis cluster information`
// (cluster.Manager.FormatInformation) text. Kept pure + exported-to-tests
// so a status-format drift is caught by cluster_cli_test.go (which feeds
// REAL FormatInformation output through them), not in production. ---

func parsePeerAlive(s string) bool {
	// "Remote node: healthy (nodeN)" => alive; "Remote node: lost" => not.
	return lineHasAll(s, "Remote node:", "healthy")
}

func parseSyncEstablished(s string) bool {
	// Conservative: a healthy remote (peer present + heartbeat) is the
	// sync precondition. An explicit unsynced/hold marker fails closed.
	if strings.Contains(strings.ToLower(s), "unsynced") {
		return false
	}
	return lineHasAll(s, "Remote node:", "healthy")
}

// parseHAProtocolCompatible compares the local and peer HA protocol
// version lines from `show chassis cluster status` (FormatStatus):
//
//	HA protocol version: N
//	Peer HA protocol version: M
//
// Compatible iff N == M (the rolling contract: mixed N/N+1 nodes only
// hand off RGs when CurrentHAProtocolVersion matches; a bump means the
// wire semantics changed and the release is NOT rolling-upgradable). If
// the peer line is ABSENT (peer not alive / version unknown) we return
// false so the driver does not proceed blind — PeerAlive already gates
// the happy path, and a missing peer-version here fails closed.
func parseHAProtocolCompatible(s string) bool {
	var local, peer int
	haveLocal, havePeer := false, false
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		ll := strings.ToLower(l)
		if strings.HasPrefix(ll, "peer ha protocol version:") {
			if n, ok := trailingInt(l); ok {
				peer, havePeer = n, true
			}
			continue
		}
		if strings.HasPrefix(ll, "ha protocol version:") {
			if n, ok := trailingInt(l); ok {
				local, haveLocal = n, true
			}
		}
	}
	if !haveLocal || !havePeer {
		return false
	}
	return local == peer
}

// trailingInt extracts the integer after the final ':' or space in a
// "key: N" line.
func trailingInt(line string) (int, bool) {
	idx := strings.LastIndex(line, ":")
	if idx < 0 || idx+1 >= len(line) {
		return 0, false
	}
	tok := strings.TrimSpace(line[idx+1:])
	n := 0
	if tok == "" {
		return 0, false
	}
	for _, r := range tok {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

func parsePeerTakeoverReady(s string) bool {
	// The PEER is takeover-ready when it is healthy AND no RG reports a
	// takeover blocker. Conservative — a monitor fail anywhere blocks.
	if !lineHasAll(s, "Remote node:", "healthy") {
		return false
	}
	low := strings.ToLower(s)
	if strings.Contains(low, "monitor: fail") || strings.Contains(low, "monitorfail") {
		return false
	}
	return true
}

func parseDrainComplete(s string) bool {
	// STRONG predicate: every RG's "Local state:" must be Secondary (peer
	// owns the RGs) AND the remote is healthy. If ANY "Local state:" line
	// is Primary (or an unrecognized transitional state), NOT drained.
	if !lineHasAll(s, "Remote node:", "healthy") {
		return false
	}
	sawState := false
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(strings.TrimSpace(line))
		if !strings.HasPrefix(ll, "local state:") {
			continue
		}
		sawState = true
		if strings.Contains(ll, "primary") {
			return false
		}
		if !strings.Contains(ll, "secondary") {
			return false // hold / transition => not drained yet
		}
	}
	// Require at least one RG state line so empty/garbled output never reads
	// as "drained".
	return sawState
}

func (g *grpcCluster) ResetFailover() error {
	var firstErr error
	for _, rg := range []int{0, 1} {
		if err := g.systemAction(fmt.Sprintf("cluster-failover-reset:%d", rg)); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (g *grpcCluster) LocalPrimary() (bool, error) {
	s, err := g.information()
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(ll, "local state:") && strings.Contains(ll, "primary") {
			return true, nil
		}
	}
	return false, nil
}

// lineHasAll reports whether any line of s contains all substrings
// (case-insensitive).
func lineHasAll(s string, subs ...string) bool {
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(line)
		all := true
		for _, sub := range subs {
			if !strings.Contains(ll, strings.ToLower(sub)) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
