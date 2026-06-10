package grpcapi

import (
	"context"
	"os/exec"
	"time"
)

// Request-path exec bounding (#1805). This mirrors the apply-path helper
// in pkg/daemon/exec_timeout.go (#1794), which is the contract reference
// for the 15s/5s constants. It cannot be imported here: pkg/daemon
// imports pkg/grpcapi (daemon_run.go), so a shared helper would create
// an import cycle. The gRPC handlers below external-exec on the request
// path (ps/df/ss/journalctl/chronyc/ntpq/timedatectl/tail/ip neigh
// flush/systemctl); without a bound, a wedged binary pins the handler
// goroutine and its gRPC stream indefinitely.
//
// requestExecTimeout bounds the child process runtime; on expiry the
// process is killed and the error reflects the context deadline.
const requestExecTimeout = 15 * time.Second

// requestExecWaitDelay caps the post-kill pipe-drain window (see the
// WaitDelay rationale in pkg/daemon/exec_timeout.go): without it,
// Output/CombinedOutput block until every inherited write end of the
// output pipe closes, which may be long after the main process dies.
// Hard ceiling per exec becomes 15s+5s=20s.
const requestExecWaitDelay = 5 * time.Second

// outputTimeout runs a command under the request-path bound and returns
// stdout only (wraps cmd.Output()). Used by sites whose stdout feeds
// user-visible responses directly — a CombinedOutput variant would leak
// stderr into them.
func outputTimeout(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = requestExecWaitDelay
	return cmd.Output()
}

// combinedOutputTimeout runs a command under the request-path bound and
// returns combined stdout+stderr (wraps cmd.CombinedOutput()), for the
// sites that already surface combined output today.
func combinedOutputTimeout(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = requestExecWaitDelay
	return cmd.CombinedOutput()
}

// runTimeout runs a command under the request-path bound, discarding
// output (wraps cmd.Run()). Used by the deferred power-action
// goroutines, which pass context.Background() — a client disconnect
// must not cancel a confirmed reboot/halt/poweroff — and ignore the
// returned error exactly as the raw .Run() calls did.
func runTimeout(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, requestExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = requestExecWaitDelay
	return cmd.Run()
}

// clampTailLines bounds the request-controlled `tail -n N` line count to
// [1, maxTailLines]. The time bound alone is insufficient here: N is
// attacker/operator-controlled and a huge N against a large log file
// completes well inside 15s while producing an unbounded response
// allocation — the byte exposure must be capped independently of time.
const maxTailLines = 10000

func clampTailLines(n int) int {
	if n < 1 {
		return 1
	}
	if n > maxTailLines {
		return maxTailLines
	}
	return n
}
