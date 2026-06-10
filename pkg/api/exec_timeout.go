package api

import (
	"context"
	"os/exec"
	"time"
)

// Request-path exec bounding (#1805). This mirrors the apply-path helper
// in pkg/daemon/exec_timeout.go (#1794), which is the contract reference
// for the 15s/5s constants. It cannot be imported here: pkg/daemon
// imports pkg/api (daemon_run.go), so a shared helper would create an
// import cycle. pkg/grpcapi carries the sibling copy with the
// Output/CombinedOutput variants; this package's only raw exec sites
// are the deferred power actions, so only the Run variant exists here —
// add the other variants from pkg/grpcapi/exec_timeout.go if a future
// handler needs command output.

// requestExecTimeout bounds the child process runtime; on expiry the
// process is killed and the error reflects the context deadline.
const requestExecTimeout = 15 * time.Second

// requestExecWaitDelay caps the post-kill pipe-drain window (see the
// WaitDelay rationale in pkg/daemon/exec_timeout.go): without it, Wait
// blocks until every inherited write end of the output pipes closes,
// which may be long after the main process dies. Hard ceiling per exec
// becomes its context timeout + 5s.
const requestExecWaitDelay = 5 * time.Second

// runTimeout runs a command under the request-path bound, discarding
// output (wraps cmd.Run()). Used by the deferred power-action
// goroutines, which pass context.Background() — a client disconnect
// must not cancel a confirmed reboot/halt — and ignore the returned
// error exactly as the raw .Run() calls did.
func runTimeout(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, requestExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = requestExecWaitDelay
	return cmd.Run()
}
