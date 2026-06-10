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

// Diag-stream budgets (#1819). Ping/Traceroute stream child output and
// legitimately run longer than requestExecTimeout, so they size their
// bound from the request instead of sharing the 15s constant. The same
// formulas live in pkg/api/exec_timeout.go for the HTTP REST siblings
// (not importable either way without an import cycle / a layering
// inversion); keep the two copies in sync.

// diagPingPacketInterval is the per-packet budget for ping: the
// handlers do not pass -i, so ping sends one packet per second
// (iputils default). If an interval knob is ever added to the request,
// this constant must become a parameter of pingExecTimeout.
const diagPingPacketInterval = 1 * time.Second

// diagExecSlack absorbs exec/VRF setup, DNS resolution, and the final
// per-packet reply timeout so a fully-successful run never grazes the
// deadline.
const diagExecSlack = 15 * time.Second

// diagPingFloor is the previous hardcoded streamDiagCmd bound. The
// #1819 right-sizing must not tighten any existing budget, so small
// counts keep at least the 30s they had.
const diagPingFloor = 30 * time.Second

// diagExecCeiling caps every request-sized diag budget. The Count
// clamp (≤100 → 115s) keeps well under it today; the ceiling is
// defense-in-depth so a future clamp change cannot let one request pin
// a handler goroutine for minutes.
const diagExecCeiling = 150 * time.Second

// diagTracerouteTimeout bounds gRPC and HTTP traceroute. Neither
// request carries max_ttl, so this is a constant rather than a
// formula; 60s matches the pre-#1819 HTTP bound (the gRPC path was
// 30s — this aligns it without tightening the HTTP side).
const diagTracerouteTimeout = 60 * time.Second

// pingExecTimeout sizes the ping budget from the (already clamped)
// packet count: count × 1s/packet + slack, floored at the previous 30s
// bound and capped at the diag ceiling.
func pingExecTimeout(count int) time.Duration {
	d := time.Duration(count)*diagPingPacketInterval + diagExecSlack
	if d < diagPingFloor {
		d = diagPingFloor
	}
	return clampDiagTimeout(d)
}

// clampDiagTimeout enforces diagExecCeiling on any diag-stream budget;
// streamDiagCmd applies it to whatever the caller passes so no future
// formula can exceed the ceiling.
func clampDiagTimeout(d time.Duration) time.Duration {
	if d > diagExecCeiling {
		return diagExecCeiling
	}
	return d
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
