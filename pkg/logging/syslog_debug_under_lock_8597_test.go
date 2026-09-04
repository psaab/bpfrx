package logging

import (
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"testing"
	"time"
)

// #8597 (muse-004 K32) — the #2287 self-deadlock had two residual emit sites.
//
// #2287 moved the DROP WARNING out from under `SyslogClient.mu` (the
// `pendingDropWarn` capture-under-lock / emit-after-unlock pattern). Two
// `slog.Debug("... reconnecting")` calls on the SAME failure path stayed under
// the lock, in `Send` and in `SendBinary`.
//
// Why the existing #2287 cells could not see it: they install
// `slog.NewTextHandler(io.Discard, nil)` as the base handler, whose default
// level is Info. `slog.Debug` short-circuits in `slog.Default().Enabled()` and
// never reaches `SyslogSlogHandler.Handle`, so the record never routes back
// into the locked client. The defect lives on an axis those fixtures hold
// constant, not in a branch they miss: the ONLY difference between the cells
// below and `TestSelfReferentialSendNoDeadlock` is the base handler's LEVEL.
//
// `xpfd --debug` sets exactly that level (`cmd/xpfd/main.go`), and the daemon
// installs a `SyslogSlogHandler` as the default handler
// (`pkg/daemon/daemon_run.go`), so the production wiring under `--debug` is the
// wiring below: collector down + debug on, which is the state an operator
// creates while diagnosing a collector outage.
//
// Failure mode is a HANG, not a wrong value, so every cell here is bounded by
// a timeout — an unbounded version would make its own mutant a void.
func debugLevelSyslogHandler(t *testing.T, c *SyslogClient) {
	t.Helper()
	base := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})
	h := NewSyslogSlogHandler(base)
	h.SetClients([]*SyslogClient{c})
	withSlogDefault(t, h)
}

func failingStreamClient(addr string) *SyslogClient {
	return &SyslogClient{
		hostname:          "test",
		remoteAddr:        addr,
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              &alwaysFailConn{},
		dialFn:            func() (net.Conn, error) { return nil, errors.New("down") },
	}
}

// TestDebugLevelSelfReferentialSendNoDeadlock_8597 is the fix-on-revert proof
// for the `Send` site. Restoring `slog.Debug("syslog send failed,
// reconnecting", ...)` to its position under `s.mu` makes this cell time out.
func TestDebugLevelSelfReferentialSendNoDeadlock_8597(t *testing.T) {
	c := failingStreamClient("203.0.113.17:514")
	debugLevelSyslogHandler(t, c)

	done := make(chan struct{})
	go func() {
		_ = c.Send(SyslogInfo, "event-path message that drops with debug on")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Send did not return with a Debug-level base handler — the " +
			"reconnect slog.Debug is being emitted under s.mu (#8597/K32, the " +
			"#2287 residual)")
	}
}

// TestDebugLevelSelfReferentialSendBinaryNoDeadlock_8597 is the `SendBinary`
// arm. The two sites carry independent copies of the emit, so a fix applied to
// only one of them leaves the other wedging the event reader — and the binary
// path is the one the dataplane event reader actually uses for structured
// RT_FLOW records (`pkg/logging/ringbuf.go`).
func TestDebugLevelSelfReferentialSendBinaryNoDeadlock_8597(t *testing.T) {
	c := failingStreamClient("203.0.113.18:514")
	debugLevelSyslogHandler(t, c)

	done := make(chan struct{})
	go func() {
		// A self-framing record: length lives at [3:5]; content is irrelevant
		// because the write fails unconditionally.
		_ = c.SendBinary([]byte{0, 0, 0, 0, 8, 1, 2, 3})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SendBinary did not return with a Debug-level base handler — the " +
			"reconnect slog.Debug is being emitted under s.mu (#8597/K32)")
	}
}

// TestDebugRecordsStillReachTheHandler_8597 is the non-vacuity control for the
// two cells above. If `slog.Debug` were disabled — the accident that kept the
// #2287 cells green over this defect — they would pass whether or not the emit
// sits under the lock, and would guard nothing.
//
// It asserts the discriminator directly: with a Debug-level base handler the
// default handler reports Debug ENABLED, so a `slog.Debug` from inside the send
// path really does route back into `SyslogSlogHandler.Handle`. Setting the base
// level back to Info fails this cell instead of silently hollowing the others.
func TestDebugRecordsStillReachTheHandler_8597(t *testing.T) {
	c := failingStreamClient("203.0.113.19:514")
	debugLevelSyslogHandler(t, c)

	if !slog.Default().Enabled(t.Context(), slog.LevelDebug) {
		t.Fatal("Debug is not enabled on the test's default handler; the deadlock " +
			"cells above cannot reach the emit site and are vacuous")
	}
	// And the Info-level fixture the #2287 cells use genuinely does NOT reach
	// it — this is the axis those cells hold constant, stated as an assertion
	// rather than left implicit.
	infoBase := slog.New(NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil)))
	if infoBase.Enabled(t.Context(), slog.LevelDebug) {
		t.Fatal("an Info-level base handler reports Debug enabled; the explanation " +
			"for why the #2287 cells missed K32 no longer holds — re-derive it")
	}
}

// TestSlogDefaultSwapDoesNotLeakTheStdlibLogWriter_8597 guards the hazard this
// file itself created before it was found.
//
// slog.SetDefault re-points log.Default()'s output at a handlerWriter around
// the new handler, but SKIPS that step when the handler is slog's internal
// defaultHandler — the stdlib does so deliberately, to avoid recursing into
// log.Output. Restoring the previous logger therefore does NOT undo the
// re-point, and log.Default() keeps writing into a test's SyslogSlogHandler
// after that test ends.
//
// The consequence is the very deadlock shape this file is about, moved one
// level out: a later test's slog record takes the stdlib log package's global
// mutex, reaches the leftover handler, sends to its failing client, and the
// client's drop warning re-enters log.Output on the same goroutine. It wedged
// TestLazyStreamReconnectsAndDelivers — a test with no connection to any of
// this — and turned a 1.2-second package into a 9-minute timeout.
//
// The inner assertion is the non-vacuity control: if slog.SetDefault ever stops
// re-pointing the writer, the restore has nothing to undo and the outer check
// would pass while guarding nothing.
func TestSlogDefaultSwapDoesNotLeakTheStdlibLogWriter_8597(t *testing.T) {
	before := log.Writer()

	t.Run("inner", func(t *testing.T) {
		debugLevelSyslogHandler(t, failingStreamClient("203.0.113.20:514"))
		if log.Writer() == before {
			t.Fatal("slog.SetDefault did not re-point the stdlib log writer; there is " +
				"nothing for the cleanup to restore and the outer assertion is vacuous")
		}
	})

	if log.Writer() != before {
		t.Fatal("the stdlib log writer still points at the subtest's SyslogSlogHandler " +
			"after it finished; a later test's slog record will re-enter log.Output " +
			"under log's own global mutex and deadlock (#8597)")
	}
}
