package daemon

import (
	"errors"
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/grpcapi"
)

// #8233: the routing decision, bound. The gRPC supervisor giving up on a
// management port another xpfd holds must end the daemon; every other Run error
// stays non-fatal, exactly as before.
func TestGRPCRunErrIsFatalSelectsOnlyManagementPortHeld_8233(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"the sentinel", grpcapi.ErrManagementPortHeld, true},
		{"wrapped, as the supervisor returns it",
			fmt.Errorf("%w: 127.0.0.1:50051 held for 30s", grpcapi.ErrManagementPortHeld), true},
		{"nil", nil, false},
		// The faults the supervisor exists to ride out. Treating these as fatal
		// would take a node down for a transient condition -- the #1960
		// no-brick case, and the reason this selects rather than blanket-fails.
		{"an ordinary serve fault", errors.New("gRPC listener serve fault"), false},
		{"a permissions failure", errors.New("listen tcp: bind: permission denied"), false},
	}
	for _, c := range cases {
		if got := grpcRunErrIsFatal(c.err); got != c.want {
			t.Errorf("%s: grpcRunErrIsFatal = %v, want %v", c.name, got, c.want)
		}
	}
}

// signalFatal must never block the reporting goroutine and must be single-shot:
// a second fatal arriving during shutdown has nowhere to go and nothing left to
// trigger.
func TestSignalFatalIsNonBlockingAndSingleShot_8233(t *testing.T) {
	d := &Daemon{fatalCh: make(chan error, 1)}
	first := errors.New("first")
	d.signalFatal(first)
	d.signalFatal(errors.New("second")) // must not block, must not displace
	d.signalFatal(nil)                  // must be ignored

	select {
	case got := <-d.fatalCh:
		if !errors.Is(got, first) {
			t.Errorf("fatalCh delivered %v, want the FIRST fatal %v", got, first)
		}
	default:
		t.Fatal("fatalCh is empty; the fatal never reached the daemon's wait")
	}
	select {
	case got := <-d.fatalCh:
		t.Errorf("a second value %v is queued; the channel must be single-shot", got)
	default:
	}
}

// A nil channel must not panic. Daemon values built outside New (tests, embedded
// callers) have no fatalCh, and a panic there would be a new failure mode
// introduced by a change that exists to make failures cleaner.
func TestSignalFatalToleratesANilChannel_8233(t *testing.T) {
	(&Daemon{}).signalFatal(errors.New("boom"))
}
