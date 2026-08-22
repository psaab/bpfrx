package ddns

// #6709/#7009 regression: the in-process fake DNS server binds UDP and TCP on
// ONE ephemeral port, but UDP and TCP are independent port namespaces — a port
// the kernel reports free for UDP may be held for TCP by any other process on
// the host. Binding UDP once and asserting the TCP bind succeeds failed ~7% of
// full-package runs (20% with six concurrent instances of this package) with
// "bind: address already in use", on a DIFFERENT test each time.
//
// listenDNSPair RESAMPLES: each attempt draws a fresh port, so attempts are
// independent. These tests pin that behaviour deterministically, without
// occupying real host ports to force a collision.

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

// TestListenDNSPairResamplesPastAConflictingPort_6709 is the fail-on-revert
// proof for the resample loop: with the first attempts failing EADDRINUSE and a
// later one succeeding, listenDNSPair must still return a usable pair. A
// single-attempt implementation returns the first error instead.
func TestListenDNSPairResamplesPastAConflictingPort_6709(t *testing.T) {
	for _, conflicts := range []int{1, 3, dnsPairAttempts - 1} {
		calls := 0
		prev := dnsPairAttempt
		dnsPairAttempt = func() (net.PacketConn, net.Listener, error) {
			calls++
			if calls <= conflicts {
				return nil, nil, &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE}
			}
			return realDNSPairAttempt()
		}
		pc, l, err := listenDNSPair()
		dnsPairAttempt = prev

		if err != nil {
			t.Fatalf("conflicts=%d: listenDNSPair must resample past a busy port, got %v", conflicts, err)
		}
		if calls != conflicts+1 {
			t.Fatalf("conflicts=%d: want %d attempts, got %d", conflicts, conflicts+1, calls)
		}
		// The pair must be on ONE port — that is the whole point of pairing.
		_, up, _ := net.SplitHostPort(pc.LocalAddr().String())
		_, tp, _ := net.SplitHostPort(l.Addr().String())
		if up != tp {
			t.Fatalf("conflicts=%d: udp port %s != tcp port %s", conflicts, up, tp)
		}
		_ = pc.Close()
		_ = l.Close()
	}
}

// TestListenDNSPairGivesUpLoudly_6709 pins the other half: the loop is BOUNDED
// and reports the underlying cause. A retry loop that spun forever would turn a
// fast failure into a hang, which is the outcome #7009 warns against.
func TestListenDNSPairGivesUpLoudly_6709(t *testing.T) {
	calls := 0
	sentinel := &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE}
	prev := dnsPairAttempt
	dnsPairAttempt = func() (net.PacketConn, net.Listener, error) {
		calls++
		return nil, nil, sentinel
	}
	pc, l, err := listenDNSPair()
	dnsPairAttempt = prev

	if err == nil {
		_ = pc.Close()
		_ = l.Close()
		t.Fatal("listenDNSPair must fail when every attempt conflicts")
	}
	if calls != dnsPairAttempts {
		t.Fatalf("want exactly %d bounded attempts, got %d", dnsPairAttempts, calls)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("the give-up error must carry the underlying cause, got %v", err)
	}
	if !strings.Contains(err.Error(), "8 attempts") {
		t.Fatalf("the give-up error must say how many attempts were made, got %v", err)
	}
}
