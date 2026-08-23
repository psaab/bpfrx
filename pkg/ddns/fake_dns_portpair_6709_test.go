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
//
// #7563: "deterministically" was only half true. The loop test stubbed the
// FAILING attempts but let the succeeding one fall through to the real
// sampler, so the very port contention these tests exist to describe could
// still reach them through the back door — under a parallel `go test ./...`
// the fall-through attempt legitimately conflicts, the loop legitimately
// resamples, and the exact-attempt-count assertion legitimately fails. The
// resample loop is now driven entirely by injected outcomes and asserts the
// pair it was handed; the same-port PROPERTY, which genuinely needs the real
// sampler, is asserted separately through the bounded loop that production
// uses.

import (
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestListenDNSPairResamplesPastAConflictingPort_6709 is the fail-on-revert
// proof for the resample loop: with the first attempts failing EADDRINUSE and a
// later one succeeding, listenDNSPair must still return a usable pair. A
// single-attempt implementation returns the first error instead.
func TestListenDNSPairResamplesPastAConflictingPort_6709(t *testing.T) {
	for _, conflicts := range []int{1, 3, dnsPairAttempts - 1} {
		// The winning attempt returns an INERT pair rather than a real one.
		// A real bind here would consult the host's port space, which is the
		// one thing this test must not do: another process holding the drawn
		// port makes the sampler resample, and the resample is correct — so
		// the attempt count would be a reading of the machine, not of the
		// loop (#7563).
		wantPC := stubPacketConn{addr: stubAddr("127.0.0.1:5353")}
		wantL := stubListener{addr: stubAddr("127.0.0.1:5353")}

		calls := 0
		prev := dnsPairAttempt
		dnsPairAttempt = func() (net.PacketConn, net.Listener, error) {
			calls++
			if calls <= conflicts {
				return nil, nil, &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE}
			}
			return wantPC, wantL, nil
		}
		pc, l, err := listenDNSPair()
		dnsPairAttempt = prev

		if err != nil {
			t.Fatalf("conflicts=%d: listenDNSPair must resample past a busy port, got %v", conflicts, err)
		}
		if calls != conflicts+1 {
			t.Fatalf("conflicts=%d: want %d attempts, got %d", conflicts, conflicts+1, calls)
		}
		// The loop must hand back the SUCCEEDING attempt's pair. A loop that
		// resampled correctly but returned a stale or zero pair would pass
		// the attempt-count check and hand the caller an unusable server.
		if pc != net.PacketConn(wantPC) {
			t.Fatalf("conflicts=%d: returned udp conn %v, want the succeeding attempt's %v", conflicts, pc, wantPC)
		}
		if l != net.Listener(wantL) {
			t.Fatalf("conflicts=%d: returned tcp listener %v, want the succeeding attempt's %v", conflicts, l, wantL)
		}
	}
}

// TestListenDNSPairBindsOneRealPortInBothNamespaces_7563 keeps the same-port
// property under test after the loop test above stopped touching real ports.
//
// This one MUST consult the host, because that pairing is precisely what the
// host may refuse — but it goes through the bounded resample loop, so it is
// exactly as reliable as newFakeDNSServer itself: at the measured ~0.2%
// per-attempt collision rate, 8 independent draws leave a residual around
// 1e-22. It asserts the INVARIANT (both namespaces, one port number) rather
// than how many draws it took to get there.
func TestListenDNSPairBindsOneRealPortInBothNamespaces_7563(t *testing.T) {
	pc, l, err := listenDNSPair()
	if err != nil {
		t.Fatalf("listenDNSPair: %v", err)
	}
	defer pc.Close()
	defer l.Close()

	_, up, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("udp addr %q: %v", pc.LocalAddr(), err)
	}
	_, tp, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("tcp addr %q: %v", l.Addr(), err)
	}
	if up != tp {
		t.Fatalf("udp port %s != tcp port %s: the pair is not on one port, so a "+
			"client that retries a truncated reply over TCP reaches nothing", up, tp)
	}
	if up == "0" {
		t.Fatalf("udp port is 0: the pair was never actually bound")
	}
}

// stubPacketConn, stubListener and stubAddr are inert stand-ins for a bound
// pair. They exist so the resample-loop test can express "this attempt
// succeeded" without asking the kernel for a port — see #7563. Nothing reads
// or writes them; only identity and LocalAddr/Addr are used.
type stubAddr string

func (a stubAddr) Network() string { return "stub" }
func (a stubAddr) String() string  { return string(a) }

type stubPacketConn struct{ addr stubAddr }

func (s stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (s stubPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, io.ErrClosedPipe }
func (s stubPacketConn) Close() error                           { return nil }
func (s stubPacketConn) LocalAddr() net.Addr                    { return s.addr }
func (s stubPacketConn) SetDeadline(time.Time) error            { return nil }
func (s stubPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (s stubPacketConn) SetWriteDeadline(time.Time) error       { return nil }

type stubListener struct{ addr stubAddr }

func (s stubListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (s stubListener) Close() error              { return nil }
func (s stubListener) Addr() net.Addr            { return s.addr }

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
