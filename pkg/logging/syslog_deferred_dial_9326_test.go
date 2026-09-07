// #9326: construction dialed, so the config-commit path paid a 5s dialer
// timeout per unreachable TCP stream.
//
// The assertion here is TIMING-FREE by construction, which is the point: a
// wall-time test would pass on a fast machine, or against a host that REFUSES
// rather than blackholes, while the coupling it is meant to forbid is still
// there. A dial that HAPPENED to an unreachable host reports an error; a dial
// that never happened cannot. The error is the observable.

package logging

import (
	"errors"
	"testing"
)

// 192.0.2.0/24 is RFC 5737 TEST-NET-1: it is not routable, so a dial to it can
// never succeed by accident on a developer machine or in CI.
const unreachable9326 = "192.0.2.11"

func TestDeferredConstructionDoesNotDial9326(t *testing.T) {
	// SUBJECT: the deferred constructor must not dial, so it cannot report a
	// dial failure for a host nothing can reach.
	c, err := NewSyslogClientDeferred(unreachable9326, 514, "", "tcp", nil)
	if err != nil {
		t.Fatalf("#9326: NewSyslogClientDeferred reported %v for an unreachable host. "+
			"An error can only come from a dial, so construction is still dialing — "+
			"which is the 5s-per-stream the commit path was paying.", err)
	}
	if c == nil {
		t.Fatal("deferred construction returned no client")
	}

	// POSITIVE CONTROL, and without it the assertion above is satisfied by any
	// constructor that cannot fail for any reason. The dialing constructor DOES
	// report the same host as unreachable, which is what proves the subject's
	// silence means "did not dial" rather than "cannot report".
	if _, terr := NewSyslogClientTransport(unreachable9326, 514, "", "tcp", nil); terr == nil {
		t.Fatal("CONTROL FAILED: the DIALING constructor reported no error for an " +
			"unreachable host, so the subject's silence proves nothing about whether " +
			"it dialed. Either the host became reachable or the dial stopped " +
			"reporting failures.")
	}
}

// UDP must keep dialing at construction: it has no lazy reconnect, so a
// deferred UDP client would forward nothing, silently, for the life of the
// config. The refusal is what stops a later caller losing that.
func TestDeferredRefusesUDP9326(t *testing.T) {
	_, err := NewSyslogClientDeferred(unreachable9326, 514, "", "udp", nil)
	if err == nil {
		t.Fatal("#9326: udp must be refused by the deferred constructor")
	}
	if !errors.Is(err, ErrUnsupportedTransport) {
		t.Errorf("the refusal should carry ErrUnsupportedTransport so callers can "+
			"distinguish it from a dial failure; got %v", err)
	}
}

// The UDP dialer is bounded like its TCP/TLS siblings (#9326). `net.Dial` on a
// HOSTNAME resolves with no deadline and no context, so the unbounded call was
// on the commit path; the connectionless nature of UDP bounds the SEND, not the
// name lookup that precedes it.
func TestUDPDialerIsBounded9326(t *testing.T) {
	c, err := NewSyslogClientTransport("192.0.2.12", 514, "", "udp", nil)
	if err != nil || c == nil {
		t.Fatalf("a UDP client to a literal address must construct; got %v", err)
	}
	// A literal address needs no resolution, so this cannot hang either way —
	// what it pins is that the UDP path still CONSTRUCTS a usable client after
	// the dialer change, i.e. adding the timeout did not break the common case.
	if c.Protocol() != "udp" {
		t.Fatalf("protocol = %q, want udp", c.Protocol())
	}
}
