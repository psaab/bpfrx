package rpm

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestProbeDialerMalformedSourceReturnsSetupError pins the #2492 runtime
// guard: a NON-EMPTY but unparseable source-address must return an
// ErrProbeSetup-wrapped error rather than proceeding with a
// net.TCPAddr{IP:nil} wildcard bind. ErrProbeSetup makes runSingleTest
// hold the test's state (no counter, no status flip, no Transition), so
// ip-monitoring never actuates routes off a wrong-path measurement.
func TestProbeDialerMalformedSourceReturnsSetupError(t *testing.T) {
	for _, src := range []string{"not-an-ip", "10.0.0.999", "2001:db8::g"} {
		d, err := probeDialer(5*time.Second, src, probeSockOpts{})
		if err == nil {
			t.Fatalf("probeDialer(%q) returned nil error; want ErrProbeSetup (would wildcard-bind)", src)
		}
		if !errors.Is(err, ErrProbeSetup) {
			t.Fatalf("probeDialer(%q) err = %v, want ErrProbeSetup", src, err)
		}
		if d != nil {
			t.Fatalf("probeDialer(%q) returned non-nil dialer with error", src)
		}
	}
}

// TestProbeDialerEmptySourceIsDefaultBind confirms an EMPTY
// source-address stays legitimate: it means "default source", so the
// dialer is returned with no LocalAddr and no error.
func TestProbeDialerEmptySourceIsDefaultBind(t *testing.T) {
	d, err := probeDialer(5*time.Second, "", probeSockOpts{})
	if err != nil {
		t.Fatalf("probeDialer(\"\") err = %v, want nil (empty = default source)", err)
	}
	if d == nil {
		t.Fatal("probeDialer(\"\") returned nil dialer")
	}
	if d.LocalAddr != nil {
		t.Fatalf("probeDialer(\"\") LocalAddr = %v, want nil (kernel default source)", d.LocalAddr)
	}
}

// TestProbeDialerValidSourceBinds confirms a parseable source-address is
// carried through to the dialer's LocalAddr.
func TestProbeDialerValidSourceBinds(t *testing.T) {
	d, err := probeDialer(5*time.Second, "10.0.0.5", probeSockOpts{})
	if err != nil {
		t.Fatalf("probeDialer valid source err = %v, want nil", err)
	}
	ta, ok := d.LocalAddr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("LocalAddr type = %T, want *net.TCPAddr", d.LocalAddr)
	}
	if !ta.IP.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("LocalAddr IP = %v, want 10.0.0.5", ta.IP)
	}
}
