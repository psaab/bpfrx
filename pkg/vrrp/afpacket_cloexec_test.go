package vrrp

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestAfPacketReceiverSocketTypeCloexec asserts that openAfPacketReceiver
// passes SOCK_CLOEXEC (OR'd into the socket type) at the socket(2) call site.
// This is the close-on-exec guarantee for the raw VRRP capture fd: without it
// the fd leaks to every child the daemon execs (frr-reload.py, swanctl, dhcp
// helpers), both an fd leak and a security boundary (a child could read raw
// VRRP frames). The check intercepts the socket(2) entry point via the
// afPacketSocket seam, so it captures the EXACT flags the call site uses and
// runs deterministically without CAP_NET_RAW.
//
// Fail-on-revert: reverting the call site to plain unix.SOCK_RAW makes the
// captured type lack SOCK_CLOEXEC and this test fails.
func TestAfPacketReceiverSocketTypeCloexec(t *testing.T) {
	var gotType int
	called := false
	orig := afPacketSocket
	afPacketSocket = func(domain, typ, proto int) (int, error) {
		gotType = typ
		called = true
		// Return an error so openAfPacketReceiver bails out before it tries
		// to bind/setsockopt on a fd we did not actually open. We only need
		// the captured type flags.
		return -1, unix.EPERM
	}
	defer func() { afPacketSocket = orig }()

	// ifindex value is irrelevant — the stub returns before bind.
	if _, err := openAfPacketReceiver(1); err == nil {
		t.Fatal("expected openAfPacketReceiver to surface the stub error")
	}
	if !called {
		t.Fatal("afPacketSocket seam was not invoked")
	}
	if gotType&unix.SOCK_CLOEXEC == 0 {
		t.Fatalf("AF_PACKET socket type %#x missing SOCK_CLOEXEC", gotType)
	}
	if gotType&unix.SOCK_RAW == 0 {
		t.Fatalf("AF_PACKET socket type %#x missing SOCK_RAW", gotType)
	}
}

// TestAfPacketReceiverRealFDCloexec opens a real AF_PACKET socket (requires
// CAP_NET_RAW/root) and verifies the kernel actually set FD_CLOEXEC on it.
// Skips gracefully when the test process lacks the capability. This is the
// end-to-end confirmation that the atomic SOCK_CLOEXEC in the type argument
// reaches the fd, complementing the deterministic seam test above.
func TestAfPacketReceiverRealFDCloexec(t *testing.T) {
	fd, err := openAfPacketReceiver(1) // ifindex 1 == lo
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("no CAP_NET_RAW for AF_PACKET socket: %v", err)
		}
		t.Fatalf("openAfPacketReceiver: %v", err)
	}
	defer unix.Close(fd)

	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD: %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("AF_PACKET receiver fd lacks FD_CLOEXEC (F_GETFD=%#x)", flags)
	}
}
