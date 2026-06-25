package linuxsock

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestSocketForcesCloexec asserts the factory ORs SOCK_CLOEXEC into the type
// argument at the socket(2) call site. It intercepts the socketFn seam so it
// captures the EXACT flags the helper passes, without needing CAP_NET_RAW or a
// real socket. Reverting the `typ|unix.SOCK_CLOEXEC` to a bare `typ` makes
// gotType lack SOCK_CLOEXEC and this test fails (fail-on-revert).
func TestSocketForcesCloexec(t *testing.T) {
	orig := socketFn
	defer func() { socketFn = orig }()

	var gotType int
	called := false
	socketFn = func(domain, typ, proto int) (int, error) {
		gotType = typ
		called = true
		return -1, unix.EPERM // do not actually create an fd
	}

	for _, tc := range []struct {
		name string
		typ  int
	}{
		{"raw", unix.SOCK_RAW},
		{"dgram", unix.SOCK_DGRAM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			gotType = 0
			_, _ = Socket(unix.AF_INET, tc.typ, 0)
			if !called {
				t.Fatal("socketFn seam was not invoked")
			}
			if gotType&unix.SOCK_CLOEXEC == 0 {
				t.Fatalf("socket type %#x missing SOCK_CLOEXEC", gotType)
			}
			if gotType&^unix.SOCK_CLOEXEC != tc.typ {
				t.Fatalf("socket type %#x altered the base type %#x", gotType, tc.typ)
			}
		})
	}
}

// TestSocketRealFDIsCloexec creates a real socket and asserts the kernel set
// FD_CLOEXEC on it. SOCK_DGRAM/IPPROTO_UDP needs no privilege, so this runs
// unprivileged; if the platform still rejects it (sandbox), skip cleanly.
func TestSocketRealFDIsCloexec(t *testing.T) {
	fd, err := Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Skipf("cannot create socket in this environment: %v", err)
	}
	defer unix.Close(fd)

	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD: %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("fd flags %#x missing FD_CLOEXEC", flags)
	}
}
