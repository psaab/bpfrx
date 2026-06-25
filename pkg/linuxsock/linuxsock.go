// Package linuxsock centralizes raw/datagram socket creation so that
// close-on-exec is non-optional.
//
// Go's net package sets O_CLOEXEC on every fd it creates, but a raw
// unix.Socket(2) does NOT — the fd is left inheritable. xpfd fork-execs
// helpers constantly (frr-reload.py, swanctl, DHCP/script helpers), so any
// inheritable raw AF_PACKET / raw-ICMP / datagram fd leaks into those children:
// an fd leak and a security boundary issue (a child could read or inject raw
// frames on the interface). #2476 fixed the VRRP receiver in isolation; this
// package makes the policy structural for every sibling socket so a new direct
// unix.Socket call site fails the canary test (see linuxsock_canary_test.go).
//
// The single Socket helper ORs unix.SOCK_CLOEXEC into the type argument so the
// fd is created close-on-exec ATOMICALLY at socket(2) time. The atomic OR-into-
// type is deliberate: a separate post-creation fcntl(FD_CLOEXEC) races a
// concurrent fork-exec between the two syscalls, and an inherited fd in that
// window is exactly the leak we are closing.
package linuxsock

import "golang.org/x/sys/unix"

// socketFn is the socket(2) entry point. It is a package var so tests can
// intercept the call and assert the type flags (notably SOCK_CLOEXEC) without
// needing CAP_NET_RAW or a real socket. Production uses unix.Socket.
var socketFn = unix.Socket

// Socket creates a socket with SOCK_CLOEXEC forced into the type argument.
//
// Callers pass the bare type (e.g. unix.SOCK_RAW, unix.SOCK_DGRAM); they must
// NOT pass SOCK_CLOEXEC themselves and must NOT call unix.Socket directly. The
// returned fd is close-on-exec, so it is never inherited by an exec'd child.
func Socket(domain, typ, proto int) (int, error) {
	return socketFn(domain, typ|unix.SOCK_CLOEXEC, proto)
}
