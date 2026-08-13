package authz

import (
	"net"

	"github.com/psaab/xpf/pkg/osident"
)

// passwd.go maps a numeric UID to an OS account name (#5561).
//
// It DELEGATES to pkg/osident rather than scanning the database itself. That
// package is the SSOT for "which account is this uid", already consumed by the
// CLI, and it is dependency-free (`go list -deps ./pkg/osident` returns only
// itself), so importing it here costs nothing and cannot cycle.
//
// Why delegation rather than a second scanner, stated because this file HAD one
// until #6645: the two implementations disagreed on duplicate UIDs, and the
// disagreement was a privilege escalation. This file returned the FIRST
// matching row — "what libc's getpwuid does" — while osident refuses to name an
// ambiguous uid at all. On `admin:x:4242` + `bob:x:4242` with only
// `system login user admin { class super-user; }` configured, REST admitted uid
// 4242 as super-user and let it commit a candidate edit, while the CLI denied
// the same caller as `unauthorized`. Both packages were green: nothing compared
// the resolvers. See osident.lookupPasswd for the argument, and
// TestRESTAndCLIAgreeOnAnAmbiguousUID_6645 for the binding.
//
// (The no-cgo reasoning that motivated a hand-rolled scanner still holds and is
// unchanged — osident parses the file directly for the same reason.)

// UsernameForUID returns the account name for uid.
//
// ok=false means the UID has no entry, the entry is AMBIGUOUS (two accounts
// share the uid), or the database could not be read. All three are an absence
// of identity: the caller must deny, never substitute a default and never pick
// one of the candidate names.
func UsernameForUID(uid uint32) (string, bool) {
	id := osident.ForUID(int(uid))
	return id.Name, id.Resolved()
}

// SetPasswdPathForTest points the UID resolver at path and restores the
// previous value through the returned function. Test-only; it exists so a
// cross-package test (pkg/api) can exercise the real resolution path against a
// fixture instead of depending on the accounts that happen to exist on the
// machine running the suite.
//
// It forwards to osident's seam so that pointing "the" passwd path at a fixture
// moves BOTH surfaces at once. A local copy here would let a test configure the
// REST resolver while the CLI kept reading /etc/passwd — the same split this
// file exists to close.
func SetPasswdPathForTest(path string) (restore func()) {
	return osident.SetPasswdPathForTest(path)
}

// SetProcNetTCPPathsForTest points the socket-table parser at fixtures and
// restores the previous values through the returned function. Test-only; it
// lets the parser be exercised against known kernel output (including the
// TIME_WAIT/UID-0 row the ESTABLISHED requirement exists to reject, and the
// v4-mapped-in-tcp6 row) without needing to provoke those states on a live
// socket.
func SetProcNetTCPPathsForTest(v4, v6 string) (restore func()) {
	prev4, prev6 := procNetTCPPath, procNetTCP6Path
	procNetTCPPath, procNetTCP6Path = v4, v6
	return func() { procNetTCPPath, procNetTCP6Path = prev4, prev6 }
}

// setLocalAddrsForTest fixes the host address list LookupPeer consults when it
// finds no socket, so the "is this caller on our own box" decision is
// deterministic instead of depending on the machine's interfaces. Test-only,
// unexported: only pkg/authz's own tests need it.
func setLocalAddrsForTest(addrs []net.Addr) (restore func()) {
	prev := localAddrsFn
	localAddrsFn = func() ([]net.Addr, error) { return addrs, nil }
	resetLocalAddrCacheForTest()
	return func() { localAddrsFn = prev; resetLocalAddrCacheForTest() }
}
