package authz

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
)

// passwd.go maps a numeric UID to an OS account name (#5561).
//
// It parses /etc/passwd directly rather than using os/user, matching the
// deliberate choice already made in pkg/daemon/login_password.go: os/user pulls
// in cgo's libc resolver unless the binary is built with the osusergo tag, and
// this daemon stays cgo-free. The account names it must resolve are the ones
// the daemon itself provisioned with `useradd` (pkg/daemon/daemon_system.go),
// which land in /etc/passwd; NSS-only identities (LDAP, systemd-homed) are not
// part of the `system login user` model and are correctly not resolved.

// passwdPath is the account database. It is a variable so a test can point the
// resolver at a fixture; production never changes it.
var passwdPath = "/etc/passwd"

// UsernameForUID returns the account name for uid from /etc/passwd.
//
// On a duplicate UID it returns the FIRST matching entry, which is what libc's
// getpwuid does; an operator who deliberately aliases two names onto one UID has
// made them the same principal as far as the kernel is concerned, so there is no
// more specific answer to give.
//
// ok=false means the UID has no entry, or the database could not be read. Both
// are an absence of identity: the caller must deny, never substitute a default.
func UsernameForUID(uid uint32) (string, bool) {
	f, err := os.Open(passwdPath)
	if err != nil {
		return "", false
	}
	defer f.Close()

	want := strconv.FormatUint(uint64(uid), 10)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:uid:gid:gecos:home:shell
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[2] == want && fields[0] != "" {
			return fields[0], true
		}
	}
	return "", false
}

// SetPasswdPathForTest points the UID resolver at path and restores the
// previous value through the returned function. Test-only; it exists so a
// cross-package test (pkg/api) can exercise the real resolution path against a
// fixture instead of depending on the accounts that happen to exist on the
// machine running the suite. Dep-free — no test-only import leaks into the
// production binary.
func SetPasswdPathForTest(path string) (restore func()) {
	prev := passwdPath
	passwdPath = path
	return func() { passwdPath = prev }
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
	return func() { localAddrsFn = prev }
}
