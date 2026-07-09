package daemon

import "testing"

// #4047 part B: the runtime fail-safe clamp that pulls an off-loopback +
// unauthenticated web-management REST bind back to loopback so an
// already-persisted (leniently-loaded) vulnerable config does not expose the
// mutating config endpoints to the network after upgrade. hostIsLoopback and
// clampBindToLoopback are the pure decision helpers; daemon_run.go applies the
// result to apiCfg.Addr / apiCfg.HTTPSAddr and logs the clamp.

func TestHostIsLoopback(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},    // canonical IPv4 loopback
		{"127.0.0.5", true},    // anywhere in 127.0.0.0/8 is loopback
		{"::1", true},          // IPv6 loopback
		{"localhost", true},    // hostname (not a parseable IP) but a loopback spelling
		{"10.0.0.5", false},    // routable IPv4 (RFC1918, but network-reachable)
		{"192.168.1.1", false}, // routable IPv4
		{"2001:db8::1", false}, // routable IPv6
		{"0.0.0.0", false},     // wildcard bind — reachable on every interface
		{"::", false},          // IPv6 wildcard/unspecified — reachable everywhere
		{"", false},            // #4903: empty host is the ":port" wildcard, NOT loopback
		{"not-an-ip", false},   // #4903: unparseable, non-loopback => fail safe (clamp)
	}
	for _, c := range cases {
		if got := hostIsLoopback(c.host); got != c.want {
			t.Errorf("hostIsLoopback(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestClampBindToLoopback(t *testing.T) {
	cases := []struct {
		name        string
		addr        string
		hasAuth     bool
		wantAddr    string
		wantClamped bool
	}{
		// Off-loopback + no auth => clamped to the same-family loopback, port kept.
		{"v4 off-loopback no-auth clamps", "10.0.0.5:8080", false, "127.0.0.1:8080", true},
		{"v4 off-loopback no-auth https port kept", "192.168.1.1:8443", false, "127.0.0.1:8443", true},
		{"v6 off-loopback no-auth clamps to v6 loopback", "[2001:db8::1]:8080", false, "[::1]:8080", true},
		// Off-loopback WITH auth => bind as configured (authenticated is allowed).
		{"v4 off-loopback with auth not clamped", "10.0.0.5:8080", true, "10.0.0.5:8080", false},
		{"v6 off-loopback with auth not clamped", "[2001:db8::1]:8080", true, "[2001:db8::1]:8080", false},
		// Loopback binds are left untouched regardless of auth.
		{"v4 loopback untouched", "127.0.0.1:8080", false, "127.0.0.1:8080", false},
		{"v4 loopback-range untouched", "127.0.0.5:8080", false, "127.0.0.5:8080", false},
		{"v6 loopback untouched", "[::1]:8080", false, "[::1]:8080", false},
		// Wildcard bind is off-loopback => clamped.
		{"v4 wildcard no-auth clamps", "0.0.0.0:8080", false, "127.0.0.1:8080", true},
		// #4903: the Go wildcard spelling ":port" (empty host) is all-interfaces,
		// NOT loopback — it MUST clamp when unauthenticated (this is the bug).
		{"empty-host wildcard no-auth clamps", ":8080", false, "127.0.0.1:8080", true},
		{"empty-host wildcard with auth not clamped", ":8080", true, ":8080", false},
		{"v6 empty-host wildcard no-auth clamps", "[::]:8080", false, "[::1]:8080", true},
		// #4903: a split-but-unparseable host fails safe => clamped when no-auth.
		{"unparseable split host no-auth clamps", "bad_host:8080", false, "127.0.0.1:8080", true},
		// "localhost" is a loopback spelling => left unchanged.
		{"localhost loopback untouched", "localhost:8080", false, "localhost:8080", false},
		// Unparseable / no-port (SplitHostPort errors) => left unchanged (no port to clamp).
		{"unparseable no-port untouched", "not-an-addr", false, "not-an-addr", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotAddr, gotClamped := clampBindToLoopback(c.addr, c.hasAuth)
			if gotAddr != c.wantAddr || gotClamped != c.wantClamped {
				t.Errorf("clampBindToLoopback(%q, hasAuth=%v) = (%q, %v), want (%q, %v)",
					c.addr, c.hasAuth, gotAddr, gotClamped, c.wantAddr, c.wantClamped)
			}
		})
	}
}
