package cli

import (
	"reflect"
	"testing"
)

// assertVRFDeviceOnce checks the #2143 invariant on a VRF-wrapped argv:
// when a routing-instance is requested the device argument (the element
// after `ip vrf exec`) must equal wantDev exactly — in particular it
// must never be double-prefixed (vrf-vrf-red), and the literal "vrf-"
// must appear at most once anywhere in the argv.
func assertVRFDeviceOnce(t *testing.T, argv []string, wantDev string) {
	t.Helper()
	exec := indexOf(argv, "exec")
	if exec < 0 || exec+1 >= len(argv) {
		t.Fatalf("argv %v: missing `ip vrf exec <device>` wrapper", argv)
	}
	if got := argv[exec+1]; got != wantDev {
		t.Fatalf("argv %v: VRF device = %q, want %q (double-prefix regression?)", argv, got, wantDev)
	}
}

// indexOf returns the index of want in argv, or -1 if absent.
func indexOf(argv []string, want string) int {
	for i, a := range argv {
		if a == want {
			return i
		}
	}
	return -1
}

// assertSeparatorBeforeTarget checks the option-confusion hardening
// invariant (#2084): a "--" end-of-options separator must appear in the
// argv and the user-supplied target must be the element immediately
// after it, and the last element.
func assertSeparatorBeforeTarget(t *testing.T, argv []string, target string) {
	t.Helper()
	sep := indexOf(argv, "--")
	if sep < 0 {
		t.Fatalf("argv %v: missing \"--\" end-of-options separator", argv)
	}
	if sep+1 >= len(argv) {
		t.Fatalf("argv %v: \"--\" has no following operand", argv)
	}
	if argv[sep+1] != target {
		t.Fatalf("argv %v: target %q is not immediately after \"--\" (got %q)", argv, target, argv[sep+1])
	}
	if sep+1 != len(argv)-1 {
		t.Fatalf("argv %v: target is not the final argv element", argv)
	}
}

func TestBuildPingArgvSeparator(t *testing.T) {
	tests := []struct {
		name              string
		target            string
		count, source, sz string
		vrf               string
	}{
		{"plain target", "192.0.2.1", "5", "", "", ""},
		{"dash-prefixed target", "-I", "5", "", "", ""},
		{"with source and size", "-f", "5", "10.0.0.1", "1400", ""},
		{"with routing instance", "-c", "5", "", "", "blue"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv := buildPingArgv(tt.target, tt.count, tt.source, tt.sz, tt.vrf)
			assertSeparatorBeforeTarget(t, argv, tt.target)
			ping := indexOf(argv, "ping")
			if ping < 0 || ping > indexOf(argv, "--") {
				t.Fatalf("argv %v: ping must be present and precede the separator", argv)
			}
		})
	}
}

func TestBuildPingArgvVRFInnerSeparator(t *testing.T) {
	argv := buildPingArgv("-bad", "5", "", "", "red")
	if indexOf(argv, "ip") != 0 {
		t.Fatalf("argv %v: VRF wrapper must lead the argv", argv)
	}
	if indexOf(argv, "vrf-red") < 0 {
		t.Fatalf("argv %v: missing vrf-red device", argv)
	}
	ping := indexOf(argv, "ping")
	sep := indexOf(argv, "--")
	if ping < 0 || sep < 0 || sep < ping {
		t.Fatalf("argv %v: separator must follow ping in the inner command", argv)
	}
	assertSeparatorBeforeTarget(t, argv, "-bad")
}

// TestBuildPingArgvVRFNoDoublePrefix is the direct #2143 regression
// guard on the CLI entry point: the local CLI buildPingArgv must apply
// the "vrf-" prefix exactly once. A bare "red" becomes "vrf-red"; an
// already-prefixed "vrf-red" stays "vrf-red" (NOT "vrf-vrf-red"). Before
// the fix the CLI unconditionally prepended "vrf-", producing a
// non-existent device for the already-prefixed case while REST and gRPC
// produced the correct one.
func TestBuildPingArgvVRFNoDoublePrefix(t *testing.T) {
	tests := []struct {
		name    string
		vrf     string
		wantDev string
	}{
		{"bare name gets one prefix", "red", "vrf-red"},
		{"already-prefixed name not doubled", "vrf-red", "vrf-red"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv := buildPingArgv("192.0.2.1", "5", "", "", tt.vrf)
			assertVRFDeviceOnce(t, argv, tt.wantDev)
		})
	}
}

// TestBuildPingArgvParityWithVRF asserts the local CLI builder produces
// the exact argv expected for both VRF axes (regression-locks the full
// shape, not just the device token).
func TestBuildPingArgvParityWithVRF(t *testing.T) {
	got := buildPingArgv("192.0.2.1", "5", "", "", "vrf-red")
	want := []string{"ip", "vrf", "exec", "vrf-red", "ping", "-c", "5", "--", "192.0.2.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildPingArgv =\n  %v\nwant\n  %v", got, want)
	}
}

// TestBuildTracerouteArgvVRFNoDoublePrefix is the #2143 regression guard
// on the CLI traceroute builder.
func TestBuildTracerouteArgvVRFNoDoublePrefix(t *testing.T) {
	tests := []struct {
		name    string
		vrf     string
		wantDev string
	}{
		{"bare name gets one prefix", "green", "vrf-green"},
		{"already-prefixed name not doubled", "vrf-green", "vrf-green"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv := buildTracerouteArgv("2001:db8::1", "", tt.vrf)
			assertVRFDeviceOnce(t, argv, tt.wantDev)
		})
	}
}

func TestBuildTracerouteArgvSeparator(t *testing.T) {
	tests := []struct {
		name           string
		target, source string
		vrf            string
	}{
		{"plain target", "2001:db8::1", "", ""},
		{"dash-prefixed target", "-s", "", ""},
		{"with source", "-m", "10.0.0.1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argv := buildTracerouteArgv(tt.target, tt.source, tt.vrf)
			assertSeparatorBeforeTarget(t, argv, tt.target)
			tr := indexOf(argv, "traceroute")
			if tr < 0 || tr > indexOf(argv, "--") {
				t.Fatalf("argv %v: traceroute must be present and precede the separator", argv)
			}
		})
	}
}

func TestBuildTracerouteArgvVRFInnerSeparator(t *testing.T) {
	argv := buildTracerouteArgv("-bad", "", "green")
	if indexOf(argv, "ip") != 0 {
		t.Fatalf("argv %v: VRF wrapper must lead the argv", argv)
	}
	tr := indexOf(argv, "traceroute")
	sep := indexOf(argv, "--")
	if tr < 0 || sep < 0 || sep < tr {
		t.Fatalf("argv %v: separator must follow traceroute in the inner command", argv)
	}
	assertSeparatorBeforeTarget(t, argv, "-bad")
}
