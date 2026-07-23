package api

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// pingArgvSize returns the value passed to `ping -s` in argv, or "" if none.
func pingArgvSize(argv []string) string {
	for i, a := range argv {
		if a == "-s" && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// TestBuildPingArgvClampsSize_5250 is the fail-on-revert guard for the REST ping
// payload clamp (#5250 A8-b1 F4). A -s far above the max valid ICMP echo data
// must be capped to diagcmd.MaxPingSize. Removing the clamp passes the raw value
// straight through.
func TestBuildPingArgvClampsSize_5250(t *testing.T) {
	argv := buildPingArgv(PingRequest{Target: "192.0.2.1", Size: 1 << 20}, 5)
	got := pingArgvSize(argv)
	want := fmt.Sprintf("%d", diagcmd.MaxPingSize)
	if got != want {
		t.Fatalf("ping -s = %q, want clamped %q", got, want)
	}
}

// TestBuildPingArgvKeepsInBoundSize_5250 confirms an in-range -s is untouched.
func TestBuildPingArgvKeepsInBoundSize_5250(t *testing.T) {
	argv := buildPingArgv(PingRequest{Target: "192.0.2.1", Size: 1000}, 5)
	if got := pingArgvSize(argv); got != "1000" {
		t.Fatalf("ping -s = %q, want 1000 (in-bound size must pass through)", got)
	}
}
