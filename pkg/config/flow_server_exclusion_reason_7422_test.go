package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6565 row 11 / #7422 — the acceptance set of config.FlowServerExcludedReason,
// which the snapshot builder and the three show surfaces now share.
func TestFlowServerExcludedReason7422(t *testing.T) {
	cases := []struct {
		name       string
		fs         *config.FlowServer
		wantExcl   bool
		wantSubstr string
	}{
		{"nil", nil, true, "no collector address"},
		{"no address", &config.FlowServer{Port: 2055}, true, "no collector address"},
		{"port 0 absent sentinel", &config.FlowServer{Address: "10.0.0.1"}, true, "no `port` configured"},
		{"negative port", &config.FlowServer{Address: "10.0.0.1", Port: -1}, true, "outside the UDP port range"},
		{"above u16", &config.FlowServer{Address: "10.0.0.1", Port: 65536}, true, "outside the UDP port range"},
		{"far above u16", &config.FlowServer{Address: "10.0.0.1", Port: 70000}, true, "outside the UDP port range"},
		{"port 1 installs", &config.FlowServer{Address: "10.0.0.1", Port: 1}, false, ""},
		{"port 2055 installs", &config.FlowServer{Address: "10.0.0.1", Port: 2055}, false, ""},
		{"port 65535 installs", &config.FlowServer{Address: "10.0.0.1", Port: 65535}, false, ""},
		{"ipv6 installs", &config.FlowServer{Address: "2001:db8::9", Port: 4739}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := config.FlowServerExcludedReason(tc.fs)
			if (got != "") != tc.wantExcl {
				t.Fatalf("FlowServerExcludedReason(%+v) = %q, want excluded=%v",
					tc.fs, got, tc.wantExcl)
			}
			if tc.wantSubstr != "" && !strings.Contains(got, tc.wantSubstr) {
				t.Fatalf("reason %q does not name the cause %q — the operator "+
					"reads this string verbatim and cannot tell WHICH condition "+
					"dropped the collector", got, tc.wantSubstr)
			}
		})
	}
	// The boundaries are where an off-by-one lives, and 65535/65536 above
	// already pin the top. Pin the bottom explicitly too: 0 must be excluded
	// for the ABSENT reason, not the range reason, because they send the
	// operator to different fixes.
	if got := config.FlowServerExcludedReason(&config.FlowServer{Address: "10.0.0.1"}); strings.Contains(got, "outside the UDP") {
		t.Fatalf("port 0 reported as an out-of-range port (%q); it is the "+
			"absent-port sentinel and the fix is to add a `port`, not to change one", got)
	}
}
