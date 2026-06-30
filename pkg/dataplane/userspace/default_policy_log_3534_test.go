package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Test_3534_DefaultPolicyLogReachesSnapshot is the #3534 fail-on-revert guard
// for the Go control-plane wiring: the implicit-default-policy RT_FLOW log
// selection (SecurityConfig.DefaultPolicyLogSessionInit/Close) must reach the
// dataplane ConfigSnapshot.DefaultLogSessionInit/Close, mirroring a named
// policy's per-rule log selection. Reverting the builder.go assignment drops
// the flags from the snapshot and this test goes RED.
func Test_3534_DefaultPolicyLogReachesSnapshot(t *testing.T) {
	cases := []struct {
		name      string
		init      bool
		close     bool
		wantInit  bool
		wantClose bool
	}{
		{"both", true, true, true, true},
		{"init-only", true, false, true, false},
		{"close-only", false, true, false, true},
		{"none", false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Security.DefaultPolicy = config.PolicyPermit
			cfg.Security.DefaultPolicyLogSessionInit = tc.init
			cfg.Security.DefaultPolicyLogSessionClose = tc.close
			snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			if snap.DefaultLogSessionInit != tc.wantInit {
				t.Errorf("snap.DefaultLogSessionInit = %v, want %v", snap.DefaultLogSessionInit, tc.wantInit)
			}
			if snap.DefaultLogSessionClose != tc.wantClose {
				t.Errorf("snap.DefaultLogSessionClose = %v, want %v", snap.DefaultLogSessionClose, tc.wantClose)
			}
		})
	}
}
