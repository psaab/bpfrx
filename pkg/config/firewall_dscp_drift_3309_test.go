package config_test

import (
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestFilterDSCPResolvableMatchesDSCPValues is the #3309 drift guard. pkg/config
// cannot import pkg/dataplane (import cycle: pkg/dataplane imports pkg/config),
// so validateFilterDSCPStrict INLINE-mirrors dataplane.DSCPValues (the snapshot
// builder's table, pkg/dataplane/userspace/filters.go) plus the numeric 0..63
// range it accepts. This external test pins the two together: every name in
// dataplane.DSCPValues must be accepted by config.FilterDSCPResolvable, and the
// numeric range must agree. A future edit to dataplane.DSCPValues that the
// pkg/config copy does not track turns this RED.
func TestFilterDSCPResolvableMatchesDSCPValues(t *testing.T) {
	// Every DSCP code-point name the snapshot builder resolves must be accepted.
	for name := range dataplane.DSCPValues {
		if !config.FilterDSCPResolvable(name) {
			t.Errorf("dataplane.DSCPValues has %q but config.FilterDSCPResolvable rejects it", name)
		}
	}

	// Numeric range parity: the snapshot builder accepts strconv.Atoi in 0..63
	// (filters.go). Confirm config.FilterDSCPResolvable agrees across the whole
	// byte range and rejects everything outside 0..63.
	for n := -1; n <= 256; n++ {
		want := n >= 0 && n <= 63
		if got := config.FilterDSCPResolvable(strconv.Itoa(n)); got != want {
			t.Errorf("FilterDSCPResolvable(%d) = %v, want %v (snapshot builder accepts 0..63)", n, got, want)
		}
	}
}
