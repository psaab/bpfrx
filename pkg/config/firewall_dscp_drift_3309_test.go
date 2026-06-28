package config_test

import (
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestFilterDSCPResolvableMatchesDSCPValues is the #3309 BIDIRECTIONAL drift
// guard. pkg/config cannot import pkg/dataplane (import cycle: pkg/dataplane
// imports pkg/config), so validateFilterDSCPStrict INLINE-mirrors
// dataplane.DSCPValues (the snapshot builder's table,
// pkg/dataplane/userspace/filters.go) plus the numeric 0..63 range it accepts.
// This external test pins the two tables together in BOTH directions plus the
// numeric range. Either table drifting from the other turns it RED.
func TestFilterDSCPResolvableMatchesDSCPValues(t *testing.T) {
	// Forward: every DSCP code-point name the snapshot builder resolves must be
	// accepted by the config mirror. Catches the config mirror MISSING a name
	// that the dataplane added (commit would reject a value the dataplane emits).
	for name := range dataplane.DSCPValues {
		if !config.FilterDSCPResolvable(name) {
			t.Errorf("dataplane.DSCPValues has %q but config.FilterDSCPResolvable rejects it "+
				"(config name mirror is stale — add %q to filterDSCPNames)", name, name)
		}
	}

	// Reverse: every name the config mirror accepts must STILL be present in
	// dataplane.DSCPValues. Catches a name DROPPED from the dataplane SSOT while
	// the config mirror still accepts it — the validator would pass that stale
	// name at commit and the snapshot builder would then silently drop it at
	// encode (a no-op match, not a commit error). This is the direction the
	// forward-only guard could not see.
	for _, name := range config.FilterDSCPNames() {
		if _, ok := dataplane.DSCPValues[name]; !ok {
			t.Errorf("config.FilterDSCPNames() accepts %q but dataplane.DSCPValues no longer "+
				"defines it (config name mirror is stale — drop %q from filterDSCPNames)", name, name)
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
