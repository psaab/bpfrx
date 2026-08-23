package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #6772: pkg/config's heartbeat overflow validator must substitute the SAME
// defaults the runtime does for an unset field, or it validates a config the
// runtime will not run.
//
// The constants are duplicated because pkg/cluster imports pkg/config, so the
// dependency cannot run the other way. A divergence between the two copies is
// always a bug, so this asserts the AGREEMENT rather than pinning either side
// to a literal — pinning one would encode which copy is trusted, and the stale
// comments this change corrected (`0=default(1000)` / `0=default(3)`, against a
// runtime of 100ms/5) are what that looks like when it goes wrong.
func TestHeartbeatDefaultsAgreeAcrossPackages6772(t *testing.T) {
	if got := time.Duration(config.DefaultHeartbeatIntervalMillis) * time.Millisecond; got != DefaultHeartbeatInterval {
		t.Errorf("config.DefaultHeartbeatIntervalMillis = %v, runtime DefaultHeartbeatInterval = %v — "+
			"the overflow validator would model an interval the runtime never uses",
			got, DefaultHeartbeatInterval)
	}
	if int(config.DefaultHeartbeatThreshold) != DefaultHeartbeatThreshold {
		t.Errorf("config.DefaultHeartbeatThreshold = %d, runtime DefaultHeartbeatThreshold = %d",
			config.DefaultHeartbeatThreshold, DefaultHeartbeatThreshold)
	}
}
