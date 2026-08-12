package api

import (
	"fmt"
	"strings"
	"testing"
)

// #4800: pin the EXACT Prometheus metric names of the new-flow contention
// surface.
//
// These names are the contract with everything outside this repo — the
// analyzer's scrape (`newflow_ceiling_analyze.py` greps them by name), any
// dashboard, and any alert. Nothing bound them: the emit tests match on
// DESCRIPTOR POINTER (deliberately, so they survive a client_golang change),
// which is exactly the right choice for those tests and exactly why it cannot
// see a rename. Misspell a name and every one of them stays green while the
// series silently disappears from the scrape.
//
// Matching is on `fqName: "..."` rather than a bare substring, because
// `Desc.String()` also embeds the HELP text — a bare `strings.Contains` would
// match a name that merely appears in another metric's help string and report
// a rename as present.
//
// RED on revert: change any name literal in metrics_descriptors_worker.go,
// metrics_descriptors_nat.go or metrics_descriptors_userspace_session.go and
// this fails naming the metric that lost its name.
func TestNewFlowContentionMetricNamesAreStable_4800(t *testing.T) {
	c := newCollector(nil)

	for _, tc := range []struct {
		want string
		desc fmt.Stringer
	}{
		// Per-worker install distribution — the sole input to both
		// cross-worker analyzer gates.
		{"xpf_userspace_worker_new_flow_installs_total", c.workerNewFlowInstalls},
		// SNAT allocator lock pair, per pool.
		{"xpf_userspace_source_nat_pool_live_lock_acquisitions_total", c.userspaceSNATPoolLiveLockAcquisitionsTotal},
		{"xpf_userspace_source_nat_pool_live_lock_contended_total", c.userspaceSNATPoolLiveLockContendedTotal},
		// Publish leg: call count + lock pair.
		{"xpf_userspace_shared_session_publishes_total", c.userspaceSharedSessionPublishes},
		{"xpf_userspace_shared_session_publish_lock_acquisitions_total", c.userspaceSharedSessionPublishLockAcquired},
		{"xpf_userspace_shared_session_publish_lock_contended_total", c.userspaceSharedSessionPublishLockBlocked},
		// Replication leg: fan-out pair, contention, and both depth shapes.
		{"xpf_userspace_session_replication_upserts_total", c.userspaceSessionReplicationUpserts},
		{"xpf_userspace_session_replication_enqueued_total", c.userspaceSessionReplicationEnqueued},
		{"xpf_userspace_session_replication_lock_contended_total", c.userspaceSessionReplicationLockBlocked},
		{"xpf_userspace_session_replication_queue_depth_sum", c.userspaceSessionReplicationQueueDepthSum},
		{"xpf_userspace_session_replication_queue_depth_max", c.userspaceSessionReplicationQueueDepthMax},
	} {
		if tc.desc == nil {
			t.Errorf("%s: descriptor is nil — it is not initialised by newCollector", tc.want)
			continue
		}
		marker := fmt.Sprintf("fqName: %q", tc.want)
		if !strings.Contains(tc.desc.String(), marker) {
			t.Errorf("metric %q is not exposed under that name; the descriptor "+
				"reads %s. Renaming a series breaks the analyzer scrape and every "+
				"dashboard built on it, with no error at runtime — the series just "+
				"stops existing", tc.want, tc.desc.String())
		}
	}
}
