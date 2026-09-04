package daemon

import "testing"

// #8397: the accessor that feeds xpf_dataplane_helper_crash_episodes_total.
//
// BIND THE WIRING, NOT ONLY THE FUNCTION IT CALLS. The metric, the collector
// and the history ring each have their own cells and each passes on its own —
// and all three would keep passing if `HelperCrashEpisodesFn` were never set on
// the api.Config. A nil there disables the metric silently: the descriptor is
// still registered, the series is simply never emitted, and "no series" is
// indistinguishable from "a daemon that has not crashed".
//
// This cell drives the daemon-side accessor directly. It cannot see the one
// assignment in daemon_run_servers.go — that line is a literal in a struct
// literal with no seam — so what it binds is the accessor's CONTRACT, which is
// the half a future refactor is likely to get wrong: returning 0 versus
// panicking when the userspace manager is absent.

func TestHelperCrashEpisodesAccessorIsSafeWithoutADataplane8397(t *testing.T) {
	// The daemon reaches the userspace Manager only through the published
	// dataplane. Before one is published — and on a config-only daemon that
	// never publishes one — this must answer 0 rather than panic. The metric
	// is collected on every scrape, including during startup, so a panic here
	// takes down the scrape path for every other metric with it.
	var d Daemon
	if got := d.helperCrashEpisodes(); got != 0 {
		t.Errorf("helperCrashEpisodes with no dataplane = %d, want 0", got)
	}
}

func TestHelperCrashEpisodesAccessorIsSafeOnANilDaemon8397(t *testing.T) {
	// The accessor is handed to api.Config as a method value, so it outlives
	// the construction site and is called from the collector goroutine. The
	// sibling it copies (persistentNatLeaseManager) guards nil for the same
	// reason; keep the guard rather than assume the caller.
	var d *Daemon
	if got := d.helperCrashEpisodes(); got != 0 {
		t.Errorf("helperCrashEpisodes on a nil daemon = %d, want 0", got)
	}
}
