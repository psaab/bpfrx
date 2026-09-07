package daemon

import "github.com/psaab/xpf/pkg/logging"

// syslogDropStats snapshots every installed remote-syslog client's drop
// counters for the xpf_syslog_messages_dropped_total family (#9165).
//
// Before this reader existed, all three SyslogClient drop accessors had ZERO
// production consumers: a counted drop reached an operator through exactly one
// channel — the logging package's own ≤1/s slog.Warn — so a warning that had
// already been rate-limited away left nothing behind. Syslog is where an
// operator looks AFTER an incident, and a dead collector means that record does
// not exist while `show` still renders the collector as configured.
//
// Nil-safe on purpose: this is called from a metrics scrape, which races the
// daemon's own startup and every commit that rebuilds the client set.
func (d *Daemon) syslogDropStats() []logging.SyslogDropStat {
	if d == nil || d.eventReader == nil {
		return nil
	}
	return d.eventReader.SyslogDropStats()
}
