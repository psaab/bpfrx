package logging

// SyslogDropStat is one remote syslog collector's drop accounting, snapshotted
// for an operator-facing surface.
//
// #9165: `DroppedWrites`/`DroppedDials`/`DroppedCooldown` existed with ZERO
// production readers. Every counted drop reached an operator through exactly
// one channel — the ≤1/s `slog.Warn` inside the package — and a warning that
// has already been rate-limited away leaves nothing behind. A counter nobody
// reads is indistinguishable from no counter, which is why the missing reader
// is half of the defect rather than a follow-up.
type SyslogDropStat struct {
	// RemoteAddr is the collector's host:port, as configured.
	RemoteAddr string
	// Protocol is "udp", "tcp" or "tls" — the label that makes a UDP-only
	// silence visible as a transport property rather than a mystery.
	Protocol string
	// Writes counts messages dropped because the write itself failed.
	Writes uint64
	// Dials counts messages dropped because the post-failure reconnect dial
	// failed. Stream transports only; a datagram socket never reconnects.
	Dials uint64
	// Cooldown counts messages dropped because a reconnect was suppressed by
	// the cooldown window. Stream transports only.
	Cooldown uint64
}

// SyslogDropStats snapshots the drop counters of every installed syslog client
// (goroutine-safe).
//
// The returned slice is a copy taken under the same RLock that guards the
// client set, so a concurrent ReplaceSyslogClients cannot be observed
// half-applied. The counters themselves are atomics read individually: a
// snapshot is not a consistent instant across all three, which is correct for
// monotonic counters scraped by Prometheus and is why they are exported as
// counters rather than as a rate computed here.
func (er *EventReader) SyslogDropStats() []SyslogDropStat {
	er.syslogMu.RLock()
	defer er.syslogMu.RUnlock()
	if len(er.syslogClients) == 0 {
		return nil
	}
	out := make([]SyslogDropStat, 0, len(er.syslogClients))
	for _, c := range er.syslogClients {
		if c == nil {
			continue
		}
		out = append(out, SyslogDropStat{
			RemoteAddr: c.RemoteAddr(),
			Protocol:   c.Protocol(),
			Writes:     c.DroppedWrites(),
			Dials:      c.DroppedDials(),
			Cooldown:   c.DroppedCooldown(),
		})
	}
	return out
}
