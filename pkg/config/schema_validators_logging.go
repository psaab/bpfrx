package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ValidateSyslogSourceInterface accepts a `security log source-interface`
// value: an interface name with an optional `.<unit>` suffix where the unit,
// when present, MUST be a non-negative integer (#3349). The source resolver
// (pkg/daemon/daemon_system.go resolveSourceAddr) splits on the FIRST '.' and
// strconv.Atoi's the remainder; a non-numeric unit is an ignored error that
// silently falls back to unit 0 — binding the syslog source to the WRONG
// logical unit's address. Rejecting it at commit makes the typo
// operator-visible instead of misrouting the audit source IP. The split rule
// (first '.') mirrors resolveSourceAddr's strings.Cut exactly.
func ValidateSyslogSourceInterface(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected an interface name, e.g. ge-0-0-0 or reth1.100)")
	}
	base, unit, hasUnit := strings.Cut(trimmed, ".")
	if base == "" {
		return fmt.Errorf("invalid interface name %q (empty name before '.')", raw)
	}
	if hasUnit {
		n, err := strconv.Atoi(unit)
		if err != nil || n < 0 {
			return fmt.Errorf("invalid logical unit %q in %q (expected a non-negative "+
				"integer; a non-numeric unit silently binds the syslog source to unit 0)", unit, raw)
		}
	}
	return nil
}
