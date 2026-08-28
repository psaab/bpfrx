package config

import (
	"net"
	"strconv"
	"strings"
)

// ResolveSyslogSourceAddr returns the source IP to bind syslog forwarding to,
// resolved from a `security log source-interface` value (an interface name with
// an optional `.<unit>` suffix). It prefers the unit's configured
// PrimaryAddress (stripped to a bare IP); failing that it falls back to the
// first IPv4 address on the live kernel interface, and returns "" when neither
// is available.
//
// It lives in pkg/config, not pkg/daemon, so BOTH the daemon reconcile
// (applySyslogConfig) and the CLI in-process commit path (reloadSyslog /
// buildSyslogClients) resolve the global source-interface fallback identically
// — a stream configured with source-interface but no per-stream source-address
// must bind the same source IP whether the config is applied by daemon reconcile
// or a local-console commit (#5738). The split rule (first '.') mirrors
// ValidateSyslogSourceInterface exactly.
func ResolveSyslogSourceAddr(cfg *Config, srcIface string) string {
	// #6942: normalise exactly as ValidateSyslogSourceInterface does. The
	// validator trims before it parses, so on the strict path a value with
	// surrounding whitespace is judged in its trimmed form and then handed here
	// untrimmed — the two disagreed about the same string. The callers only
	// guard `!= ""`, which a whitespace-only value passes.
	srcIface = strings.TrimSpace(srcIface)

	// Parse "iface.unit" — e.g. "reth1.100" → base="reth1", unit=100
	base, unitStr, hasUnit := strings.Cut(srcIface, ".")
	unitNum := 0
	unitOK := true
	if hasUnit {
		// #6942: the error was checked and then IGNORED — unitNum stayed 0, so
		// "reth1.abc" resolved to reth1 unit 0 and syslog bound the wrong
		// logical unit, silently and plausibly. ValidateSyslogSourceInterface
		// rejects this and its message names this exact behaviour ("a
		// non-numeric unit silently binds the syslog source to unit 0"), so the
		// strict path masked it; the lenient path (Load / SyncApply) did not.
		//
		// A BARE name legitimately means unit 0 — that is why the skip is
		// conditioned on hasUnit && parse-failed rather than on unitNum == 0.
		n, err := strconv.Atoi(unitStr)
		if err != nil {
			unitOK = false
		} else {
			unitNum = n
		}
	}
	if ifc, ok := cfg.Interfaces.Interfaces[base]; ok && ifc != nil && unitOK {
		if unit, ok := ifc.Units[unitNum]; ok && unit.PrimaryAddress != "" {
			// PrimaryAddress is CIDR — strip the prefix length
			if ip, _, err := net.ParseCIDR(unit.PrimaryAddress); err == nil {
				return ip.String()
			}
		}
	}
	// Fallback: first IPv4 from kernel
	if iface, err := net.InterfaceByName(srcIface); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					return ipn.IP.String()
				}
			}
		}
	}
	return ""
}
