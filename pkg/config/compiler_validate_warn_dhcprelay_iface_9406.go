package config

import (
	"fmt"
	"sort"
)

// validateDHCPRelayInterfaceRefWarnings makes the #9406 failure AUDIBLE.
//
// `forwarding-options dhcp-relay group <g> interface <ref>` is the relay's bind
// key. Under the canonical Junos spelling the reference is a LOGICAL interface
// (`ge-0/0/0.0`, `reth0.0`), and the relay resolves it to a kernel device
// (#9406) — but resolution cannot invent one. A member naming an interface or
// unit the config never declares produces a relay that binds nothing.
//
// That failure is silent BY CONSTRUCTION on the runtime side, which is why it
// needs a commit-time voice: `resolveGIAddrWithRetry` is an unbounded retry
// loop with ONE `slog.Warn` and then `slog.Debug` forever and returns no error;
// the "dhcp-relay: started" line is logged before any bind; and every counter
// in `RelayStats` is a forwarding counter, so a relay bound to nothing looks
// exactly like an idle segment. The runtime cannot distinguish "nobody is
// asking for a lease" from "there is no socket". The COMMIT can.
//
// Advisory rather than gate, for the same reason as the #9405 protocol
// advisory: the tolerant load / HA config-sync paths must still accept a config
// whose interface set does not explain every reference (#1960 no-brick), and
// the failure being fixed is "no signal", not "wrong signal".
//
// Groups are reported in sorted order so the message set is deterministic;
// members keep config order within a group.
func validateDHCPRelayInterfaceRefWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	relay := cfg.ForwardingOptions.DHCPRelay
	if relay == nil || len(relay.Groups) == 0 || len(cfg.Interfaces.Interfaces) == 0 {
		// With no declared interfaces there is nothing to compare against and
		// every member would warn — noise, not signal.
		return nil
	}

	names := make([]string, 0, len(relay.Groups))
	for name := range relay.Groups {
		names = append(names, name)
	}
	sort.Strings(names)

	declared := declaredInterfaceIndex(cfg)
	var warnings []string
	for _, name := range names {
		g := relay.Groups[name]
		if g == nil {
			continue
		}
		for _, ref := range g.Interfaces {
			if ref == "" {
				continue
			}
			reason := unresolvedInterfaceRef(declared, ref)
			if reason == "" {
				continue
			}
			warnings = append(warnings, fmt.Sprintf(
				"forwarding-options dhcp-relay group %s interface %s %s — the "+
					"relay will bind no device on it and relay nothing, and it "+
					"reports as a started service with all-zero counters "+
					"(#9406).", name, ref, reason))
		}
	}
	return warnings
}
