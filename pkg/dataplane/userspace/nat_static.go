package userspace

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// clampPort narrows a compiler-stored port (int; 0 = port ABSENT / match-any,
// the whole-address 1:1 wildcard sentinel) into the u16 wire slot. Callers MUST
// first reject a PRESENT-but-out-of-range value with staticNATPortOutOfRange —
// buildStaticNATSnapshots drops such a rule so it fails CLOSED — because the
// only in-band "no port" value here is 0, which the Rust side reads as the
// whole-address wildcard. Coercing an invalid port to 0 would therefore
// fail OPEN (expose every port of the external address), not closed (#5101).
// The residual out-of-range guard below is a belt-and-suspenders narrow;
// it should be unreachable given the upstream drop.
func clampPort(p int) uint16 {
	if p < 1 || p > 65535 {
		return 0
	}
	return uint16(p)
}

// staticNATPortOutOfRange reports whether a compiler-stored static-NAT port
// carries a PRESENT-but-invalid value: a nonzero magnitude outside the valid
// 1..65535 wire range (e.g. a persisted / peer-synced 70000). 0 is the
// legitimate "port absent / match any" sentinel — the whole-address 1:1 shape —
// and is NOT out of range. This mirrors the strict commit-check predicate
// (validateNATMatchDestinationPortStrict / validateNATHostMaskStrict, pkg/config
// compiler_validate_strict_nat.go). Strict commit rejects such a port outright;
// on the lenient load / peer-sync path this lets buildStaticNATSnapshots drop
// the rule so an invalid port fails CLOSED instead of collapsing to the port-0
// whole-address wildcard and exposing every port of the external address (#5101).
func staticNATPortOutOfRange(p int) bool {
	return p != 0 && (p < 1 || p > 65535)
}

func buildStaticNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []StaticNATRuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		return nil
	}
	out := make([]StaticNATRuleSnapshot, 0)
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 {
				continue
			}
			// #5859: `then static-nat inet` is the Junos NAT64 keyword. The
			// compiler records rule.Then=="inet", but this same-family
			// static_nat table stores an IP address in InternalIP — emitting
			// the literal "inet" makes the Rust parse_nat_prefix fail and the
			// rule is SILENTLY SKIPPED (a strict-valid config claims NAT64 but
			// installs nothing). Strict commit now REJECTS this target
			// (validateStaticNATInetTargetStrict); on the lenient load /
			// peer-sync path it is a surfaced compile warning. Drop the rule
			// here too so the unparseable "inet" sentinel never reaches the
			// dataplane — fail CLOSED, symmetric with the #5101 out-of-range
			// port drop below. The supported IPv6->IPv4 path is the native
			// `security nat nat64` rule-set (buildNAT64Snapshots), untouched.
			if rule.Then == "inet" {
				slog.Warn("userspace snapshot: dropping static NAT `then static-nat inet` (NAT64) rule; not representable in the static_nat table (use `security nat nat64`) (fail-closed, #5859)",
					"ruleset", rs.Name, "rule", rule.Name)
				continue
			}
			// #5101: a PRESENT but out-of-range destination/mapped port must
			// not reach clampPort. Clamping it to 0 collapses the rule to the
			// whole-address (port-0) wildcard, which the Rust side installs as
			// a 1:1 mapping exposing EVERY port of the external address — a
			// fail-OPEN broadening. Strict commit rejects such a port; on the
			// lenient load / peer-sync path drop the rule so it fails CLOSED,
			// symmetric with the source-NAT unusable-pool and #3435
			// source-address lenient-path guards. Genuine-absent (0) is left
			// untouched: 0 -> whole-address 1:1 is a valid, common static-NAT
			// shape.
			if staticNATPortOutOfRange(rule.MatchDestinationPort) ||
				staticNATPortOutOfRange(rule.MappedPort) {
				slog.Warn("userspace snapshot: dropping static NAT rule with out-of-range port (fail-closed)",
					"ruleset", rs.Name, "rule", rule.Name,
					"match_destination_port", rule.MatchDestinationPort,
					"mapped_port", rule.MappedPort)
				continue
			}
			// #3435: carry the `match source-address` constraint into the
			// snapshot. Prefer the full bracket-list (SourceAddresses); fall
			// back to the singular SourceAddress for an older typed config.
			// Empty = match any source (unscoped, pre-#3435 behavior).
			sourceAddrs := append([]string(nil), rule.SourceAddresses...)
			if len(sourceAddrs) == 0 && rule.SourceAddress != "" {
				sourceAddrs = append(sourceAddrs, rule.SourceAddress)
			}
			out = append(out, StaticNATRuleSnapshot{
				Name:                 rule.Name,
				FromZone:             rs.FromZone,
				FromInterface:        rs.FromInterface,
				FromRoutingInstance:  rs.FromRoutingInstance,
				SourceAddresses:      sourceAddrs,
				ExternalIP:           rule.Match,
				InternalIP:           rule.Then,
				MatchDestinationPort: clampPort(rule.MatchDestinationPort),
				MappedPort:           clampPort(rule.MappedPort),
				CounterID:            natCounterID(natCounterIDs, dataplane.NATCounterTypeStatic, rs.Name, rule.Name),
			})
		}
	}
	return out
}
