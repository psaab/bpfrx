package natshow

import (
	"fmt"
	"io"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// RenderSourceRuleDetail renders detailed source NAT rule information,
// including pool details, translation hit counters, and active session
// counts per rule-set.
//
// crFn lazily supplies the apply result (zone-ID and NAT-counter maps);
// it is invoked only after the empty-config guard, preserving the
// master ordering where the consumer's applyResult() was called after
// the guard (so an empty config never touches dataplane state). A nil
// crFn, or a crFn returning nil, reproduces the "not loaded" path (no
// session counts, no translation hits).
func RenderSourceRuleDetail(w io.Writer, cfg *config.Config, dp Reader, crFn func() *dataplane.ApplyResult) {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		io.WriteString(w, "No source NAT rules configured\n")
		return
	}
	var cr *dataplane.ApplyResult
	if crFn != nil {
		cr = crFn()
	}
	// Count active SNAT sessions per rule-set
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)
	var scanErr error
	if dp != nil && dp.IsLoaded() && cr != nil {
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		if err := dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		}); err != nil {
			scanErr = err
		}
		if err := dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		}); err != nil && scanErr == nil {
			scanErr = err
		}
	}

	noteSessionScanError(w, scanErr)
	// #6534: the aggregate pool-cardinality budget is a per-CONFIG walk, so
	// hoist it out of the rule loop. The builder
	// (buildSourceNATSnapshots) hoists the identical call for the identical
	// reason; SourceNATPoolDisarmedReason composes it with the pool's own
	// definition verdict in the builder's precedence order.
	overBudgetPools := config.SourceNATAggregateOverBudgetPools(cfg)
	ruleIdx := 0
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			ruleIdx++
			// #7640: render the action the rule ACTUALLY carries. This
			// defaulted to "interface" whenever neither a pool nor `off` was
			// set — so an ACTIONLESS rule (one the strict gate rejects, and
			// which a tolerant load can still admit) displayed an action it
			// does not have and will not perform. That is the worst possible
			// output for the one rule shape an operator most needs to find.
			action := "none"
			switch {
			case rule.Then.PoolName != "":
				action = "pool " + rule.Then.PoolName
			case rule.Then.Off:
				action = "off"
			case rule.Then.Interface:
				action = "interface"
			}
			// #7363: the FULL match on BOTH sides. The source renderer had the
			// same singular-field shape as the destination one, so a fix to
			// only one would leave `show security nat source rule` still
			// rendering a name-scoped rule as 0.0.0.0/0.
			srcMatch := natMatchAddresses(
				rule.Match.SourceAddress, rule.Match.SourceAddresses,
				rule.Match.SourceAddressName, rule.Match.SourceAddressNames)
			if srcMatch == "" {
				srcMatch = "0.0.0.0/0"
			}
			dstMatch := natMatchAddresses(
				rule.Match.DestinationAddress, rule.Match.DestinationAddresses,
				rule.Match.DestinationAddressName, rule.Match.DestinationAddressNames)
			if dstMatch == "" {
				dstMatch = "0.0.0.0/0"
			}
			fmt.Fprintf(w, "source NAT rule: %s\n", rule.Name)
			fmt.Fprintf(w, "  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Fprintf(w, "    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
			fmt.Fprintf(w, "    Match:\n")
			fmt.Fprintf(w, "      Source addresses:      %s\n", srcMatch)
			fmt.Fprintf(w, "      Destination addresses: %s\n", dstMatch)
			if protos := rule.Match.ProtocolList(); len(protos) > 0 {
				fmt.Fprintf(w, "      IP protocol:           %s\n", strings.Join(protos, " "))
			}
			fmt.Fprintf(w, "    Action:                  %s\n", action)
			// #6534: a pool-mode rule whose pool the builder marks unusable
			// ships PoolUnusable=true and the Rust source-NAT path declines to
			// translate — but every field above rendered from config as if the
			// rule were armed. Interface-mode NAT has no pool, so gate on a
			// non-empty pool name exactly as the builder does.
			if rule.Then.PoolName != "" {
				noteNotInstalled(w, config.SourceNATDisarmReasonText(
					config.SourceNATPoolDisarmedReason(
						cfg.Security.NAT.SourcePools[rule.Then.PoolName],
						rule.Then.PoolName, overBudgetPools)))
			}
			noteLenientTerminalAction(w, cfg, "source", rs.Name, rule.Name)

			if rule.Then.PoolName != "" && cfg.Security.NAT.SourcePools != nil {
				if pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]; ok {
					if pool.PersistentNAT != nil {
						fmt.Fprintf(w, "    Persistent NAT:          enabled\n")
					}
					if len(pool.Addresses) > 0 {
						fmt.Fprintf(w, "    Pool addresses:          %s\n", strings.Join(pool.Addresses, ", "))
					}
					// #7173: a `port no-translation` pool does not translate the
					// source port at all — the dataplane takes the address-only
					// path and ignores the range entirely (see the #3906 note in
					// pkg/dataplane/userspace/nat_source.go). Printing
					// "Port range: 1024-65535" for one told the operator the pool
					// uses a port range it does not use, and the number shown was
					// a default this display invented locally rather than
					// anything configured.
					if pool.PortNoTranslation {
						fmt.Fprintf(w, "    Port translation:        disabled (source port preserved)\n")
					} else {
						portLow, portHigh := pool.PortLow, pool.PortHigh
						if portLow == 0 {
							portLow = 1024
						}
						if portHigh == 0 {
							portHigh = 65535
						}
						fmt.Fprintf(w, "    Port range:              %d-%d\n", portLow, portHigh)
					}
				}
			}

			if dp != nil && cr != nil {
				ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeSource, rs.Name, rule.Name)
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Fprintf(w, "    Translation hits:        %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}

			sessions := rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}]
			fmt.Fprintf(w, "    Number of sessions:      %d\n\n", sessions)
		}
	}
}
