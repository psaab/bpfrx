// Phase 10 of #1043: extract the three policy-related ShowText case
// bodies (`policies-hit-count`, `policies-detail`, `policy-options`)
// into dedicated methods. Same methodology as Phases 1-9: semantic
// relocation, no behavior change. Each case body is moved verbatim
// apart from `&buf` references becoming `buf` (passed-in
// `*strings.Builder`) and `break`/early-`else` patterns flattened
// into early-return form.
//
// `showPoliciesHitCount` and `showPoliciesDetail` take a `filter`
// string parameter (originally `req.Filter`) so the bodies no longer
// reference the gRPC request struct directly.

package grpcapi

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/policymatch"
)

// policySchedulerStateProvider is the optional dataplane capability the
// gRPC policy-detail text surface uses to learn the live per-scheduler
// active-state map (#3062). The userspace dataplane adapter implements
// it; when it is unavailable the surface renders every policy enabled
// (bit-identical to the pre-#3062 output).
type policySchedulerStateProvider interface {
	PolicySchedulerActiveState() map[string]bool
}

// policySchedulerActiveState returns the live scheduler active-state map
// and whether it could be queried. ok=false means the runtime state is
// unknown and the caller must not claim any policy is scheduler-inactive.
func (s *Server) policySchedulerActiveState() (state map[string]bool, ok bool) {
	if s == nil || s.dp == nil {
		return nil, false
	}
	p, isProvider := s.dp.(policySchedulerStateProvider)
	if !isProvider {
		return nil, false
	}
	return p.PolicySchedulerActiveState(), true
}

// policyInactiveFn returns a per-policy scheduler-inactivity predicate bound to
// the live active-state snapshot for use as policymatch.Query.PolicyInactiveFn
// (#3104). It always returns a non-nil predicate so the simulator agrees with
// the dataplane in BOTH directions (#3414): when the runtime scheduler state
// cannot be queried (no provider / early boot), state is nil, and
// PolicyInactiveFn(nil) marks every scheduler-bound policy inactive — exactly
// what the snapshot builder does (policyRuleInactive: nil map => dropped) until
// live state arrives, so the diagnostic never certifies a verdict for a
// scheduled policy the dataplane is currently skipping. A NON-scheduled policy
// (empty scheduler name) is always active regardless of the (possibly nil)
// state map, so its verdict is unchanged.
func (s *Server) policyInactiveFn() func(string) bool {
	state, _ := s.policySchedulerActiveState()
	return dpuserspace.PolicyInactiveFn(state)
}

// policyDetailStateSuffix returns the per-policy detail header suffix for
// a scheduler-inactive policy (", State: inactive, Scheduler: <name>"),
// or "" otherwise. haveSched gates the lookup so that when the runtime
// state cannot be queried the suffix is empty and the header stays
// bit-identical to the pre-#3062 output for active/non-scheduled
// policies (#3062).
func policyDetailStateSuffix(schedulerName string, activeState map[string]bool, haveSched bool) string {
	if haveSched && dpuserspace.PolicyInactive(schedulerName, activeState) {
		return fmt.Sprintf(", State: inactive, Scheduler: %s", schedulerName)
	}
	return ""
}

// showPoliciesHitCount renders the per-policy packet/byte hit counters
// with a fixed-width tabular format. `filter` is parsed for
// `from-zone X to-zone Y` selectors.
func (s *Server) showPoliciesHitCount(filter string, buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	// Parse optional zone filter from filter: "from-zone X to-zone Y"
	var filterFrom, filterTo string
	if filter != "" {
		parts := strings.Fields(filter)
		for i := 0; i+1 < len(parts); i++ {
			switch parts[i] {
			case "from-zone":
				filterFrom = parts[i+1]
				i++
			case "to-zone":
				filterTo = parts[i+1]
				i++
			}
		}
	}
	// Honor `set security policy-stats system-wide enable` (#2008 M4 /
	// #2118): Junos maintains and displays per-policy hit counters only
	// when policy-stats is enabled system-wide (default off). The
	// Prometheus collector (metrics_counters.go) already gates on this
	// knob; gate the text/structured display surfaces identically so all
	// four surfaces (Prometheus, gRPC text hit-count, gRPC text detail,
	// structured gRPC GetPolicies, local CLI) report the SAME values.
	// When the knob is off, the per-rule counter columns read 0 (we skip
	// the dataplane read) rather than surfacing live counts the operator
	// did not enable.
	statsEnabled := cfg.Security.PolicyStatsEnabled
	// #3408: surface a per-policy counter read failure as a warning AFTER all
	// reads rather than printing clean-zero hit counts.
	var readErr error
	fmt.Fprintf(buf, "%-12s %-12s %-24s %-8s %12s %16s\n",
		"From zone", "To zone", "Policy", "Action", "Packets", "Bytes")
	fmt.Fprintln(buf, strings.Repeat("-", 88))
	policySetID := uint32(0)
	var totalPkts, totalBytes uint64
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, mirroring the runtime walker.
		if zpp == nil {
			policySetID++
			continue
		}
		if (filterFrom != "" && zpp.FromZone != filterFrom) ||
			(filterTo != "" && zpp.ToZone != filterTo) {
			policySetID++
			continue
		}
		for i, pol := range zpp.Policies {
			// #3476: skip a nil rule like the runtime walker does.
			if pol == nil {
				continue
			}
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var pkts, bytes uint64
			if (statsEnabled || pol.Count) && s.dp != nil && s.dp.IsLoaded() {
				if counters, err := s.dp.ReadPolicyCounters(ruleID); err == nil {
					pkts = counters.Packets
					bytes = counters.Bytes
				} else if readErr == nil {
					readErr = err
				}
			}
			totalPkts += pkts
			totalBytes += bytes
			fmt.Fprintf(buf, "%-12s %-12s %-24s %-8s %12d %16d\n",
				zpp.FromZone, zpp.ToZone, pol.Name, action, pkts, bytes)
		}
		policySetID++
	}
	// Global policies (#3059): the runtime evaluates global policies after
	// the exact zone-pair policies, and the gRPC detail view, CLI,
	// Prometheus collector, and structured GetPolicies all expose them.
	// The hit-count text surface must too — otherwise an operator using
	// the exact command meant to prove which policy is catching traffic
	// sees zero evidence for a global emergency deny/permit. Render globals
	// with from/to zone "*" (matching the other surfaces). Counter IDs
	// continue from the zone-pair loop: policySetID*MaxRulesPerPolicy + i,
	// keeping the global slots aligned with the dataplane (#3045/#3050 did
	// the same for the REST inventory).
	//
	// #3357: a from/to-zone filter no longer suppresses the whole global
	// block. An unscoped global is enforced for every zone pair and a scoped
	// global (#3148) may target exactly the filtered pair, so the filtered
	// hit-count surface must show the globals that govern it.
	// GlobalPolicyAppliesToZonePair selects per-rule scope against the filter.
	if len(cfg.Security.GlobalPolicies) > 0 {
		for i, pol := range cfg.Security.GlobalPolicies {
			if pol == nil {
				continue
			}
			// #3357: drop a scoped global that targets a different zone pair.
			if !policymatch.GlobalPolicyAppliesToZonePair(pol.Match.FromZone, pol.Match.ToZone, filterFrom, filterTo) {
				continue
			}
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var pkts, bytes uint64
			if (statsEnabled || pol.Count) && s.dp != nil && s.dp.IsLoaded() {
				if counters, err := s.dp.ReadPolicyCounters(ruleID); err == nil {
					pkts = counters.Packets
					bytes = counters.Bytes
				} else if readErr == nil {
					readErr = err
				}
			}
			totalPkts += pkts
			totalBytes += bytes
			// #3286: a scoped global (#3148) reports its zone pair in the
			// From/To columns so the hit-count row is not ambiguous; an
			// unscoped global keeps "*"/"*".
			hcFrom, hcTo := "*", "*"
			if pol.Match.FromZone != "" {
				hcFrom = pol.Match.FromZone
			}
			if pol.Match.ToZone != "" {
				hcTo = pol.Match.ToZone
			}
			fmt.Fprintf(buf, "%-12s %-12s %-24s %-8s %12d %16d\n",
				hcFrom, hcTo, pol.Name, action, pkts, bytes)
		}
	}
	// #3363: the IMPLICIT default-policy catch-all has a reserved hit counter
	// (read via the DefaultPolicySentinelID handle). Surface it as a final row
	// — separated from the configured-rule totals — in the unfiltered view so
	// the operator can see default-deny/permit hits across every zone pair.
	// Gated on policy-stats like every other row for cross-surface consistency.
	if filterFrom == "" && filterTo == "" {
		defAction := "permit"
		switch cfg.Security.DefaultPolicy {
		case config.PolicyDeny:
			defAction = "deny"
		case config.PolicyReject:
			defAction = "reject"
		}
		var pkts, bytes uint64
		if statsEnabled && s.dp != nil && s.dp.IsLoaded() {
			if counters, err := s.dp.ReadPolicyCounters(dataplane.DefaultPolicySentinelID); err == nil {
				pkts = counters.Packets
				bytes = counters.Bytes
			} else if readErr == nil {
				readErr = err
			}
		}
		totalPkts += pkts
		totalBytes += bytes
		fmt.Fprintf(buf, "%-12s %-12s %-24s %-8s %12d %16d\n",
			"-", "-", dataplane.DefaultPolicyName, defAction, pkts, bytes)
	}
	fmt.Fprintln(buf, strings.Repeat("-", 88))
	fmt.Fprintf(buf, "%-48s %8s %12d %16d\n", "Total", "", totalPkts, totalBytes)
	if readErr != nil {
		fmt.Fprintf(buf, "warning: policy counter read failed (hit counts may be incomplete): %v\n", readErr)
	}
}

// showPoliciesDetail renders per-policy detail (match conditions,
// then-actions, session statistics) plus the global-policies block.
// `filter` is parsed for `from-zone X to-zone Y` selectors.
func (s *Server) showPoliciesDetail(filter string, buf *strings.Builder) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		fmt.Fprintln(buf, "No active configuration")
		return
	}
	var filterFrom, filterTo string
	if filter != "" {
		parts := strings.Fields(filter)
		for i := 0; i+1 < len(parts); i++ {
			switch parts[i] {
			case "from-zone":
				filterFrom = parts[i+1]
				i++
			case "to-zone":
				filterTo = parts[i+1]
				i++
			}
		}
	}
	// Same policy-stats gate as showPoliciesHitCount (#2008 M4 / #2118):
	// the "Session statistics" block is per-policy hit-count display, so
	// it must honor the knob for cross-surface consistency.
	statsEnabled := cfg.Security.PolicyStatsEnabled
	schedActive, haveSched := s.policySchedulerActiveState()
	// #3667 (H05): the displayed Index must equal the runtime/RT_FLOW policy ID
	// so a remote operator can map a policy-deny/RT_FLOW log line (which carries
	// the numeric policy ID) back to the detail row. RuntimePolicyIDs is the same
	// SSOT the local CLI detail + REST/gRPC structured inventory key off.
	runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
	// #3667 (H01, correctness): shared source/destination address renderer.
	// When the match sense is inverted (source-address-excluded /
	// destination-address-excluded) the header is annotated "(except)" so the
	// gRPC text detail shows the SAME security meaning as the rule and the local
	// CLI — the rule matches every address EXCEPT those listed. Printing the
	// listed addresses under a plain header showed the OPPOSITE meaning.
	printAddrs := func(label string, addrs []string, excluded bool) {
		if excluded {
			fmt.Fprintf(buf, "      %s (except):\n", label)
		} else {
			fmt.Fprintf(buf, "      %s:\n", label)
		}
		for _, addr := range addrs {
			resolved := grpcResolveAddress(cfg, addr)
			// #3358: unqualify a synthetic zone-local key (#3061,
			// zone-local/<zone>/<name>) to the authored book name so the
			// internal compiler token never leaks; resolution still keys off
			// the qualified token (it is the global-book key).
			fmt.Fprintf(buf, "        %s%s\n", config.DisplayAddressName(addr), resolved)
		}
	}
	// #3408: surface a per-policy counter read failure as a warning AFTER all
	// reads rather than silently omitting the session-statistics block.
	var readErr error
	policySetID := uint32(0)
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, mirroring the runtime walker.
		if zpp == nil {
			policySetID++
			continue
		}
		if (filterFrom != "" && zpp.FromZone != filterFrom) ||
			(filterTo != "" && zpp.ToZone != filterTo) {
			policySetID++
			continue
		}
		fmt.Fprintf(buf, "Policy: %s -> %s, State: enabled\n", zpp.FromZone, zpp.ToZone)
		for i, pol := range zpp.Policies {
			// #3476: skip a nil rule like the runtime walker does.
			if pol == nil {
				continue
			}
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			capAction := strings.ToUpper(action[:1]) + action[1:]
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			// #3062: a scheduler-inactive policy appends State: inactive +
			// the scheduler name. Active/non-scheduled policies stay
			// bit-identical (no suffix), keeping the gRPC text plane in
			// agreement with the CLI detail surface.
			fmt.Fprintf(buf, "\n  Policy: %s, action-type: %s%s, Index: %d\n", pol.Name, capAction,
				policyDetailStateSuffix(pol.SchedulerName, schedActive, haveSched),
				dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i)))
			if pol.Description != "" {
				fmt.Fprintf(buf, "    Description: %s\n", pol.Description)
			}
			fmt.Fprintf(buf, "    Match:\n")
			fmt.Fprintf(buf, "      Source zone: %s\n", zpp.FromZone)
			fmt.Fprintf(buf, "      Destination zone: %s\n", zpp.ToZone)
			printAddrs("Source addresses", pol.Match.SourceAddresses, pol.Match.SourceAddressExcluded)
			printAddrs("Destination addresses", pol.Match.DestinationAddresses, pol.Match.DestinationAddressExcluded)
			fmt.Fprintf(buf, "      Applications:\n")
			for _, app := range pol.Match.Applications {
				fmt.Fprintf(buf, "        %s\n", app)
			}
			fmt.Fprintf(buf, "    Then:\n")
			fmt.Fprintf(buf, "      %s\n", action)
			// #3667 (H04): surface the independent at-create/at-close session-log
			// modes instead of a bare "log" so a remote operator can tell whether
			// session starts, closes, or both are logged (different cost + audit
			// meaning). SessionLogModes is the SSOT shared with the local CLI.
			if modes := pol.Log.SessionLogModes(); len(modes) > 0 {
				fmt.Fprintf(buf, "      Session log: %s\n", strings.Join(modes, ", "))
			}
			if pol.Count {
				fmt.Fprintf(buf, "      count\n")
			}
			if (statsEnabled || pol.Count) && s.dp != nil && s.dp.IsLoaded() {
				if counters, err := s.dp.ReadPolicyCounters(ruleID); err == nil {
					fmt.Fprintf(buf, "    Session statistics:\n")
					fmt.Fprintf(buf, "      %d packets, %d bytes\n", counters.Packets, counters.Bytes)
				} else if readErr == nil {
					readErr = err
				}
			}
		}
		policySetID++
		fmt.Fprintln(buf)
	}
	// Global policies. #3357: a from/to-zone filter no longer suppresses the
	// global block — the filtered detail surface must still show an unscoped
	// global (enforced for every pair) and a scoped global (#3148) targeting
	// the filtered pair. The "Global policies:" header prints lazily so a
	// filter that selects no global leaves no dangling empty header.
	if len(cfg.Security.GlobalPolicies) > 0 {
		globalHeaderPrinted := false
		for i, pol := range cfg.Security.GlobalPolicies {
			// #3476: skip a nil global rule like the runtime walker does.
			if pol == nil {
				continue
			}
			// #3357: drop a scoped global that targets a different zone pair.
			if !policymatch.GlobalPolicyAppliesToZonePair(pol.Match.FromZone, pol.Match.ToZone, filterFrom, filterTo) {
				continue
			}
			if !globalHeaderPrinted {
				fmt.Fprintf(buf, "Global policies:\n")
				globalHeaderPrinted = true
			}
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			capAction := strings.ToUpper(action[:1]) + action[1:]
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			// #3062: scheduler-inactive global policy appends State: inactive.
			fmt.Fprintf(buf, "\n  Policy: %s, action-type: %s%s, Index: %d\n", pol.Name, capAction,
				policyDetailStateSuffix(pol.SchedulerName, schedActive, haveSched),
				dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i)))
			if pol.Description != "" {
				fmt.Fprintf(buf, "    Description: %s\n", pol.Description)
			}
			fmt.Fprintf(buf, "    Match:\n")
			// #3286: a scoped global (#3148) narrows itself to a zone pair;
			// surface the configured scope so the detail view does not read
			// as all-zones. Omitted for an unscoped global (no regression).
			if pol.Match.FromZone != "" {
				fmt.Fprintf(buf, "      Source zone: %s\n", pol.Match.FromZone)
			}
			if pol.Match.ToZone != "" {
				fmt.Fprintf(buf, "      Destination zone: %s\n", pol.Match.ToZone)
			}
			printAddrs("Source addresses", pol.Match.SourceAddresses, pol.Match.SourceAddressExcluded)
			printAddrs("Destination addresses", pol.Match.DestinationAddresses, pol.Match.DestinationAddressExcluded)
			fmt.Fprintf(buf, "      Applications:\n")
			for _, app := range pol.Match.Applications {
				fmt.Fprintf(buf, "        %s\n", app)
			}
			fmt.Fprintf(buf, "    Then:\n")
			fmt.Fprintf(buf, "      %s\n", action)
			// #3667 (H04): surface the independent at-create/at-close session-log
			// modes instead of a bare "log" so a remote operator can tell whether
			// session starts, closes, or both are logged (different cost + audit
			// meaning). SessionLogModes is the SSOT shared with the local CLI.
			if modes := pol.Log.SessionLogModes(); len(modes) > 0 {
				fmt.Fprintf(buf, "      Session log: %s\n", strings.Join(modes, ", "))
			}
			if pol.Count {
				fmt.Fprintf(buf, "      count\n")
			}
			if (statsEnabled || pol.Count) && s.dp != nil && s.dp.IsLoaded() {
				if counters, err := s.dp.ReadPolicyCounters(ruleID); err == nil {
					fmt.Fprintf(buf, "    Session statistics:\n")
					fmt.Fprintf(buf, "      %d packets, %d bytes\n", counters.Packets, counters.Bytes)
				} else if readErr == nil {
					readErr = err
				}
			}
		}
		fmt.Fprintln(buf)
	}
	if readErr != nil {
		fmt.Fprintf(buf, "warning: policy counter read failed (session statistics may be incomplete): %v\n", readErr)
	}
}

// showPolicyOptions renders prefix-lists and policy-statement terms
// from `policy-options { ... }` configuration.
func (s *Server) showPolicyOptions(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return
	}
	po := &cfg.PolicyOptions
	if len(po.PrefixLists) > 0 {
		buf.WriteString("Prefix lists:\n")
		for name, pl := range po.PrefixLists {
			fmt.Fprintf(buf, "  %-30s %d prefixes\n", name, len(pl.Prefixes))
			for _, p := range pl.Prefixes {
				fmt.Fprintf(buf, "    %s\n", p)
			}
		}
	}
	if len(po.PolicyStatements) > 0 {
		if len(po.PrefixLists) > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString("Policy statements:\n")
		for name, ps := range po.PolicyStatements {
			fmt.Fprintf(buf, "  %s", name)
			if ps.DefaultAction != "" {
				fmt.Fprintf(buf, " (default: %s)", ps.DefaultAction)
			}
			buf.WriteString("\n")
			for _, t := range ps.Terms {
				fmt.Fprintf(buf, "    term %s:\n", t.Name)
				if len(t.FromProtocols) == 1 {
					fmt.Fprintf(buf, "      from protocol %s\n", t.FromProtocols[0])
				} else if len(t.FromProtocols) > 1 {
					fmt.Fprintf(buf, "      from protocol [ %s ]\n", strings.Join(t.FromProtocols, " "))
				}
				for _, pl := range t.PrefixList {
					fmt.Fprintf(buf, "      from prefix-list %s\n", pl)
				}
				for _, c := range t.FromCommunity {
					fmt.Fprintf(buf, "      from community %s\n", c)
				}
				for _, ap := range t.FromASPath {
					fmt.Fprintf(buf, "      from as-path %s\n", ap)
				}
				for _, rf := range t.RouteFilters {
					match := rf.MatchType
					if rf.MatchType == "upto" && rf.UptoLen > 0 {
						match = fmt.Sprintf("upto /%d", rf.UptoLen)
					}
					fmt.Fprintf(buf, "      from route-filter %s %s\n", rf.Prefix, match)
				}
				if t.Action != "" {
					fmt.Fprintf(buf, "      then %s\n", t.Action)
				}
				if t.NextHop != "" {
					fmt.Fprintf(buf, "      then next-hop %s\n", t.NextHop)
				}
				if t.LoadBalance != "" {
					fmt.Fprintf(buf, "      then load-balance %s\n", t.LoadBalance)
				}
			}
		}
	}
	if len(po.PrefixLists) == 0 && len(po.PolicyStatements) == 0 {
		buf.WriteString("No policy-options configured\n")
	}
}
