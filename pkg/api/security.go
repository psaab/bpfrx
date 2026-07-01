package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/policymatch"
)

func (s *Server) zonesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []ZoneInfo{})
		return
	}

	cr := s.applyResult()
	// #3408: a per-zone counter read failure must not be reported as a clean
	// 0 — surface it as HTTP 500 after building, mirroring the global
	// /stats/global contract (#3345).
	var readErr error
	var zones []ZoneInfo
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		zi := ZoneInfo{
			Name:        zoneName,
			Description: zone.Description,
			TcpRst:      zone.TCPRst,
			Interfaces:  zone.Interfaces,
		}
		if zone.ScreenProfile != "" {
			zi.ScreenProfile = zone.ScreenProfile
		}

		// Host-inbound services. #3328: surface the admission posture
		// distinctly. HostInbound stays the flattened back-compat alias, but the
		// split fields let automation tell a service (ssh, ping) apart from a
		// protocol (ospf, bgp). Post-#3405 the admitted set — empty = deny-all —
		// is the discriminating signal (HostInboundConfigured is true for every
		// configured zone; see below).
		if zone.HostInboundTraffic != nil {
			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.SystemServices...)
			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.Protocols...)
			zi.HostInboundSystemServices = append(zi.HostInboundSystemServices, zone.HostInboundTraffic.SystemServices...)
			zi.HostInboundProtocols = append(zi.HostInboundProtocols, zone.HostInboundTraffic.Protocols...)
		}
		// HostInboundConfigured mirrors ZoneSnapshot.HostInboundConfigured
		// (#3070/#3362/#3405). Post-#3405 EVERY configured security zone is
		// host-inbound ENFORCING (Junos default-deny parity): a zone with no
		// `host-inbound-traffic` stanza default-DENIES host-bound traffic
		// exactly like an explicit empty stanza. buildZoneSnapshots sets
		// HostInboundConfigured=true unconditionally for every non-nil zone
		// (dataplane/userspace/zones.go). Re-deriving the bit from config shape
		// (stanza-or-override) reported false for a no-stanza zone — the API's
		// own "false = admit-all" contract, the exact OPPOSITE of the runtime
		// default-deny (#3653). Report the dataplane truth: enforcing. The
		// admitted token set (which may be empty = deny-all) lives in the split
		// fields below.
		zi.HostInboundConfigured = true
		for _, ref := range zone.SortedInterfaceHostInboundRefs() {
			hib := zone.InterfaceHostInbound[ref]
			zi.InterfaceHostInbound = append(zi.InterfaceHostInbound, ZoneInterfaceHostInbound{
				Interface:      ref,
				Configured:     true,
				SystemServices: append([]string{}, hib.SystemServices...),
				Protocols:      append([]string{}, hib.Protocols...),
			})
		}
		if zi.HostInbound == nil {
			zi.HostInbound = []string{}
		}
		if zi.HostInboundSystemServices == nil {
			zi.HostInboundSystemServices = []string{}
		}
		if zi.HostInboundProtocols == nil {
			zi.HostInboundProtocols = []string{}
		}
		if zi.Interfaces == nil {
			zi.Interfaces = []string{}
		}

		// Zone ID + counters
		if cr != nil {
			if id, ok := cr.ZoneIDs[zoneName]; ok {
				zi.ID = id
				if s.dp != nil && s.dp.IsLoaded() {
					ing, errIn := s.dp.ReadZoneCounters(id, 0)
					eg, errOut := s.dp.ReadZoneCounters(id, 1)
					switch {
					case errors.Is(errIn, dataplane.ErrCounterNotPopulated) ||
						errors.Is(errOut, dataplane.ErrCounterNotPopulated):
						// #3643 HIDE: per-zone traffic counters are not sourced
						// by the userspace dataplane. Flag them unavailable and
						// leave the counts unset rather than reporting a
						// misleading 0 or 500'ing the whole endpoint on the
						// structural stable-hash-id OOB.
						zi.PerZoneCountersAvailable = false
					case errIn != nil:
						if readErr == nil {
							readErr = errIn
						}
					case errOut != nil:
						if readErr == nil {
							readErr = errOut
						}
					default:
						zi.PerZoneCountersAvailable = true
						zi.IngressPackets = ing.Packets
						zi.IngressBytes = ing.Bytes
						zi.EgressPackets = eg.Packets
						zi.EgressBytes = eg.Bytes
					}
				}
			}
		}
		zones = append(zones, zi)
	}
	if readErr != nil {
		writeError(w, http.StatusInternalServerError,
			"zone counter read failed: "+readErr.Error())
		return
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	writeOK(w, zones)
}

func (s *Server) policiesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []PolicyInfo{})
		return
	}

	// Honor `set security policy-stats system-wide enable` (#2008 M4 /
	// #2118): per-policy hit counters are populated only when policy-stats
	// is enabled system-wide (default off), matching the Prometheus
	// collector and the CLI/gRPC display surfaces. When the knob is off,
	// hit_packets/hit_bytes stay 0 (we skip the dataplane read).
	statsEnabled := cfg.Security.PolicyStatsEnabled
	// #3408: surface a per-policy counter read failure as HTTP 500 after
	// building, rather than reporting clean-zero hit counts.
	var readErr error
	// #3336: span-accumulated runtime/RT_FLOW policy IDs keyed
	// [policySetID, sliceIndex] — the identity the event path logs, so
	// automation can join a policy_id back to a rule. The raw ordinal stays the
	// counter handle below.
	runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
	// #3624: live per-scheduler active-state, the same view the #3062 text
	// policy-detail surface uses (cli_show_security.go / server_show_policies_
	// text.go). haveSched gates the lookup: when the accessor is not wired or
	// returns ok=false (early boot / NoDataplane) the inventory reports every
	// rule active (inactive=false), matching the text surface's fail-open
	// display rather than the fail-closed match-policies simulator (#3414).
	var schedActive map[string]bool
	var haveSched bool
	if s.policySchedActiveFn != nil {
		schedActive, haveSched = s.policySchedActiveFn()
	}
	var policySetID uint32
	var result []PolicyInfo
	for _, zpp := range cfg.Security.Policies {
		// #3476: the tolerant / HA-sync config path can leave a nil
		// zone-pair set (Policies is []*ZonePairPolicies); the runtime
		// walker skips it while advancing the policy-set ID. Mirror that so
		// the inventory does not panic on zpp.FromZone.
		if zpp == nil {
			policySetID++
			continue
		}
		pi := PolicyInfo{
			FromZone: zpp.FromZone,
			ToZone:   zpp.ToZone,
		}
		for i, rule := range zpp.Policies {
			// #3476: skip a nil rule (Policies is []*Policy) like the
			// runtime walker does, rather than dereferencing rule.Name.
			if rule == nil {
				continue
			}
			pr := PolicyRule{
				Name:        rule.Name,
				Description: rule.Description,
				Action:      policyActionStr(rule.Action),
				// #3358: unqualify synthetic zone-local keys (#3061) so the
				// inventory exposes the authored book name, not the internal
				// compiler token. DisplayAddressNames returns a new slice.
				SrcAddresses: config.DisplayAddressNames(rule.Match.SourceAddresses),
				DstAddresses: config.DisplayAddressNames(rule.Match.DestinationAddresses),
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
				// #3336: surface the match-inversion flags so an audit does not
				// read a `source-address-excluded` rule's meaning inverted, the
				// independent session-init/close log modes the Log bool hides,
				// and the runtime identity (policy_id matches the event path,
				// rule_id the snapshot) for event<->rule correlation.
				SourceAddressExcluded:      rule.Match.SourceAddressExcluded,
				DestinationAddressExcluded: rule.Match.DestinationAddressExcluded,
				LogSessionInit:             rule.Log != nil && rule.Log.SessionInit,
				LogSessionClose:            rule.Log != nil && rule.Log.SessionClose,
				PolicyID:                   dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i)),
				RuleID:                     dpuserspace.StablePolicyRuleID(zpp.FromZone, zpp.ToZone, rule.Name),
				// #3624: scheduler binding + runtime scheduler state, mirroring
				// the #3062 text detail (Scheduler: line + State: inactive).
				SchedulerName: rule.SchedulerName,
				Inactive:      haveSched && dpuserspace.PolicyInactive(rule.SchedulerName, schedActive),
			}
			if pr.SrcAddresses == nil {
				pr.SrcAddresses = []string{}
			}
			if pr.DstAddresses == nil {
				pr.DstAddresses = []string{}
			}
			if pr.Applications == nil {
				pr.Applications = []string{}
			}

			if (statsEnabled || rule.Count) && s.dp != nil && s.dp.IsLoaded() {
				// #3474: the counter read handle MUST use the RAW slice index i,
				// not len(pi.Rules) (the compacted, nil-skipped count). The
				// resolver (policyRuleIDForCounter) and every other caller —
				// metrics_counters.go's policyCounterID(policySetID, i),
				// cli_show_security*.go, server_show_policies_text.go, and this
				// function's OWN global-policy loop below (+ uint32(i)) — key off
				// the raw slice index. With a nil rule before a real rule
				// len(pi.Rules) would lag i and mis-resolve this rule's counter;
				// using i keeps every counter handle on the one raw-slice-index
				// SSOT. (Nil rules are not reachable via any production config
				// path today; this is defensive SSOT-alignment, like #3476/#3494.)
				policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				if ctrs, err := s.dp.ReadPolicyCounters(policyID); err == nil {
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
				} else if readErr == nil {
					readErr = err
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []PolicyRule{}
		}
		result = append(result, pi)
		policySetID++
	}

	// Global policies (#3045): the CLI, gRPC GetPolicies, and the
	// Prometheus collector all expose globals; the REST inventory
	// endpoint must too, otherwise automation/dashboards cannot audit
	// rules the dataplane actively enforces. Emit a single global row
	// with from_zone="*"/to_zone="*" (matching gRPC) after the zone-pair
	// rows, preserving the policy-counter ID ordering: global counter IDs
	// start after the zone-pair policy-set count (policySetID continues
	// from the loop above).
	if len(cfg.Security.GlobalPolicies) > 0 {
		pi := PolicyInfo{
			FromZone: "*",
			ToZone:   "*",
		}
		for i, rule := range cfg.Security.GlobalPolicies {
			if rule == nil {
				continue
			}
			pr := PolicyRule{
				Name:        rule.Name,
				Description: rule.Description,
				Action:      policyActionStr(rule.Action),
				// #3358: unqualify synthetic zone-local keys (#3061) so the
				// inventory exposes the authored book name, not the internal
				// compiler token. DisplayAddressNames returns a new slice.
				SrcAddresses: config.DisplayAddressNames(rule.Match.SourceAddresses),
				DstAddresses: config.DisplayAddressNames(rule.Match.DestinationAddresses),
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
				// #3286: surface the scoped-global zone context (#3148) so
				// a global narrowed to a zone pair is not reported as
				// all-zones. Empty for an unscoped global — no regression.
				MatchFromZone: rule.Match.FromZone,
				MatchToZone:   rule.Match.ToZone,
				// #3336: match-inversion flags + independent log modes + runtime
				// identity. The global rule_id uses the "junos-global" sentinel
				// zones, matching the snapshot builder so it joins to the same
				// event.
				SourceAddressExcluded:      rule.Match.SourceAddressExcluded,
				DestinationAddressExcluded: rule.Match.DestinationAddressExcluded,
				LogSessionInit:             rule.Log != nil && rule.Log.SessionInit,
				LogSessionClose:            rule.Log != nil && rule.Log.SessionClose,
				PolicyID:                   dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i)),
				RuleID:                     dpuserspace.StablePolicyRuleID("junos-global", "junos-global", rule.Name),
				// #3624: scheduler binding + runtime scheduler state (see above).
				SchedulerName: rule.SchedulerName,
				Inactive:      haveSched && dpuserspace.PolicyInactive(rule.SchedulerName, schedActive),
			}
			if pr.SrcAddresses == nil {
				pr.SrcAddresses = []string{}
			}
			if pr.DstAddresses == nil {
				pr.DstAddresses = []string{}
			}
			if pr.Applications == nil {
				pr.Applications = []string{}
			}

			if (statsEnabled || rule.Count) && s.dp != nil && s.dp.IsLoaded() {
				policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				if ctrs, err := s.dp.ReadPolicyCounters(policyID); err == nil {
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
				} else if readErr == nil {
					readErr = err
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []PolicyRule{}
		}
		result = append(result, pi)
	}

	// #3363: the IMPLICIT default-policy catch-all now has a reserved hit
	// counter (read via the DefaultPolicySentinelID handle). Surface it as a
	// final synthetic policy set ("-"/"-") with one rule named
	// dataplane.DefaultPolicyName so automation/dashboards can audit
	// default-deny/permit hits — the most security-relevant boundary — without
	// scraping logs. Counts gate on policy-stats like every other rule.
	{
		defRule := PolicyRule{
			Name:         dataplane.DefaultPolicyName,
			Action:       policyActionStr(cfg.Security.DefaultPolicy),
			SrcAddresses: []string{},
			DstAddresses: []string{},
			Applications: []string{},
			// #3670: the implicit default-policy carries its own RT_FLOW log
			// intent (DefaultPolicyLogSessionInit/Close, threaded to the
			// dataplane via ConfigSnapshot.DefaultLogSessionInit/Close in the
			// #3534 builder). Surface it on the synthetic row exactly as the
			// configured rows expose Log/LogSessionInit/LogSessionClose (#3336)
			// so audit tooling does not read the most security-relevant
			// boundary as unlogged while the dataplane is emitting the records.
			Log:             cfg.Security.DefaultPolicyLogSessionInit || cfg.Security.DefaultPolicyLogSessionClose,
			LogSessionInit:  cfg.Security.DefaultPolicyLogSessionInit,
			LogSessionClose: cfg.Security.DefaultPolicyLogSessionClose,
			PolicyID:        dataplane.DefaultPolicySentinelID,
			RuleID:          dataplane.DefaultPolicyName,
		}
		if statsEnabled && s.dp != nil && s.dp.IsLoaded() {
			if ctrs, err := s.dp.ReadPolicyCounters(dataplane.DefaultPolicySentinelID); err == nil {
				defRule.HitPackets = ctrs.Packets
				defRule.HitBytes = ctrs.Bytes
			} else if readErr == nil {
				readErr = err
			}
		}
		result = append(result, PolicyInfo{
			FromZone: "-",
			ToZone:   "-",
			Rules:    []PolicyRule{defRule},
		})
	}

	if readErr != nil {
		writeError(w, http.StatusInternalServerError,
			"policy counter read failed: "+readErr.Error())
		return
	}
	writeOK(w, result)
}

func (s *Server) screenHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []ScreenInfo{})
		return
	}

	var result []ScreenInfo
	for name, profile := range cfg.Security.Screen {
		si := ScreenInfo{Name: name}
		si.Checks = screenChecks(profile)
		if si.Checks == nil {
			si.Checks = []string{}
		}
		si.Thresholds = config.ScreenThresholds(profile)
		result = append(result, si)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	writeOK(w, result)
}

func (s *Server) eventsHandler(w http.ResponseWriter, r *http.Request) {
	if s.eventBuf == nil {
		writeOK(w, []EventEntry{})
		return
	}

	limit := queryInt(r, "limit", 50)
	if limit > 10000 {
		limit = 10000
	}

	filter := logging.EventFilter{
		Action:   r.URL.Query().Get("action"),
		Protocol: r.URL.Query().Get("protocol"),
	}
	// Zone filter: presence of the `zone` query parameter selects the filter,
	// so zone 0 — the "unknown" / unassigned zone carried by pre-classification
	// and host-inbound events — is selectable (#3338). Zone IDs are 1-based, so
	// 0 used to be swallowed by the `0 = no filter` sentinel and those events
	// were invisible to any zone-filtered query. The word sentinels "unknown"
	// and "none" are accepted as aliases for 0, mirroring the unknown-zone label
	// used elsewhere. An absent parameter leaves the filter unset (match-all); a
	// malformed/out-of-range value fails closed with HTTP 400.
	if zoneStr := r.URL.Query().Get("zone"); zoneStr != "" {
		z, ok := parseEventZoneFilter(zoneStr)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid zone filter: "+zoneStr)
			return
		}
		filter.Zone = z
		filter.HasZone = true
	}

	var events []logging.EventRecord
	if filter.IsEmpty() {
		events = s.eventBuf.Latest(limit)
	} else {
		events = s.eventBuf.LatestFiltered(limit, filter)
	}

	result := make([]EventEntry, len(events))
	for i, ev := range events {
		result[i] = eventEntryFromRecord(ev)
	}
	writeOK(w, result)
}

// parseEventZoneFilter parses a security-event zone filter value. It accepts a
// 1-based numeric zone ID (0..65535) and the case-insensitive word sentinels
// "unknown"/"none" as aliases for zone 0, the unassigned/pre-classification
// zone (#3338). It returns (0,false) for a malformed or out-of-range value so
// the caller fails closed with HTTP 400 rather than silently widening the query
// (mirrors queryUint16Strict's fail-closed contract).
func parseEventZoneFilter(s string) (uint16, bool) {
	switch strings.ToLower(s) {
	case "unknown", "none":
		return 0, true
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

func (s *Server) matchPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		// #3375: no active config is the deterministic fail-closed default deny.
		// Surface the explicit string AND the typed default_used bit (same SSOT
		// renderer the gRPC surface uses).
		nilRes := policymatch.Result{DefaultUsed: true, Action: config.PolicyDeny}
		writeOK(w, MatchPoliciesResult{
			Action:      nilRes.DisplayAction(),
			DefaultUsed: true,
			// #3627 M06: echo the queried zone pair even on the no-config
			// fail-closed default deny so a stored diagnostic proves which zone
			// pair produced the verdict.
			QueriedFromZone: r.URL.Query().Get("from_zone"),
			QueriedToZone:   r.URL.Query().Get("to_zone"),
		})
		return
	}

	fromZone := r.URL.Query().Get("from_zone")
	toZone := r.URL.Query().Get("to_zone")

	// #3355 (H06): the CLI surfaces (show security match-policies / test
	// policy) require BOTH zones; REST accepted a missing zone and evaluated as
	// if the empty string were a zone, which the #3355 defined-zone guard would
	// then send straight to the default-policy — a misleading silent verdict for
	// what is really a malformed query. Reject it for parity with the CLI.
	if fromZone == "" || toZone == "" {
		writeError(w, http.StatusBadRequest, "from_zone and to_zone are required")
		return
	}

	// A non-empty but malformed src_ip/dst_ip would parse to nil and be
	// treated as a wildcard by matchPolicyAddr, yielding a false-positive
	// PERMIT verdict in the simulator (#1711). Reject it with 400. An
	// empty value still means "unspecified" (match any).
	srcIPStr := r.URL.Query().Get("src_ip")
	if srcIPStr != "" && net.ParseIP(srcIPStr) == nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid src_ip %q", srcIPStr))
		return
	}
	dstIPStr := r.URL.Query().Get("dst_ip")
	if dstIPStr != "" && net.ParseIP(dstIPStr) == nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid dst_ip %q", dstIPStr))
		return
	}

	srcIP := net.ParseIP(srcIPStr)
	dstIP := net.ParseIP(dstIPStr)
	// A malformed dst_port/src_port must not silently become 0 (the "any
	// port" wildcard) — that yields a misleading PERMIT/DENY verdict in the
	// simulator (#2934). Fail closed with 400. queryIntStrict rejects
	// malformed/negative values; policymatch.ValidatePort additionally
	// rejects an out-of-range port (>65535) that cannot describe a real
	// packet (#3116). 0/absent stays the unspecified wildcard.
	dstPort, ok := queryIntStrict(r, "dst_port", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid dst_port: "+r.URL.Query().Get("dst_port"))
		return
	}
	if err := policymatch.ValidatePort(dstPort); err != nil {
		writeError(w, http.StatusBadRequest, "invalid dst_port: "+err.Error())
		return
	}
	srcPort, ok := queryIntStrict(r, "src_port", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid src_port: "+r.URL.Query().Get("src_port"))
		return
	}
	if err := policymatch.ValidatePort(srcPort); err != nil {
		writeError(w, http.StatusBadRequest, "invalid src_port: "+err.Error())
		return
	}
	// A non-empty but unknown/out-of-range protocol token (e.g. "tcpp", "999")
	// must NOT silently become "any protocol" — the shared matcher's matchApp
	// short-circuits to match-any for an empty/unresolvable protocol, yielding a
	// misleading PERMIT/DENY verdict for a policy using `application any`
	// (#3108). Reject it with 400. An empty value still means "unspecified"
	// (match any protocol), unchanged.
	proto := r.URL.Query().Get("protocol")
	if err := policymatch.ValidateProtocol(proto); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// #3284: optional ICMP/ICMPv6 type/code so a type-constrained application
	// term (junos-ping = type 8) is honored. An empty value is unspecified (a
	// type-constrained term then fails closed, mirroring the dataplane); a
	// malformed/out-of-range value is rejected, never coerced.
	icmpType, err := policymatch.ParseICMPValue(r.URL.Query().Get("icmp_type"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid icmp_type: "+err.Error())
		return
	}
	icmpCode, err := policymatch.ParseICMPValue(r.URL.Query().Get("icmp_code"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid icmp_code: "+err.Error())
		return
	}

	// #3042: delegate to the single shared simulator so REST agrees with the
	// runtime evaluator (exact zone-pair -> wildcard-zone tiers (#3090) ->
	// scoped global (#3148) -> default-policy, predefined + nested-app-set +
	// literal-CIDR + any-ipv4/any-ipv6 + exclusion + feed overlay). The
	// pre-#3042 hand-written loop skipped globals, hard-coded "deny (default)",
	// and missed predefined apps / literal CIDRs.
	var overlay map[string][]string
	if s.feedOverlayFn != nil {
		overlay = s.feedOverlayFn()
	}
	// #3104: thread live per-scheduler active-state so the simulator skips a
	// scheduler-inactive policy exactly like the runtime (policy.rs
	// try_match_rule), falling through to the next active rule / default-policy.
	//
	// #3414: always bind a non-nil predicate so the unavailable-state path
	// fails the SAME direction as the dataplane. When the accessor is not
	// wired or returns ok=false (early boot / NoDataplane), schedState is nil,
	// and PolicyInactiveFn(nil) treats every scheduler-bound policy as inactive
	// — exactly as the snapshot builder does (policyRuleInactive: nil map =>
	// dropped) until live state arrives. Previously the closure stayed nil and
	// scheduled policies were simulated as-if-active, so the REST diagnostic
	// could certify a permit/deny the dataplane actually skips (#3414). A
	// NON-scheduled policy (empty scheduler name) is unaffected: PolicyInactiveFn
	// returns false for it regardless of the (possibly nil) state map.
	var schedState map[string]bool
	if s.policySchedActiveFn != nil {
		schedState, _ = s.policySchedActiveFn()
	}
	inactiveFn := dpuserspace.PolicyInactiveFn(schedState)
	res := policymatch.Match(cfg, policymatch.Query{
		FromZone:         fromZone,
		ToZone:           toZone,
		SrcIP:            srcIP,
		DstIP:            dstIP,
		Protocol:         proto,
		SrcPort:          srcPort,
		DstPort:          dstPort,
		ICMPType:         icmpType,
		ICMPCode:         icmpCode,
		FeedOverlay:      overlay,
		PolicyInactiveFn: inactiveFn,
	})
	// #3285: a `to-zone junos-host` query that matched no host-bound policy is
	// not a transit default — the dataplane host gate returns None (local
	// delivery; no global/default fallback). Surface it explicitly so the
	// caller does not read a misleading default-policy verdict for the host
	// path.
	if res.HostInboundUnmatched {
		writeOK(w, MatchPoliciesResult{
			HostInboundUnmatched: true,
			Action:               res.DisplayAction(),
			// #3627 M06: echo the queried zone pair on the host-inbound path so
			// the diagnostic names the tested zones (the host gate returns no
			// matched-policy scope to fill FromZone/ToZone).
			QueriedFromZone: fromZone,
			QueriedToZone:   toZone,
		})
		return
	}
	if !res.Matched {
		writeOK(w, MatchPoliciesResult{
			Action:      res.DisplayAction(),
			DefaultUsed: res.DefaultUsed,
			// #3627 M06: echo the queried zone pair on the no-match/default path
			// so a stored default-deny diagnostic proves which zone pair was
			// tested (FromZone/ToZone carry matched-policy scope, unset here).
			QueriedFromZone: fromZone,
			QueriedToZone:   toZone,
		})
		return
	}
	matchedID := res.PolicyID
	writeOK(w, MatchPoliciesResult{
		Matched:    true,
		PolicyName: res.PolicyName,
		Global:     res.Global,
		FromZone:   res.FromZone,
		ToZone:     res.ToZone,
		// #3627 M06: also echo the queried zone pair on a positive match. It is
		// the query context, distinct from FromZone/ToZone (the matched policy's
		// declared scope), which can differ for a wildcard-zone or global match.
		QueriedFromZone: fromZone,
		QueriedToZone:   toZone,
		// #3623: set the pointer only on a match (the two early returns above
		// leave it nil), so a matched first policy (id 0) is emitted as
		// "policy_id":0 rather than dropped and mistaken for no match.
		PolicyID: &matchedID,
		// #3668: the stable rule identity (inventory join key) + the
		// address-exclusion flags so a positive verdict against a
		// source/destination-address-excluded rule does not read backwards.
		RuleID: res.RuleID,
		// #3685 M05: carry the matched policy's description (ticket / change
		// context) so the match verdict is not weaker than the inventory /
		// local CLI answers over the same policymatch.Result.
		Description: res.Description,
		// #3685 M06: name the scheduler time-gate and confirm it is currently
		// admitting the rule. A positive match here is by construction active
		// (inactiveFn above already skipped a scheduler-inactive rule, #3414),
		// so SchedulerActive tracks whether the matched rule is scheduler-gated
		// at all — true only for a scheduled policy, omitted for an always-on
		// one.
		SchedulerName:              res.SchedulerName,
		SchedulerActive:            res.SchedulerName != "",
		Action:                     res.DisplayAction(),
		SrcAddresses:               res.SrcAddresses,
		DstAddresses:               res.DstAddresses,
		SourceAddressExcluded:      res.SourceAddressExcluded,
		DestinationAddressExcluded: res.DestinationAddressExcluded,
		Applications:               res.Applications,
	})
}

func policyActionStr(a config.PolicyAction) string {
	switch a {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyDeny:
		return "deny"
	case config.PolicyReject:
		return "reject"
	default:
		return "unknown"
	}
}

// screenChecks delegates to config.ScreenChecks, the single source of truth
// shared with gRPC (#3327). A nil profile (reachable on the tolerant / HA-sync
// config path the runtime walker pkg/dataplane/userspace/screens.go skips)
// renders as "no checks" rather than panicking on p.TCP.SynFlood (#3476).
func screenChecks(p *config.ScreenProfile) []string {
	return config.ScreenChecks(p)
}
