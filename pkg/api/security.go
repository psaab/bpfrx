package api

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"

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
	var zones []ZoneInfo
	for zoneName, zone := range cfg.Security.Zones {
		zi := ZoneInfo{
			Name:       zoneName,
			Interfaces: zone.Interfaces,
		}
		if zone.ScreenProfile != "" {
			zi.ScreenProfile = zone.ScreenProfile
		}

		// Host-inbound services
		if zone.HostInboundTraffic != nil {
			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.SystemServices...)
			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.Protocols...)
		}
		if zi.HostInbound == nil {
			zi.HostInbound = []string{}
		}
		if zi.Interfaces == nil {
			zi.Interfaces = []string{}
		}

		// Zone ID + counters
		if cr != nil {
			if id, ok := cr.ZoneIDs[zoneName]; ok {
				zi.ID = id
				if s.dp != nil && s.dp.IsLoaded() {
					if ing, err := s.dp.ReadZoneCounters(id, 0); err == nil {
						zi.IngressPackets = ing.Packets
						zi.IngressBytes = ing.Bytes
					}
					if eg, err := s.dp.ReadZoneCounters(id, 1); err == nil {
						zi.EgressPackets = eg.Packets
						zi.EgressBytes = eg.Bytes
					}
				}
			}
		}
		zones = append(zones, zi)
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
	var policySetID uint32
	var result []PolicyInfo
	for _, zpp := range cfg.Security.Policies {
		pi := PolicyInfo{
			FromZone: zpp.FromZone,
			ToZone:   zpp.ToZone,
		}
		for _, rule := range zpp.Policies {
			pr := PolicyRule{
				Name:         rule.Name,
				Action:       policyActionStr(rule.Action),
				SrcAddresses: rule.Match.SourceAddresses,
				DstAddresses: rule.Match.DestinationAddresses,
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
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
				policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(len(pi.Rules))
				if ctrs, err := s.dp.ReadPolicyCounters(policyID); err == nil {
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
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
				Name:         rule.Name,
				Action:       policyActionStr(rule.Action),
				SrcAddresses: rule.Match.SourceAddresses,
				DstAddresses: rule.Match.DestinationAddresses,
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
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
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []PolicyRule{}
		}
		result = append(result, pi)
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

	zone, ok := queryUint16Strict(r, "zone", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid zone filter: "+r.URL.Query().Get("zone"))
		return
	}
	filter := logging.EventFilter{
		Zone:     zone,
		Action:   r.URL.Query().Get("action"),
		Protocol: r.URL.Query().Get("protocol"),
	}

	var events []logging.EventRecord
	if filter.IsEmpty() {
		events = s.eventBuf.Latest(limit)
	} else {
		events = s.eventBuf.LatestFiltered(limit, filter)
	}

	result := make([]EventEntry, len(events))
	for i, ev := range events {
		result[i] = EventEntry{
			Time:         ev.Time.Format(time.RFC3339),
			Type:         ev.Type,
			SrcAddr:      ev.SrcAddr,
			DstAddr:      ev.DstAddr,
			Protocol:     ev.Protocol,
			Action:       ev.Action,
			PolicyID:     ev.PolicyID,
			InZone:       ev.InZone,
			OutZone:      ev.OutZone,
			ScreenCheck:  ev.ScreenCheck,
			SessionPkts:  ev.SessionPkts,
			SessionBytes: ev.SessionBytes,
		}
	}
	writeOK(w, result)
}

func (s *Server) matchPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, MatchPoliciesResult{Action: "deny (default)"})
		return
	}

	fromZone := r.URL.Query().Get("from_zone")
	toZone := r.URL.Query().Get("to_zone")

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
	// When the daemon has not wired the accessor or state is unavailable, the
	// closure stays nil and scheduled policies are simulated as-if-active.
	var inactiveFn func(string) bool
	if s.policySchedActiveFn != nil {
		if state, ok := s.policySchedActiveFn(); ok {
			inactiveFn = dpuserspace.PolicyInactiveFn(state)
		}
	}
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
			Action:               "host-inbound (local delivery; not governed by transit/global/default policy)",
		})
		return
	}
	if !res.Matched {
		writeOK(w, MatchPoliciesResult{Action: policymatch.ActionString(res.Action) + " (default)"})
		return
	}
	writeOK(w, MatchPoliciesResult{
		Matched:      true,
		PolicyName:   res.PolicyName,
		Action:       policymatch.ActionString(res.Action),
		SrcAddresses: res.SrcAddresses,
		DstAddresses: res.DstAddresses,
		Applications: res.Applications,
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

func screenChecks(p *config.ScreenProfile) []string {
	var checks []string
	if p.TCP.SynFlood != nil {
		checks = append(checks, "syn-flood")
	}
	if p.TCP.Land {
		checks = append(checks, "land")
	}
	if p.TCP.WinNuke {
		checks = append(checks, "winnuke")
	}
	if p.TCP.SynFrag {
		checks = append(checks, "syn-frag")
	}
	if p.TCP.SynFin {
		checks = append(checks, "syn-fin")
	}
	if p.TCP.NoFlag {
		checks = append(checks, "tcp-no-flag")
	}
	if p.TCP.FinNoAck {
		checks = append(checks, "fin-no-ack")
	}
	if p.ICMP.PingDeath {
		checks = append(checks, "ping-death")
	}
	if p.ICMP.FloodThreshold > 0 {
		checks = append(checks, "icmp-flood")
	}
	if p.UDP.FloodThreshold > 0 {
		checks = append(checks, "udp-flood")
	}
	if p.IP.SourceRouteOption {
		checks = append(checks, "source-route-option")
	}
	if p.IP.TearDrop {
		checks = append(checks, "tear-drop")
	}
	return checks
}
