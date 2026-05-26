package api

import (
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
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

			if s.dp != nil && s.dp.IsLoaded() {
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

	filter := logging.EventFilter{
		Zone:     queryUint16(r, "zone", 0),
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
	srcIP := net.ParseIP(r.URL.Query().Get("src_ip"))
	dstIP := net.ParseIP(r.URL.Query().Get("dst_ip"))
	dstPort := queryInt(r, "dst_port", 0)
	proto := r.URL.Query().Get("protocol")

	for _, zpp := range cfg.Security.Policies {
		if zpp.FromZone != fromZone || zpp.ToZone != toZone {
			continue
		}
		for _, pol := range zpp.Policies {
			if !matchPolicyAddr(pol.Match.SourceAddresses, srcIP, cfg) {
				continue
			}
			if !matchPolicyAddr(pol.Match.DestinationAddresses, dstIP, cfg) {
				continue
			}
			if !matchPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
				continue
			}

			writeOK(w, MatchPoliciesResult{
				Matched:      true,
				PolicyName:   pol.Name,
				Action:       policyActionStr(pol.Action),
				SrcAddresses: pol.Match.SourceAddresses,
				DstAddresses: pol.Match.DestinationAddresses,
				Applications: pol.Match.Applications,
			})
			return
		}
	}

	writeOK(w, MatchPoliciesResult{Action: "deny (default)"})
}

// matchPolicyAddr checks if an IP matches any address references.
func matchPolicyAddr(addrs []string, ip net.IP, cfg *config.Config) bool {
	if len(addrs) == 0 || ip == nil {
		return true
	}
	for _, a := range addrs {
		if a == "any" {
			return true
		}
		if cfg.Security.AddressBook == nil {
			continue
		}
		if addr, ok := cfg.Security.AddressBook.Addresses[a]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
		if matchPolicyAddrSet(a, ip, cfg, 0) {
			return true
		}
	}
	return false
}

func matchPolicyAddrSet(setName string, ip net.IP, cfg *config.Config, depth int) bool {
	if depth > 5 || cfg.Security.AddressBook == nil {
		return false
	}
	as, ok := cfg.Security.AddressBook.AddressSets[setName]
	if !ok {
		return false
	}
	for _, addrName := range as.Addresses {
		if addr, ok := cfg.Security.AddressBook.Addresses[addrName]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}
	for _, nested := range as.AddressSets {
		if matchPolicyAddrSet(nested, ip, cfg, depth+1) {
			return true
		}
	}
	return false
}

// matchPolicyApp checks if a protocol/port matches application references.
func matchPolicyApp(apps []string, proto string, dstPort int, cfg *config.Config) bool {
	if len(apps) == 0 || proto == "" {
		return true
	}
	for _, a := range apps {
		if a == "any" {
			return true
		}
		if matchSingleApp(a, proto, dstPort, cfg) {
			return true
		}
		if cfg.Applications.ApplicationSets != nil {
			if as, ok := cfg.Applications.ApplicationSets[a]; ok {
				for _, appRef := range as.Applications {
					if matchSingleApp(appRef, proto, dstPort, cfg) {
						return true
					}
				}
			}
		}
	}
	return false
}

func matchSingleApp(appName, proto string, dstPort int, cfg *config.Config) bool {
	if cfg.Applications.Applications == nil {
		return false
	}
	app, ok := cfg.Applications.Applications[appName]
	if !ok {
		return false
	}
	if app.Protocol != "" && !strings.EqualFold(app.Protocol, proto) {
		return false
	}
	if app.DestinationPort != "" && dstPort > 0 {
		if strings.Contains(app.DestinationPort, "-") {
			parts := strings.SplitN(app.DestinationPort, "-", 2)
			lo, _ := strconv.Atoi(parts[0])
			hi, _ := strconv.Atoi(parts[1])
			if dstPort < lo || dstPort > hi {
				return false
			}
		} else {
			p, _ := strconv.Atoi(app.DestinationPort)
			if p != dstPort {
				return false
			}
		}
	}
	return true
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
