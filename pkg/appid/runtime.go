package appid

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

const Unknown = "UNKNOWN"

type builtinApp struct {
	proto uint8
	port  uint16
}

// Keep fallback heuristics intentionally narrow. Real AppID names should come
// from dataplane-assigned app_id values, not broad protocol-only guesses.
var builtinFallbacks = map[string]builtinApp{
	"junos-http":        {proto: 6, port: 80},
	"junos-https":       {proto: 6, port: 443},
	"junos-ssh":         {proto: 6, port: 22},
	"junos-telnet":      {proto: 6, port: 23},
	"junos-ftp":         {proto: 6, port: 21},
	"junos-smtp":        {proto: 6, port: 25},
	"junos-dns-tcp":     {proto: 6, port: 53},
	"junos-dns-udp":     {proto: 17, port: 53},
	"junos-bgp":         {proto: 6, port: 179},
	"junos-ntp":         {proto: 17, port: 123},
	"junos-snmp":        {proto: 17, port: 161},
	"junos-syslog":      {proto: 17, port: 514},
	"junos-dhcp-client": {proto: 17, port: 68},
	"junos-ike":         {proto: 17, port: 500},
	"junos-ipsec-nat-t": {proto: 17, port: 4500},
}

// CatalogNames returns the set of application names that should be compiled.
// When includeAll is true, it includes all predefined and user-defined apps so
// session tracking can identify flows even when policies do not reference them.
func CatalogNames(cfg *config.Config, includeAll bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}

	names := make(map[string]struct{})
	if includeAll {
		for name := range config.PredefinedApplications {
			names[name] = struct{}{}
		}
		for name := range cfg.Applications.Applications {
			names[name] = struct{}{}
		}
		return sortedNames(names), nil
	}

	addPolicyApps := func(policies []*config.Policy) error {
		for _, pol := range policies {
			for _, appName := range pol.Match.Applications {
				if appName == "" || appName == "any" {
					continue
				}
				if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
					expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications)
					if err != nil {
						return fmt.Errorf("expand application-set %q: %w", appName, err)
					}
					for _, expandedName := range expanded {
						names[expandedName] = struct{}{}
					}
					continue
				}
				names[appName] = struct{}{}
			}
		}
		return nil
	}

	for _, zpp := range cfg.Security.Policies {
		if err := addPolicyApps(zpp.Policies); err != nil {
			return nil, err
		}
	}
	if err := addPolicyApps(cfg.Security.GlobalPolicies); err != nil {
		return nil, err
	}

	return sortedNames(names), nil
}

// ResolveSessionName returns the session application name using the actual
// dataplane-assigned app_id when available. When AppID is enabled, unknown
// sessions are reported as UNKNOWN instead of guessed from port heuristics.
func ResolveSessionName(appNames map[uint16]string, cfg *config.Config, proto uint8, dstPort uint16, appID uint16) string {
	if appID != 0 {
		if name := appNames[appID]; name != "" {
			return name
		}
	}

	if cfg != nil && cfg.Services.ApplicationIdentification {
		if appID != 0 {
			if guess := resolveTupleFallback(proto, dstPort, cfg); guess != "" {
				return guess
			}
		}
		return Unknown
	}

	return resolveTupleFallback(proto, dstPort, cfg)
}

func SessionMatches(filter string, appNames map[uint16]string, cfg *config.Config, proto uint8, dstPort uint16, appID uint16) bool {
	if filter == "" {
		return true
	}
	return strings.EqualFold(ResolveSessionName(appNames, cfg, proto, dstPort, appID), filter)
}

func sortedNames(names map[string]struct{}) []string {
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func resolveTupleFallback(proto uint8, dstPort uint16, cfg *config.Config) string {
	if cfg != nil {
		for name, app := range cfg.Applications.Applications {
			if !matchTuple(proto, dstPort, app.Protocol, app.DestinationPort) {
				continue
			}
			return name
		}
	}
	for name, ba := range builtinFallbacks {
		if ba.proto == proto && ba.port == dstPort {
			return name
		}
	}
	return ""
}

func matchTuple(proto uint8, dstPort uint16, appProto, appPort string) bool {
	if appProto == "" {
		return false
	}
	if pn, ok := protocolNumber(appProto); !ok || pn != proto {
		return false
	}
	if appPort == "" {
		return false
	}
	if strings.Contains(appPort, "-") {
		parts := strings.SplitN(appPort, "-", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		return err1 == nil && err2 == nil && int(dstPort) >= lo && int(dstPort) <= hi
	}
	v, err := strconv.Atoi(appPort)
	return err == nil && uint16(v) == dstPort
}

func protocolNumber(proto string) (uint8, bool) {
	switch strings.ToLower(proto) {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "icmp":
		return 1, true
	case "icmpv6":
		return 58, true
	case "gre":
		return 47, true
	}
	v, err := strconv.Atoi(proto)
	if err != nil || v < 0 || v > 255 {
		return 0, false
	}
	return uint8(v), true
}
