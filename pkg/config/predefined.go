package config

import "fmt"

// PredefinedApplications contains built-in Junos application definitions.
var PredefinedApplications = map[string]*Application{
	"junos-ftp":         {Name: "junos-ftp", Protocol: "tcp", DestinationPort: "21"},
	"junos-ssh":         {Name: "junos-ssh", Protocol: "tcp", DestinationPort: "22"},
	"junos-telnet":      {Name: "junos-telnet", Protocol: "tcp", DestinationPort: "23"},
	"junos-smtp":        {Name: "junos-smtp", Protocol: "tcp", DestinationPort: "25"},
	"junos-dns-udp":     {Name: "junos-dns-udp", Protocol: "udp", DestinationPort: "53"},
	"junos-dns-tcp":     {Name: "junos-dns-tcp", Protocol: "tcp", DestinationPort: "53"},
	"junos-dhcp-client": {Name: "junos-dhcp-client", Protocol: "udp", DestinationPort: "68"},
	"junos-dhcp-server": {Name: "junos-dhcp-server", Protocol: "udp", DestinationPort: "67"},
	"junos-tftp":        {Name: "junos-tftp", Protocol: "udp", DestinationPort: "69"},
	"junos-http":        {Name: "junos-http", Protocol: "tcp", DestinationPort: "80"},
	"junos-pop3":        {Name: "junos-pop3", Protocol: "tcp", DestinationPort: "110"},
	"junos-ntp":         {Name: "junos-ntp", Protocol: "udp", DestinationPort: "123"},
	"junos-imap":        {Name: "junos-imap", Protocol: "tcp", DestinationPort: "143"},
	"junos-bgp":         {Name: "junos-bgp", Protocol: "tcp", DestinationPort: "179"},
	"junos-ldap":        {Name: "junos-ldap", Protocol: "tcp", DestinationPort: "389"},
	"junos-https":       {Name: "junos-https", Protocol: "tcp", DestinationPort: "443"},
	"junos-smb":         {Name: "junos-smb", Protocol: "tcp", DestinationPort: "445"},
	"junos-ike":         {Name: "junos-ike", Protocol: "udp", DestinationPort: "500"},
	"junos-syslog":      {Name: "junos-syslog", Protocol: "udp", DestinationPort: "514"},
	"junos-rip":         {Name: "junos-rip", Protocol: "udp", DestinationPort: "520"},
	"junos-rtsp":        {Name: "junos-rtsp", Protocol: "tcp", DestinationPort: "554"},
	"junos-imaps":       {Name: "junos-imaps", Protocol: "tcp", DestinationPort: "993"},
	"junos-radius":      {Name: "junos-radius", Protocol: "udp", DestinationPort: "1812"},
	"junos-radacct":     {Name: "junos-radacct", Protocol: "udp", DestinationPort: "1813"},
	"junos-snmp":        {Name: "junos-snmp", Protocol: "udp", DestinationPort: "161"},
	"junos-ping":        {Name: "junos-ping", Protocol: "icmp", DestinationPort: ""},
	"junos-pingv6":      {Name: "junos-pingv6", Protocol: "icmpv6", DestinationPort: ""},
	"junos-traceroute":  {Name: "junos-traceroute", Protocol: "udp", DestinationPort: "33434-33523"},
}

// ResolveApplication looks up an application by name, checking user-defined
// applications first, then predefined.
func ResolveApplication(name string, userApps map[string]*Application) (*Application, bool) {
	if userApps != nil {
		if app, ok := userApps[name]; ok {
			return app, true
		}
	}
	if app, ok := PredefinedApplications[name]; ok {
		return app, true
	}
	return nil, false
}

// ResolveApplicationSet looks up an application-set by name.
func ResolveApplicationSet(name string, appSets map[string]*ApplicationSet) (*ApplicationSet, bool) {
	if appSets != nil {
		if as, ok := appSets[name]; ok {
			return as, true
		}
	}
	return nil, false
}

// ExpandApplicationSet recursively expands an application-set to individual
// application names. Returns an error if a member is not found. Max depth 3.
func ExpandApplicationSet(name string, apps *ApplicationsConfig) ([]string, error) {
	return expandAppSet(name, apps, 0)
}

func expandAppSet(name string, apps *ApplicationsConfig, depth int) ([]string, error) {
	if depth > 3 {
		return nil, fmt.Errorf("application-set nesting too deep (max 3): %s", name)
	}

	as, ok := apps.ApplicationSets[name]
	if !ok {
		return nil, fmt.Errorf("application-set %q not found", name)
	}

	var result []string
	seen := make(map[string]bool)

	for _, memberName := range as.Applications {
		// Check if it's another application-set (recurse)
		if _, isSet := apps.ApplicationSets[memberName]; isSet {
			expanded, err := expandAppSet(memberName, apps, depth+1)
			if err != nil {
				return nil, err
			}
			for _, a := range expanded {
				if !seen[a] {
					seen[a] = true
					result = append(result, a)
				}
			}
			continue
		}

		// Must be an individual application
		if _, found := ResolveApplication(memberName, apps.Applications); !found {
			return nil, fmt.Errorf("application-set %q: member %q not found", name, memberName)
		}
		if !seen[memberName] {
			seen[memberName] = true
			result = append(result, memberName)
		}
	}

	return result, nil
}
