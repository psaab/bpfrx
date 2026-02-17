package config

import "fmt"

// PredefinedApplications contains built-in Junos application definitions.
// Based on the official Junos OS predefined application list.
var PredefinedApplications = map[string]*Application{
	// --- Basic services ---
	"junos-ftp":    {Name: "junos-ftp", Protocol: "tcp", DestinationPort: "21", ALG: "ftp"},
	"junos-ssh":    {Name: "junos-ssh", Protocol: "tcp", DestinationPort: "22"},
	"junos-telnet": {Name: "junos-telnet", Protocol: "tcp", DestinationPort: "23"},
	"junos-smtp":   {Name: "junos-smtp", Protocol: "tcp", DestinationPort: "25"},
	"junos-smtps":  {Name: "junos-smtps", Protocol: "tcp", DestinationPort: "465"},
	"junos-http":   {Name: "junos-http", Protocol: "tcp", DestinationPort: "80"},
	"junos-https":  {Name: "junos-https", Protocol: "tcp", DestinationPort: "443"},
	"junos-rtsp":   {Name: "junos-rtsp", Protocol: "tcp", DestinationPort: "554"},

	// --- DNS ---
	"junos-dns-udp": {Name: "junos-dns-udp", Protocol: "udp", DestinationPort: "53"},
	"junos-dns-tcp": {Name: "junos-dns-tcp", Protocol: "tcp", DestinationPort: "53"},

	// --- Mail ---
	"junos-pop3":  {Name: "junos-pop3", Protocol: "tcp", DestinationPort: "110"},
	"junos-imap":  {Name: "junos-imap", Protocol: "tcp", DestinationPort: "143"},
	"junos-imaps": {Name: "junos-imaps", Protocol: "tcp", DestinationPort: "993"},
	"junos-nntp":  {Name: "junos-nntp", Protocol: "tcp", DestinationPort: "119"},

	// --- DHCP & Boot ---
	"junos-dhcp-client": {Name: "junos-dhcp-client", Protocol: "udp", DestinationPort: "68"},
	"junos-dhcp-server": {Name: "junos-dhcp-server", Protocol: "udp", DestinationPort: "67"},
	"junos-bootpc":      {Name: "junos-bootpc", Protocol: "udp", DestinationPort: "68"},
	"junos-bootps":      {Name: "junos-bootps", Protocol: "udp", DestinationPort: "67"},

	// --- File transfer ---
	"junos-tftp": {Name: "junos-tftp", Protocol: "udp", DestinationPort: "69"},

	// --- Network management ---
	"junos-ntp":            {Name: "junos-ntp", Protocol: "udp", DestinationPort: "123"},
	"junos-snmp":           {Name: "junos-snmp", Protocol: "udp", DestinationPort: "161"},
	"junos-snmp-agentx":    {Name: "junos-snmp-agentx", Protocol: "tcp", DestinationPort: "705"},
	"junos-syslog":         {Name: "junos-syslog", Protocol: "udp", DestinationPort: "514"},
	"junos-xnm-ssl":       {Name: "junos-xnm-ssl", Protocol: "tcp", DestinationPort: "3220"},
	"junos-xnm-clear-text": {Name: "junos-xnm-clear-text", Protocol: "tcp", DestinationPort: "3221"},

	// --- Routing ---
	"junos-bgp":     {Name: "junos-bgp", Protocol: "tcp", DestinationPort: "179"},
	"junos-rip":     {Name: "junos-rip", Protocol: "udp", DestinationPort: "520"},
	"junos-ldp-tcp": {Name: "junos-ldp-tcp", Protocol: "tcp", DestinationPort: "646"},
	"junos-ldp-udp": {Name: "junos-ldp-udp", Protocol: "udp", DestinationPort: "646"},
	"junos-ospf":    {Name: "junos-ospf", Protocol: "89"},

	// --- Directory & authentication ---
	"junos-ldap":      {Name: "junos-ldap", Protocol: "tcp", DestinationPort: "389"},
	"junos-tacacs":    {Name: "junos-tacacs", Protocol: "tcp", DestinationPort: "49"},
	"junos-tacacs-ds": {Name: "junos-tacacs-ds", Protocol: "tcp", DestinationPort: "65"},
	"junos-radius":    {Name: "junos-radius", Protocol: "udp", DestinationPort: "1812"},
	"junos-radacct":   {Name: "junos-radacct", Protocol: "udp", DestinationPort: "1813"},

	// --- VPN & tunneling ---
	"junos-ike":     {Name: "junos-ike", Protocol: "udp", DestinationPort: "500"},
	"junos-ike-nat": {Name: "junos-ike-nat", Protocol: "udp", DestinationPort: "4500"},
	"junos-l2tp":    {Name: "junos-l2tp", Protocol: "udp", DestinationPort: "1701"},
	"junos-gre":     {Name: "junos-gre", Protocol: "gre"},
	"junos-ip-in-ip": {Name: "junos-ip-in-ip", Protocol: "4"},
	"junos-ipip":    {Name: "junos-ipip", Protocol: "4"},

	// --- Windows/SMB ---
	"junos-smb":              {Name: "junos-smb", Protocol: "tcp", DestinationPort: "445"},
	"junos-smb-session":      {Name: "junos-smb-session", Protocol: "tcp", DestinationPort: "445"},
	"junos-netbios-session":  {Name: "junos-netbios-session", Protocol: "tcp", DestinationPort: "139"},
	"junos-nbname":           {Name: "junos-nbname", Protocol: "udp", DestinationPort: "137"},
	"junos-nbds":             {Name: "junos-nbds", Protocol: "udp", DestinationPort: "138"},
	"junos-ms-sql":           {Name: "junos-ms-sql", Protocol: "tcp", DestinationPort: "1433"},
	"junos-ms-rpc-tcp":       {Name: "junos-ms-rpc-tcp", Protocol: "tcp", DestinationPort: "135"},
	"junos-ms-rpc-udp":       {Name: "junos-ms-rpc-udp", Protocol: "udp", DestinationPort: "135"},

	// --- RPC / NFS ---
	"junos-sun-rpc-tcp":  {Name: "junos-sun-rpc-tcp", Protocol: "tcp", DestinationPort: "111"},
	"junos-sun-rpc-udp":  {Name: "junos-sun-rpc-udp", Protocol: "udp", DestinationPort: "111"},
	"junos-nfsd-tcp":     {Name: "junos-nfsd-tcp", Protocol: "tcp", DestinationPort: "2049"},
	"junos-nfsd-udp":     {Name: "junos-nfsd-udp", Protocol: "udp", DestinationPort: "2049"},

	// --- Printing ---
	"junos-printer": {Name: "junos-printer", Protocol: "tcp", DestinationPort: "515"},

	// --- Database ---
	"junos-sqlnet-v1":  {Name: "junos-sqlnet-v1", Protocol: "tcp", DestinationPort: "1525"},
	"junos-sqlnet-v2":  {Name: "junos-sqlnet-v2", Protocol: "tcp", DestinationPort: "1521"},
	"junos-cvspserver": {Name: "junos-cvspserver", Protocol: "tcp", DestinationPort: "2401"},

	// --- VoIP / signaling ---
	"junos-sip":     {Name: "junos-sip", Protocol: "udp", DestinationPort: "5060"},
	"junos-mgcp-ua": {Name: "junos-mgcp-ua", Protocol: "udp", DestinationPort: "2427"},
	"junos-mgcp-ca": {Name: "junos-mgcp-ca", Protocol: "udp", DestinationPort: "2727"},
	"junos-h323":    {Name: "junos-h323", Protocol: "tcp", DestinationPort: "1720"},
	"junos-sccp":    {Name: "junos-sccp", Protocol: "tcp", DestinationPort: "2000"},

	// --- Messaging ---
	"junos-msn": {Name: "junos-msn", Protocol: "tcp", DestinationPort: "1863"},
	"junos-aol": {Name: "junos-aol", Protocol: "tcp", DestinationPort: "5190-5193"},
	"junos-irc": {Name: "junos-irc", Protocol: "tcp", DestinationPort: "6660-6669"},

	// --- Remote desktop ---
	"junos-vnc":         {Name: "junos-vnc", Protocol: "tcp", DestinationPort: "5800"},
	"junos-x-windows":   {Name: "junos-x-windows", Protocol: "tcp", DestinationPort: "6000-6063"},
	"junos-winframe":    {Name: "junos-winframe", Protocol: "tcp", DestinationPort: "1494"},
	"junos-pc-anywhere": {Name: "junos-pc-anywhere", Protocol: "udp", DestinationPort: "5632"},
	"junos-rdp":         {Name: "junos-rdp", Protocol: "tcp", DestinationPort: "3389"},

	// --- Streaming / misc ---
	"junos-vdo-live": {Name: "junos-vdo-live", Protocol: "udp", DestinationPort: "7000-7010"},
	"junos-gnutella": {Name: "junos-gnutella", Protocol: "udp", DestinationPort: "6346-6347"},
	"junos-http-ext": {Name: "junos-http-ext", Protocol: "tcp", DestinationPort: "7001"},
	"junos-gtp":      {Name: "junos-gtp", Protocol: "udp", DestinationPort: "2123"},

	// --- Lookup / info ---
	"junos-finger": {Name: "junos-finger", Protocol: "tcp", DestinationPort: "79"},
	"junos-ident":  {Name: "junos-ident", Protocol: "tcp", DestinationPort: "113"},
	"junos-whois":  {Name: "junos-whois", Protocol: "tcp", DestinationPort: "43"},
	"junos-gopher": {Name: "junos-gopher", Protocol: "tcp", DestinationPort: "70"},
	"junos-wais":   {Name: "junos-wais", Protocol: "tcp", DestinationPort: "210"},

	// --- Juniper management ---
	"junos-ns-global":     {Name: "junos-ns-global", Protocol: "tcp", DestinationPort: "15397"},
	"junos-ns-global-pro": {Name: "junos-ns-global-pro", Protocol: "tcp", DestinationPort: "15397"},

	// --- ICMP / ICMPv6 ---
	"junos-ping":         {Name: "junos-ping", Protocol: "icmp"},
	"junos-pingv6":       {Name: "junos-pingv6", Protocol: "icmpv6"},
	"junos-icmp-all":     {Name: "junos-icmp-all", Protocol: "icmp"},
	"junos-icmp6-all":    {Name: "junos-icmp6-all", Protocol: "icmpv6"},

	// --- Traceroute ---
	"junos-traceroute": {Name: "junos-traceroute", Protocol: "udp", DestinationPort: "33434-33523"},

	// --- Wildcard protocol ---
	"junos-tcp-any": {Name: "junos-tcp-any", Protocol: "tcp"},
	"junos-udp-any": {Name: "junos-udp-any", Protocol: "udp"},
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

// ExpandAddressSet recursively expands an address-set to individual
// address names. Handles nested address-sets with cycle detection.
// Max depth 5.
func ExpandAddressSet(name string, ab *AddressBook) ([]string, error) {
	return expandAddrSet(name, ab, make(map[string]bool), 0)
}

func expandAddrSet(name string, ab *AddressBook, visited map[string]bool, depth int) ([]string, error) {
	if depth > 5 {
		return nil, fmt.Errorf("address-set nesting too deep (max 5): %s", name)
	}
	if visited[name] {
		return nil, fmt.Errorf("cycle detected in address-set %q", name)
	}

	as, ok := ab.AddressSets[name]
	if !ok {
		return nil, fmt.Errorf("address-set %q not found", name)
	}

	visited[name] = true
	defer delete(visited, name)

	var result []string
	seen := make(map[string]bool)

	// Direct address members
	for _, addrName := range as.Addresses {
		if !seen[addrName] {
			seen[addrName] = true
			result = append(result, addrName)
		}
	}

	// Nested address-set members
	for _, setName := range as.AddressSets {
		expanded, err := expandAddrSet(setName, ab, visited, depth+1)
		if err != nil {
			return nil, err
		}
		for _, a := range expanded {
			if !seen[a] {
				seen[a] = true
				result = append(result, a)
			}
		}
	}

	return result, nil
}
