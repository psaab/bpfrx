package config

import "net"

// SNMP community `clients` source-IP restriction (#4289).
//
// Junos `snmp community <c> clients { <prefix> [restrict]; ... }` scopes a
// community so it is answered only from the listed source prefixes. xpf parsed
// only `authorization` and served every source, so a community scoped to a
// management subnet was queryable from anywhere — the restriction was silently
// ignored (a security fail-open). The compiler now captures the allowlist
// (parseSNMPClients) and the SNMP agent enforces it before serving a v2c
// request (AllowsSource).

// AllowsSource reports whether a v2c query from srcIP may be served under this
// community. Semantics (Junos):
//
//   - No `clients` configured (empty allowlist): allow all (the default).
//   - Otherwise longest-prefix match wins: the most-specific entry containing
//     srcIP decides — `restrict` denies, a plain entry allows.
//   - `clients` configured but srcIP matches no entry: deny (an allowlist that
//     lists some sources implicitly excludes the rest).
//
// A nil srcIP (e.g. a non-IP transport / test path with no address) is allowed
// so enforcement never blocks a request whose source cannot be determined; the
// real serving path always supplies the UDP source address.
func (c *SNMPCommunity) AllowsSource(srcIP net.IP) bool {
	if c == nil {
		return false
	}
	if len(c.Clients) == 0 {
		return true // no restriction — allow-all (Junos default)
	}
	if srcIP == nil {
		return true
	}
	bestBits := -1
	bestAllow := false
	for _, cl := range c.Clients {
		_, ipnet, err := parseClientPrefix(cl.Prefix)
		if err != nil || ipnet == nil {
			continue // an unparseable prefix is inert, never a silent allow-all
		}
		if !ipnet.Contains(srcIP) {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		if ones > bestBits {
			bestBits = ones
			bestAllow = !cl.Restrict
		}
	}
	if bestBits < 0 {
		return false // clients configured, no match: default-deny
	}
	return bestAllow
}

// parseClientPrefix parses a `clients` entry as either a CIDR prefix
// (10.0.0.0/24, 2001:db8::/32) or a bare address (192.168.1.5, ::1), the bare
// form treated as a host route (/32 or /128).
func parseClientPrefix(s string) (net.IP, *net.IPNet, error) {
	if ip, ipnet, err := net.ParseCIDR(s); err == nil {
		return ip, ipnet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, nil, &net.ParseError{Type: "SNMP client prefix", Text: s}
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return ip, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// parseSNMPClients extracts the `clients` allowlist from a community's `clients`
// node, across both parser AST shapes (the #2419 dual-shape class). Each entry
// is a `<prefix> [restrict]` group: a token equal to "restrict" attaches to the
// prefix immediately preceding it (modeled on firewallPrefixListRefs's
// `<name> [except]` handling).
//
//   - hierarchical block   `clients { 10.0.0.0/24; 0.0.0.0/0 restrict; }`
//     → one child node per entry (child.Keys=["10.0.0.0/24"] / ["0.0.0.0/0","restrict"])
//   - flat set / bracket   `clients 10.0.0.0/24` / `clients [ a b ]`
//     → tokens on node.Keys[1:]
func parseSNMPClients(node *Node) []SNMPClient {
	var out []SNMPClient
	appendTokens := func(tokens []string) {
		for _, t := range tokens {
			if t == "" {
				continue
			}
			if t == "restrict" {
				if len(out) > 0 {
					out[len(out)-1].Restrict = true
				}
				continue
			}
			out = append(out, SNMPClient{Prefix: t})
		}
	}
	appendTokens(node.Keys[1:])
	for _, ch := range node.Children {
		appendTokens(ch.Keys)
	}
	return out
}
