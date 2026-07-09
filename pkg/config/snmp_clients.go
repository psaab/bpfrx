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
//
// #4711: the `clients` prefixes are parsed ONCE at config-compile time into
// clientNets (a []compiledSNMPClient) rather than re-parsed on every incoming
// v2c packet. AllowsSource then does an allocation-free longest-prefix match
// over the precomputed *net.IPNet set. compileClientNets runs during compilation
// (compiler_system.go), before the config is published to the SNMP agent, so the
// cache is set with no concurrent readers; AllowsSource never mutates it.

// compiledSNMPClient is a `clients` allowlist entry with its prefix already
// parsed into a *net.IPNet (#4711). ones is the prefix length (net.IPMask
// Size), cached so the longest-prefix comparison in AllowsSource needs no
// per-packet Mask.Size() call. restrict mirrors SNMPClient.Restrict.
type compiledSNMPClient struct {
	net      *net.IPNet
	ones     int
	restrict bool
}

// compileClientNets pre-parses a `clients` allowlist into the allocation-free
// match set consumed by AllowsSource (#4711). An unparseable prefix is skipped
// (inert), exactly as the former per-call parse skipped it — never a silent
// allow-all. Returns nil for an empty allowlist; a non-empty allowlist whose
// entries are all unparseable yields a non-nil empty slice, so a populated but
// fully-inert list still default-denies (and is distinguishable from "not yet
// compiled").
func compileClientNets(clients []SNMPClient) []compiledSNMPClient {
	if len(clients) == 0 {
		return nil
	}
	out := make([]compiledSNMPClient, 0, len(clients))
	for _, cl := range clients {
		_, ipnet, err := parseClientPrefix(cl.Prefix)
		if err != nil || ipnet == nil {
			continue // an unparseable prefix is inert, never a silent allow-all
		}
		ones, _ := ipnet.Mask.Size()
		out = append(out, compiledSNMPClient{net: ipnet, ones: ones, restrict: cl.Restrict})
	}
	return out
}

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
//
// #4711: the match runs against clientNets, the prefixes parsed once at compile
// time. A community built directly (e.g. a unit test) that never went through
// the compiler has a nil clientNets; AllowsSource then parses on the fly for the
// same decision — this reads only local state, so it stays race-free under
// concurrent serving, and the real serving path always has clientNets populated.
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
	nets := c.clientNets
	if nets == nil {
		// Not compiled (directly-constructed community) — parse on the fly.
		// Same decision, just not the precomputed fast path.
		nets = compileClientNets(c.Clients)
	}
	bestBits := -1
	bestAllow := false
	for _, cn := range nets {
		if !cn.net.Contains(srcIP) {
			continue
		}
		if cn.ones > bestBits {
			bestBits = cn.ones
			bestAllow = !cn.restrict
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
