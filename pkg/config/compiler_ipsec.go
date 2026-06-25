package config

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// parseDHGroup converts a Junos/vSRX dh-group value to its numeric
// Diffie-Hellman group. It accepts both the prefixed Junos spelling
// ("group14", "group19") and a bare number ("14"). TrimPrefix leaves a
// bare number unchanged, so a single Atoi handles both forms. The ok
// return is false when the value does not parse, leaving the caller's
// DHGroup at its zero value.
//
// This is the single source of truth for dh-group parsing across the
// Phase 1 IKE proposal, the Phase 2 ESP proposal, and the PFS keys
// stanza so the three sites cannot drift (#2639: the Phase 2 site used a
// bare strconv.Atoi and silently dropped "group14", leaving the ESP
// proposal with no PFS group).
func parseDHGroup(v string) (int, bool) {
	g := strings.TrimPrefix(v, "group")
	if n, err := strconv.Atoi(g); err == nil {
		return n, true
	}
	return 0, false
}

func compileIKE(node *Node, sec *SecurityConfig) error {
	if sec.IPsec.IKEProposals == nil {
		sec.IPsec.IKEProposals = make(map[string]*IKEProposal)
	}
	if sec.IPsec.IKEPolicies == nil {
		sec.IPsec.IKEPolicies = make(map[string]*IKEPolicy)
	}
	if sec.IPsec.Gateways == nil {
		sec.IPsec.Gateways = make(map[string]*IPsecGateway)
	}

	// IKE proposals (Phase 1 crypto)
	for _, inst := range namedInstances(node.FindChildren("proposal")) {
		prop := &IKEProposal{Name: inst.name}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "authentication-method":
				prop.AuthMethod = v
			case "encryption-algorithm":
				prop.EncryptionAlg = v
			case "authentication-algorithm":
				prop.AuthAlg = v
			case "dh-group":
				// Handle "group2" or "2" format
				if n, ok := parseDHGroup(v); ok {
					prop.DHGroup = n
				}
			case "lifetime-seconds":
				if n, err := strconv.Atoi(v); err == nil {
					prop.LifetimeSeconds = n
				}
			}
		}
		sec.IPsec.IKEProposals[prop.Name] = prop
	}

	// IKE policies (Phase 1 mode + PSK + proposal ref)
	for _, inst := range namedInstances(node.FindChildren("policy")) {
		pol := &IKEPolicy{Name: inst.name}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "mode":
				pol.Mode = v
			case "proposals":
				pol.Proposals = v
			case "pre-shared-key":
				// "pre-shared-key ascii-text VALUE" or children
				if len(p.Keys) >= 3 {
					pol.PSK = Secret(p.Keys[2])
				} else {
					for _, c := range p.Children {
						if c.Name() == "ascii-text" {
							pol.PSK = Secret(nodeVal(c))
						}
					}
				}
			}
		}
		sec.IPsec.IKEPolicies[pol.Name] = pol
	}

	// IKE gateways
	for _, inst := range namedInstances(node.FindChildren("gateway")) {
		gw := sec.IPsec.Gateways[inst.name]
		if gw == nil {
			gw = &IPsecGateway{Name: inst.name}
		}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "address":
				if v != "" {
					gw.Address = v
				}
			case "local-address":
				if v != "" {
					gw.LocalAddress = v
				}
			case "ike-policy":
				if v != "" {
					gw.IKEPolicy = v
				}
			case "external-interface":
				if v != "" {
					gw.ExternalIface = v
				}
			case "local-certificate":
				if v != "" {
					gw.LocalCertificate = v
				}
			case "version":
				if v != "" {
					gw.Version = v
				}
			case "no-nat-traversal":
				gw.NoNATTraversal = true
				gw.NATTraversal = "disable"
			case "nat-traversal":
				if v != "" {
					gw.NATTraversal = v
				}
				if v == "disable" {
					gw.NoNATTraversal = true
				}
			case "dead-peer-detection":
				parseDeadPeerDetectionNode(p, gw)
			case "local-identity":
				if len(p.Keys) >= 3 {
					gw.LocalIDType = p.Keys[1]
					gw.LocalIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.LocalIDType = c.Name()
						gw.LocalIDValue = nodeVal(c)
					}
				}
			case "remote-identity":
				if len(p.Keys) >= 3 {
					gw.RemoteIDType = p.Keys[1]
					gw.RemoteIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.RemoteIDType = c.Name()
						gw.RemoteIDValue = nodeVal(c)
					}
				}
			case "dynamic":
				// "dynamic hostname FQDN" or children. A `dynamic` block
				// with no hostname marks a responder-only / dynamic-IP peer
				// (remote_addrs = %any) — see the IPsec-stanza copy below
				// and resolveRemoteAddr (#2404).
				if len(p.Keys) >= 3 && p.Keys[1] == "hostname" {
					gw.DynamicHostname = p.Keys[2]
				} else {
					for _, c := range p.Children {
						if c.Name() == "hostname" && len(c.Keys) >= 2 {
							gw.DynamicHostname = c.Keys[1]
						}
					}
				}
				if gw.DynamicHostname == "" {
					gw.ResponderOnly = true
				}
			}
		}
		sec.IPsec.Gateways[gw.Name] = gw
	}

	return nil
}

func parseDeadPeerDetectionNode(node *Node, gw *IPsecGateway) {
	if gw == nil || node == nil {
		return
	}

	if v := nodeVal(node); v != "" {
		gw.DeadPeerDetect = v
	}

	for _, c := range node.Children {
		switch c.Name() {
		case "always-send", "optimized", "probe-idle-tunnel":
			gw.DeadPeerDetect = c.Name()
		case "interval":
			if n, err := strconv.Atoi(nodeVal(c)); err == nil {
				gw.DPDInterval = n
			}
		case "threshold":
			if n, err := strconv.Atoi(nodeVal(c)); err == nil {
				gw.DPDThreshold = n
			}
		}
	}

	if gw.DeadPeerDetect == "" && (len(node.Children) > 0 || len(node.Keys) > 1) {
		gw.DeadPeerDetect = "always-send"
	}
}

func compileIPsec(node *Node, sec *SecurityConfig) error {
	if sec.IPsec.Proposals == nil {
		sec.IPsec.Proposals = make(map[string]*IPsecProposal)
	}
	if sec.IPsec.Policies == nil {
		sec.IPsec.Policies = make(map[string]*IPsecPolicyDef)
	}
	if sec.IPsec.VPNs == nil {
		sec.IPsec.VPNs = make(map[string]*IPsecVPN)
	}

	// IPsec proposals (Phase 2 crypto)
	for _, inst := range namedInstances(node.FindChildren("proposal")) {
		prop := &IPsecProposal{Name: inst.name}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "protocol":
				prop.Protocol = v
			case "encryption-algorithm":
				prop.EncryptionAlg = v
			case "authentication-algorithm":
				prop.AuthAlg = v
			case "dh-group":
				// Handle "group14" or "14" format (#2639): the bare
				// strconv.Atoi here dropped the Junos "group14" spelling,
				// silently disabling PFS on the ESP/Phase-2 proposal.
				if n, ok := parseDHGroup(v); ok {
					prop.DHGroup = n
				}
			case "lifetime-seconds":
				if n, err := strconv.Atoi(v); err == nil {
					prop.LifetimeSeconds = n
				}
			}
		}
		sec.IPsec.Proposals[prop.Name] = prop
	}

	// IPsec policies (PFS + proposal reference)
	for _, inst := range namedInstances(node.FindChildren("policy")) {
		pol := &IPsecPolicyDef{Name: inst.name}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "proposals":
				pol.Proposals = v
			case "perfect-forward-secrecy":
				for _, c := range p.Children {
					if c.Name() == "keys" {
						if n, ok := parseDHGroup(nodeVal(c)); ok {
							pol.PFSGroup = n
						}
					}
				}
			}
		}
		sec.IPsec.Policies[pol.Name] = pol
	}

	// Gateways (may appear under ipsec or ike)
	if sec.IPsec.Gateways == nil {
		sec.IPsec.Gateways = make(map[string]*IPsecGateway)
	}
	for _, inst := range namedInstances(node.FindChildren("gateway")) {
		gw := sec.IPsec.Gateways[inst.name]
		if gw == nil {
			gw = &IPsecGateway{Name: inst.name}
		}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "address":
				if v != "" {
					gw.Address = v
				}
			case "local-address":
				if v != "" {
					gw.LocalAddress = v
				}
			case "ike-policy":
				if v != "" {
					gw.IKEPolicy = v
				}
			case "external-interface":
				if v != "" {
					gw.ExternalIface = v
				}
			case "local-certificate":
				if v != "" {
					gw.LocalCertificate = v
				}
			case "version":
				if v != "" {
					gw.Version = v
				}
			case "no-nat-traversal":
				gw.NoNATTraversal = true
				gw.NATTraversal = "disable"
			case "nat-traversal":
				if v != "" {
					gw.NATTraversal = v
				}
				if v == "disable" {
					gw.NoNATTraversal = true
				}
			case "dead-peer-detection":
				parseDeadPeerDetectionNode(p, gw)
			case "local-identity":
				if len(p.Keys) >= 3 {
					gw.LocalIDType = p.Keys[1]
					gw.LocalIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.LocalIDType = c.Name()
						gw.LocalIDValue = nodeVal(c)
					}
				}
			case "remote-identity":
				if len(p.Keys) >= 3 {
					gw.RemoteIDType = p.Keys[1]
					gw.RemoteIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.RemoteIDType = c.Name()
						gw.RemoteIDValue = nodeVal(c)
					}
				}
			case "dynamic":
				// A `dynamic` block with no hostname marks a responder-only
				// / dynamic-IP peer: the peer initiates from an unknown
				// address, so the gateway carries no remote_addrs target and
				// renders remote_addrs = %any (#2404).
				if len(p.Keys) >= 3 && p.Keys[1] == "hostname" {
					gw.DynamicHostname = p.Keys[2]
				} else {
					for _, c := range p.Children {
						if c.Name() == "hostname" {
							gw.DynamicHostname = nodeVal(c)
						}
					}
				}
				if gw.DynamicHostname == "" {
					gw.ResponderOnly = true
				}
			}
		}
		sec.IPsec.Gateways[gw.Name] = gw
	}

	// VPN tunnels
	for _, inst := range namedInstances(node.FindChildren("vpn")) {
		vpn := &IPsecVPN{Name: inst.name}
		for _, p := range inst.node.Children {
			v := nodeVal(p)
			switch p.Name() {
			case "bind-interface":
				vpn.BindInterface = v
			case "df-bit":
				vpn.DFBit = v
			case "establish-tunnels":
				vpn.EstablishTunnels = v
			case "ike":
				// Nested ike { gateway X; ipsec-policy Y; }
				for _, c := range p.Children {
					cv := nodeVal(c)
					switch c.Name() {
					case "gateway":
						vpn.Gateway = cv
					case "ipsec-policy":
						vpn.IPsecPolicy = cv
					}
				}
			case "gateway":
				vpn.Gateway = v
			case "ipsec-policy":
				vpn.IPsecPolicy = v
			case "local-identity":
				vpn.LocalID = v
			case "remote-identity":
				vpn.RemoteID = v
			case "pre-shared-key":
				vpn.PSK = Secret(v)
			case "local-address":
				vpn.LocalAddr = v
			}
		}
		for _, tsInst := range namedInstances(inst.node.FindChildren("traffic-selector")) {
			if vpn.TrafficSelectors == nil {
				vpn.TrafficSelectors = make(map[string]*IPsecTrafficSelector)
			}
			ts := &IPsecTrafficSelector{Name: tsInst.name}
			for _, p := range tsInst.node.Children {
				switch p.Name() {
				case "local-ip":
					ts.LocalIP = nodeVal(p)
				case "remote-ip":
					ts.RemoteIP = nodeVal(p)
				}
			}
			vpn.TrafficSelectors[ts.Name] = ts
		}
		sec.IPsec.VPNs[vpn.Name] = vpn
	}

	return nil
}

// validateIPsecGatewayReferencesStrict (#2074) rejects an IPsec VPN that
// references an IKE gateway which is neither a defined gateway object
// (carrying an address or dynamic hostname) nor a usable inline
// IP/hostname. Without this check, renderConfig would emit
// `remote_addrs = <gateway-name>` — a config-object name strongSwan
// cannot use — producing a silently-dead tunnel with no diagnostic.
//
// It runs on the fully-compiled *Config (the strict-validator chain in
// compileExpanded), so both `ike { gateway }` and `ipsec { gateway }`
// definitions are present in sec.IPsec.Gateways regardless of which
// stanza was authored first. The caller downgrades this to a warning on
// the tolerant load / peer-sync paths (lenientIPsecGatewayRefs) so a
// config persisted by an older binary, or synced from a peer, still
// boots; commit / commit-check stay strict.
//
// VPN names are sorted so a multi-VPN config reports a deterministic
// first failure.
func validateIPsecGatewayReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ipsec := &cfg.Security.IPsec
	if len(ipsec.VPNs) == 0 {
		return nil
	}
	names := make([]string, 0, len(ipsec.VPNs))
	for name := range ipsec.VPNs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		vpn := ipsec.VPNs[name]
		if vpn == nil || vpn.Gateway == "" {
			// A VPN may legitimately omit the remote endpoint (the
			// generated connection simply has no remote_addrs line).
			continue
		}
		if gw, ok := ipsec.Gateways[vpn.Gateway]; ok {
			if gw.Address == "" && gw.DynamicHostname == "" && !gw.ResponderOnly {
				return fmt.Errorf("security ipsec vpn %s: ike gateway %q "+
					"has no address or dynamic hostname; the tunnel would "+
					"never establish", name, vpn.Gateway)
			}
			// A responder-only gateway (dynamic block, no address/hostname)
			// legitimately omits remote_addrs and renders %any (#2404).
			continue // resolves to a defined, addressed (or responder-only) gateway
		}
		if IsUsableIPsecEndpoint(vpn.Gateway) {
			continue // legacy inline literal IP / dotted hostname
		}
		return fmt.Errorf("security ipsec vpn %s: ike gateway %q is not "+
			"defined and is not a valid address or hostname", name, vpn.Gateway)
	}
	return nil
}

// IsUsableIPsecEndpoint reports whether s is something strongSwan can
// place in a swanctl `remote_addrs` directly: a literal IP address, or a
// plausible dotted DNS hostname / FQDN. It deliberately REJECTS a bare
// config-object name with no hostname structure (e.g. a typo'd gateway
// reference such as `gw-to-hq`), so such a name is caught at commit
// rather than DNS-probed forever at runtime (#2074).
//
// It lives in pkg/config so that both the commit-time validator
// (validateIPsecGatewayReferencesStrict, pkg/config) and the swanctl
// render belt (pkg/ipsec, which imports pkg/config) share one predicate
// with no import cycle.
func IsUsableIPsecEndpoint(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	return isPlausibleHostname(s)
}

// isPlausibleHostname reports whether s looks like a multi-label DNS
// hostname / FQDN: it must contain at least one dot (Rule A — this is
// what distinguishes an operator-supplied peer hostname from a typo'd
// single-label gateway object name), and every dot-separated label must
// be a syntactically valid host label (1-63 chars, alphanumeric with
// internal hyphens, no leading/trailing hyphen). Total length is capped
// at 253. A single trailing dot is accepted as the absolute-root marker
// of a fully qualified domain name ("vpn.example.com." — Junos accepts
// it); "..", a leading/interior empty label, and a bare "." are still
// rejected. No regexp — a manual byte scan keeps it allocation-free.
//
// The single-label-hostname limitation (a bare `vpnpeer` resolvable via
// the system resolver is rejected) is intentional and documented: define
// a proper `security ike gateway <name> { address <ip>; }` (or
// `dynamic { hostname <fqdn>; }`) instead.
func isPlausibleHostname(s string) bool {
	if len(s) == 0 {
		return false
	}
	// A single trailing dot is the absolute-root marker of a fully
	// qualified domain name (e.g. "vpn.example.com."); Junos accepts it.
	// Strip exactly one terminal dot so the label scan below treats it as
	// a valid absolute FQDN rather than a name with an empty last label.
	// A name that is only dots ("."), ends in ".." (empty last label), or
	// has a leading/interior empty label is NOT made valid by this: after
	// stripping one trailing dot the scan still rejects "", a trailing
	// dot, or any "..".
	//
	// The strip MUST precede the 253-octet presentation cap: RFC 1035 §3.1
	// counts only the labels (max 253 chars), and the absolute-root dot
	// does not consume part of that budget. A maximal 253-char FQDN written
	// in absolute form is 254 bytes including the trailing "." and is valid
	// (#2596) — capping the raw byte length first wrongly rejected it.
	if strings.HasSuffix(s, ".") {
		s = s[:len(s)-1]
		if len(s) == 0 {
			return false // name was just "."
		}
	}
	if len(s) > 253 {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	labelLen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if labelLen == 0 {
				return false // empty label (leading dot or "..")
			}
			if s[i-1] == '-' {
				return false // label ends with hyphen
			}
			labelLen = 0
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			labelLen++
		case c == '-':
			if labelLen == 0 {
				return false // label begins with hyphen
			}
			labelLen++
		default:
			return false // illegal character for a hostname
		}
		if labelLen > 63 {
			return false
		}
	}
	// Trailing label must be non-empty and not end with a hyphen.
	if labelLen == 0 {
		return false // trailing dot => empty last label
	}
	if s[len(s)-1] == '-' {
		return false
	}
	return true
}
