package config

import (
	"strconv"
	"strings"
)

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
				g := strings.TrimPrefix(v, "group")
				if n, err := strconv.Atoi(g); err == nil {
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
					pol.PSK = p.Keys[2]
				} else {
					for _, c := range p.Children {
						if c.Name() == "ascii-text" {
							pol.PSK = nodeVal(c)
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
				// "dynamic hostname FQDN" or children
				if len(p.Keys) >= 3 && p.Keys[1] == "hostname" {
					gw.DynamicHostname = p.Keys[2]
				} else {
					for _, c := range p.Children {
						if c.Name() == "hostname" && len(c.Keys) >= 2 {
							gw.DynamicHostname = c.Keys[1]
						}
					}
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
				if n, err := strconv.Atoi(v); err == nil {
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
						g := strings.TrimPrefix(nodeVal(c), "group")
						if n, err := strconv.Atoi(g); err == nil {
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
				if len(p.Keys) >= 3 && p.Keys[1] == "hostname" {
					gw.DynamicHostname = p.Keys[2]
				} else {
					for _, c := range p.Children {
						if c.Name() == "hostname" {
							gw.DynamicHostname = nodeVal(c)
						}
					}
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
				vpn.PSK = v
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
