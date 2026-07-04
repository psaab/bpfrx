package config

// parseHostInboundNode parses a `host-inbound-traffic { system-services ...;
// protocols ...; }` subtree into a HostInboundTraffic. It is the SSOT for both
// the zone-level stanza and the per-interface override (#3362) so the two parse
// identically. A present-but-empty stanza returns a non-nil empty struct
// (preserving the historical zone-level behaviour where an empty stanza means
// "the operator opened nothing" → host-inbound enforcing, deny-all). A nil node
// (no stanza) returns nil.
func parseHostInboundNode(n *Node) *HostInboundTraffic {
	if n == nil {
		return nil
	}
	hib := &HostInboundTraffic{}
	for _, hit := range n.Children {
		switch hit.Name() {
		case "system-services":
			// #3703: system-services is a multi-value value-tail leaf. A
			// bracket / single-line / repeated list carries values as the
			// leaf's Keys[1:] AND/OR one-per-child; read BOTH via the
			// firewallMatchValues SSOT so every token reaches the compiled
			// slice (reading only child.Name()/Keys[0] dropped all but the
			// first list value — the #2419 collapse bug). The compiled slice
			// is then token-validated by validateHostInboundTokensStrict.
			hib.SystemServices = append(hib.SystemServices, firewallMatchValues(hit)...)
		case "protocols":
			hib.Protocols = append(hib.Protocols, firewallMatchValues(hit)...)
		}
	}
	return hib
}

func compileZones(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("security-zone")) {
		zone := &ZoneConfig{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "interfaces":
				for _, iface := range prop.Children {
					zone.Interfaces = append(zone.Interfaces, iface.Name())
					// #3362: per-interface host-inbound-traffic override
					// (`interfaces <if> host-inbound-traffic { ... }`). Same
					// token grammar as the zone-level stanza; parsed by the
					// shared parseHostInboundNode so both shapes stay in lockstep.
					if hib := parseHostInboundNode(iface.FindChild("host-inbound-traffic")); hib != nil {
						if zone.InterfaceHostInbound == nil {
							zone.InterfaceHostInbound = make(map[string]*HostInboundTraffic)
						}
						zone.InterfaceHostInbound[iface.Name()] = hib
					}
				}
			case "screen":
				zone.ScreenProfile = nodeVal(prop)
			case "host-inbound-traffic":
				zone.HostInboundTraffic = parseHostInboundNode(prop)
			case "tcp-rst":
				zone.TCPRst = true
			case "description":
				zone.Description = nodeVal(prop)
			case "address-book":
				// #3061: zone-local address book. Same entry grammar as the
				// global book; resolved into the global book under
				// zone-qualified internal names later (resolveZoneLocalAddressBooks).
				ab := &AddressBook{
					Addresses:   make(map[string]*Address),
					AddressSets: make(map[string]*AddressSet),
				}
				parseAddressBookEntries(prop, ab)
				zone.AddressBook = ab
			}
		}

		sec.Zones[inst.name] = zone
	}
	return nil
}
