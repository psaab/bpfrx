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

// mergeHostInbound unions the SystemServices and Protocols of src into dst,
// implementing Junos merge semantics for repeated host-inbound-traffic blocks
// under one zone or interface (#4544). A hand-authored `load override` config
// can carry two literal `host-inbound-traffic { ... }` blocks; the hierarchical
// parser keeps them as separate same-key siblings (it does not merge same-key
// blocks — unlike flat-set SetPath / load-merge, which route through a
// same-key-container reuse and are structurally immune), so the compiler must
// union them here. Otherwise the second block silently overwrites the first
// (zone level) or is ignored (interface level), narrowing host-inbound
// admission — a service DoS — or fail-opening it if the dropped block was the
// restrictive one, versus what the operator authored.
//
// dst is nil for the first block, in which case src is returned UNCHANGED so a
// SINGLE block stays byte-identical to the pre-#4544 behaviour (no dedup, no
// copy — a single block preserves its exact token multiset). Only when a second
// block is actually merged are the unioned slices deduplicated (first-seen
// order preserved). src nil (no stanza) is a no-op.
func mergeHostInbound(dst, src *HostInboundTraffic) *HostInboundTraffic {
	if src == nil {
		return dst
	}
	if dst == nil {
		return src
	}
	dst.SystemServices = dedupHostInboundTokens(append(dst.SystemServices, src.SystemServices...))
	dst.Protocols = dedupHostInboundTokens(append(dst.Protocols, src.Protocols...))
	return dst
}

// dedupHostInboundTokens returns vals with duplicate entries removed, preserving
// first-seen order. Used only on the merged (2+ block) host-inbound path (#4544)
// so a single block keeps its exact token multiset (byte-identical behaviour).
func dedupHostInboundTokens(vals []string) []string {
	if len(vals) < 2 {
		return vals
	}
	seen := make(map[string]struct{}, len(vals))
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func compileZones(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("security-zone")) {
		// #4818: find-or-create by name rather than always allocating a
		// fresh ZoneConfig. A hand-authored `load override` config can carry
		// two literal `security-zone <name> { ... }` TOP-LEVEL sibling
		// blocks — the hierarchical parser (parseStatements) keeps them as
		// separate same-key siblings (it does not merge), so namedInstances
		// yields TWO entries for the same zone name. The pre-fix unconditional
		// `zone := &ZoneConfig{...}` + `sec.Zones[inst.name] = zone` let the
		// second instance silently REPLACE the first, discarding its
		// interfaces/host-inbound/address-book/description/screen/tcp-rst
		// wholesale. This is the outer-instance analogue of the #4544 fix
		// below, which already merges repeated host-inbound-traffic blocks
		// WITHIN one instance — that fix is a no-op against a duplicate
		// instance because it never runs on the first instance's properties
		// once the whole ZoneConfig is replaced. Properties below now
		// accumulate into the SAME zone across every sibling instance:
		// Interfaces appends, HostInboundTraffic/InterfaceHostInbound merge
		// via mergeHostInbound, AddressBook merges by name (find-or-create,
		// same as parseAddressBookEntries already does for repeated
		// address/address-set children — #4706). ScreenProfile, TCPRst, and
		// Description are scalars with no natural union; they are last-wins
		// across sibling instances (matches their existing last-wins
		// behaviour across repeated properties WITHIN one instance).
		zone := sec.Zones[inst.name]
		if zone == nil {
			zone = &ZoneConfig{Name: inst.name}
			sec.Zones[inst.name] = zone
		}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "interfaces":
				for _, iface := range prop.Children {
					zone.Interfaces = append(zone.Interfaces, iface.Name())
					// #3362: per-interface host-inbound-traffic override
					// (`interfaces <if> host-inbound-traffic { ... }`). Same
					// token grammar as the zone-level stanza; parsed by the
					// shared parseHostInboundNode so both shapes stay in lockstep.
					//
					// #4544/#4818: MERGE across ALL host-inbound-traffic blocks
					// under this interface (Junos merge semantics), not
					// FindChild (first-wins) and not a bare overwrite. A
					// hand-authored `load override` config can carry two
					// literal blocks under one interface — either as siblings
					// within one security-zone instance (#4544) or split
					// across two duplicate top-level security-zone instances
					// naming the same interface (#4818); the hierarchical
					// parser keeps all of them as separate same-key siblings —
					// it does NOT merge — so FindChild would read only the
					// first and a plain map assignment would drop whichever
					// instance's interface block ran first. Merge into
					// whatever is already recorded for this interface name.
					var hib *HostInboundTraffic
					for _, hn := range iface.FindChildren("host-inbound-traffic") {
						hib = mergeHostInbound(hib, parseHostInboundNode(hn))
					}
					if hib != nil {
						if zone.InterfaceHostInbound == nil {
							zone.InterfaceHostInbound = make(map[string]*HostInboundTraffic)
						}
						zone.InterfaceHostInbound[iface.Name()] = mergeHostInbound(zone.InterfaceHostInbound[iface.Name()], hib)
					}
				}
			case "screen":
				zone.ScreenProfile = nodeVal(prop)
			case "host-inbound-traffic":
				// #4544: MERGE repeated zone-level host-inbound-traffic blocks
				// rather than overwrite (Junos merge semantics). This case
				// fires once per host-inbound-traffic child; `load override`
				// splices a raw hierarchical parse whose two literal blocks stay
				// as separate siblings, so a bare `=` assignment silently drops
				// every block but the last. Accumulate into the zone value.
				// #4818 extends this across duplicate top-level security-zone
				// instances too, since zone is now find-or-create.
				zone.HostInboundTraffic = mergeHostInbound(zone.HostInboundTraffic, parseHostInboundNode(prop))
			case "tcp-rst":
				zone.TCPRst = true
			case "description":
				zone.Description = nodeVal(prop)
			case "address-book":
				// #3061: zone-local address book. Same entry grammar as the
				// global book; resolved into the global book under
				// zone-qualified internal names later (resolveZoneLocalAddressBooks).
				// #4818: find-or-create rather than always allocating a fresh
				// AddressBook, so a second security-zone instance's
				// address-book block MERGES into the first's (by address/
				// address-set name, via parseAddressBookEntries's own
				// find-or-create — #4706) instead of replacing it outright.
				ab := zone.AddressBook
				if ab == nil {
					ab = &AddressBook{
						Addresses:   make(map[string]*Address),
						AddressSets: make(map[string]*AddressSet),
					}
					zone.AddressBook = ab
				}
				parseAddressBookEntries(prop, ab)
			}
		}
	}
	return nil
}
