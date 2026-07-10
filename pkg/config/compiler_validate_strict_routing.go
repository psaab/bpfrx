package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// routingRedistProtocolTokens is the set of bare protocol keywords that an
// OSPF/OSPFv3/BGP/IS-IS `export` (or a RIP `redistribute`) accepts in lieu
// of a named policy-statement. resolveRedistribute (pkg/frr/policy_render.go)
// emits a bare `redistribute <token>` for these. It mirrors
// knownRedistProtocols there, plus Junos's `direct` spelling for FRR's
// `connected`. Keep the two in sync: a token accepted here but unknown to
// the renderer would emit a line FRR rejects; a token the renderer accepts
// but missing here would be wrongly rejected at commit.
var routingRedistProtocolTokens = map[string]bool{
	"connected": true, "direct": true, "static": true, "kernel": true,
	"ospf": true, "bgp": true, "rip": true, "isis": true,
}

// validateRoutingExportReferencesStrict hard-rejects a dynamic-protocol
// `export` (OSPF / OSPFv3 / BGP / IS-IS), a RIP `redistribute`, a BGP
// group/neighbor `export`, or a `routing-options forwarding-table export`
// whose token resolves to neither a known redistribution protocol nor a
// defined policy-statement (#2144).
//
// Without this gate a typo passes commit and reaches FRR render-time, where
// it fails OPEN in three distinct ways:
//
//   - resolveRedistribute's fallback (policy_render.go) emits
//     `redistribute <typo>` for any unknown token. FRR either rejects the
//     line — failing the whole frr-reload (a single vtysh -f add-batch
//     exits non-zero on any CMD_WARNING_CONFIG_FAILED) — or silently
//     no-ops, so the intended redistribution never happens.
//   - a BGP group/neighbor `export` renders `neighbor <addr> route-map
//     <typo> out`. FRR resolves a route-map name with no definition to
//     NULL, which it treats as permit-all — the outbound filter the
//     operator wrote silently advertises EVERYTHING.
//   - `forwarding-table export <typo>` is read by resolveECMP
//     (config_render.go), which returns 0 max-paths when the policy is
//     missing — silently DISABLING the expected ECMP / consistent-hash
//     load balancing instead of rejecting the config.
//
// Protocol-token acceptance differs by site. A redistribute-backed export
// (OSPF/OSPFv3/BGP/IS-IS export, RIP redistribute) legitimately names a
// bare protocol (`export static`) OR a policy-statement, matching
// resolveRedistribute. A BGP group/neighbor export and a forwarding-table
// export render directly as a route-map / ECMP policy name, so only a
// defined policy-statement is valid there — a protocol token would be a
// dangling route-map / missing-policy reference, not a redistribute verb.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientRoutingExportRef) so an already-persisted or
// peer-synced config carrying the typo still boots (#1960
// fail-closed-on-load class); the render-path fallbacks above keep it inert
// or fail-open-on-an-already-committed-config exactly as before. Commit /
// commit-check stay strict. Mirrors validateLogProfileStreamReferencesStrict.
func validateRoutingExportReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(name string) bool {
		if cfg.PolicyOptions.PolicyStatements == nil {
			return false
		}
		_, ok := cfg.PolicyOptions.PolicyStatements[name]
		return ok
	}

	// checkRedist validates a redistribute-backed export list: each token
	// must be a known protocol OR a defined policy-statement.
	checkRedist := func(scope, proto string, exports []string) error {
		for _, e := range exports {
			if e == "" || routingRedistProtocolTokens[e] || defined(e) {
				continue
			}
			return fmt.Errorf("%s%s export %q references neither a known "+
				"redistribution protocol (connected/direct/static/kernel/"+
				"ospf/bgp/rip/isis) nor a defined policy-statement — the "+
				"FRR redistribute line would be rejected or silently no-op; "+
				"define the policy-statement or fix the export name",
				scope, proto, e)
		}
		return nil
	}

	// checkPolicyRef validates a reference that renders directly as a
	// route-map / ECMP policy name: only a defined policy-statement is valid.
	// hint is the trailing remediation text — direction-aware so an import
	// failure does not say "fix the export name" (Copilot review, #2490).
	checkPolicyRef := func(detail, name, hint string) error {
		if name == "" || defined(name) {
			return nil
		}
		return fmt.Errorf("%s references undefined policy-statement %q; %s",
			detail, name, hint)
	}
	const (
		hintExport = "define the policy-statement or fix the export name"
		hintImport = "define the policy-statement or fix the import name"
	)

	checkProtocols := func(scope string, ospf *OSPFConfig, ospfv3 *OSPFv3Config, bgp *BGPConfig, rip *RIPConfig, isis *ISISConfig) error {
		if ospf != nil {
			if err := checkRedist(scope, "protocols ospf", ospf.Export); err != nil {
				return err
			}
		}
		if ospfv3 != nil {
			if err := checkRedist(scope, "protocols ospf3", ospfv3.Export); err != nil {
				return err
			}
		}
		if rip != nil {
			if err := checkRedist(scope, "protocols rip", rip.Redistribute); err != nil {
				return err
			}
		}
		if isis != nil {
			if err := checkRedist(scope, "protocols isis", isis.Export); err != nil {
				return err
			}
		}
		if bgp != nil {
			if err := checkRedist(scope, "protocols bgp", bgp.Export); err != nil {
				return err
			}
			// A global `protocols bgp import` renders `route-map <name> in`.
			// Unlike export, import has NO redistribute equivalent — inbound
			// filtering is route-map-only — so it must name a DEFINED
			// policy-statement (no protocol-token fallback). An undefined ref
			// would render a dangling `route-map in` that FRR resolves to
			// PERMIT-ALL, accepting every inbound advertisement and defeating
			// the operator's filter (#2490, the #2473 lesson on the inbound
			// direction). #2490.
			for _, e := range bgp.Import {
				detail := fmt.Sprintf("%sprotocols bgp import", scope)
				if err := checkPolicyRef(detail, e, hintImport); err != nil {
					return err
				}
			}
			// A BGP group/neighbor export renders `route-map <name> out`,
			// and a group/neighbor import renders `route-map <name> in`, so
			// both must be defined policy-statements (no protocol-token
			// fallback). Sort neighbor addresses for a deterministic
			// first-error message.
			neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
			sort.SliceStable(neighbors, func(i, j int) bool {
				return neighbors[i].Address < neighbors[j].Address
			})
			for _, n := range neighbors {
				if n == nil {
					continue
				}
				for _, e := range n.Export {
					detail := fmt.Sprintf("%sprotocols bgp neighbor %s export", scope, n.Address)
					if n.GroupName != "" {
						detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %s export", scope, n.GroupName, n.Address)
					}
					if err := checkPolicyRef(detail, e, hintExport); err != nil {
						return err
					}
				}
				for _, e := range n.Import {
					detail := fmt.Sprintf("%sprotocols bgp neighbor %s import", scope, n.Address)
					if n.GroupName != "" {
						detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %s import", scope, n.GroupName, n.Address)
					}
					if err := checkPolicyRef(detail, e, hintImport); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}

	// Top-level protocols.
	if err := checkProtocols("", cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP, cfg.Protocols.RIP, cfg.Protocols.ISIS); err != nil {
		return err
	}

	// Per routing-instance protocols.
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkProtocols(scope, ri.OSPF, ri.OSPFv3, ri.BGP, ri.RIP, ri.ISIS); err != nil {
			return err
		}
	}

	// forwarding-table export → resolveECMP (config_render.go). Renders
	// directly as an ECMP policy lookup, so it must be a defined
	// policy-statement; a missing one silently disables ECMP/consistent-hash.
	if err := checkPolicyRef(
		"routing-options forwarding-table export",
		cfg.RoutingOptions.ForwardingTableExport,
		hintExport,
	); err != nil {
		return fmt.Errorf("%s (the expected ECMP / consistent-hash "+
			"load-balancing would be silently disabled)", err)
	}

	return nil
}

// validatePolicyCommunityReferencesStrict hard-rejects a policy-statement term
// whose `from community <name>` or `then community delete <name>` references a
// community the config never defines under `policy-options community <name>`
// (#2881).
//
// xpf renders `from community <name>` as the FRR route-map clause
// `match community <name>` and `then community delete <name>` (added in #2848)
// as `set comm-list <name> delete`. Both clauses reference an FRR
// `bgp community-list <name>`, which xpf emits ONLY for a defined
// `policy-options community <name>` (policy_render.go). With no validation an
// undefined name passes commit and breaks at FRR render time: a dangling
// `match community` / `set comm-list ... delete` line is rejected by
// frr-reload, and because a single vtysh -f add-batch exits non-zero on any
// CMD_WARNING_CONFIG_FAILED, the WHOLE reload fails — leaving dynamic routing
// stale, a commit-accepted config the routing daemon cannot load.
//
// Only NAME references are checked. `then community (set|add) <value>` and the
// bare `then community <value>` carry a community VALUE (e.g. 65000:100 /
// no-export), not a community-list reference, so they are not validated here;
// `then community none` carries no argument. Multiple `from community` siblings
// (FromCommunity slice) and a multi-list `then community delete [ a b ]`
// (CommunityDelete slice) are each fully walked.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientPolicyCommunityRef) so an already-persisted or
// peer-synced config carrying the typo still boots (#1960 fail-closed-on-load
// class). Commit / commit-check stay strict. Runs on the fully-compiled
// *Config so the community map is populated regardless of authoring order.
// Mirrors validateRoutingExportReferencesStrict.
func validatePolicyCommunityReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(name string) bool {
		if cfg.PolicyOptions.Communities == nil {
			return false
		}
		_, ok := cfg.PolicyOptions.Communities[name]
		return ok
	}

	// Sort policy-statement names for a deterministic first-error message
	// (the typed-config map iteration order is otherwise random).
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, psName := range names {
		ps := cfg.PolicyOptions.PolicyStatements[psName]
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term == nil {
				continue
			}
			for _, c := range term.FromCommunity {
				if c == "" || defined(c) {
					continue
				}
				return fmt.Errorf("policy-statement %s term %s `from community %s` "+
					"references undefined community %q — xpf renders no "+
					"`bgp community-list %s`, so the `match community` line would "+
					"fail frr-reload (failing the entire FRR config load); define "+
					"`policy-options community %s` or fix the name",
					psName, term.Name, c, c, c, c)
			}
			for _, c := range term.CommunityDelete {
				if c == "" || defined(c) {
					continue
				}
				return fmt.Errorf("policy-statement %s term %s `then community delete %s` "+
					"references undefined community %q — xpf renders no "+
					"`bgp community-list %s`, so the `set comm-list %s delete` line "+
					"would fail frr-reload (failing the entire FRR config load); "+
					"define `policy-options community %s` or fix the name",
					psName, term.Name, c, c, c, c, c)
			}
		}
	}
	return nil
}

// frrTokenUnsafeIndex returns the byte index of the first character in s
// that FRR's command lexer cannot carry inside a single config token, or
// -1 if every character is safe.
//
// FRR's CLI lexer (lib/command_lex.l) tokenizes a vtysh / frr.conf line on
// ASCII whitespace and has NO quoted-string rule and NO rest-of-line
// ("LINE") token — a double-quoted value is NOT grouped, the quotes are
// taken literally. So any whitespace inside a rendered value splits it into
// multiple arguments: a password / auth key is truncated at the first space,
// or trailing words become spurious vtysh arguments. We therefore reject
// only the characters that actually break tokenization: ASCII space, tab,
// and the C0 / DEL control set (which sanitizeFRRValue would otherwise turn
// into spaces at render time, re-introducing the same split). Other
// punctuation (`.`, `@`, `!`, `#`, …) is matched by the lexer's single-char
// catch-all rule and stays adjacent with no whitespace, so it is safe.
func frrTokenUnsafeIndex(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c < 0x20 || c == 0x7f {
			return i
		}
	}
	return -1
}

// validateFRRAuthValuesStrict hard-rejects a dynamic-routing authentication
// secret that cannot be rendered as a single FRR/vtysh token (#2889):
//
//   - a BGP neighbor TCP-MD5 password (`neighbor <addr> password ...`)
//   - an OSPF interface authentication key (`ip ospf message-digest-key`
//     md5 / `ip ospf authentication-key`)
//   - a RIP authentication key (`ip rip authentication string`)
//   - an IS-IS area/domain or per-interface authentication key
//     (`area-password` / `domain-password` / `isis password`)
//
// All of these render the secret directly into a frr.conf line. FRR's
// command lexer (lib/command_lex.l) splits on whitespace and supports
// neither a quoted string nor a rest-of-line token, so a secret containing
// a space or tab is parsed as multiple arguments at config load: the secret
// is truncated at the first space, or — worse — the trailing words are
// interpreted as additional vtysh arguments (a malformed-line / injection
// risk). The render-side belt (sanitizeFRRValue, #1798) already collapses
// embedded control characters to spaces, so it cannot rescue this; it would
// only widen the split. Quoting is not an option here, so the safe contract
// is to reject the value at commit, naming the field.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientFRRAuthValues) so an already-persisted or peer-synced
// config carrying such a value still BOOTS (#1960 fail-closed-on-load
// class); the render path strips control chars and the offending line stays
// inert / single-line. Commit / commit-check stay strict. Mirrors
// validateRoutingExportReferencesStrict.
func validateFRRAuthValuesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	const why = "FRR's vtysh config lexer splits on whitespace and supports " +
		"no quoting, so the secret would be truncated at the first space or " +
		"inject trailing words as extra arguments at frr.conf load — remove " +
		"the whitespace/control characters from the value"

	checkKey := func(scope, field string, s Secret) error {
		if s == "" {
			return nil
		}
		if i := frrTokenUnsafeIndex(s.Reveal()); i >= 0 {
			return fmt.Errorf("%s%s contains whitespace or a control "+
				"character (at byte offset %d) that cannot be represented "+
				"in FRR config — %s", scope, field, i, why)
		}
		return nil
	}

	checkProtocols := func(scope string, ospf *OSPFConfig, bgp *BGPConfig, rip *RIPConfig, isis *ISISConfig) error {
		if ospf != nil {
			for _, area := range ospf.Areas {
				if area == nil {
					continue
				}
				for _, iface := range area.Interfaces {
					if iface == nil {
						continue
					}
					fld := fmt.Sprintf("protocols ospf area %s interface %s authentication-key", area.ID, iface.Name)
					if err := checkKey(scope, fld, iface.AuthKey); err != nil {
						return err
					}
				}
			}
		}
		if rip != nil {
			if err := checkKey(scope, "protocols rip authentication-key", rip.AuthKey); err != nil {
				return err
			}
		}
		if isis != nil {
			if err := checkKey(scope, "protocols isis authentication-key", isis.AuthKey); err != nil {
				return err
			}
			for _, iface := range isis.Interfaces {
				if iface == nil {
					continue
				}
				fld := fmt.Sprintf("protocols isis interface %s authentication-key", iface.Name)
				if err := checkKey(scope, fld, iface.AuthKey); err != nil {
					return err
				}
			}
		}
		if bgp != nil {
			// Sort neighbor addresses for a deterministic first-error
			// message (Go map / slice authoring order is not stable across
			// the parse paths).
			neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
			sort.SliceStable(neighbors, func(i, j int) bool {
				return neighbors[i].Address < neighbors[j].Address
			})
			for _, n := range neighbors {
				if n == nil {
					continue
				}
				fld := fmt.Sprintf("protocols bgp neighbor %s authentication-key", n.Address)
				if n.GroupName != "" {
					fld = fmt.Sprintf("protocols bgp group %s neighbor %s authentication-key", n.GroupName, n.Address)
				}
				if err := checkKey(scope, fld, n.AuthPassword); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// Top-level protocols.
	if err := checkProtocols("", cfg.Protocols.OSPF, cfg.Protocols.BGP, cfg.Protocols.RIP, cfg.Protocols.ISIS); err != nil {
		return err
	}

	// Per routing-instance protocols.
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkProtocols(scope, ri.OSPF, ri.BGP, ri.RIP, ri.ISIS); err != nil {
			return err
		}
	}

	return nil
}

// validateBGPNeighborPeerASStrict hard-rejects a BGP neighbor whose effective
// peer-as (remote-as) is missing/0 or out of the valid AS range (#2963).
//
// peer-as is optional in the parser/compiler (compiler_protocols.go assigns
// BGPNeighbor.PeerAS only when a per-neighbor `peer-as` token or an inherited
// group `peer-as` is present; otherwise it stays the zero value). The FRR
// renderer (pkg/frr/policy_render.go) emits `neighbor <addr> remote-as <PeerAS>`
// unconditionally, so a neighbor authored without a peer-as renders
// `neighbor <addr> remote-as 0`. AS 0 is reserved (RFC 7607) and FRR/vtysh
// rejects it: the whole frr-reload fails (a single vtysh -f add-batch exits
// non-zero on any CMD_WARNING_CONFIG_FAILED), leaving dynamic routing in a
// broken/stale state. That is a commit-accepted config the routing daemon
// cannot load — exactly the fail-class this gate closes.
//
// The valid 4-byte AS space is 1..4294967295 (uint32 max); 0 is reserved
// (RFC 7607) and 23456 (AS_TRANS) is reserved for 4-byte transition but is a
// legal configured remote-as, so only 0 is rejected here. (PeerAS is a uint32
// so the upper bound cannot be exceeded by the typed value — the range check
// documents intent and is robust to a future wider type.)
//
// Both the global `protocols bgp` and per-routing-instance scopes are checked.
// Neighbor addresses are sorted for a deterministic first-error message.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientBGPNeighborPeerAS) so an already-persisted or
// peer-synced config carrying such a neighbor still BOOTS (#1960
// fail-closed-on-load class); the render path now skips a remote-as-0 neighbor
// (defense-in-depth) so AS 0 never reaches frr.conf and a leniently-loaded bad
// neighbor is inert. Commit / commit-check stay strict. Mirrors
// validateRoutingExportReferencesStrict.
func validateBGPNeighborPeerASStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	checkBGP := func(scope string, bgp *BGPConfig) error {
		if bgp == nil {
			return nil
		}
		neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
		sort.SliceStable(neighbors, func(i, j int) bool {
			return neighbors[i].Address < neighbors[j].Address
		})
		for _, n := range neighbors {
			if n == nil {
				continue
			}
			if n.PeerAS == 0 {
				detail := fmt.Sprintf("%sprotocols bgp neighbor %s", scope, n.Address)
				if n.GroupName != "" {
					detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %s", scope, n.GroupName, n.Address)
				}
				return fmt.Errorf("%s: missing/invalid peer-as — a BGP neighbor "+
					"requires a peer-as (remote-as) in 1..4294967295; AS 0 is "+
					"reserved (RFC 7607) and FRR/vtysh rejects `remote-as 0`, "+
					"failing the frr-reload — set the neighbor (or its group) "+
					"peer-as", detail)
			}
		}
		return nil
	}

	if err := checkBGP("", cfg.Protocols.BGP); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkBGP(scope, ri.BGP); err != nil {
			return err
		}
	}
	return nil
}

// validateRouterIDStrict hard-rejects an OSPF / OSPFv3 / BGP router-id that is
// not a valid 32-bit IPv4 dotted-quad (#2980).
//
// router-id is parsed as a raw string and stored verbatim
// (compiler_protocols.go assigns OSPF/OSPFv3/BGP RouterID = child.Keys[1] with
// no validation). The FRR renderer (pkg/frr/policy_render.go) emits
// `ospf router-id <v>` / `ospf6 router-id <v>` / `bgp router-id <v>` whenever
// the field is non-empty. FRR/vtysh requires a 32-bit dotted-quad router-id
// for ALL of these protocols — including the IPv6 protocols OSPFv3 (ospf6) and
// BGP — and rejects anything else (e.g. `foo`, `300.1.2.3`, or an IPv6
// address): the whole frr-reload fails (a single vtysh -f add-batch exits
// non-zero on any CMD_WARNING_CONFIG_FAILED), leaving dynamic routing in a
// broken/stale state. That is a commit-accepted config the routing daemon
// cannot load — exactly the fail-class this gate closes.
//
// A router-id is the 32-bit dotted-quad form even for IPv6 protocols, so the
// check is net.ParseIP + To4()!=nil (net/netip ParseAddr+Is4 is equivalent;
// To4 keeps the validator on the same net.* surface the file already uses for
// other address checks). Empty is allowed at every scope — an unset router-id
// is omitted by the renderer and FRR auto-derives one, which is the documented
// Junos/FRR default.
//
// Both the global `protocols {}` and per-routing-instance scopes are checked,
// covering OSPF, OSPFv3, and BGP. Routing instances are walked in declaration
// order for a deterministic first-error message.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientRouterID) so an already-persisted or peer-synced config
// carrying a bad router-id still BOOTS (#1960 fail-closed-on-load class); the
// render path now skips an invalid router-id (defense-in-depth) so a malformed
// value never reaches frr.conf and a leniently-loaded bad router-id is inert.
// Commit / commit-check stay strict. Mirrors validateBGPNeighborPeerASStrict.
func validateRouterIDStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	check := func(scope, proto, routerID string) error {
		if routerID == "" {
			return nil
		}
		if ip := net.ParseIP(routerID); ip == nil || ip.To4() == nil {
			return fmt.Errorf("%s%s router-id %q is not a valid IPv4 "+
				"dotted-quad address — FRR/vtysh requires a 32-bit IPv4 "+
				"router-id for all routing protocols (including OSPFv3 and "+
				"BGP) and rejects anything else, failing the frr-reload",
				scope, proto, routerID)
		}
		return nil
	}

	checkScope := func(scope string, ospf *OSPFConfig, ospfv3 *OSPFv3Config, bgp *BGPConfig) error {
		if ospf != nil {
			if err := check(scope, "protocols ospf", ospf.RouterID); err != nil {
				return err
			}
		}
		if ospfv3 != nil {
			if err := check(scope, "protocols ospf3", ospfv3.RouterID); err != nil {
				return err
			}
		}
		if bgp != nil {
			if err := check(scope, "protocols bgp", bgp.RouterID); err != nil {
				return err
			}
		}
		return nil
	}

	if err := checkScope("", cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkScope(scope, ri.OSPF, ri.OSPFv3, ri.BGP); err != nil {
			return err
		}
	}
	return nil
}

// validateRibGroupImportRibReferencesStrict hard-rejects a
// `routing-options rib-groups <group> import-rib <rib>` entry whose rib
// name resolves to no real routing table (#2226).
//
// A valid import-rib names one of:
//   - inet.0 / inet6.0 (the main table), OR
//   - "<instance>.inet.0" / "<instance>.inet6.0" where <instance> is a
//     defined routing-instance.
//
// Any other name — a typo, a non-existent instance, or unparseable
// garbage — is undefined. ValidateConfig only ever emitted an over-limit
// WARNING for rib-groups; it never validated that an import-rib names a
// real rib. The applier's resolveRibTable previously mapped any
// unresolvable name to a bare table 0 (see pkg/routing/rules.go). Because
// a routing-instance's source table is always >= 100, an unresolvable
// import-rib yielded targetTable(0) != sourceTable, which set needsLeak
// and installed an `ip rule from all lookup <sourceTable> pref 33000` for
// a rib that does not exist — a silent mis-leak of the source table into
// the main lookup, with no diagnostic. This gate makes the dangling
// reference an operator-visible commit error; resolveRibTable's ok=false
// path is the defense-in-depth backstop for any reference that still
// reaches apply via the tolerant load / peer-sync path.
//
// Rib-group names are iterated in sorted order, and each group's
// import-rib list is walked in declaration order, so the first-reported
// error is deterministic (Go map order is randomized). Every defined
// rib-group is validated (not only ones referenced by an instance's
// interface-routes rib-group), mirroring Junos, which rejects an
// undefined rib regardless of whether the group is in use.
//
// On the tolerant load / peer-sync paths the call site downgrades this to
// a warning (opts.lenientRibGroupRefs) so an already-persisted or peer-
// synced config carrying a dangling import-rib still BOOTS (#1960
// fail-closed-on-load class); the applier's ok=false guard keeps it inert
// (the phantom rib is skipped, no rule is installed), exactly matching the
// post-fix runtime behaviour. Commit / commit-check stay strict. Mirrors
// validateRoutingExportReferencesStrict.
func validateRibGroupImportRibReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ribGroups := cfg.RoutingOptions.RibGroups
	if len(ribGroups) == 0 {
		return nil
	}
	definedInstance := make(map[string]bool, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name != "" {
			definedInstance[ri.Name] = true
		}
	}
	// resolvable mirrors pkg/routing.resolveRibTable's definedness view:
	// inet.0 / inet6.0, or "<defined-instance>.inet[6].0". The instance form
	// requires an EXACT family suffix (see ribInstanceFromName) — a loose
	// ".inet" substring match would accept malformed names like
	// "<instance>.inetX.0" and "<instance>.inet.0.garbage" (#2253). The
	// commit-time gate and pkg/routing's runtime applier MUST agree on what
	// resolves, so both call the same exact-suffix matcher (#2226).
	resolvable := func(ribName string) bool {
		if ribName == "inet.0" || ribName == "inet6.0" {
			return true
		}
		if instance, ok := ribInstanceFromName(ribName); ok {
			return definedInstance[instance]
		}
		return false
	}
	names := make([]string, 0, len(ribGroups))
	for name := range ribGroups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rg := ribGroups[name]
		if rg == nil {
			continue
		}
		for _, ribName := range rg.ImportRibs {
			if ribName == "" || resolvable(ribName) {
				continue
			}
			return fmt.Errorf(
				"routing-options rib-groups %q import-rib %q references an "+
					"undefined rib (name a defined routing-instance as "+
					"\"<instance>.inet.0\" / \"<instance>.inet6.0\", or use "+
					"inet.0 / inet6.0 for the main table — an undefined rib "+
					"would otherwise silently leak this table's routes into "+
					"the main lookup)",
				name, ribName)
		}
	}
	return nil
}

// ribInstanceFromName extracts the routing-instance prefix from a non-default
// rib name of the EXACT form "<instance>.inet.0" or "<instance>.inet6.0",
// returning ok=false for any other shape. The instance prefix must be
// non-empty. Bare "inet.0" / "inet6.0" (the main table) are NOT instance ribs
// and are handled by callers directly. Malformed family tokens
// (".inetX.0", ".inetfoo.0", ".inet60.0") and trailing garbage (".inet.0.x")
// return ok=false (#2253). This mirrors pkg/routing.ribInstanceFromName — the
// two MUST stay in lockstep so the commit-time gate and the runtime applier
// agree on what resolves (#2226).
func ribInstanceFromName(ribName string) (string, bool) {
	for _, suffix := range []string{".inet.0", ".inet6.0"} {
		if instance, ok := strings.CutSuffix(ribName, suffix); ok && instance != "" {
			return instance, true
		}
	}
	return "", false
}

// validateRouteFilterMatchTypesStrict gates the two route-filter match-types
// that the FRR prefix-list backend cannot render losslessly (#2525):
//
//   - "through <prefix2>" has NO FRR equivalent. Junos "through" matches the
//     base prefix, prefix2, and only the prefixes on the direct radix-tree
//     path between them — not every prefix of intermediate length. FRR
//     prefix-lists express only length ranges (ge/le), so any rendering would
//     change the match set. Reject it loudly rather than silently degrade.
//
//   - "prefix-length-range /low-/high" maps to FRR "ge low le high", but only
//     when the bounds are well-formed. Reject a malformed, inverted, out-of-
//     family-range, or below-base range so the operator fixes it instead of
//     getting the pre-#2525 silent open-ended "le maxLen" fall-through.
//
// Strict on commit / commit-check (hard reject so the unsupported / malformed
// match-type is operator-visible); the compiler downgrades this to a warning on
// the tolerant load / peer-sync path (#1960) so an already-persisted or
// peer-synced config still boots — the renderer then skips the offending entry
// (match-nothing, fail-closed). Runs on the fully-compiled *Config.
func validateRouteFilterMatchTypesStrict(cfg *Config) error {
	if cfg == nil || cfg.PolicyOptions.PolicyStatements == nil {
		return nil
	}
	// Deterministic first-error: iterate policy-statements by sorted name.
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ps := cfg.PolicyOptions.PolicyStatements[name]
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term == nil {
				continue
			}
			for _, rf := range term.RouteFilters {
				if rf == nil {
					continue
				}
				switch rf.MatchType {
				case "through":
					return fmt.Errorf(
						"policy-statement %q term %q route-filter %q through %q: the "+
							"`through` match-type is not supported by the FRR routing "+
							"backend — it matches a two-prefix containment path that has "+
							"no lossless prefix-list (ge/le) equivalent. Use "+
							"`prefix-length-range /<low>-/<high>`, `upto /<n>`, or "+
							"`orlonger` instead",
						name, term.Name, rf.Prefix, rf.ThroughPrefix)
				case "prefix-length-range":
					if err := validatePrefixLengthRange(rf); err != nil {
						return fmt.Errorf(
							"policy-statement %q term %q route-filter %q prefix-length-range: %v",
							name, term.Name, rf.Prefix, err)
					}
				}
			}
		}
	}
	return nil
}

// validatePrefixLengthRange enforces the semantic constraints on a
// prefix-length-range route-filter (#2525): both bounds parsed (non-zero), the
// per-family max not exceeded, low<=high, and low at least the base prefix
// length (Junos requires the range to be no less specific than the base).
func validatePrefixLengthRange(rf *RouteFilter) error {
	maxLen := 32
	if strings.Contains(rf.Prefix, ":") {
		maxLen = 128
	}
	if rf.RangeLow == 0 || rf.RangeHigh == 0 {
		return fmt.Errorf(
			"malformed range (expected /<low>-/<high> with both lengths in 1..%d, e.g. /16-/24)",
			maxLen)
	}
	if rf.RangeLow > maxLen || rf.RangeHigh > maxLen {
		return fmt.Errorf(
			"range /%d-/%d exceeds the address-family maximum /%d",
			rf.RangeLow, rf.RangeHigh, maxLen)
	}
	if rf.RangeLow > rf.RangeHigh {
		return fmt.Errorf(
			"inverted range /%d-/%d (low must be <= high)",
			rf.RangeLow, rf.RangeHigh)
	}
	// The base prefix length floors the range: the range low bound must be
	// STRICTLY more specific than the base prefix. Junos requires this, and FRR
	// rejects a prefix-list whose `ge` value is not strictly greater than the
	// prefix length ("len < ge-value"). Accepting RangeLow == baseLen would emit
	// `ge baseLen le high` → FRR rejects the line → frr-reload exits non-zero on
	// the whole managed batch → FRR brick (#1880-class). The renderer carries
	// the same guard for the lenient (downgraded-to-warning) path.
	if _, ipnet, err := net.ParseCIDR(rf.Prefix); err == nil {
		baseLen, _ := ipnet.Mask.Size()
		if rf.RangeLow <= baseLen {
			return fmt.Errorf(
				"range low /%d must be more specific than the base prefix /%d "+
					"(low > base; FRR rejects a ge value not strictly greater "+
					"than the prefix length)",
				rf.RangeLow, baseLen)
		}
	}
	return nil
}

// ReservedRedistSuffix is the route-map name suffix xpf RESERVES for the
// per-use-site fail-closed redistribute aliases the FRR renderer derives
// (redistFailClosedRouteMap in pkg/frr/policy_render.go emits `name + suffix`).
// FRR keys route-maps by NAME in a single GLOBAL namespace, so an operator
// policy-statement whose name ends in this suffix would collide with a
// generated alias in that shared object and could silently undo the #4481
// fail-closed BGP/IGP separation — reintroducing route redistribution leakage
// under a config that otherwise passes validation (#5116). The alias derivation
// (pkg/frr) and the strict validator below MUST agree on this exact string;
// pkg/frr references this constant so the two never drift.
const ReservedRedistSuffix = "-xpf-redist"

// validatePolicyReservedRedistNameStrict hard-rejects an operator
// policy-statement whose name ends in the reserved ReservedRedistSuffix. That
// suffix is owned by the FRR renderer's generated fail-closed redistribute
// aliases (#4481); an operator name in that namespace can collide with a
// generated alias in FRR's global name-keyed route-map object and silently
// reintroduce BGP/IGP redistribution leakage (#5116). Reserving the suffix at
// commit makes the generated-alias namespace injective BY CONSTRUCTION — no
// legal config can name a policy-statement into the generated slot.
//
// Strict on commit / commit-check (hard reject so the reserved name is
// operator-visible); lenient on load / peer-sync (warn so an already-persisted
// or peer-synced config an older binary accepted still boots — #1960
// fail-closed-on-load class). The render-side defense-in-depth (redistAliasCollision
// in pkg/frr) fails the whole managed-section apply CLOSED on the tolerant path,
// so a leniently-loaded collision cannot leak. Runs on the fully-compiled
// *Config so the policy-statement map is populated regardless of authoring
// order. Mirrors validateRoutingExportReferencesStrict.
func validatePolicyReservedRedistNameStrict(cfg *Config) error {
	if cfg == nil || cfg.PolicyOptions.PolicyStatements == nil {
		return nil
	}
	// Deterministic first-error: iterate policy-statement names in sorted order.
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.HasSuffix(name, ReservedRedistSuffix) {
			return fmt.Errorf(
				"policy-statement %q ends in the reserved %q suffix; xpf owns "+
					"that suffix for generated fail-closed redistribute route-map "+
					"aliases (#4481/#5116) and an operator name in that namespace "+
					"can collide with a generated alias in FRR's global route-map "+
					"object, silently reintroducing BGP/IGP redistribution leakage "+
					"— rename the policy-statement off the reserved suffix",
				name, ReservedRedistSuffix)
		}
	}
	return nil
}

// ReservedChainSuffix is the route-map name suffix xpf RESERVES for the composed
// BGP policy-chain route-maps the FRR renderer derives for an ordered
// import/export policy list of length >= 2 (composedChainName in pkg/frr joins
// the member policy names and appends this suffix). FRR keys route-maps by NAME
// in a single GLOBAL namespace, so an operator policy-statement whose name ends
// in this suffix would collide with a generated composed route-map in that
// shared object and FRR would MERGE the two same-named definitions, silently
// altering the operator's BGP filtering (#5277/#5442). The composed-name
// derivation (pkg/frr) and the strict validator below MUST agree on this exact
// string; pkg/frr re-exports this constant (frr.ReservedChainSuffix =
// config.ReservedChainSuffix) so the two never drift.
const ReservedChainSuffix = "-xpf-chain"

// validatePolicyReservedChainNameStrict hard-rejects an operator
// policy-statement whose name ends in the reserved ReservedChainSuffix. That
// suffix is owned by the FRR renderer's generated composed BGP policy-chain
// route-maps (#5277): an ordered import/export chain of length >= 2 is joined
// and suffixed with ReservedChainSuffix (composedChainName in pkg/frr). An
// operator name in that suffix namespace can collide with a generated composed
// route-map in FRR's global name-keyed route-map object; FRR MERGES two
// same-named route-map definitions, silently altering the operator's BGP
// filtering (#5442). Reserving the suffix at commit makes the composed-name
// namespace injective against operator policy-statements BY CONSTRUCTION — no
// legal config can name a policy-statement into the generated slot.
//
// Strict on commit / commit-check (hard reject so the reserved name is
// operator-visible); lenient on load / peer-sync (warn so an already-persisted
// or peer-synced config an older binary accepted still boots — #1960
// fail-closed-on-load class). The render-side defense-in-depth
// (bgpComposedChainCollision in pkg/frr) fails the whole managed-section apply
// CLOSED on the tolerant path, so a leniently-loaded collision cannot leak. Runs
// on the fully-compiled *Config so the policy-statement map is populated
// regardless of authoring order. Mirrors validatePolicyReservedRedistNameStrict.
func validatePolicyReservedChainNameStrict(cfg *Config) error {
	if cfg == nil || cfg.PolicyOptions.PolicyStatements == nil {
		return nil
	}
	// Deterministic first-error: iterate policy-statement names in sorted order.
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.HasSuffix(name, ReservedChainSuffix) {
			return fmt.Errorf(
				"policy-statement %q ends in the reserved %q suffix; xpf owns "+
					"that suffix for generated composed BGP policy-chain "+
					"route-maps (#5277/#5442) and an operator name in that "+
					"namespace can collide with a generated composed route-map "+
					"in FRR's global route-map object, which FRR would merge — "+
					"silently altering BGP route filtering — rename the "+
					"policy-statement off the reserved suffix",
				name, ReservedChainSuffix)
		}
	}
	return nil
}
