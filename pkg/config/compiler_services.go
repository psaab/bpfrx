package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var supportedRPMProbeTypes = map[string]struct{}{
	DefaultRPMProbeType: {},
	"tcp-ping":          {},
	"http-get":          {},
}

func parseRPMPositiveInt(probeName, testName, field, raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("services rpm probe %q test %q %s: invalid integer %q", probeName, testName, field, raw)
	}
	if n <= 0 {
		return 0, fmt.Errorf("services rpm probe %q test %q %s: must be > 0", probeName, testName, field)
	}
	return n, nil
}

func parseRPMRootPositiveInt(field, raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("services rpm %s: invalid integer %q", field, raw)
	}
	if n <= 0 {
		return 0, fmt.Errorf("services rpm %s: must be > 0", field)
	}
	return n, nil
}

func validateRPMTest(probeName string, test *RPMTest) error {
	if test.Target == "" {
		return fmt.Errorf("services rpm probe %q test %q: target is required", probeName, test.Name)
	}
	if _, ok := supportedRPMProbeTypes[test.EffectiveProbeType()]; !ok {
		return fmt.Errorf(
			"services rpm probe %q test %q: unsupported probe-type %q (want icmp-ping, tcp-ping, or http-get)",
			probeName, test.Name, test.ProbeType,
		)
	}
	if test.DestPort > 65535 {
		return fmt.Errorf("services rpm probe %q test %q destination-port: must be 1-65535", probeName, test.Name)
	}
	if test.NextHop != "" {
		nh := net.ParseIP(test.NextHop)
		if nh == nil {
			return fmt.Errorf("services rpm probe %q test %q next-hop: invalid IP address %q",
				probeName, test.Name, test.NextHop)
		}
		// The pinned host route is installed with an explicit `dev` +
		// `onlink`, so the egress interface must be named (#1827 §4.2.4).
		if test.DestinationInterface == "" {
			return fmt.Errorf("services rpm probe %q test %q: next-hop requires destination-interface "+
				"(the probe pin route needs an explicit egress device)", probeName, test.Name)
		}
		// The pin installs <target>/32 (or /128) via <next-hop>, so the
		// target must be an IP literal of the same address family.
		target := net.ParseIP(test.Target)
		if target == nil {
			return fmt.Errorf("services rpm probe %q test %q: next-hop pinning requires an IP-literal target (got %q)",
				probeName, test.Name, test.Target)
		}
		if (target.To4() == nil) != (nh.To4() == nil) {
			return fmt.Errorf("services rpm probe %q test %q: next-hop %q address family does not match target %q",
				probeName, test.Name, test.NextHop, test.Target)
		}
	}
	return nil
}

// validateRPMSourceAddressStrict rejects a malformed RPM test
// `source-address` (#2492). A non-empty but unparseable value silently
// turns the tcp-ping/http-get probe dialer into a wildcard/kernel-chosen
// source bind (net.ParseIP -> nil -> net.TCPAddr{IP:nil}), so the probe
// measures the DEFAULT uplink instead of the source-specific path the
// operator pinned. Because RPM feeds event-options / ip-monitoring
// failover, that publishes PASS for the wrong uplink (or FAILs a healthy
// source-specific path). The ICMP path already surfaces a bad source via
// its real listen error; tcp-ping/http-get had no such backstop.
//
// When the target is an IP literal, the source must share its address
// family: a v6 source can never bind a v4 destination connection (and
// vice-versa). For a hostname target the family is unknown until DNS
// resolves, so the family check is skipped — only the parse check
// applies. An EMPTY source-address is legitimate (default source bind)
// and is never rejected.
func validateRPMSourceAddressStrict(cfg *Config) error {
	if cfg == nil || cfg.Services.RPM == nil {
		return nil
	}
	for _, probe := range cfg.Services.RPM.Probes {
		if probe == nil {
			continue
		}
		for _, test := range probe.Tests {
			if test == nil || test.SourceAddress == "" {
				continue
			}
			src := net.ParseIP(test.SourceAddress)
			if src == nil {
				return fmt.Errorf("services rpm probe %q test %q source-address: invalid IP address %q",
					probe.Name, test.Name, test.SourceAddress)
			}
			// Family compatibility only applies to an IP-literal target;
			// a hostname target's family is unknown at commit time.
			if target := net.ParseIP(test.Target); target != nil {
				if (src.To4() == nil) != (target.To4() == nil) {
					return fmt.Errorf(
						"services rpm probe %q test %q: source-address %q address family does not match target %q",
						probe.Name, test.Name, test.SourceAddress, test.Target)
				}
			}
		}
	}
	return nil
}

// #2614: the #2493 validateRPMScopedHostnameStrict gate (which rejected a
// hostname target on a scoped RPM test) was REMOVED. The runtime resolver
// now binds the DNS socket to the probe's VRF/path scope
// (rpm.resolveProbeTarget / probeDialer.Resolver use the same
// SO_BINDTODEVICE / SO_MARK as the probe socket), so a scoped hostname
// resolves in-context and is a legitimate configuration. See
// docs/multi-wan.md.

// validateRPMLinkLocalZoneStrict rejects an IPv6 link-local RPM target
// that carries no scope (#2494). A link-local destination (fe80::/10) is
// meaningless without a zone: the kernel cannot pick the egress link, so
// the ICMP echo goes to the wrong link or fails outright. The scope can
// come from an explicit `%zone` on the target literal (fe80::1%ge-0/0/3)
// or be derived from the test's destination-interface (the same egress
// device the probe data socket binds via SO_BINDTODEVICE). A bare
// link-local with NEITHER is unprobeable and is refused so the operator
// sees the gap at commit instead of a silently-dead probe feeding
// ip-monitoring failover.
//
// Only IP-literal targets are checked: net.ParseIP rejects a zoned
// literal so the zone is split off by hand first (no DNS at commit). A
// hostname resolving to a link-local cannot be caught here (resolution is
// runtime); a hostname that resolves to a bare link-local would fail at
// runtime with ErrProbeSetup (the same missing-zone error in probeICMP).
// routing-instance / next-hop scopes do
// NOT supply a link scope (a VRF master device / fwmark route is not an
// egress link for fe80::), so only destination-interface satisfies the
// requirement. Strict on commit / commit-check (hard reject so the gap is
// operator-visible); lenient on load / peer-sync (warn — #1960 no-brick;
// the runtime probeICMP guard returns ErrProbeSetup for the same bare
// link-local, so a leniently-loaded test HOLDS state instead of actuating
// routes off a dead measurement). Mirrors validateRPMSourceAddressStrict.
func validateRPMLinkLocalZoneStrict(cfg *Config) error {
	if cfg == nil || cfg.Services.RPM == nil {
		return nil
	}
	for _, probe := range cfg.Services.RPM.Probes {
		if probe == nil {
			continue
		}
		for _, test := range probe.Tests {
			if test == nil || test.Target == "" {
				continue
			}
			host := test.Target
			zone := ""
			if i := strings.IndexByte(host, '%'); i >= 0 {
				zone = host[i+1:]
				host = host[:i]
			}
			ip := net.ParseIP(host)
			if ip == nil || ip.To4() != nil || !ip.IsLinkLocalUnicast() {
				continue // not an IPv6 link-local literal
			}
			if zone == "" && test.DestinationInterface == "" {
				return fmt.Errorf(
					"services rpm probe %q test %q: target %q is an IPv6 link-local address "+
						"with no scope — add an explicit %%zone (fe80::1%%ge-0/0/3) or a "+
						"destination-interface so the probe can pick the egress link",
					probe.Name, test.Name, test.Target)
			}
		}
	}
	return nil
}

// validateRPMHTTPGetSchemeStrict rejects an http-get RPM test whose
// target carries an unsupported URL scheme (#2495). The runtime probe
// canonicalizes a schemeless target (bare hostname / IP / host:port) by
// prepending "http://", and accepts an explicit "http://" or "https://"
// target as-is; any other scheme (ftp://, gopher://, …) is meaningless
// for an http-get probe and makes http.NewRequestWithContext error
// before a packet is sent — the probe never runs and publishes a
// permanent FAIL into event-options / ip-monitoring failover. A scheme
// is only present when the target contains the "://" separator; a bare
// "host:port" (no "://") is NOT a scheme and is left for the runtime to
// prefix with http://. Only the literal target is inspected (no DNS at
// commit).
//
// Strict on commit / commit-check (hard reject so the operator sees the
// bad scheme immediately); lenient on load / peer-sync (warn — #1960
// no-brick; the runtime canonicalizeHTTPTarget guard returns the same
// error for the bad scheme, so a leniently-loaded test HOLDS state
// instead of actuating routes off a probe that can never run). Mirrors
// validateRPMLinkLocalZoneStrict.
func validateRPMHTTPGetSchemeStrict(cfg *Config) error {
	if cfg == nil || cfg.Services.RPM == nil {
		return nil
	}
	for _, probe := range cfg.Services.RPM.Probes {
		if probe == nil {
			continue
		}
		for _, test := range probe.Tests {
			if test == nil || test.Target == "" {
				continue
			}
			if test.EffectiveProbeType() != "http-get" {
				continue
			}
			// A scheme is present only with the "://" separator; a bare
			// host:port is schemeless (the runtime prepends http://).
			if !strings.Contains(test.Target, "://") {
				continue
			}
			u, err := url.Parse(test.Target)
			if err != nil {
				return fmt.Errorf("services rpm probe %q test %q: invalid http-get target URL %q: %w",
					probe.Name, test.Name, test.Target, err)
			}
			switch u.Scheme {
			case "http", "https":
				// supported
			default:
				return fmt.Errorf(
					"services rpm probe %q test %q: http-get target %q uses unsupported scheme %q "+
						"(only http and https are valid for an http-get probe)",
					probe.Name, test.Name, test.Target, u.Scheme)
			}
		}
	}
	return nil
}

// validateRPMRoutingInstanceStrict rejects an RPM test whose
// `routing-instance` does not name a CONFIGURED routing instance (#2496).
// The runtime binds the probe DATA socket to the instance's VRF device
// via SO_BINDTODEVICE — vrfDeviceName(ri) synthesizes "vrf-<name>"
// (pkg/rpm/rpm.go). A typo'd / nonexistent instance has no such kernel
// device, so the bind fails with ENODEV: the probe never sends a packet
// and the test silently HOLDS its state forever (never PASS, never FAIL),
// so any event-options / ip-monitoring policy keyed off it gets no
// failover signal. It fails safe (no false PASS), but the candidate
// config should have been rejected at commit so the operator sees the
// typo rather than a permanently dead probe.
//
// An EMPTY routing-instance means the default (master) context and is NOT
// scoped to a VRF device — it is always accepted. Only a non-empty name
// that does not match a configured instance is the error. The configured-
// instance enumeration mirrors validateIPMonitoringStrict's preferred-route
// routing-instance check exactly (same cfg.RoutingInstances source, same
// empty-is-default handling, same "does not exist" error shape).
//
// Strict on commit / commit-check (hard reject so the typo is
// operator-visible); lenient on load / peer-sync (warn — #1960 no-brick;
// the runtime bind returns ENODEV for the same nonexistent instance, so a
// leniently-loaded test HOLDS state instead of actuating routes off a dead
// measurement). Mirrors validateRPMHTTPGetSchemeStrict.
func validateRPMRoutingInstanceStrict(cfg *Config) error {
	if cfg == nil || cfg.Services.RPM == nil {
		return nil
	}
	instances := make(map[string]*RoutingInstanceConfig)
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			instances[ri.Name] = ri
		}
	}
	for _, probe := range cfg.Services.RPM.Probes {
		if probe == nil {
			continue
		}
		for _, test := range probe.Tests {
			if test == nil || test.RoutingInstance == "" {
				continue
			}
			if _, ok := instances[test.RoutingInstance]; !ok {
				return fmt.Errorf(
					"services rpm probe %q test %q: routing-instance %q does not exist "+
						"(the probe would bind a nonexistent vrf-%s device and never run)",
					probe.Name, test.Name, test.RoutingInstance, test.RoutingInstance)
			}
		}
	}
	return nil
}

// validateRPMProbePinsStrict enforces the probe-pin band invariants
// (#1827 PR-1a): at most ProbeTableCount next-hop-pinned tests (one
// reserved kernel table each), and no routing-instance table ID may
// collide with the reserved probe table range 7000-7049.
func validateRPMProbePinsStrict(cfg *Config) error {
	pinned := 0
	if cfg.Services.RPM != nil {
		for _, probe := range cfg.Services.RPM.Probes {
			if probe == nil {
				continue
			}
			for _, test := range probe.Tests {
				if test != nil && test.NextHop != "" {
					pinned++
				}
			}
		}
	}
	if pinned > ProbeTableCount {
		return fmt.Errorf("services rpm: %d tests configure next-hop pinning, exceeding the reserved probe table band (%d tables %d-%d)",
			pinned, ProbeTableCount, ProbeTableBase, ProbeTableBase+ProbeTableCount-1)
	}
	if pinned > 0 {
		for _, ri := range cfg.RoutingInstances {
			if ri == nil {
				continue
			}
			if ri.TableID >= ProbeTableBase && ri.TableID < ProbeTableBase+ProbeTableCount {
				return fmt.Errorf("routing-instance %q table ID %d collides with the reserved RPM probe table range %d-%d",
					ri.Name, ri.TableID, ProbeTableBase, ProbeTableBase+ProbeTableCount-1)
			}
		}
	}
	return nil
}

func compileDHCPLocalServer(node *Node, dhcp *DHCPServerConfig, isV6 bool) error {
	lsc := &DHCPLocalServerConfig{
		Groups: make(map[string]*DHCPServerGroup),
	}
	if isV6 {
		dhcp.DHCPv6LocalServer = lsc
	} else {
		dhcp.DHCPLocalServer = lsc
	}

	// #1387: the dynamic-dns block is a server-level policy shared by all
	// pools of the family. It can appear under dhcp-local-server and/or
	// dhcpv6-local-server; the typed model carries a single
	// DHCPDynamicDNSConfig (the reconciler walks both families' leases).
	// When BOTH families carry a block we MERGE field-by-field rather than
	// whole-struct overwrite: a partial second block (e.g. only `domain`
	// under v6) must NOT clear the v4 block's Enabled/server/ttl. A field
	// set in either block wins; presence-only `enable` latches on (once any
	// family enables DDNS it stays enabled). See mergeDHCPDynamicDNS.
	if ddnsNode := node.FindChild("dynamic-dns"); ddnsNode != nil {
		if ddns := compileDHCPDynamicDNS(ddnsNode); ddns != nil {
			dhcp.DynamicDNS = mergeDHCPDynamicDNS(dhcp.DynamicDNS, ddns)
		}
	}

	// #1387 (stale-lease-cleanup slice / Path S): the
	// expired-leases-processing block is GLOBAL to the family (Kea renders
	// it per Dhcp4/Dhcp6, never per-subnet), so it attaches to this
	// family's DHCPLocalServerConfig (lsc), NOT to a pool. v4 and v6 are
	// tuned independently. A truly empty/garbage block compiles to nil so
	// it neither forces reclamation on nor renders anything.
	if elpNode := node.FindChild("expired-leases-processing"); elpNode != nil {
		lsc.ExpiredLeases = compileDHCPExpiredLeases(elpNode)
	}

	for _, groupInst := range namedInstances(node.FindChildren("group")) {
		group := &DHCPServerGroup{Name: groupInst.name}

		for _, prop := range groupInst.node.Children {
			switch prop.Name() {
			case "interface":
				if v := nodeVal(prop); v != "" {
					group.Interfaces = append(group.Interfaces, v)
				}
			case "pool":
				poolName := nodeVal(prop)
				if poolName != "" {
					pool := &DHCPPool{Name: poolName}
					poolChildren := prop.Children
					if len(prop.Keys) < 2 && len(prop.Children) > 0 {
						poolChildren = prop.Children[0].Children
					}
					for _, pp := range poolChildren {
						switch pp.Name() {
						case "address-range":
							if len(pp.Keys) >= 5 && pp.Keys[1] == "low" && pp.Keys[3] == "high" {
								pool.RangeLow = pp.Keys[2]
								pool.RangeHigh = pp.Keys[4]
							}
						case "subnet":
							pool.Subnet = nodeVal(pp)
						case "router":
							pool.Router = nodeVal(pp)
						case "dns-server":
							if v := nodeVal(pp); v != "" {
								pool.DNSServers = append(pool.DNSServers, v)
							}
						case "lease-time":
							if v := nodeVal(pp); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									pool.LeaseTime = n
								}
							}
						case "domain-name":
							pool.Domain = nodeVal(pp)
						case "static-binding":
							// #2243: fixed/reserved host bindings. Dual-AST:
							// hierarchical `static-binding <mac> { fixed-address
							// <ip>; host-name <n>; }` packs the MAC into Keys[1]
							// (namedInstances picks it up directly); a flat-set
							// `static-binding <mac> fixed-address <ip>` lands the
							// MAC in Keys[1] too. A bare `static-binding { <mac> {
							// ... } }` block nests the MAC one level down, which
							// namedInstances also handles. Each instance's leaves
							// (fixed-address / host-name) are the instance node's
							// children in both shapes.
							for _, sbInst := range namedInstances([]*Node{pp}) {
								sb := &DHCPStaticBinding{MACAddress: sbInst.name}
								for _, leaf := range sbInst.node.Children {
									switch leaf.Name() {
									case "fixed-address":
										sb.FixedAddress = nodeVal(leaf)
									case "host-name":
										sb.HostName = nodeVal(leaf)
									}
								}
								pool.StaticBindings = append(pool.StaticBindings, sb)
							}
						}
					}
					group.Pools = append(group.Pools, pool)
				}
			}
		}

		lsc.Groups[group.Name] = group
	}
	return nil
}

// mergeDHCPDynamicDNS merges a freshly-compiled dynamic-dns block (src)
// into the existing one (dst), field-by-field, so a partial block under the
// second family does not clobber settings the first family established
// (#1387). dst may be nil (first family seen). A field set in EITHER block
// wins: for strings/ttl, a non-zero src value fills an empty dst field (dst
// keeps its own non-zero value — first-family-wins on a genuine conflict,
// matching compileDHCPDynamicDNS's first-value-wins intra-block rule). The
// presence-only Enabled flag LATCHES: once any family enables DDNS it stays
// enabled (a partial second block can never flip it false). src is non-nil
// (compileDHCPDynamicDNS returned a real block).
func mergeDHCPDynamicDNS(dst, src *DHCPDynamicDNSConfig) *DHCPDynamicDNSConfig {
	if dst == nil {
		return src
	}
	dst.Enabled = dst.Enabled || src.Enabled
	if dst.Domain == "" {
		dst.Domain = src.Domain
	}
	if dst.HostnameSource == "" {
		dst.HostnameSource = src.HostnameSource
	}
	if dst.ConflictPolicy == "" {
		dst.ConflictPolicy = src.ConflictPolicy
	}
	if dst.Backend == "" {
		dst.Backend = src.Backend
	}
	if dst.UpdateServer == "" {
		dst.UpdateServer = src.UpdateServer
	}
	if dst.TSIGKeyName == "" {
		dst.TSIGKeyName = src.TSIGKeyName
	}
	if dst.TSIGAlgorithm == "" {
		dst.TSIGAlgorithm = src.TSIGAlgorithm
	}
	if dst.TSIGSecret == "" {
		dst.TSIGSecret = src.TSIGSecret
	}
	if dst.TTLSeconds == 0 {
		dst.TTLSeconds = src.TTLSeconds
	}
	return dst
}

// dhcpDDNSStringProps are the dynamic-dns leaves that carry a string
// value (everything except the valueless `enable` flag and the integer
// `ttl`). Used by compileDHCPDynamicDNS's internal subtree walker to
// recognize a "<leaf> <value>" pair at any depth regardless of the AST
// shape.
var dhcpDDNSStringProps = map[string]bool{
	"domain":          true,
	"hostname-source": true,
	"conflict-policy": true,
	"backend":         true,
	"update-server":   true,
	"tsig-key":        true,
	"tsig-algorithm":  true,
	"tsig-secret":     true,
}

// compileDHCPDynamicDNS converts a parsed `dynamic-dns` subtree into a
// typed *DHCPDynamicDNSConfig (#1387). It handles BOTH the hierarchical
// shape (`dynamic-dns { enable; ttl 300; domain corp.example.com; }`,
// each leaf a separate child node) and the flat-set shape
// (`set ... dynamic-dns ttl 300`, where SetPath may pack trailing
// property tokens into a single leaf node's Keys). Returns nil for a
// truly empty block so an empty/garbage stanza does not force DDNS on;
// the runtime keys "configured" on a non-nil block AND Enabled.
func compileDHCPDynamicDNS(node *Node) *DHCPDynamicDNSConfig {
	d := &DHCPDynamicDNSConfig{}
	props := map[string]string{}
	enabled := false

	// Walk the subtree. A leaf can appear as a child node (Keys[0]==leaf,
	// value at Keys[1]) or be packed into a parent node's Keys at any
	// depth (e.g. flat-set `dynamic-dns ttl 300 domain x` collapses into
	// one node with Keys=[..., ttl, 300, domain, x]). First value wins so
	// a later malformed re-set cannot clobber a good one.
	var walk func(n *Node, isRoot bool)
	walk = func(n *Node, isRoot bool) {
		start := 0
		if isRoot {
			start = 1 // skip the "dynamic-dns" identifier itself
		}
		for i := start; i < len(n.Keys); i++ {
			k := n.Keys[i]
			switch {
			case k == "enable":
				enabled = true
			case k == "ttl" && i+1 < len(n.Keys):
				if _, ok := props["ttl"]; !ok {
					props["ttl"] = n.Keys[i+1]
				}
				i++
			case dhcpDDNSStringProps[k] && i+1 < len(n.Keys):
				if _, ok := props[k]; !ok {
					props[k] = n.Keys[i+1]
				}
				i++
			}
		}
		for _, c := range n.Children {
			walk(c, false)
		}
	}
	walk(node, true)

	d.Enabled = enabled
	d.Domain = props["domain"]
	d.HostnameSource = props["hostname-source"]
	d.ConflictPolicy = props["conflict-policy"]
	d.Backend = props["backend"]
	d.UpdateServer = props["update-server"]
	d.TSIGKeyName = props["tsig-key"]
	d.TSIGAlgorithm = props["tsig-algorithm"]
	d.TSIGSecret = Secret(props["tsig-secret"])
	if v := props["ttl"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			d.TTLSeconds = n
		}
	}

	// Empty block -> treat as absent (no DDNS). A block with only
	// `enable` is meaningful (defaults apply), so check the union.
	if !d.Enabled && d.Domain == "" && d.HostnameSource == "" &&
		d.ConflictPolicy == "" && d.Backend == "" && d.UpdateServer == "" &&
		d.TSIGKeyName == "" && d.TSIGAlgorithm == "" && d.TSIGSecret == "" &&
		d.TTLSeconds == 0 {
		return nil
	}
	return d
}

// dhcpExpiredLeasesIntProps are the integer-valued expired-leases-processing
// leaves (everything except the valueless `enable` flag). Used by
// compileDHCPExpiredLeases's subtree walker to recognize a "<leaf> <value>"
// pair at any depth regardless of the AST shape.
var dhcpExpiredLeasesIntProps = map[string]bool{
	"reclaim-timer":   true,
	"flush-timer":     true,
	"hold-time":       true,
	"max-leases":      true,
	"max-time":        true,
	"unwarned-cycles": true,
}

// compileDHCPExpiredLeases converts a parsed `expired-leases-processing`
// subtree into a typed *DHCPExpiredLeasesConfig (#1387 stale-lease-cleanup
// slice). Like compileDHCPDynamicDNS it handles BOTH the hierarchical
// shape (`expired-leases-processing { enable; reclaim-timer 10; }`, each
// leaf a separate child node) and the flat-set shape
// (`set ... expired-leases-processing reclaim-timer 10`, where SetPath may
// pack trailing property tokens into a single leaf node's Keys). First
// value wins so a later malformed re-set cannot clobber a good one.
//
// Returns nil for a truly empty/garbage block so an empty stanza neither
// forces reclamation on nor renders anything (closing the
// empty-tree-compiles-non-nil trap). The set/unset distinction for the
// cap knobs (max-leases / max-time) is preserved into the model: 0 is a
// MEANINGFUL Kea value (unlimited) that must render distinctly from unset
// (invariant H2), so a *Set bool latches when the operator supplies the
// key.
func compileDHCPExpiredLeases(node *Node) *DHCPExpiredLeasesConfig {
	c := &DHCPExpiredLeasesConfig{}
	props := map[string]string{}
	enabled := false

	var walk func(n *Node, isRoot bool)
	walk = func(n *Node, isRoot bool) {
		start := 0
		if isRoot {
			start = 1 // skip the "expired-leases-processing" identifier itself
		}
		for i := start; i < len(n.Keys); i++ {
			k := n.Keys[i]
			switch {
			case k == "enable":
				enabled = true
			case dhcpExpiredLeasesIntProps[k] && i+1 < len(n.Keys):
				if _, ok := props[k]; !ok {
					props[k] = n.Keys[i+1]
				}
				i++
			}
		}
		for _, ch := range n.Children {
			walk(ch, false)
		}
	}
	walk(node, true)

	c.Enabled = enabled
	// parseInt sets the field from a decimal prop value when present and
	// well-formed, returning whether the key was present at all (so the
	// caller can distinguish a configured 0 from an unset key for the cap
	// knobs). A garbage value is treated as unset for that field.
	parseInt := func(key string, dst *int) bool {
		v, present := props[key]
		if !present {
			return false
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return false
		}
		*dst = n
		return true
	}
	parseInt("reclaim-timer", &c.ReclaimTimerWait)
	parseInt("flush-timer", &c.FlushReclaimedTimerWait)
	parseInt("hold-time", &c.HoldReclaimedTime)
	c.MaxReclaimLeasesSet = parseInt("max-leases", &c.MaxReclaimLeases)
	c.MaxReclaimTimeSet = parseInt("max-time", &c.MaxReclaimTime)
	parseInt("unwarned-cycles", &c.UnwarnedReclaimCycles)

	// Empty block -> treat as absent (no reclamation block rendered). A
	// block with only `enable` is meaningful (Kea reads {} as "defaults"),
	// so check the union of enable + any configured field.
	if !c.Enabled && c.ReclaimTimerWait == 0 && c.FlushReclaimedTimerWait == 0 &&
		c.HoldReclaimedTime == 0 && !c.MaxReclaimLeasesSet && !c.MaxReclaimTimeSet &&
		c.UnwarnedReclaimCycles == 0 {
		return nil
	}
	return c
}

func compileDynamicAddress(node *Node, sec *SecurityConfig) error {
	if sec.DynamicAddress.FeedServers == nil {
		sec.DynamicAddress.FeedServers = make(map[string]*FeedServer)
	}
	if sec.DynamicAddress.AddressBindings == nil {
		sec.DynamicAddress.AddressBindings = make(map[string]*AddressBinding)
	}

	for _, inst := range namedInstances(node.FindChildren("feed-server")) {
		fs := &FeedServer{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "url":
				fs.URL = nodeVal(prop)
			case "hostname":
				fs.Hostname = nodeVal(prop)
			case "update-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						fs.UpdateInterval = n
					}
				}
			case "hold-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						fs.HoldInterval = n
					}
				}
			case "feed-name":
				fnName := nodeVal(prop)
				if len(prop.Children) > 0 {
					fe := FeedEntry{Name: fnName}
					for _, c := range prop.Children {
						if c.Name() == "path" {
							fe.Path = nodeVal(c)
						}
					}
					fs.FeedEntries = append(fs.FeedEntries, fe)
				} else {
					fs.FeedName = fnName
				}
			}
		}

		sec.DynamicAddress.FeedServers[fs.Name] = fs
	}

	for _, inst := range namedInstances(node.FindChildren("address-name")) {
		ab := &AddressBinding{Name: inst.name}
		if profile := inst.node.FindChild("profile"); profile != nil {
			for _, c := range profile.Children {
				if c.Name() == "feed-name" {
					if fn := nodeVal(c); fn != "" {
						ab.FeedNames = append(ab.FeedNames, fn)
					}
				}
			}
		}
		sec.DynamicAddress.AddressBindings[ab.Name] = ab
	}

	return nil
}

func compileServices(node *Node, svc *ServicesConfig) error {
	if fmNode := node.FindChild("flow-monitoring"); fmNode != nil {
		if err := compileFlowMonitoring(fmNode, svc); err != nil {
			return err
		}
	}
	if rpmNode := node.FindChild("rpm"); rpmNode != nil {
		if err := compileRPM(rpmNode, svc); err != nil {
			return err
		}
	}
	if ipmNode := node.FindChild("ip-monitoring"); ipmNode != nil {
		if err := compileIPMonitoring(ipmNode, svc); err != nil {
			return err
		}
	}
	if node.FindChild("application-identification") != nil {
		svc.ApplicationIdentification = true
	}
	return nil
}

// compileIPMonitoring parses `services ip-monitoring` (#1827 PR-1b).
// Both AST shapes are handled: hierarchical blocks and flat-set replay.
// Two set lines for the same (routing-instance, route) merge into one
// PreferredRoute (next-hop + preferred-metric arrive on separate lines).
func compileIPMonitoring(node *Node, svc *ServicesConfig) error {
	cfg := &IPMonitoringConfig{Policies: make(map[string]*IPMonitoringPolicy)}

	for _, polInst := range namedInstances(node.FindChildren("policy")) {
		pol := &IPMonitoringPolicy{Name: polInst.name}
		routes := make(map[string]*PreferredRoute)
		var order []string

		for _, prop := range polInst.node.Children {
			switch prop.Name() {
			case "match":
				// `match { rpm-probe X; }` or inline `match rpm-probe X;`
				if len(prop.Keys) >= 3 && prop.Keys[1] == "rpm-probe" {
					pol.MatchRPMProbe = prop.Keys[2]
				}
				if c := prop.FindChild("rpm-probe"); c != nil {
					if v := nodeVal(c); v != "" {
						pol.MatchRPMProbe = v
					}
				}
			case "then":
				for _, prNode := range prop.FindChildren("preferred-route") {
					if err := compilePreferredRoutes(prNode, "", pol.Name, routes, &order); err != nil {
						return err
					}
					for _, riInst := range namedInstances(prNode.FindChildren("routing-instance")) {
						if err := compilePreferredRoutes(riInst.node, riInst.name, pol.Name, routes, &order); err != nil {
							return err
						}
					}
				}
			case "hold-down":
				if v := nodeVal(prop); v != "" {
					n, err := strconv.Atoi(v)
					if err != nil || n < 0 {
						return fmt.Errorf("services ip-monitoring policy %q hold-down: invalid value %q", pol.Name, v)
					}
					pol.HoldDownSecs = n
				}
			}
		}

		for _, key := range order {
			pol.PreferredRoutes = append(pol.PreferredRoutes, routes[key])
		}
		cfg.Policies[pol.Name] = pol
	}

	svc.IPMonitoring = cfg
	return nil
}

// compilePreferredRoutes collects `route <cidr> { next-hop X;
// preferred-metric N; }` children of a preferred-route (or its
// routing-instance sub-block), merging repeated lines for the same
// destination.
func compilePreferredRoutes(node *Node, ri, polName string, routes map[string]*PreferredRoute, order *[]string) error {
	for _, rInst := range namedInstances(node.FindChildren("route")) {
		key := ri + "|" + rInst.name
		r := routes[key]
		if r == nil {
			r = &PreferredRoute{RoutingInstance: ri, Destination: rInst.name}
			routes[key] = r
			*order = append(*order, key)
		}
		setMetric := func(v string) error {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return fmt.Errorf("services ip-monitoring policy %q route %s preferred-metric: invalid value %q",
					polName, r.Destination, v)
			}
			r.PreferredMetric = n
			return nil
		}
		// Inline keys: `route 0.0.0.0/0 next-hop 1.2.3.4;`
		keys := rInst.node.Keys
		for i := 2; i+1 < len(keys); i += 2 {
			switch keys[i] {
			case "next-hop":
				r.NextHop = keys[i+1]
			case "preferred-metric":
				if err := setMetric(keys[i+1]); err != nil {
					return err
				}
			}
		}
		// Child-node shape (hierarchical blocks + flat-set replay).
		for _, p := range rInst.node.Children {
			switch p.Name() {
			case "next-hop":
				if v := nodeVal(p); v != "" {
					r.NextHop = v
				}
			case "preferred-metric":
				if v := nodeVal(p); v != "" {
					if err := setMetric(v); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// validateIPMonitoringStrict enforces the #1827 commit checks:
// the matched probe exists, every policy has at least one
// preferred-route, destinations/next-hops are family-consistent, and
// referenced routing instances exist. PR-1b additionally rejected
// `instance-type forwarding` targets; PR-2 lifted that rejection —
// forwarding instances now render into their dedicated kernel table
// (FRR `table <id>`), matching the dataplane's `<ri>.inet.0`, so the
// FRR-vs-dataplane divergence that motivated the fence is fixed.
//
// #1844: a next-hop value that is not an IP literal may instead name a
// DHCP-enabled interface unit (`next-hop ge-0/0/3.0`) — the injected
// route then tracks that unit's DHCP-learned gateway. This function
// also DERIVES the typed-model split for that form (it runs on every
// compile path, strict and lenient alike, so the derivation is present
// after boot Load as well as commit): on success
// PreferredRoute.NextHopInterface is set to the shared DHCPLeaseIfName
// lease key and NextHop is cleared (mutually exclusive). Idempotent:
// an already-derived route is left untouched.
func validateIPMonitoringStrict(cfg *Config) error {
	ipm := cfg.Services.IPMonitoring
	if ipm == nil {
		return nil
	}
	instances := make(map[string]*RoutingInstanceConfig)
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			instances[ri.Name] = ri
		}
	}
	for name, pol := range ipm.Policies {
		if pol == nil {
			continue
		}
		if pol.MatchRPMProbe == "" {
			return fmt.Errorf("services ip-monitoring policy %q: match rpm-probe is required", name)
		}
		if cfg.Services.RPM == nil || cfg.Services.RPM.Probes[pol.MatchRPMProbe] == nil {
			return fmt.Errorf("services ip-monitoring policy %q: match rpm-probe %q does not reference a configured services rpm probe",
				name, pol.MatchRPMProbe)
		}
		if len(pol.PreferredRoutes) == 0 {
			return fmt.Errorf("services ip-monitoring policy %q: at least one then preferred-route route is required", name)
		}
		for _, pr := range pol.PreferredRoutes {
			_, dst, err := net.ParseCIDR(pr.Destination)
			if err != nil {
				return fmt.Errorf("services ip-monitoring policy %q route %q: invalid destination prefix",
					name, pr.Destination)
			}
			switch {
			case pr.NextHopInterface != "":
				// Already derived (idempotent re-validation).
			case net.ParseIP(pr.NextHop) != nil:
				nh := net.ParseIP(pr.NextHop)
				if (dst.IP.To4() == nil) != (nh.To4() == nil) {
					return fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q address family does not match destination",
						name, pr.Destination, pr.NextHop)
				}
			default:
				leaseIface, err := resolveIPMonitoringInterfaceNextHop(cfg, name, pr, dst)
				if err != nil {
					return err
				}
				pr.NextHopInterface = leaseIface
				pr.NextHop = ""
			}
			if pr.RoutingInstance != "" {
				if _, ok := instances[pr.RoutingInstance]; !ok {
					return fmt.Errorf("services ip-monitoring policy %q route %s: routing-instance %q does not exist",
						name, pr.Destination, pr.RoutingInstance)
				}
			}
		}
	}
	return nil
}

// resolveIPMonitoringInterfaceNextHop classifies a non-IP-literal
// preferred-route next-hop value as a DHCP interface unit reference
// (#1844 plan §4.1) and returns the Linux lease key the runtime
// resolver will look up. The accepted form is `<ifd>.<unit-number>`
// where <ifd> is EXACTLY an interface name as configured under
// `interfaces` (Junos form, e.g. ge-0/0/3 — the dashed Linux form is
// not accepted) and <unit-number> is a configured unit of it with
// `family inet dhcp`. Restrictions (each with a distinct error):
//
//   - a bare ifd without `.unit` is rejected;
//   - management interfaces (fxp*/em*/fab* — the name classes the
//     daemon binds to the mgmt VRF) are rejected: collectDHCPRoutes
//     deliberately excludes mgmt leases from FRR, and an overlay route
//     through the mgmt gateway would leak management routing into the
//     default table;
//   - inet6 destinations are rejected (v4-only: DHCPv6 gateways are
//     RA-discovered link-locals and the snapshot RouteSnapshot has no
//     device field — v6 support is a wire-protocol follow-up);
//   - a unit without `family inet dhcp` is rejected (the route tracks
//     a DHCP-learned gateway by definition);
//   - tunnel and loopback interfaces are rejected explicitly (Codex
//     PR #1851 review): the interface compiler sets unit.DHCP from
//     the AST without an interface-class guard, so `family inet dhcp`
//     on a gr-/ip-/st0/lo0/fti unit DOES compile — a DHCP client on a
//     tunnel/loopback can never acquire a lease, so accepting it here
//     would only manufacture a permanently-unresolvable route.
func resolveIPMonitoringInterfaceNextHop(cfg *Config, polName string, pr *PreferredRoute, dst *net.IPNet) (string, error) {
	val := pr.NextHop
	if cfg.Interfaces.Interfaces[val] != nil {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: interface-typed next-hop requires <ifd>.<unit> (got bare interface %q)",
			polName, pr.Destination, val)
	}
	idx := strings.LastIndex(val, ".")
	if idx <= 0 || idx == len(val)-1 {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q is not a valid IP address or DHCP interface unit",
			polName, pr.Destination, val)
	}
	ifdName, unitStr := val[:idx], val[idx+1:]
	unitNum, err := strconv.Atoi(unitStr)
	ifc := cfg.Interfaces.Interfaces[ifdName]
	if err != nil || unitNum < 0 || ifc == nil {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q is not a valid IP address or DHCP interface unit (interface units use the configured Junos name, e.g. ge-0/0/3.0)",
			polName, pr.Destination, val)
	}
	if strings.HasPrefix(ifdName, "fxp") || strings.HasPrefix(ifdName, "em") ||
		strings.HasPrefix(ifdName, "fab") {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q names a management interface; management leases cannot back an ip-monitoring preferred route",
			polName, pr.Destination, val)
	}
	if dst.IP.To4() == nil {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: interface-typed next-hop %q is inet-only (DHCPv6 gateways are RA-derived link-locals; inet6 support is a follow-up)",
			polName, pr.Destination, val)
	}
	unit := ifc.Units[unitNum]
	if unit == nil {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q: interface %s has no unit %d",
			polName, pr.Destination, val, ifdName, unitNum)
	}
	if ifc.Tunnel != nil || unit.Tunnel != nil ||
		strings.HasPrefix(ifdName, "lo") || strings.HasPrefix(ifdName, "st") ||
		strings.HasPrefix(ifdName, "gr-") || strings.HasPrefix(ifdName, "ip-") ||
		strings.HasPrefix(ifdName, "fti") {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: next-hop %q names a tunnel or loopback interface; a DHCP-tracked next-hop requires a broadcast interface unit",
			polName, pr.Destination, val)
	}
	if !unit.DHCP {
		return "", fmt.Errorf("services ip-monitoring policy %q route %s: interface-typed next-hop requires family inet dhcp on %s unit %d",
			polName, pr.Destination, ifdName, unitNum)
	}
	return DHCPLeaseIfName(ifdName, unit), nil
}

func compileRPM(node *Node, svc *ServicesConfig) error {
	rpmCfg := &RPMConfig{Probes: make(map[string]*RPMProbe)}
	defaultProbeLimit := 0

	if probeLimitNode := node.FindChild("probe-limit"); probeLimitNode != nil {
		if v := nodeVal(probeLimitNode); v != "" {
			n, err := parseRPMRootPositiveInt("probe-limit", v)
			if err != nil {
				return err
			}
			defaultProbeLimit = n
		}
	}

	for _, probeInst := range namedInstances(node.FindChildren("probe")) {
		probe := &RPMProbe{
			Name:  probeInst.name,
			Tests: make(map[string]*RPMTest),
		}

		for _, testInst := range namedInstances(probeInst.node.FindChildren("test")) {
			test := &RPMTest{Name: testInst.name}

			for _, prop := range testInst.node.Children {
				switch prop.Name() {
				case "probe-type":
					test.ProbeType = nodeVal(prop)
				case "target":
					// Handle "target 1.1.1.1;", the canonical Junos form
					// "target address 1.1.1.1;" (#1827), and
					// "target url http://1.1.1.1;" — in both inline-keys
					// and child-node AST shapes.
					if len(prop.Keys) >= 3 && (prop.Keys[1] == "url" || prop.Keys[1] == "address") {
						test.Target = prop.Keys[2]
					} else if urlChild := prop.FindChild("url"); urlChild != nil {
						test.Target = nodeVal(urlChild)
					} else if addrChild := prop.FindChild("address"); addrChild != nil {
						test.Target = nodeVal(addrChild)
					} else {
						test.Target = nodeVal(prop)
					}
				case "source-address":
					test.SourceAddress = nodeVal(prop)
				case "routing-instance":
					test.RoutingInstance = nodeVal(prop)
				case "destination-interface":
					test.DestinationInterface = nodeVal(prop)
				case "next-hop":
					test.NextHop = nodeVal(prop)
				case "probe-interval":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "probe-interval", v)
						if err != nil {
							return err
						}
						test.ProbeInterval = n
					}
				case "probe-count":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "probe-count", v)
						if err != nil {
							return err
						}
						test.ProbeCount = n
					}
				case "test-interval":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "test-interval", v)
						if err != nil {
							return err
						}
						test.TestInterval = n
					}
				case "thresholds":
					for _, th := range prop.Children {
						if th.Name() == "successive-loss" {
							if v := nodeVal(th); v != "" {
								n, err := parseRPMPositiveInt(probe.Name, test.Name, "thresholds successive-loss", v)
								if err != nil {
									return err
								}
								test.ThresholdSuccessive = n
							}
						}
					}
				case "probe-limit":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "probe-limit", v)
						if err != nil {
							return err
						}
						test.ProbeLimit = n
					}
				case "destination-port":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "destination-port", v)
						if err != nil {
							return err
						}
						test.DestPort = n
					}
				}
			}

			if test.ProbeLimit == 0 && defaultProbeLimit > 0 {
				test.ProbeLimit = defaultProbeLimit
			}

			if err := validateRPMTest(probe.Name, test); err != nil {
				return err
			}

			probe.Tests[test.Name] = test
		}

		rpmCfg.Probes[probe.Name] = probe
	}

	svc.RPM = rpmCfg
	return nil
}

func compileFlowMonitoring(node *Node, svc *ServicesConfig) error {
	fm := &FlowMonitoringConfig{}

	if v9Node := node.FindChild("version9"); v9Node != nil {
		v9cfg := &NetFlowV9Config{
			Templates: make(map[string]*NetFlowV9Template),
		}
		for _, tmplInst := range namedInstances(v9Node.FindChildren("template")) {
			tmpl := &NetFlowV9Template{Name: tmplInst.name}
			for _, prop := range tmplInst.node.Children {
				switch prop.Name() {
				case "flow-active-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowActiveTimeout = n
						}
					}
				case "flow-inactive-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowInactiveTimeout = n
						}
					}
				case "template-refresh-rate":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.TemplateRefreshRate = n
						}
					}
					if secNode := prop.FindChild("seconds"); secNode != nil {
						if v := nodeVal(secNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tmpl.TemplateRefreshRate = n
							}
						}
					}
				case "ipv4-template", "ipv6-template":
					tmpl.ExportExtensions = append(tmpl.ExportExtensions, parseExportExtensions(prop)...)
				}
			}
			v9cfg.Templates[tmpl.Name] = tmpl
		}
		fm.Version9 = v9cfg
	}

	if ipfixNode := node.FindChild("version-ipfix"); ipfixNode != nil {
		ipfixCfg := &NetFlowIPFIXConfig{
			Templates: make(map[string]*NetFlowIPFIXTemplate),
		}
		for _, tmplInst := range namedInstances(ipfixNode.FindChildren("template")) {
			tmpl := &NetFlowIPFIXTemplate{Name: tmplInst.name}
			for _, prop := range tmplInst.node.Children {
				switch prop.Name() {
				case "flow-active-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowActiveTimeout = n
						}
					}
				case "flow-inactive-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowInactiveTimeout = n
						}
					}
				case "template-refresh-rate":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.TemplateRefreshRate = n
						}
					}
					if secNode := prop.FindChild("seconds"); secNode != nil {
						if v := nodeVal(secNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tmpl.TemplateRefreshRate = n
							}
						}
					}
				case "ipv4-template", "ipv6-template":
					tmpl.ExportExtensions = append(tmpl.ExportExtensions, parseExportExtensions(prop)...)
				}
			}
			ipfixCfg.Templates[tmpl.Name] = tmpl
		}
		fm.VersionIPFIX = ipfixCfg
	}

	svc.FlowMonitoring = fm
	return nil
}

func compileForwardingOptions(node *Node, fo *ForwardingOptionsConfig) error {
	sampNode := node.FindChild("sampling")
	if sampNode != nil {
		if err := compileSampling(sampNode, fo); err != nil {
			return err
		}
	}

	relayNode := node.FindChild("dhcp-relay")
	if relayNode != nil {
		if err := compileDHCPRelay(relayNode, fo); err != nil {
			return err
		}
	}

	// Parse family { inet6 { mode <flow-based|packet-based> } }
	if famNode := node.FindChild("family"); famNode != nil {
		if inet6Node := famNode.FindChild("inet6"); inet6Node != nil {
			if modeNode := inet6Node.FindChild("mode"); modeNode != nil {
				fo.FamilyInet6Mode = nodeVal(modeNode)
			}
		}
	}

	if pmNode := node.FindChild("port-mirroring"); pmNode != nil {
		if err := compilePortMirroring(pmNode, fo); err != nil {
			return err
		}
	}

	// #2008 H13 Stage 1: presence flag (mirrors security power-mode-disable).
	if node.FindChild("allow-dataplane-sleep") != nil {
		fo.AllowDataplaneSleep = true
	}

	return nil
}

func compilePortMirroring(node *Node, fo *ForwardingOptionsConfig) error {
	pm := &PortMirroringConfig{
		Instances: make(map[string]*PortMirrorInstance),
	}

	for _, inst := range namedInstances(node.FindChildren("instance")) {
		mi := &PortMirrorInstance{Name: inst.name}

		if inputNode := inst.node.FindChild("input"); inputNode != nil {
			if rateNode := inputNode.FindChild("rate"); rateNode != nil {
				if v := nodeVal(rateNode); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						mi.InputRate = n
					}
				}
			}
			if ingressNode := inputNode.FindChild("ingress"); ingressNode != nil {
				for _, child := range ingressNode.Children {
					if child.Name() == "interface" {
						if v := nodeVal(child); v != "" {
							mi.Input = append(mi.Input, v)
						}
					}
				}
			}
		}

		if outputNode := inst.node.FindChild("output"); outputNode != nil {
			if ifNode := outputNode.FindChild("interface"); ifNode != nil {
				mi.Output = nodeVal(ifNode)
			}
		}

		pm.Instances[mi.Name] = mi
	}

	fo.PortMirroring = pm
	return nil
}

func compileSampling(node *Node, fo *ForwardingOptionsConfig) error {
	sc := &SamplingConfig{
		Instances: make(map[string]*SamplingInstance),
	}

	for _, sampInst := range namedInstances(node.FindChildren("instance")) {
		inst := &SamplingInstance{Name: sampInst.name}

		inputNode := sampInst.node.FindChild("input")
		if inputNode != nil {
			for _, prop := range inputNode.Children {
				if prop.Name() == "rate" {
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							inst.InputRate = n
						}
					}
				}
			}
		}

		for _, familyNode := range sampInst.node.FindChildren("family") {
			var afNodes []*Node
			if len(familyNode.Keys) >= 2 {
				afNodes = append(afNodes, familyNode)
			} else {
				afNodes = append(afNodes, familyNode.Children...)
			}
			for _, afNode := range afNodes {
				afName := afNode.Keys[0]
				if len(afNode.Keys) >= 2 {
					afName = afNode.Keys[1]
				}

				sf := compileSamplingFamily(afNode)
				switch afName {
				case "inet":
					inst.FamilyInet = sf
				case "inet6":
					inst.FamilyInet6 = sf
				}
			}
		}

		sc.Instances[inst.Name] = inst
	}

	fo.Sampling = sc
	return nil
}

func compileSamplingFamily(node *Node) *SamplingFamily {
	sf := &SamplingFamily{}

	outputNode := node.FindChild("output")
	if outputNode == nil {
		return sf
	}

	for _, child := range outputNode.Children {
		switch child.Name() {
		case "flow-server":
			fsAddr := nodeVal(child)
			if fsAddr != "" {
				fs := &FlowServer{Address: fsAddr}
				fsChildren := child.Children
				if len(child.Keys) < 2 && len(child.Children) > 0 {
					fsChildren = child.Children[0].Children
				}
				for _, prop := range fsChildren {
					switch prop.Name() {
					case "port":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								fs.Port = n
							}
						}
					case "version9-template":
						fs.Version9Template = nodeVal(prop)
						fs.Version = FlowServerVersion9
					case "version9":
						// Hierarchical: version9 { template { <name>; } }
						fs.Version = FlowServerVersion9
						if tmplNode := prop.FindChild("template"); tmplNode != nil {
							// Template name is either nodeVal or first child's name
							if v := nodeVal(tmplNode); v != "" {
								fs.Version9Template = v
							} else if len(tmplNode.Children) > 0 {
								fs.Version9Template = tmplNode.Children[0].Name()
							}
						}
					case "version-ipfix-template":
						fs.VersionIPFIXTemplate = nodeVal(prop)
						fs.Version = FlowServerVersionIPFIX
					case "version-ipfix":
						// Hierarchical: version-ipfix { template { <name>; } }
						// Junos binds each flow-server to exactly one export
						// version; the per-server version-ipfix selector routes
						// THIS collector to the IPFIX exporter only (#2136).
						fs.Version = FlowServerVersionIPFIX
						if tmplNode := prop.FindChild("template"); tmplNode != nil {
							if v := nodeVal(tmplNode); v != "" {
								fs.VersionIPFIXTemplate = v
							} else if len(tmplNode.Children) > 0 {
								fs.VersionIPFIXTemplate = tmplNode.Children[0].Name()
							}
						}
					case "source-address":
						sf.SourceAddress = nodeVal(prop)
					}
				}
				sf.FlowServers = append(sf.FlowServers, fs)
			}
		case "inline-jflow":
			sf.InlineJflow = true
			if saNode := child.FindChild("source-address"); saNode != nil {
				sf.InlineJflowSourceAddress = nodeVal(saNode)
			}
			// Also handle inline keys: "inline-jflow source-address X"
			for i := 1; i < len(child.Keys)-1; i++ {
				if child.Keys[i] == "source-address" {
					sf.InlineJflowSourceAddress = child.Keys[i+1]
				}
			}
		}
	}

	return sf
}

func compileDHCPRelay(node *Node, fo *ForwardingOptionsConfig) error {
	relay := &DHCPRelayConfig{
		ServerGroups: make(map[string]*DHCPRelayServerGroup),
		Groups:       make(map[string]*DHCPRelayGroup),
	}

	for _, sgInst := range namedInstances(node.FindChildren("server-group")) {
		sg := relay.ServerGroups[sgInst.name]
		if sg == nil {
			sg = &DHCPRelayServerGroup{Name: sgInst.name}
			relay.ServerGroups[sg.Name] = sg
		}
		// Inline keys (#1797 dual-AST): "server-group sg1 10.1.1.1;" packs
		// the server addresses into Keys[2:].
		for i := 2; i < len(sgInst.node.Keys); i++ {
			sg.Servers = append(sg.Servers, sgInst.node.Keys[i])
		}
		// Block form: every child is a server address; a child line may
		// itself carry several addresses in its Keys (#1813).
		for _, child := range sgInst.node.Children {
			sg.Servers = append(sg.Servers, child.Keys...)
		}
	}

	for _, gInst := range namedInstances(node.FindChildren("group")) {
		g := relay.Groups[gInst.name]
		if g == nil {
			g = &DHCPRelayGroup{Name: gInst.name}
			relay.Groups[g.Name] = g
		}
		// Inline keys (#1797 dual-AST): "group lan interface ge-0/0/0.0;"
		// packs the properties into Keys[2:].
		keys := gInst.node.Keys
		for i := 2; i < len(keys); i++ {
			switch keys[i] {
			case "interface":
				// Multi-value (#1813): consume every following token up
				// to the next recognized property keyword —
				// `group lan interface [ a b ];` packs all interfaces
				// inline. `overrides` MUST be a boundary keyword
				// (#2076) so a flat-set
				// `group g interface ge-0/0/0.0 overrides always-broadcast`
				// does not swallow `overrides`/`always-broadcast` into
				// the interface list.
				for i+1 < len(keys) && keys[i+1] != "interface" &&
					keys[i+1] != "active-server-group" &&
					keys[i+1] != "overrides" {
					i++
					g.Interfaces = append(g.Interfaces, keys[i])
				}
			case "active-server-group":
				if i+1 < len(keys) {
					i++
					g.ActiveServerGroup = keys[i]
				}
			case "overrides":
				// Inline flat-set spelling (#2076):
				// `group g overrides always-broadcast`. Consume the
				// override sub-keywords until the next group property.
				for i+1 < len(keys) && keys[i+1] != "interface" &&
					keys[i+1] != "active-server-group" &&
					keys[i+1] != "overrides" {
					i++
					if keys[i] == "always-broadcast" {
						g.AlwaysBroadcast = true
					}
				}
			}
		}
		for _, prop := range gInst.node.Children {
			switch prop.Name() {
			case "interface":
				// Multi-value spellings (#1813): bracketed
				// `interface [ a b ];` packs all interfaces into
				// Keys[1:] (flat-set replay may carry trailing values
				// as children); braced block `interface { a; b; }`
				// holds one child per interface. nodeVal kept only the
				// first of each.
				for _, k := range prop.Keys[1:] {
					g.Interfaces = append(g.Interfaces, k)
				}
				for _, child := range prop.Children {
					if v := child.Name(); v != "" {
						g.Interfaces = append(g.Interfaces, v)
					}
				}
			case "active-server-group":
				g.ActiveServerGroup = nodeVal(prop)
			case "overrides":
				// Block form (#2076): `overrides { always-broadcast; }`.
				// always-broadcast may also ride in Keys[1:] when the
				// override block collapses to a single inline value.
				if prop.FindChild("always-broadcast") != nil {
					g.AlwaysBroadcast = true
				}
				for _, k := range prop.Keys[1:] {
					if k == "always-broadcast" {
						g.AlwaysBroadcast = true
					}
				}
			}
		}
	}

	fo.DHCPRelay = relay
	return nil
}

func compileEventOptions(node *Node, policies *[]*EventPolicy) error {
	for _, pInst := range namedInstances(node.FindChildren("policy")) {
		ep := &EventPolicy{
			Name: pInst.name,
		}

		for _, child := range pInst.node.Children {
			switch child.Name() {
			case "events":
				// Hierarchical: events [ evt1 evt2 ]; → Keys = ["events", "evt1", "evt2"]
				// Hierarchical: events evt1;          → Keys = ["events", "evt1"]
				// Brackets are stripped by the lexer, so just take Keys[1:]
				for i := 1; i < len(child.Keys); i++ {
					ep.Events = append(ep.Events, child.Keys[i])
				}
				// Flat set format: children are individual event name nodes
				for _, evtChild := range child.Children {
					ep.Events = append(ep.Events, evtChild.Name())
				}
			case "within":
				w := &EventWithin{}
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						w.Seconds = n
					}
				}
				if trigNode := child.FindChild("trigger"); trigNode != nil {
					// trigger on N or trigger until N
					for i := 1; i < len(trigNode.Keys)-1; i++ {
						switch trigNode.Keys[i] {
						case "on":
							if n, err := strconv.Atoi(trigNode.Keys[i+1]); err == nil {
								w.TriggerOn = n
							}
						case "until":
							if n, err := strconv.Atoi(trigNode.Keys[i+1]); err == nil {
								w.TriggerUntil = n
							}
						}
					}
					// Also check children
					if onNode := trigNode.FindChild("on"); onNode != nil {
						if v := nodeVal(onNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								w.TriggerOn = n
							}
						}
					}
					if untilNode := trigNode.FindChild("until"); untilNode != nil {
						if v := nodeVal(untilNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								w.TriggerUntil = n
							}
						}
					}
				}
				ep.WithinClauses = append(ep.WithinClauses, w)
			case "attributes-match":
				// Each child is a match line like "ping_test_failed.test-owner matches Comcast"
				for _, amChild := range child.Children {
					// Reconstruct the match expression from keys
					ep.AttributesMatch = append(ep.AttributesMatch, strings.Join(amChild.Keys, " "))
				}
			case "then":
				if ccNode := child.FindChild("change-configuration"); ccNode != nil {
					if cmdsNode := ccNode.FindChild("commands"); cmdsNode != nil {
						for _, cmdChild := range cmdsNode.Children {
							ep.ThenCommands = append(ep.ThenCommands, cmdChild.Name())
						}
					}
				}
			}
		}

		*policies = append(*policies, ep)
	}
	return nil
}

// compileBridgeDomains parses the bridge-domains AST section into typed BridgeDomainConfig structs.
func compileBridgeDomains(node *Node, bds *[]*BridgeDomainConfig) error {
	for _, child := range node.Children {
		if child.IsLeaf {
			continue
		}
		bdName := child.Name()
		bd := &BridgeDomainConfig{
			Name: bdName,
		}

		// Collect VLAN IDs — multi-value leaf: each "vlan-id-list" child is a separate leaf
		for _, vlanNode := range child.FindChildren("vlan-id-list") {
			valStr := nodeVal(vlanNode)
			if valStr == "" {
				continue
			}
			v, err := strconv.Atoi(valStr)
			if err != nil {
				return fmt.Errorf("bridge-domain %s: invalid vlan-id-list value %q: %w", bdName, valStr, err)
			}
			if v < 1 || v > 4094 {
				return fmt.Errorf("bridge-domain %s: vlan-id %d out of range (1-4094)", bdName, v)
			}
			bd.VlanIDs = append(bd.VlanIDs, v)
		}

		// Routing interface (e.g. "irb.0")
		if riNode := child.FindChild("routing-interface"); riNode != nil {
			bd.RoutingInterface = nodeVal(riNode)
		}

		// Domain type
		if dtNode := child.FindChild("domain-type"); dtNode != nil {
			bd.DomainType = nodeVal(dtNode)
		}

		*bds = append(*bds, bd)
	}
	return nil
}
