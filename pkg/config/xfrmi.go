package config

import (
	"fmt"
	"strconv"
	"strings"
)

// secureTunnelIndex parses a secure-tunnel BASE name (`st<N>`, no unit
// suffix) into its index, reporting ok=false for every name that is NOT a
// secure tunnel.
//
// This is the ONE range rule for the `st` namespace, and it is deliberately
// unexported: XFRMIfNameAndID (which builds the device) and
// IsSecureTunnelIfName (which classifies it) both call it, so the two can no
// longer disagree about what an `st` name is.
//
// #6691: they DID disagree. IsSecureTunnelIfName ran a bare strconv.Atoi with
// no bounds, so `st-3` and `st65536` classified as secure tunnels while
// XFRMIfNameAndID refuses to derive an if_id for either (negative index; index
// >= 0x10000 would overflow the 16-bit index field of `stIndex<<16 | unit+1`).
// Interface names are wildcard-authorable with no `st` reservation
// (schema_interfaces.go), so `st65536` is a perfectly ordinary data interface —
// and classifying it as a secure tunnel dropped it from the userspace ingress
// map, the AF_XDP binding plan and the RSS allowlist. That is a traffic outage
// on a valid interface, produced by a classifier that admitted names the
// constructor rejects.
//
// The sign is accepted because strconv.Atoi accepts it: `st+5` parses to index
// 5 and DOES yield a device, so it must classify as a secure tunnel. `st-3`
// parses to -3 and yields nothing, so it must not. The Rust mirror
// (is_secure_tunnel_ifname, userspace-dp/src/server/helpers/planning.rs) uses
// `parse::<i64>()` plus the identical bounds for exactly this reason —
// `str::parse` and Atoi agree on the sign forms.
func secureTunnelIndex(base string) (int, bool) {
	if len(base) < 3 || base[:2] != "st" {
		return 0, false
	}
	idx, err := strconv.Atoi(base[2:])
	if err != nil || idx < 0 || idx >= 0x10000 {
		return 0, false
	}
	return idx, true
}

// XFRMIfNameAndID resolves a secure-tunnel bind-interface to the Linux xfrmi
// device name and a stable XFRM if_id.
func XFRMIfNameAndID(bindIface string) (string, uint32) {
	if bindIface == "" {
		return "", 0
	}

	parts := strings.SplitN(bindIface, ".", 2)
	stIndex, ok := secureTunnelIndex(parts[0])
	if !ok {
		return "", 0
	}

	unit := 0
	if len(parts) == 2 {
		parsed, err := strconv.Atoi(parts[1])
		if err != nil || parsed < 0 || parsed >= 0xffff {
			return "", 0
		}
		unit = parsed
	}

	ifID := uint32(stIndex)<<16 | uint32(unit+1)
	if ifID == 0 {
		return "", 0
	}

	return LinuxIfName(bindIface), ifID
}

// IsSecureTunnelIfName reports whether an interface BASE name (no unit
// suffix) is a secure-tunnel interface — `st<N>` for an N that yields a
// usable XFRM if_id.
//
// This is the shared predicate behind the "do not unit-zero-collapse a secure
// tunnel" rule. A secure tunnel is materialized by the xfrmi reconciler
// (pkg/routing/xfrm.go) under exactly `LinuxIfName(bindInterface)` — the
// AUTHORED string. It is NOT "the dotted ref verbatim", as an earlier revision
// of this comment said: `bind-interface st0.0` creates a netdev named `st0.0`
// but `bind-interface st0` creates one named `st0`, and the unit ref is
// `st0.0` in both cases. The name therefore cannot be derived from the ref at
// all — see SecureTunnelUnitNetdev, which reads it back from the config.
//
// It is NOT true that every resolver calls it. Two live sites in
// pkg/dataplane/compiler_iface.go still derive the netdev from the ref, and
// both are reached on the userspace path (loader.go CompileConfig →
// compiler.go compileZones):
//
//	:72   resolveInterfaceRef          physName = config.LinuxIfName(ref)
//	:757  buildInterfaceNetworkdModels XFRMIfNameAndID("<ifName>.<unit>")
//
// That file calls SecureTunnelUnitNetdev zero times. The migration is 3 of 5
// resolvers, tracked as #6728-#6731, and userspace-dp/src/server/README.md
// scopes it correctly — this comment is the one that overstated it. Do not
// restore the absolute here without re-counting the call sites; an unqualified
// "every" in a doc is what a later reader will rely on instead of grepping.
//
// Callers of the PREDICATE: SecureTunnelUnitNetdev (below) and
// userspaceSkipsIngressInterface (pkg/dataplane/userspace/maps_sync.go), whose
// Rust mirror is is_secure_tunnel_ifname. Before #5619 the dataplane copy
// silently lacked the resolution rule, so a secure-tunnel unit resolved to a
// nonexistent netdev, reported ifindex 0 / MTU 0 / no addresses, and fell out
// of every ifindex-keyed dataplane set.
//
// Scope: this is the BASE-name test, and it answers exactly one question —
// "would XFRMIfNameAndID build an xfrmi for this base?". It shares
// secureTunnelIndex with that constructor, so the two cannot drift.
//
// #6691 folded the range in, which is a behaviour change and the point of the
// fix: the earlier revision ran a bare Atoi with no bounds and so classified
// `st-3` and `st65536` as secure tunnels even though XFRMIfNameAndID creates no
// device for either. Interface names are wildcard-authorable and nothing
// reserves the `st` prefix, so `st65536` is an ordinary data interface — and
// mis-classifying it removed it from the ingress-adjudication map, the AF_XDP
// binding plan and the RSS allowlist. A classifier that admits names the
// constructor rejects does not "stay a pure name-shape question"; it takes a
// live interface out of the dataplane.
//
// This does NOT bound the UNIT (`st0.70000`): the unit lives on the ref, not on
// the base, and every caller passes a base. Callers that need the unit bounded
// go through XFRMIfNameAndID, which checks it.
func IsSecureTunnelIfName(base string) bool {
	_, ok := secureTunnelIndex(base)
	return ok
}

// SecureTunnelUnitNetdev resolves the kernel netdev for a secure-tunnel UNIT
// ref (`st<N>.<unit>`), and is the SINGLE resolver behind that rule — not a
// rule restated in each caller and asserted to agree.
//
// Returns ok=false when the ref is not a secure-tunnel unit, which is the
// signal for the caller to fall through to its ordinary resolution. It never
// returns ok=true with an empty name.
//
// Callers: ResolveKernelIfName (types.go), snapshotLinuxName
// (pkg/dataplane/userspace/interfaces.go) and junosHostLinuxName
// (junos_host_deny.go).
//
// #6691: junosHostLinuxName is why this exists as a function rather than three
// copies. It resolves the iifname scope for the `to-zone junos-host ... deny`
// nft rules, and it did NOT have the rule. Before #5619 that was harmless —
// both sides collapsed `st0.0` to `st0` and agreed on a wrong name. Adding the
// rule to the snapshot alone made them disagree on a RIGHT one: the snapshot
// said `st0.0` (the device the xfrmi reconciler actually creates) while the nft
// renderer still emitted `iifname st0`, so with `bind-interface st0.0` a
// junos-host deny was scoped to a netdev that does not exist and the decrypted
// traffic — arriving on `st0.0` — never matched it. A security guard that
// cannot fire.
func (c *Config) SecureTunnelUnitNetdev(ref string) (string, bool) {
	base, _, hasUnit := strings.Cut(ref, ".")
	if !hasUnit || !IsSecureTunnelIfName(base) {
		return "", false
	}
	if dev, found := c.SecureTunnelNetdevForRef(ref); found {
		return dev, true
	}
	// No VPN binds this unit's if_id, so the xfrmi reconciler creates no
	// device for it. The verbatim dotted ref names nothing on the box, which
	// is the honest answer — the unit-0 collapse would instead alias the row
	// onto `st<N>`, a name that is equally absent but LOOKS resolvable.
	return LinuxIfName(ref), true
}

// SecureTunnelNetdevForRef returns the Linux netdev the xfrmi reconciler
// creates for a secure-tunnel UNIT reference (e.g. "st0.0"), resolved from the
// AUTHORED `bind-interface` string rather than reconstructed from the ref.
//
// This distinction is the whole point. The reconciler creates the device as
// `LinuxIfName(bindInterface)` VERBATIM, and a bare `st0` and an explicit
// `st0.0` derive the SAME XFRM if_id under DIFFERENT device names — stated
// outright in pkg/routing/xfrm.go:
//
//	"a bare "st0" and an explicit "st0.0" both yield if_id 1 ... under
//	 DIFFERENT device names ("st0" vs "st0.0")"
//
// So the netdev name simply CANNOT be derived from the unit ref: `st0.0` is
// the device for `bind-interface st0.0` and `st0` is the device for
// `bind-interface st0`, and the ref is identical in both cases. It has to be
// read back from whichever string the operator actually authored.
//
// The if_id is the join key that makes that lookup well-defined, and
// XFRMIfNameAndID is the single source of truth for both halves of it.
// Reconstructing a name that another component owns is exactly what caused the
// #5619 drift; doing it again inside the fix would be the same mistake one
// level down.
//
// Returns ("", false) when no configured VPN binds this ref's if_id — then no
// xfrmi device exists for the unit at all and the caller keeps its own
// fallback, rather than this inventing a name for a device nobody creates.
//
// FAILS CLOSED under an if_id collision — two DISTINCT bind-interface strings
// deriving one if_id (e.g. `st0` and `st0.0`) resolve to NOTHING, not to a
// winner. #6691: an earlier revision picked the lexicographically smallest name
// "for determinism", which is the wrong contract. pkg/routing/xfrm.go treats a
// collision as unresolvable and deletes BOTH devices from its desired set
// ("refusing to create either (cross-VPN leak / EEXIST risk)"), so on a box in
// that state NEITHER name exists. Naming one of them anyway does not make the
// resolver deterministic-and-correct; it makes it deterministically WRONG, and
// it attaches forwarding state to a device the reconciler has guaranteed is
// absent (or, worse, to a stale leftover under that name).
//
// Two VPNs authoring the SAME bind-interface string are not a collision — one
// name, one device — and routing programs it. This mirrors that: only DISTINCT
// names for one if_id fail.
//
// Strict commit rejects such a config (#2933) and apply refuses it (#2909), so
// this governs only the tolerant-load path — which is precisely the path that
// must not invent a device.
func (c *Config) SecureTunnelNetdevForRef(ref string) (string, bool) {
	if c == nil {
		return "", false
	}
	_, wantID := XFRMIfNameAndID(ref)
	if wantID == 0 {
		return "", false
	}
	best := ""
	for _, vpn := range c.Security.IPsec.VPNs {
		if vpn == nil || vpn.BindInterface == "" {
			continue
		}
		name, id := XFRMIfNameAndID(vpn.BindInterface)
		if id != wantID || name == "" {
			continue
		}
		if best != "" && name != best {
			// Distinct names, one if_id: routing creates neither. Order of
			// discovery does not matter — any iteration order reaches this
			// branch once two distinct names have been seen, so the false
			// result is a pure function of the config.
			return "", false
		}
		best = name
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// ValidateSecureTunnelBindInterface reports whether a `security ipsec vpn
// <name> bind-interface` value is a canonical secure-tunnel interface — the
// only shape the route-based-VPN datapath can bind. The accepted lexical form
// is st<N> or st<N>.<unit> (e.g. st0, st0.1); XFRMIfNameAndID resolves every
// other name to if_id 0, which the pkg/routing reconciler treats as "invalid
// bind-interface name" and creates NO XFRM device for. Such a config commits
// successfully yet the VPN is silently DOWN (#5297).
//
// The if_id-0 sentinel from XFRMIfNameAndID is the authoritative
// "creates no XFRM device" signal; the message states the canonical lexical
// requirement so the operator sees an actionable error rather than an opaque
// id reference.
//
// Used both as the #1319 typed-leaf commit-check validator on the
// `bind-interface` schema leaf (schema_security.go) and — mirrored via
// XFRMIfNameAndID's if_id-0 check — by the compiled-config strict gate in
// compiler_ipsec_bindiface.go, which additionally catches group-expanded /
// packed forms the schema layer can miss (#1960 layered-defense doctrine).
func ValidateSecureTunnelBindInterface(raw string, _ *Config) error {
	name := strings.TrimSpace(raw)
	if name == "" {
		return fmt.Errorf(
			"missing bind-interface (expected a secure-tunnel interface " +
				"st<N> or st<N>.<unit>, e.g. st0 or st0.1)")
	}
	if _, ifID := XFRMIfNameAndID(name); ifID == 0 {
		return fmt.Errorf(
			"invalid bind-interface %q: must be a secure-tunnel interface "+
				"st<N> or st<N>.<unit> (e.g. st0 or st0.1); any other name "+
				"resolves to no XFRM interface, so the route-based VPN commits "+
				"but carries no traffic (silent tunnel down)",
			raw)
	}
	return nil
}
