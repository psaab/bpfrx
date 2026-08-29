package config

import (
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
)

// stable_iface_7095.go — #7095: a CLUSTER-STABLE name for a session's ingress
// interface, so the #4983 identity can ride the HA session-sync wire.
//
// WHY NOT THE IFINDEX. An ifindex is NODE-LOCAL. Node 0's `ge-0-0-1` and node
// 1's `ge-7-0-1` are the same logical RETH member with different numbers, so
// shipping the originating node's value renders a confidently WRONG interface
// name on the importing node — worse than the zone approximation it would
// replace. #6928 therefore syncs nothing and the peer falls back to the zone.
//
// WHAT IS STABLE. The RETH-RELATIVE name is: `docs/ha-cluster-userspace.conf`
// binds its zones to `reth0.50` / `reth0.80` / `reth1` — byte-identical strings
// on both nodes — while only the members differ, and RethToPhysical resolves
// reth to the LOCAL member by node id. So both nodes agree on the name by
// construction, and each resolves it to its own device. That is what rides the
// wire, folded to a u32 in the manner of StableZoneID (#3075).
//
// ZERO IS "UNKNOWN", AND IT IS ALSO WHAT A LEGACY PEER SENDS. The wire field is
// length-gated (the #2170 Generation pattern), so an old sender emits nothing,
// the decoder reads absent, and the value is 0 — the same 0 a fabric-redirected
// session records deliberately (#7096: the fabric stamp carries a u16 zone id
// and nothing else, so the peer's real ingress interface is not knowable on the
// receiving node). One encoding serves both, and the consumer's fallback for
// both is the #4792 zone approximation. Do NOT add a separate unknown marker.

// StableIfaceID folds a cluster-stable interface name to a non-zero u32.
//
// Zero is reserved as the unknown/legacy sentinel, so the fold never returns
// it: a name that hashes to 0 is mapped to 1. That collision is one extra name
// sharing bucket 1, which the reverse lookup resolves the same way it resolves
// any other collision — by comparing candidate names, not by trusting the id.
func StableIfaceID(name string) uint32 {
	if name == "" {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	s := h.Sum64()
	folded := uint32(s) ^ uint32(s>>32)
	if folded == 0 {
		return 1
	}
	return folded
}

// ClusterStableIfaceName maps a LOCAL interface name and VLAN id to the name
// both nodes agree on, or "" when there is none.
//
// A member of a RETH becomes its reth-relative form (`ge-0-0-1` -> `reth1`); a
// non-member keeps its own name, which is stable only if both nodes happen to
// name it identically. That second case is deliberately included: a
// single-homed interface with the same name on both nodes (a management or
// fabric-parent link) is as agreed as a reth is, and excluding it would report
// "unknown" for a session whose interface both nodes can name.
//
// The VLAN suffix is appended when vlan > 0, matching how zones bind units
// (`reth0.50`). A VID of 0 is not distinguishable from an untagged frame at
// this layer (see SessionValue.IngressVlanID), so it contributes no suffix.
func (c *Config) ClusterStableIfaceName(local string, vlan uint16) string {
	if c == nil || local == "" {
		return ""
	}
	base := local
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	// The caller's name may be either spelling: config carries the Junos form
	// (`ge-0/0/1`) while the kernel — and therefore anything derived from an
	// ifindex — carries the Linux one (`ge-0-0-1`). Compare in the Linux form so
	// both land on the same member.
	//
	// Getting this wrong does not fail loudly: an unmatched member keeps its own
	// name, so node 0 would fold `ge-0-0-1` while node 1 folds `ge-7-0-1`, the
	// folds would disagree, the peer would resolve nothing, and every session
	// would silently degrade to the zone approximation — the exact outcome this
	// change exists to remove, with no error anywhere.
	baseLinux := LinuxIfName(base)
	stable := base
	for reth, member := range c.RethToPhysical() {
		if LinuxIfName(member) == baseLinux {
			stable = reth
			break
		}
	}
	if vlan > 0 {
		return stable + "." + strconv.FormatUint(uint64(vlan), 10)
	}
	return stable
}

// ClusterStableIfaceNames enumerates every cluster-stable name this config can
// produce, in a deterministic order.
//
// It is the candidate set the reverse lookup folds over. Enumerating rather
// than inverting the hash is what makes a collision harmless: two names folding
// alike are both candidates, and the caller sees the ambiguity instead of
// silently getting the wrong one.
func (c *Config) ClusterStableIfaceNames() []string {
	if c == nil {
		return nil
	}
	seen := make(map[string]struct{})
	add := func(n string) {
		if n != "" {
			seen[n] = struct{}{}
		}
	}
	rethOf := make(map[string]string)
	for reth, member := range c.RethToPhysical() {
		rethOf[member] = reth
		add(reth)
	}
	for name, ifc := range c.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		base := name
		if reth, ok := rethOf[name]; ok {
			base = reth
		}
		add(base)
		for _, unit := range ifc.Units {
			if unit != nil && unit.VlanID > 0 {
				add(base + "." + strconv.FormatUint(uint64(unit.VlanID), 10))
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// LocalIfaceForStableID resolves a wire fold back to a LOCAL interface name.
//
// It returns ok=false for 0 (unknown / legacy peer) and for an id no local name
// folds to — a session whose ingress interface this node does not have, which
// happens when the peer's config is ahead of ours. Both are the same answer to
// the consumer: fall back to the zone approximation rather than name a device.
//
// On a collision it returns ok=false as well, rather than the first match: two
// names folding alike means this node cannot tell WHICH interface the peer
// meant, and the zone approximation is honest where a coin flip is not.
func (c *Config) LocalIfaceForStableID(id uint32) (string, bool) {
	if c == nil || id == 0 {
		return "", false
	}
	var hit string
	for _, name := range c.ClusterStableIfaceNames() {
		if StableIfaceID(name) != id {
			continue
		}
		if hit != "" {
			return "", false
		}
		hit = name
	}
	if hit == "" {
		return "", false
	}
	return c.ResolveReth(hit), true
}
