// bfd.go holds the BFD (Bidirectional Forwarding Detection) profile/peer
// accumulator the protocol renderer uses to dedup and emit a single
// global `bfd` block across the default instance and every VRF (#2550).
//
// Split out of policy_render.go (#6424) as a pure code-motion refactor;
// the emitted frr.conf is byte-identical.
//
// Symbols:
//   - bfdProfile, bfdPeer, bfdSection (+ methods), newBFDSection
//   - bfdProfileName
package frr

import (
	"fmt"
	"sort"
	"strings"
)

// bfdProfile holds a unique BFD profile (interval + multiplier).
type bfdProfile struct {
	interval   int
	multiplier int
}

// bfdPeer holds a BGP BFD peer destined for the single top-level `bfd`
// block. vrfName carries the routing-instance the peer belongs to so
// bfdd associates the session with the VRF-bound neighbor (#2489).
type bfdPeer struct {
	address    string
	vrfName    string
	interval   int
	multiplier int
}

// bfdSection accumulates BFD profiles and peers across the default
// routing instance AND every VRF so the FRR manager can emit a SINGLE
// top-level `bfd { ... }` block exactly once (#2550). FRR's bfdd is one
// global daemon; emitting a `bfd` stanza per routing instance produced
// redundant blocks and repeated profile definitions in the consolidated
// frr.conf, risking frr-reload parse warnings.
type bfdSection struct {
	profiles map[string]bfdProfile
	peers    []bfdPeer
}

// newBFDSection returns an empty accumulator.
func newBFDSection() *bfdSection {
	return &bfdSection{profiles: make(map[string]bfdProfile)}
}

// addProfile records a unique profile (dedup is by name, which already
// encodes interval+multiplier via bfdProfileName).
func (s *bfdSection) addProfile(name string, p bfdProfile) {
	s.profiles[name] = p
}

// addPeer appends a BGP BFD peer in caller (instance) order.
func (s *bfdSection) addPeer(p bfdPeer) {
	s.peers = append(s.peers, p)
}

// empty reports whether nothing was accumulated.
func (s *bfdSection) empty() bool {
	return len(s.profiles) == 0 && len(s.peers) == 0
}

// render emits a single top-level `bfd` block containing all accumulated
// peers (in instance order) followed by all profiles (sorted by name for
// deterministic output). Returns "" when nothing was accumulated. The
// per-stanza format is byte-identical to the pre-#2550 per-instance
// emission, so only the block COUNT changes (one global block instead of
// one per routing instance).
func (s *bfdSection) render() string {
	if s.empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString("bfd\n")
	for _, p := range s.peers {
		// A `peer <addr>` line with no `vrf` suffix lands in the DEFAULT
		// VRF. A VRF-scoped BGP session's BFD peer MUST carry the same
		// `vrf <name>` so bfdd associates the BFD session with the
		// VRF-bound neighbor; otherwise the session stays DOWN and
		// sub-second failover never works (#2489).
		if p.vrfName != "" {
			// Render belt (#5557): sanitize the routing-instance name like the
			// `router ... vrf` and static-route vrf clauses. A leniently-loaded
			// control character in the instance name would otherwise inject a
			// standalone line into the managed `bfd` block.
			fmt.Fprintf(&b, " peer %s vrf %s\n", p.address, sanitizeFRRValue(p.vrfName))
		} else {
			fmt.Fprintf(&b, " peer %s\n", p.address)
		}
		multiplier := p.multiplier
		if multiplier == 0 {
			multiplier = 3
		}
		interval := p.interval
		if interval == 0 {
			interval = 300
		}
		fmt.Fprintf(&b, "  detect-multiplier %d\n", multiplier)
		fmt.Fprintf(&b, "  receive-interval %d\n", interval)
		fmt.Fprintf(&b, "  transmit-interval %d\n", interval)
		b.WriteString(" exit\n")
	}
	var profileNames []string
	for name := range s.profiles {
		profileNames = append(profileNames, name)
	}
	sort.Strings(profileNames)
	for _, name := range profileNames {
		p := s.profiles[name]
		interval := p.interval
		if interval == 0 {
			interval = 300
		}
		multiplier := p.multiplier
		if multiplier == 0 {
			multiplier = 3
		}
		fmt.Fprintf(&b, " profile %s\n", name)
		fmt.Fprintf(&b, "  detect-multiplier %d\n", multiplier)
		fmt.Fprintf(&b, "  receive-interval %d\n", interval)
		fmt.Fprintf(&b, "  transmit-interval %d\n", interval)
		b.WriteString(" exit\n")
	}
	b.WriteString("exit\n!\n")
	return b.String()
}

// bfdProfileName returns a deterministic profile name like "xpf-300-3".
func bfdProfileName(interval, multiplier int) string {
	if interval == 0 {
		interval = 300
	}
	if multiplier == 0 {
		multiplier = 3
	}
	return fmt.Sprintf("xpf-%d-%d", interval, multiplier)
}
