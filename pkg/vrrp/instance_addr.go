package vrrp

import (
	"bytes"
	"net"
	"sort"
	"strings"
)

// interfaceAddrs returns the interface's current addresses, via the test seam
// when set, else live from the kernel. Re-queried on every resolve so the
// addr-watcher (#2528) always sees the CURRENT address set.
func (vi *vrrpInstance) interfaceAddrs() ([]net.Addr, error) {
	if vi.addrsFn != nil {
		return vi.addrsFn()
	}
	return vi.iface.Addrs()
}

// getLocalIP returns the resolved local IPv4 address, or nil if unresolved.
// Safe to call from any goroutine — the field is written via setLocalIP from
// openSocket() (pre-goroutine) and from the sendPacket() lazy-resolve path
// (run-loop goroutine), while the receiver goroutines read it (#2258).
func (vi *vrrpInstance) getLocalIP() net.IP {
	if p := vi.localIP.Load(); p != nil {
		return *p
	}
	return nil
}

// setLocalIP atomically stores the resolved local IPv4 address.
func (vi *vrrpInstance) setLocalIP(ip net.IP) {
	if ip == nil {
		vi.localIP.Store(nil)
		return
	}
	vi.localIP.Store(&ip)
}

// getLocalIPv6 returns the resolved local link-local IPv6 address, or nil if
// unresolved. Safe to call from any goroutine — see getLocalIP (#2258).
func (vi *vrrpInstance) getLocalIPv6() net.IP {
	if p := vi.localIPv6.Load(); p != nil {
		return *p
	}
	return nil
}

// setLocalIPv6 atomically stores the resolved local link-local IPv6 address.
func (vi *vrrpInstance) setLocalIPv6(ip net.IP) {
	if ip == nil {
		vi.localIPv6.Store(nil)
		return
	}
	vi.localIPv6.Store(&ip)
}

// vipAddrSet returns the configured virtual addresses (prefix stripped) as a
// set. Used to EXCLUDE VIPs when selecting our own advert source: during
// split-brain both nodes hold the VIP, so sending from it would make the peer
// filter our adverts as self-sent. cfg.VirtualAddresses is set once at
// newInstance and never mutated in place (VIP changes go through a full
// instance rebuild), so reading it without the lock is safe — the same
// pattern the sendPacket() lazy resolve already relies on.
func (vi *vrrpInstance) vipAddrSet() map[string]bool {
	s := make(map[string]bool, len(vi.cfg.VirtualAddresses))
	for _, vip := range vi.cfg.VirtualAddresses {
		addr := vip
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		s[canonAddr(addr)] = true
	}
	return s
}

// canonAddr returns the canonical string form of an IP literal so that VIP
// exclusion keys match the lookup side, which uses net.IP.String() (Go's
// canonical form). A non-canonically-formatted VIP — e.g. an uppercase or
// non-zero-compressed link-local "fe80::AB" — would otherwise be keyed by its
// raw config string and miss the "fe80::ab" lookup, leaking the VIP into local
// link-local source selection and making the engine treat its own adverts as
// self-sent (#2516). net.ParseIP rejects CIDR, so the caller must strip any
// "/prefix" first; an unparseable string falls back to itself unchanged.
func canonAddr(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// resolveLocalIPv4 deterministically selects our IPv4 advert source: the
// lowest non-VIP IPv4 currently assigned to the interface, or nil if none.
// Deterministic (lowest) selection — mirroring resolveIPv6LinkLocal — keeps
// the source STABLE across unrelated secondary-address churn so the
// addr-watcher re-resolve (#2528) never flips the advert source on an event
// for some other address on the same interface. (Member interfaces normally
// carry exactly one non-VIP primary IPv4, so this is a no-op in practice; the
// determinism only matters for the multi-address edge.)
func (vi *vrrpInstance) resolveLocalIPv4(vipSet map[string]bool) net.IP {
	addrs, err := vi.interfaceAddrs()
	if err != nil {
		return nil
	}
	var candidates []net.IP
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || vipSet[ip4.String()] {
			continue
		}
		candidates = append(candidates, ip4)
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return bytes.Compare(candidates[i], candidates[j]) < 0
	})
	return candidates[0]
}

// reresolveLocalAddrs recomputes localIP and localIPv6 from the interface's
// CURRENT kernel addresses and stores them atomically. Called once at
// openSocket() and again from the manager addr-watcher whenever an address is
// added/removed on this instance's interface (#2528).
//
// Before #2528 the cached source was resolved exactly once and never
// invalidated: if the interface's IPv4 or link-local IPv6 changed during
// operation — most acutely the RETH MAC reprogram cycle (programRethMAC does
// link DOWN -> set MAC -> UP, which flushes ALL kernel addresses; networkd
// KeepConfiguration=static restores them but with a 30ms-1s timing window
// against the next 30ms advert) — the instance kept sending from a stale
// source. The kernel then silently rejects the advert (source no longer on
// the interface) AND incoming self-adverts fail self-filtering in
// handleMasterRx -> false master conflict / split-brain. Re-resolving on every
// address event closes that window. A nil result (address transiently absent)
// is stored as nil so the sendPacket()/sendPacketIPv6() lazy path re-resolves
// on the next advert. The atomic setLocalIP/setLocalIPv6 stores make this
// addr-watcher-goroutine write race-clean against the receiver/run-loop reads
// (#2258).
func (vi *vrrpInstance) reresolveLocalAddrs() {
	vipSet := vi.vipAddrSet()
	vi.setLocalIP(vi.resolveLocalIPv4(vipSet))
	vi.setLocalIPv6(vi.resolveIPv6LinkLocal(vipSet))
}

// resolveIPv6LinkLocal deterministically selects the lowest non-VIP
// link-local IPv6 address on the interface. Sorting ensures the same
// address is always chosen regardless of kernel enumeration order,
// even when multiple link-locals exist (e.g. after MAC changes).
func (vi *vrrpInstance) resolveIPv6LinkLocal(vipSet map[string]bool) net.IP {
	addrs, err := vi.interfaceAddrs()
	if err != nil {
		return nil
	}
	var candidates []net.IP
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil {
			continue
		}
		if !ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if vipSet[ipNet.IP.String()] {
			continue
		}
		candidates = append(candidates, ipNet.IP)
	}
	if len(candidates) == 0 {
		return nil
	}
	// Sort and pick lowest for determinism.
	sort.Slice(candidates, func(i, j int) bool {
		return bytes.Compare(candidates[i], candidates[j]) < 0
	})
	return candidates[0]
}
