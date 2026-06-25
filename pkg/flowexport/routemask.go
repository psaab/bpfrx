package flowexport

import (
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

// MaskResolver returns the prefix length (subnet mask, in bits) of the FIB
// longest-prefix-match route for an IP, plus whether a mask was resolved.
//
// #2866: NetFlow v9 srcMask (IE 9) / dstMask (IE 13) and the IPv6 variants
// (IE 29 / IE 30) are the prefix lengths of the routing-table entries that
// match the flow's source and destination addresses (the same semantics
// Junos/vSRX export). The SESSION_CLOSE wire frame carries no route mask, so
// the exporter resolves it from the local FIB at export time. A default-route
// match legitimately yields 0 — that is the matched route's real prefix
// length, NOT the "unpopulated" zero the field carried before this change.
//
// The bool return lets a caller distinguish "resolved to /0 (default route)"
// from "no route / resolver unavailable"; the exporters write the resolved
// length on either true OR a 0 from a successful default-route match, and
// leave the field at 0 only when no resolver is wired (zero-value exporter).
type MaskResolver func(ip net.IP) (mask uint8, ok bool)

// routeMaskCache caches FIB-match results for a short TTL so the per-flow
// session-close export path does not issue an RTM_GETROUTE netlink syscall for
// every record. Flows to the same destination/source prefix are common
// (per-host or per-subnet aggregates), so a small TTL cache collapses the
// syscall rate dramatically while keeping the mask fresh across routing
// changes. The cache is keyed by the 16-byte IP representation.
type routeMaskCache struct {
	ttl time.Duration
	// lookup is the FIB query; a package var/field so tests can inject a
	// deterministic resolver without touching the kernel routing table.
	lookup func(ip net.IP) (uint8, bool)

	mu      sync.Mutex
	entries map[string]routeMaskEntry
}

type routeMaskEntry struct {
	mask    uint8
	ok      bool
	expires time.Time
}

// NewRouteMaskResolver returns a MaskResolver backed by the kernel FIB
// (RTM_GETROUTE with RTM_F_FIB_MATCH), with a short TTL cache to bound the
// netlink syscall rate on the hot session-close export path. ttl<=0 selects a
// sensible default (10s).
func NewRouteMaskResolver(ttl time.Duration) MaskResolver {
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	c := &routeMaskCache{
		ttl:     ttl,
		lookup:  fibMatchMask,
		entries: make(map[string]routeMaskEntry),
	}
	return c.resolve
}

// resolve implements MaskResolver with caching.
func (c *routeMaskCache) resolve(ip net.IP) (uint8, bool) {
	if ip == nil {
		return 0, false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return 0, false
	}
	key := string(ip16)
	now := time.Now()

	c.mu.Lock()
	if e, found := c.entries[key]; found && now.Before(e.expires) {
		c.mu.Unlock()
		return e.mask, e.ok
	}
	c.mu.Unlock()

	mask, ok := c.lookup(ip)

	c.mu.Lock()
	c.entries[key] = routeMaskEntry{mask: mask, ok: ok, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return mask, ok
}

// resolveMasks returns the src/dst route prefix lengths for a flow using r.
// A nil resolver (zero-value exporter) yields 0/0 — the pre-#2866 behaviour.
// A resolver miss (no matching route) also yields 0 for that half. A
// successful match to a default route legitimately yields 0; that is the real
// matched-route prefix length, not "unpopulated".
func resolveMasks(r MaskResolver, srcIP, dstIP net.IP) (srcMask, dstMask uint8) {
	if r == nil {
		return 0, 0
	}
	srcMask, _ = r(srcIP)
	dstMask, _ = r(dstIP)
	return srcMask, dstMask
}

// fibMatchMask queries the kernel FIB for the longest-prefix-match route to ip
// and returns the matched route's prefix length. RTM_F_FIB_MATCH makes the
// kernel report the actual matching FIB entry (with its Dst prefix) rather than
// echoing the queried host as a /32 or /128, so a default-route match returns
// the real /0.
func fibMatchMask(ip net.IP) (uint8, bool) {
	routes, err := netlink.RouteGetWithOptions(ip, &netlink.RouteGetOptions{FIBMatch: true})
	if err != nil || len(routes) == 0 {
		return 0, false
	}
	// RouteGet may return multiple ECMP nexthops for ONE matched prefix; they
	// all share the same Dst, so the first entry's Dst is authoritative.
	dst := routes[0].Dst
	if dst == nil {
		// No Dst reported (kernel without FIB_MATCH support, or a cache route):
		// the route covers the whole family — treat as default (/0).
		return 0, true
	}
	ones, _ := dst.Mask.Size()
	if ones < 0 || ones > 128 {
		return 0, false
	}
	return uint8(ones), true
}
