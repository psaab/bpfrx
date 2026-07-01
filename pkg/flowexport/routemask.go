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

// routeMaskCacheMax bounds the number of distinct IPs the cache retains. The
// TTL bounds the syscall RATE; this bounds the FOOTPRINT. On an internet-facing
// firewall the destination-IP cardinality is effectively unbounded, so without
// a size cap the map would grow for the daemon's lifetime (~50-70 B/entry) — a
// slow leak. 8192 entries (~0.5 MB worst case) is far above the working set of
// distinct src/dst prefixes for any realistic flow mix yet a hard ceiling.
const routeMaskCacheMax = 8192

// defaultRouteMaskInflight bounds the number of concurrent BACKGROUND FIB
// lookups (#3743). resolve() runs inside the EventReader session-close
// callback; a synchronous RTM_GETROUTE netlink round-trip there stalls the
// event reader and every other callback behind it (including the trace writer)
// under netlink latency, and high destination-IP churn turns close handling
// into a netlink-bound path. So a cache miss no longer blocks: it schedules the
// lookup on a background goroutine and returns the default immediately. This
// ceiling caps how many such lookups run at once, so a slow/loaded netlink
// socket under churn cannot spawn unbounded goroutines — once it is reached,
// further misses just return the default and are retried on a later flow.
const defaultRouteMaskInflight = 32

// routeMaskCache caches FIB-match results for a short TTL so the per-flow
// session-close export path does not issue an RTM_GETROUTE netlink syscall for
// every record. Flows to the same destination/source prefix are common
// (per-host or per-subnet aggregates), so a small TTL cache collapses the
// syscall rate dramatically while keeping the mask fresh across routing
// changes. The cache is keyed by the 16-byte IP representation and bounded at
// routeMaskCacheMax entries.
type routeMaskCache struct {
	ttl     time.Duration
	maxSize int
	// lookup is the FIB query; a package var/field so tests can inject a
	// deterministic resolver without touching the kernel routing table.
	lookup func(ip net.IP) (uint8, bool)

	// maxInflight bounds concurrent background FIB lookups (#3743). 0 selects
	// defaultRouteMaskInflight. See scheduleLookupLocked.
	maxInflight int

	mu       sync.Mutex
	entries  map[string]routeMaskEntry
	pending  map[string]struct{} // keys with a background lookup in flight (dedup)
	inflight int                 // count of background lookups currently running

	// afterPopulate, when non-nil, is invoked after each background lookup has
	// stored its result. Test-only seam for deterministic assertions; nil in
	// production (the resolve() fast path never touches it).
	afterPopulate func()
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
		ttl:         ttl,
		maxSize:     routeMaskCacheMax,
		maxInflight: defaultRouteMaskInflight,
		lookup:      fibMatchMask,
		entries:     make(map[string]routeMaskEntry),
		pending:     make(map[string]struct{}),
	}
	return c.resolve
}

// resolve implements MaskResolver with caching. It NEVER issues the netlink
// FIB lookup on the calling goroutine (#3743): resolve() runs inside the
// EventReader session-close callback, so a synchronous RTM_GETROUTE round-trip
// would serialize the event reader (and every callback behind it) behind
// netlink latency. On a fresh cache hit it returns the cached prefix length; on
// a miss it schedules a bounded, deduplicated background lookup that warms the
// cache for the NEXT flow to this prefix and returns the safe default (0,
// false) now. An approximate mask on the first flow to a new prefix is the
// accepted trade-off for never blocking the shared event-reader path.
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
		mask, ok := e.mask, e.ok
		c.mu.Unlock()
		return mask, ok
	}
	// Cache miss (or expired): schedule the FIB lookup off this goroutine and
	// return the default now — do NOT block the callback on netlink.
	c.scheduleLookupLocked(key, ip16)
	c.mu.Unlock()
	return 0, false
}

// scheduleLookupLocked starts a background FIB lookup for key (the 16-byte
// string form of an IP) unless one is already in flight for it (dedup) or the
// concurrent-lookup cap is reached (backpressure — the miss is retried on a
// later flow rather than piling up goroutines behind a slow netlink socket).
// ip16 is copied because the caller's slice may be reused after resolve()
// returns. The caller holds c.mu. #3743.
func (c *routeMaskCache) scheduleLookupLocked(key string, ip16 net.IP) {
	if c.lookup == nil {
		return
	}
	if c.pending == nil {
		c.pending = make(map[string]struct{})
	}
	if _, inFlight := c.pending[key]; inFlight {
		return
	}
	limit := c.maxInflight
	if limit <= 0 {
		limit = defaultRouteMaskInflight
	}
	if c.inflight >= limit {
		return
	}
	c.pending[key] = struct{}{}
	c.inflight++
	ipCopy := append(net.IP(nil), ip16...)
	go c.populate(key, ipCopy)
}

// populate runs a single background FIB lookup and stores the result so the
// next flow to this prefix resolves from the warm cache. It is the goroutine
// body scheduled by scheduleLookupLocked; the netlink round-trip happens here,
// entirely off the EventReader callback path. #3743.
func (c *routeMaskCache) populate(key string, ip net.IP) {
	mask, ok := c.lookup(ip)
	now := time.Now()
	c.mu.Lock()
	c.storeLocked(key, mask, ok, now)
	delete(c.pending, key)
	if c.inflight > 0 {
		c.inflight--
	}
	after := c.afterPopulate
	c.mu.Unlock()
	if after != nil {
		after()
	}
}

// storeLocked bounds the cache then inserts a resolved entry. The caller holds
// c.mu.
func (c *routeMaskCache) storeLocked(key string, mask uint8, ok bool, now time.Time) {
	c.evictLocked(key, now)
	c.entries[key] = routeMaskEntry{mask: mask, ok: ok, expires: now.Add(c.ttl)}
}

// evictLocked bounds the cache before an insert. It is a no-op until the map is
// at the size cap; at the cap it first drops every expired entry (cheap, and it
// usually recovers headroom on a busy cache because TTLs are short), and if the
// map is STILL at the cap (a burst of distinct live IPs) it clears the whole
// map. Clearing is the simplest hard bound — it sacrifices the warm set for one
// cold round of syscalls rather than tracking per-entry LRU, which is not worth
// the bookkeeping for a syscall-amortization cache. maxSize<=0 disables the
// bound (used only by tests). The caller holds c.mu.
func (c *routeMaskCache) evictLocked(key string, now time.Time) {
	if c.maxSize <= 0 || len(c.entries) < c.maxSize {
		return
	}
	// Re-inserting an existing key does not grow the map, so it never needs
	// eviction; only a NEW key crossing the cap does.
	if _, exists := c.entries[key]; exists {
		return
	}
	for k, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) >= c.maxSize {
		clear(c.entries)
	}
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
