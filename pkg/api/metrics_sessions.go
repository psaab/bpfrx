package api

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
)

// sessionGaugeTTL is the freshness window for the cached session-aggregate
// snapshot (#4162). A scrape within this window of the last successful walk
// serves the cached snapshot instead of re-walking the conntrack table, so the
// walk rate is capped at <=1 per TTL regardless of scrape frequency.
//
// 3s is chosen deliberately: a Prometheus scrape interval is conventionally
// 15-60s, so at normal cadence every scrape lands well outside a 3s window and
// therefore always triggers a fresh walk — the cache is transparent to normal
// operation and introduces no session-gauge staleness an operator would see. It
// only engages when scrapes arrive faster than every 3s (a misconfigured tight
// scrape loop or a deliberate amplification attempt), which is exactly the
// #4162 DoS vector: there the cache collapses an unbounded scrape rate onto at
// most one O(sessions) walk per 3s. 3s stays under the finest reasonable scrape
// interval while still meaningfully rate-limiting the walk under abuse.
const sessionGaugeTTL = 3 * time.Second

// sessionGaugeSnapshot is the set of scalar aggregates produced by one full
// walk of the v4+v6 conntrack tables. It carries no per-session cardinality —
// the O(sessions) walk collapses to these seven O(1) counters — which is what
// makes the walk result cacheable without dropping any Prometheus label.
type sessionGaugeSnapshot struct {
	active      int
	established int
	ipv4        int
	ipv6        int
	snat        int
	dnat        int
}

func (c *xpfCollector) collectSessionGauges(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	// xpf_gc_sweep_duration_seconds reflects the last BPF GC sweep timing.
	// On the userspace dataplane (the only live forwarding path) the BPF GC
	// sweep is skipped (#333), so this is 0 — expected, and orthogonal to the
	// session counts derived below. It is not part of the cached snapshot: it
	// is a single field read, not a table walk.
	if c.srv.gc != nil {
		ch <- prometheus.MustNewConstMetric(c.gcSweepDuration, prometheus.GaugeValue,
			c.srv.gc.Stats().LastSweepDuration.Seconds())
	}

	// #3929: derive the active/established/breakdown session gauges from the
	// LIVE dataplane session table — the same source `show security flow
	// session` reads. Previously xpf_sessions_active/xpf_sessions_established
	// were sourced from GC sweep stats (gc.Stats().TotalEntries /
	// EstablishedSessions), which are permanently 0 on the userspace dataplane
	// because the BPF GC sweep is skipped (#333).
	//
	// #4162: the walk is behind a short-TTL, singleflight-coalesced cache
	// (sessionGaugeSnapshotCached) so the scrape rate is decoupled from the
	// walk rate — at most one full v4+v6 table walk per sessionGaugeTTL,
	// regardless of how fast (or from how many concurrent clients) /metrics is
	// scraped. This defeats the unauthenticated / tight-loop amplification of
	// the O(sessions) scan over the box's largest hot structure.
	//
	// A backend iterator error (e.g. a helper restart mid-scrape) truncates the
	// scan; publishing the partial counts would report a wrong-but-confident
	// picture (#2469), so on error we EXPOSE xpf_sessions_breakdown_scrape_ok=0
	// and OMIT every session gauge, letting an alert on scrape_ok fire rather
	// than a graph silently dropping toward zero. The cache is NOT poisoned on
	// error — a failed walk leaves the previous good snapshot in place (and its
	// TTL unchanged), so the next scrape retries the walk.
	snap, ok := c.sessionGaugeSnapshotCached(dp)
	if !ok {
		ch <- prometheus.MustNewConstMetric(c.sessionScrapeOK, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.sessionScrapeOK, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(c.sessionsActive, prometheus.GaugeValue, float64(snap.active))
	ch <- prometheus.MustNewConstMetric(c.sessionsEstablished, prometheus.GaugeValue, float64(snap.established))
	ch <- prometheus.MustNewConstMetric(c.sessionsIPv4, prometheus.GaugeValue, float64(snap.ipv4))
	ch <- prometheus.MustNewConstMetric(c.sessionsIPv6, prometheus.GaugeValue, float64(snap.ipv6))
	ch <- prometheus.MustNewConstMetric(c.sessionsSNAT, prometheus.GaugeValue, float64(snap.snat))
	ch <- prometheus.MustNewConstMetric(c.sessionsDNAT, prometheus.GaugeValue, float64(snap.dnat))
}

// sessionGaugeTTLEffective returns the cache freshness window. Production uses
// the sessionGaugeTTL const; tests set sessionGaugeTTLOverride to drive TTL
// boundaries deterministically without a real sleep.
func (c *xpfCollector) sessionGaugeTTLEffective() time.Duration {
	if c.sessionGaugeTTLOverride > 0 {
		return c.sessionGaugeTTLOverride
	}
	return sessionGaugeTTL
}

// sessionGaugeSnapshotCached returns the seven session aggregates, serving a
// cached snapshot when it is younger than the effective TTL and otherwise
// performing exactly one refresh walk. The second return is false when the
// backing walk failed AND no prior good snapshot is available to serve, in
// which case the caller emits scrape_ok=0 and omits the gauges (#2469).
//
// Concurrency: the fast-path freshness check takes sessionGaugeMu only briefly.
// On a miss the refresh runs under singleflight keyed on a constant, so N
// concurrent stale scrapes coalesce onto ONE walk and all observe its result —
// they never fan out to N parallel walks over the shared conntrack maps.
func (c *xpfCollector) sessionGaugeSnapshotCached(dp apiRuntimeDataPlane) (sessionGaugeSnapshot, bool) {
	ttl := c.sessionGaugeTTLEffective()

	// Fast path: a fresh snapshot serves without a walk or singleflight entry.
	c.sessionGaugeMu.Lock()
	if c.sessionGaugeValid && time.Since(c.sessionGaugeComputedAt) < ttl {
		snap := c.sessionGaugeSnap
		c.sessionGaugeMu.Unlock()
		return snap, true
	}
	c.sessionGaugeMu.Unlock()

	// Slow path: coalesce concurrent refreshes onto a single in-flight walk.
	v, err, _ := c.sessionGaugeSF.Do("session-gauges", func() (interface{}, error) {
		// Re-check under the lock: a sibling scrape may have refreshed the
		// snapshot between our fast-path miss and acquiring the singleflight
		// slot (singleflight only dedups callers that overlap the SAME in-flight
		// call; a caller arriving just after a refresh completed would otherwise
		// walk again immediately).
		c.sessionGaugeMu.Lock()
		if c.sessionGaugeValid && time.Since(c.sessionGaugeComputedAt) < ttl {
			snap := c.sessionGaugeSnap
			c.sessionGaugeMu.Unlock()
			return snap, nil
		}
		c.sessionGaugeMu.Unlock()

		snap, werr := walkSessionGauges(dp)
		if werr != nil {
			return sessionGaugeSnapshot{}, werr
		}
		c.sessionGaugeMu.Lock()
		c.sessionGaugeSnap = snap
		c.sessionGaugeComputedAt = time.Now()
		c.sessionGaugeValid = true
		c.sessionGaugeMu.Unlock()
		return snap, nil
	})
	if err != nil {
		// Walk failed. Do NOT poison the cache (leave any prior good snapshot
		// and its TTL untouched so the next scrape retries). Signal scrape_ok=0.
		return sessionGaugeSnapshot{}, false
	}
	return v.(sessionGaugeSnapshot), true
}

// walkSessionGauges performs one full walk of the v4 and v6 conntrack tables
// and tallies the seven scalar aggregates. It returns an error if either
// iterator fails; the caller discards a partial result rather than reporting a
// truncated-but-confident count (#2469).
//
// active   = forward session entries (IsReverse == 0) — the live count.
// established = forward entries whose State is ESTABLISHED (a distinct session
//
//	state). Half-open / opening sessions are counted in active but
//	not established.
func walkSessionGauges(dp apiRuntimeDataPlane) (sessionGaugeSnapshot, error) {
	// #8001: take a sessionWalkLimiter slot like every other full-table walk in
	// this package. Six siblings do (sessions.go x5, nat.go x1); this one did
	// not, so the limiter's guarantee was not the guarantee anyone reading it
	// would assume -- correct about every call site but this one.
	//
	// It matters more here than at a request-driven site, not less: this walk is
	// driven by a Prometheus scraper on a fixed interval rather than by an
	// operator, so it is the call site least likely to be noticed under load and
	// most likely to overlap with something else.
	//
	// Acquire() is NON-BLOCKING -- it returns ErrBusy immediately at the cap --
	// so a scrape can never hang behind an operator's session walk. Returning
	// the error takes the caller's EXISTING failure path: the cached snapshot
	// and its TTL are left untouched so the next scrape retries, and scrape_ok
	// goes to 0. That is the #3345 convention (skip the sample rather than
	// report a misleading one) reached without new error handling.
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		return sessionGaugeSnapshot{}, err
	}
	defer release()

	var s sessionGaugeSnapshot
	countForward := func(state uint8, flags uint16, ipCounter *int) {
		s.active++
		*ipCounter++
		if state == dataplane.SessStateEstablished {
			s.established++
		}
		if flags&dataplane.SessFlagSNAT != 0 {
			s.snat++
		}
		if flags&dataplane.SessFlagDNAT != 0 {
			s.dnat++
		}
	}
	if err := dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse == 0 {
			countForward(val.State, val.Flags, &s.ipv4)
		}
		return true
	}); err != nil {
		return sessionGaugeSnapshot{}, err
	}
	if err := dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse == 0 {
			countForward(val.State, val.Flags, &s.ipv6)
		}
		return true
	}); err != nil {
		return sessionGaugeSnapshot{}, err
	}
	return s, nil
}
