package grpcapi

import (
	"sync"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/monitoriface"
)

// monitorStatusTTL bounds how long the MonitorInterface streaming path reuses a
// single userspace-dataplane Status() snapshot (#5707). A stream polls once per
// second, so a sub-second window collapses both the per-interface fan-out
// (summary mode reads every configured interface each tick) and the per-stream
// fan-out (S concurrent subscribers each running their own ticker) to one
// control-socket query per tick, while never serving data older than one poll.
const monitorStatusTTL = 900 * time.Millisecond

// monitorStatusCache coalesces userspace-dataplane Status() queries so that
// concurrent MonitorInterface streams — and the per-interface loop inside a
// single summary-mode tick — share one control-socket read instead of issuing
// O(interfaces*streams) of them. It is a single-flight cache: the first caller
// after the freshness window elapses performs the fetch while holding the lock,
// and every caller that arrives within the window (or blocks behind the
// in-flight fetch) receives the same result. Status() returns the whole-process
// snapshot for every interface at once, so one shared read fully serves a tick.
type monitorStatusCache struct {
	mu    sync.Mutex
	fetch monitoriface.StatusReader
	ttl   time.Duration
	now   func() time.Time

	status  dpuserspace.ProcessStatus
	err     error
	fetched time.Time
	valid   bool
}

// newMonitorStatusCache builds a cache over fetch with the given freshness
// window. now is injectable so tests can drive the window deterministically;
// nil defaults to time.Now.
func newMonitorStatusCache(fetch monitoriface.StatusReader, ttl time.Duration, now func() time.Time) *monitorStatusCache {
	if now == nil {
		now = time.Now
	}
	return &monitorStatusCache{fetch: fetch, ttl: ttl, now: now}
}

// get returns a Status() snapshot no older than the cache TTL, issuing at most
// one backing fetch per window regardless of how many callers race for it.
func (c *monitorStatusCache) get() (dpuserspace.ProcessStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.now()
	if c.valid && t.Sub(c.fetched) < c.ttl {
		return c.status, c.err
	}
	if c.fetch == nil {
		return dpuserspace.ProcessStatus{}, nil
	}
	c.status, c.err = c.fetch()
	c.fetched = t
	c.valid = true
	return c.status, c.err
}

// monitorStatusReader returns the shared, coalescing Status() reader used by the
// MonitorInterface streaming path. All streams on this Server share one cache so
// concurrent subscribers do not multiply the control-socket load (#5707).
func (s *Server) monitorStatusReader() monitoriface.StatusReader {
	s.monitorStatusOnce.Do(func() {
		if s.monitorStatusCache == nil {
			s.monitorStatusCache = newMonitorStatusCache(s.userspaceDataplaneStatus, monitorStatusTTL, nil)
		}
	})
	return s.monitorStatusCache.get
}
