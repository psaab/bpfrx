package logging

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// defaultMaxAggKeys bounds the number of distinct source/destination IPs
// retained per flush window in each map. It exists to defend against a
// control-plane resource-exhaustion amplifier (#2936): an attacker driving
// high source/destination cardinality (spoofed-source or scan traffic — the
// exact pattern a security appliance observes during an incident) would
// otherwise force the daemon to retain two unbounded maps for the full flush
// window, then allocate and sort O(N) entries twice per flush. Capping the
// admitted key set bounds both the resident memory and the per-flush
// allocate+sort cost by configuration rather than by traffic cardinality.
//
// 10000 distinct keys per map per window keeps the aggregator well within a
// few MB of transient memory while remaining far above any plausible
// legitimate top-N working set (the report only emits top-10).
const defaultMaxAggKeys = 10000

// SessionAggregator tracks session statistics and periodically flushes
// top-N source and destination reports.
type SessionAggregator struct {
	mu   sync.Mutex
	srcs map[string]*aggEntry // srcIP -> stats
	dsts map[string]*aggEntry // dstIP -> stats

	// maxKeys caps the distinct keys admitted into each map per window.
	// Once a map reaches maxKeys, NEW keys are dropped (and counted in
	// droppedSrc/droppedDst); keys already admitted continue to aggregate
	// normally, so the top-N over the admitted set stays accurate.
	maxKeys int

	// droppedSrc/droppedDst count NEW keys refused this window because the
	// corresponding map was already at maxKeys. They reset on each flush and
	// are surfaced in the flush report so an operator sees that the cap was
	// hit — a high cardinality signal that is itself an incident indicator.
	droppedSrc uint64
	droppedDst uint64

	flushInterval time.Duration
	topN          int
	logFn         func(severity int, msg string) // where to send aggregate reports
}

type aggEntry struct {
	Sessions uint64
	Bytes    uint64
}

// AggregateEntry is a single top-N entry returned by Flush.
type AggregateEntry struct {
	IP       string
	Sessions uint64
	Bytes    uint64
}

// NewSessionAggregator creates a new aggregator.
// flushInterval controls how often top-N stats are emitted (default 5min).
// topN controls how many entries per category (default 10).
func NewSessionAggregator(flushInterval time.Duration, topN int) *SessionAggregator {
	if flushInterval <= 0 {
		flushInterval = 5 * time.Minute
	}
	if topN <= 0 {
		topN = 10
	}
	return &SessionAggregator{
		srcs:          make(map[string]*aggEntry),
		dsts:          make(map[string]*aggEntry),
		maxKeys:       defaultMaxAggKeys,
		flushInterval: flushInterval,
		topN:          topN,
	}
}

// SetLogFunc sets the function used to emit aggregate log lines.
func (sa *SessionAggregator) SetLogFunc(fn func(severity int, msg string)) {
	sa.mu.Lock()
	sa.logFn = fn
	sa.mu.Unlock()
}

// Add records a session event. Only SESSION_CLOSE events update counters.
func (sa *SessionAggregator) Add(rec EventRecord) {
	if rec.Type != "SESSION_CLOSE" {
		return
	}

	srcIP, _ := splitAddrPort(rec.SrcAddr)
	dstIP, _ := splitAddrPort(rec.DstAddr)

	sa.mu.Lock()
	defer sa.mu.Unlock()

	// Existing keys always aggregate. A NEW key is admitted only while the
	// map is below the cardinality cap; otherwise it is dropped and counted,
	// bounding memory and per-flush sort cost by config (#2936).
	if e, ok := sa.srcs[srcIP]; ok {
		e.Sessions++
		e.Bytes += rec.SessionBytes
	} else if sa.maxKeys <= 0 || len(sa.srcs) < sa.maxKeys {
		sa.srcs[srcIP] = &aggEntry{Sessions: 1, Bytes: rec.SessionBytes}
	} else {
		sa.droppedSrc++
	}

	if e, ok := sa.dsts[dstIP]; ok {
		e.Sessions++
		e.Bytes += rec.SessionBytes
	} else if sa.maxKeys <= 0 || len(sa.dsts) < sa.maxKeys {
		sa.dsts[dstIP] = &aggEntry{Sessions: 1, Bytes: rec.SessionBytes}
	} else {
		sa.droppedDst++
	}
}

// Flush returns top-N sources and destinations by bytes, then resets counters.
func (sa *SessionAggregator) Flush() (topSrc, topDst []AggregateEntry) {
	topSrc, topDst, _, _ = sa.flushWithDropped()
	return
}

// flushWithDropped is Flush plus the per-window dropped-key counts. The maps
// and the dropped counters are swapped out atomically under the lock so the
// snapshot is internally consistent and the next window starts clean.
func (sa *SessionAggregator) flushWithDropped() (topSrc, topDst []AggregateEntry, droppedSrc, droppedDst uint64) {
	sa.mu.Lock()
	srcs := sa.srcs
	dsts := sa.dsts
	droppedSrc = sa.droppedSrc
	droppedDst = sa.droppedDst
	sa.srcs = make(map[string]*aggEntry)
	sa.dsts = make(map[string]*aggEntry)
	sa.droppedSrc = 0
	sa.droppedDst = 0
	sa.mu.Unlock()

	topSrc = topEntries(srcs, sa.topN)
	topDst = topEntries(dsts, sa.topN)
	return
}

// Run starts the periodic flush loop. Blocks until ctx is cancelled.
func (sa *SessionAggregator) Run(ctx context.Context) {
	ticker := time.NewTicker(sa.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sa.flushAndLog()
		}
	}
}

// HandleEvent is an EventCallback adapter for use with EventReader.AddCallback.
func (sa *SessionAggregator) HandleEvent(rec EventRecord, _ []byte) {
	sa.Add(rec)
}

func (sa *SessionAggregator) flushAndLog() {
	topSrc, topDst, droppedSrc, droppedDst := sa.flushWithDropped()

	if len(topSrc) == 0 && len(topDst) == 0 && droppedSrc == 0 && droppedDst == 0 {
		return
	}

	sa.mu.Lock()
	logFn := sa.logFn
	sa.mu.Unlock()

	// Surface the cardinality cap being hit. A non-zero count means new
	// source/destination keys were dropped this window because a map reached
	// the cap (defaultMaxAggKeys) — an incident-grade high-cardinality signal,
	// not just a sizing hint. Emit at warning severity so it is visible.
	if droppedSrc > 0 || droppedDst > 0 {
		msg := fmt.Sprintf("RT_FLOW_SESSION_AGGREGATE dropped-keys source=%d destination=%d cap=%d "+
			"(high source/destination cardinality exceeded the aggregation cap; top-N covers admitted keys only)",
			droppedSrc, droppedDst, sa.maxKeys)
		if logFn != nil {
			logFn(SyslogWarning, msg)
		}
		slog.Warn(msg)
	}

	for _, e := range topSrc {
		msg := fmt.Sprintf("RT_FLOW_SESSION_AGGREGATE top-source=%q sessions=%d bytes=%d",
			e.IP, e.Sessions, e.Bytes)
		if logFn != nil {
			logFn(SyslogInfo, msg)
		}
		slog.Info(msg)
	}
	for _, e := range topDst {
		msg := fmt.Sprintf("RT_FLOW_SESSION_AGGREGATE top-destination=%q sessions=%d bytes=%d",
			e.IP, e.Sessions, e.Bytes)
		if logFn != nil {
			logFn(SyslogInfo, msg)
		}
		slog.Info(msg)
	}
}

func topEntries(m map[string]*aggEntry, n int) []AggregateEntry {
	if len(m) == 0 {
		return nil
	}
	entries := make([]AggregateEntry, 0, len(m))
	for ip, e := range m {
		entries = append(entries, AggregateEntry{IP: ip, Sessions: e.Sessions, Bytes: e.Bytes})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Bytes > entries[j].Bytes
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}
