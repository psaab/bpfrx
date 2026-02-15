package logging

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// SessionAggregator tracks session statistics and periodically flushes
// top-N source and destination reports.
type SessionAggregator struct {
	mu   sync.Mutex
	srcs map[string]*aggEntry // srcIP -> stats
	dsts map[string]*aggEntry // dstIP -> stats

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

	if e, ok := sa.srcs[srcIP]; ok {
		e.Sessions++
		e.Bytes += rec.SessionBytes
	} else {
		sa.srcs[srcIP] = &aggEntry{Sessions: 1, Bytes: rec.SessionBytes}
	}

	if e, ok := sa.dsts[dstIP]; ok {
		e.Sessions++
		e.Bytes += rec.SessionBytes
	} else {
		sa.dsts[dstIP] = &aggEntry{Sessions: 1, Bytes: rec.SessionBytes}
	}
}

// Flush returns top-N sources and destinations by bytes, then resets counters.
func (sa *SessionAggregator) Flush() (topSrc, topDst []AggregateEntry) {
	sa.mu.Lock()
	srcs := sa.srcs
	dsts := sa.dsts
	sa.srcs = make(map[string]*aggEntry)
	sa.dsts = make(map[string]*aggEntry)
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
	topSrc, topDst := sa.Flush()

	if len(topSrc) == 0 && len(topDst) == 0 {
		return
	}

	sa.mu.Lock()
	logFn := sa.logFn
	sa.mu.Unlock()

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
