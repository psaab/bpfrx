package logging

import (
	"strings"
	"sync"
	"time"
)

// EventRecord is a formatted event stored in the event buffer.
type EventRecord struct {
	Time            time.Time
	Type            string // "SESSION_OPEN", "POLICY_DENY", etc.
	SrcAddr         string // "10.0.1.5:443"
	DstAddr         string
	Protocol        string // "TCP", "UDP" (rendered name; numeric for unnamed)
	ProtocolNum     uint8  // raw IP protocol number the record carries (#3382). The matcher compares this directly rather than re-parsing the rendered name: numeric comparison stays total for named, numeric-only, and any future render-only protocols (the ProtocolName↔ProtocolNumber round-trip is closed since #3393, but the raw number is the robust key regardless).
	Action          string // "permit", "deny"
	PolicyID        uint32
	RuleID          uint32
	TermID          uint32
	Reason          string
	OwnerRGID       int16
	InZone          uint16
	OutZone         uint16
	ScreenCheck     string // for SCREEN_DROP
	SessionPkts     uint64 // for SESSION_CLOSE (client→server)
	SessionBytes    uint64
	NATSrcAddr      string // "172.16.1.1:12345" (post-NAT source)
	NATDstAddr      string // "10.0.2.1:80" (post-NAT destination)
	InZoneName      string // resolved zone name
	OutZoneName     string // resolved zone name
	ElapsedTime     uint32 // seconds since session creation (for CLOSE)
	Created         uint32 // #2465: absolute session-creation Unix seconds (for CLOSE); 0 = unknown (exporter falls back to the packet-count estimate)
	CreatedNanos    uint32 // #2853: sub-second nanosecond remainder (0..=999_999_999) of the session-creation instant (SESSION_CLOSE only; rides the close-unused [44:48] wire slot). Combined with Created so the flow StartTime keeps millisecond resolution.
	PolicyName      string // resolved policy name (e.g. "allow-everything")
	RevSessionPkts  uint64 // packets from server (for SESSION_CLOSE)
	RevSessionBytes uint64 // bytes from server (for SESSION_CLOSE)
	AppName         string // resolved application name (e.g. "junos-http")
	IngressIface    string // resolved interface name (e.g. "trust0")
	// IngressIfindex is the raw numeric ingress ifindex carried on the
	// SESSION_CLOSE wire frame ([128:132], #2615). IngressIface is the
	// name resolution of this value; the numeric form is retained so the
	// NetFlow v9 / IPFIX exporters can populate ingressInterface
	// (IE 10 / IN_SNMP), which is an SNMP ifIndex, not a name (#2749).
	// 0 means the dataplane could not attribute an ingress interface.
	IngressIfindex uint32
	// #2749: class-of-service / interface-attribution fields carried on the
	// SESSION_CLOSE wire frame's additive [144:152] block. TOS is the IP ToS
	// byte (DSCP<<2, ECN cleared) observed on the forward direction;
	// TCPControlBits is the OR of every TCP flag byte seen over the flow;
	// EgressIfindex is the SNMP ifIndex of the session's resolved output
	// interface. They drive the re-introduced NetFlow v9 srcTos (IE 5) /
	// tcpFlags (IE 6) / OutputSNMP (IE 14) and the IPFIX ipClassOfService /
	// tcpControlBits / egressInterface close-record fields. 0 keeps the
	// collector's "unknown" sentinel for a frame that did not carry them
	// (a short legacy frame, or a non-close event).
	TOS            uint8
	TCPControlBits uint8
	EgressIfindex  uint32
	CloseReason    string // "idle Timeout", "TCP FIN", "TCP RST", etc.
	// SessionID is the dataplane's STABLE per-session identity (#4915). On a
	// SESSION_CREATE / SESSION_CLOSE frame it is decoded from the [152:160] wire
	// slot — the SAME uint64 the userspace-dp session table assigns and that
	// `show security flow session` will surface — so a session's open and close
	// records correlate and a reused 5-tuple is disambiguated. 0 means "unknown":
	// a non-session event (deny/screen/filter), or a short legacy frame that did
	// not carry the slot. Before #4915 this field held a per-EVENT monotonic
	// ordinal that could never match across a session's create and close; that
	// ordinal now lives in EventSeq.
	SessionID uint64
	// EventSeq is a per-EVENT monotonic ordinal stamped by the live event reader
	// (#4915). Unlike SessionID it increments on EVERY event (including
	// deny/screen/filter), so it orders events within a reader session and
	// exposes gaps; it is NOT a session identity and does not correlate a
	// session's create with its close. It is 0 on records produced by
	// DecodeRawEventRecord (which has no reader-scoped counter).
	EventSeq uint64
}

// EventBuffer is a thread-safe circular buffer for recent events.
type EventBuffer struct {
	mu    sync.RWMutex
	buf   []EventRecord
	size  int
	head  int    // next write position
	count int    // number of events stored
	seq   uint64 // monotonically increasing sequence number

	subMu   sync.RWMutex
	subs    map[*Subscription]struct{}
	maxSubs int // cap on concurrent subscribers (0 = unbounded)
}

// Subscription receives new events from an EventBuffer.
type Subscription struct {
	C    chan EventRecord
	eb   *EventBuffer
	once sync.Once
}

// Close unsubscribes and closes the channel (#3384). It honors the documented
// contract so a consumer ranging over sub.C until it closes terminates instead
// of blocking forever. The unsubscribe runs first under eb.subMu (write lock),
// which removes this subscription from the fan-out map and waits out any
// in-flight Add send — so close(s.C) afterwards can never race a send-on-closed
// in Add. sync.Once makes a double Close safe (the in-tree consumers Close via
// defer; some also Close explicitly).
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.eb.unsubscribe(s)
		close(s.C)
	})
}

// defaultEventBufferSize is the fallback ring capacity used when a caller
// requests a non-positive size. A zero-capacity ring is a footgun: Add
// indexes buf[head] and computes head % size, so size==0 panics with an
// index-out-of-range / divide-by-zero on the first event (#3342).
const defaultEventBufferSize = 1000

// defaultMaxSubscribers bounds the number of concurrent event-stream
// subscribers (#4484 L-2). Every Add fans out O(N) over the subscriber set
// and each subscriber holds a buffered channel, so an unbounded set is a
// memory + per-event-CPU DoS vector — chiefly via the untrusted REST SSE
// surface (/events/stream, /logs/stream), which can open many connections.
// This mirrors metricsMaxInFlight (#4162), which bounds concurrent /metrics
// scrapes. The cap counts ALL subscribers uniformly; the trusted internal
// consumers (gRPC event stream, CLI monitor) use Subscribe (never rejected)
// and are few, so the untrusted REST path is what the cap actually gates via
// TrySubscribe.
const defaultMaxSubscribers = 64

// NewEventBuffer creates a new event buffer with the given capacity. A
// non-positive size is clamped to defaultEventBufferSize so the ring is
// always usable; Add must never index an empty buffer or divide by zero.
func NewEventBuffer(size int) *EventBuffer {
	if size < 1 {
		size = defaultEventBufferSize
	}
	return &EventBuffer{
		buf:     make([]EventRecord, size),
		size:    size,
		subs:    make(map[*Subscription]struct{}),
		maxSubs: defaultMaxSubscribers,
	}
}

// Add appends an event to the buffer, overwriting the oldest if full.
// Subscribers are notified non-blocking.
func (eb *EventBuffer) Add(rec EventRecord) {
	eb.mu.Lock()
	eb.buf[eb.head] = rec
	eb.head = (eb.head + 1) % eb.size
	if eb.count < eb.size {
		eb.count++
	}
	eb.seq++
	eb.mu.Unlock()

	eb.subMu.RLock()
	for sub := range eb.subs {
		select {
		case sub.C <- rec:
		default: // drop if subscriber is slow
		}
	}
	eb.subMu.RUnlock()
}

// Subscribe returns a Subscription that receives new events.
// Call Close() on the subscription when done.
//
// Subscribe never fails: it is the entry point for the TRUSTED, inherently
// bounded internal consumers (gRPC event stream, CLI monitor). The untrusted
// REST SSE surface must use TrySubscribe, which enforces the concurrency cap.
func (eb *EventBuffer) Subscribe(bufSize int) *Subscription {
	if bufSize < 1 {
		bufSize = 64
	}
	sub := &Subscription{
		C:  make(chan EventRecord, bufSize),
		eb: eb,
	}
	eb.subMu.Lock()
	eb.subs[sub] = struct{}{}
	eb.subMu.Unlock()
	return sub
}

// TrySubscribe is Subscribe with a concurrency cap (#4484 L-2): it returns nil
// when the live subscriber count has reached maxSubs, so the untrusted REST
// SSE surface (/events/stream, /logs/stream) cannot grow the fan-out set — and
// its per-event O(N) cost — without bound. Callers MUST handle a nil return
// (the REST handlers respond 503). Trusted internal callers use Subscribe,
// which never fails but still counts toward the cap here.
func (eb *EventBuffer) TrySubscribe(bufSize int) *Subscription {
	if bufSize < 1 {
		bufSize = 64
	}
	sub := &Subscription{
		C:  make(chan EventRecord, bufSize),
		eb: eb,
	}
	eb.subMu.Lock()
	if eb.maxSubs > 0 && len(eb.subs) >= eb.maxSubs {
		eb.subMu.Unlock()
		return nil
	}
	eb.subs[sub] = struct{}{}
	eb.subMu.Unlock()
	return sub
}

func (eb *EventBuffer) unsubscribe(sub *Subscription) {
	eb.subMu.Lock()
	delete(eb.subs, sub)
	eb.subMu.Unlock()
}

// EventFilter specifies criteria for filtering events.
//
// Zone-filter presence is tracked by HasZone, NOT by overloading Zone==0 as
// "no filter" (#3338). Zone IDs are 1-based (the pkg/dataplane compiler
// assigns 1..N; see compiler.go phase 1), so zone 0 is the "unknown" /
// unassigned zone — the pre-classification drops, host-inbound, and
// emitted-before-zone-resolution events. Those are exactly the records an
// operator needs to isolate during an incident, so zone 0 MUST be a
// selectable filter value. With the old `Zone==0 means no filter` sentinel
// they were silently invisible to any zone-filtered query.
type EventFilter struct {
	Zone     uint16 // zone ID to match against InZone/OutZone; gated by HasZone
	HasZone  bool   // true if Zone is an active filter (0 = the unknown zone)
	Protocol string // exact case-insensitive match on Protocol ("" = no filter)
	Action   string // exact case-insensitive match on Action ("" = no filter)
}

// IsEmpty returns true if no filter criteria are set.
func (f EventFilter) IsEmpty() bool {
	return !f.HasZone && f.Protocol == "" && f.Action == ""
}

func (f EventFilter) matches(rec *EventRecord) bool {
	if f.HasZone && rec.InZone != f.Zone && rec.OutZone != f.Zone {
		return false
	}
	// Exact (case-insensitive) match, NOT substring: substring matching
	// over-matches for forensic queries — protocol=C would match TCP,
	// ICMP, and ICMPv6 simultaneously, and action substrings are equally
	// ambiguous (#2939). This aligns the event filter with the exact
	// matching the other operator surfaces use.
	if f.Protocol != "" && !strings.EqualFold(rec.Protocol, f.Protocol) {
		return false
	}
	if f.Action != "" && !strings.EqualFold(rec.Action, f.Action) {
		return false
	}
	return true
}

// LatestFiltered returns the most recent n events matching the filter, newest first.
func (eb *EventBuffer) LatestFiltered(n int, f EventFilter) []EventRecord {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if n <= 0 {
		return nil
	}

	var result []EventRecord
	for i := 0; i < eb.count && len(result) < n; i++ {
		idx := (eb.head - 1 - i + eb.size) % eb.size
		if f.matches(&eb.buf[idx]) {
			result = append(result, eb.buf[idx])
		}
	}
	return result
}

// Latest returns the most recent n events, newest first.
func (eb *EventBuffer) Latest(n int) []EventRecord {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	// Guard non-positive n first: a negative count must not reach
	// make([]EventRecord, n), which panics ("makeslice: len out of
	// range"). This mirrors LatestFiltered's `n <= 0` contract so a
	// count argument behaves identically on both surfaces (#3342).
	if n <= 0 {
		return nil
	}
	if n > eb.count {
		n = eb.count
	}
	if n == 0 {
		return nil
	}

	result := make([]EventRecord, n)
	for i := 0; i < n; i++ {
		// Walk backwards from the most recent entry
		idx := (eb.head - 1 - i + eb.size) % eb.size
		result[i] = eb.buf[idx]
	}
	return result
}
