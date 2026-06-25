package flowexport

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #2866 fail-on-revert pins: NetFlow v9 srcMask (IE 9) / dstMask (IE 13) and
// the IPFIX sourceIPv4PrefixLength (IE 9) / destinationIPv4PrefixLength (IE 13)
// — plus the IPv6 variants IE 29 / IE 30 — must carry the FIB longest-prefix-
// match prefix length of the flow's source/destination route, NOT the
// always-zero value they had before this change.
//
// Before #2866 the templates advertised (NetFlow) / never advertised (IPFIX)
// the mask fields and the encoder wrote FlowRecord.SrcMask/DstMask, but those
// members were never assigned in ExportSessionClose, so every flow exported a
// /0 mask. These tests inject a deterministic MaskResolver (no kernel FIB
// dependency) and assert:
//   - the FlowRecord built by ExportSessionClose carries the resolved masks;
//   - the encoded record carries the masks at the template's field offset.
// Reverting the SessionCloseData->FlowRecord mask population, the template
// field, or the encoder write flips one of these RED.

// Sentinel non-default prefix lengths so a reverted (always-0) population is
// detectable — a real /0 default route would falsely pass an "is it non-zero"
// check, so the resolver returns distinct non-zero values keyed by address.
const (
	testSrcMask uint8 = 24
	testDstMask uint8 = 30
)

// maskResolverFor returns a MaskResolver that maps the test src IP -> testSrcMask
// and the test dst IP -> testDstMask, mirroring a FIB that has a /24 covering
// the source and a /30 covering the destination.
func maskResolverFor(srcIP, dstIP net.IP) MaskResolver {
	return func(ip net.IP) (uint8, bool) {
		switch {
		case ip.Equal(srcIP):
			return testSrcMask, true
		case ip.Equal(dstIP):
			return testDstMask, true
		default:
			return 0, false
		}
	}
}

func closeRecordForMask(v6 bool) (logging.EventRecord, SessionCloseData) {
	rec := logging.EventRecord{
		Type:         "SESSION_CLOSE",
		Time:         time.Unix(1_700_000_100, 0),
		Created:      1_700_000_000,
		SessionPkts:  0x1122334455667788,
		SessionBytes: 0x99AABBCCDDEEFF00,
	}
	sd := SessionCloseData{SrcPort: 40000, DstPort: 80, Protocol: 6, IsIPv6: v6}
	if v6 {
		sd.SrcIP = net.ParseIP("fd00::1")
		sd.DstIP = net.ParseIP("2001:db8::200")
	} else {
		sd.SrcIP = net.IPv4(10, 0, 1, 100)
		sd.DstIP = net.IPv4(172, 16, 80, 200)
	}
	return rec, sd
}

// TestNetflowSrcDstMaskPopulated pins the NetFlow v9 mask fields.
func TestNetflowSrcDstMaskPopulated(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	opts := DefaultV9TemplateOptions()
	for _, tc := range []struct {
		name         string
		v6           bool
		fields       []templateField
		srcIE, dstIE uint16
	}{
		{"v4", false, netflowTemplateFieldsV4, fieldSrcMask, fieldDstMask},
		{"v6", true, netflowTemplateFieldsV6, fieldIPv6SrcMask, fieldIPv6DstMask},
	} {
		rec, sd := closeRecordForMask(tc.v6)

		srcOff, ok := netflowFieldBodyOffset(tc.fields, tc.srcIE)
		if !ok {
			t.Fatalf("%s: template missing srcMask IE %d", tc.name, tc.srcIE)
		}
		dstOff, ok := netflowFieldBodyOffset(tc.fields, tc.dstIE)
		if !ok {
			t.Fatalf("%s: template missing dstMask IE %d", tc.name, tc.dstIE)
		}

		e := Exporter{MaskResolver: maskResolverFor(sd.SrcIP, sd.DstIP)}
		e.ExportSessionClose(rec, sd)
		v4recs, v6recs := e.batch.drain()
		recs := v4recs
		if tc.v6 {
			recs = v6recs
		}
		if len(recs) != 1 {
			t.Fatalf("%s: drained %d records, want 1", tc.name, len(recs))
		}
		if recs[0].SrcMask != testSrcMask || recs[0].DstMask != testDstMask {
			t.Fatalf("%s: FlowRecord masks = src %d/dst %d, want %d/%d (population reverted)",
				tc.name, recs[0].SrcMask, recs[0].DstMask, testSrcMask, testDstMask)
		}

		fs := encodeDataFlowSet(recs, boot, opts)
		// 4-byte set header precedes the record body.
		if got := fs[4+srcOff]; got != testSrcMask {
			t.Fatalf("%s: encoded srcMask = %d, want %d (encoder write reverted)", tc.name, got, testSrcMask)
		}
		if got := fs[4+dstOff]; got != testDstMask {
			t.Fatalf("%s: encoded dstMask = %d, want %d (encoder write reverted)", tc.name, got, testDstMask)
		}
	}
}

// TestIPFIXSrcDstMaskPopulated mirrors the check for IPFIX.
func TestIPFIXSrcDstMaskPopulated(t *testing.T) {
	for _, tc := range []struct {
		name         string
		v6           bool
		fields       []ipfixField
		srcIE, dstIE uint16
	}{
		{"v4", false, ipfixTemplateV4, ipfixSourceIPv4PrefixLength, ipfixDestIPv4PrefixLength},
		{"v6", true, ipfixTemplateV6, ipfixSourceIPv6PrefixLength, ipfixDestIPv6PrefixLength},
	} {
		rec, sd := closeRecordForMask(tc.v6)

		srcOff, ok := ipfixFieldBodyOffset(tc.fields, tc.srcIE)
		if !ok {
			t.Fatalf("%s: template missing srcMask IE %d", tc.name, tc.srcIE)
		}
		dstOff, ok := ipfixFieldBodyOffset(tc.fields, tc.dstIE)
		if !ok {
			t.Fatalf("%s: template missing dstMask IE %d", tc.name, tc.dstIE)
		}

		e := IPFIXExporter{MaskResolver: maskResolverFor(sd.SrcIP, sd.DstIP)}
		e.ExportSessionClose(rec, sd)
		v4recs, v6recs := e.batch.drain()
		recs := v4recs
		if tc.v6 {
			recs = v6recs
		}
		if len(recs) != 1 {
			t.Fatalf("%s: drained %d records, want 1", tc.name, len(recs))
		}
		if recs[0].SrcMask != testSrcMask || recs[0].DstMask != testDstMask {
			t.Fatalf("%s: FlowRecord masks = src %d/dst %d, want %d/%d (population reverted)",
				tc.name, recs[0].SrcMask, recs[0].DstMask, testSrcMask, testDstMask)
		}

		ds := encodeIPFIXDataSet(recs)
		if got := ds[4+srcOff]; got != testSrcMask {
			t.Fatalf("%s: encoded srcMask = %d, want %d (encoder write reverted)", tc.name, got, testSrcMask)
		}
		if got := ds[4+dstOff]; got != testDstMask {
			t.Fatalf("%s: encoded dstMask = %d, want %d (encoder write reverted)", tc.name, got, testDstMask)
		}
	}
}

// TestRouteMaskCacheResolves checks the cache wrapper returns the lookup's
// result, caches it (a second call with a deliberately changed lookup still
// returns the cached value within TTL), and handles a default-route /0 as a
// successful resolve (ok=true) distinct from a miss (ok=false).
func TestRouteMaskCacheResolves(t *testing.T) {
	calls := 0
	c := &routeMaskCache{
		ttl:     time.Hour,
		entries: make(map[string]routeMaskEntry),
	}
	c.lookup = func(net.IP) (uint8, bool) {
		calls++
		return 16, true
	}
	ip := net.IPv4(192, 0, 2, 1)
	if m, ok := c.resolve(ip); m != 16 || !ok {
		t.Fatalf("first resolve = %d,%v want 16,true", m, ok)
	}
	// Swap the lookup; within TTL the cached value must win (no new call).
	c.lookup = func(net.IP) (uint8, bool) { calls++; return 99, true }
	if m, ok := c.resolve(ip); m != 16 || !ok {
		t.Fatalf("cached resolve = %d,%v want 16,true (cache miss?)", m, ok)
	}
	if calls != 1 {
		t.Fatalf("lookup called %d times, want 1 (cache not used)", calls)
	}
	// nil IP -> miss without a lookup.
	if m, ok := c.resolve(nil); m != 0 || ok {
		t.Fatalf("nil IP resolve = %d,%v want 0,false", m, ok)
	}
}

// TestRouteMaskCacheBounded is a fail-on-revert pin for the cache size bound.
// Inserting many more distinct keys than the cap must NOT grow the map without
// bound — len(entries) stays <= maxSize. Reverting evictLocked (the unbounded
// map[key]=val of the original #2866 implementation) lets the map grow to the
// full insert count and flips this RED. A within-TTL repeated key still hits
// the cache (no extra lookup), so the bound does not break the hit path.
func TestRouteMaskCacheBounded(t *testing.T) {
	const maxSize = 64
	calls := 0
	c := &routeMaskCache{
		ttl:     time.Hour, // long TTL: entries never expire during the test,
		maxSize: maxSize,   // so the bound is enforced purely by the size cap.
		entries: make(map[string]routeMaskEntry),
	}
	c.lookup = func(net.IP) (uint8, bool) { calls++; return 24, true }

	// Insert far more distinct keys than the cap. Each is a fresh IPv4 address.
	const inserts = maxSize * 10
	for i := 0; i < inserts; i++ {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		c.resolve(ip)
		if got := len(c.entries); got > maxSize {
			t.Fatalf("after %d inserts len(entries) = %d, want <= %d (cache unbounded — leak)",
				i+1, got, maxSize)
		}
	}
	if calls != inserts {
		t.Fatalf("lookup called %d times, want %d (one per distinct insert)", calls, inserts)
	}

	// A repeated key within TTL must still hit the cache (no new lookup), even
	// after the churn above evicted older entries.
	before := calls
	ip := net.IPv4(192, 0, 2, 7)
	if m, ok := c.resolve(ip); m != 24 || !ok {
		t.Fatalf("warm insert = %d,%v want 24,true", m, ok)
	}
	if m, ok := c.resolve(ip); m != 24 || !ok {
		t.Fatalf("warm hit = %d,%v want 24,true", m, ok)
	}
	if calls != before+1 {
		t.Fatalf("repeated key triggered %d lookups, want 1 (hit path broken)", calls-before)
	}
	if len(c.entries) > maxSize {
		t.Fatalf("final len(entries) = %d, want <= %d", len(c.entries), maxSize)
	}
}

// TestRouteMaskCacheEvictsExpiredFirst checks that at the cap the bound first
// drops expired entries (recovering headroom) before resorting to a full clear,
// so a steady cache of live entries below the cap is not needlessly wiped.
func TestRouteMaskCacheEvictsExpiredFirst(t *testing.T) {
	const maxSize = 4
	c := &routeMaskCache{
		ttl:     time.Hour,
		maxSize: maxSize,
		entries: make(map[string]routeMaskEntry),
	}
	c.lookup = func(net.IP) (uint8, bool) { return 16, true }

	past := time.Now().Add(-time.Hour)
	// Fill to the cap: 1 live entry + (maxSize-1) already-expired entries.
	live := net.IPv4(10, 0, 0, 1)
	c.entries[string(live.To16())] = routeMaskEntry{mask: 16, ok: true, expires: time.Now().Add(time.Hour)}
	for i := 0; i < maxSize-1; i++ {
		ip := net.IPv4(10, 0, 1, byte(i))
		c.entries[string(ip.To16())] = routeMaskEntry{mask: 16, ok: true, expires: past}
	}
	if len(c.entries) != maxSize {
		t.Fatalf("setup len = %d, want %d", len(c.entries), maxSize)
	}

	// A new key at the cap should purge the expired entries (not clear the
	// whole map), leaving the live entry + the newcomer.
	c.resolve(net.IPv4(203, 0, 113, 9))
	if _, ok := c.entries[string(live.To16())]; !ok {
		t.Fatalf("live entry was wiped — expired-first purge did not run")
	}
	if len(c.entries) > maxSize {
		t.Fatalf("len after purge = %d, want <= %d", len(c.entries), maxSize)
	}
}

// TestResolveMasksNilResolver pins the pre-#2866 fallback: a zero-value
// exporter (nil resolver) leaves both masks 0.
func TestResolveMasksNilResolver(t *testing.T) {
	s, d := resolveMasks(nil, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))
	if s != 0 || d != 0 {
		t.Fatalf("nil resolver masks = %d/%d, want 0/0", s, d)
	}
}
