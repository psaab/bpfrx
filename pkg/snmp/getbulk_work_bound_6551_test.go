package snmp

import (
	"bytes"
	"math"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #6551: GETBULK used to materialize the whole repeaters x max-repetitions grid
// BEFORE the RFC 3416 §4.2.3 response-size bound was applied. repeaterCount is
// len(oids)-nonRepeaters and is bounded only by how many varbinds a manager can
// pack into one request datagram, and every grid cell costs a findNextOIDSnap
// MIB walk plus a getOIDValueSnap.
//
// Measured on the pre-fix code with 50 interfaces, a 4094-byte v2c GETBULK
// carrying 580 minimal repeater OIDs and max-repetitions >= 100:
//
//	varbinds BUILT   58,000   (405 ms inside buildBulkVarbinds)
//	varbinds RETURNED   116   (4092-byte response)
//	end-to-end handlePacket   667 ms   vs a ~2.5 us single-varbind poll
//
// (the trim itself accounts for the remaining ~260 ms: trimToFit binary-searches
// ~log2(58000) = 16 full re-encodes of the 58,000-varbind list). ~1.5 requests
// per second saturate the single serial SNMP goroutine permanently.
//
// Post-fix the same request builds 118 varbinds in 48 us and answers in 1.0 ms,
// returning the identical 116 varbinds.
//
// These tests assert on varbinds BUILT, not returned: the returned count was
// always ~116, so a test that only checked the response would pass on the
// unfixed code.

// minVarbindEncodedBytes is the smallest number of bytes any varbind can
// occupy in an encoded varbind list: a SEQUENCE header (tag + 1 length byte)
// wrapping an empty-bodied OID TLV and an empty-bodied value TLV. berEncodeOID
// returns a nil body for an OID with fewer than two components, so 2+2+2 is
// actually reachable and this is a true floor, not an estimate.
const minVarbindEncodedBytes = 6

// varbindListEncodedLen sums the exact encoded size of a varbind list.
func varbindListEncodedLen(vbs []varbind) int {
	total := 0
	for _, vb := range vbs {
		total += varbindEncodedLen(vb)
	}
	return total
}

// maxRepeaterBulkRequest builds the largest v2c GETBULK datagram that still fits
// in maxPacketSize, packing as many copies of start as possible as repeater
// OIDs. It returns the datagram and the repeater count, which is the R that
// multiplies max-repetitions in the grid.
func maxRepeaterBulkRequest(t *testing.T, community string, maxReps int, start []int) (req []byte, repeaters int) {
	t.Helper()
	var oids [][]int
	for {
		cand := append(oids, start)
		next := buildV2cGetBulkRequest(community, 1, 0, maxReps, cand)
		if len(next) > maxPacketSize {
			break
		}
		oids, req = cand, next
	}
	if len(oids) == 0 {
		t.Fatalf("no repeater OID fits in %d bytes", maxPacketSize)
	}
	return req, len(oids)
}

// bulkTestAgent returns a v2c agent serving n synthetic interfaces.
func bulkTestAgent(n int) *Agent {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(func() []IfData { return manyIfData(n) })
	return a
}

// decodeBulkPDU strips the v2c envelope off a GETBULK request and returns the
// decoded, clamp-applied PDU fields the handler would work from.
func decodeBulkPDU(t *testing.T, req []byte) (nonRepeaters, maxRepetitions int, oids [][]int) {
	t.Helper()
	_, body, err := berDecodeHeader(req)
	if err != nil {
		t.Fatalf("request: outer SEQUENCE: %v", err)
	}
	_, rest, err := berDecodeInteger(body) // version
	if err != nil {
		t.Fatalf("request: version: %v", err)
	}
	_, rest, err = berDecodeOctetString(rest) // community
	if err != nil {
		t.Fatalf("request: community: %v", err)
	}
	_, pduBody, err := berDecodeHeader(rest)
	if err != nil {
		t.Fatalf("request: PDU header: %v", err)
	}
	_, nonRepeaters, maxRepetitions, oids, err = decodePDUFields(pduBody)
	if err != nil {
		t.Fatalf("request: PDU fields: %v", err)
	}
	if maxRepetitions > 100 {
		maxRepetitions = 100 // the handler's own defense-in-depth clamp
	}
	return nonRepeaters, maxRepetitions, oids
}

// TestGetBulkBuildBounded_6551 is the fail-on-revert guard. It drives the
// worst-case shape — a max-size datagram of minimal repeater OIDs with
// max-repetitions clamped to 100 — straight at buildBulkVarbinds and asserts on
// how many varbinds it BUILT.
//
// To neutralize the fix for a RED-on-revert check, make bulkBudget.add always
// report false (`return false` as its body); that compiles cleanly and restores
// the unbounded grid, and this test then fails on the built-count assertions.
func TestGetBulkBuildBounded_6551(t *testing.T) {
	a := bulkTestAgent(50)
	req, repeaters := maxRepeaterBulkRequest(t, "public", 100000, []int{1, 3})
	nonRep, maxReps, oids := decodeBulkPDU(t, req)

	if repeaters < 100 {
		t.Fatalf("test is not exercising the defect: only %d repeaters fit", repeaters)
	}
	if maxReps != 100 {
		t.Fatalf("max-repetitions clamp = %d, want 100", maxReps)
	}
	grid := repeaters * maxReps // what the pre-fix code materialized

	maxSize := effectiveMaxSize(maxPacketSize)
	built := a.buildBulkVarbinds(oids, nonRep, maxReps, a.newIfSnapshot(), maxSize)

	// (1) Structural bound: every varbind occupies at least
	// minVarbindEncodedBytes on the wire, so a build that stops at the response
	// ceiling can never produce more than maxSize/minVarbindEncodedBytes cells
	// (+1 for the cell that trips the budget).
	hardCap := maxSize/minVarbindEncodedBytes + 1
	if len(built) > hardCap {
		t.Fatalf("buildBulkVarbinds built %d varbinds for a %d-byte ceiling; "+
			"at >= %d bytes each no more than %d can ever be returned "+
			"(grid was %d cells, each a MIB walk)",
			len(built), maxSize, minVarbindEncodedBytes, hardCap, grid)
	}

	// (2) Exact invariant: everything built except the cell that tripped the
	// budget must still fit the ceiling. This is the real contract — "never
	// build more than can be returned" — and it is what makes the work
	// proportional to the response rather than to R*M.
	if n := len(built); n > 1 {
		if used := varbindListEncodedLen(built[:n-1]); used > maxSize {
			t.Fatalf("varbinds built beyond the ceiling: built[:%d] encodes to %d bytes > %d",
				n-1, used, maxSize)
		}
	}

	// (3) Amplification: the response for this request is ~116 varbinds. The
	// pre-fix build/return ratio was 500x.
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	errStatus, returned := v2cResponseVarbinds(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError", errStatus)
	}
	if len(returned) == 0 {
		t.Fatal("no varbinds returned; manager cannot continue the walk")
	}
	// Every cell the grid builds past the returned prefix is pure waste. The
	// envelope (version/community/PDU headers) costs at most a handful of
	// varbinds' worth of budget, so a correct stop overshoots by a tiny margin.
	if len(built) > len(returned)+16 {
		t.Fatalf("built %d varbinds to return %d (%.0fx amplification); "+
			"the grid is not bounded by the response ceiling",
			len(built), len(returned), float64(len(built))/float64(len(returned)))
	}
	t.Logf("grid %d cells -> built %d -> returned %d (%d-byte response)",
		grid, len(built), len(returned), len(resp))
}

// TestGetBulkCostDoesNotScaleWithMaxRepetitions_6551 guards the CALL SITES.
// The assertions above drive buildBulkVarbinds directly with the real ceiling,
// so they would still pass if handleGetBulk (or the v3 dispatcher) started
// handing it an effectively infinite budget. This one goes through
// handlePacket and pins the property that actually matters end to end: once the
// response ceiling is reached, answering a GETBULK must cost the same whether
// the manager asked for 1 repetition or 100.
//
// It is a ratio between two measurements of the same magnitude on the same
// machine, not an absolute deadline, so machine load cancels out. Pre-fix the
// R*100 grid costs ~100x the R*1 grid (58,000 cells vs 580); post-fix both stop
// at the same ~118 cells and the ratio sits near 1. The 10x threshold has an
// order of magnitude of headroom on both sides.
func TestGetBulkCostDoesNotScaleWithMaxRepetitions_6551(t *testing.T) {
	a := bulkTestAgent(50)
	oneRep, _ := maxRepeaterBulkRequest(t, "public", 1, []int{1, 3})
	manyRep, repeaters := maxRepeaterBulkRequest(t, "public", 100, []int{1, 3})

	timeReq := func(req []byte) time.Duration {
		const iters = 5
		a.handlePacket(req) // warm any lazily-built state
		start := time.Now()
		for i := 0; i < iters; i++ {
			if a.handlePacket(req) == nil {
				t.Fatal("nil response")
			}
		}
		return time.Since(start) / iters
	}

	// Measure in both orders and keep the better (smallest) reading for each, so
	// a scheduling hiccup landing on one measurement cannot manufacture a ratio.
	one, many := timeReq(oneRep), timeReq(manyRep)
	if second := timeReq(manyRep); second < many {
		many = second
	}
	if second := timeReq(oneRep); second < one {
		one = second
	}
	if one <= 0 {
		t.Skip("timer resolution too coarse to compare")
	}

	ratio := float64(many) / float64(one)
	t.Logf("%d repeaters: max-repetitions=1 %v, max-repetitions=100 %v (ratio %.1fx)",
		repeaters, one, many, ratio)
	if ratio > 10 {
		t.Fatalf("GETBULK cost scales with max-repetitions: %v at M=1 vs %v at M=100 (%.1fx); "+
			"the grid is still expanding past the response ceiling", one, many, ratio)
	}
}

// TestGetBulkBuildBoundedV3_6551 is the same guard for the SNMPv3 path, which
// shares buildBulkVarbinds but bounds against the manager-advertised
// msgMaxSize. An unbounded grid hurts more here: every trimToFit rebuild re-runs
// USM framing and HMAC over the whole varbind list.
func TestGetBulkBuildBoundedV3_6551(t *testing.T) {
	a, authKey, engineID, boots, tm := v3GetBulkAgent(t, manyIfData(50))

	// Pack the v3 request with as many minimal repeater OIDs as fit.
	var oids [][]int
	var req []byte
	for {
		cand := append(oids, []int{1, 3})
		next := buildV3GetBulkRequest(t, "sha", "alice", engineID, authKey, boots, tm,
			maxPacketSize, 0, 100, cand)
		if len(next) > maxPacketSize {
			break
		}
		oids, req = cand, next
	}
	if len(oids) < 100 {
		t.Fatalf("test is not exercising the defect: only %d v3 repeaters fit", len(oids))
	}

	maxSize := effectiveMaxSize(maxPacketSize)
	built := a.buildBulkVarbinds(oids, 0, 100, a.newIfSnapshot(), maxSize)
	hardCap := maxSize/minVarbindEncodedBytes + 1
	if len(built) > hardCap {
		t.Fatalf("v3 buildBulkVarbinds built %d varbinds for a %d-byte ceiling, cap %d (grid was %d cells)",
			len(built), maxSize, hardCap, len(oids)*100)
	}

	resp := a.handlePacketFrom(req, nil)
	if resp == nil {
		t.Fatal("nil v3 response")
	}
	if len(resp) > maxPacketSize {
		t.Fatalf("v3 response %d bytes exceeds %d", len(resp), maxPacketSize)
	}
	errStatus, returned := v3ResponseErrorStatus(t, resp)
	if errStatus != errNoError {
		t.Fatalf("v3 error-status = %d, want noError", errStatus)
	}
	if len(built) > len(returned)+16 {
		t.Fatalf("v3 built %d varbinds to return %d; grid not bounded by the ceiling",
			len(built), len(returned))
	}
	t.Logf("v3: grid %d cells -> built %d -> returned %d (%d-byte response)",
		len(oids)*100, len(built), len(returned), len(resp))
}

// TestGetBulkBoundedMatchesUnbounded_6551 is the over-reach guard. Stopping the
// grid early must be output-neutral: for every shape, the response built from
// the bounded grid must be BYTE-IDENTICAL to the one built from the full
// (pre-fix) grid, because the cells the stop drops are exactly the ones
// trimToFit would have discarded.
//
// math.MaxInt as the budget reproduces the pre-fix expansion exactly — the
// budget never trips — so the comparison is against the real old behavior, not
// against a restatement of the new one.
//
// The walk start OIDs deliberately sit at or after sysUpTime in the static OID
// order, so no varbind in these responses carries the live TimeTicks counter,
// which would otherwise differ between the two builds for reasons unrelated to
// the bound.
func TestGetBulkBoundedMatchesUnbounded_6551(t *testing.T) {
	deepTail := []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18, 50}
	cases := []struct {
		name         string
		ifaces       int
		nonRepeaters int
		maxReps      int
		oids         [][]int
	}{
		// Ordinary small requests: must be untouched by the bound.
		{"small-one-repeater", 1, 0, 3, [][]int{oidSysUpTime}},
		{"small-three-columns", 4, 0, 5, [][]int{oidSysUpTime, oidIfTablePrefix, oidIfXTablePrefix}},
		{"small-with-nonrepeaters", 4, 2, 4, [][]int{oidSysUpTime, oidIfNumber, oidIfTablePrefix, oidIfXTablePrefix}},
		// MIB exhaustion: columns run off the end of the view and emit
		// endOfMibView placeholders; the bound must not disturb that.
		{"exhausted-columns", 2, 0, 40, [][]int{deepTail, oidIfXTablePrefix}},
		{"exhausted-nonrepeater", 2, 1, 20, [][]int{deepTail, oidIfTablePrefix}},
		// Oversized: the bound actually fires and the response is trimmed.
		{"oversized-single-column", 50, 0, 100, [][]int{oidIfTablePrefix}},
		{"oversized-deep-tail", 50, 0, 100, [][]int{deepTail}},
		{"oversized-many-columns", 50, 0, 100, repeatOID(oidIfTablePrefix, 60)},
		{"oversized-with-nonrepeaters", 50, 3, 100, repeatOID(oidIfXTablePrefix, 40)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := bulkTestAgent(tc.ifaces)
			maxSize := effectiveMaxSize(maxPacketSize)
			build := func(vbs []varbind) []byte {
				return a.buildResponse([]byte("public"), 42, errNoError, 0, vbs)
			}

			bounded := a.buildBulkVarbinds(tc.oids, tc.nonRepeaters, tc.maxReps, a.newIfSnapshot(), maxSize)
			unbounded := a.buildBulkVarbinds(tc.oids, tc.nonRepeaters, tc.maxReps, a.newIfSnapshot(), math.MaxInt)

			if len(bounded) > len(unbounded) {
				t.Fatalf("bounded build produced MORE varbinds (%d) than the unbounded one (%d)",
					len(bounded), len(unbounded))
			}
			// The bounded list must be a prefix of the unbounded one: same
			// cells, same order, just stopped early (RFC 3416 §4.2.3 removes
			// from the END of the ordered set).
			for i := range bounded {
				if !oidEqual(bounded[i].oid, unbounded[i].oid) ||
					bounded[i].tag != unbounded[i].tag ||
					!bytes.Equal(bounded[i].value, unbounded[i].value) {
					t.Fatalf("varbind[%d] differs: bounded {oid=%v tag=0x%02x} vs unbounded {oid=%v tag=0x%02x}",
						i, bounded[i].oid, bounded[i].tag, unbounded[i].oid, unbounded[i].tag)
				}
			}

			boundedResp, okB := trimToFit(bounded, maxSize, build)
			unboundedResp, okU := trimToFit(unbounded, maxSize, build)
			if okB != okU {
				t.Fatalf("trimToFit ok mismatch: bounded=%v unbounded=%v", okB, okU)
			}
			if !bytes.Equal(boundedResp, unboundedResp) {
				t.Fatalf("response differs from the unbounded build: %d bytes vs %d bytes",
					len(boundedResp), len(unboundedResp))
			}
			if len(boundedResp) > maxSize {
				t.Fatalf("response %d bytes exceeds ceiling %d", len(boundedResp), maxSize)
			}
			t.Logf("grid %d cells, built %d (unbounded %d), response %d bytes",
				len(tc.oids)*tc.maxReps, len(bounded), len(unbounded), len(boundedResp))
		})
	}
}

// repeatOID returns n copies of oid, for building wide repeater lists.
func repeatOID(oid []int, n int) [][]int {
	out := make([][]int, n)
	for i := range out {
		out[i] = oid
	}
	return out
}

// TestVarbindEncodedLenMatchesEncoder_6551 pins varbindEncodedLen to what the
// response encoder actually emits. The bound is only output-neutral while the
// accounted size is a true lower bound on the encoded message: an OVERestimate
// would stop the grid short of varbinds that would have fit and silently shrink
// every large GETBULK response. The expected value is read back off a real
// encoded response rather than recomputed, so this fails if the two encodings
// ever drift apart.
func TestVarbindEncodedLenMatchesEncoder_6551(t *testing.T) {
	a := bulkTestAgent(1)
	long := make([]byte, 300) // forces a multi-byte BER length header
	for i := range long {
		long[i] = 'x'
	}
	cases := []struct {
		name string
		vb   varbind
	}{
		{"short-oid-octet-string", varbind{oid: oidSysDescr, tag: tagOctetString, value: []byte("xpf")}},
		{"empty-value", varbind{oid: oidSysContact, tag: tagOctetString, value: nil}},
		{"long-value-multibyte-length", varbind{oid: oidSysLocation, tag: tagOctetString, value: long}},
		{"integer", varbind{oid: oidIfNumber, tag: tagInteger, value: berEncodeIntegerValue(42)}},
		{"counter64", varbind{oid: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 1}, tag: tagCounter64,
			value: berEncodeCounter64(18000000000000000000)}},
		{"end-of-mib-view", varbind{oid: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18, 50}, tag: tagEndOfMibView}},
		{"no-such-instance", varbind{oid: oidSysName, tag: tagNoSuchInstance}},
		{"no-such-object", varbind{oid: oidSysObjectID, tag: tagNoSuchObject}},
		{"large-subid-oid", varbind{oid: []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2097151}, tag: tagInteger,
			value: berEncodeIntegerValue(1)}},
		{"short-oid-no-body", varbind{oid: []int{1}, tag: tagEndOfMibView}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := a.buildResponse([]byte("public"), 1, errNoError, 0, []varbind{tc.vb})
			want := onlyVarbindEncodedLen(t, resp)
			if got := varbindEncodedLen(tc.vb); got != want {
				t.Fatalf("varbindEncodedLen = %d, encoder emitted %d bytes", got, want)
			}
		})
	}

	// A varbind can never encode to fewer than minVarbindEncodedBytes, which is
	// what the structural cap in TestGetBulkBuildBounded_6551 rests on.
	for _, tc := range cases {
		if n := varbindEncodedLen(tc.vb); n < minVarbindEncodedBytes {
			t.Fatalf("%s: varbindEncodedLen = %d < floor %d", tc.name, n, minVarbindEncodedBytes)
		}
	}
}

// onlyVarbindEncodedLen returns the encoded byte length of the single varbind in
// a v2c GetResponse, read straight off the wire. It walks TLV headers only and
// never decodes the OID body, so it also measures degenerate shapes (an OID with
// fewer than two components encodes to an empty body, which berDecodeOID
// rejects) — buildBulkVarbinds echoes request OIDs verbatim in its endOfMibView
// cells, so such a varbind is reachable and must still be accounted correctly.
func onlyVarbindEncodedLen(t *testing.T, resp []byte) int {
	t.Helper()
	_, body, err := berDecodeHeader(resp)
	if err != nil {
		t.Fatalf("resp: outer SEQUENCE: %v", err)
	}
	_, rest, err := berDecodeInteger(body) // version
	if err != nil {
		t.Fatalf("resp: version: %v", err)
	}
	_, rest, err = berDecodeOctetString(rest) // community
	if err != nil {
		t.Fatalf("resp: community: %v", err)
	}
	_, pduBody, err := berDecodeHeader(rest)
	if err != nil {
		t.Fatalf("resp: PDU: %v", err)
	}
	_, pduRest, err := berDecodeInteger(pduBody) // request-id
	if err != nil {
		t.Fatalf("resp: request-id: %v", err)
	}
	_, pduRest, err = berDecodeInteger(pduRest) // error-status
	if err != nil {
		t.Fatalf("resp: error-status: %v", err)
	}
	_, pduRest, err = berDecodeInteger(pduRest) // error-index
	if err != nil {
		t.Fatalf("resp: error-index: %v", err)
	}
	tag, vbListBody, err := berDecodeHeader(pduRest)
	if err != nil || tag != tagSequence {
		t.Fatalf("resp: varbind list: %v", err)
	}
	n := berEncodedLen(vbListBody)
	if n <= 0 || n > len(vbListBody) {
		t.Fatalf("resp: varbind length %d out of range (list body %d)", n, len(vbListBody))
	}
	return n
}

// TestGetBulkTrimmedTailIsWellFormed_6551 checks the truncated response is one a
// normal manager can act on, not merely a smaller one: the varbind list decodes
// cleanly, stays in repetition-major order (varbind index nonRepeaters+rep*R+col
// per RFC 3416 §4.2.3 / #5065), the tail is a complete varbind rather than a
// severed one, and any endOfMibView marker sits in its own column's cell.
func TestGetBulkTrimmedTailIsWellFormed_6551(t *testing.T) {
	const repeaters = 3
	a := bulkTestAgent(50)
	oids := [][]int{oidIfTablePrefix, oidIfXTablePrefix, []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18, 40}}
	req := buildV2cGetBulkRequest("public", 7, 0, 100, oids)

	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp) > maxPacketSize {
		t.Fatalf("response %d bytes exceeds %d", len(resp), maxPacketSize)
	}
	// decodeVarbindOIDs fatals on any malformed varbind, so a clean decode is
	// itself the well-formedness check.
	errStatus, got := v2cResponseVarbinds(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError", errStatus)
	}
	if len(got) < repeaters {
		t.Fatalf("only %d varbinds returned; not even one full repetition", len(got))
	}

	// The response must be the leading prefix of the unbounded grid, so each
	// returned varbind still lands in its originating column.
	full := a.buildBulkVarbinds(oids, 0, 100, a.newIfSnapshot(), math.MaxInt)
	if len(got) > len(full) {
		t.Fatalf("returned %d varbinds, grid only has %d", len(got), len(full))
	}
	for i := range got {
		if !oidEqual(got[i], full[i].oid) {
			t.Fatalf("varbind[%d] OID %v is not the grid's cell %v (order or column alignment broken)",
				i, got[i], full[i].oid)
		}
	}

	// Column 2 starts at the ifXTable tail and exhausts almost immediately, so
	// its cells become endOfMibView while columns 0/1 keep returning data —
	// exactly the per-column placeholder contract. Verify the exhausted column's
	// cells carry endOfMibView and the others do not.
	sawExhausted := false
	for i := 0; i+repeaters <= len(got); i += repeaters {
		if full[i+2].tag == tagEndOfMibView {
			sawExhausted = true
		}
		for col := 0; col < 2; col++ {
			if full[i+col].tag == tagEndOfMibView {
				t.Fatalf("column %d cell at varbind %d is endOfMibView; it should still have data",
					col, i+col)
			}
		}
	}
	if !sawExhausted {
		t.Fatal("test did not exercise an exhausted column; endOfMibView placement unverified")
	}
}
