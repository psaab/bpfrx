package snmp

import (
	"bytes"
	"math"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9133: OID sub-identifiers were modelled as a platform-width SIGNED `int`
// with no RFC 2578 bound, and three symptoms followed from that ONE modelling
// choice — a silently wrapped decode, an encoder that emitted a lone
// continuation octet for a negative value, and a signed `oidCompare` that
// sorted a huge sub-id before 1.
//
// The fix bounds the DECODER, which is the only entry point from the wire, and
// makes the encoder's parameter `uint32` so the bad case is unrepresentable
// rather than checked. `oidCompare` is deliberately untouched: with the decoder
// bounded it only ever sees 0..4294967295 and its signed comparison is correct
// as written. These cells assert the bound at the entry point AND the
// downstream properties it buys, so a fix that repaired only a symptom would
// fail one of them.

// The two vectors the issue executed, restated as inputs that must ERROR.
//
// Both decoded WITHOUT error at master, which is what makes the corruption
// silent: the first returned a plausible-looking component
// (-9223372036854775807) and the second re-encoded to `2b ff`, malformed BER
// the agent's OWN decoder rejects.
//
// RED at master: berDecodeOID returns (value, nil) for both.
func TestOverlongOIDSubIdentifierIsAnError9133(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		why  string
	}{
		{
			name: "ten-continuation-octets-70-bits",
			data: []byte{
				0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xfd, 0x59,
				0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
			},
			why: "at master this returned [1 3 6 1 4 1 32473 -9223372036854775807] " +
				"with no error, and re-encoding it produced the DIFFERENT, " +
				"well-formed OID .32473.1",
		},
		{
			name: "nine-0xff-octets",
			data: []byte{0x2b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
			why: "at master this returned [1 3 -1]; berEncodeSubID(-1) then emitted " +
				"0xff, a lone continuation octet with no terminator",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := berDecodeOID(tc.data)
			if err == nil {
				t.Fatalf("berDecodeOID = %v, nil; want an error. %s", got, tc.why)
			}
			if got != nil {
				t.Errorf("berDecodeOID returned %v alongside its error; a rejected "+
					"OID must not also hand the caller a value", got)
			}
		})
	}
}

// The bound is RFC 2578's, not an arbitrary one: 4294967295 is LEGAL and must
// still decode, 4294967296 must not.
//
// The pair is the point. A cell that only asserted the rejection would pass for
// a fix that rejected the whole legal range too, which would break every real
// manager that uses a large table index.
func TestOIDSubIdentifierBoundIsExactlyRFC2578_9133(t *testing.T) {
	// 4294967295 = 0x8f 0xff 0xff 0xff 0x7f in base-128.
	maxWire := []byte{0x2b, 0x8f, 0xff, 0xff, 0xff, 0x7f}
	got, err := berDecodeOID(maxWire)
	if err != nil {
		t.Fatalf("berDecodeOID(4294967295) = %v; the RFC 2578 MAXIMUM must decode", err)
	}
	want := []int{1, 3, math.MaxUint32}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("berDecodeOID = %v, want %v", got, want)
	}

	// 4294967296 = 0x90 0x80 0x80 0x80 0x00, one past the range.
	overWire := []byte{0x2b, 0x90, 0x80, 0x80, 0x80, 0x00}
	if got, err := berDecodeOID(overWire); err == nil {
		t.Fatalf("berDecodeOID(4294967296) = %v, nil; one past the RFC 2578 "+
			"maximum must be rejected", got)
	}
}

// THE INVARIANT THE DEFECT BROKE, stated directly: the agent must be able to
// parse everything it emits.
//
// `echoVarbinds` puts the REQUEST OIDs into the response, so any OID the
// decoder admits is an OID the encoder will emit. Round-tripping the full legal
// range through both halves is what binds the two together — a fix to only one
// side would leave this red.
func TestEverythingTheDecoderAdmitsReEncodesAndParses9133(t *testing.T) {
	corpus := [][]int{
		{1, 3, 6, 1, 2, 1, 1, 1, 0},
		{1, 3, 6, 1, 4, 1, 32473, 1},
		{1, 3, 0},
		{1, 3, 0x7f},
		{1, 3, 0x80},
		{1, 3, 0x3fff},
		{1, 3, 0x4000},
		{1, 3, 1 << 21},
		{1, 3, (1 << 28) - 1},
		{1, 3, 1 << 28},
		{1, 3, math.MaxUint32 - 1},
		{1, 3, math.MaxUint32},
		{1, 3, 6, 1, 4, 1, 32473, math.MaxUint32, 0, math.MaxUint32},
	}
	for _, oid := range corpus {
		enc := berEncodeOID(oid)
		if enc == nil {
			t.Errorf("berEncodeOID(%v) = nil; every component is inside RFC 2578's range", oid)
			continue
		}
		if n := len(enc); n > 0 && enc[n-1]&0x80 != 0 {
			t.Errorf("berEncodeOID(%v) = % x; the LAST octet has its continuation "+
				"bit set, which is the malformed shape #9133 is about", oid, enc)
		}
		back, err := berDecodeOID(enc)
		if err != nil {
			t.Errorf("berDecodeOID(berEncodeOID(%v)) = %v; the agent must be able "+
				"to parse what it emits", oid, err)
			continue
		}
		if !oidsEqual(back, oid) {
			t.Errorf("round trip of %v gave %v", oid, back)
		}
	}
}

// The encoder's guard, and the specific malformed output it replaces.
//
// With the decoder bounded this cannot fire on a wire-sourced OID — it is
// defence in depth against an internal bug. It is asserted anyway because the
// alternative was SILENT: the old `val < 0x80` fast path was true for every
// negative value and returned `byte(val)`, so -1 became 0xff and nothing
// downstream could tell that apart from a real encoding.
func TestEncoderRefusesAnOutOfRangeComponent9133(t *testing.T) {
	for _, oid := range [][]int{
		{1, 3, -1},
		{1, 3, 6, 1, -12345},
		{1, 3, math.MaxUint32 + 1},
		{1, 3, 6, 1, math.MaxUint32 + 1, 2},
	} {
		enc := berEncodeOID(oid)
		if enc != nil {
			t.Errorf("berEncodeOID(%v) = % x, want nil: a component outside RFC "+
				"2578's 0..4294967295 is not encodable", oid, enc)
		}
	}
	// The exact master output this replaces, named so a regression is
	// recognisable rather than merely "not nil".
	if enc := berEncodeOID([]int{1, 3, -1}); bytes.Equal(enc, []byte{0x2b, 0xff}) {
		t.Errorf("berEncodeOID([1 3 -1]) = 2b ff — a lone continuation octet with " +
			"no terminator, which the agent's own decoder rejects")
	}
}

// OVER-REACH GUARD. The first two arcs are folded into ONE octet by X.690
// §8.19.4 and are deliberately NOT bounded by this change.
//
// berDecodeOID reconstructs them as data[0]/40 and data[0]%40, so a first octet
// above 0x77 yields a first arc above 2 — technically invalid ASN.1 that
// nonetheless round-trips byte-for-byte. Rejecting it would replace a faithful
// echo of the client's own OID with an empty one, which is worse for the client
// and is not what #9133 is about.
//
// GREEN at master. It constrains what the fix must NOT do.
func TestTheFoldedFirstArcsAreLeftAlone9133(t *testing.T) {
	for _, first := range []byte{0x00, 0x2b, 0x77, 0x78, 0xfe, 0xff} {
		oid, err := berDecodeOID([]byte{first, 0x01})
		if err != nil {
			t.Fatalf("berDecodeOID([% x]) = %v; the folded first octet must still decode",
				[]byte{first, 0x01}, err)
		}
		enc := berEncodeOID(oid)
		if enc == nil {
			t.Fatalf("berEncodeOID(%v) = nil; a decoded OID must remain encodable, "+
				"or the echo path answers with an empty OID", oid)
		}
		if !bytes.Equal(enc, []byte{first, 0x01}) {
			t.Fatalf("round trip of first octet 0x%02x gave % x, want % x",
				first, enc, []byte{first, 0x01})
		}
	}
}

// The ORDERING half of the finding, bound where it is now decidable.
//
// The inversion was `oidCompare` comparing a NEGATIVE component with a signed
// `<`. A negative component can no longer arrive from the wire, so the property
// worth asserting is the one that replaces it: over the whole legal range,
// larger sorts later — including across the 2^31 boundary, which is where a
// 32-bit `int` would have wrapped.
//
// GREEN at master for the positive values (that is the point — the fix is at
// the decoder), and it is what makes `oidCompare`'s "no change needed" claim
// falsifiable rather than asserted.
func TestOIDOrderingHoldsOverTheWholeLegalRange9133(t *testing.T) {
	ordered := [][]int{
		{1, 3, 6, 1, 0},
		{1, 3, 6, 1, 1},
		{1, 3, 6, 1, 0x7f},
		{1, 3, 6, 1, 0x80},
		{1, 3, 6, 1, math.MaxInt32 - 1},
		{1, 3, 6, 1, math.MaxInt32},
		{1, 3, 6, 1, math.MaxInt32 + 1},
		{1, 3, 6, 1, math.MaxUint32 - 1},
		{1, 3, 6, 1, math.MaxUint32},
	}
	for i := 0; i+1 < len(ordered); i++ {
		if got := oidCompare(ordered[i], ordered[i+1]); got != -1 {
			t.Errorf("oidCompare(%v, %v) = %d, want -1", ordered[i], ordered[i+1], got)
		}
		if got := oidCompare(ordered[i+1], ordered[i]); got != 1 {
			t.Errorf("oidCompare(%v, %v) = %d, want 1", ordered[i+1], ordered[i], got)
		}
	}
	// And every one of them must be REACHABLE through the wire codec, so this
	// is a statement about values the agent can actually hold.
	for _, oid := range ordered {
		back, err := berDecodeOID(berEncodeOID(oid))
		if err != nil || !oidsEqual(back, oid) {
			t.Errorf("%v does not survive the codec (got %v, err %v); the ordering "+
				"claim above would then be about values the agent cannot hold",
				oid, back, err)
		}
	}
}

// --- END TO END: the WIRING, through the agent's own packet entry point. ---

// buildRawOIDv1Get builds a v1 GET whose single varbind carries the given RAW
// OID value bytes. It cannot go through buildV1Request, which encodes from
// []int and so can never produce the crafted encoding this cell is about.
func buildRawOIDv1Get9133(community string, requestID int, rawOID []byte) []byte {
	oidBytes := berEncodeTLV(tagObjectIdentifier, rawOID)
	valBytes := berEncodeTLV(tagNull, nil)
	vbList := berEncodeTLV(tagSequence, append(oidBytes, valBytes...))
	vbListEnc := berEncodeTLV(tagSequence, vbList)

	pduBody := berEncodeIntegerTLV(requestID)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbListEnc...)
	pdu := berEncodeTLV(pduGetRequest, pduBody)

	msg := berEncodeIntegerTLV(snmpVersion1)
	msg = append(msg, berEncodeTLV(tagOctetString, []byte(community))...)
	msg = append(msg, pdu...)
	return berEncodeTLV(tagSequence, msg)
}

func agent9133(t *testing.T) *Agent {
	t.Helper()
	a := NewAgent(&config.SNMPConfig{
		Description: "xpf 9133 test",
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(func() []IfData {
		return []IfData{{IfIndex: 1, IfDescr: "ge-0-0-0", IfType: 6, AdminStatus: 1, OperStatus: 1}}
	})
	return a
}

// A crafted GET must not make the agent emit a reply it cannot itself parse.
//
// This is the wiring cell: it goes through handlePacket -> decodePDUFields ->
// berDecodeOID, so deleting the bound from the decoder reds it even though the
// unit cells above call berDecodeOID directly.
//
// The assertion is deliberately NOT "the response is nil". Dropping a malformed
// PDU is what the agent does with every other decode failure, but a fix that
// answered with a well-formed error response would also be acceptable — so the
// cell asserts the PROPERTY (whatever comes back, the agent's own decoder
// parses it) and reports which of the two happened.
//
// RED at master: the response contains the varbind OID TLV `06 02 2b ff`, whose
// dangling continuation octet berDecodeOID rejects.
func TestACraftedOIDNeverProducesAnUnparseableReply9133(t *testing.T) {
	crafted := [][]byte{
		{0x2b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		{
			0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xfd, 0x59,
			0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
		},
	}
	// Positive control at the SAME entry point: a well-formed request must get
	// a well-formed answer, so "no response" below cannot be read as the agent
	// being broken for an unrelated reason.
	a := agent9133(t)
	ok := a.handlePacket(buildV1Request(pduGetRequest, "public", 1, [][]int{oidSysDescr}))
	if ok == nil {
		t.Fatal("positive control: a well-formed v1 GET of sysDescr got no response, " +
			"so a nil answer to the crafted request below would prove nothing")
	}

	for _, rawOID := range crafted {
		resp := a.handlePacket(buildRawOIDv1Get9133("public", 2, rawOID))
		if resp == nil {
			// The malformed PDU was rejected at decode — the expected outcome.
			continue
		}
		t.Logf("crafted OID % x produced a response; checking it is parseable", rawOID)
		// Whatever came back, the agent's own decoder must accept it.
		decodeV1Response(t, resp)
	}
}

// PINS A PRE-EXISTING BEHAVIOUR THIS FIX NEWLY EXERCISES, and says so.
//
// `decodePDUFields` SKIPS (`continue`) a varbind whose OID fails to decode
// rather than failing the PDU, so a two-varbind GET with one undecodable OID
// gets a noError response carrying ONE varbind — an RFC 1157 §4.1.2 arity
// violation (the response's variable-bindings must name the same variables the
// request did).
//
// It is NOT introduced by #9133 and it is NOT a #9133 regression: the skip is
// already reachable at master through the same function's OTHER error, which
// the vector `06 02 2b 80` (a dangling continuation octet with nothing after
// it) triggers there and here alike — that vector is in this cell precisely so
// the "pre-existing" claim is measured rather than argued. What #9133 changes
// is that an OVERFLOWING sub-identifier now takes this path too, instead of
// being echoed back as malformed BER.
//
// Pinned rather than fixed because the remedy is a decision about every
// malformed-varbind class in that loop (bad tag, bad length, short body all
// `continue` the same way), not about OID bounds, and making one of the five
// behave differently would be the worse outcome. Tracked as #9333.
func TestAnUndecodableVarbindIsSkippedNotRejected9133(t *testing.T) {
	a := agent9133(t)

	build := func(rawOID []byte) []byte {
		good := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oidSysDescr))
		goodVB := berEncodeTLV(tagSequence, append(good, berEncodeTLV(tagNull, nil)...))
		bad := berEncodeTLV(tagObjectIdentifier, rawOID)
		badVB := berEncodeTLV(tagSequence, append(bad, berEncodeTLV(tagNull, nil)...))
		vbList := berEncodeTLV(tagSequence, append(append([]byte{}, goodVB...), badVB...))
		pduBody := berEncodeIntegerTLV(7)
		pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
		pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
		pduBody = append(pduBody, vbList...)
		msg := berEncodeIntegerTLV(snmpVersion1)
		msg = append(msg, berEncodeTLV(tagOctetString, []byte("public"))...)
		msg = append(msg, berEncodeTLV(pduGetRequest, pduBody)...)
		return berEncodeTLV(tagSequence, msg)
	}

	for _, tc := range []struct {
		name   string
		rawOID []byte
	}{
		// Reachable at master AND here: the pre-existing path.
		{"truncated-continuation", []byte{0x2b, 0x80}},
		// New to this path as of #9133; echoed as malformed BER at master.
		{"overflowing-subidentifier", []byte{0x2b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := berDecodeOID(tc.rawOID); err == nil {
				t.Fatalf("fixture: berDecodeOID(% x) must fail for this cell to be "+
					"about the skip path at all", tc.rawOID)
			}
			resp := a.handlePacket(build(tc.rawOID))
			if resp == nil {
				t.Fatalf("the PDU was dropped; if that is now the behaviour, this " +
					"pin is stale and the arity concern is resolved — update it " +
					"deliberately rather than deleting it")
			}
			errStatus, _, vbs := decodeV1Response(t, resp)
			if errStatus != errNoError {
				t.Fatalf("error-status = %d; the pinned behaviour is a noError "+
					"response, not an error one", errStatus)
			}
			if len(vbs) != 1 {
				t.Fatalf("response carried %d varbinds; the pinned behaviour is 1 "+
					"(the request had 2 and the undecodable one is skipped)", len(vbs))
			}
			if !oidsEqual(vbs[0].oid, oidSysDescr) {
				t.Fatalf("surviving varbind is %v, want sysDescr %v", vbs[0].oid, oidSysDescr)
			}
		})
	}
}
