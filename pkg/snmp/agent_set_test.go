package snmp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// buildV2cSetRequest constructs a minimal SNMP v2c SET request packet for a
// single OID with a null value. It mirrors buildResponse but emits a
// pduSetRequest PDU so the agent's SET path can be exercised end to end.
func buildV2cSetRequest(community string, requestID int, oid []int) []byte {
	// Single varbind: SEQUENCE { OID, NULL }.
	oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
	valBytes := berEncodeTLV(tagNull, nil)
	vb := berEncodeTLV(tagSequence, append(oidBytes, valBytes...))
	vbList := berEncodeTLV(tagSequence, vb)

	// PDU body: request-id, error-status(0), error-index(0), varbind-list.
	pduBody := berEncodeIntegerTLV(requestID)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbList...)
	pdu := berEncodeTLV(pduSetRequest, pduBody)

	// Message: version(v2c), community, PDU.
	msg := berEncodeIntegerTLV(snmpVersion2c)
	msg = append(msg, berEncodeTLV(tagOctetString, []byte(community))...)
	msg = append(msg, pdu...)
	return berEncodeTLV(tagSequence, msg)
}

// decodeResponseErrorStatus parses a SNMP v2c GetResponse packet and returns
// its error-status field. It walks SEQUENCE -> version -> community -> PDU ->
// request-id -> error-status.
func decodeResponseErrorStatus(t *testing.T, resp []byte) int {
	t.Helper()
	tag, body, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Fatalf("response: not a SEQUENCE (tag=0x%02x err=%v)", tag, err)
	}
	// version
	_, rest, err := berDecodeInteger(body)
	if err != nil {
		t.Fatalf("response: decode version: %v", err)
	}
	// community
	_, rest, err = berDecodeOctetString(rest)
	if err != nil {
		t.Fatalf("response: decode community: %v", err)
	}
	// PDU
	pduTag, pduBody, err := berDecodeHeader(rest)
	if err != nil {
		t.Fatalf("response: decode PDU header: %v", err)
	}
	if pduTag != pduGetResponse {
		t.Fatalf("response: PDU tag = 0x%02x, want GetResponse (0x%02x)", pduTag, pduGetResponse)
	}
	// request-id
	_, pduRest, err := berDecodeInteger(pduBody)
	if err != nil {
		t.Fatalf("response: decode request-id: %v", err)
	}
	// error-status
	errStatus, _, err := berDecodeInteger(pduRest)
	if err != nil {
		t.Fatalf("response: decode error-status: %v", err)
	}
	return errStatus
}

// TestSetRequest_ReadOnlyCommunityDenied verifies that a SET request from a
// read-only community is rejected with noAccess. This is the authorization
// gate added for issue #2008 H17: prior to the fix the agent had no SET
// handler at all (the default case dropped the PDU and returned nil), so a
// read-only community's configured authorization was never enforced.
//
// Mutation check: if communityCanWrite always returned true (gate removed),
// a read-only SET would be answered with notWritable like a read-write SET,
// and this test would fail on the errNoAccess assertion.
func TestSetRequest_ReadOnlyCommunityDenied(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})

	pkt := buildV2cSetRequest("public", 7, oidSysContact)
	resp := a.handlePacket(pkt)
	if resp == nil {
		t.Fatal("SET from read-only community produced no response (PDU was dropped)")
	}
	if got := decodeResponseErrorStatus(t, resp); got != errNoAccess {
		t.Errorf("read-only SET error-status = %d, want noAccess (%d)", got, errNoAccess)
	}
}

// TestSetRequest_ReadWriteCommunityPassesGate verifies that a read-write
// community is NOT denied at the authorization gate. The agent exposes no
// writable objects, so the write itself is refused with notWritable rather
// than noAccess. The distinction (notWritable != noAccess) is exactly what
// the authorization gate produces; removing the gate would yield noAccess for
// both communities (failing the read-only test) or notWritable for both
// (failing nothing here but failing the read-only test's noAccess assertion).
func TestSetRequest_ReadWriteCommunityPassesGate(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"private": {Name: "private", Authorization: "read-write"},
		},
	})

	pkt := buildV2cSetRequest("private", 9, oidSysContact)
	resp := a.handlePacket(pkt)
	if resp == nil {
		t.Fatal("SET from read-write community produced no response")
	}
	got := decodeResponseErrorStatus(t, resp)
	if got == errNoAccess {
		t.Errorf("read-write SET was denied at authorization gate (noAccess); "+
			"authorization read-write must pass the gate, got error-status %d", got)
	}
	if got != errNotWritable {
		t.Errorf("read-write SET error-status = %d, want notWritable (%d)", got, errNotWritable)
	}
}

// TestSetRequest_UnknownCommunityDropped verifies that a SET from an
// unconfigured community is dropped (no response), matching the read path's
// silent-drop behavior for invalid communities.
func TestSetRequest_UnknownCommunityDropped(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-write"},
		},
	})

	pkt := buildV2cSetRequest("nope", 3, oidSysContact)
	if resp := a.handlePacket(pkt); resp != nil {
		t.Errorf("SET from unknown community should be dropped, got %d-byte response", len(resp))
	}
}

// TestGetCommunity_Authorization verifies getCommunity returns the community
// struct with its authorization level intact, the lookup that backs the SET
// access-control gate.
func TestGetCommunity_Authorization(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"ro": {Name: "ro", Authorization: "read-only"},
			"rw": {Name: "rw", Authorization: "read-write"},
		},
	})

	if c := a.getCommunity("ro"); c == nil || communityCanWrite(c) {
		t.Errorf("getCommunity(ro): want non-nil read-only, communityCanWrite=%v", communityCanWrite(c))
	}
	if c := a.getCommunity("rw"); c == nil || !communityCanWrite(c) {
		t.Errorf("getCommunity(rw): want non-nil read-write, communityCanWrite=%v", communityCanWrite(c))
	}
	if c := a.getCommunity("missing"); c != nil {
		t.Errorf("getCommunity(missing) = %v, want nil", c)
	}
}
