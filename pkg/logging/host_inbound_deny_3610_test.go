package logging

import (
	"net"
	"strings"
	"testing"
)

// rawHostInboundDenyFrame builds a POLICY_DENY raw event frame (eventType 3)
// carrying the #3610 host-inbound reason byte at [134]. This mirrors what the
// userspace-dp emit_host_inbound_deny_event produces: the policy-deny wire kind
// (so it reuses the #3615 event machinery) with the distinct
// closeReasonHostInbound reason, action DENY, and no admitting policy id.
func rawHostInboundDenyFrame(reason byte) []byte {
	data := make([]byte, rawEventWireSize)
	data[40] = 0x30 // src port 12345
	data[41] = 0x39
	data[42] = 0x00 // dst port 179 (BGP — a control-plane service)
	data[43] = 0xb3
	data[52] = eventTypePolicyDeny
	data[53] = 6 // TCP
	data[54] = actionDeny
	data[55] = addrFamilyInet
	copy(data[8:12], net.ParseIP("10.0.61.102").To4())
	copy(data[24:28], net.ParseIP("10.255.0.1").To4())
	data[134] = reason
	return data
}

// TestHostInboundDenyReasonRendersDistinctly is the #3610 fail-on-revert: a
// POLICY_DENY event whose reason byte is closeReasonHostInbound (6) must decode
// to the distinct "Denied by host-inbound-traffic" reason and render it on the
// structured RT_FLOW_SESSION_DENY record, so incident response can tell a
// control-plane host-inbound drop apart from a transit security-policy deny.
// The full 5-tuple must be present so the operator sees WHICH flow was dropped.
//
// Reverting closeReasonName (dropping the closeReasonHostInbound case) or the
// formatStructuredMsg POLICY_DENY change (hardcoding "Rejected by policy") turns
// this RED.
func TestHostInboundDenyReasonRendersDistinctly(t *testing.T) {
	rec, ok := DecodeRawEventRecord(rawHostInboundDenyFrame(closeReasonHostInbound))
	if !ok {
		t.Fatalf("DecodeRawEventRecord returned ok=false")
	}
	if rec.Type != "POLICY_DENY" {
		t.Fatalf("record type = %q, want POLICY_DENY", rec.Type)
	}
	if rec.Reason != "Denied by host-inbound-traffic" {
		t.Fatalf("host-inbound deny Reason = %q, want %q", rec.Reason, "Denied by host-inbound-traffic")
	}

	structured := formatStructuredMsg(rec, 6)
	if !strings.Contains(structured, "RT_FLOW_SESSION_DENY") {
		t.Fatalf("structured record is not an RT_FLOW_SESSION_DENY:\n%s", structured)
	}
	if !strings.Contains(structured, `reason="Denied by host-inbound-traffic"`) {
		t.Fatalf("structured host-inbound deny missing the distinct reason:\n%s", structured)
	}
	// The tuple must be present so the operator can see WHICH flow was denied.
	if !strings.Contains(structured, `source-address="10.0.61.102"`) ||
		!strings.Contains(structured, `destination-address="10.255.0.1"`) ||
		!strings.Contains(structured, `destination-port="179"`) {
		t.Fatalf("structured host-inbound deny missing the denied 5-tuple:\n%s", structured)
	}
}

// TestPolicyDenyReasonUnchanged is the byte-identical guard: a transit
// security-policy deny (reason byte closeReasonPolicy = 5) must STILL render
// reason="Rejected by policy" after #3610 generalized the formatter to read the
// on-wire reason. If the formatter regressed to a wrong default or read the
// wrong byte, this catches it.
func TestPolicyDenyReasonUnchanged(t *testing.T) {
	rec, ok := DecodeRawEventRecord(rawHostInboundDenyFrame(closeReasonPolicy))
	if !ok {
		t.Fatalf("DecodeRawEventRecord returned ok=false")
	}
	if rec.Reason != "Rejected by policy" {
		t.Fatalf("policy deny Reason = %q, want %q", rec.Reason, "Rejected by policy")
	}
	structured := formatStructuredMsg(rec, 6)
	if !strings.Contains(structured, `reason="Rejected by policy"`) {
		t.Fatalf("transit policy deny reason regressed:\n%s", structured)
	}
}
