package logging

import (
	"strings"
	"testing"
)

// sessionOpenRecord builds an EventRecord that mirrors what decodeUserspaceEvent
// produces for a SESSION_OPEN frame: the wire action byte is 0 (a session open
// is a permit-and-create event and carries no permit/deny/reject decision),
// which actionName maps to "deny". eventTypeName(eventTypeSessionOpen) returns
// "SESSION_OPEN", so that is the Type string that reaches formatSyslogMsg.
func sessionOpenRecord() EventRecord {
	return EventRecord{
		Type:         "SESSION_OPEN",
		SrcAddr:      "10.0.1.5:51000",
		DstAddr:      "10.0.2.7:443",
		Protocol:     "TCP",
		Action:       actionName(0), // wire action 0 -> "deny" before #2593
		PolicyID:     7,
		InZone:       1,
		OutZone:      2,
		InZoneName:   "trust",
		OutZoneName:  "untrust",
		SessionID:    99,
		PolicyName:   "allow-web",
		AppName:      "junos-https",
		IngressIface: "ge-0-0-0",
	}
}

// TestStandardSessionOpenOmitsAction is the #2593 golden test for the plain
// RT_FLOW SESSION_OPEN line. A session open is a permit-and-create event, not a
// forwarding decision, so the standard formatter must NOT render the wire action
// byte (which is 0 and decodes to "deny"). Reverting the formatter change
// reintroduces "action=deny" here and turns this test red (fail-on-revert).
func TestStandardSessionOpenOmitsAction(t *testing.T) {
	rec := sessionOpenRecord()

	// Guard: confirm the input record really does carry the misleading value,
	// so this test would actually catch a regression in the formatter.
	if rec.Action != "deny" {
		t.Fatalf("precondition: wire action 0 should map to %q, got %q",
			"deny", rec.Action)
	}

	got := formatSyslogMsg(rec)

	const want = "RT_FLOW SESSION_OPEN src=10.0.1.5:51000 dst=10.0.2.7:443 " +
		"proto=TCP policy=7 zone=trust->untrust"
	if got != want {
		t.Errorf("standard SESSION_OPEN line mismatch:\n got: %s\nwant: %s", got, want)
	}

	if strings.Contains(got, "action=") {
		t.Errorf("standard SESSION_OPEN line must omit action= (a session open "+
			"is a permit-and-create, not a deny decision, #2593); got: %s", got)
	}
	if strings.Contains(got, "deny") {
		t.Errorf("standard SESSION_OPEN line must not contain \"deny\" (#2593); got: %s", got)
	}
}

// TestStructuredSessionOpenUnchanged pins the structured RT_FLOW_SESSION_CREATE
// line: it already omits action. This guards against the #2593 fix accidentally
// altering the structured output.
func TestStructuredSessionOpenUnchanged(t *testing.T) {
	rec := sessionOpenRecord()

	got := formatStructuredMsg(rec, 6) // protocol-id 6 = TCP

	if strings.Contains(got, "action=") {
		t.Errorf("structured SESSION_OPEN line must not contain action=; got: %s", got)
	}
	if !strings.Contains(got, "RT_FLOW_SESSION_CREATE") {
		t.Errorf("structured line missing RT_FLOW_SESSION_CREATE tag; got: %s", got)
	}
	// Spot-check the contract is intact (tuple, zones, policy, app, iface).
	for _, want := range []string{
		`source-address="10.0.1.5" source-port="51000"`,
		`destination-address="10.0.2.7" destination-port="443"`,
		`protocol-id="6"`,
		`policy-name="allow-web"`,
		`source-zone-name="trust" destination-zone-name="untrust"`,
		`session-id="99"`,
		`packet-incoming-interface="ge-0-0-0" application="junos-https"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("structured SESSION_OPEN line missing %q; got: %s", want, got)
		}
	}
}

// TestStandardSessionOpenNonDenyKeyedOnType confirms the #2593 change is keyed
// on event type == SESSION_OPEN, not on action == 0 globally: a POLICY_DENY (the
// genuine deny path) still renders action=deny in the standard formatter. This
// pairs with TestStandardNonCloseStillRendersAction (#2513) — both deny paths
// must keep action even though the create/close paths drop it.
func TestStandardSessionOpenNonDenyKeyedOnType(t *testing.T) {
	rec := EventRecord{
		Type:        "POLICY_DENY",
		SrcAddr:     "10.0.1.5:51000",
		DstAddr:     "10.0.2.7:443",
		Protocol:    "TCP",
		Action:      actionName(actionDeny),
		PolicyID:    7,
		InZoneName:  "trust",
		OutZoneName: "untrust",
	}
	got := formatSyslogMsg(rec)
	if !strings.Contains(got, "action=deny") {
		t.Errorf("POLICY_DENY standard line must still render action=deny (the "+
			"#2593 omission is SESSION_OPEN-type-scoped, not action==0 global); got: %s", got)
	}
}
