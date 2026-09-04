package logging

import (
	"strings"
	"testing"
	"time"
)

// #7531: an intentionally meaningless wire action byte was rendered as `deny`.
//
// The Rust producer writes 0 for BOTH lifecycle events and says so at each
// write site, in as many words — "this byte is intentionally 0 … Do NOT rely
// on the 0 rendering as a value". The Go side then taught the exception to the
// formatters one at a time: #2513 for the close text lines, #2593 for the open
// text lines, #4914 for the binary close record. Every surface that came later
// inherited the raw `actionName(0)` == "deny" until someone noticed it too, and
// the ones that never got their own issue were EventRecord.Action itself (which
// trace, REST and SSE all read) and the binary SESSION_OPEN record.
//
// So the fix is one predicate — eventCarriesForwardingAction — read by the
// surfaces, rather than a fourth surface-specific exception.
//
// WHY EMPTY AND NOT A PLACEHOLDER. EventRecord.Action feeds the event-buffer
// FILTER (eventbuf.go: `f.Action != "" && !strings.EqualFold(rec.Action, ...)`).
// Before this, an operator filtering `action deny` matched EVERY normal session
// open and close — the most concrete harm, because it makes a deny filter
// useless on a busy box. A placeholder string would just be a new value to
// match by accident.

func lifecycleEvent7531(t *testing.T, eventType uint8, action uint8) EventRecord {
	t.Helper()
	evt := &rawEvent{
		EventType:  eventType,
		Protocol:   6,
		Action:     action,
		AddrFamily: addrFamilyInet,
	}
	return EventRecord{
		Time:     time.Unix(1700000000, 0),
		Type:     eventTypeName(evt.EventType),
		Protocol: protoName(evt.Protocol),
		Action:   recordActionName(evt.EventType, evt.Action),
	}
}

func TestLifecycleEventsCarryNoAction7531(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  uint8
	}{
		{"SESSION_OPEN", eventTypeSessionOpen},
		{"SESSION_CLOSE", eventTypeSessionClose},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The producer writes 0; that is the case that occurs.
			if got := recordActionName(tc.typ, 0); got != "" {
				t.Errorf("recordActionName(%s, 0) = %q, want \"\". The producer writes "+
					"this byte as 0 deliberately, so rendering it attributes a "+
					"forwarding decision nobody made — and 0 renders as %q (#7531)",
					tc.name, got, "deny")
			}
			// And it must not depend on the byte's value: a lifecycle event has
			// no action WHATEVER the byte says, so a future producer writing a
			// stray non-zero cannot resurrect the claim.
			if got := recordActionName(tc.typ, actionPermit); got != "" {
				t.Errorf("recordActionName(%s, actionPermit) = %q, want \"\" — "+
					"applicability is a property of the EVENT TYPE, not of the byte",
					tc.name, got)
			}
		})
	}
}

// THE CONTROL, and it is what stops the fix from being "never render an
// action". A real forwarding event must keep its decision — blanking those
// would destroy the field's only real use.
func TestNonLifecycleEventsKeepTheirAction7531(t *testing.T) {
	for _, tc := range []struct {
		typ  uint8
		act  uint8
		want string
	}{
		{eventTypePolicyDeny, actionDeny, "deny"},
		{eventTypePolicyDeny, actionReject, "reject"},
		{eventTypeScreenDrop, actionPermit, "permit"},
	} {
		if got := recordActionName(tc.typ, tc.act); got != tc.want {
			t.Errorf("recordActionName(type=%d, action=%d) = %q, want %q — a real "+
				"forwarding event must keep its decision", tc.typ, tc.act, got, tc.want)
		}
	}
}

// THE BINARY RECORD. #4914 gave SESSION_CLOSE the not-applicable sentinel and
// left SESSION_OPEN stamping a raw 0 — which a binary forensic consumer reads
// as `deny`, i.e. as a BLOCKED connection attempt rather than an established
// one. That is the more misleading of the two.
func TestBinaryLifecycleRecordsUseTheSentinel7531(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  uint8
		want uint8
	}{
		{"SESSION_OPEN", eventTypeSessionOpen, actionNotApplicable},
		{"SESSION_CLOSE", eventTypeSessionClose, actionNotApplicable},
		// The control: a policy deny keeps its real byte.
		{"POLICY_DENY", eventTypePolicyDeny, actionDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evt := &rawEvent{EventType: tc.typ, Protocol: 6, Action: actionDeny,
				AddrFamily: addrFamilyInet}
			rec := &EventRecord{Time: time.Unix(1700000000, 0)}
			buf := formatBinaryRecord(evt, rec, SyslogInfo, 0)
			if buf[7] != tc.want {
				t.Errorf("binary action byte = %d, want %d (#7531)", buf[7], tc.want)
			}
		})
	}
}

// THE TRACE SURFACE omits `action=` rather than printing an empty one. An empty
// field reads as a producer that failed to populate it — a different and more
// alarming claim than "this event type has no action".
func TestTraceOmitsActionForLifecycleEvents7531(t *testing.T) {
	tw := &TraceWriter{}
	for _, typ := range []uint8{eventTypeSessionOpen, eventTypeSessionClose} {
		rec := lifecycleEvent7531(t, typ, 0)
		out := tw.formatTrace(rec)
		if strings.Contains(out, "action=deny") {
			t.Errorf("the trace rendered a lifecycle event as a DENY (#7531):\n%s", out)
		}
		if strings.Contains(out, "action=") {
			t.Errorf("the trace printed an empty `action=` field. Omit it, as the "+
				"standard and structured syslog lines already do (#2513/#2593):\n%s", out)
		}
		// Non-vacuity: the line must still be a real trace line, or the two
		// assertions above are satisfied by an empty string.
		if !strings.Contains(out, rec.Type) {
			t.Errorf("the trace line does not name the event type at all:\n%s", out)
		}
	}
	// Control: a forwarding event still shows its action, so the omission is
	// scoped to lifecycle events rather than applied to everything.
	pd := EventRecord{Time: time.Unix(1700000000, 0), Type: "POLICY_DENY",
		Protocol: "tcp", Action: "deny"}
	if out := tw.formatTrace(pd); !strings.Contains(out, "action=deny") {
		t.Errorf("a POLICY_DENY lost its action on the trace:\n%s", out)
	}
}

// THE FILTER, which is the operator-visible harm. Filtering `action deny` used
// to match every normal session open and close.
func TestDenyFilterNoLongerMatchesLifecycleEvents7531(t *testing.T) {
	f := EventFilter{Action: "deny"}
	open := lifecycleEvent7531(t, eventTypeSessionOpen, 0)
	if f.matches(&open) {
		t.Error("an `action deny` filter matched a SESSION_OPEN. Every normal " +
			"session start passes a deny filter, which makes the filter useless on " +
			"a busy box (#7531)")
	}
	deny := EventRecord{Type: "POLICY_DENY", Action: "deny"}
	if !f.matches(&deny) {
		t.Error("the `action deny` filter stopped matching an actual deny; the fix " +
			"must narrow the filter, not break it")
	}
}
