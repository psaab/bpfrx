package logging

import "testing"

// TestEventSeverityScreenAlarmIsNotice is the #2298 regression on the syslog
// severity classifier. The #2234 scan-table-pressure saturation alarm is a
// screen event with action=PERMIT — the packet forwards, so it is an
// informational alarm, not a drop. Logging it at SyslogError is contradictory
// and would page drop-severity alerts. It must map to SyslogNotice; only a
// real screen drop (action=DENY/REJECT) stays at SyslogError.
//
// Fail-on-revert: if eventSeverity reverts to classifying screen events by
// type alone (always SyslogError), the permit-alarm case below fails.
func TestEventSeverityScreenAlarmIsNotice(t *testing.T) {
	cases := []struct {
		name      string
		eventType uint8
		action    uint8
		want      int
	}{
		{"screen_alarm_permit", eventTypeScreenDrop, actionPermit, SyslogNotice},
		{"screen_drop_deny", eventTypeScreenDrop, actionDeny, SyslogError},
		{"screen_drop_reject", eventTypeScreenDrop, actionReject, SyslogError},
		{"policy_deny", eventTypePolicyDeny, actionDeny, SyslogWarning},
		{"filter_log", eventTypeFilterLog, actionPermit, SyslogInfo},
		{"session_open_default", eventTypeSessionOpen, actionPermit, SyslogInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := eventSeverity(tc.eventType, tc.action); got != tc.want {
				t.Fatalf("eventSeverity(type=%d, action=%d) = %d, want %d",
					tc.eventType, tc.action, got, tc.want)
			}
		})
	}
	// A permit screen alarm and a deny screen drop must NOT share severity.
	if eventSeverity(eventTypeScreenDrop, actionPermit) ==
		eventSeverity(eventTypeScreenDrop, actionDeny) {
		t.Fatal("screen alarm (permit) and screen drop (deny) must not share severity")
	}
}
