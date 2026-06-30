package main

import "testing"

// #3547: the remote `cli` `show security log [<count>] [zone <name>]
// [protocol <proto>] [action <action>]` must forward the FULL argument
// string to the daemon's ShowText security-log topic, not just a bare
// numeric count. Before #3547 showEvents picked out the first numeric token
// and dropped everything else, so `show security log zone <name>` (including
// the unknown/none/0 zone-0 selector #3338) reached the daemon as an empty
// filter and silently dumped every event instead of isolating the zone.
//
// FAIL-ON-REVERT: restoring the numeric-only extraction makes the
// zone-selector cases forward filter="" (no numeric token present), so the
// "zone unknown" / "zone trust" assertions fail; the count+zone case
// forwards just "10", failing that assertion too.
func TestShowEventsForwardsFullFilter(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantFilter string
	}{
		{"zone unknown sentinel", []string{"zone", "unknown"}, "zone unknown"},
		{"named zone", []string{"zone", "trust"}, "zone trust"},
		{"protocol", []string{"protocol", "tcp"}, "protocol tcp"},
		{"count plus zone", []string{"10", "zone", "trust"}, "10 zone trust"},
		{"bare count", []string{"25"}, "25"},
		{"no args", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeBpfrxClient{}
			c := &ctl{client: fake}
			if err := c.showEvents(tc.args); err != nil {
				t.Fatalf("showEvents(%v) = %v; want nil", tc.args, err)
			}
			if fake.showTextCalls != 1 {
				t.Fatalf("ShowText called %d times; want exactly 1", fake.showTextCalls)
			}
			if fake.showTextTopic != "security-log" {
				t.Fatalf("ShowText topic = %q; want %q", fake.showTextTopic, "security-log")
			}
			if fake.showTextFilter != tc.wantFilter {
				t.Fatalf("ShowText filter = %q; want %q (the zone/protocol/action selector must reach the daemon)",
					fake.showTextFilter, tc.wantFilter)
			}
		})
	}
}
