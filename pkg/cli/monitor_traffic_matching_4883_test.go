package cli

import "testing"

// TestParseMonitorTrafficRejectsEmptyMatching is the #4883-A regression guard.
// `monitor traffic interface ge-0-0-0 matching` (a trailing bare `matching`,
// or `matching` immediately followed by another grammar keyword) collected an
// empty `rest`, returned filter="", and launched tcpdump with NO BPF
// expression — a privileged capture that exposes ALL interface traffic instead
// of the intended flow. The parser must now reject an empty `matching`
// predicate.
//
// Goes RED on revert: without the guard filter would be "" and err nil, so
// handleMonitorTraffic would start an unfiltered capture.
func TestParseMonitorTrafficRejectsEmptyMatching(t *testing.T) {
	cases := [][]string{
		{"interface", "ge-0-0-0", "matching"},                // trailing bare matching
		{"interface", "ge-0-0-0", "matching", "count", "20"}, // keyword, no filter
	}
	for _, args := range cases {
		_, filter, _, err := parseMonitorTrafficArgs(args)
		if err == nil {
			t.Errorf("parseMonitorTrafficArgs(%v) = filter %q, nil err; want an error (an empty matching predicate must not start an unfiltered capture)", args, filter)
		}
		if filter != "" {
			t.Errorf("parseMonitorTrafficArgs(%v) set filter=%q; want empty on rejection", args, filter)
		}
	}
}

// TestParseMonitorTrafficRejectsTypoPredicate is the #4883-A regression guard
// for a mistyped predicate. `monitor traffic interface ge-0-0-0 matchng tcp
// port 443` (note the typo `matchng`) hit no switch arm, so every following
// token was silently discarded and an UNFILTERED capture started. The parser
// must now reject any unrecognized/stray token.
//
// Goes RED on revert: without the default arm the typo tokens are dropped,
// filter stays "", err is nil, and the capture runs unfiltered.
func TestParseMonitorTrafficRejectsTypoPredicate(t *testing.T) {
	cases := [][]string{
		{"interface", "ge-0-0-0", "matchng", "tcp", "port", "443"}, // typo'd matching
		{"interface", "ge-0-0-0", "bogus"},                         // stray trailing token
	}
	for _, args := range cases {
		iface, filter, _, err := parseMonitorTrafficArgs(args)
		if err == nil {
			t.Errorf("parseMonitorTrafficArgs(%v) = iface %q filter %q, nil err; want an error (a stray/typo token must not be discarded into an unfiltered capture)", args, iface, filter)
		}
		if filter != "" {
			t.Errorf("parseMonitorTrafficArgs(%v) set filter=%q; want empty on rejection", args, filter)
		}
	}
}
