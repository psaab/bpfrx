package cli

import (
	"strings"
	"testing"
)

// #4824: printChronyTracking (pkg/cli/chrony.go) parses `chronyc tracking`
// output — external, whitespace-aligned "Key : Value" lines — and renders a
// Junos-style "NTP sync status:" block. It had no unit coverage: a change in
// chronyc's field labels or in the presenter's key lookups / render prefixes
// would silently drop fields with nothing to catch the regression. These
// table-driven cases feed representative and edge-case tracking output and
// assert the rendered block, exercising:
//   - the " : " split + TrimSpace key/value extraction,
//   - every one of the 11 rendered field lookups (in fixed render order),
//   - the deliberate OMISSION of chronyc fields the presenter does not map
//     (Residual freq, Skew),
//   - the idx>0 guard that skips a leading-separator line with an empty key,
//   - malformed lines with no " : " separator being ignored,
//   - last-value-wins on a duplicated key (map overwrite),
//   - unusual / unsynchronised Leap status values passing through verbatim,
//   - empty input rendering only the header.

func TestPrintChronyTracking4824(t *testing.T) {
	// Canonical, fully-synchronised chronyc tracking block. Values are made
	// distinct (esp. Frequency vs Skew) so the omission checks are meaningful.
	fullOutput := `Reference ID    : 0A000001 (ntp1.example.net)
Stratum         : 3
Ref time (UTC)  : Thu Jul 10 12:34:56 2026
System time     : 0.000123456 seconds slow of NTP time
Last offset     : -0.000012345 seconds
RMS offset      : 0.000034567 seconds
Frequency       : 12.345 ppm slow
Residual freq   : +0.001 ppm
Skew            : 0.234 ppm
Root delay      : 0.001234567 seconds
Root dispersion : 0.000567890 seconds
Update interval : 64.2 seconds
Leap status     : Normal`

	// The presenter renders a fixed 12-line block (header + 11 fields) in a
	// deterministic order regardless of input line order. Exact-match this one.
	fullExpected := strings.Join([]string{
		"NTP sync status:",
		"  Reference: 0A000001 (ntp1.example.net)",
		"  Stratum: 3",
		"  Reference time: Thu Jul 10 12:34:56 2026",
		"  System time offset: 0.000123456 seconds slow of NTP time",
		"  Last offset: -0.000012345 seconds",
		"  RMS offset: 0.000034567 seconds",
		"  Frequency: 12.345 ppm slow",
		"  Root delay: 0.001234567 seconds",
		"  Root dispersion: 0.000567890 seconds",
		"  Poll interval: 64.2 seconds",
		"  Leap status: Normal",
		"",
	}, "\n")

	cases := []struct {
		name string
		// wantExact, when non-empty, asserts the captured stdout matches byte
		// for byte (strongest check: catches field drops, relabels, reorders).
		wantExact string
		// wantContain / wantAbsent assert presence / absence of substrings for
		// the edge cases where an exact block is not the point.
		output      string
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:      "fully synchronized block renders all fields in order",
			output:    fullOutput,
			wantExact: fullExpected,
			// Belt-and-suspenders: chronyc emits Residual freq and Skew, but the
			// presenter maps neither, so their labels and the Skew value must not
			// leak into the rendered block.
			wantAbsent: []string{"Residual freq", "Skew", "0.234 ppm"},
		},
		{
			name: "unsynchronised block passes Leap status verbatim",
			output: `Reference ID    : 00000000 ()
Stratum         : 0
Ref time (UTC)  : Thu Jan 01 00:00:00 1970
System time     : 0.000000000 seconds slow of NTP time
Last offset     : +0.000000000 seconds
RMS offset      : 0.000000000 seconds
Frequency       : 0.000 ppm slow
Root delay      : 1.000000000 seconds
Root dispersion : 1.000000000 seconds
Update interval : 0.0 seconds
Leap status     : Not synchronised`,
			wantContain: []string{
				"NTP sync status:",
				"  Reference: 00000000 ()",
				"  Stratum: 0",
				"  Leap status: Not synchronised",
			},
		},
		{
			name:   "unusual leap status value is not normalised",
			output: "Stratum         : 2\nLeap status     : Insert second",
			wantContain: []string{
				"  Stratum: 2",
				"  Leap status: Insert second",
			},
		},
		{
			name: "malformed and empty-key lines are ignored, valid fields still parse",
			// Line 2 has no " : " separator; line 4 has a leading " : " so its
			// key is empty and idx==0 (must be skipped by the idx>0 guard);
			// the remaining lines are well-formed.
			output: "Reference ID    : 0A000002 (ntp2)\n" +
				"this line has no separator at all\n" +
				"Stratum : 5\n" +
				" : orphan value with empty key\n" +
				"Leap status     : Normal",
			wantContain: []string{
				"  Reference: 0A000002 (ntp2)",
				"  Stratum: 5",
				"  Leap status: Normal",
			},
			wantAbsent: []string{
				"this line has no separator",
				"orphan value with empty key",
			},
		},
		{
			name:   "duplicated key keeps the last value",
			output: "Stratum         : 2\nStratum         : 9",
			wantContain: []string{
				"  Stratum: 9",
			},
			wantAbsent: []string{
				"  Stratum: 2",
			},
		},
		{
			name:      "empty input renders only the header",
			output:    "",
			wantExact: "NTP sync status:\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := captureStdout(t, func() {
				printChronyTracking(tc.output)
			})
			if tc.wantExact != "" {
				if got != tc.wantExact {
					t.Fatalf("printChronyTracking() rendered block mismatch\n got:\n%q\nwant:\n%q", got, tc.wantExact)
				}
			}
			for _, want := range tc.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("printChronyTracking() output missing %q\nfull output:\n%s", want, got)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("printChronyTracking() output unexpectedly contains %q\nfull output:\n%s", absent, got)
				}
			}
		})
	}
}
