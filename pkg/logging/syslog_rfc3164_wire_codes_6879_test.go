package logging

import (
	"net"
	"strings"
	"testing"
)

// #6879: the RFC 3164 facility and severity numbers are a WIRE CONTRACT. They
// leave the appliance verbatim inside `<PRI>` and a third-party collector files,
// routes, retains and alerts on them. Nothing in this package pinned them to
// their RFC values, so a renumbering shipped silently.
//
// # Provenance of the expected numbers
//
// Every literal below is transcribed from the normative tables of RFC 3164,
// fetched raw rather than summarized:
//
//	https://www.rfc-editor.org/rfc/rfc3164.txt
//	72951 bytes, md5 7f7aef1274f676b90bff677d477a18e6
//
// §4.1.1 "Table 1. syslog Message Facilities" and "Table 2. syslog Message
// Severities". The two priority examples are quoted from the same section:
//
//	"The Priority value is calculated by first multiplying the Facility
//	 number by 8 and then adding the numerical value of the Severity. For
//	 example, a kernel message (Facility=0) with a Severity of Emergency
//	 (Severity=0) would have a Priority value of 0.  Also, a "local use 4"
//	 message (Facility=20) with a Severity of Notice (Severity=5) would
//	 have a Priority value of 165."
//
// The numbers are recorded here rather than derived, because a transcription
// from memory or from a second implementation agrees with whatever it was
// copied from. These agree with the RFC or they are wrong.
//
// # Why the expected column is a bare integer
//
// The pre-existing tables reference the constants on BOTH sides of the
// assertion, so they compare a value to itself and bind only WHICH names map,
// never WHAT they map to. Measured before writing this: `FacilityAuth = 9`
// leaves the whole package green.

// rfc3164Facilities is RFC 3164 §4.1.1 Table 1, for the codes xpf declares.
// Codes 2, 6..10, 13..15 are in the RFC but have no xpf constant; they are
// deliberately absent rather than invented.
var rfc3164Facilities = []struct {
	junosName string // name accepted by ParseFacility, "" if not parseable
	constant  int
	rfc       int // literal from Table 1
	rfcLabel  string
}{
	{"kern", FacilityKern, 0, "kernel messages"},
	{"user", FacilityUser, 1, "user-level messages"},
	{"daemon", FacilityDaemon, 3, "system daemons"},
	{"auth", FacilityAuth, 4, "security/authorization messages"},
	{"syslog", FacilitySyslog, 5, "messages generated internally by syslogd"},
	{"", FacilityFTP, 11, "FTP daemon"},
	{"", FacilityNTP, 12, "NTP subsystem"},
	{"local0", FacilityLocal0, 16, "local use 0"},
	{"local1", FacilityLocal1, 17, "local use 1"},
	{"local2", FacilityLocal2, 18, "local use 2"},
	{"local3", FacilityLocal3, 19, "local use 3"},
	{"local4", FacilityLocal4, 20, "local use 4"},
	{"local5", FacilityLocal5, 21, "local use 5"},
	{"local6", FacilityLocal6, 22, "local use 6"},
	{"local7", FacilityLocal7, 23, "local use 7"},
}

// rfc3164Severities is RFC 3164 §4.1.1 Table 2 in full.
var rfc3164Severities = []struct {
	constant int
	rfc      int // literal from Table 2
	rfcLabel string
}{
	{SyslogEmergency, 0, "Emergency: system is unusable"},
	{SyslogAlert, 1, "Alert: action must be taken immediately"},
	{SyslogCritical, 2, "Critical: critical conditions"},
	{SyslogError, 3, "Error: error conditions"},
	{SyslogWarning, 4, "Warning: warning conditions"},
	{SyslogNotice, 5, "Notice: normal but significant condition"},
	{SyslogInfo, 6, "Informational: informational messages"},
	{SyslogDebug, 7, "Debug: debug-level messages"},
}

func TestRFC3164FacilityCodesAreGolden6879(t *testing.T) {
	for _, f := range rfc3164Facilities {
		if f.constant != f.rfc {
			t.Errorf("facility constant = %d, RFC 3164 Table 1 says %d (%s) — "+
				"this integer goes out on the wire verbatim, so a collector would "+
				"file every record under the wrong facility",
				f.constant, f.rfc, f.rfcLabel)
		}
		if f.junosName == "" {
			continue
		}
		// End-to-end: bind the NAME -> NUMBER mapping, not just the constant's
		// value, so a rewired ParseFacility is caught as well as a renumbering.
		if got := ParseFacility(f.junosName); got != f.rfc {
			t.Errorf("ParseFacility(%q) = %d, RFC 3164 Table 1 says %d (%s)",
				f.junosName, got, f.rfc, f.rfcLabel)
		}
	}
}

// TestRFC3164SeverityCodesAreGolden6879 pins severity VALUES.
//
// The pre-existing ShouldSend tests look like they cover this and do not: they
// assert ORDERING, so they survive any renumbering that preserves the
// comparison order. Measured before writing this: `SyslogDebug = 8` leaves the
// whole package green while every debug record ships the wrong wire byte.
func TestRFC3164SeverityCodesAreGolden6879(t *testing.T) {
	for _, s := range rfc3164Severities {
		if s.constant != s.rfc {
			t.Errorf("severity constant = %d, RFC 3164 Table 2 says %d (%s)",
				s.constant, s.rfc, s.rfcLabel)
		}
	}
}

// TestRFC3164PriorityOnTheWire6879 binds the PRI byte the collector actually
// receives, using the RFC's own two worked examples.
//
// Deliberately driven through a real UDP send rather than re-computing
// `facility*8 + severity` in the test: re-deriving the formula here would pass
// even if Send stopped using it. The expected values are the RFC's, not this
// test's arithmetic.
func TestRFC3164PriorityOnTheWire6879(t *testing.T) {
	for _, tc := range []struct {
		name     string
		facility int
		severity int
		wantPRI  string // quoted from RFC 3164 §4.1.1
	}{
		{"kernel + emergency -> <0>", FacilityKern, SyslogEmergency, "<0>"},
		{"local use 4 + notice -> <165>", FacilityLocal4, SyslogNotice, "<165>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			addr := pc.LocalAddr().(*net.UDPAddr)

			client, err := NewSyslogClient("127.0.0.1", addr.Port)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.Facility = tc.facility

			if err := client.Send(tc.severity, "rfc3164 priority probe"); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4096)
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			got := string(buf[:n])
			if !strings.HasPrefix(got, tc.wantPRI) {
				t.Errorf("wire PRI = %.12q…, want prefix %s — RFC 3164 §4.1.1 states "+
					"this exact priority for this facility/severity pair",
					got, tc.wantPRI)
			}
		})
	}
}

// TestMinSeveritySentinelsAreNotWireCodes6879 guards the #5314 invariant that
// makes the two tables above safe to read separately.
//
// SeverityEmergency(-1) and SeverityNone(-2) are MinSeverity FILTER sentinels,
// not RFC severities — the file says so, and the golden table above therefore
// pins SyslogEmergency to 0 rather than to them. If a future change collapsed
// the sentinel onto the wire code, `emergency` would mean send-all again (the
// #5314 over-forward bug) AND the golden table would start describing a
// different thing than the wire.
func TestMinSeveritySentinelsAreNotWireCodes6879(t *testing.T) {
	if SeverityEmergency == SyslogEmergency {
		t.Error("SeverityEmergency collapsed onto the wire code SyslogEmergency(0), " +
			"which is the send-all sentinel — the #5314 over-forward bug")
	}
	if SeverityNone >= 0 {
		t.Errorf("SeverityNone = %d, must stay negative so it cannot collide with "+
			"an RFC 3164 severity code", SeverityNone)
	}
	// The sentinels must also not collide with each other or the filter cannot
	// distinguish "send only emergency" from "send nothing".
	if SeverityNone == SeverityEmergency {
		t.Error("SeverityNone and SeverityEmergency are equal — `none` and " +
			"`emergency` would be indistinguishable to ShouldSend")
	}
}
