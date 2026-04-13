package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestFormatSessionBriefEndpoint(t *testing.T) {
	if got, want := formatSessionBriefEndpoint("192.0.2.10", 443), "192.0.2.10:443"; got != want {
		t.Fatalf("formatSessionBriefEndpoint() = %q, want %q", got, want)
	}
	if got, want := formatSessionBriefEndpoint("2001:db8::10", 443), "[2001:db8::10]:443"; got != want {
		t.Fatalf("formatSessionBriefEndpoint() = %q, want %q", got, want)
	}
}

func TestSessionBriefWriterPreservesLongValues(t *testing.T) {
	var buf bytes.Buffer
	w := newSessionBriefWriter(&buf)
	printSessionBriefHeader(w)
	printSessionBriefRow(w, sessionBriefRow{
		ID:          42,
		Source:      formatSessionBriefEndpoint("2001:db8:100::1234", 65535),
		Destination: formatSessionBriefEndpoint("2001:db8:200::5678", 443),
		Proto:       "tcp",
		Zone:        "very-long-trust-zone-name->another-very-long-untrust-zone-name",
		NAT:         "-",
		State:       "ESTAB",
		Age:         123,
		FwdPackets:  456789,
		RevPackets:  987654,
	})
	flushSessionBriefWriter(w)

	out := buf.String()
	for _, needle := range []string{
		"ID",
		"[2001:db8:100::1234]:65535",
		"[2001:db8:200::5678]:443",
		"very-long-trust-zone-name->another-very-long-untrust-zone-name",
		"456789/987654",
	} {
		if !strings.Contains(out, needle) {
			t.Fatalf("brief output missing %q:\n%s", needle, out)
		}
	}
	if strings.Contains(out, "\t") {
		t.Fatalf("brief output still contains tabs after flush:\n%s", out)
	}
}
