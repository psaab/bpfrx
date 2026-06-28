package cli

import (
	"regexp"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #2288: the `monitor security flow file <name> match <regex>` filter was a
// dead field — set but never read. These tests pin the now-implemented
// behavior: a valid regex is compiled at configure time and applied as a
// line filter; a malformed regex is rejected cleanly (no panic, state
// unchanged).

func TestHandleMonitorSecurityFlowFile_CompilesMatch(t *testing.T) {
	c := &CLI{}
	if err := c.handleMonitorSecurityFlowFile([]string{"trace", "match", "deny|drop"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.monitorFlow == nil {
		t.Fatal("monitorFlow not initialized")
	}
	if c.monitorFlow.match != "deny|drop" {
		t.Fatalf("match = %q, want %q", c.monitorFlow.match, "deny|drop")
	}
	if c.monitorFlow.matchRe == nil {
		t.Fatal("matchRe is nil; match regex was not compiled")
	}
	if !c.monitorFlow.matchRe.MatchString("policy=deny") {
		t.Fatal("compiled regex should match 'policy=deny'")
	}
	if c.monitorFlow.matchRe.MatchString("policy=permit") {
		t.Fatal("compiled regex should not match 'policy=permit'")
	}
}

func TestHandleMonitorSecurityFlowFile_RejectsBadRegex(t *testing.T) {
	c := &CLI{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("bad regex caused panic: %v", r)
		}
	}()
	// "[" is an unterminated character class — invalid RE2.
	if err := c.handleMonitorSecurityFlowFile([]string{"trace", "match", "["}); err != nil {
		t.Fatalf("unexpected error return (should print + return nil): %v", err)
	}
	if c.monitorFlow == nil {
		t.Fatal("monitorFlow not initialized")
	}
	// The bad regex must NOT be stored, and matchRe must stay nil so a trace
	// never starts with a silently-broken filter.
	if c.monitorFlow.match != "" {
		t.Fatalf("match = %q, want empty (bad regex rejected)", c.monitorFlow.match)
	}
	if c.monitorFlow.matchRe != nil {
		t.Fatal("matchRe should remain nil after a rejected regex")
	}
	// #3380: the file command now commits atomically — a failed option (the bad
	// regex) must NOT mutate the stored filename. It stays empty.
	if c.monitorFlow.filename != "" {
		t.Fatalf("filename = %q, want empty (failed option must not mutate filename)", c.monitorFlow.filename)
	}
}

func TestTraceLineMatches(t *testing.T) {
	tests := []struct {
		line    string
		pattern string // "" means nil regex
		want    bool
	}{
		{"policy=deny-all", "deny", true},
		{"policy=permit", "deny", false},
		{"anything at all", "", true}, // nil regex admits everything
		{"TCP 10.0.1.5->10.0.2.1", "^TCP", true},
		{"10.0.1.5 TCP", "^TCP", false}, // anchored: TCP not at start
		{"TCP 10.0.1.5->10.0.2.1", "UDP", false},
	}
	for _, tt := range tests {
		var re *regexp.Regexp
		if tt.pattern != "" {
			re = regexp.MustCompile(tt.pattern)
		}
		if got := traceLineMatches(tt.line, re); got != tt.want {
			t.Errorf("traceLineMatches(%q, %q) = %v, want %v", tt.line, tt.pattern, got, tt.want)
		}
	}
}

// TestTraceMatch_FiltersFormattedEvents wires the match filter to the actual
// formatted flow-event output: only lines matching the regex survive, exactly
// as the live trace loop applies it.
func TestTraceMatch_FiltersFormattedEvents(t *testing.T) {
	re := regexp.MustCompile(`policy=deny`)

	denied := logging.EventRecord{
		Time:        time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC),
		SrcAddr:     "10.0.1.5:12345",
		DstAddr:     "10.0.2.1:80",
		Protocol:    "TCP",
		Action:      "deny",
		InZoneName:  "trust",
		OutZoneName: "untrust",
		PolicyName:  "deny",
	}
	permitted := logging.EventRecord{
		Time:        time.Date(2026, 3, 1, 10, 0, 1, 0, time.UTC),
		SrcAddr:     "10.0.1.6:23456",
		DstAddr:     "10.0.2.2:443",
		Protocol:    "TCP",
		Action:      "permit",
		InZoneName:  "trust",
		OutZoneName: "untrust",
		PolicyName:  "allow-web",
	}

	var written []string
	for _, rec := range []logging.EventRecord{denied, permitted} {
		line := formatFlowEvent(rec)
		if traceLineMatches(line, re) {
			written = append(written, line)
		}
	}

	if len(written) != 1 {
		t.Fatalf("expected exactly 1 matching line, got %d: %v", len(written), written)
	}
	if !regexp.MustCompile(`policy=deny`).MatchString(written[0]) {
		t.Fatalf("surviving line should be the denied event: %q", written[0])
	}
}
