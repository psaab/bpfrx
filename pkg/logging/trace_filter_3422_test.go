package logging

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestTraceWriterInvalidFilterMatchesNone is the #3422 M01 runtime guard: a
// packet-filter whose prefix does not parse must NARROW tracing to nothing, not
// be silently dropped. Before the fix NewTraceWriter dropped the typo'd filter,
// leaving tw.filters empty, and HandleEvent skips filtering when there are no
// filters — so a filter meant to narrow tracing broadened it to every event.
//
// FAIL-ON-REVERT: restore the `continue` that drops an invalid filter and this
// test fails (filters becomes empty -> matchFilters reports a match).
func TestTraceWriterInvalidFilterMatchesNone(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{
		File: "rt-flow.log",
		PacketFilters: []*config.TracePacketFilter{
			{Name: "pf1", SourcePrefix: "10.0.0.999/32"},
		},
	})
	if err != nil {
		t.Fatalf("NewTraceWriter: %v", err)
	}
	defer tw.Close()

	// The invalid filter must be retained so the writer still has a non-empty
	// filter set (otherwise HandleEvent traces everything).
	if len(tw.filters) != 1 {
		t.Fatalf("filters = %d, want 1 (invalid filter retained as match-none)", len(tw.filters))
	}
	if !tw.filters[0].invalid {
		t.Fatalf("filter not marked invalid")
	}

	// No event matches the all-invalid filter set.
	rec := EventRecord{SrcAddr: "10.0.1.5:1000", DstAddr: "10.0.2.5:80", Protocol: "TCP"}
	if tw.matchFilters(rec) {
		t.Fatalf("matchFilters returned true for an all-invalid filter set; tracing was broadened (#3422 M01)")
	}
}

// TestTraceWriterOneValidOneInvalidFilter verifies a valid filter alongside an
// invalid one still works: the valid filter matches its traffic, the invalid
// one never matches (and never broadens to all traffic).
func TestTraceWriterOneValidOneInvalidFilter(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{
		File: "rt-flow.log",
		PacketFilters: []*config.TracePacketFilter{
			{Name: "pf1", SourcePrefix: "10.0.1.0/24"},
			{Name: "pf2", SourcePrefix: "bogus/24"},
		},
	})
	if err != nil {
		t.Fatalf("NewTraceWriter: %v", err)
	}
	defer tw.Close()

	// Both filters must be retained (the invalid one kept as match-none, not
	// dropped) so the writer has a non-empty filter set and the second filter
	// is marked invalid. Asserting both pins the M01 fail-safe: if the invalid
	// filter were dropped instead, len would be 1 and this fails.
	if len(tw.filters) != 2 {
		t.Fatalf("filters = %d, want 2 (valid + invalid both retained)", len(tw.filters))
	}
	if tw.filters[0].invalid {
		t.Fatalf("valid filter pf1 wrongly marked invalid")
	}
	if !tw.filters[1].invalid {
		t.Fatalf("invalid filter pf2 not marked invalid")
	}

	// Inside the valid filter -> match.
	if !tw.matchFilters(EventRecord{SrcAddr: "10.0.1.5:1000", DstAddr: "10.0.2.5:80", Protocol: "TCP"}) {
		t.Fatalf("valid filter did not match its own traffic")
	}
	// Outside the valid filter -> no match (the invalid filter must not catch it).
	if tw.matchFilters(EventRecord{SrcAddr: "10.0.9.5:1000", DstAddr: "10.0.2.5:80", Protocol: "TCP"}) {
		t.Fatalf("invalid filter broadened tracing to non-matching traffic (#3422 M01)")
	}
}

// TestTraceWriterEmptyPrefixMatchesNone is the #3422 BLOCKER runtime guard: a
// filter whose source-prefix was PRESENT but empty (`source-prefix ""`, flagged
// by the compiler as InvalidPrefix) must NARROW tracing to nothing, not broaden
// it to every event. An empty prefix string is indistinguishable from an absent
// one at the runtime, so the compiler carries the present-but-empty conclusion
// in InvalidPrefix and NewTraceWriter must fail the filter closed.
//
// FAIL-ON-REVERT: drop the `invalid: pf.InvalidPrefix` seed in NewTraceWriter
// and this filter parses to zero srcNet/dstNet/proto -> matchFilters returns
// true for everything (the M01 fail-open in a smaller costume).
func TestTraceWriterEmptyPrefixMatchesNone(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{
		File: "rt-flow.log",
		PacketFilters: []*config.TracePacketFilter{
			// Present-but-empty prefix: the compiler sets InvalidPrefix.
			{Name: "pf1", SourcePrefix: "", InvalidPrefix: true},
		},
	})
	if err != nil {
		t.Fatalf("NewTraceWriter: %v", err)
	}
	defer tw.Close()

	if len(tw.filters) != 1 {
		t.Fatalf("filters = %d, want 1 (empty-prefix filter retained as match-none)", len(tw.filters))
	}
	if !tw.filters[0].invalid {
		t.Fatalf("empty-prefix filter not marked invalid; it would match every event (#3422 BLOCKER)")
	}
	if tw.matchFilters(EventRecord{SrcAddr: "10.0.1.5:1000", DstAddr: "10.0.2.5:80", Protocol: "TCP"}) {
		t.Fatalf("empty-prefix filter matched an event; tracing was broadened to everything (#3422 BLOCKER)")
	}
}

// TestTraceWriterProtocolOnlyFilterMatches is the anti-over-rejection guard for
// the #3422 BLOCKER fix: a filter with NO prefixes but a protocol (an absent
// prefix, InvalidPrefix false) must stay VALID and match on its protocol. This
// is the case the empty-prefix rejection must NOT catch.
//
// FAIL-ON-REVERT: mark an absent-prefix filter invalid (over-reject) and this
// fails (a legitimate protocol-only filter would stop matching).
func TestTraceWriterProtocolOnlyFilterMatches(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{
		File: "rt-flow.log",
		PacketFilters: []*config.TracePacketFilter{
			{Name: "pf1", Protocol: "tcp"}, // no prefixes, InvalidPrefix false
		},
	})
	if err != nil {
		t.Fatalf("NewTraceWriter: %v", err)
	}
	defer tw.Close()

	if len(tw.filters) != 1 {
		t.Fatalf("filters = %d, want 1", len(tw.filters))
	}
	if tw.filters[0].invalid {
		t.Fatalf("protocol-only filter wrongly marked invalid (over-rejection)")
	}
	// Matches its protocol regardless of address.
	if !tw.matchFilters(EventRecord{SrcAddr: "10.0.9.5:1000", DstAddr: "8.8.8.8:80", Protocol: "TCP"}) {
		t.Fatalf("protocol-only filter did not match a TCP event")
	}
	// Does not match a different protocol.
	if tw.matchFilters(EventRecord{SrcAddr: "10.0.9.5:1000", DstAddr: "8.8.8.8:80", Protocol: "UDP"}) {
		t.Fatalf("protocol-only TCP filter matched a UDP event")
	}
}

// TestTraceWriterUnknownFlagAppliesDefaults is the #3422 M02 runtime guard: an
// unimplemented flag must be dropped so the basic-datapath/session defaults
// still apply, not installed into a non-empty map that suppresses the defaults
// and makes matchFlags never match (empty trace file while reporting enabled).
//
// FAIL-ON-REVERT: install every flag unconditionally and this test fails (the
// unknown flag suppresses defaults, so SESSION_OPEN no longer matches).
func TestTraceWriterUnknownFlagAppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{
		File:  "rt-flow.log",
		Flags: []string{"sesson"}, // typo for "session"
	})
	if err != nil {
		t.Fatalf("NewTraceWriter: %v", err)
	}
	defer tw.Close()

	if tw.flags["sesson"] {
		t.Fatalf("unknown flag was installed into the flag map (#3422 M02)")
	}
	// Defaults applied -> matchFlags recognizes the event types.
	if !tw.matchFlags("SESSION_OPEN") {
		t.Fatalf("defaults not applied after dropping unknown flag; SESSION_OPEN did not match (#3422 M02)")
	}
	if !tw.matchFlags("BASIC_EVENT") {
		t.Fatalf("basic-datapath default not applied after dropping unknown flag")
	}
}

// TestTraceWriterKnownFlagSuppressesOther verifies an implemented single flag is
// still honored exactly (defaults are NOT auto-added when a real flag is set).
func TestTraceWriterKnownFlagSuppressesDefaults(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{
		File:  "rt-flow.log",
		Flags: []string{"session"},
	})
	if err != nil {
		t.Fatalf("NewTraceWriter: %v", err)
	}
	defer tw.Close()

	if tw.flags["basic-datapath"] {
		t.Fatalf("basic-datapath default added despite an explicit session flag")
	}
	if !tw.matchFlags("SESSION_OPEN") {
		t.Fatalf("explicit session flag did not match SESSION_OPEN")
	}
	if tw.matchFlags("BASIC_EVENT") {
		t.Fatalf("session-only flag matched a basic-datapath event")
	}
}
