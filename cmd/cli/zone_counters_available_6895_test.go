package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/zonecounters"
)

// zone_counters_available_6895_test.go — #6895.
//
// The remote cli omitted the traffic section whenever both packet counts were
// zero, and the wire carried no way to tell a real zero from the absence of a
// reading. So a zone whose counters are UNAVAILABLE rendered identically to an
// idle one: silence, which an operator reads as "this zone has no traffic" — a
// wrong answer, not a missing one, on the surface an operator is most likely
// holding.
//
// WHAT THESE CELLS DO NOT CLAIM. They do not show idle being distinguished from
// unavailable, because nothing distinguishes those: the helper's status
// snapshot is sparse and OMITS ALL-ZERO ROWS, so a pre-#3651 helper, a zone past
// hot-path slot capacity and a merely idle zone all reach the same sentinel.
// The ambiguity is inherited. What changes is that the surface now SAYS it has
// no reading instead of implying zero traffic.

func renderZone6895(t *testing.T, z *pb.ZoneInfo) string {
	t.Helper()
	return captureStdout(t, func() { renderZoneTraffic6895(z) })
}

func TestUnavailableCountersAreLabelled6895(t *testing.T) {
	out := renderZone6895(t, &pb.ZoneInfo{
		Name:                       "dmz",
		PerZoneCounterAvailability: pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_UNAVAILABLE,
	})

	if strings.TrimSpace(out) == "" {
		t.Fatal("a zone with UNAVAILABLE counters rendered SILENCE — indistinguishable " +
			"from an idle zone, which is the defect (#6895)")
	}
	// It must be the ONE canonical line every surface uses, not a third
	// spelling of the same state.
	if want := zonecounters.UnavailableLine(false); !strings.Contains(out, want) {
		t.Fatalf("the remote cli does not use the shared canonical line.\ngot:  %q\nwant: %q",
			out, want)
	}
	// And it must NOT print numbers, which would be the misleading zero.
	if strings.Contains(out, "packets") {
		t.Fatalf("an unavailable zone rendered packet counts: %q", out)
	}
}

// TestAvailableZeroIsPrintedNotOmitted6895 is the defensive case, and it is
// labelled as such deliberately.
//
// `available && zero` is essentially UNREACHABLE in production — the helper
// omits all-zero rows, so a zone with no traffic yields the not-populated
// sentinel rather than a zero reading. This cell therefore does NOT demonstrate
// "an idle zone now shows 0 packets"; asserting that would be asserting a state
// the data source cannot produce. It pins the renderer's contract: if the server
// ever DOES report a reading of zero, that is an answer and must be shown, not
// silently dropped the way the pre-#6895 `> 0` test dropped it.
func TestAvailableZeroIsPrintedNotOmitted6895(t *testing.T) {
	out := renderZone6895(t, &pb.ZoneInfo{
		Name:                       "trust",
		PerZoneCounterAvailability: pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_AVAILABLE,
	})

	if !strings.Contains(out, "Traffic statistics:") {
		t.Fatalf("an AVAILABLE reading of zero was omitted — the renderer still gates on "+
			"the counts being non-zero, so a measured zero is indistinguishable from "+
			"no measurement: %q", out)
	}
	if !strings.Contains(out, "Input:  0 packets, 0 bytes") {
		t.Fatalf("expected an explicit zero reading: %q", out)
	}
}

func TestAvailableNonZeroRenders6895(t *testing.T) {
	out := renderZone6895(t, &pb.ZoneInfo{
		Name:                       "untrust",
		PerZoneCounterAvailability: pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_AVAILABLE,
		IngressPackets:             12, IngressBytes: 3400,
		EgressPackets: 7, EgressBytes: 900,
	})
	for _, want := range []string{"Input:  12 packets, 3400 bytes", "Output: 7 packets, 900 bytes"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
	if strings.Contains(out, "not available") {
		t.Fatalf("a zone with real counters was labelled unavailable: %q", out)
	}
}

// TestOldServerRendersExactlyAsBefore6895 is the VERSION-SKEW cell, and it is
// the only one that can catch a polarity change.
//
// proto3 has no field presence for scalars. Had this been a `bool
// per_zone_counters_available`, an OLD server's omitted field would decode to
// `false` on a new client and EVERY zone — including ones with real counters —
// would render "not available". The inverted spelling has the mirror-image
// defect: absent decodes to "available" and an unpopulated zone renders as a
// real 0. Both introduce a new wrong answer through the fix for a wrong answer.
//
// UNKNOWN = 0 makes the benign case the default BY CONSTRUCTION. A message with
// the field absent must render byte-for-byte as it did before #6895.
func TestOldServerRendersExactlyAsBefore6895(t *testing.T) {
	// An old server sends no availability field at all: the zero value.
	oldServerIdle := &pb.ZoneInfo{Name: "dmz"}
	if oldServerIdle.PerZoneCounterAvailability !=
		pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_UNKNOWN {
		t.Fatal("precondition: an absent field must decode to UNKNOWN, or this cell " +
			"cannot model a skewed pair")
	}

	// Pre-#6895 behaviour with both counts zero: the section is OMITTED.
	if got := strings.TrimSpace(renderZone6895(t, oldServerIdle)); got != "" {
		t.Fatalf("an OLD server's zero-count zone now renders %q — a new wrong answer "+
			"introduced by the fix. UNKNOWN must render exactly as before #6895", got)
	}

	// Pre-#6895 behaviour with real counts: the section is PRINTED.
	oldServerBusy := &pb.ZoneInfo{Name: "untrust", IngressPackets: 5, IngressBytes: 60}
	out := renderZone6895(t, oldServerBusy)
	if !strings.Contains(out, "Input:  5 packets, 60 bytes") {
		t.Fatalf("an OLD server's zone with real counters lost its numbers: %q", out)
	}
	if strings.Contains(out, "not available") {
		t.Fatalf("an OLD server's zone with real counters was labelled unavailable — "+
			"this is exactly what a `bool ..._available` would have done to every "+
			"zone: %q", out)
	}
}

// TestAllSurfacesShareOneSpelling6895 binds the AGREEMENT rather than pinning a
// literal in each surface.
//
// Three surfaces report this one dataplane state. Before #6895 the generic
// sentence was duplicated verbatim in two of them with nothing binding them, and
// checking that agreement is what surfaced a real gap: the gRPC text renderer
// had NO #6845 overflow specialisation while the local CLI did, so the same
// cluster reported slot exhaustion on one surface and the generic line on the
// other. Asserting a literal here would re-encode the duplication this removes.
func TestAllSurfacesShareOneSpelling6895(t *testing.T) {
	generic := zonecounters.UnavailableLine(false)
	overflow := zonecounters.UnavailableLine(true)

	if generic == overflow {
		t.Fatal("the overflow specialisation is not distinct from the generic line, so " +
			"the one actionable cause reads identically to the ambiguous ones (#6845)")
	}
	// The generic line must keep admitting the ambiguity it cannot resolve —
	// naming a single cause would be a guess (see maps_counters.go).
	if !strings.Contains(generic, "idle") {
		t.Fatalf("the generic line stopped admitting that an idle zone is one of the "+
			"indistinguishable causes; it must not name a cause it cannot know: %q",
			generic)
	}
	// The overflow line must name the actionable cause.
	if !strings.Contains(overflow, "EXHAUSTED") {
		t.Fatalf("the overflow line does not name slot exhaustion, the one cause that "+
			"needs operator action: %q", overflow)
	}
	// And the remote cli must emit the shared generic line verbatim.
	out := renderZone6895(t, &pb.ZoneInfo{
		PerZoneCounterAvailability: pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_UNAVAILABLE,
	})
	if !strings.Contains(out, generic) {
		t.Fatalf("the remote cli emits a spelling of its own rather than the shared "+
			"line:\ngot:  %q\nwant: %q", out, generic)
	}
}
