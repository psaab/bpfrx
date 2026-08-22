package frr

import (
	"strings"
	"testing"
)

// #6590: a peer-advertised IS-IS hostname containing a SPACE must not shift the
// adjacency columns and let the peer forge State/Level/Interface/HoldTime.
//
// The first column of `show isis neighbor` is the hostname the peer advertised
// in its Dynamic Hostname TLV (RFC 5301, `hostname dynamic`, on by default),
// and FRR retains printable ASCII spaces when decoding that TLV. Assigning
// tokens to columns purely by POSITION therefore let the peer push its own
// bytes into every later cell:
//
//	wire row:  evil peer ge-0-0-1 2 Up 27
//	parsed as: SystemID=evil Interface=peer Level=ge-0-0-1 State=2 HoldTime=Up
//
// With enough space-separated tokens the peer controls all five displayed cells
// and the operator sees a well-formed table whose values come from the
// adjacency's own remote end.
//
// This is NOT the #6468 escape-injection defect and is not fixed by the #6579
// display guard: sanitizing preserves plausible printable text, so it cannot
// distinguish a genuine State=Up from a peer-supplied token. The row can be
// terminal-safe and still materially false — a display INTEGRITY defect whose
// fix belongs in the parser.
//
// FAIL-ON-REVERT: restore the positional assignment (drop the field-count and
// level/holdtime shape checks) and the shifted rows below parse as well-formed
// with peer-chosen values in every cell.

func isisManager(t *testing.T, table string) *Manager {
	t.Helper()
	return &Manager{exec: &fakeExecutor{
		vtyshResp: map[string]string{"show isis neighbor": table},
	}}
}

const isisHeader = "Area 1:\n" +
	" System Id           Interface   L  State        Holdtime SNPA\n"

// TestSpaceBearingHostnameIsNotRenderedAsColumns is the core RED-on-revert.
func TestSpaceBearingHostnameIsNotRenderedAsColumns(t *testing.T) {
	cases := []struct {
		name string
		row  string
	}{
		{
			// One space: pushes the count to 7 with SNPA present.
			"one-space-with-snpa",
			" evil peer           ge-0-0-1    2  Up           27       2020.2020.2020",
		},
		{
			// One space, no SNPA: exactly 6 fields, so the COUNT bound alone
			// does not catch it — the level slot holds "ge-0-0-1" and the
			// shape check is what rejects it.
			"one-space-no-snpa",
			" evil peer ge-0-0-1 2 Up 27",
		},
		{
			// The full forgery from the issue: the peer supplies every cell.
			"peer-controls-every-cell",
			" x ge-0-0-9 2 Down 99   ge-0-0-1    2  Up           27       2020.2020.2020",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adjs, err := isisManager(t, isisHeader+tc.row+"\n").GetISISAdjacency()
			if err != nil {
				t.Fatalf("GetISISAdjacency: %v", err)
			}
			if len(adjs) != 1 {
				t.Fatalf("want 1 adjacency, got %d: %+v", len(adjs), adjs)
			}
			a := adjs[0]
			if !a.Malformed {
				t.Fatalf("a space-bearing hostname parsed as a well-formed row: "+
					"SystemID=%q Interface=%q Level=%q State=%q HoldTime=%q — "+
					"every one of those cells is peer-controlled",
					a.SystemID, a.Interface, a.Level, a.State, a.HoldTime)
			}
			// A malformed row must assert NOTHING. Reporting a neighbour in
			// state "" is quieter than the forgery but still false.
			if a.SystemID != "" || a.Interface != "" || a.Level != "" ||
				a.State != "" || a.HoldTime != "" {
				t.Errorf("malformed row still carries derived values: %+v", a)
			}
			// ...but it must not be DROPPED either: a silently discarded row
			// hides a real adjacency.
			if a.Raw == "" {
				t.Error("malformed row has no Raw text, so the operator cannot " +
					"see that an adjacency exists at all")
			}
		})
	}
}

// TestWellFormedRowsStillParse is the negative control. A guard that rejected
// everything would satisfy the test above while breaking the command.
func TestWellFormedRowsStillParse(t *testing.T) {
	cases := []struct {
		name                             string
		row                              string
		sysID, iface, level, state, hold string
	}{
		{
			"with-snpa",
			" rtr1                ge-0-0-1    2  Up           27       2020.2020.2020",
			"rtr1", "ge-0-0-1", "2", "Up", "27",
		},
		{
			// SNPA absent (5 fields) is legitimate and must still parse.
			"without-snpa",
			" rtr2                ge-0-0-2    1  Up           30",
			"rtr2", "ge-0-0-2", "1", "Up", "30",
		},
		{
			"level-1-2",
			" rtr3                ge-0-0-3    1-2  Init       9        2020.2020.2021",
			"rtr3", "ge-0-0-3", "1-2", "Init", "9",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adjs, err := isisManager(t, isisHeader+tc.row+"\n").GetISISAdjacency()
			if err != nil {
				t.Fatalf("GetISISAdjacency: %v", err)
			}
			if len(adjs) != 1 {
				t.Fatalf("want 1 adjacency, got %d: %+v", len(adjs), adjs)
			}
			a := adjs[0]
			if a.Malformed {
				t.Fatalf("a well-formed row was rejected: %+v", a)
			}
			if a.SystemID != tc.sysID || a.Interface != tc.iface ||
				a.Level != tc.level || a.State != tc.state || a.HoldTime != tc.hold {
				t.Errorf("got %+v, want sysID=%q iface=%q level=%q state=%q hold=%q",
					a, tc.sysID, tc.iface, tc.level, tc.state, tc.hold)
			}
		})
	}
}

// TestEscapeBearingHostnameStaysWellFormed keeps #6590 and #6468 orthogonal.
//
// A hostname carrying an ESC/CSI sequence but NO space is a well-formed row:
// the columns are correctly attributed and the escape is the display guard's
// problem, not the parser's. If this went Malformed, the #6468/#6579 escape
// regression fixtures would stop exercising the display guard they exist for —
// they would be testing this parser's rejection instead, and the guard could
// rot undetected.
func TestEscapeBearingHostnameStaysWellFormed(t *testing.T) {
	row := " rtr1\x1b[2Kforged     ge-0-0-1    2  Up           27       2020.2020.2020"
	adjs, err := isisManager(t, isisHeader+row+"\n").GetISISAdjacency()
	if err != nil {
		t.Fatalf("GetISISAdjacency: %v", err)
	}
	if len(adjs) != 1 {
		t.Fatalf("want 1 adjacency, got %d", len(adjs))
	}
	a := adjs[0]
	if a.Malformed {
		t.Fatal("an escape-bearing (but space-free) hostname must stay a " +
			"well-formed row — the escape is the display guard's job")
	}
	if !strings.Contains(a.SystemID, "\x1b") {
		t.Errorf("the raw escape must survive into SystemID for the display "+
			"guard to escape; got %q", a.SystemID)
	}
	if a.State != "Up" || a.Level != "2" || a.HoldTime != "27" {
		t.Errorf("columns misattributed: %+v", a)
	}
}

// TestShapeChecksRejectForgedLevelAndHoldTime pins the two FRR-generated
// columns individually, so neither check can be dropped without a red.
func TestShapeChecksRejectForgedLevelAndHoldTime(t *testing.T) {
	for _, tc := range []struct{ name, row string }{
		// Level slot is not an IS-IS level.
		{"bad-level", " rtr1 ge-0-0-1 XX Up 27 2020.2020.2020"},
		// Holdtime slot is not numeric.
		{"bad-holdtime", " rtr1 ge-0-0-1 2 Up notanumber 2020.2020.2020"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adjs, err := isisManager(t, isisHeader+tc.row+"\n").GetISISAdjacency()
			if err != nil {
				t.Fatalf("GetISISAdjacency: %v", err)
			}
			if len(adjs) != 1 || !adjs[0].Malformed {
				t.Fatalf("want a malformed row, got %+v", adjs)
			}
		})
	}
}

// TestHeaderAndAreaLinesStillSkipped: the parser's existing skips must survive.
func TestHeaderAndAreaLinesStillSkipped(t *testing.T) {
	adjs, err := isisManager(t, isisHeader).GetISISAdjacency()
	if err != nil {
		t.Fatalf("GetISISAdjacency: %v", err)
	}
	if len(adjs) != 0 {
		t.Fatalf("header/area lines produced adjacencies: %+v", adjs)
	}
}
