package frr

import (
	"context"
	"strings"
	"testing"
)

// isis_malformed_row_7430_test.go — #7430.
//
// GetISISAdjacency `continue`d on a row it could not parse — no header seen
// (trailing <= 0), or a row shorter than the trailing width. The row was
// DROPPED, so the adjacency simply did not appear.
//
// To an operator debugging a missing neighbour that is indistinguishable from
// "the adjacency does not exist", and it points at the wrong problem. A row
// saying THIS LINE COULD NOT BE PARSED points at the real one: an FRR version
// change, or a truncated vtysh response.
//
// The rejected alternative — rendering the row with empty derived fields —
// would report a neighbour in state "": quieter than the #6590 column-forgery
// but still false. So the shape is "report as unparseable", never "render
// partially", and the derived fields stay EMPTY so a consumer that forgets to
// branch cannot read a fabricated state.

func adjsFromOutput7430(t *testing.T, output string) []ISISAdjacency {
	t.Helper()
	m := &Manager{exec: &fakeExecutor{vtyshResp: map[string]string{"show isis neighbor": output}}}
	adjs, err := m.GetISISAdjacency(context.Background())
	if err != nil {
		t.Fatalf("GetISISAdjacency: %v", err)
	}
	return adjs
}

// A row SHORTER than the trailing width is reported, not dropped.
func TestShortRowIsReportedNotDropped7430(t *testing.T) {
	out := "" +
		"Area 1:\n" +
		"System Id           Interface   L  State        Holdtime SNPA\n" +
		"good-peer           ge-0/0/0    2  Up           27       2c21.72e5.1eb1\n" +
		"truncated-row       ge-0/0/1\n"
	adjs := adjsFromOutput7430(t, out)
	if len(adjs) != 2 {
		t.Fatalf("got %d rows, want 2 (one good, one reported-malformed); a dropped row "+
			"is indistinguishable from 'no such adjacency' (#7430): %+v", len(adjs), adjs)
	}
	var bad *ISISAdjacency
	for i := range adjs {
		if adjs[i].Malformed {
			bad = &adjs[i]
		}
	}
	if bad == nil {
		t.Fatal("the short row was not reported as malformed")
	}
	if !strings.Contains(bad.Raw, "truncated-row") {
		t.Errorf("Raw does not carry the offending line: %q", bad.Raw)
	}
	// The derived fields must stay EMPTY. A consumer that forgets to branch on
	// Malformed must not be able to read a fabricated state — that is the
	// rejected render-partially shape.
	if bad.SystemID != "" || bad.Interface != "" || bad.Level != "" || bad.State != "" || bad.HoldTime != "" {
		t.Errorf("a malformed row carries derived fields %+v; they must be empty so a "+
			"consumer cannot report a neighbour in state \"\" (#7430)", *bad)
	}
}

// A table with NO header is reported too — that is the other unparseable case.
func TestHeaderlessTableIsReportedNotDropped7430(t *testing.T) {
	out := "" +
		"Area 1:\n" +
		"some-peer           ge-0/0/0    2  Up           27       2c21.72e5.1eb1\n"
	adjs := adjsFromOutput7430(t, out)
	if len(adjs) != 1 {
		t.Fatalf("got %d rows, want 1 reported-malformed: %+v", len(adjs), adjs)
	}
	if !adjs[0].Malformed {
		t.Error("a row seen with no header was parsed anyway; without the header the " +
			"trailing width is unknown and guessing is the #6590 failure")
	}
	if !strings.Contains(adjs[0].Raw, "some-peer") {
		t.Errorf("Raw does not carry the line: %q", adjs[0].Raw)
	}
}

// THE ORTHOGONALITY CONSTRAINT — this is the cell #7430 asks for by name.
//
// An escape-bearing but SPACE-FREE hostname must remain a WELL-FORMED row. If
// it were marked Malformed, the #6468/#6579 escape fixtures would stop
// exercising the display guard they exist for — they would be testing this
// parser's rejection instead, and THE DISPLAY GUARD COULD ROT UNDETECTED.
//
// It stays well-formed because strings.Fields splits on unicode.IsSpace only,
// so ESC/DEL/BEL and the C1 range do not split a field: a space-free hostname
// is one token however many escapes it carries.
func TestEscapeBearingHostnameStaysWellFormed7430(t *testing.T) {
	const hostile = "peer\x1b[31mred\x07"
	out := "" +
		"Area 1:\n" +
		"System Id           Interface   L  State        Holdtime SNPA\n" +
		hostile + "   ge-0/0/0    2  Up           27       2c21.72e5.1eb1\n"
	adjs := adjsFromOutput7430(t, out)
	if len(adjs) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(adjs), adjs)
	}
	if adjs[0].Malformed {
		t.Fatal("an escape-bearing but SPACE-FREE hostname was marked malformed. #6590 " +
			"and #6468 must stay orthogonal: if this row stops being well-formed, the " +
			"#6468/#6579 escape fixtures stop exercising the DISPLAY guard they exist " +
			"for — they would be testing this parser's rejection instead, and the " +
			"display guard could rot undetected (#7430)")
	}
	if adjs[0].SystemID != hostile {
		t.Errorf("SystemID = %q, want the hostname verbatim %q — the parser must not "+
			"sanitize; that is the display layer's job", adjs[0].SystemID, hostile)
	}
	if adjs[0].State != "Up" {
		t.Errorf("State = %q, want \"Up\": the right-anchored parse must still assign "+
			"the trailing columns correctly", adjs[0].State)
	}
}

// CONTROL — an ordinary table is unaffected. Without this, a parser that marked
// EVERY row malformed would satisfy the two reporting cells above.
func TestWellFormedRowsAreUnaffected7430(t *testing.T) {
	out := "" +
		"Area 1:\n" +
		"System Id           Interface   L  State        Holdtime SNPA\n" +
		"peer-a              ge-0/0/0    2  Up           27       2c21.72e5.1eb1\n" +
		"peer-b              ge-0/0/1    2  Up           29       2c21.72e5.1eb2\n"
	adjs := adjsFromOutput7430(t, out)
	if len(adjs) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(adjs), adjs)
	}
	for _, a := range adjs {
		if a.Malformed {
			t.Errorf("a well-formed row was marked malformed: %+v", a)
		}
		if a.State != "Up" || a.Level != "2" {
			t.Errorf("well-formed parse regressed: %+v", a)
		}
	}
	// A hostname WITH a space is still absorbed right-anchored (#6590).
	out2 := "" +
		"Area 1:\n" +
		"System Id           Interface   L  State        Holdtime SNPA\n" +
		"peer with spaces    ge-0/0/0    2  Up           27       2c21.72e5.1eb1\n"
	adjs2 := adjsFromOutput7430(t, out2)
	if len(adjs2) != 1 || adjs2[0].Malformed {
		t.Fatalf("a spaced hostname must stay well-formed (#6590): %+v", adjs2)
	}
	if adjs2[0].SystemID != "peer with spaces" || adjs2[0].State != "Up" {
		t.Errorf("right-anchored parse regressed: %+v", adjs2[0])
	}
}
