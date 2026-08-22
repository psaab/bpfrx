package frr

import (
	"testing"
)

// #6590 — a peer-advertised IS-IS hostname containing SPACES must not shift the
// columns of `show isis neighbor`.
//
// The first column is not a system ID: FRR substitutes the hostname the peer
// advertised in its Dynamic Hostname TLV (RFC 5301, `hostname dynamic`, on by
// default), and it retains printable ASCII spaces when decoding that TLV. The
// old parser assigned tokens to columns POSITIONALLY with strings.Fields, so a
// hostname with N spaces moved every later column N places right and filled
// State/Level/Interface/HoldTime with peer-chosen bytes.
//
// This is NOT the #6468 escape-injection class and #6579's sanitiser cannot fix
// it. Sanitising keeps a row SAFE TO PRINT while preserving plausible printable
// text, so a sanitised row can still be materially false — an operator reading
// `show isis adjacency` to decide whether a neighbour is healthy can be shown a
// `State` the neighbour chose. Display integrity is a parser property.
//
// The fix is right-anchored parsing: only the first column can contain a space,
// so the trailing columns are taken from the END and the hostname absorbs the
// surplus. The trailing width is learned from the header rather than hardcoded
// (note "System Id" is one column spelled with a space).

// isisMgr6590 builds a Manager whose vtysh returns out for `show isis neighbor`,
// reusing the package's existing fakeExecutor seam rather than adding a second
// double.
func isisMgr6590(out string) *Manager {
	return NewForTest("", &fakeExecutor{
		vtyshResp: map[string]string{"show isis neighbor": out},
	})
}

// isisTable6590 builds a `show isis neighbor` table with the real FRR header.
func isisTable6590(rows ...string) string {
	out := "Area 1:\n" +
		" System Id           Interface   L  State        Holdtime SNPA\n"
	for _, r := range rows {
		out += " " + r + "\n"
	}
	return out
}

// TestISISHostnameWithSpacesCannotForgeColumns6590 is the fail-on-revert case.
//
// FAIL-ON-REVERT: restore the left-anchored fields[0..4] assignment.
func TestISISHostnameWithSpacesCannotForgeColumns6590(t *testing.T) {
	// The attack from the issue: the peer advertises a hostname whose spaces
	// spell out a complete, plausible set of trailing columns. Positionally
	// parsed, the operator sees Interface=peer, Level=ge-0-0-1, State=2,
	// HoldTime=Up — every displayed cell chosen by the neighbour.
	m := isisMgr6590(isisTable6590(
		"evil peer ge-0-0-1 2 Up 27 ge-0-0-9 1 Down 99 dead.dead.dead",
	))

	adjs, err := m.GetISISAdjacency()
	if err != nil {
		t.Fatalf("GetISISAdjacency: %v", err)
	}
	if len(adjs) != 1 {
		t.Fatalf("want 1 adjacency, got %d: %+v", len(adjs), adjs)
	}
	got := adjs[0]

	// The REAL trailing columns are the last five tokens; everything before
	// them is the hostname, spaces and all.
	if got.Interface != "ge-0-0-9" {
		t.Errorf("#6590: Interface is peer-forged: got %q, want %q — the hostname's "+
			"spaces shifted the columns", got.Interface, "ge-0-0-9")
	}
	if got.Level != "1" {
		t.Errorf("#6590: Level is peer-forged: got %q, want %q", got.Level, "1")
	}
	if got.State != "Down" {
		t.Errorf("#6590: State is peer-forged: got %q, want %q — an operator deciding "+
			"whether this neighbour is healthy would be reading a value the neighbour "+
			"chose", got.State, "Down")
	}
	if got.HoldTime != "99" {
		t.Errorf("#6590: HoldTime is peer-forged: got %q, want %q", got.HoldTime, "99")
	}

	// And the hostname keeps everything it actually claimed, so the operator
	// can SEE that the name is absurd rather than having it silently
	// redistributed into the other cells.
	const wantName = "evil peer ge-0-0-1 2 Up 27"
	if got.SystemID != wantName {
		t.Errorf("#6590: SystemID = %q, want %q — the surplus tokens belong to the "+
			"hostname, which is the column the peer legitimately controls",
			got.SystemID, wantName)
	}
}

// TestISISOrdinaryRowStillParses6590 is the over-correction guard: a normal row
// must be unchanged by the fix.
//
// FAIL-ON-REVERT: an off-by-one in the right-anchor split reds here.
func TestISISOrdinaryRowStillParses6590(t *testing.T) {
	m := isisMgr6590(isisTable6590(
		"rtr1                ge-0-0-1    2  Up           27       2020.2020.2020",
		"rtr2                ge-0-0-2    1  Init         9        2020.2020.2021",
	))

	adjs, err := m.GetISISAdjacency()
	if err != nil {
		t.Fatalf("GetISISAdjacency: %v", err)
	}
	if len(adjs) != 2 {
		t.Fatalf("want 2 adjacencies, got %d: %+v", len(adjs), adjs)
	}
	for i, want := range []ISISAdjacency{
		{SystemID: "rtr1", Interface: "ge-0-0-1", Level: "2", State: "Up", HoldTime: "27"},
		{SystemID: "rtr2", Interface: "ge-0-0-2", Level: "1", State: "Init", HoldTime: "9"},
	} {
		if adjs[i] != want {
			t.Errorf("row %d: got %+v, want %+v", i, adjs[i], want)
		}
	}
}

// TestISISMalformedRowsAreNotRendered6590 pins the "reported rather than
// rendered" half.
//
// A row too short to carry every trailing column cannot be split safely — any
// assignment would put peer-chosen text under a heading it does not belong to,
// which is the defect itself. Such a row is dropped, not guessed at.
//
// A table with NO header is likewise not parsed: the trailing width is unknown
// without it, and guessing the width is the same failure in a different place.
func TestISISMalformedRowsAreNotRendered6590(t *testing.T) {
	// Short row: fewer fields than the header's trailing width + 1.
	short := isisMgr6590(isisTable6590("rtr1 ge-0-0-1 2"))
	adjs, err := short.GetISISAdjacency()
	if err != nil {
		t.Fatalf("GetISISAdjacency(short): %v", err)
	}
	if len(adjs) != 0 {
		t.Errorf("#6590: a row too short to carry every trailing column must be dropped, "+
			"not split by guesswork; got %+v", adjs)
	}

	// Headerless table: width unknown.
	headerless := isisMgr6590("Area 1:\n rtr1 ge-0-0-1 2 Up 27 2020.2020.2020\n")
	adjs, err = headerless.GetISISAdjacency()
	if err != nil {
		t.Fatalf("GetISISAdjacency(headerless): %v", err)
	}
	if len(adjs) != 0 {
		t.Errorf("#6590: without the header the trailing width is unknown — parsing anyway "+
			"reintroduces the positional guess; got %+v", adjs)
	}
}

// TestISISTrailingWidthFollowsTheHeader6590 pins that the width is DERIVED.
//
// Hardcoding five trailing columns would silently mis-parse an FRR release that
// adds or drops one. Deriving it from the header means the parser follows the
// table it was actually given.
//
// FAIL-ON-REVERT: replace the header-derived width with a constant.
func TestISISTrailingWidthFollowsTheHeader6590(t *testing.T) {
	// A hypothetical FRR that drops the SNPA column: four trailing columns.
	out := "Area 1:\n" +
		" System Id           Interface   L  State        Holdtime\n" +
		" host with spaces ge-0-0-1 2 Up 27\n"

	adjs, err := isisMgr6590(out).GetISISAdjacency()
	if err != nil {
		t.Fatalf("GetISISAdjacency: %v", err)
	}
	if len(adjs) != 1 {
		t.Fatalf("want 1 adjacency, got %d: %+v", len(adjs), adjs)
	}
	want := ISISAdjacency{
		SystemID: "host with spaces", Interface: "ge-0-0-1",
		Level: "2", State: "Up", HoldTime: "27",
	}
	if adjs[0] != want {
		t.Errorf("#6590: the trailing width must follow the header, not a constant; "+
			"got %+v, want %+v", adjs[0], want)
	}
}
