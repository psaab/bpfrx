// #5034 (C175-HC-073 remainder): a FILTERED GetSessions must return the
// REAL count of filter-matching (forward-only) sessions in Total, not the
// legacy -1 sentinel. PR #5033 only papered over the sentinel in the CLI
// (falling back to len(Sessions), which undercounts once the peer result is
// capped). The fix computes a real filtered total server-side via a
// count-only scan in setSessionsTotal, so any consumer — including a
// cluster peer's session detail — gets a meaningful "Total sessions".
//
// FAIL-ON-REVERT: restoring the `if f.hasFilters { resp.Total = -1 }`
// sentinel in setSessionsTotal makes the cursor-path assertions here go RED
// (want a positive count, got -1).
package grpcapi

import (
	"context"
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// filteredTotalDP is a session-store fake carrying a fixed set of v4/v6
// sessions. It satisfies both the legacy iterators (IterateSessions*) used
// by setSessionsTotal's count-only scan and the cursor iterators
// (IterateSessions*From) used by getSessionsCursor's page walk, so the same
// fake exercises both GetSessions paths.
type filteredTotalDP struct {
	*dataplane.Manager
	v4 []v4Session
	v6 []v6Session
}

type v4Session struct {
	key dataplane.SessionKey
	val dataplane.SessionValue
}

type v6Session struct {
	key dataplane.SessionKeyV6
	val dataplane.SessionValueV6
}

func (d *filteredTotalDP) IsLoaded() bool { return true }

func (d *filteredTotalDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for _, s := range d.v4 {
		if !fn(s.key, s.val) {
			return nil
		}
	}
	return nil
}

func (d *filteredTotalDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for _, s := range d.v6 {
		if !fn(s.key, s.val) {
			return nil
		}
	}
	return nil
}

// Cursor iterators: ignore the resume cursor (the fake set is tiny and
// single-page) but honor the early-stop return so a full page halts.
func (d *filteredTotalDP) IterateSessionsFrom(_ *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return d.IterateSessions(fn)
}

func (d *filteredTotalDP) IterateSessionsV6From(_ *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return d.IterateSessionsV6(fn)
}

// Reverse-entry merge is disabled by erroring the point lookups — the count
// path never calls these, and the page path tolerates the error (skips the
// merge).
func (d *filteredTotalDP) GetSessionV4(dataplane.SessionKey) (dataplane.SessionValue, error) {
	return dataplane.SessionValue{}, errors.New("no reverse entry in test")
}

func (d *filteredTotalDP) GetSessionV6(dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	return dataplane.SessionValueV6{}, errors.New("no reverse entry in test")
}

// SessionCount reports forward-only entries, matching the production map
// walk (IsReverse == 0). Used for the unfiltered total.
func (d *filteredTotalDP) SessionCount() (v4, v6 int) {
	for _, s := range d.v4 {
		if s.val.IsReverse == 0 {
			v4++
		}
	}
	for _, s := range d.v6 {
		if s.val.IsReverse == 0 {
			v6++
		}
	}
	return
}

// newFilteredTotalDP builds a fake with a known mix: 3 forward TCP + 2
// forward UDP + 1 REVERSE TCP over v4, and 1 forward TCP over v6.
//
//	forward TCP: 3 (v4) + 1 (v6) = 4  -> the filtered (proto=tcp) total
//	forward all: 5 (v4) + 1 (v6) = 6  -> the unfiltered total
//
// The reverse TCP entry must be excluded from both (forward-only counting).
func newFilteredTotalDP() *filteredTotalDP {
	tcp := func(srcLast byte, reverse uint8) v4Session {
		return v4Session{
			key: dataplane.SessionKey{
				SrcIP:    [4]byte{10, 0, 1, srcLast},
				DstIP:    [4]byte{172, 16, 80, 8},
				SrcPort:  hostToNetwork16(40000 + uint16(srcLast)),
				DstPort:  hostToNetwork16(443),
				Protocol: 6,
			},
			val: dataplane.SessionValue{IsReverse: reverse},
		}
	}
	udp := func(srcLast byte) v4Session {
		return v4Session{
			key: dataplane.SessionKey{
				SrcIP:    [4]byte{10, 0, 1, srcLast},
				DstIP:    [4]byte{172, 16, 80, 8},
				SrcPort:  hostToNetwork16(50000 + uint16(srcLast)),
				DstPort:  hostToNetwork16(53),
				Protocol: 17,
			},
		}
	}
	v6tcp := v6Session{
		key: dataplane.SessionKeyV6{
			SrcIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10},
			DstIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08},
			SrcPort:  hostToNetwork16(41000),
			DstPort:  hostToNetwork16(443),
			Protocol: 6,
		},
	}
	return &filteredTotalDP{
		Manager: dataplane.New(),
		v4: []v4Session{
			tcp(11, 0), tcp(12, 0), tcp(13, 0), // 3 forward TCP
			udp(21), udp(22), // 2 forward UDP
			tcp(14, 1), // 1 REVERSE TCP — must NOT be counted
		},
		v6: []v6Session{v6tcp}, // 1 forward TCP (v6)
	}
}

// TestGetSessionsFilteredTotalRealCount pins the #5034 server behavior: a
// filtered GetSessions returns the exact forward-only match count in Total,
// on BOTH the cursor and legacy paths, and never the -1 sentinel.
func TestGetSessionsFilteredTotalRealCount(t *testing.T) {
	s := newViewServer(t, newFilteredTotalDP())
	ctx := context.Background()

	// --- Cursor path (PageSize > 0) — where the -1 sentinel used to live.
	cursor, err := s.GetSessions(ctx, &pb.GetSessionsRequest{Protocol: "tcp", PageSize: 100})
	if err != nil {
		t.Fatalf("cursor GetSessions(proto=tcp) error = %v", err)
	}
	if cursor.Total == -1 {
		t.Fatal("cursor filtered Total = -1 sentinel (regressed to pre-#5034)")
	}
	if cursor.Total != 4 {
		t.Fatalf("cursor filtered Total = %d, want 4 (3 v4 + 1 v6 forward TCP; reverse excluded)", cursor.Total)
	}
	if len(cursor.Sessions) != 4 {
		t.Fatalf("cursor returned %d sessions, want 4", len(cursor.Sessions))
	}

	// --- Legacy path (PageSize == 0) — must agree with the cursor total.
	legacy, err := s.GetSessions(ctx, &pb.GetSessionsRequest{Protocol: "tcp"})
	if err != nil {
		t.Fatalf("legacy GetSessions(proto=tcp) error = %v", err)
	}
	if legacy.Total != 4 {
		t.Fatalf("legacy filtered Total = %d, want 4", legacy.Total)
	}

	// --- UDP filter: exactly the 2 forward UDP sessions.
	udp, err := s.GetSessions(ctx, &pb.GetSessionsRequest{Protocol: "udp", PageSize: 100})
	if err != nil {
		t.Fatalf("cursor GetSessions(proto=udp) error = %v", err)
	}
	if udp.Total != 2 {
		t.Fatalf("cursor filtered Total(udp) = %d, want 2", udp.Total)
	}

	// --- Unfiltered still uses the lightweight forward-only SessionCount.
	all, err := s.GetSessions(ctx, &pb.GetSessionsRequest{PageSize: 100})
	if err != nil {
		t.Fatalf("cursor GetSessions(unfiltered) error = %v", err)
	}
	if all.Total != 6 {
		t.Fatalf("cursor unfiltered Total = %d, want 6 (5 v4 + 1 v6 forward)", all.Total)
	}
}
