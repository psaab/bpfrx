package grpcapi

import (
	"math"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// clampTotalsDP reports session counts large enough that their sum overflows
// int32. It embeds *dataplane.Manager for everything setSessionsTotal does not
// touch on the no-filter path.
type clampTotalsDP struct {
	*dataplane.Manager
	v4 int
	v6 int
}

func (d *clampTotalsDP) IsLoaded() bool           { return true }
func (d *clampTotalsDP) SessionCount() (int, int) { return d.v4, d.v6 }

// #5250 (A8-b2 F3). setSessionsTotal wrote `int32(v4 + v6)` with no clamp, so a
// sum past MaxInt32 WRAPPED — the operator-facing "Total sessions" went
// NEGATIVE. clampInt32 (server_nat.go, added by #2282 for exactly this class on
// the NAT port-pool size) sat unused one file over. Reverting either call site
// to a bare int32() conversion makes this test RED with a negative Total.
func TestSessionsTotalSaturatesInsteadOfWrapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		v4, v6 int
		want   int32
	}{
		{"sum below the ceiling is exact", 1000, 2000, 3000},
		{"sum exactly at the ceiling", math.MaxInt32, 0, math.MaxInt32},
		{"sum one past the ceiling saturates", math.MaxInt32, 1, math.MaxInt32},
		{"each half under, sum far over", math.MaxInt32 - 5, 1000, math.MaxInt32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{dp: &clampTotalsDP{v4: tc.v4, v6: tc.v6}}
			resp := &pb.GetSessionsResponse{}
			if err := s.setSessionsTotal(resp, &sessionFilter{}); err != nil {
				t.Fatalf("setSessionsTotal() error = %v", err)
			}
			if resp.Total < 0 {
				t.Fatalf("Total = %d — a session count wrapped NEGATIVE; the int32 "+
					"conversion is unclamped again", resp.Total)
			}
			if resp.Total != tc.want {
				t.Fatalf("Total = %d, want %d", resp.Total, tc.want)
			}
		})
	}
}

// The NAT session counters accumulate in int64 and clamp at the protobuf
// boundary for the same reason.
func TestNATSessionCountsClampAtTheWire(t *testing.T) {
	if got := clampInt32(int64(math.MaxInt32) + 1); got != math.MaxInt32 {
		t.Fatalf("clampInt32(MaxInt32+1) = %d, want MaxInt32", got)
	}
	var counts natSessionCounts
	counts.total = int64(math.MaxInt32) + 100
	if got := clampInt32(counts.total); got < 0 {
		t.Fatalf("natSessionCounts.total clamped to %d — it must saturate, not wrap", got)
	}
	// The field must be wide enough to HOLD the over-range value in the first
	// place: an int32 field would have wrapped at increment time, before any
	// clamp could see it.
	if counts.total <= math.MaxInt32 {
		t.Fatalf("natSessionCounts.total narrowed to %d — the accumulator must be int64", counts.total)
	}
}
