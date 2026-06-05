package api

import (
	"math"
	"testing"
)

// #1772: pin the Go-side bucket conversion that turns the dataplane's
// NON-cumulative pow2-ns sample counts into the cumulative seconds-`le`
// map a Prometheus histogram requires. The boundaries MUST mirror the
// Rust `neigh_latency_bucket_upper_ns` (bucket i upper bound 2^(16+i) ns)
// exactly, or the histogram `le` labels drift from where samples landed.

func TestNeighLatencyBucketUpperSecondsMirrorsRust(t *testing.T) {
	// Bucket i (0..=14) upper bound is 2^(16+i) ns, expressed in seconds.
	cases := []struct {
		idx    int
		wantNs uint64
	}{
		{0, 1 << 16},  // 65536 ns
		{7, 1 << 23},  // 8.4 ms
		{13, 1 << 29}, // 537 ms
		{14, 1 << 30}, // 1.07 s — last finite bucket
	}
	for _, c := range cases {
		got := neighLatencyBucketUpperSeconds(c.idx)
		want := float64(c.wantNs) / 1e9
		if math.Abs(got-want) > 1e-12 {
			t.Errorf("bucket %d: got %g s, want %g s", c.idx, got, want)
		}
	}
}

func TestNeighLatencyCumulativeBucketsAccumulates(t *testing.T) {
	// Non-cumulative per-bucket counts: 3 in bucket 0, 2 in bucket 1,
	// 5 in bucket 14 (last finite). The 16th (+Inf) bucket is implicit.
	raw := make([]uint64, neighLatencyBucketCount)
	raw[0] = 3
	raw[1] = 2
	raw[14] = 5

	got := neighLatencyCumulativeBuckets(raw)

	// Only the 15 finite buckets get an explicit `le`.
	if len(got) != neighLatencyBucketCount-1 {
		t.Fatalf("expected %d finite le-buckets, got %d", neighLatencyBucketCount-1, len(got))
	}
	// Cumulative: le(2^16)=3, le(2^17)=5, ... le(2^30)=10.
	mustBucket := func(idx int, want uint64) {
		le := neighLatencyBucketUpperSeconds(idx)
		if got[le] != want {
			t.Errorf("cumulative le=%g (bucket %d): got %d, want %d", le, idx, got[le], want)
		}
	}
	mustBucket(0, 3)
	mustBucket(1, 5)
	mustBucket(13, 5)  // nothing added between bucket 1 and 13
	mustBucket(14, 10) // + the 5 in bucket 14
}

// A 3 s dwell lands in the +Inf saturate bucket on the Rust side (index
// 15), which is NOT an explicit `le` boundary — so a sample there must
// NOT inflate any finite `le` bucket; it shows up only via the histogram
// total count. Model that here: a saturate-tail sample (slot 15) leaves
// every finite cumulative bucket at its pre-tail value.
func TestNeighLatencyCumulativeBucketsExcludesSaturateTail(t *testing.T) {
	raw := make([]uint64, neighLatencyBucketCount)
	raw[15] = 7 // 7 multi-second (>=1.07 s) samples — the 3 s blackout class

	got := neighLatencyCumulativeBuckets(raw)
	for idx := 0; idx < neighLatencyBucketCount-1; idx++ {
		le := neighLatencyBucketUpperSeconds(idx)
		if got[le] != 0 {
			t.Errorf("saturate-tail samples must not enter finite le=%g: got %d", le, got[le])
		}
	}
}

// Defensive: a short/empty slice from an older peer (no buckets sent)
// must yield all-zero finite buckets, never panic or index out of range.
func TestNeighLatencyCumulativeBucketsShortSlice(t *testing.T) {
	for _, raw := range [][]uint64{nil, {}, {1, 2}} {
		got := neighLatencyCumulativeBuckets(raw)
		if len(got) != neighLatencyBucketCount-1 {
			t.Fatalf("short slice %v: expected %d le-buckets, got %d", raw, neighLatencyBucketCount-1, len(got))
		}
		// Cumulative counts never exceed what the (short) slice carried.
		var total uint64
		for _, v := range raw {
			total += v
		}
		top := got[neighLatencyBucketUpperSeconds(neighLatencyBucketCount-2)]
		if top != total {
			t.Errorf("short slice %v: top cumulative %d, want %d", raw, top, total)
		}
	}
}
