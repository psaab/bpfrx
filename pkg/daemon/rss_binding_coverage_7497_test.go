package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #7497 blocker 7: RSS must never steer traffic to a queue with no AF_XDP
// binding, and must not starve one that has a binding.
//
// The planner binds `min(rx_queues, BindingQueuesPerIface)` queues per
// interface. `computeWeightVector` decided the fed set from `workers` and the
// HARDWARE queue count, so on a NIC with more RX queues than the stride the two
// sets diverged and queues with no socket received traffic — which the shim
// drops as BINDING_MISSING while the interface reads up.
//
// Two of the failing cases never reached vector construction. `workers=20,
// hwq=20` took the `workers >= queues` skip and `workers=1, hwq=32` took the
// single-worker skip, so a fix that bounded only the vector would have left
// both wrong with a green suite. They are fixture rows for that reason.
func TestRSSFedSetNeverExceedsBoundQueues7497(t *testing.T) {
	stride := int(dataplane.BindingQueuesPerIface)

	cases := []struct {
		name     string
		workers  int
		hwQueues int
		wantFed  int  // queues that end up receiving traffic
		wantSkip bool // nil vector => default round-robin over ALL hw queues
	}{
		// Unchanged: fed < bound is the deliberate 1:1 worker:queue
		// concentration from #785. Bound-but-idle queues are a separate
		// (efficiency) question, not this one.
		{"concentrate-8-of-32", 8, 32, 8, false},
		{"concentrate-2-of-6", 2, 6, 2, false},
		{"concentrate-4-of-6", 4, 6, 4, false},

		// Everything bound and worker-served: the default table is already
		// exactly right, so skipping is correct.
		{"all-bound-all-served", 6, 6, 6, true},

		// FIXED — vector path: workers exceeded the stride, so the fed set
		// spilled past the last bound queue.
		{"workers-past-stride-32q", 20, 32, stride, false},
		{"workers-just-past-stride", 17, 32, stride, false},

		// FIXED — SKIP path. This is the row that makes the fix about the skip
		// condition and not only the vector: `workers >= queues` was true, so
		// the default table fed all 20 hardware queues while only 16 were
		// bound. If this row is absent, reverting the skip condition changes
		// nothing observable.
		{"skip-path-hwq-past-stride", 20, 20, stride, false},

		// FIXED — single-worker path. #5124 keeps the spread (no serializing on
		// one IRQ) but it must be a spread over BOUND queues.
		{"single-worker-past-stride", 1, 32, stride, false},

		// Single worker, everything bound: still skips, #5124 intent intact.
		{"single-worker-all-bound", 1, 6, 6, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			v, reason := computeWeightVector(tc.workers, tc.hwQueues)

			bound := tc.hwQueues
			if bound > stride {
				bound = stride
			}

			fed := 0
			if v == nil {
				// A skip leaves the kernel's round-robin default in place,
				// which feeds every HARDWARE queue — not every bound one.
				fed = tc.hwQueues
			} else {
				if len(v) != tc.hwQueues {
					t.Fatalf("vector length %d, want one entry per hw queue (%d)", len(v), tc.hwQueues)
				}
				for _, w := range v {
					if w > 0 {
						fed++
					}
				}
				// The fed queues must be a PREFIX. A vector feeding a
				// high-numbered queue would satisfy a count-only assertion
				// while steering to a queue the planner never binds.
				for i := 0; i < len(v); i++ {
					want := 0
					if i < fed {
						want = 1
					}
					if v[i] != want {
						t.Fatalf("vector %v is not the prefix [1]*%d", v, fed)
					}
				}
			}

			if (v == nil) != tc.wantSkip {
				t.Fatalf("skip=%v, want %v (reason=%q)", v == nil, tc.wantSkip, reason)
			}
			if fed != tc.wantFed {
				t.Fatalf("fed %d queues, want %d (bound=%d, reason=%q)", fed, tc.wantFed, bound, reason)
			}

			// The invariant the whole change exists for. Stated separately from
			// the per-row expectation so it still holds if a future row is
			// added with a wrong wantFed.
			if fed > bound {
				t.Fatalf("RSS feeds %d queues but only %d are bound — queues %d..%d "+
					"receive traffic with no AF_XDP socket and the shim drops it as "+
					"BINDING_MISSING (#7497)", fed, bound, bound, fed-1)
			}
		})
	}
}

// The invariant over a swept range rather than hand-picked rows: for every
// plausible (workers, hwQueues), the fed set must fit inside the bound set.
//
// The table above names the cases that were wrong; this catches a future
// combination nobody thought to enumerate.
func TestRSSFedSetFitsBoundQueuesAcrossRange7497(t *testing.T) {
	stride := int(dataplane.BindingQueuesPerIface)
	for workers := 1; workers <= 40; workers++ {
		for hwq := 1; hwq <= 40; hwq++ {
			v, _ := computeWeightVector(workers, hwq)
			bound := hwq
			if bound > stride {
				bound = stride
			}
			fed := hwq
			if v != nil {
				fed = 0
				for _, w := range v {
					if w > 0 {
						fed++
					}
				}
			}
			if fed > bound {
				t.Fatalf("workers=%d hwq=%d: RSS feeds %d queues, only %d bound",
					workers, hwq, fed, bound)
			}
			// Non-vacuity: a vector of all zeros would satisfy the bound above
			// while starving every queue. At least one queue must be fed.
			if fed == 0 {
				t.Fatalf("workers=%d hwq=%d: no queue is fed at all", workers, hwq)
			}
		}
	}
}
