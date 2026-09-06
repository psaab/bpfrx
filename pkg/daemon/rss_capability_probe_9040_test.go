package daemon

import (
	"errors"
	"strings"
	"testing"
)

// A default (round-robin) table for an 8-queue NIC, in the shape `ethtool -x`
// prints. The driver name in the header is deliberately NOT mlx5: the header
// text must not be what decides eligibility.
const defaultTable8q9040 = `RX flow hash indirection table for i40e0 with 8 RX ring(s):
    0:      0     1     2     3     4     5     6     7
    8:      0     1     2     3     4     5     6     7
`

// #9040: a NIC with more RX queues than workers had its RSS indirection table
// left at the default, so traffic hashed to queues no AF_XDP worker binds was
// silently dropped. The clamp itself was never the gap — `computeWeightVector`
// has always been driver-generic — the gap was one level up, where
// `applyRSSIndirection` matched on `driver == mlx5_core` and skipped everything
// else, so the generic clamp was never reached for a non-mlx5 NIC.
//
// FAIL-ON-REVERT: restore a `driver != mlx5Driver { return }` gate and this
// goes red with zero writes.
func TestNonMlx5WithReadableTableIsReshaped9040(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"i40e0": "i40e"},
		queues:   map[string]int{"i40e0": 8},
		ethtoolX: map[string][]byte{"i40e0": []byte(defaultTable8q9040)},
	}

	applyRSSIndirectionOne("i40e0", 4, f)

	var weightWrite []string
	for _, c := range f.calls {
		if len(c) > 2 && c[0] == "-X" && c[2] == "weight" {
			weightWrite = c
		}
	}
	if weightWrite == nil {
		t.Fatalf("an i40e NIC with 8 queues and 4 workers was not reshaped — "+
			"traffic hashed to queues 4..7 has no worker bound and is dropped; calls=%v", f.calls)
	}
	// The weights must actually concentrate onto the bound set. An assertion
	// that merely checked "a weight vector was written" would pass a vector
	// that feeds every queue, which is the defect with extra steps.
	tail := strings.Join(weightWrite[3+4:], " ")
	if !strings.Contains(tail, "0") {
		t.Errorf("weights %v do not zero any unbound queue", weightWrite)
	}
}

// The other half of the same contract, and the reason this is a PROBE rather
// than simply deleting the driver gate: `ethtool -X` support varies by driver,
// this path deliberately swallows its errors so a regression cannot break
// interface bring-up, and a reshape that silently succeeds on some drivers and
// silently fails on others would be THE SAME CLASS OF DEFECT as the one being
// fixed, one layer up. An unreadable table is identified BEFORE the write.
func TestUnreadableTableIsNeverWritten9040(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    *fakeRSSExecutor
	}{
		{"ethtool -x errors", &fakeRSSExecutor{
			drivers: map[string]string{"virt0": "virtio_net"},
			queues:  map[string]int{"virt0": 8},
			argvErr: map[string]argvErrSpec{
				"-x virt0": {out: []byte("Operation not supported"), err: errors.New("exit status 1")},
			},
		}},
		{"ethtool -x prints no table", &fakeRSSExecutor{
			drivers:  map[string]string{"virt0": "virtio_net"},
			queues:   map[string]int{"virt0": 8},
			ethtoolX: map[string][]byte{"virt0": []byte("RSS hash key:\n00:11:22:33\n")},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applyRSSIndirectionOne("virt0", 4, tc.f)
			for _, c := range tc.f.calls {
				if len(c) > 0 && c[0] == "-X" {
					t.Fatalf("wrote to a NIC whose table could not be read: %v", c)
				}
			}
			// REFERENCE ARM: the probe must have been attempted. Otherwise
			// this passes for a build that skipped the interface entirely on
			// its driver name — the very behaviour under replacement.
			var probed bool
			for _, c := range tc.f.calls {
				if len(c) > 1 && c[0] == "-x" && c[1] == "virt0" {
					probed = true
				}
			}
			if !probed {
				t.Error("no capability probe was issued; this cell cannot tell a " +
					"capability gate from a driver gate")
			}
		})
	}
}

// The probe must run AT MOST ONCE per interface. Two of the three write sites
// need the table bytes, and the first version of this change re-read them,
// issuing two `ethtool -x` ioctls to answer one question on a path whose whole
// purpose is to avoid unnecessary NIC churn.
func TestCapabilityProbeIsIssuedAtMostOnce9040(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": []byte(staleTable6q4w)},
	}
	applyRSSIndirectionOne("eth0", 6, f)

	var probes int
	for _, c := range f.calls {
		if len(c) > 0 && c[0] == "-x" {
			probes++
		}
	}
	if probes != 1 {
		t.Errorf("want exactly 1 capability probe, got %d: %v", probes, f.calls)
	}
}

// A NIC that needs no work must still issue ZERO ethtool calls. The probe is
// lazy for this reason: this path runs on every daemon start and every
// reconcile, and an unconditional probe would add an ioctl per interface per
// reconcile for interfaces there is nothing to do about.
func TestNoWorkMeansNoProbe9040(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": mlx5Driver},
		queues:   map[string]int{"eth0": 1},
		ethtoolX: map[string][]byte{"eth0": []byte(defaultTable8q9040)},
	}
	applyRSSIndirectionOne("eth0", 1, f)
	if len(f.calls) != 0 {
		t.Errorf("single-queue NIC needs no reshape and must not be probed, got %v", f.calls)
	}
}
