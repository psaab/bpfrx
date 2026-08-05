package daemon

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// #5103: the AF_XDP worker join must happen BEFORE the RETH MAC link DOWN/UP,
// not after it.
//
// PrepareLinkCycle's contract is that no thread touches UMEM once it returns,
// so it has to precede the NIC queue/link teardown. The daemon used to call
// programRethMAC first and only join workers afterwards, once it saw
// linkCycled=true — its own comment conceded the workers "may have been
// accessing UMEM during the DOWN/UP". A same-plan apply with defer_workers does
// not stop already-running workers, so the barrier really did land after the
// transition.
//
// The join cannot simply be hoisted above programRethMAC: whether a cycle is
// needed at all is only knowable by ATTEMPTING the live MAC set, and joining
// workers unconditionally would pay a forwarding outage on every apply for the
// drivers (mlx5, virtio) that support IFF_LIVE_ADDR_CHANGE and need no cycle.
// So the join is a hook invoked on the fallback path only, after the live set
// has failed and before the first mutation.

// recordingRethOps is a fake netlink seam that records the ORDER of the link
// operations, so the test asserts a sequence rather than a set.
type recordingRethOps struct {
	events   *[]string
	liveFail bool // reject the live (link-UP) setHardwareAddr, forcing a cycle
	link     netlink.Link
}

func newRecordingRethOps(t *testing.T, events *[]string, curMAC net.HardwareAddr, liveFail bool) rethLinkOps {
	t.Helper()
	la := netlink.NewLinkAttrs()
	la.Name = "ge-0-0-1"
	la.HardwareAddr = curMAC
	link := &netlink.Device{LinkAttrs: la}
	r := &recordingRethOps{events: events, liveFail: liveFail, link: link}
	return rethLinkOps{
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		byName:     func(string) (netlink.Link, error) { return r.link, nil },
		byIndex:    func(int) (netlink.Link, error) { return r.link, nil },
		setDown: func(netlink.Link) error {
			*r.events = append(*r.events, "link-down")
			return nil
		},
		setUp: func(netlink.Link) error {
			*r.events = append(*r.events, "link-up")
			return nil
		},
		setName: func(netlink.Link, string) error { return nil },
		setHardwareAddr: func(_ netlink.Link, _ net.HardwareAddr) error {
			// The live attempt is the one made while the link is still UP,
			// i.e. before any link-down has been recorded.
			live := true
			for _, e := range *r.events {
				if e == "link-down" {
					live = false
				}
			}
			if live {
				*r.events = append(*r.events, "set-mac-live")
				if r.liveFail {
					return errors.New("EBUSY: device busy (no IFF_LIVE_ADDR_CHANGE)")
				}
				return nil
			}
			*r.events = append(*r.events, "set-mac-cycled")
			return nil
		},
	}
}

func withRethOps(t *testing.T, ops rethLinkOps) {
	t.Helper()
	saved := rethLinkOpsFn
	rethLinkOpsFn = ops
	t.Cleanup(func() { rethLinkOpsFn = saved })
}

var (
	curMAC5103  = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	virtMAC5103 = net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x01, 0x00}
)

// TestRethMACJoinsWorkersBeforeLinkCycle_5103 is the ordering guard. It asserts
// the full sequence, not just that the join happened: stop_workers must precede
// link-down, and the MAC write and link-up must follow it.
func TestRethMACJoinsWorkersBeforeLinkCycle_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))

	cycled, err := programRethMAC("ge-0-0-1", virtMAC5103, func() error {
		events = append(events, "stop_workers")
		return nil
	})
	if err != nil {
		t.Fatalf("programRethMAC: %v", err)
	}
	if !cycled {
		t.Fatalf("expected a link cycle when the live MAC set is rejected")
	}

	want := []string{"set-mac-live", "stop_workers", "link-down", "set-mac-cycled", "link-up"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("link-cycle sequence = %v, want %v.\nThe worker join must land BEFORE "+
			"link-down: once the NIC tears down its queues, a worker still touching UMEM "+
			"races the driver unmapping those pages (#5103)", events, want)
	}
}

// TestRethMACAbortsCycleWhenJoinFails_5103 is the fail-closed half. A join that
// cannot be completed leaves worker state unknown, so the link must NOT be
// cycled — and because the abort happens before the first mutation, the link is
// left exactly as it was found.
func TestRethMACAbortsCycleWhenJoinFails_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true))

	cycled, err := programRethMAC("ge-0-0-1", virtMAC5103, func() error {
		events = append(events, "stop_workers")
		return errors.New("stop_workers: helper did not respond")
	})

	if err == nil {
		t.Fatal("a failed worker join must abort the MAC program — proceeding would cycle " +
			"the link with workers possibly still touching UMEM (#5103)")
	}
	if cycled {
		t.Error("linkCycled must be false when the cycle was aborted; a true return would " +
			"drive the caller's post-cycle rebind for a cycle that never happened")
	}
	for _, e := range events {
		if e == "link-down" || e == "link-up" || e == "set-mac-cycled" {
			t.Fatalf("the link was MUTATED after the join failed (%q in %v). The abort must "+
				"happen before setDown so there is nothing to unwind", e, events)
		}
	}
	if got := strings.Join(events, ","); got != "set-mac-live,stop_workers" {
		t.Errorf("sequence = %v, want the live attempt then the failed join only", events)
	}
}

// TestRethMACNoJoinWhenLiveSetSucceeds_5103 is the over-rejection guard, and
// the reason the join is a hook rather than an unconditional pre-step. On a
// driver with IFF_LIVE_ADDR_CHANGE (mlx5, virtio — the cluster's own NICs) no
// cycle happens, so the workers must NOT be stopped: joining them here would
// impose a forwarding outage on every apply that touches a RETH MAC.
func TestRethMACNoJoinWhenLiveSetSucceeds_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, false /* live set works */))

	joined := false
	cycled, err := programRethMAC("ge-0-0-1", virtMAC5103, func() error {
		joined = true
		return nil
	})
	if err != nil {
		t.Fatalf("programRethMAC: %v", err)
	}
	if cycled {
		t.Error("no link cycle should be reported when the live MAC set succeeds")
	}
	if joined {
		t.Error("workers were joined even though no link cycle was needed — that is a " +
			"forwarding outage on every RETH MAC apply on IFF_LIVE_ADDR_CHANGE drivers")
	}
	if got := strings.Join(events, ","); got != "set-mac-live" {
		t.Errorf("sequence = %v, want just the successful live set", events)
	}
}

// TestRethMACNoJoinWhenMACAlreadyCorrect_5103 pins the early return: a member
// already carrying its virtual MAC needs neither a cycle nor a join, which is
// the steady-state case on every re-apply.
func TestRethMACNoJoinWhenMACAlreadyCorrect_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, virtMAC5103, true))

	joined := false
	cycled, err := programRethMAC("ge-0-0-1", virtMAC5103, func() error {
		joined = true
		return nil
	})
	if err != nil {
		t.Fatalf("programRethMAC: %v", err)
	}
	if cycled || joined || len(events) != 0 {
		t.Errorf("a member already on its virtual MAC must be a no-op; cycled=%v joined=%v "+
			"events=%v", cycled, joined, events)
	}
}

// TestRethMACNilBeforeCycleStillCycles_5103 covers the caller with no dataplane
// attached: a nil hook means "no join needed", not "abort".
func TestRethMACNilBeforeCycleStillCycles_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true))

	cycled, err := programRethMAC("ge-0-0-1", virtMAC5103, nil)
	if err != nil {
		t.Fatalf("programRethMAC with a nil hook: %v", err)
	}
	if !cycled {
		t.Error("a nil hook must not suppress the cycle")
	}
	if got := strings.Join(events, ","); got != "set-mac-live,link-down,set-mac-cycled,link-up" {
		t.Errorf("sequence = %v", events)
	}
}
