package userspace

import (
	"reflect"
	"testing"
	"time"
)

// appPortSpecCeilingCorpus is the set of specs whose HIGH bound is the u16
// ceiling AND whose width is greater than 1, so each one enters the range
// EXPANSION arm rather than the exact-port arm.
//
// These deliberately do NOT live in appPortSpecCorpus, even though the agreement
// they are checked for below is the same one that corpus drives. A wrap is
// non-termination, not a wrong answer: an implementation that counts in uint16
// would make the shared corpus test HANG the whole package until the go test
// timeout, surfacing as a timeout panic in whichever test happened to be running
// rather than as a named failure. Keeping the ceiling specs behind the watchdog
// below buys the same coverage without putting that hazard into a test that has
// no deadline of its own.
var appPortSpecCeilingCorpus = []string{
	"65534-65535", "65530-65535",
}

// #6783. A port-expansion helper that uses the parse's uint16 bounds directly as
// its ascending loop counter cannot terminate when the high bound is 65535:
// after the final iteration the counter wraps to 0, `p <= hi` is true again, and
// the loop appends forever until the process is OOM-killed. `pkg/dataplane`
// carried exactly that helper; #6783 removed it, its last production caller
// having gone away in ad31711e3. The helpers in THIS package parse into uint64
// and are total — a property nothing asserted, because the existing corpus holds
// "65535" (exact port: never enters the expansion arm) and "1-65535" (enters it,
// but a wrap there reads as a hung suite).
//
// The goroutine cannot be reaped on the failure path: a wrapped loop is not
// interruptible, and a context it does not check would not stop it. It therefore
// leaks — appending into an ever-growing slice — until the process exits. That
// hazard is NOT introduced here: appPortSpecCorpus already contains "1-65535"
// and "0-65535", so a wrapped implementation already runs a leaking expansion for
// the whole go test timeout. The short window below strictly SHORTENS it, and is
// several orders of magnitude above the microseconds a correct expansion needs,
// so it cannot flake on a loaded machine. Two cells rather than five for the same
// reason: each additional ceiling spec is another leaked goroutine, and they
// prove the same thing.
const watchdogWindow = 3 * time.Second

func TestPortExpansionTerminatesAtTheU16Ceiling6783(t *testing.T) {
	for _, spec := range appPortSpecCeilingCorpus {
		t.Run(spec, func(t *testing.T) {
			lo, hi, ok := appPortSpecBounds(spec)
			if !ok {
				t.Fatalf("appPortSpecBounds(%q) reported no bounds; the fixture "+
					"never reaches the expansion arm it exists to exercise", spec)
			}
			if hi != 65535 || hi <= lo {
				t.Fatalf("fixture %q has bounds [%d,%d]; a ceiling cell must have "+
					"high == 65535 AND width > 1 or it cannot detect a wrap",
					spec, lo, hi)
			}

			type result struct {
				ports  []int
				ranges []NatPortRangeWire
			}
			done := make(chan result, 1)
			go func() {
				ports := appPortsFromSpec(spec)
				done <- result{ports: ports, ranges: coalescePortRanges(ports)}
			}()

			var got result
			select {
			case got = <-done:
			case <-time.After(watchdogWindow):
				t.Fatalf("appPortsFromSpec(%q) did not terminate: the expansion "+
					"loop is counting in uint16 and wrapped past the 65535 "+
					"ceiling (#6783)", spec)
			}

			if want := int(hi-lo) + 1; len(got.ports) != want {
				t.Fatalf("appPortsFromSpec(%q) produced %d ports, want %d",
					spec, len(got.ports), want)
			}
			if last := got.ports[len(got.ports)-1]; last != 65535 {
				t.Fatalf("appPortsFromSpec(%q) ended at port %d, want 65535 — the "+
					"expansion stopped short of the ceiling", spec, last)
			}

			// The same agreement appPortSpecCorpus drives, run at the ceiling:
			// the live no-materialize path must equal the coalesced expansion.
			if ranges := appPortRangesFromSpec(spec); !reflect.DeepEqual(ranges, got.ranges) {
				t.Fatalf("appPortRangesFromSpec(%q) = %v, coalescePortRanges("+
					"appPortsFromSpec(%q)) = %v", spec, ranges, spec, got.ranges)
			}
		})
	}
}
