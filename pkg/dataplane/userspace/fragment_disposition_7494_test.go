package userspace

import (
	"encoding/binary"
	"os"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Behavioural coverage for the non-first-fragment handling #7494 is about.
//
// WHY THIS EXISTS. Until now the shim's control flow had NO executable test
// surface at all: every test in the tree is either a source-text census in Go
// or a pure module `#[path]`-included into userspace-dp. The verifier gate
// (#1864) is a HEADROOM instrument, not a correctness one, so two distinct
// wrong implementations of the #7494 fix both PASS it:
//
//   - having `parse_ipv6` decline a fragment, which lands on
//     `drop_degraded_transit` and blackholes every legitimate fragment;
//   - hoisting the fragment guard into `if !native_gre && !frag`, which routes
//     non-native-GRE fragments into the native-GRE inner classifier.
//
// Neither is distinguishable from a correct fix by anything that existed
// before this file. These cells run the REAL program via BPF_PROG_TEST_RUN
// against synthetic frames and read back the disposition.
//
// ROOT. Loading a BPF program needs privilege, so these skip unprivileged.
// `make test-go` therefore does NOT run them -- `make test-shim-run` does.
// A skip is a result that looks exactly like a pass, so the skip message says
// so, and the instrument-validation cells below exist to keep a green run from
// being mistaken for a covered one.
//
// READING THE DISPOSITION. The XDP return code alone is NOT a discriminator:
// the xsk map is empty here, so a successful redirect falls back and returns
// XDP_PASS just like several other paths. The per-CPU `userspace_fallback_stats`
// reason counters are what separate them:
//
//	REDIRECT_ERR  reached the XSK redirect -- i.e. handed to the userspace
//	              helper, which is the CORRECT disposition for a fragment
//	PASS_TO_KERNEL  diverted to the kernel by a session-table hit
//	PARSE_FAIL      dropped by drop_degraded_transit
//
// Note that the ingress-iface gate returns XDP_PASS with NO counter at all, so
// "no reasons" is ambiguous between "clean redirect" and "rejected at the iface
// gate". That ambiguity produced a false negative during development -- the
// session-collision cell reported the exposure as unreachable when in fact the
// packet had never reached the session lookup. spikeLoad maps a range of
// ifindexes precisely so that gate is never the variable under test.

const (
	fragMetaVersion = 4
	fragSlot        = 0
	fragIfaceRange  = 64
)

var fragReasons = map[int]string{
	0: "CTRL_DISABLED", 1: "PARSE_FAIL", 2: "BINDING_MISSING", 3: "BINDING_NOT_READY",
	4: "HEARTBEAT_MISSING", 5: "HEARTBEAT_STALE", 6: "ICMP", 7: "EARLY_FILTER",
	8: "ADJUST_META", 9: "META_BOUNDS", 10: "REDIRECT_ERR", 11: "INTERFACE_NAT_NO_SESSION",
	12: "NO_SESSION", 13: "STRICT_DROP", 14: "PASS_TO_KERNEL", 15: "TRANSIT_DROP",
}

type fragSessionKey struct {
	AddrFamily uint8
	Protocol   uint8
	Pad        uint16
	SrcPort    uint16
	DstPort    uint16
	SrcAddr    [16]byte
	DstAddr    [16]byte
}

func fragLoad(t *testing.T) *ebpf.Collection {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("SKIPPED, NOT PASSED: loading a BPF program needs root. " +
			"`make test-go` never runs this file; use `make test-shim-run`. " +
			"A green `make test-go` is NOT evidence that fragment handling is covered.")
	}
	spec, err := ebpf.LoadCollectionSpec("../userspace_xdp_bpfel.o")
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load collection: %v", err)
	}
	t.Cleanup(coll.Close)

	ctrl := userspaceCtrlValue{
		Enabled: 1, MetadataVersion: fragMetaVersion,
		Workers: 1, QueueCount: 1, HeartbeatTimeoutMS: 100000,
	}
	if err := coll.Maps["userspace_ctrl"].Put(uint32(0), &ctrl); err != nil {
		t.Fatalf("ctrl: %v", err)
	}
	// See the ambiguity note above: the iface gate is silent, so it must never
	// be the variable. Same for the binding gate.
	for idx := uint32(0); idx < fragIfaceRange; idx++ {
		if err := coll.Maps["userspace_ingress_ifaces"].Put(idx, uint8(1)); err != nil {
			t.Fatalf("ingress_ifaces[%d]: %v", idx, err)
		}
	}
	bv := userspaceBindingValue{Slot: fragSlot, Flags: userspaceBindingReady}
	for i := uint32(0); i < fragIfaceRange*bindingQueuesPerIface; i++ {
		if err := coll.Maps["userspace_bindings"].Put(i, &bv); err != nil {
			t.Fatalf("bindings[%d]: %v", i, err)
		}
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("clock: %v", err)
	}
	now := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	if err := coll.Maps["userspace_heartbeat"].Put(uint32(fragSlot), now); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	return coll
}

// fragStats sums the per-CPU reason counters. A lookup failure is FATAL rather
// than skipped: an empty reason set is a meaningful observation here, so it
// must not also be what a broken read produces.
func fragStats(t *testing.T, coll *ebpf.Collection) map[string]uint64 {
	t.Helper()
	m := coll.Maps["userspace_fallback_stats"]
	out := map[string]uint64{}
	for i := 0; i < len(fragReasons); i++ {
		var vals []uint64
		if err := m.Lookup(uint32(i), &vals); err != nil {
			t.Fatalf("fallback_stats lookup(%d): %v -- the instrument is dead, and "+
				"an empty reason set would be indistinguishable from a clean run", i, err)
		}
		var sum uint64
		for _, v := range vals {
			sum += v
		}
		if sum > 0 {
			out[fragReasons[i]] = sum
		}
	}
	return out
}

func fragDelta(before, after map[string]uint64) map[string]uint64 {
	d := map[string]uint64{}
	for k, v := range after {
		if x := v - before[k]; x > 0 {
			d[k] = x
		}
	}
	return d
}

// fragRun executes the real program. No Context is passed: for XDP the kernel
// derives data/data_end from Data, and a zeroed ctx_in clobbers them so the
// frame stops parsing at parse_l2 -- which returns XDP_PASS with no counter and
// is therefore invisible. That cost real debugging time; do not add one back
// without setting data/data_end.
func fragRun(t *testing.T, coll *ebpf.Collection, pkt []byte) (uint32, map[string]uint64) {
	t.Helper()
	before := fragStats(t, coll)
	ret, err := coll.Programs["xdp_userspace_prog"].Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog run: %v", err)
	}
	return ret, fragDelta(before, fragStats(t, coll))
}

// ipv4Frame builds ethernet+IPv4+TCP. fragOff is the raw flags+offset field:
// 0 = not a fragment, a non-zero OFFSET = a non-first fragment.
func ipv4Frame(fragOff uint16) []byte {
	p := make([]byte, 128)
	p[12], p[13] = 0x08, 0x00
	ip := p[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(p)-14))
	binary.BigEndian.PutUint16(ip[6:], fragOff)
	ip[8] = 64
	ip[9] = unix.IPPROTO_TCP
	copy(ip[12:16], []byte{10, 0, 1, 50})
	copy(ip[16:20], []byte{10, 0, 2, 60})
	l4 := p[34:]
	binary.BigEndian.PutUint16(l4[0:], 12345)
	binary.BigEndian.PutUint16(l4[2:], 443)
	// parse_l4 REQUIRES (byte 12 >> 4)*4 >= 20 for TCP. On a NON-FIRST fragment
	// this byte is PAYLOAD, which is what
	// TestNonFirstFragmentDispositionDependsOnPayloadBytes_7494 exploits.
	l4[12] = 0x50
	return p
}

func fragSessionKeyFor(srcPort, dstPort uint16) fragSessionKey {
	var src, dst [16]byte
	copy(src[:], []byte{10, 0, 1, 50})
	copy(dst[:], []byte{10, 0, 2, 60})
	return fragSessionKey{
		AddrFamily: 2, Protocol: unix.IPPROTO_TCP,
		SrcPort: srcPort, DstPort: dstPort, SrcAddr: src, DstAddr: dst,
	}
}

// TestFragmentHarnessInstrumentIsAlive is the known-answer control. An empty
// reason set is a legitimate observation elsewhere in this file, and it is also
// what a dead counter read produces. Driving a case whose reason is known a
// priori -- ctrl.enabled = 0 must report CTRL_DISABLED -- separates them. If
// this cell cannot produce a non-empty reason set, every other cell is VOID.
func TestFragmentHarnessInstrumentIsAlive(t *testing.T) {
	coll := fragLoad(t)
	ctrl := userspaceCtrlValue{Enabled: 0, MetadataVersion: fragMetaVersion}
	if err := coll.Maps["userspace_ctrl"].Put(uint32(0), &ctrl); err != nil {
		t.Fatalf("ctrl: %v", err)
	}
	ret, d := fragRun(t, coll, ipv4Frame(0))
	t.Logf("ctrl-disabled -> ret=%d reasons=%v", ret, d)
	if d["CTRL_DISABLED"] == 0 {
		t.Fatalf("CTRL_DISABLED did not increment (reasons=%v). The reason "+
			"counters are not observable, so an empty reason set proves nothing "+
			"and every other cell in this file is VOID rather than green", d)
	}
}

// TestFragmentSessionPlantingIsObservable is the known-positive control for
// the collision cell below. That cell plants a session and looks for a change
// in disposition; "no change" is ambiguous between "the collision is
// unreachable" and "no session would EVER match because the key layout is
// wrong". This drives the case that MUST match -- an ordinary non-fragment
// whose real ports are the planted ones.
//
// This control earned its place: it failed during development and correctly
// invalidated a "the exposure is not reachable" result that was really a
// harness defect.
func TestFragmentSessionPlantingIsObservable(t *testing.T) {
	coll := fragLoad(t)
	key := fragSessionKeyFor(12345, 443)
	if err := coll.Maps["userspace_sessions"].Put(&key, uint8(2)); err != nil {
		t.Fatalf("plant: %v", err)
	}
	ret, d := fragRun(t, coll, ipv4Frame(0)) // NOT a fragment: ports are real
	t.Logf("non-fragment + planted PASS_TO_KERNEL session -> ret=%d reasons=%v", ret, d)
	if d["PASS_TO_KERNEL"] == 0 {
		t.Fatalf("a planted session did NOT take effect on a NON-fragment whose "+
			"real ports match the key (reasons=%v). The key layout or byte order "+
			"is wrong, so a negative result from the collision cell would be VOID "+
			"rather than evidence of anything", d)
	}
}

// TestNonFirstFragmentIsAdjudicatedByPayloadKeyedSession_7494 demonstrates the
// first exposure #7494 lists: `live_userspace_session_action` is keyed on
// ports, and for a non-first fragment those "ports" are the first four bytes of
// fragment PAYLOAD. A collision with a live PASS_TO_KERNEL session hands the
// fragment to the kernel instead of the userspace helper.
//
// CHARACTERIZATION, NOT AN ENDORSEMENT. The assertions below pin the CURRENT,
// WRONG behaviour so that it cannot change unnoticed. When #7494 lands, a
// non-first fragment must reach the helper regardless of what its payload
// collides with, and this cell MUST go red -- inverting it is part of that
// change, not a fix to this test.
func TestNonFirstFragmentIsAdjudicatedByPayloadKeyedSession_7494(t *testing.T) {
	coll := fragLoad(t)
	frag := ipv4Frame(0x00b9) // offset 185 -> a NON-FIRST fragment

	retControl, dControl := fragRun(t, coll, frag)
	t.Logf("CONTROL   fragment, no session -> ret=%d reasons=%v", retControl, dControl)
	if dControl["REDIRECT_ERR"] == 0 {
		t.Fatalf("without a planted session the fragment did not reach the XSK "+
			"redirect (reasons=%v); the cell is not exercising the path it "+
			"claims to. IF #7494 HAS LANDED THIS RED IS EXPECTED: a fragment "+
			"should still reach the helper, so a PARSE_FAIL here means the fix "+
			"took the must-not-build blackhole shape. Invert or repair this "+
			"cell -- do not delete it", dControl)
	}

	// The tuple the shim derives from PAYLOAD bytes, not from any real header.
	key := fragSessionKeyFor(12345, 443)
	if err := coll.Maps["userspace_sessions"].Put(&key, uint8(2)); err != nil {
		t.Fatalf("plant: %v", err)
	}
	retHit, dHit := fragRun(t, coll, frag)
	t.Logf("COLLISION fragment + payload-keyed session -> ret=%d reasons=%v", retHit, dHit)

	if dHit["PASS_TO_KERNEL"] == 0 {
		t.Errorf("EXPECTED the #7494 exposure to still be present: a non-first "+
			"fragment should currently be adjudicated by a session keyed on its "+
			"PAYLOAD bytes and sent to the kernel, but reasons=%v. If #7494 has "+
			"landed, that is the intended outcome -- invert this cell to assert "+
			"REDIRECT_ERR instead of deleting it", dHit)
	}
}

// TestNonFirstFragmentDispositionDependsOnPayloadBytes_7494 is the sharper
// half, and it is not stated in the issue: `parse_l4` reads offset+12 as a TCP
// data-offset nibble and returns None when it is < 5, which lands on
// `drop_degraded_transit`. On a non-first fragment that byte is PAYLOAD.
//
// So the same fragment of the same flow is DROPPED or FORWARDED depending on
// its content. Both arms are asserted so neither can silently become the other.
//
// CHARACTERIZATION, as above: when #7494 lands both payload values must produce
// the same disposition, and this cell must go red.
func TestNonFirstFragmentDispositionDependsOnPayloadBytes_7494(t *testing.T) {
	coll := fragLoad(t)

	low := ipv4Frame(0x00b9)
	low[34+12] = 0x00 // payload byte parse_l4 reads as the data-offset nibble
	retLow, dLow := fragRun(t, coll, low)

	high := ipv4Frame(0x00b9)
	high[34+12] = 0x50
	retHigh, dHigh := fragRun(t, coll, high)

	t.Logf("payload byte 0x00 -> ret=%d reasons=%v", retLow, dLow)
	t.Logf("payload byte 0x50 -> ret=%d reasons=%v", retHigh, dHigh)

	if dLow["PARSE_FAIL"] == 0 {
		t.Errorf("a non-first fragment whose payload byte is 0x00 was expected to "+
			"be DROPPED via PARSE_FAIL, got reasons=%v. If #7494 has landed this "+
			"is the intended outcome -- invert the cell", dLow)
	}
	if dHigh["REDIRECT_ERR"] == 0 {
		t.Errorf("a non-first fragment whose payload byte is 0x50 was expected to "+
			"reach the helper via the XSK redirect, got reasons=%v. IF #7494 HAS "+
			"LANDED THIS RED IS EXPECTED only if the disposition is still the "+
			"helper; a PARSE_FAIL here means fragments are being DROPPED, which "+
			"is the blackhole shape the plan rejects. Invert or repair -- do not "+
			"delete", dHigh)
	}
	if reflect.DeepEqual(dLow, dHigh) {
		t.Errorf("both payload values produced the SAME disposition (%v). This "+
			"cell exists because they differ. IF #7494 HAS LANDED THIS RED IS "+
			"EXPECTED and is the goal: both payloads must share a disposition, "+
			"and it must be the helper, not a drop. Re-point this cell at the "+
			"new invariant -- do not delete it. If #7494 has NOT landed, the "+
			"fixture stopped discriminating", dLow)
	}
}
