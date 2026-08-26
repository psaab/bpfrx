package dataplane

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// session_value_offsets_6816_test.go — #6816.
//
// pkg/dataplane/userspace's initial-control cleanup decodes `Created` out of a
// raw []byte read straight from the BPF map. It used the literal offset 16, on
// the strength of an in-comment sum:
//
//	State(1) + Flags(1) + TCPState(1) + IsReverse(1) + AppTimeout(4) + SessionID(8) = 16
//
// wrong twice over. `Flags` has been a uint16 since #5460, and the struct
// carries three explicit padding gaps (#6082) the sum omits entirely. SessionID
// is at 16; Created is at 24. So the cleanup read a SESSION ID and compared it
// against a seconds-since-boot cutoff — the keep-or-delete decision for synced
// sessions on ctrl enable was made on a number that is not a timestamp.
//
// The fix derives the offsets with unsafe.Offsetof, so a literal cannot drift
// from the layout again. These cells guard the two things that derivation does
// NOT make automatic.

// TestCreatedIsNotWhereTheOldLiteralSaid_6816 is the cell that reds on the
// defect, and it is deliberately phrased as the DISCRIMINATOR rather than as a
// restatement of the fix.
//
// Asserting `SessionValueCreatedOffset == 24` would be a tautology against
// unsafe.Offsetof — it can only fail if the compiler is wrong. What actually
// matters is that Created and SessionID are DIFFERENT fields at DIFFERENT
// offsets and that the old literal named the wrong one. That claim is false the
// moment someone reintroduces a hand-written 16, and it stays meaningful under
// any future layout change.
func TestCreatedIsNotWhereTheOldLiteralSaid_6816(t *testing.T) {
	if SessionValueCreatedOffset == SessionValueSessionIDOffset {
		t.Fatal("Created and SessionID resolve to the SAME offset; the whole " +
			"premise of #6816 (that the cleanup read one as the other) cannot be " +
			"tested and something is badly wrong with the struct")
	}
	if SessionValueSessionIDOffset != 16 {
		t.Errorf("SessionID is at %d, not 16 — the ABI moved. That is allowed, but "+
			"the #6816 narrative (the old literal 16 pointed at SessionID) is now "+
			"stale and the docs referencing it need updating",
			SessionValueSessionIDOffset)
	}
	if SessionValueCreatedOffset == 16 {
		t.Fatal("Created is at 16, which is where the pre-#6816 literal read it " +
			"from — either the padding was removed or someone widened a field back; " +
			"re-check pkg/dataplane/userspace/helper_status_apply.go")
	}
}

// TestCreatedOffsetDecodesARealCreatedValue_6816 is the BEHAVIOURAL cell: it
// builds a session value the way the kernel lays one out, decodes it the way the
// cleanup does, and requires the timestamp back.
//
// This is what an offset assertion alone cannot give. The cleanup reads through
// encoding/binary on a []byte, not through the struct, so the property that
// matters is "decoding at the exported offset yields the value the struct
// stored there" — which is exactly the step that was broken.
//
// FAIL-ON-REVERT: change the decode offset back to 16 (or to
// SessionValueSessionIDOffset) and this reds with the session ID in the message.
func TestCreatedOffsetDecodesARealCreatedValue_6816(t *testing.T) {
	const (
		wantCreated   uint64 = 1_700_000_042 // seconds since boot — a plausible timestamp
		wantSessionID uint64 = 0xDEADBEEFCAFE
	)
	v := bpfSessionValue{Created: wantCreated, SessionID: wantSessionID}

	// Serialise exactly as the kernel map value is laid out.
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&v)), unsafe.Sizeof(v))
	buf := append([]byte(nil), raw...)

	got := binary.NativeEndian.Uint64(
		buf[SessionValueCreatedOffset : SessionValueCreatedOffset+8])
	if got != wantCreated {
		if got == wantSessionID {
			t.Fatalf("decoding at SessionValueCreatedOffset (%d) returned the "+
				"SESSION ID (%#x), not Created — this is #6816 exactly: the "+
				"keep-or-delete decision for synced sessions is made on a number "+
				"that is not a timestamp", SessionValueCreatedOffset, got)
		}
		t.Fatalf("decoding at SessionValueCreatedOffset (%d) returned %d, want %d",
			SessionValueCreatedOffset, got, wantCreated)
	}

	// The paired half: the SessionID offset must decode the session ID. Without
	// it, both exported offsets pointing at Created would satisfy the assertion
	// above, and the "read one as the other" defect could reappear with the roles
	// swapped.
	gotID := binary.NativeEndian.Uint64(
		buf[SessionValueSessionIDOffset : SessionValueSessionIDOffset+8])
	if gotID != wantSessionID {
		t.Fatalf("decoding at SessionValueSessionIDOffset (%d) returned %#x, want %#x",
			SessionValueSessionIDOffset, gotID, wantSessionID)
	}
}

// TestTheOldLiteralWouldHaveReadTheSessionID_6816 pins the defect itself, so the
// bug's mechanism is recorded as an executable fact rather than as prose in a
// commit message.
//
// It is not redundant with the cells above: they assert the fix is right, this
// asserts the OLD code was wrong and names what it read instead. If a future
// layout change ever made 16 the correct offset for Created, this cell reds and
// forces the docs and the #6816 narrative to be revisited together, rather than
// leaving a comment on master describing a defect that no longer exists.
func TestTheOldLiteralWouldHaveReadTheSessionID_6816(t *testing.T) {
	const (
		created   uint64 = 1_700_000_042
		sessionID uint64 = 0xDEADBEEFCAFE
	)
	v := bpfSessionValue{Created: created, SessionID: sessionID}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&v)), unsafe.Sizeof(v))
	buf := append([]byte(nil), raw...)

	atOldLiteral := binary.NativeEndian.Uint64(buf[16:24])
	if atOldLiteral != sessionID {
		t.Fatalf("bytes [16:24] decode to %#x, want the session ID %#x — the "+
			"#6816 defect narrative (and the comments citing it) assume the old "+
			"literal 16 pointed at SessionID; if that is no longer true, update "+
			"them together", atOldLiteral, sessionID)
	}
	if atOldLiteral == created {
		t.Fatal("bytes [16:24] decode to Created, so the pre-#6816 code was " +
			"correct and this fix has no subject")
	}
}
