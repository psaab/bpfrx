package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func dataplaneKeyFor8966() dataplane.SessionKey {
	return dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 61, 50}, DstIP: [4]byte{172, 16, 80, 200},
		Protocol: 6, SrcPort: 40000, DstPort: 5201,
	}
}

// #8966: `BulkStart` guarded nothing while `BulkEnd` guarded the epoch.
//
// A delayed or reordered BulkStart carrying a LOWER epoch -- the ordinary case
// with two fabric streams -- overwrote `bulkRecvEpoch` and reset the
// accumulators, discarding the in-progress bulk's receive set. The newer
// stream's BulkEnd then failed the comparison at the bottom of the same
// function. Two handlers disagreeing about which epoch is authoritative, and
// only one of them checking.
//
// THE #2198 F2 RATIONALE IS TRUE AND COVERS A DIFFERENT CASE. A rebooted peer
// legitimately restarts its genCounter lower, and refusing that bulk would
// strand the standby. The code could not tell that from a late BulkStart on
// the other stream, and applied the reboot treatment to both. `switched` --
// already computed two lines above for #6910's fabric preference -- is exactly
// the discriminator, so the information was in hand and not consulted by the
// code that needed it.

// A stale BulkStart within ONE boot incarnation must not clobber the
// in-progress epoch or the accumulated set.
func TestStaleBulkStartIsRefusedWithinOneIncarnation8966(t *testing.T) {
	inc := bootIncarnation{1, 1}
	e := newIncEnv(t, 2)

	e.prime(0, 7, &inc)
	if got := e.s.bulkRecvEpoch; got != 7 {
		t.Fatalf("CONTROL FAILED: the first BulkStart did not take (epoch=%d, want 7). "+
			"Nothing below can distinguish a refused stale start from a fixture "+
			"that never started a bulk", got)
	}
	if !e.s.bulkInProgress {
		t.Fatal("CONTROL FAILED: bulkInProgress is false after a BulkStart")
	}

	// A LATE, LOWER epoch on the other fabric stream, same incarnation.
	e.prime(1, 5, &inc)

	if got := e.s.bulkRecvEpoch; got != 7 {
		t.Errorf("#8966: a stale BulkStart (epoch 5) clobbered the in-progress epoch: "+
			"got %d, want 7.\n"+
			"  BulkEnd refuses a mismatched epoch; BulkStart assigned "+
			"unconditionally, so the newer bulk's accumulated receive set is "+
			"discarded and its own BulkEnd is then rejected as mismatched. Two "+
			"fabric streams is the normal configuration, so reordering between "+
			"them is the expected case rather than an exotic one.", got)
	}
}

// An EQUAL epoch must also be refused, and this cell exists because a mutation
// found the gap: changing `<=` to `<` in the guard left every other cell green.
//
// A duplicate BulkStart at the SAME epoch is the retransmit/reorder case, and
// accepting it resets the accumulators for the bulk already in progress --
// discarding a partly-received set and then failing its own BulkEnd. Identical
// consequence to the lower-epoch case, so the boundary is `<=`, not `<`.
func TestDuplicateEpochBulkStartIsRefused8966(t *testing.T) {
	inc := bootIncarnation{1, 1}
	e := newIncEnv(t, 2)

	e.prime(0, 7, &inc)
	if !e.s.bulkInProgress || e.s.bulkRecvEpoch != 7 {
		t.Fatalf("CONTROL FAILED: first BulkStart did not take (inProgress=%v epoch=%d)",
			e.s.bulkInProgress, e.s.bulkRecvEpoch)
	}
	e.s.bulkMu.Lock()
	e.s.bulkRecvV4[dataplaneKeyFor8966()] = struct{}{}
	before := len(e.s.bulkRecvV4)
	e.s.bulkMu.Unlock()
	if before != 1 {
		t.Fatalf("CONTROL FAILED: could not seed the accumulator (len=%d)", before)
	}

	// The SAME epoch again, on the other stream.
	e.prime(1, 7, &inc)

	e.s.bulkMu.Lock()
	after := len(e.s.bulkRecvV4)
	e.s.bulkMu.Unlock()
	if after != before {
		t.Errorf("#8966: a duplicate BulkStart at the SAME epoch reset the "+
			"accumulator: %d entries before, %d after. A retransmit or a "+
			"reorder discards a partly-received set and then fails its own "+
			"BulkEnd -- the same consequence as a lower epoch, which is why "+
			"the boundary is `<=` rather than `<`", before, after)
	}
}

// A HIGHER epoch within the same incarnation must still be accepted -- the
// guard must not refuse a legitimate re-prime.
func TestNewerBulkStartStillAcceptedWithinOneIncarnation8966(t *testing.T) {
	inc := bootIncarnation{1, 1}
	e := newIncEnv(t, 2)

	e.prime(0, 5, &inc)
	if e.s.bulkRecvEpoch != 5 {
		t.Fatalf("CONTROL FAILED: first BulkStart did not take")
	}
	e.prime(1, 9, &inc)

	if got := e.s.bulkRecvEpoch; got != 9 {
		t.Errorf("#8966: a NEWER BulkStart (epoch 9) was refused: got %d, want 9. "+
			"The guard is meant to refuse only a start that is not newer; "+
			"refusing a newer one would strand the standby on a stale bulk", got)
	}
}

// THE #2198 CASE MUST STILL WORK. Across a boot-incarnation change, a LOWER
// epoch is legitimate -- the peer rebooted and its counter restarted -- and
// accept-and-reset is correct. This is the case the original unconditional
// assignment existed for, and the guard must not break it.
func TestRebootedPeerLowerEpochStillAccepted8966(t *testing.T) {
	incA := bootIncarnation{1, 1}
	incB := bootIncarnation{2, 2}
	e := newIncEnv(t, 2)

	e.prime(0, 7, &incA)
	if e.s.bulkRecvEpoch != 7 {
		t.Fatalf("CONTROL FAILED: first BulkStart did not take")
	}

	// Same LOWER epoch as the refused case above, but a DIFFERENT incarnation.
	// The only variable between this cell and the stale one is the incarnation,
	// which is what makes it a test of the discriminator rather than of the
	// epoch comparison.
	e.prime(1, 5, &incB)

	if got := e.s.bulkRecvEpoch; got != 5 {
		t.Errorf("#8966/#2198: a REBOOTED peer's lower epoch (5) was refused: got %d, "+
			"want 5.\n"+
			"  A restarted peer legitimately restarts its genCounter lower. "+
			"Refusing it strands the standby on a bulk from a boot that no "+
			"longer exists -- the stale-RETAIN inverse #2198 F2 closed. The "+
			"guard must key on `switched`, not on the epoch alone.", got)
	}
}
