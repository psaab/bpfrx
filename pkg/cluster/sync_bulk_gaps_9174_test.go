package cluster

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9174 — three independent gaps in the bulk-session-sync protocol that let a
// stale or mistimed peer frame complete, reset or gut a bulk transfer.
//
// They share a file and a review pass; they do NOT share a fix, and these cells
// are kept apart deliberately. Each must red for its OWN reason — a single
// "the standby is synced" assertion cannot distinguish them and would let two
// of the three regress silently.
//
//	V013  BulkEnd carried no incarnation, so a frame buffered from the peer's
//	      PREVIOUS boot completed the bulk currently in progress.
//	V015  the #8966 BulkStart guard required `bulkInProgress`, so BETWEEN two
//	      bulks a stale full pair was accepted, resetting the accumulators and
//	      driving a reconcile.
//	V014  `epochReboot` armed incarnation retirement but was absent from the
//	      `needColdPrime` condition, so a peer rebooting into an EMPTY slot was
//	      never re-primed.
//
// Every one ends in the same place: a standby that believes it is synced and is
// not. That is invisible until a failover, at which point every session absent
// from the standby's table is a dropped flow.

// bulkEndPayload builds a BulkEnd body: the 8-byte epoch, plus the 16-byte
// incarnation when one is given. The no-incarnation form is byte-identical to
// what a pre-#9174 sender emits, which is what makes the rolling-upgrade
// fail-open row below a real observation rather than a stipulation.
func bulkEndPayload(epoch uint64, inc *bootIncarnation) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, epoch)
	if inc != nil {
		buf = append(buf, inc[:]...)
	}
	return buf
}

func (e *incEnv) bulkEnd(idx int, epoch uint64, inc *bootIncarnation) {
	e.s.handleMessage(e.conns[idx], syncMsgBulkEnd, bulkEndPayload(epoch, inc))
}

// bulkCompleted reports the three observables a completed bulk leaves behind.
// The one that MATTERS operationally is the release of the VRRP sync hold
// (OnBulkSyncReceived), because that is what makes the node MASTER-eligible;
// the other two are what `show chassis cluster` renders.
type bulkOutcome struct {
	everCompleted bool
	endTime       int64
	holdReleased  bool
}

func (e *incEnv) observeBulk(released chan struct{}) bulkOutcome {
	o := bulkOutcome{
		everCompleted: e.s.bulkEverCompleted.Load(),
		endTime:       e.s.stats.BulkSyncEndTime.Load(),
	}
	// OnBulkSyncReceived is dispatched with `go`, so this needs a real wait on
	// the positive side. On the negative side the wait is what makes "it did
	// not fire" a measurement rather than a race.
	select {
	case <-released:
		o.holdReleased = true
	case <-time.After(250 * time.Millisecond):
	}
	return o
}

// newBulkEnv wires an incEnv whose sync-hold release is observable.
func newBulkEnv(t *testing.T) (*incEnv, chan struct{}) {
	t.Helper()
	e := newIncEnv(t, 2)
	released := make(chan struct{}, 4)
	e.s.OnBulkSyncReceived = func() { released <- struct{}{} }
	return e, released
}

// ── V013: BulkEnd carries no incarnation ──────────────────────────────────

// THE DEFECT. The peer reboots mid-transfer. Its replacement primes a NEW bulk
// (accepted: the incarnation switched, which is the #2198 case). A BulkEnd
// buffered on the dead boot's socket then lands carrying the SAME epoch — the
// peer's send counter restarts from zero on reboot, so epoch collision across
// boots is ordinary, not exotic.
//
// Matching on epoch alone, that frame completes the bulk that is currently in
// progress. The standby reconciles against a PARTIAL table, latches
// bulkEverCompleted, and releases the VRRP sync hold: MASTER-eligible while
// forwarding with a table it never finished receiving.
func TestPriorBootBulkEndDoesNotCompleteTheCurrentBulk9174(t *testing.T) {
	e, released := newBulkEnv(t)

	// Boot A primes epoch 7 on fabric 0.
	e.prime(0, 7, &incA)
	if !e.s.bulkInProgress || e.s.bulkRecvEpoch != 7 {
		t.Fatalf("CONTROL FAILED: boot A's BulkStart did not take (inProgress=%v epoch=%d). "+
			"Nothing below can distinguish a refused prior-boot BulkEnd from a fixture "+
			"that never started a bulk", e.s.bulkInProgress, e.s.bulkRecvEpoch)
	}

	// The peer reboots. Boot B primes a fresh bulk at the SAME epoch, which is
	// accepted because the incarnation switched (#2198 F2 / #8966).
	e.prime(1, 7, &incB)
	if !e.s.bulkInProgress || e.s.bulkRecvEpoch != 7 {
		t.Fatalf("CONTROL FAILED: boot B's BulkStart was refused (inProgress=%v epoch=%d); "+
			"the cell needs a bulk from the CURRENT boot to be in progress",
			e.s.bulkInProgress, e.s.bulkRecvEpoch)
	}

	// A BulkEnd buffered from the DEAD boot arrives on its still-ESTABLISHED
	// socket. Same epoch; different boot.
	e.bulkEnd(0, 7, &incA)

	got := e.observeBulk(released)
	if got.everCompleted || got.endTime != 0 || got.holdReleased {
		t.Errorf("#9174 V013: a BulkEnd from the PEER'S PREVIOUS BOOT completed the bulk "+
			"currently in progress (everCompleted=%v endTime=%d holdReleased=%v).\n"+
			"  BulkStart carries the sender's boot incarnation and BulkEnd did not, so "+
			"the end marker was matched on EPOCH ALONE — and the epoch counter restarts "+
			"at zero on a peer reboot, so a collision across boots is the ordinary case.\n"+
			"  The standby reconciles against a partly-received table, latches "+
			"bulkEverCompleted and releases the VRRP sync hold: MASTER-eligible while "+
			"forwarding with sessions it never received. Invisible until the failover "+
			"that drops them.",
			got.everCompleted, got.endTime, got.holdReleased)
	}
	// The bulk must still be OPEN, so the real BulkEnd can still complete it.
	if !e.s.bulkInProgress {
		t.Errorf("#9174 V013: refusing the prior-boot BulkEnd also tore down the live "+
			"bulk (inProgress=%v). The live transfer must survive an ignored frame, or "+
			"the remedy strands the standby exactly like the defect", e.s.bulkInProgress)
	}
}

// LOAD-BEARING CONTROL. A BulkEnd from the CURRENT boot must still complete.
// This is the row a "refuse everything" implementation fails: consistency
// between BulkStart and BulkEnd is trivially satisfiable by never completing a
// bulk at all, which is strictly worse than the defect.
func TestCurrentBootBulkEndStillCompletes9174(t *testing.T) {
	e, released := newBulkEnv(t)
	e.prime(0, 7, &incA)
	e.bulkEnd(0, 7, &incA)

	got := e.observeBulk(released)
	if !got.everCompleted || got.endTime == 0 || !got.holdReleased {
		t.Fatalf("a BulkEnd carrying the CURRENT boot incarnation must complete the bulk "+
			"(everCompleted=%v endTime=%d holdReleased=%v). Refusing it strands the "+
			"standby: the sync hold is never released and the node never becomes "+
			"MASTER-eligible", got.everCompleted, got.endTime, got.holdReleased)
	}
}

// LOAD-BEARING CONTROL, rolling upgrade. A peer on an older build emits the
// 8-byte BulkEnd with no incarnation at all. That frame must complete exactly
// as it does today — the absent field means "no information", not "a different
// boot", which is the fail-open posture #5084 already fixed for BulkStart.
//
// Failing closed here would refuse every bulk from a not-yet-upgraded peer for
// the whole rolling-upgrade window.
func TestLegacyBulkEndWithoutIncarnationStillCompletes9174(t *testing.T) {
	e, released := newBulkEnv(t)
	e.prime(0, 7, &incA)
	e.bulkEnd(0, 7, nil) // byte-identical to a pre-#9174 sender

	got := e.observeBulk(released)
	if !got.everCompleted || got.endTime == 0 || !got.holdReleased {
		t.Fatalf("a legacy 8-byte BulkEnd must still complete the bulk "+
			"(everCompleted=%v endTime=%d holdReleased=%v). A mixed-version pair is the "+
			"normal state during a rolling upgrade, and refusing the old peer's end "+
			"marker strands its standby for the whole window",
			got.everCompleted, got.endTime, got.holdReleased)
	}
}

// The other fail-open direction: the bulk was started by a peer that sent NO
// incarnation, and an incarnated BulkEnd arrives. There is nothing to compare
// against, so it must complete.
func TestIncarnatedBulkEndAfterAnUnincarnatedStartStillCompletes9174(t *testing.T) {
	e, released := newBulkEnv(t)
	e.prime(0, 7, nil)
	e.bulkEnd(0, 7, &incA)

	got := e.observeBulk(released)
	if !got.everCompleted || got.endTime == 0 || !got.holdReleased {
		t.Fatalf("an incarnated BulkEnd after an UN-incarnated BulkStart must complete "+
			"(everCompleted=%v endTime=%d holdReleased=%v): the receiver recorded no "+
			"incarnation for this bulk, so it has no evidence the frame is from another "+
			"boot", got.everCompleted, got.endTime, got.holdReleased)
	}
}

// THE SENDER HALF, BOUND AT THE CALL SITE. Every receiver cell above injects
// its own payload, so all of them stay green on a build whose send path never
// appends the field at all — the receiver would then see an un-incarnated peer
// forever and the guard would be inert while looking present. This reads the
// BulkEnd frame off a real connection through the production write path, the
// same shape #5084 used to bind BulkStart's sender.
func TestBulkEndCarriesTheLocalBootIncarnationOnTheWire9174(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", &mockSweepDP{})
	s.mu.Lock()
	s.conn0 = local
	s.mu.Unlock()
	s.stats.Connected.Store(true)

	frames := make(chan syncFrame, 8)
	readFramesInto(peer, frames)
	go func() { _ = s.BulkSyncSnapshot(BulkSnapshot{}) }()

	var end syncFrame
	deadline := time.After(3 * time.Second)
	for end.typ != syncMsgBulkEnd {
		select {
		case f := <-frames:
			end = f
		case <-deadline:
			t.Fatal("no BulkEnd frame was written")
		}
	}

	want := localBootIncarnation()
	if !want.known() {
		t.Fatalf("this node's %s could not be read, so the sender has nothing to "+
			"advertise and the guard is inert on it. On Linux this file always exists; "+
			"a build or sandbox that hides it silently disables the guard", bootIDPath)
	}
	if len(end.payload) != 8+bootIncarnationLen {
		t.Fatalf("#9174 V013: BulkEnd payload = %d bytes, want %d (8B epoch + 16B boot "+
			"incarnation). An 8-byte payload means the sender never appends the field, "+
			"so an upgraded receiver can never tell a prior-boot end marker from a "+
			"current one", len(end.payload), 8+bootIncarnationLen)
	}
	if !bytes.Equal(end.payload[8:], want[:]) {
		t.Fatalf("BulkEnd tail = %x, want this node's boot incarnation %s",
			end.payload[8:], want)
	}
}

// A node whose own boot id could not be read appends NOTHING rather than 16
// zero bytes: an explicit zero is indistinguishable on the wire from a real
// incarnation the receiver must compare against, and the absent-field path is
// the one already specified to fail open.
func TestUnreadableLocalBootIDEmitsTheLegacyBulkEnd9174(t *testing.T) {
	if got := appendBootIncarnation(bulkEndPayload(7, nil), bootIncarnation{}); len(got) != 8 {
		t.Fatalf("an unreadable local boot id must emit the legacy 8-byte BulkEnd, got %d bytes", len(got))
	}
}

// ── V015: the #8966 guard does not cover the between-bulks window ─────────

func keyFor9174() dataplane.SessionKey {
	return dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 61, 51}, DstIP: [4]byte{172, 16, 80, 200},
		Protocol: 6, SrcPort: 40001, DstPort: 5201,
	}
}

// completeOneBulk runs a full BulkStart -> BulkEnd window so the receiver ends
// up BETWEEN bulks: bulkInProgress false, bulkRecvEpoch still at `epoch`.
func (e *incEnv) completeOneBulk(t *testing.T, idx int, epoch uint64, inc *bootIncarnation) {
	t.Helper()
	e.prime(idx, epoch, inc)
	e.bulkEnd(idx, epoch, inc)
	if e.s.bulkInProgress {
		t.Fatalf("setup: the bulk did not complete (inProgress still true)")
	}
	if e.s.bulkRecvEpoch != epoch {
		t.Fatalf("setup: the completed bulk's epoch was not retained (%d, want %d)",
			e.s.bulkRecvEpoch, epoch)
	}
}

// THE DEFECT. `reconcileStaleSessions` clears `bulkInProgress` at BulkEnd but
// leaves `bulkRecvEpoch` standing, so between two bulks the #8966 guard —
// `!switched && s.bulkInProgress && epoch <= s.bulkRecvEpoch` — cannot fire at
// all. A stale full pair reordered off the OTHER fabric is then accepted: it
// resets the accumulators, and its BulkEnd drives a reconcile against a set
// that was never received. Mass delete, then resurrection on the next sync.
//
// Two consecutive bulks CAN pin different fabrics (`BulkSync` pins
// `getActiveConn` once), which is the ordinary route to a reordered pair.
func TestStaleBulkStartBetweenBulksIsRefused9174(t *testing.T) {
	e, _ := newBulkEnv(t)
	e.completeOneBulk(t, 0, 7, &incA)

	// A late BulkStart from the SAME boot on the other fabric, carrying an
	// epoch that is not newer.
	e.prime(1, 5, &incA)

	if e.s.bulkInProgress {
		t.Errorf("#9174 V015: a STALE BulkStart (epoch 5) was accepted BETWEEN bulks and " +
			"opened a new receive window.\n" +
			"  The #8966 guard requires `s.bulkInProgress`, and reconcileStaleSessions " +
			"clears that flag at BulkEnd while leaving bulkRecvEpoch standing — so " +
			"between two bulks the guard cannot fire at all.\n" +
			"  The accepted pair resets the accumulators and its BulkEnd reconciles " +
			"against a set that was never received: a mass delete of live peer-owned " +
			"sessions, followed by resurrection on the next sync.")
	}
	if got := e.s.bulkRecvEpoch; got != 7 {
		t.Errorf("#9174 V015: the stale BulkStart clobbered the epoch high-water: got %d, "+
			"want 7", got)
	}
}

// An EQUAL epoch between bulks is the retransmit case and must be refused for
// the same reason `<=` rather than `<` is the boundary inside a bulk (#8966).
func TestDuplicateEpochBulkStartBetweenBulksIsRefused9174(t *testing.T) {
	e, _ := newBulkEnv(t)
	e.completeOneBulk(t, 0, 7, &incA)

	e.prime(1, 7, &incA)

	if e.s.bulkInProgress {
		t.Errorf("#9174 V015: a DUPLICATE BulkStart at the already-completed epoch 7 was " +
			"accepted between bulks. A retransmit or a cross-fabric reorder reopens a " +
			"window for a transfer that already finished")
	}
}

// LOAD-BEARING CONTROL. A genuinely NEWER bulk between bulks must be accepted —
// this is the ordinary steady-state path, and the guard exists to refuse stale
// starts, not to refuse the next one.
func TestNewerBulkStartBetweenBulksIsAccepted9174(t *testing.T) {
	e, _ := newBulkEnv(t)
	e.completeOneBulk(t, 0, 7, &incA)

	e.prime(1, 9, &incA)

	if !e.s.bulkInProgress || e.s.bulkRecvEpoch != 9 {
		t.Fatalf("a NEWER BulkStart (epoch 9) after a completed bulk must be accepted "+
			"(inProgress=%v epoch=%d, want true/9). Refusing it stops every subsequent "+
			"bulk for the life of the connection — strictly worse than the defect",
			e.s.bulkInProgress, e.s.bulkRecvEpoch)
	}
}

// LOAD-BEARING CONTROL, #2198 F2. A rebooted peer legitimately restarts its
// epoch counter LOWER. Across an incarnation change that is not a stale frame,
// and accept-and-reset is the correct treatment — between bulks exactly as
// within one. The only variable between this cell and the stale one is the
// incarnation, which is what makes it a test of the discriminator.
func TestRebootedPeerLowerEpochBetweenBulksIsAccepted9174(t *testing.T) {
	e, _ := newBulkEnv(t)
	e.completeOneBulk(t, 0, 7, &incA)

	e.prime(1, 5, &incB) // same lower epoch as the refused cell, different boot

	if !e.s.bulkInProgress || e.s.bulkRecvEpoch != 5 {
		t.Fatalf("#2198 F2: a REBOOTED peer's lower epoch must still be accepted between "+
			"bulks (inProgress=%v epoch=%d, want true/5). Its counter restarted; "+
			"refusing it strands the standby with no re-prime",
			e.s.bulkInProgress, e.s.bulkRecvEpoch)
	}
}

// LOAD-BEARING CONTROL, fail-open. Without an incarnation on the frame there is
// no way to tell "the peer rebooted and restarted its counter" from "this start
// is stale", and guessing wrong strands the standby. So an UN-INCARNATED stale
// start keeps today's accept — the same fail-open #5084 chose, made explicit
// rather than incidental.
func TestUnincarnatedStaleBulkStartBetweenBulksStillAccepted9174(t *testing.T) {
	e, _ := newBulkEnv(t)
	e.completeOneBulk(t, 0, 7, nil)

	e.prime(1, 5, nil)

	if !e.s.bulkInProgress {
		t.Fatalf("an UN-INCARNATED lower-epoch BulkStart between bulks must still be " +
			"accepted: with no incarnation on the wire, a rebooted peer restarting its " +
			"counter and a stale reordered frame are the same bytes. Failing closed " +
			"here refuses every re-prime from a peer on an older build")
	}
}

// REGRESSION CONTROL for #8966, not a V015 cell — it is green at the base
// commit and stays green, and that is the point: extending the guard to the
// between-bulks window must not weaken the WITHIN-bulk arm #8966 landed. The
// accumulator is what a wrongly-accepted start destroys, so it is asserted
// directly rather than inferred from the flags.
func TestInProgressStaleStartStillRefusedAfterTheBetweenBulksFix9174(t *testing.T) {
	e, _ := newBulkEnv(t)
	e.completeOneBulk(t, 0, 7, &incA)
	e.prime(1, 9, &incA) // a legitimate newer bulk is now in progress

	e.s.bulkMu.Lock()
	e.s.bulkRecvV4[keyFor9174()] = struct{}{}
	before := len(e.s.bulkRecvV4)
	e.s.bulkMu.Unlock()
	if before != 1 {
		t.Fatalf("CONTROL FAILED: could not seed the accumulator (len=%d)", before)
	}

	// A stale start for the bulk that already COMPLETED.
	e.prime(0, 7, &incA)

	e.s.bulkMu.Lock()
	after := len(e.s.bulkRecvV4)
	e.s.bulkMu.Unlock()
	if after != before {
		t.Errorf("#9174 V015: a stale BulkStart discarded the in-flight bulk's receive "+
			"set (%d entries before, %d after); its BulkEnd then reconciles against a "+
			"set that was never received", before, after)
	}
}

// ── V014: epochReboot never arms needColdPrime ────────────────────────────

// THE DEFECT. A peer that reboots and dials the EMPTY alternate slot supersedes
// nothing and leaves the registry non-empty, so it satisfies neither
// `supersededCurrent` nor `wasDisconnected`. #7762 taught installConn to
// RETIRE the dead incarnation on the raised boot epoch — but that same evidence
// never reached the `needColdPrime` arm, so the survivor never re-primes the
// replacement. A rebooted peer has an EMPTY session table, so the standby ends
// up holding nothing and blackholes every established flow on the next failover
// to it — the #5480 blackhole, reached through the epoch edge.
func TestEpochRebootArmsColdPrime9174(t *testing.T) {
	ss := newAckTestSync(t)
	src := &epochSource{epoch: 100, latched: true}
	ss.PeerBootEpochFn = src.fn

	ss.installConn(0, pipeConn(t))
	// The first install arms the latch through wasDisconnected (the registry was
	// empty). Clear it, so anything observed below is the epoch edge and not a
	// leftover from setup.
	ss.needColdPrime.Store(false)

	src.epoch = 101 // the peer rebooted; its heartbeat raised the floor
	d := ss.installConn(1, pipeConn(t))

	if !ss.needColdPrime.Load() {
		t.Errorf("#9174 V014: a peer reboot observed on the boot EPOCH did not arm " +
			"needColdPrime.\n" +
			"  installConn already acts on this evidence — `if supersededCurrent || " +
			"epochReboot` advances the incarnation and evicts the corpse — but the " +
			"cold-prime arm three dozen lines below is still `if d.wasDisconnected || " +
			"supersededCurrent`, and a replacement dialling the EMPTY alternate slot " +
			"satisfies neither.\n" +
			"  A rebooted peer's session table is EMPTY. Without a re-prime the standby " +
			"holds nothing, and the next failover to it blackholes every established " +
			"flow.")
	}
	if !d.shouldColdPrime {
		t.Errorf("#9174 V014: needColdPrime is the latch, but handleNewConnection drives " +
			"the bulk off `d.shouldColdPrime` — computed in the same locked region. " +
			"Arming the latch without the decision reaching this connection leaves the " +
			"re-prime unrun")
	}
}

// LOAD-BEARING NEGATIVE CONTROL. Without a raised epoch, a second fabric coming
// up beside a live one is the SAME peer bringing up its other link — not a
// reboot — and must NOT arm a cold prime. This is the row that proves the arm
// is reading the epoch rather than arming on every install; "always arm"
// satisfies the cell above and fails here.
func TestSecondFabricWithoutAnEpochRaiseDoesNotArmColdPrime9174(t *testing.T) {
	ss := newAckTestSync(t)
	src := &epochSource{epoch: 100, latched: true}
	ss.PeerBootEpochFn = src.fn

	ss.installConn(0, pipeConn(t))
	ss.needColdPrime.Store(false)

	// Same boot: the epoch does not move.
	d := ss.installConn(1, pipeConn(t))

	if ss.needColdPrime.Load() || d.shouldColdPrime {
		t.Fatalf("the SAME peer boot bringing up its second fabric must not arm a cold "+
			"prime (needColdPrime=%v shouldColdPrime=%v). Re-priming on every install "+
			"turns a routine second-fabric connect into a full table re-send",
			ss.needColdPrime.Load(), d.shouldColdPrime)
	}
}

// The unwired arm: an embedder with no epoch source keeps exactly its pre-#7762
// behaviour. This is also the control showing the fixture does not arm the
// latch on its own, so the headline cell's pass comes from the epoch signal.
func TestNilEpochFnDoesNotArmColdPrime9174(t *testing.T) {
	ss := newAckTestSync(t)
	if ss.PeerBootEpochFn != nil {
		t.Fatal("fixture must start unwired for this control to mean anything")
	}
	ss.installConn(0, pipeConn(t))
	ss.needColdPrime.Store(false)

	d := ss.installConn(1, pipeConn(t))

	if ss.needColdPrime.Load() || d.shouldColdPrime {
		t.Fatalf("with no epoch source wired, installing a second fabric must behave "+
			"exactly as it did before #7762 (needColdPrime=%v shouldColdPrime=%v)",
			ss.needColdPrime.Load(), d.shouldColdPrime)
	}
}

// The unlatched race window must not arm either: on a peer reboot the heartbeat
// and the fabric connect race, and an unlatched floor reads 0 and means
// nothing. #7762 already refuses to CLASSIFY it; this pins that the cold-prime
// arm inherits that refusal rather than reading a fabricated zero.
func TestUnlatchedEpochDoesNotArmColdPrime9174(t *testing.T) {
	ss := newAckTestSync(t)
	src := &epochSource{epoch: 100, latched: true}
	ss.PeerBootEpochFn = src.fn

	ss.installConn(0, pipeConn(t))
	ss.needColdPrime.Store(false)

	src.epoch, src.latched = 0, false
	d := ss.installConn(1, pipeConn(t))

	if ss.needColdPrime.Load() || d.shouldColdPrime {
		t.Fatalf("an install during the UNLATCHED window must not arm a cold prime "+
			"(needColdPrime=%v shouldColdPrime=%v): the floor is 0 because no heartbeat "+
			"has landed, not because the peer is on boot 0",
			ss.needColdPrime.Load(), d.shouldColdPrime)
	}
}
