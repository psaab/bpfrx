package cluster

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMarshalHeartbeatAuthEpoch_RoundTrip verifies a v2 signed frame carries a
// detectable, verifiable auth trailer with the boot epoch, while the body still
// parses. It also confirms the empty-key case is byte-identical legacy.
func TestMarshalHeartbeatAuthEpoch_RoundTrip(t *testing.T) {
	key := []byte("cluster-shared-secret")
	pkt := samplePkt()
	data := MarshalHeartbeatAuthEpoch(pkt, key, 0xdeadbeef, 7, 0x515151)

	// The body still decodes with the (longer) v2 trailer appended.
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal authed frame: %v", err)
	}
	if len(got.Groups) != 2 || got.Groups[0].Priority != 200 {
		t.Errorf("body parse wrong: %+v", got.Groups)
	}
	if got.SoftwareVersion != "xpf-test-1" {
		t.Errorf("software version lost under v2 trailer: %q", got.SoftwareVersion)
	}

	auth := parseHeartbeatAuth(data, key)
	if !auth.present || !auth.macOK || !auth.hasEpoch {
		t.Fatalf("v2 trailer not detected/verified: %+v", auth)
	}
	if auth.session != 0xdeadbeef || auth.counter != 7 || auth.epoch != 0x515151 {
		t.Errorf("parsed (session,counter,epoch) = (%#x,%d,%#x), want (0xdeadbeef,7,0x515151)",
			auth.session, auth.counter, auth.epoch)
	}

	// Empty key -> byte-identical legacy frame (dual-accept: a keyless node emits
	// legacy). This is the same invariant MarshalHeartbeatAuth has.
	legacy := MarshalHeartbeat(pkt)
	authless := MarshalHeartbeatAuthEpoch(pkt, nil, 1, 1, 1)
	if string(authless) != string(legacy) {
		t.Fatalf("empty key must produce legacy frame (len %d vs %d)", len(authless), len(legacy))
	}
}

// TestParseHeartbeatAuth_DualAccept verifies the parser recognises BOTH the v1
// (nonce-only) and v2 (epoch) trailers and reports a legacy unsigned frame as
// not present — the rolling-upgrade dual-accept property. A v2 frame verified
// against the RIGHT key sets macOK; a v1 frame reports hasEpoch=false.
func TestParseHeartbeatAuth_DualAccept(t *testing.T) {
	key := []byte("cluster-shared-secret")

	// v1 frame: present, verifiable, no epoch.
	v1 := MarshalHeartbeatAuth(samplePkt(), key, 0x1111, 3)
	a1 := parseHeartbeatAuth(v1, key)
	if !a1.present || !a1.macOK || a1.hasEpoch {
		t.Errorf("v1 parse: %+v (want present, macOK, !hasEpoch)", a1)
	}
	if a1.session != 0x1111 || a1.counter != 3 {
		t.Errorf("v1 nonce = (%#x,%d), want (0x1111,3)", a1.session, a1.counter)
	}

	// v2 frame: present, verifiable, epoch.
	v2 := MarshalHeartbeatAuthEpoch(samplePkt(), key, 0x2222, 4, 999)
	a2 := parseHeartbeatAuth(v2, key)
	if !a2.present || !a2.macOK || !a2.hasEpoch || a2.epoch != 999 {
		t.Errorf("v2 parse: %+v (want present, macOK, hasEpoch, epoch=999)", a2)
	}

	// Legacy unsigned frame: no trailer.
	legacy := MarshalHeartbeat(samplePkt())
	al := parseHeartbeatAuth(legacy, key)
	if al.present {
		t.Errorf("legacy unsigned frame reported an auth trailer: %+v", al)
	}

	// Wrong key: trailer present (format detected) but macOK false. Both v1 and
	// v2 forms must fail closed.
	if aw := parseHeartbeatAuth(v2, []byte("attacker")); !aw.present || aw.macOK {
		t.Errorf("v2 under wrong key: %+v (want present, !macOK)", aw)
	}
	if aw := parseHeartbeatAuth(v1, []byte("attacker")); !aw.present || aw.macOK {
		t.Errorf("v1 under wrong key: %+v (want present, !macOK)", aw)
	}
}

// TestHeartbeatEpochAdmit exercises the receiver's boot-epoch high-water logic
// directly: the first epoch anchors, an equal epoch (another frame from the
// SAME incarnation) is admitted, a strictly-lower epoch (a retired incarnation)
// is rejected, and a higher epoch (a genuine reboot) advances the mark.
func TestHeartbeatEpochAdmit(t *testing.T) {
	r := &heartbeatReceiver{}

	if !r.epochAdmit(100) {
		t.Fatal("first epoch must anchor and be admitted")
	}
	if !r.epochAdmit(100) {
		t.Error("equal epoch (same incarnation) must be admitted")
	}
	if r.epochAdmit(99) {
		t.Error("lower epoch (retired incarnation) must be REJECTED")
	}
	if !r.epochAdmit(101) {
		t.Error("higher epoch (genuine reboot) must be admitted")
	}
	// The reboot advanced the mark: the previously-live 100 is now retired.
	if r.epochAdmit(100) {
		t.Error("epoch below the advanced high-water must be REJECTED")
	}
	if r.highEpoch != 101 {
		t.Errorf("highEpoch = %d, want 101", r.highEpoch)
	}
}

// TestHeartbeatEpochDecision pins the #6169 epoch policy truth table. Reverting
// the enforcement (e.g. always returning accept) flips a REJECT case GREEN.
func TestHeartbeatEpochDecision(t *testing.T) {
	cases := []struct {
		name                                string
		hasEpoch, epochFresh, peerEpochSeen bool
		wantAccept                          bool
	}{
		{"v2/fresh-epoch", true, true, false, true},
		{"v2/stale-epoch-replay", true, false, false, false},    // retired incarnation -> REJECT
		{"v1/peer-not-yet-epoched", false, false, false, true},  // rolling upgrade dual-accept
		{"v1/downgrade-after-epoch", false, false, true, false}, // epoch strip -> REJECT
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := heartbeatEpochDecision(tc.hasEpoch, tc.epochFresh, tc.peerEpochSeen)
			if got != tc.wantAccept {
				t.Fatalf("accept = %v (reason %q), want %v", got, reason, tc.wantAccept)
			}
			if !got && reason == "" {
				t.Error("a rejection must carry a non-empty reason")
			}
		})
	}
}

// heartbeatGate reconstructs the readLoop auth gate (heartbeat.go readLoop) over
// a real frame and returns whether the frame would refresh peer liveness. It
// mutates the receiver's real authReplay / epoch / peerAuthSeen state exactly as
// the readLoop does, so a test can feed a sequence of frames and observe the
// cumulative accept/reject decisions.
func heartbeatGate(r *heartbeatReceiver, key, frame []byte) bool {
	auth := parseHeartbeatAuth(frame, key)
	nonceFresh := auth.macOK && r.authReplay.admit(auth.session, auth.counter)
	accept, _ := heartbeatAuthDecision(len(key) > 0, auth.present, auth.macOK, nonceFresh, r.peerAuthSeen.Load())
	if accept && auth.macOK {
		epochFresh := auth.hasEpoch && r.epochAdmit(auth.epoch)
		accept, _ = heartbeatEpochDecision(auth.hasEpoch, epochFresh, r.sawEpoch)
	}
	if auth.macOK {
		r.peerAuthSeen.Store(true)
	}
	return accept
}

// TestHeartbeatEpochRejectsRetiredIncarnationAfterRingChurn is the #6169
// fail-on-revert gate — the complete fix for the >=65-recording sustained
// replay the bounded session ring cannot close (issue body / #6167 residual).
//
// Scenario, faithful to the issue: an on-link attacker captured a RETIRED
// incarnation R (a low boot epoch). Over the cluster's life the peer rebooted
// heartbeatReplaySessions more times (each a genuinely-new session with a
// strictly HIGHER epoch), churning the 64-slot session ring so R's watermark is
// EVICTED. The ring now treats a replay of R as a never-seen session and would
// ADMIT it — exactly the residual #5477 documented. The boot epoch closes it:
// R's epoch is below the high-water, so the replay is rejected regardless of
// ring state.
//
// RED-on-revert: neutralising the epoch reject in heartbeatReceiver.epochAdmit
// (`if r.sawEpoch && epoch < r.highEpoch { return false }`) makes epochAdmit
// always admit, so the replayed retired frame passes the gate and would refresh
// liveness / apply its stale role — this test then fails as a clean assertion.
func TestHeartbeatEpochRejectsRetiredIncarnationAfterRingChurn(t *testing.T) {
	key := []byte("cluster-shared-secret")
	const retiredEpoch = 1_000_000

	// Build the retired incarnation's captured frame (epoch below every later
	// reboot). counter=1 is its first (and here only) recorded frame.
	const sessR = 0xBADCAFE
	retired := MarshalHeartbeatAuthEpoch(samplePkt(), key, sessR, 1, retiredEpoch)

	r := &heartbeatReceiver{}

	// 1) The attacker's capture was live once: it is admitted and anchors the
	// high-water at retiredEpoch. (Model the moment R was the live incarnation.)
	if !heartbeatGate(r, key, retired) {
		t.Fatal("R was once the live incarnation and must have been admitted")
	}

	// 2) heartbeatReplaySessions genuine reboots, each a NEW session with a
	// strictly HIGHER epoch. These both advance the high-water AND churn the
	// ring, evicting R's watermark (FIFO after a full ring of newer sessions).
	for i := 0; i < heartbeatReplaySessions; i++ {
		sess := uint64(0x10000 + i)
		epoch := uint64(retiredEpoch + 1 + i)
		frame := MarshalHeartbeatAuthEpoch(samplePkt(), key, sess, 1, epoch)
		if !heartbeatGate(r, key, frame) {
			t.Fatalf("genuine reboot %d (sess %#x, epoch %d) must be admitted", i, sess, epoch)
		}
	}

	// Sanity: R's session is now evicted from the ring, so the RING ALONE would
	// re-admit the replay (this is the exact residual the epoch closes). Prove it
	// on an independent ring driven with the same churn.
	var ringOnly heartbeatAuthReplay
	if !ringOnly.admit(sessR, 1) {
		t.Fatal("setup: first admit of R must succeed")
	}
	for i := 0; i < heartbeatReplaySessions; i++ {
		ringOnly.admit(uint64(0x10000+i), 1)
	}
	if !ringOnly.admit(sessR, 1) {
		t.Fatal("precondition: after >=64 churned sessions the ring ALONE re-admits the retired replay (the residual the boot epoch must close)")
	}

	// 3) THE FIX: replay the retired incarnation R. The ring admits it
	// (never-seen), but its epoch (retiredEpoch) is below the high-water
	// (retiredEpoch+heartbeatReplaySessions), so the epoch gate REJECTS it.
	if heartbeatGate(r, key, retired) {
		t.Error("#6169: replay of a retired (lower-epoch) incarnation must be REJECTED even after >=65 incarnations churn the session ring")
	}
	// And a sustained loop stays closed.
	if heartbeatGate(r, key, retired) {
		t.Error("#6169: a sustained retired-epoch replay must remain REJECTED")
	}
}

// TestHeartbeatEpochDowngradeRejected verifies that once the peer has proven it
// carries a boot epoch (sent a MAC-valid v2 frame), a later MAC-valid v1 frame
// WITHOUT an epoch is rejected as a downgrade (epoch strip). Before the peer
// sends any epoch, a v1 frame is dual-accepted (rolling upgrade). This mirrors
// the cleartext-downgrade gate: a proven capability cannot be silently dropped.
func TestHeartbeatEpochDowngradeRejected(t *testing.T) {
	key := []byte("cluster-shared-secret")

	// A pre-upgrade v1 frame is accepted while the peer has not yet epoched.
	r := &heartbeatReceiver{}
	v1early := MarshalHeartbeatAuth(samplePkt(), key, 0x1, 1)
	if !heartbeatGate(r, key, v1early) {
		t.Fatal("a v1 frame before any epoch must be dual-accepted (rolling upgrade)")
	}

	// Peer upgrades: a v2 frame arrives and proves the epoch capability.
	v2 := MarshalHeartbeatAuthEpoch(samplePkt(), key, 0x2, 1, 500)
	if !heartbeatGate(r, key, v2) {
		t.Fatal("the peer's first v2 frame must be admitted")
	}
	if !r.sawEpoch {
		t.Fatal("sawEpoch must latch once a MAC-valid epoch frame is accepted")
	}

	// Now a MAC-valid v1 frame (no epoch) is a downgrade -> reject.
	v1late := MarshalHeartbeatAuth(samplePkt(), key, 0x3, 1)
	if heartbeatGate(r, key, v1late) {
		t.Error("#6169: a MAC-valid v1 frame after the peer proved it carries an epoch must be REJECTED (epoch strip)")
	}
}

// TestNextBootEpoch_Monotonic verifies the sender epoch source strictly
// increases across successive incarnations (each call = one daemon start) and
// survives a wall-clock step BACKWARDS via the persisted floor. A missing file
// is first boot (wall-clock seeded), not an error.
func TestNextBootEpoch_Monotonic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ha-boot-epoch")

	e1 := nextBootEpoch(path)
	if e1 == 0 {
		t.Fatal("first epoch must be non-zero (wall-clock seeded)")
	}
	// The file was persisted.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("epoch not persisted: %v", err)
	}

	e2 := nextBootEpoch(path)
	if e2 <= e1 {
		t.Errorf("epoch must strictly increase across restarts: e2=%d <= e1=%d", e2, e1)
	}

	// Simulate a wall-clock step backwards by planting a persisted value FAR
	// above the current wall clock: the next epoch must still exceed it
	// (persisted+1 floor dominates), so a rebooted peer with a skewed clock is
	// never mistaken for a replay of its own retired incarnation.
	future := e2 + 1_000_000_000_000
	if err := os.WriteFile(path, []byte(itoa(future)+"\n"), 0o644); err != nil {
		t.Fatalf("plant future epoch: %v", err)
	}
	e3 := nextBootEpoch(path)
	if e3 <= future {
		t.Errorf("persisted floor must dominate a backwards clock: e3=%d <= planted=%d", e3, future)
	}
}

// itoa avoids importing strconv in the test just for one conversion.
func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
