package cluster

import (
	"testing"
)

// samplePkt is a representative heartbeat with a couple of RGs and a monitor,
// used across the auth tests.
func samplePkt() *HeartbeatPacket {
	return &HeartbeatPacket{
		NodeID:            1,
		ClusterID:         42,
		SoftwareVersion:   "xpf-test-1",
		HAProtocolVersion: CurrentHAProtocolVersion,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
			{GroupID: 1, Priority: 150, Weight: 100, State: uint8(StateSecondary)},
		},
		Monitors: []HeartbeatMonitor{
			{RGID: 0, Weight: 10, Up: true, Interface: "ge-0-0-1"},
		},
	}
}

// TestMarshalHeartbeatAuth_RoundTrip verifies a signed frame carries a
// detectable, verifiable auth trailer while the body still parses.
func TestMarshalHeartbeatAuth_RoundTrip(t *testing.T) {
	key := []byte("cluster-shared-secret")
	pkt := samplePkt()
	data := MarshalHeartbeatAuth(pkt, key, 0xdeadbeef, 7)

	// The body still decodes (RG/monitor/version) with the trailer appended.
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal authed frame: %v", err)
	}
	if len(got.Groups) != 2 || got.Groups[0].Priority != 200 {
		t.Errorf("body parse wrong: %+v", got.Groups)
	}
	if got.SoftwareVersion != "xpf-test-1" {
		t.Errorf("software version lost under auth trailer: %q", got.SoftwareVersion)
	}

	session, counter, present := heartbeatAuthTrailer(data)
	if !present {
		t.Fatal("auth trailer not detected on signed frame")
	}
	if session != 0xdeadbeef || counter != 7 {
		t.Errorf("nonce = (%d,%d), want (%d,7)", session, counter, uint64(0xdeadbeef))
	}
	if !verifyHeartbeatMAC(data, key) {
		t.Error("valid HMAC rejected")
	}
}

// TestMarshalHeartbeatAuth_NoKeyIsLegacy verifies that an empty key yields a
// byte-identical legacy frame with no trailer (dual-accept: a node without a
// key emits legacy).
func TestMarshalHeartbeatAuth_NoKeyIsLegacy(t *testing.T) {
	pkt := samplePkt()
	legacy := MarshalHeartbeat(pkt)
	authed := MarshalHeartbeatAuth(pkt, nil, 1, 1)
	if len(authed) != len(legacy) || string(authed) != string(legacy) {
		t.Fatalf("empty key must produce legacy frame: authed=%d legacy=%d", len(authed), len(legacy))
	}
	if _, _, present := heartbeatAuthTrailer(authed); present {
		t.Error("legacy frame must not carry an auth trailer")
	}
}

// TestVerifyHeartbeatMAC_TamperAndWrongKey verifies the MAC rejects a modified
// frame and a wrong key — the core anti-forgery property.
func TestVerifyHeartbeatMAC_TamperAndWrongKey(t *testing.T) {
	key := []byte("cluster-shared-secret")
	data := MarshalHeartbeatAuth(samplePkt(), key, 5, 1)

	if !verifyHeartbeatMAC(data, key) {
		t.Fatal("baseline valid MAC rejected")
	}

	// Wrong key.
	if verifyHeartbeatMAC(data, []byte("attacker-guess")) {
		t.Error("MAC accepted under wrong key")
	}

	// Tamper a body byte (flip the priority of group 0). heartbeatHeaderSize is
	// the start of the group section.
	tampered := append([]byte(nil), data...)
	tampered[heartbeatHeaderSize+1] ^= 0xFF
	if verifyHeartbeatMAC(tampered, key) {
		t.Error("MAC accepted a tampered body")
	}

	// Tamper the MAC itself.
	tampered2 := append([]byte(nil), data...)
	tampered2[len(tampered2)-1] ^= 0xFF
	if verifyHeartbeatMAC(tampered2, key) {
		t.Error("MAC accepted a tampered digest")
	}
}

// TestHeartbeatAuthReplay verifies intra-session monotonic acceptance and
// session-change re-anchor (reboot tolerance).
func TestHeartbeatAuthReplay(t *testing.T) {
	var r heartbeatAuthReplay

	if !r.admit(100, 1) {
		t.Fatal("first heartbeat must be admitted")
	}
	if !r.admit(100, 2) {
		t.Error("strictly increasing counter must be admitted")
	}
	if r.admit(100, 2) {
		t.Error("replay of the same counter must be rejected")
	}
	if r.admit(100, 1) {
		t.Error("lower counter within a session must be rejected")
	}
	// New sender session (restart/reboot) re-anchors even with a lower counter.
	if !r.admit(200, 1) {
		t.Error("new session must re-anchor and be admitted (reboot tolerance)")
	}
	if !r.admit(200, 2) {
		t.Error("post-reanchor increasing counter must be admitted")
	}
	if r.admit(200, 2) {
		t.Error("replay after re-anchor must be rejected")
	}
}

// TestHeartbeatAuthDecision is the RED-on-revert core: it pins the accept/reject
// truth table of the dual-accept policy. Reverting the enforcement (e.g. always
// returning accept, or dropping the macOK/peerAuthSeen checks) turns one of
// these REJECT cases GREEN — i.e. a forged/unauthenticated heartbeat would
// drive election.
func TestHeartbeatAuthDecision(t *testing.T) {
	cases := []struct {
		name                                                string
		keyConfigured, present, macOK, nonceFresh, peerSeen bool
		wantAccept                                          bool
	}{
		// No local key -> dual-accept everything (cannot verify; may be the
		// not-yet-keyed side of a rolling upgrade). No regression.
		{"no-key/legacy", false, false, false, false, false, true},
		{"no-key/authed-frame", false, true, false, false, false, true},

		// Local key + authed frame -> enforce.
		{"key/good-hmac-fresh", true, true, true, true, false, true},
		{"key/bad-hmac", true, true, false, false, false, false},       // forged/tampered -> REJECT
		{"key/good-hmac-replay", true, true, true, false, true, false}, // replayed nonce -> REJECT

		// Local key + no trailer.
		{"key/legacy-peer-not-yet-authed", true, false, false, false, false, true}, // rolling upgrade dual-accept
		{"key/legacy-after-peer-authed", true, false, false, false, true, false},   // downgrade -> REJECT
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := heartbeatAuthDecision(tc.keyConfigured, tc.present, tc.macOK, tc.nonceFresh, tc.peerSeen)
			if got != tc.wantAccept {
				t.Fatalf("accept = %v (reason %q), want %v", got, reason, tc.wantAccept)
			}
			if !got && reason == "" {
				t.Error("a rejection must carry a non-empty reason")
			}
		})
	}
}

// TestHeartbeatAuthDecision_ForgedFrameRejected is the end-to-end anti-forgery
// assertion tying the wire path to the decision: a frame signed with the WRONG
// key (an attacker who does not hold the PSK) is rejected when a key is
// configured and the peer has authenticated. RED on revert: if the receiver
// stops enforcing, macOK would be ignored and this forged frame would be
// accepted -> forced election.
func TestHeartbeatAuthDecision_ForgedFrameRejected(t *testing.T) {
	realKey := []byte("real-cluster-psk")
	forged := MarshalHeartbeatAuth(samplePkt(), []byte("attacker-psk"), 9, 1)

	_, _, present := heartbeatAuthTrailer(forged)
	macOK := present && verifyHeartbeatMAC(forged, realKey)
	if macOK {
		t.Fatal("forged frame verified under the real key — HMAC broken")
	}
	// peerAuthSeen=true (both nodes keyed, peer previously authed).
	accept, reason := heartbeatAuthDecision(true, present, macOK, false, true)
	if accept {
		t.Fatalf("forged heartbeat accepted (reason %q) — forged frame drives election", reason)
	}

	// A correctly-signed frame from the genuine peer is accepted.
	good := MarshalHeartbeatAuth(samplePkt(), realKey, 9, 2)
	var replay heartbeatAuthReplay
	s, c, gp := heartbeatAuthTrailer(good)
	goodMAC := gp && verifyHeartbeatMAC(good, realKey)
	fresh := goodMAC && replay.admit(s, c)
	if accept2, _ := heartbeatAuthDecision(true, gp, goodMAC, fresh, true); !accept2 {
		t.Error("correctly-signed heartbeat rejected")
	}
}
