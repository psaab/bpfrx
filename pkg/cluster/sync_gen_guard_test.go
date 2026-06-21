package cluster

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #2170 — HA session-sync install-generation guard tests.
//
// These exercise the cluster apply layer (installClusterSyncedV4/V6,
// deleteClusterSyncedV4/V6) through the mockSweepDP SessionStore, plus the
// wire round-trip for the new length-gated trailing generation field. Every
// guard test is written so it FAILS against the pre-fix behavior (where a
// delete unconditionally removes whatever sits at the key).

func gen2170KeyV4() dataplane.SessionKey {
	return dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  12345,
		DstPort:  5201,
	}
}

func gen2170KeyV6() dataplane.SessionKeyV6 {
	k := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 12345, DstPort: 5201}
	k.SrcIP[15] = 1
	k.DstIP[15] = 2
	return k
}

// installWithGenV4 drives the real apply layer with an explicit generation,
// as if the value had arrived off the wire (decode sets val.Generation).
func installWithGenV4(ss *SessionSync, key dataplane.SessionKey, gen uint64) {
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	val.Generation = gen
	ss.installClusterSyncedV4(key, val)
}

func installWithGenV6(ss *SessionSync, key dataplane.SessionKeyV6, gen uint64) {
	val := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	val.Generation = gen
	ss.installClusterSyncedV6(key, val)
}

// TestStaleDeleteIgnoredForReplacement is the §3.4 race: S(K) closes (delete
// journaled at gen=1), a replacement S'(K) is installed with a NEWER gen=2,
// then the stale delete (gen=1) replays. The delete MUST be refused and S'
// MUST survive. Against the pre-fix code this deleted S'.
func TestStaleDeleteIgnoredForReplacement(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// T0..T1: install S(K) gen=1, then the replacement S'(K) gen=2 (overwrites,
	// stored gen=2).
	installWithGenV4(ss, key, 1)
	installWithGenV4(ss, key, 2)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("replacement session S' should be installed")
	}

	// T2: the journaled delete for the OLD incarnation (gen=1) replays.
	ss.deleteClusterSyncedV4(key, 1)

	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("stale delete (gen=1) wrongly removed the live replacement S' (gen=2)")
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 1 {
		t.Fatalf("DeletesStaleIgnored = %d, want 1", got)
	}
}

func TestStaleDeleteIgnoredForReplacementV6(t *testing.T) {
	key := gen2170KeyV6()
	dp := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	installWithGenV6(ss, key, 1)
	installWithGenV6(ss, key, 2)
	ss.deleteClusterSyncedV6(key, 1)

	if _, ok := dp.v6sessions[key]; !ok {
		t.Fatal("stale v6 delete (gen=1) wrongly removed the live replacement (gen=2)")
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 1 {
		t.Fatalf("DeletesStaleIgnored = %d, want 1", got)
	}
}

// TestRealDeleteApplied: the delete of the very session installed (equal
// generation) MUST apply. Equality is NOT refusal (SMR C2: never <=).
func TestRealDeleteApplied(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	installWithGenV4(ss, key, 2)
	ss.deleteClusterSyncedV4(key, 2) // equal generation — must delete

	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("real delete (equal generation) did not remove the session")
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 0 {
		t.Fatalf("DeletesStaleIgnored = %d, want 0 for an equal-generation delete", got)
	}
}

// TestNewerDeleteApplied: a delete with a strictly NEWER generation than the
// stored entry must apply (the stored entry is the older incarnation).
func TestNewerDeleteApplied(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	installWithGenV4(ss, key, 2)
	ss.deleteClusterSyncedV4(key, 5)

	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("newer-generation delete did not remove the session")
	}
}

// TestLegacyPeerNoGenStillDeletes: gen==0 on EITHER side falls back to today's
// unconditional delete (rolling-upgrade safe). Covers both directions.
func TestLegacyPeerNoGenStillDeletes(t *testing.T) {
	t.Run("legacy_install_then_genned_delete", func(t *testing.T) {
		key := gen2170KeyV4()
		dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
		ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
		installWithGenV4(ss, key, 0) // legacy peer install: stored gen stays 0
		ss.deleteClusterSyncedV4(key, 7)
		if _, ok := dp.v4sessions[key]; ok {
			t.Fatal("delete against a gen-0 stored entry must be unconditional")
		}
	})
	t.Run("genned_install_then_legacy_delete", func(t *testing.T) {
		key := gen2170KeyV4()
		dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
		ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
		installWithGenV4(ss, key, 9)
		ss.deleteClusterSyncedV4(key, 0) // legacy delete: unconditional
		if _, ok := dp.v4sessions[key]; ok {
			t.Fatal("a gen-0 (legacy) delete must be unconditional even against a genned entry")
		}
		if got := ss.stats.DeletesStaleIgnored.Load(); got != 0 {
			t.Fatalf("DeletesStaleIgnored = %d, want 0 for a legacy delete", got)
		}
	})
}

// TestStaleInstallDoesNotRegressStoredGen (SMR C3): a delayed stale install
// (gen=1) arriving after S'(K, gen=2) must be REFUSED so the stored generation
// stays 2 — otherwise a later stale delete (gen=1) could match and wrongly
// remove the live entry. Verifies the per-key stored gen never regresses.
func TestStaleInstallDoesNotRegressStoredGen(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	installWithGenV4(ss, key, 2)
	installWithGenV4(ss, key, 1) // delayed stale install — must be refused
	if got := ss.stats.InstallsStaleIgnored.Load(); got != 1 {
		t.Fatalf("InstallsStaleIgnored = %d, want 1", got)
	}

	// The stored generation must still be 2, so a stale delete (gen=1) is
	// refused and the live session survives.
	ss.deleteClusterSyncedV4(key, 1)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("stale install rolled the stored generation back, letting a stale delete kill the live entry")
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 1 {
		t.Fatalf("DeletesStaleIgnored = %d, want 1", got)
	}
}

// TestSenderEchoesInstallGenerationV4 verifies the sender stamps a fresh,
// strictly-increasing generation on every install send and echoes the exact
// install generation on the matching delete (SMR fix #1). This is the property
// that makes a journaled delete strictly older than a re-synced replacement.
func TestSenderEchoesInstallGenerationV4(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.stats.Connected.Store(true)
	key := gen2170KeyV4()

	val := dataplane.SessionValue{}
	ss.stampInstallGenV4(key, &val)
	g1 := val.Generation
	if g1 == 0 {
		t.Fatal("first install generation must be non-zero")
	}

	val2 := dataplane.SessionValue{}
	ss.stampInstallGenV4(key, &val2)
	g2 := val2.Generation
	if g2 <= g1 {
		t.Fatalf("second install generation %d must be strictly greater than first %d", g2, g1)
	}

	// The delete echoes the LAST stamped generation for the key.
	if echoed := ss.takeDeleteGenV4(key); echoed != g2 {
		t.Fatalf("delete echoed generation %d, want last-installed %d", echoed, g2)
	}
	// After the echo the entry is evicted; a second delete returns 0 (legacy
	// fallback) rather than a stale value.
	if echoed := ss.takeDeleteGenV4(key); echoed != 0 {
		t.Fatalf("delete after eviction echoed %d, want 0", echoed)
	}
}

// TestGenerationMonotonicSameSecondSameSlot is the §3.3 trap: two installs of
// the same key get strictly increasing generations regardless of clock
// resolution — the case the old now_seconds<<16|slot SessionID could NOT
// distinguish.
func TestGenerationMonotonicSameSecondSameSlot(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	key := gen2170KeyV4()
	v1 := dataplane.SessionValue{}
	v2 := dataplane.SessionValue{}
	ss.stampInstallGenV4(key, &v1)
	ss.stampInstallGenV4(key, &v2)
	if v1.Generation == 0 || v2.Generation == 0 {
		t.Fatal("generations must be non-zero")
	}
	if v2.Generation <= v1.Generation {
		t.Fatalf("same-second/same-slot reuse must get strictly increasing generations: %d then %d", v1.Generation, v2.Generation)
	}
}

// TestFailoverDomainGenerationReStamp (SMR B1, unit-level model): after an
// ownership change the new owner re-installs an inherited key with its own
// (higher) generation, which re-stamps the stored generation. A delete the new
// owner then issues compares same-domain and applies; a stale cross-domain
// delete (older generation) does not wrongly remove a live flow.
func TestFailoverDomainGenerationReStamp(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// Old owner installed the inherited key with gen=100.
	installWithGenV4(ss, key, 100)
	// New owner re-syncs the inherited key with its own (higher) generation.
	installWithGenV4(ss, key, 250)

	// A stale delete from the OLD owner's domain (gen=100) must be refused.
	ss.deleteClusterSyncedV4(key, 100)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("a stale cross-domain delete removed the re-stamped live entry")
	}
	// The new owner's own delete (gen=250) applies.
	ss.deleteClusterSyncedV4(key, 250)
	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("the new owner's same-domain delete did not apply")
	}
}

// --- Wire round-trip / cross-version decode -------------------------------

// TestSessionWireRoundTripGenerationV4 verifies the trailing generation field
// encodes and decodes identically through the v4 session wire format.
func TestSessionWireRoundTripGenerationV4(t *testing.T) {
	key := gen2170KeyV4()
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, Generation: 0xDEADBEEFCAFE}
	payload := encodeSessionV4Payload(key, val)
	dKey, dVal, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if dKey != key {
		t.Fatalf("key mismatch: %+v vs %+v", dKey, key)
	}
	if dVal.Generation != val.Generation {
		t.Fatalf("generation round-trip mismatch: got %#x, want %#x", dVal.Generation, val.Generation)
	}
}

func TestSessionWireRoundTripGenerationV6(t *testing.T) {
	key := gen2170KeyV6()
	val := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, Generation: 0x0102030405060708}
	payload := encodeSessionV6Payload(key, val)
	dKey, dVal, ok := decodeSessionV6Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if dKey != key {
		t.Fatalf("key mismatch")
	}
	if dVal.Generation != val.Generation {
		t.Fatalf("generation round-trip mismatch: got %#x, want %#x", dVal.Generation, val.Generation)
	}
}

// TestDeleteWireRoundTripGeneration verifies the delete message carries the
// generation as a length-gated trailing uint64 (24/48-byte payload).
func TestDeleteWireRoundTripGeneration(t *testing.T) {
	key := gen2170KeyV4()
	msg := encodeDeleteV4(key, 0x1122334455667788)
	payload := msg[syncHeaderSize:]
	if len(payload) != 24 {
		t.Fatalf("v4 delete payload len = %d, want 24", len(payload))
	}
	if g := binary.LittleEndian.Uint64(payload[16:24]); g != 0x1122334455667788 {
		t.Fatalf("v4 delete generation mismatch: got %#x", g)
	}

	key6 := gen2170KeyV6()
	msg6 := encodeDeleteV6(key6, 0x8877665544332211)
	payload6 := msg6[syncHeaderSize:]
	if len(payload6) != 48 {
		t.Fatalf("v6 delete payload len = %d, want 48", len(payload6))
	}
	if g := binary.LittleEndian.Uint64(payload6[40:48]); g != 0x8877665544332211 {
		t.Fatalf("v6 delete generation mismatch: got %#x", g)
	}
}

// TestCrossVersionShortPayloadDecode: an OLD encoder's session payload (no
// trailing generation) must decode to Generation==0 on a NEW decoder, and the
// new (longer) payload must decode losslessly. This is the rolling-upgrade
// seam (#1961-class wire hazard).
func TestCrossVersionShortPayloadDecode(t *testing.T) {
	key := gen2170KeyV4()
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, Generation: 42}
	full := encodeSessionV4Payload(key, val)
	// Simulate an OLD encoder: drop the trailing 8-byte generation.
	short := full[:len(full)-8]
	_, dVal, ok := decodeSessionV4Payload(short)
	if !ok {
		t.Fatal("short (legacy) payload should still decode")
	}
	if dVal.Generation != 0 {
		t.Fatalf("legacy short payload should decode to Generation 0, got %d", dVal.Generation)
	}

	// An OLD delete decoder (16-byte payload) must tolerate the longer 24-byte
	// payload; and a NEW delete decoder reading a 16-byte (legacy) payload sees
	// generation 0.
	legacyDelete := encodeDeleteV4(key, 0)[syncHeaderSize:][:16]
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{key: {State: 1}}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.handleMessage(nil, syncMsgDeleteV4, legacyDelete)
	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("legacy 16-byte delete should still remove the session (gen=0 fallback)")
	}
}

// TestJournalFlushReplayRefusesStaleDelete is the end-to-end #2163 flush
// scenario: a delete is journaled at gen=1 (peer disconnected), the
// replacement S'(K) is synced at gen=2 over a healthy connection, then the
// journal flush replays the stale delete. S' must survive.
//
// It drives the receive side directly (the install + the journaled-delete
// replay both arrive on the wire) to model the cross-reconnect causality.
func TestJournalFlushReplayRefusesStaleDelete(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// The sender stamped D(K) with gen=1 at T0 (journaled). Model that as the
	// journaled delete wire message.
	journaledDelete := encodeDeleteV4(key, 1)[syncHeaderSize:]

	// T1: S'(K) is synced at gen=2 over a healthy connection and installed.
	syncedReplacement := func() []byte {
		v := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, Generation: 2}
		return encodeSessionV4Payload(key, v)
	}()
	ss.handleMessage(nil, syncMsgSessionV4, syncedReplacement)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("replacement S' should be installed")
	}

	// T2: the journal flush replays the stale delete.
	ss.handleMessage(nil, syncMsgDeleteV4, journaledDelete)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("journal-flush replay of the stale delete killed the live replacement S'")
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 1 {
		t.Fatalf("DeletesStaleIgnored = %d, want 1", got)
	}
}

// TestGenGuardConcurrentMaps stress-tests the sender- and receiver-side
// generation maps under concurrent access to surface any data race on
// genSentV4 / recvGenV4 (run with -race). It exercises the guard/echo helpers
// directly — the receiver apply path is single-threaded per connection in
// production, so this targets the maps' own locking, not the (non-thread-safe)
// mock session store.
func TestGenGuardConcurrentMaps(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)

	const workers = 8
	const perWorker = 500
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				key := dataplane.SessionKey{Protocol: 6, SrcPort: uint16(w + 1), DstPort: uint16(i + 1)}
				// Sender echo path.
				val := dataplane.SessionValue{}
				ss.stampInstallGenV4(key, &val)
				_ = ss.takeDeleteGenV4(key)
				// Receiver guard path.
				rec, apply := ss.installGenGuardV4(key, val.Generation)
				if apply {
					ss.recordInstalledGenV4(key, rec)
				}
				_ = ss.deleteGenGuardV4(key, val.Generation)
			}
		}(w)
	}
	wg.Wait()

	// Every key was install-then-delete-guarded at equal generation, so both
	// maps must be fully drained.
	ss.genSentMu.Lock()
	sentRemaining := len(ss.genSentV4)
	ss.genSentMu.Unlock()
	ss.recvGenMu.Lock()
	recvRemaining := len(ss.recvGenV4)
	ss.recvGenMu.Unlock()
	if sentRemaining != 0 {
		t.Fatalf("genSentV4 not drained: %d entries remain", sentRemaining)
	}
	if recvRemaining != 0 {
		t.Fatalf("recvGenV4 not drained: %d entries remain", recvRemaining)
	}
}
