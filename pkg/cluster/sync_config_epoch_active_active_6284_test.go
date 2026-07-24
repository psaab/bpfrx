package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #6284 item 1 — active/active directional coverage of the #5274 config-epoch
// guard.
//
// Config sync is UNIDIRECTIONAL: only the rg0ConfigSyncAuthority pushes config
// (QueueConfig -> nextConfigGen), so configGenCounter (the value the SENDER
// stamps onto every synced session, stampInstallGen*) advances ONLY on the
// authority. A node's receive high-water (lastAppliedConfigGen) advances only
// when IT applies a peer-pushed config (recordAppliedConfigGen). Those are the
// two ends of ONE sender->receiver namespace, and the guard (configEpochStale)
// compares an install's stamped epoch against the RECEIVER's high-water.
//
// The consequence, documented in docs/session-sync-architecture.md and #6284:
//   - config-authority -> peer direction: the authority's stamp advances and
//     the peer's high-water advances, so the guard PROTECTS (a stale permit is
//     refused). Active/passive is wholly this direction (primary owns all
//     sessions AND is the config authority).
//   - non-authority -> authority direction (only reachable active/active): the
//     non-authority stamps with its FROZEN boot-seed epoch and the authority's
//     receive high-water never advances (it applies no peer config), so the
//     guard is INERT (fail-OPEN — no false reject, but no stale-permit
//     protection either).
//
// These tests pin BOTH halves of that directional correctness on the REAL
// apply/stamp code:
//   - the PROTECTED half FAILS RED if configEpochStale is neutralized (the
//     frozen-epoch install would then be admitted against the advanced
//     high-water), and RED if the guard is mis-"fixed" to compare against the
//     local send counter (configGenCounter) instead of lastAppliedConfigGen;
//   - the INERT half pins the documented fail-OPEN behavior at the authority;
//   - the ROOT-CAUSE block FAILS RED if a future item-1 fix couples
//     configGenCounter to config apply (recordAppliedConfigGen advancing the
//     send stamp), or if stampInstallGen* stops sourcing the epoch from
//     configGenCounter.

// TestActiveActiveConfigEpochDirectionalCoverage6284 drives the SAME frozen
// non-authority epoch into two receivers with OPPOSITE outcomes, then pins the
// sender-side root cause that makes the non-authority stamp frozen.
func TestActiveActiveConfigEpochDirectionalCoverage6284(t *testing.T) {
	// A non-authority node's synced-out sessions all carry the SAME frozen
	// boot-seed epoch, because it never sends config to advance its counter.
	const frozenEpoch = 3

	// --- PROTECTED direction (config-authority -> peer) ---
	// This receiver APPLIED a strictly-newer peer config, so its receive
	// high-water advanced to 10 (the same namespace the authority stamps in).
	// A session stamped with the older epoch 3 is a stale permit the newer
	// config may deny — it MUST be refused.
	dpApplied := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ssApplied := NewSessionSync(":0", "10.0.0.2:4785", dpApplied)
	ssApplied.recordAppliedConfigGen(10) // real receiver high-water advance
	if got := ssApplied.lastAppliedConfigGen.Load(); got != 10 {
		t.Fatalf("recordAppliedConfigGen(10): lastAppliedConfigGen = %d, want 10", got)
	}
	protectedKey := configEpochKeyV4(60001)
	installWithConfigEpochV4(ssApplied, protectedKey, frozenEpoch) // 3 < applied 10 -> REFUSE
	if _, ok := dpApplied.v4sessions[protectedKey]; ok {
		t.Fatal("config-authority->peer direction: a frozen-epoch(3) install must be REFUSED once this node applied a newer config(10) — the #5274 guard covers this direction")
	}
	if got := ssApplied.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 1 after the protected-direction reject", got)
	}

	// --- INERT direction (non-authority -> authority), item-1 fail-OPEN ---
	// This receiver IS the config authority: it never APPLIES a peer config, so
	// its receive high-water stays 0. Its OWN send counter is advanced far past
	// the peer's frozen stamp (local commits), but the guard keys off the
	// receive high-water, NOT the send counter — so the SAME frozen-epoch(3)
	// session is ADMITTED (max(fence 0, applied 0) = 0; 3 < 0 is false).
	dpAuth := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ssAuth := NewSessionSync(":0", "10.0.0.2:4785", dpAuth)
	ssAuth.configGenCounter.Store(100) // authority advanced its OWN send counter via local commits
	// ssAuth.lastAppliedConfigGen deliberately left at 0 (authority applies no peer push).
	inertKey := configEpochKeyV4(60002)
	installWithConfigEpochV4(ssAuth, inertKey, frozenEpoch) // barrier 0 -> ADMIT
	if _, ok := dpAuth.v4sessions[inertKey]; !ok {
		t.Fatal("non-authority->authority direction (item-1): the frozen-epoch(3) install must be ADMITTED at the authority (receive high-water 0) — documented fail-OPEN; the guard must key off lastAppliedConfigGen, not the local configGenCounter(100)")
	}
	if got := ssAuth.stats.SessionsStaleConfigIgnored.Load(); got != 0 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 0 at the authority (guard inert for this direction)", got)
	}

	// --- ROOT CAUSE: why the non-authority stamp is frozen ---
	// On a non-authority node, applying peer configs advances the RECEIVE
	// high-water but must NOT advance the SEND-stamp counter, so every session
	// it syncs out carries the frozen boot-seed epoch (which is exactly why the
	// authority admits them, above).
	dpB := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	ssB := NewSessionSync(":0", "10.0.0.2:4785", dpB)
	ssB.configGenCounter.Store(frozenEpoch) // frozen boot seed; this node never sends config
	ssB.recordAppliedConfigGen(10)          // applies the authority's config (real path)
	ssB.recordAppliedConfigGen(11)          // and its next commit
	if got := ssB.lastAppliedConfigGen.Load(); got != 11 {
		t.Fatalf("recordAppliedConfigGen advanced receive high-water to %d, want 11", got)
	}
	if got := ssB.configGenCounter.Load(); got != frozenEpoch {
		t.Fatalf("config apply must NOT advance the send-stamp counter (item-1 directional scope, #5274 deliberately unidirectional): configGenCounter = %d, want frozen %d", got, frozenEpoch)
	}
	var ownV4 dataplane.SessionValue
	ssB.stampInstallGenV4(configEpochKeyV4(60003), &ownV4)
	if ownV4.ConfigEpoch != frozenEpoch {
		t.Fatalf("non-authority node must stamp its OWN synced-out sessions with the frozen boot-seed epoch %d (not the receive high-water 11), got %d", frozenEpoch, ownV4.ConfigEpoch)
	}
	var ownV6 dataplane.SessionValueV6
	ssB.stampInstallGenV6(configEpochKeyV6(60004), &ownV6)
	if ownV6.ConfigEpoch != frozenEpoch {
		t.Fatalf("non-authority node v6 stamp = %d, want frozen boot-seed epoch %d", ownV6.ConfigEpoch, frozenEpoch)
	}
}

// TestActiveActiveConfigEpochDirectionalCoverage6284V6 mirrors the protected +
// inert directional pair on the v6 install path (installClusterSyncedV6). The
// guard body is shared, but this proves the v6 admission honors the same
// directional outcome for an identical frozen epoch.
func TestActiveActiveConfigEpochDirectionalCoverage6284V6(t *testing.T) {
	const frozenEpoch = 3

	// PROTECTED: applied a newer config -> refuse the frozen-epoch install.
	dpApplied := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ssApplied := NewSessionSync(":0", "10.0.0.2:4785", dpApplied)
	ssApplied.recordAppliedConfigGen(10)
	protectedKey := configEpochKeyV6(60101)
	installWithConfigEpochV6(ssApplied, protectedKey, frozenEpoch)
	if _, ok := dpApplied.v6sessions[protectedKey]; ok {
		t.Fatal("config-authority->peer direction (v6): frozen-epoch(3) install must be REFUSED after applying config(10)")
	}
	if got := ssApplied.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 1 after the v6 protected-direction reject", got)
	}

	// INERT: authority (receive high-water 0) admits the same frozen epoch.
	dpAuth := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ssAuth := NewSessionSync(":0", "10.0.0.2:4785", dpAuth)
	ssAuth.configGenCounter.Store(100)
	inertKey := configEpochKeyV6(60102)
	installWithConfigEpochV6(ssAuth, inertKey, frozenEpoch)
	if _, ok := dpAuth.v6sessions[inertKey]; !ok {
		t.Fatal("non-authority->authority direction (v6, item-1): frozen-epoch(3) install must be ADMITTED at the authority (receive high-water 0) — documented fail-OPEN")
	}
	if got := ssAuth.stats.SessionsStaleConfigIgnored.Load(); got != 0 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 0 at the v6 authority (guard inert)", got)
	}
}
