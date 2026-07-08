package vrrp

import (
	"net"
	"testing"
	"time"
)

// Tests for RFC 5798 §6.1/§6.4.2 Master_Adver_Interval adoption (#4061). A
// BACKUP must compute Master_Down_Interval + Skew_Time from the interval the
// MASTER advertises (learned from the received advert's Max Adver Int field),
// NOT from its own locally-configured AdvertiseInterval. These tests inject an
// advert with a specific Max Adver Int and assert the learned interval and the
// resulting master-down timer.
//
// RED-on-revert: reverting the fix (masterDownInterval computing from the local
// cfg.AdvertiseInterval) makes the master-down assertion below fail because the
// backup's local interval (30 ms) differs from the master's advertised interval
// (1000 ms).

// newMasterIntervalTestInstance builds a BACKUP instance with a chosen local
// advertise interval and priority, GARP suppressed so no stray goroutine runs.
func newMasterIntervalTestInstance(t *testing.T, priority, localAdvertMS int) *vrrpInstance {
	t.Helper()
	vi := newInstance(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          priority,
		Preempt:           true,
		AdvertiseInterval: localAdvertMS,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 16), nil)
	vi.setLocalIP(net.IPv4(10, 0, 0, 1))
	vi.suppressGARP.Store(true)
	vi.setState(StateBackup)
	return vi
}

// TestMasterAdverInterval_LearnedFromAdvert verifies that receiving a master
// advertisement with a Max Adver Int different from the backup's local interval
// makes the backup adopt the MASTER's interval and compute the master-down
// timer from it. This is the core #4061 assertion — it goes RED on revert.
func TestMasterAdverInterval_LearnedFromAdvert(t *testing.T) {
	// Backup configured with a 30 ms local interval, priority 100.
	vi := newMasterIntervalTestInstance(t, 100, 30)

	// Master advertises 1000 ms → Max Adver Int = 100 centiseconds.
	// (Wire is centiseconds/10 ms units; 1000 ms = 100 cs.)
	pkt := &VRRPPacket{
		VRID:         101,
		Priority:     120, // >= ours → worthy master
		MaxAdvertInt: 100, // 100 cs = 1000 ms
		SrcIP:        net.IPv4(10, 0, 0, 2),
	}

	masterDown := time.NewTimer(time.Hour)
	defer masterDown.Stop()
	preemptHold := time.NewTimer(time.Hour)
	defer preemptHold.Stop()
	vi.handleBackupRx(pkt, masterDown, preemptHold)

	// 1) The learned interval must be the master's 1000 ms, not the local 30 ms.
	vi.mu.RLock()
	learned := vi.masterAdverInterval
	vi.mu.RUnlock()
	if learned != 1000*time.Millisecond {
		t.Fatalf("masterAdverInterval = %v, want 1000ms (learned from Max Adver Int, not local 30ms)", learned)
	}

	// 2) masterDownInterval must be computed from the LEARNED 1000 ms:
	//    Skew = (256-100)*1000ms/256 = 609.375ms → 609ms (integer Duration math)
	//    Master_Down = 3*1000ms + 609ms = 3609ms.
	// If reverted to the local 30 ms interval it would be:
	//    Skew = (256-100)*30ms/256 = 18ms; Master_Down = 90+18 = 108ms.
	want := 3*1000*time.Millisecond + time.Duration(256-100)*1000*time.Millisecond/256
	if got := vi.masterDownInterval(); got != want {
		t.Fatalf("masterDownInterval() = %v, want %v (from master's advertised 1000ms, NOT local 30ms → ~108ms on revert)", got, want)
	}

	// Sanity: the reverted (local-interval) value must be materially different,
	// so this test genuinely discriminates the fix.
	localSkew := time.Duration(256-100) * 30 * time.Millisecond / 256
	revertValue := 3*30*time.Millisecond + localSkew
	if want == revertValue {
		t.Fatalf("test does not discriminate: learned (%v) == local (%v)", want, revertValue)
	}
}

// TestMasterAdverInterval_CentisecondConversion checks the wire conversion:
// Max Adver Int is centiseconds (10 ms units). A 3-cs advert (the 30 ms RETH
// default) must learn 30 ms exactly, so the common matching-interval case is
// unchanged and the ~60 ms failover is preserved.
func TestMasterAdverInterval_CentisecondConversion(t *testing.T) {
	cases := []struct {
		cs   uint16
		want time.Duration
	}{
		{3, 30 * time.Millisecond},     // 30 ms RETH default
		{100, 1000 * time.Millisecond}, // 1 s default
		{5, 50 * time.Millisecond},     // reth-advertise-interval 50
		{200, 2000 * time.Millisecond}, // 2 s
	}
	for _, c := range cases {
		vi := newMasterIntervalTestInstance(t, 100, 30)
		vi.recordMasterAdvert(&VRRPPacket{Priority: 100, MaxAdvertInt: c.cs})
		vi.mu.RLock()
		got := vi.masterAdverInterval
		vi.mu.RUnlock()
		if got != c.want {
			t.Errorf("MaxAdvertInt=%d cs: learned %v, want %v", c.cs, got, c.want)
		}
	}
}

// TestMasterAdverInterval_MatchingIntervalUnchanged verifies the common case:
// when the master advertises the SAME interval the backup is configured with
// (30 ms), the master-down timer is exactly what the old local-only computation
// produced — no regression to the ~60 ms failover behavior.
func TestMasterAdverInterval_MatchingIntervalUnchanged(t *testing.T) {
	vi := newMasterIntervalTestInstance(t, 100, 30)

	// Before any advert the fallback is the local interval.
	local := vi.masterDownInterval()
	wantLocal := 3*30*time.Millisecond + time.Duration(256-100)*30*time.Millisecond/256
	if local != wantLocal {
		t.Fatalf("pre-advert masterDownInterval() = %v, want local fallback %v", local, wantLocal)
	}

	// Master advertises the matching 30 ms (3 cs). Master-down must be identical.
	vi.recordMasterAdvert(&VRRPPacket{Priority: 120, MaxAdvertInt: 3})
	if got := vi.masterDownInterval(); got != wantLocal {
		t.Fatalf("matching-interval masterDownInterval() = %v, want unchanged %v", got, wantLocal)
	}
}

// TestMasterAdverInterval_ZeroFieldIgnored verifies a malformed advert with a
// zero Max Adver Int does NOT set a zero interval (which would collapse the
// master-down timer to Skew_Time only and cause flapping) — the local interval
// stays the fallback.
func TestMasterAdverInterval_ZeroFieldIgnored(t *testing.T) {
	vi := newMasterIntervalTestInstance(t, 100, 30)
	vi.recordMasterAdvert(&VRRPPacket{Priority: 120, MaxAdvertInt: 0})
	vi.mu.RLock()
	learned := vi.masterAdverInterval
	vi.mu.RUnlock()
	if learned != 0 {
		t.Fatalf("masterAdverInterval = %v, want 0 (zero Max Adver Int must be ignored)", learned)
	}
	// Falls back to the local 30 ms interval.
	wantLocal := 3*30*time.Millisecond + time.Duration(256-100)*30*time.Millisecond/256
	if got := vi.masterDownInterval(); got != wantLocal {
		t.Fatalf("masterDownInterval() = %v, want local fallback %v after zero-field advert", got, wantLocal)
	}
}

// TestMasterAdverInterval_LowIntervalClamped verifies the #4548 floor: a peer
// advertising a pathologically-low Max Adver Int (=1 cs = 10 ms) is clamped up
// to the local node's configured advertise interval, so the backup's
// Master_Down_Interval (and the preempt-gate staleness horizons that share the
// same effectiveAdvertInterval math) never collapse below the safe cadence and
// flap mastership on ordinary jitter.
//
// RED-on-revert: dropping the clamp lets masterAdverInterval adopt 10 ms, which
// drives masterDownInterval to ~36 ms; the exact-equality assertion against the
// 30 ms-floor computation fails on revert.
func TestMasterAdverInterval_LowIntervalClamped(t *testing.T) {
	vi := newMasterIntervalTestInstance(t, 100, 30) // local 30 ms, priority 100

	// Buggy/misconfigured peer advertises Max Adver Int=1 cs = 10 ms.
	vi.recordMasterAdvert(&VRRPPacket{Priority: 120, MaxAdvertInt: 1})

	// The learned interval is clamped UP to the 30 ms local floor, not 10 ms.
	vi.mu.RLock()
	learned := vi.masterAdverInterval
	vi.mu.RUnlock()
	if learned != 30*time.Millisecond {
		t.Fatalf("masterAdverInterval = %v, want 30ms (clamped up from 10ms to local floor)", learned)
	}

	// masterDownInterval is the 30 ms-floor computation, materially larger than
	// the ~36 ms an un-clamped 10 ms interval would produce.
	wantFloored := 3*30*time.Millisecond + time.Duration(256-100)*30*time.Millisecond/256
	if got := vi.masterDownInterval(); got != wantFloored {
		t.Fatalf("masterDownInterval() = %v, want %v (from 30ms floor, NOT ~36ms on revert)", got, wantFloored)
	}
	revert := 3*10*time.Millisecond + time.Duration(256-100)*10*time.Millisecond/256
	if wantFloored <= revert {
		t.Fatalf("test does not discriminate: floored %v <= reverted %v", wantFloored, revert)
	}
	if revert >= 90*time.Millisecond {
		t.Fatalf("sanity: reverted masterDown %v unexpectedly >= 90ms", revert)
	}
}

// TestMasterAdverInterval_FloorPreserves30msFailover verifies the clamp does NOT
// touch the intended 30 ms RETH fast-failover default: a peer advertising the
// matching 30 ms (3 cs) is adopted unchanged (floor == learned == 30 ms) and the
// master-down timer is the same value the node runs at without the clamp.
func TestMasterAdverInterval_FloorPreserves30msFailover(t *testing.T) {
	vi := newMasterIntervalTestInstance(t, 100, 30)
	vi.recordMasterAdvert(&VRRPPacket{Priority: 120, MaxAdvertInt: 3}) // 3 cs = 30 ms
	vi.mu.RLock()
	learned := vi.masterAdverInterval
	vi.mu.RUnlock()
	if learned != 30*time.Millisecond {
		t.Fatalf("masterAdverInterval = %v, want 30ms unchanged (floor must not alter the RETH default)", learned)
	}
	want := 3*30*time.Millisecond + time.Duration(256-100)*30*time.Millisecond/256
	if got := vi.masterDownInterval(); got != want {
		t.Fatalf("masterDownInterval() = %v, want %v (30ms failover preserved)", got, want)
	}
}

// TestMasterAdverInterval_LegitLowConfigNotOverClamped verifies the floor is the
// node's OWN configured interval, not a fixed 30 ms: an operator who configures
// reth-advertise-interval=10 (the schema minimum, pkg/config/schema_chassis.go)
// on both nodes still runs at 10 ms — a matching 10 ms advert is adopted
// unchanged, not forced up to 30 ms.
func TestMasterAdverInterval_LegitLowConfigNotOverClamped(t *testing.T) {
	vi := newMasterIntervalTestInstance(t, 100, 10)                    // local 10 ms
	vi.recordMasterAdvert(&VRRPPacket{Priority: 120, MaxAdvertInt: 1}) // 1 cs = 10 ms
	vi.mu.RLock()
	learned := vi.masterAdverInterval
	vi.mu.RUnlock()
	if learned != 10*time.Millisecond {
		t.Fatalf("masterAdverInterval = %v, want 10ms (legit 10ms config must not be over-clamped)", learned)
	}
}

// TestMasterAdverInterval_SlowerMasterNotClamped verifies the floor only clamps
// the LOW side: a master advertising SLOWER than the local interval (the #4061
// anti-premature-failover case) is adopted unchanged.
func TestMasterAdverInterval_SlowerMasterNotClamped(t *testing.T) {
	vi := newMasterIntervalTestInstance(t, 100, 30)                      // local 30 ms
	vi.recordMasterAdvert(&VRRPPacket{Priority: 120, MaxAdvertInt: 100}) // 100 cs = 1000 ms
	vi.mu.RLock()
	learned := vi.masterAdverInterval
	vi.mu.RUnlock()
	if learned != 1000*time.Millisecond {
		t.Fatalf("masterAdverInterval = %v, want 1000ms (slower master adopted unchanged, no clamp)", learned)
	}
}

// TestMasterAdverInterval_LowerPriorityAdvertNotAdopted verifies that a
// priority-0 (resignation) advert does not update the learned interval — the
// recordMasterAdvert contract skips priority-0 (#2082), and a zero interval
// must never leak in through that path.
func TestMasterAdverInterval_Priority0NotAdopted(t *testing.T) {
	vi := newMasterIntervalTestInstance(t, 100, 30)
	// Seed a learned interval from a real master.
	vi.recordMasterAdvert(&VRRPPacket{Priority: 120, MaxAdvertInt: 100})
	// A priority-0 resign advert (even with a bogus interval) must not disturb it.
	vi.recordMasterAdvert(&VRRPPacket{Priority: 0, MaxAdvertInt: 5})
	vi.mu.RLock()
	learned := vi.masterAdverInterval
	vi.mu.RUnlock()
	if learned != 1000*time.Millisecond {
		t.Fatalf("masterAdverInterval = %v, want 1000ms preserved (priority-0 advert must not update it)", learned)
	}
}
