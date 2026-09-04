package dataplane

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 K76 + K77, both in persistent_nat.go, and they land on opposite sides
// of the same architecture change.
//
// K77 is a fix: Save discarded every field but LastSeen when the key already
// existed, so a pool edit did not take effect until the old binding expired.
//
// K76 is a REFUTATION of its own stated fix. "Drop bindings whose pool is no
// longer configured in ClearPoolConfigs (or filter All()/render against
// poolConfigs)" reintroduces #8607's "No persistent NAT bindings" — see the
// note on ClearPoolConfigs, and the measurement in
// TestAPoolConfigFilterIsEmptyDuringEveryRecompile_8597 below.

func k77Binding(nat string, port uint16, to time.Duration, permit config.PersistentNATPermit) *PersistentNATBinding {
	return &PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.0.5"),
		SrcPort:  1000,
		NatIP:    netip.MustParseAddr(nat),
		NatPort:  port,
		PoolName: "p1",
		LastSeen: time.Now(),
		Timeout:  to,
		Permit:   permit,
	}
}

// K77. A re-save under the same key carries new facts about the SAME binding
// and must update them, not be reduced to a timestamp touch.
//
// The LastSeen refresh is deliberately NOT changed — see the note on Save. The
// first attempt at this row replaced the whole entry, which drops the caller-
// independent clock refresh TestPersistentNATTable_SaveUpdatesLastSeen pins.
func TestSaveReplacesAChangedMappingTimeoutAndPermit_8597(t *testing.T) {
	tbl := NewPersistentNATTable()
	tbl.Save(k77Binding("192.0.2.1", 5000, time.Hour, config.PersistentNATPermitTargetHost))

	// The pool is edited: new NAT address and port, shorter timeout, wider
	// permit scope. Same source and pool, so the same key.
	tbl.Save(k77Binding("198.51.100.9", 6000, time.Minute, config.PersistentNATPermitAnyRemoteHost))

	all := tbl.All()
	if len(all) != 1 {
		t.Fatalf("a re-save under the same key must not create a second binding: %d", len(all))
	}
	got := all[0]
	if got.NatIP.String() != "198.51.100.9" || got.NatPort != 6000 {
		t.Errorf("the mapping is stale: %s:%d, want 198.51.100.9:6000. The operator "+
			"edited the pool and show still reports the old translation (#8597 K77)",
			got.NatIP, got.NatPort)
	}
	if got.Timeout != time.Minute {
		t.Errorf("Timeout is stale: %s, want 1m — the show column counts down from "+
			"a lifetime the pool no longer grants (#8597 K77)", got.Timeout)
	}
	if got.PermitMode() != string(config.PersistentNATPermitAnyRemoteHost) {
		t.Errorf("Permit is stale: %s, want %s — the rendered remote scope is the "+
			"one the operator replaced (#8597 K77)",
			got.PermitMode(), config.PersistentNATPermitAnyRemoteHost)
	}
	// The identity half must be untouched: updating the mapping must not
	// relabel which binding this is.
	if got.SrcIP.String() != "10.0.0.5" || got.SrcPort != 1000 || got.PoolName != "p1" {
		t.Errorf("the binding's identity changed: %s:%d pool=%q",
			got.SrcIP, got.SrcPort, got.PoolName)
	}
}

// The other direction, so "replace" does not become "replace everything that
// looks similar": a different source port is a DIFFERENT binding.
func TestSaveStillKeysOnSourcePortAndPool_8597(t *testing.T) {
	tbl := NewPersistentNATTable()
	b1 := k77Binding("192.0.2.1", 5000, time.Hour, config.PersistentNATPermitTargetHost)
	b2 := k77Binding("192.0.2.1", 5001, time.Hour, config.PersistentNATPermitTargetHost)
	b2.SrcPort = 1001
	b3 := k77Binding("192.0.2.1", 5002, time.Hour, config.PersistentNATPermitTargetHost)
	b3.PoolName = "p2"
	tbl.Save(b1)
	tbl.Save(b2)
	tbl.Save(b3)
	if n := tbl.Len(); n != 3 {
		t.Fatalf("Len=%d, want 3: replacing on (SrcIP,SrcPort,Pool) must not collapse "+
			"distinct source ports or distinct pools onto one entry", n)
	}
}

// K76, REFUTATION PIN. ClearPoolConfigs must keep the bindings. If a future
// change drops them here, every commit blanks the show table until the next
// refresher tick — the #8607 false statement, made intermittent.
func TestClearPoolConfigsKeepsBindings_8597(t *testing.T) {
	tbl := NewPersistentNATTable()
	tbl.SetPoolConfig("p1", PersistentNATPoolInfo{Timeout: time.Hour})
	tbl.RegisterNATIP(netip.MustParseAddr("192.0.2.1"), "p1")
	tbl.Save(k77Binding("192.0.2.1", 5000, time.Hour, config.PersistentNATPermitTargetHost))

	tbl.ClearPoolConfigs()

	if n := tbl.Len(); n != 1 {
		t.Errorf("ClearPoolConfigs dropped %d binding(s). compileNAT calls it at the "+
			"TOP of every recompile and re-registers the surviving pools later, so "+
			"dropping bindings here empties `show security nat source "+
			"persistent-nat-table` after every commit until the #8607 refresher's "+
			"next tick — the exact false statement that issue removed (#8597 K76)",
			1-n)
	}
	// The pool config and the IP mapping must BOTH still be cleared — the
	// binding surviving is the point, not the config surviving.
	//
	// LookupPool needs both maps, so a bare "!ok" here cannot say WHICH one was
	// cleared and passes if either was: found by mutation, not by review. Each
	// map is therefore probed by restoring the OTHER one and asking again.
	nat := netip.MustParseAddr("192.0.2.1")
	if _, _, ok := tbl.LookupPool(nat); ok {
		t.Error("LookupPool still resolves after ClearPoolConfigs")
	}
	tbl.RegisterNATIP(nat, "p1")
	if _, _, ok := tbl.LookupPool(nat); ok {
		t.Error("poolConfigs SURVIVED ClearPoolConfigs: restoring only the IP " +
			"mapping made LookupPool resolve again, so a removed pool's timeout and " +
			"permit are still being served to preservePersistentNAT*")
	}

	// And the mirror, on a fresh table so the probe above cannot mask it.
	tbl2 := NewPersistentNATTable()
	tbl2.SetPoolConfig("p1", PersistentNATPoolInfo{Timeout: time.Hour})
	tbl2.RegisterNATIP(nat, "p1")
	tbl2.ClearPoolConfigs()
	tbl2.SetPoolConfig("p1", PersistentNATPoolInfo{Timeout: time.Hour})
	if _, _, ok := tbl2.LookupPool(nat); ok {
		t.Error("natIPToPool SURVIVED ClearPoolConfigs: restoring only the pool " +
			"config made LookupPool resolve again, so a NAT address that no longer " +
			"belongs to any pool still maps to one")
	}
}

// THE MEASUREMENT BEHIND THAT REFUSAL, rather than an assertion about it. The
// finding's other stated arm is "filter All()/render against poolConfigs". This
// reproduces the state compileNAT is in between its ClearPoolConfigs call and
// its re-registration — a state a renderer can observe, because the two take
// t.mu separately — and shows the filtered view is EMPTY while the bindings are
// all still live and correct.
func TestAPoolConfigFilterIsEmptyDuringEveryRecompile_8597(t *testing.T) {
	tbl := NewPersistentNATTable()
	tbl.SetPoolConfig("p1", PersistentNATPoolInfo{Timeout: time.Hour})
	tbl.RegisterNATIP(netip.MustParseAddr("192.0.2.1"), "p1")
	tbl.Save(k77Binding("192.0.2.1", 5000, time.Hour, config.PersistentNATPermitTargetHost))

	filtered := func() int {
		n := 0
		for _, b := range tbl.All() {
			if _, _, ok := tbl.LookupPool(b.NatIP); ok {
				n++
			}
		}
		return n
	}
	if filtered() != 1 {
		t.Fatal("the fixture does not render before the clear, so the assertion " +
			"below would pass for the wrong reason")
	}

	// compileNAT's first act on every commit. The pool "p1" is still configured
	// and WILL be re-registered — but not yet, and not under the same lock.
	tbl.ClearPoolConfigs()

	if got := filtered(); got != 0 {
		t.Fatalf("filtered=%d — this cell is meant to DEMONSTRATE the emptiness, so "+
			"a non-zero result means the model of compileNAT's sequence is wrong "+
			"and the refutation on ClearPoolConfigs needs re-deriving", got)
	}
	t.Log("a poolConfigs-filtered render answers 0 bindings here while 1 live " +
		"binding exists — for a pool that is still configured. That window opens " +
		"on every commit, which is why K76's stated fix is refused (#8607)")
}
