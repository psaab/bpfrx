package grpcapi

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #1152 regression: showPersistentNATDetail used to call b.NatIP.As4()
// unconditionally, which panics on any v6 PersistentNATBinding. The fix
// switched to a unified netip.Addr-keyed sessionCounts map.
func TestShowPersistentNATDetailDoesNotPanicOnV6Binding(t *testing.T) {
	dp := dataplane.New()
	pnat := dp.GetPersistentNAT()
	if pnat == nil {
		t.Fatal("GetPersistentNAT() = nil")
	}
	// Seed a v6 binding — this would have hit b.NatIP.As4()
	// pre-fix and panicked.
	v6 := netip.MustParseAddr("2001:559:8585:80::200")
	src := netip.MustParseAddr("2001:559:8585:bf01::102")
	pnat.Save(&dataplane.PersistentNATBinding{
		SrcIP:    src,
		SrcPort:  12345,
		NatIP:    v6,
		NatPort:  40000,
		PoolName: "pool-v6",
		LastSeen: time.Now(),
		Timeout:  600 * time.Second,
	})

	s := &Server{dp: dp}
	var buf strings.Builder
	// Pre-fix this would panic. Post-fix it renders the binding with
	// 0 sessions (IsLoaded() is false so IterateSessions is a no-op,
	// but the b.NatIP code path that used to panic is exercised).
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("showPersistentNATDetail panicked on v6 binding: %v", r)
		}
	}()
	s.showPersistentNATDetail(&buf)

	out := buf.String()
	if !strings.Contains(out, "2001:559:8585:80::200") {
		t.Fatalf("output = %q, want v6 NatIP rendered", out)
	}
	if !strings.Contains(out, "Total persistent NAT bindings: 1") {
		t.Fatalf("output = %q, want 1 binding count", out)
	}
}
