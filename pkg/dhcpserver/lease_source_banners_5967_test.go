package dhcpserver

import (
	"strings"
	"testing"
)

// TestDegradedBanners_5967 pins the #5967 shared banner-selection helper: emit
// one banner per DEGRADED family (v4 then v6), collapse an EXACT duplicate to a
// single line, and emit nothing for a healthy source. This is the single source
// of truth both the gRPC `show dhcp server` handler and the in-process CLI now
// consume, so a v6-specific detail is never dropped when v4 is also degraded.
func TestDegradedBanners_5967(t *testing.T) {
	healthy := LeaseSource{Origin: leaseSourceMemfile}
	deg4 := LeaseSource{Origin: leaseSourceMemfile, Degraded: true, Detail: "v4 sibling unreadable"}
	deg6 := LeaseSource{Origin: leaseSourceMemfile, Degraded: true, Detail: "v6 sibling unreadable"}
	sameAs4 := LeaseSource{Origin: leaseSourceMemfileFallback, Degraded: true, Detail: "v4 sibling unreadable"}

	t.Run("both distinct → two lines", func(t *testing.T) {
		got := DegradedBanners(deg4, deg6)
		if len(got) != 2 {
			t.Fatalf("want 2 banner lines, got %d: %#v", len(got), got)
		}
		if !strings.Contains(got[0], "v4 sibling") || !strings.Contains(got[1], "v6 sibling") {
			t.Fatalf("banners out of order / missing detail: %#v", got)
		}
	})

	t.Run("both degraded identical detail → collapsed to one", func(t *testing.T) {
		got := DegradedBanners(deg4, sameAs4)
		if len(got) != 1 {
			t.Fatalf("exact-duplicate banner must collapse to 1 line, got %d: %#v", len(got), got)
		}
	})

	t.Run("only v6 degraded → v6 line", func(t *testing.T) {
		got := DegradedBanners(healthy, deg6)
		if len(got) != 1 || !strings.Contains(got[0], "v6 sibling") {
			t.Fatalf("want the v6 banner only, got %#v", got)
		}
	})

	t.Run("only v4 degraded → v4 line", func(t *testing.T) {
		got := DegradedBanners(deg4, healthy)
		if len(got) != 1 || !strings.Contains(got[0], "v4 sibling") {
			t.Fatalf("want the v4 banner only, got %#v", got)
		}
	})

	t.Run("both healthy → no lines", func(t *testing.T) {
		if got := DegradedBanners(healthy, healthy); len(got) != 0 {
			t.Fatalf("healthy sources must emit no banner, got %#v", got)
		}
	})
}
