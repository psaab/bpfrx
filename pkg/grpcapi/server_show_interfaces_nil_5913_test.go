// #5913: the `show interfaces extensive` and `show interfaces detail` text
// presenters build their config lookup maps with a raw
// `range cfg.Interfaces.Interfaces` (reading `ifc.Name` / `ifc.Description`),
// the SAME present-but-nil InterfaceConfig nil-deref class as #5813/#5910 in the
// SAME file #5910 patched (showVLANs / showZonesDetail). The tolerant load / HA
// config-sync path admits present-but-nil map values (#3494/#5068), so a routine
// `show interfaces extensive|detail` against a peer-synced config panicked the
// in-process daemon.
//
// Both config-map-build loops now walk via config.RangeInterfaces (the shared
// nil-safe iterator), which SKIPS present-but-nil slots. These two presenters
// call netlink.LinkList() (real kernel) — the same real-presenter path the
// #4328 reth tests already drive and assert err==nil against, so the map-build
// loop (which runs whenever LinkList succeeds) is reachable directly.
//
// The presenters render LIVE kernel traffic counters, so two sequential renders
// are not byte-identical; the assertions therefore pin behavior that does NOT
// depend on volatile counters: no panic on the nil slot, the nil key never
// leaks, and a valid config Description for a real kernel link still surfaces
// through the guarded walk.
//
// FAIL-ON-REVERT: restoring either raw `range cfg.Interfaces.Interfaces` makes
// the injected present-but-nil slot deref `ifc.Name`/`ifc.Description` and panic;
// require5913NoPanic turns that into a test FAILURE rather than a crashed run.
package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// require5913NoPanic fails the test (rather than crashing the run) if fn panics,
// naming the #5913 nil-guard regression.
func require5913NoPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked (nil-guard regression #5913): %v", name, r)
		}
	}()
	fn()
}

// firstNonLoopbackLink returns the name of a real non-"lo" kernel link, or ""
// if the host exposes only loopback. The presenters SKIP "lo" and only emit a
// config Description when the config interface name matches a kernel link, so a
// real link name lets the test assert that valid config DATA still flows through
// the guarded walk (not merely that it doesn't panic).
func firstNonLoopbackLink(t *testing.T) string {
	t.Helper()
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("netlink.LinkList() error = %v (the presenters depend on it)", err)
	}
	for _, l := range links {
		if n := l.Attrs().Name; n != "" && n != "lo" {
			return n
		}
	}
	return ""
}

// nilSlotConfig builds a config with valid interface slots plus a present-but-nil
// InterfaceConfig slot (the tolerant load / HA config-sync shape). When a real
// kernel link exists, one valid slot is named after it and given a distinctive
// Description so the presenter (which only surfaces config for interfaces that
// appear in the netlink walk) actually renders it.
func nilSlotConfig(realIf, desc string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/9":        {Name: "ge-0/0/9", Description: "unmatched-valid-5913"},
		"zz-5913-nil-ifc": nil, // present-but-nil (tolerant path) — the nil-deref trigger
	}
	if realIf != "" {
		cfg.Interfaces.Interfaces[realIf] = &config.InterfaceConfig{Name: realIf, Description: desc}
	}
	return cfg
}

// TestShowInterfacesExtensiveNilSlots5913 drives the REAL showInterfacesExtensive
// presenter against a config carrying a present-but-nil InterfaceConfig alongside
// valid slots. The guarded walk must (a) not panic, (b) not leak the nil slot's
// key, and (c) still surface a valid config slot's Description when it matches a
// real kernel link.
func TestShowInterfacesExtensiveNilSlots5913(t *testing.T) {
	realIf := firstNonLoopbackLink(t)
	const desc = "xpf-5913-extensive-desc"
	cfg := nilSlotConfig(realIf, desc)

	var buf strings.Builder
	require5913NoPanic(t, "showInterfacesExtensive", func() {
		if err := (&Server{}).showInterfacesExtensive(cfg, "", &buf); err != nil {
			t.Fatalf("showInterfacesExtensive error = %v", err)
		}
	})
	out := buf.String()
	if strings.Contains(out, "zz-5913-nil-ifc") {
		t.Fatalf("present-but-nil InterfaceConfig key leaked into extensive output:\n%s", out)
	}
	if realIf != "" && !strings.Contains(out, desc) {
		t.Fatalf("valid config Description for kernel link %q dropped by the guarded walk:\n%s", realIf, out)
	}
}

// TestShowInterfacesDetailNilSlots5913 drives the REAL showInterfacesDetail
// presenter with the same guarantees. The detail loop reads
// `ifc.Description`/`ifc.Name`, so a raw walk nil-derefs on the nil slot.
func TestShowInterfacesDetailNilSlots5913(t *testing.T) {
	realIf := firstNonLoopbackLink(t)
	const desc = "xpf-5913-detail-desc"
	cfg := nilSlotConfig(realIf, desc)

	var buf strings.Builder
	require5913NoPanic(t, "showInterfacesDetail", func() {
		if err := (&Server{}).showInterfacesDetail(cfg, "", &buf); err != nil {
			t.Fatalf("showInterfacesDetail error = %v", err)
		}
	})
	out := buf.String()
	if strings.Contains(out, "zz-5913-nil-ifc") {
		t.Fatalf("present-but-nil InterfaceConfig key leaked into detail output:\n%s", out)
	}
	if realIf != "" && !strings.Contains(out, desc) {
		t.Fatalf("valid config Description for kernel link %q dropped by the guarded walk:\n%s", realIf, out)
	}
}
