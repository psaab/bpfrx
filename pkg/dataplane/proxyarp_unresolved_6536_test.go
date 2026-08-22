package dataplane

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

// TestReconcileProxyARP_LinkResolutionFallbackKeepsEnabledEntry is the
// dataplane half of the #6536 fail-on-revert coverage.
//
// The enabled set returned here is the daemon's ONLY input to the #2475
// responder teardown diff, so an ifindex that drops out of it is disabled and
// forgotten. Every ifindex reaching the sysctl step was built from cfg, i.e. it
// is by construction STILL CONFIGURED — a netlink LinkByIndex failure says
// nothing about the config. Pre-fix the failure was logged and the entry
// dropped, making the two indistinguishable; the caller-supplied name now keeps
// the entry (and re-asserts the sysctl under the name the caller resolved the
// ifindex from).
//
// The `no-fallback-name` row keeps the pre-#6536 drop behaviour bound for
// callers that supply no name, so the fallback is not mistaken for an
// unconditional "never drop".
func TestReconcileProxyARP_LinkResolutionFallbackKeepsEnabledEntry(t *testing.T) {
	const ifindex = 4242

	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0/0/1", Addresses: []string{"10.0.2.50/32"}},
	}
	ifaceMap := map[string]int{"ge-0/0/1": ifindex}

	tests := []struct {
		name        string
		ifaceNames  map[int]string
		wantEnabled string // "" => the interface must be absent
	}{
		{
			name:        "caller-supplied-name-retains-entry",
			ifaceNames:  map[int]string{ifindex: "ge-0-0-1"},
			wantEnabled: "ge-0-0-1",
		},
		{
			name:        "no-fallback-name",
			ifaceNames:  nil,
			wantEnabled: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Transient netlink failure resolving the ifindex back to a link.
			prevLink := linkByIndexSeam
			linkByIndexSeam = func(int) (netlink.Link, error) {
				return nil, errors.New("no such device")
			}
			t.Cleanup(func() { linkByIndexSeam = prevLink })

			// Keep the neighbor operations off the host.
			prevList, prevSet, prevDel := neighListSeam, neighSetSeam, neighDelSeam
			neighListSeam = func(int, int) ([]netlink.Neigh, error) { return nil, nil }
			neighSetSeam = func(*netlink.Neigh) error { return nil }
			neighDelSeam = func(*netlink.Neigh) error { return nil }
			t.Cleanup(func() {
				neighListSeam, neighSetSeam, neighDelSeam = prevList, prevSet, prevDel
			})

			var wrote []string
			prevSysctl := proxyARPSysctlSeam
			proxyARPSysctlSeam = func(iface string, _ int, enable bool) error {
				if enable {
					wrote = append(wrote, iface)
				}
				return nil
			}
			t.Cleanup(func() { proxyARPSysctlSeam = prevSysctl })

			_, enabled, err := ReconcileProxyARP(cfg, ifaceMap, nil, tc.ifaceNames)
			if err != nil {
				t.Fatalf("ReconcileProxyARP: %v", err)
			}

			if tc.wantEnabled == "" {
				if len(enabled) != 0 {
					t.Fatalf("enabled set = %v, want empty (no caller-supplied name to fall back to)", enabled)
				}
				return
			}
			fams, ok := enabled[tc.wantEnabled]
			if !ok {
				t.Fatalf("enabled set = %v, missing %q: a still-configured interface dropped out "+
					"of the teardown inventory because netlink could not resolve its ifindex "+
					"(#6536) — the daemon reads that absence as a config removal and disables "+
					"the responder", enabled, tc.wantEnabled)
			}
			if _, ok := fams[unix.AF_INET]; !ok {
				t.Fatalf("enabled[%q] = %v, want AF_INET", tc.wantEnabled, fams)
			}
			var sawWrite bool
			for _, w := range wrote {
				if w == tc.wantEnabled {
					sawWrite = true
				}
			}
			if !sawWrite {
				t.Fatalf("responder sysctl writes = %v, want one for %q: the fallback must also "+
					"re-assert the sysctl, not merely preserve the inventory entry", wrote, tc.wantEnabled)
			}
		})
	}
}
