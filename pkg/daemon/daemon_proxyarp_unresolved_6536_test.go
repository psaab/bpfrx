package daemon

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

// proxyARPCfgOn is a config with proxy-arp configured on "lo".
func proxyARPCfgOn() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "lo", Addresses: []string{"10.0.2.50/32"}},
	}
	return cfg
}

// TestReconcileProxyARP_UnresolvedIsNotDeconfigured is the #6536 fail-on-revert
// test. It binds the DISCRIMINATOR the pre-fix code lost: the enabled set that
// drives the #2475 responder teardown conflated
//
//	(a) "proxy-arp is no longer configured on this interface"   -> disable, and
//	(b) "this interface's ifindex would not resolve this pass"  -> must NOT disable
//
// into one signal — absence from the set — and the consumer's action on it is a
// destructive sysctl write. Both rows below run the SAME production entry point
// (d.reconcileProxyARP) over the same first pass and differ ONLY in which of
// (a)/(b) holds on the second pass, so a fix that simply stopped tearing down
// would RED the removal row. Pre-fix, the unresolved row disables "lo" while it
// is still configured AND forgets it (so no later pass can ever tear it down).
func TestReconcileProxyARP_UnresolvedIsNotDeconfigured(t *testing.T) {
	const loIdx = 1
	linuxName := config.LinuxIfName("lo")

	tests := []struct {
		name string
		// secondPass supplies the config and the resolver state for pass 2.
		secondCfg      *config.Config
		secondResolver map[string]int
		wantDisabled   bool
		// wantRemembered is whether "lo" must still be in the daemon's
		// remembered responder state after pass 2.
		wantRemembered bool
	}{
		{
			name:           "still-configured-but-unresolvable",
			secondCfg:      proxyARPCfgOn(),
			secondResolver: map[string]int{}, // transient resolution failure
			wantDisabled:   false,
			wantRemembered: true,
		},
		{
			name:           "genuinely-removed-from-config",
			secondCfg:      &config.Config{},
			secondResolver: map[string]int{linuxName: loIdx},
			wantDisabled:   true,
			wantRemembered: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withFakeIfaceResolver(t, map[string]int{linuxName: loIdx})

			var disabled []map[string]map[int]struct{}
			prevDisable := proxyARPDisableFn
			proxyARPDisableFn = func(set map[string]map[int]struct{}) int {
				disabled = append(disabled, set)
				return 0
			}
			t.Cleanup(func() { proxyARPDisableFn = prevDisable })

			d := &Daemon{}

			// Pass 1: proxy-arp configured on lo, resolution works.
			d.reconcileProxyARP(proxyARPCfgOn())
			d.proxyARPEnabledMu.Lock()
			fams := d.proxyARPEnabled["lo"]
			d.proxyARPEnabledMu.Unlock()
			if _, ok := fams[unix.AF_INET]; !ok {
				t.Fatalf("pass 1 did not record lo in the enabled set: %v", d.proxyARPEnabled)
			}
			if len(disabled) != 0 {
				t.Fatalf("pass 1 called the disable sink: %v", disabled)
			}

			// Pass 2: the row under test.
			withFakeIfaceResolver(t, tc.secondResolver)
			d.reconcileProxyARP(tc.secondCfg)

			gotDisabled := false
			for _, set := range disabled {
				if _, ok := set["lo"][unix.AF_INET]; ok {
					gotDisabled = true
				}
			}
			if gotDisabled != tc.wantDisabled {
				if tc.wantDisabled {
					t.Fatalf("lo responder NOT disabled after proxy-arp was removed "+
						"from the config (the #2475 teardown regressed): disabled=%v", disabled)
				}
				t.Fatalf("lo responder DISABLED while still configured for proxy-arp, "+
					"purely because its ifindex did not resolve this pass (#6536): disabled=%v", disabled)
			}

			d.proxyARPEnabledMu.Lock()
			_, remembered := d.proxyARPEnabled["lo"]
			state := d.proxyARPEnabled
			d.proxyARPEnabledMu.Unlock()
			if remembered != tc.wantRemembered {
				t.Fatalf("lo remembered=%v, want %v (state=%v); forgetting a still-configured "+
					"interface also loses the #4955 NTF_PROXY orphan sweep", remembered, tc.wantRemembered, state)
			}
		})
	}
}

// TestReconcileProxyARP_UnresolvedDebtIsRedeemed proves the #6536 retention is
// DEBT and not a permanent leak: once the interface really leaves the config
// (with resolution working again) the retained state is torn down exactly as a
// non-interrupted removal would be. Without this the fix would trade a
// destructive disable for a responder that can never be turned off.
func TestReconcileProxyARP_UnresolvedDebtIsRedeemed(t *testing.T) {
	const loIdx = 1
	linuxName := config.LinuxIfName("lo")
	withFakeIfaceResolver(t, map[string]int{linuxName: loIdx})

	var disabled []map[string]map[int]struct{}
	prevDisable := proxyARPDisableFn
	proxyARPDisableFn = func(set map[string]map[int]struct{}) int {
		disabled = append(disabled, set)
		return 0
	}
	t.Cleanup(func() { proxyARPDisableFn = prevDisable })

	d := &Daemon{}
	d.reconcileProxyARP(proxyARPCfgOn())

	// Pass 2: still configured, resolution fails -> retained, not disabled.
	withFakeIfaceResolver(t, map[string]int{})
	d.reconcileProxyARP(proxyARPCfgOn())
	if len(disabled) != 0 {
		t.Fatalf("disabled a still-configured interface on a transient failure: %v", disabled)
	}

	// Pass 3: proxy-arp removed, resolution healed -> the debt is redeemed.
	withFakeIfaceResolver(t, map[string]int{linuxName: loIdx})
	d.reconcileProxyARP(&config.Config{})
	if len(disabled) != 1 {
		t.Fatalf("retained responder never torn down after removal: disabled=%v", disabled)
	}
	if _, ok := disabled[0]["lo"][unix.AF_INET]; !ok {
		t.Fatalf("teardown set = %v, want lo/AF_INET", disabled[0])
	}
	d.proxyARPEnabledMu.Lock()
	defer d.proxyARPEnabledMu.Unlock()
	if _, ok := d.proxyARPEnabled["lo"]; ok {
		t.Fatalf("lo still remembered after a clean removal: %v", d.proxyARPEnabled)
	}
}
