package routing

import (
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #1884 reconcile-in-place tests. tunnelManager.Apply must not delete
// and recreate untouched tunnel devices on every apply (the gr-X flap
// that killed the userspace-dp TUN readers per commit); removals are a
// set-diff against the previous DESIRED set; reuse paths explicitly
// reconcile addresses, VRF claims, MTU, and keepalives.

// fakeVRFBinder mimics vrfManager.BindInterfaceToVRF against the
// fakeLinkOps store: a successful bind sets the interface's
// MasterIndex to the vrf-<ri> device's index (the daemon-prefixed VRF
// naming, vrf.go BindInterfaceToVRF).
type fakeVRFBinder struct {
	ops  *fakeLinkOps
	fail map[string]error // ri name -> bind error injection
}

func (b *fakeVRFBinder) BindInterfaceToVRF(ifaceName, instanceName string) error {
	if err, ok := b.fail[instanceName]; ok {
		return err
	}
	iface, ok := b.ops.links[ifaceName]
	if !ok {
		return errors.New("interface not found")
	}
	vrf, ok := b.ops.links["vrf-"+instanceName]
	if !ok {
		return errors.New("vrf not found")
	}
	iface.Attrs().MasterIndex = vrf.Attrs().Index
	return nil
}

func newReconcileManager(ops *fakeLinkOps) (*tunnelManager, *fakeVRFBinder) {
	binder := &fakeVRFBinder{ops: ops, fail: map[string]error{}}
	return &tunnelManager{
		ops:        ops,
		vrfBinder:  binder,
		keepalives: map[string]*keepaliveRunner{},
	}, binder
}

func seedVRF(ops *fakeLinkOps, ri string, index int) {
	ops.links["vrf-"+ri] = &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: "vrf-" + ri, Index: index},
	}
}

// seedAnchor seeds a kernel-shaped reusable anchor TUN.
func seedAnchor(ops *fakeLinkOps, name string, index, mtu int) *netlink.Tuntap {
	tt := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: index, MTU: mtu},
		Mode:      netlink.TUNTAP_MODE_TUN,
		Flags:     netlink.TUNTAP_NO_PI,
	}
	ops.links[name] = tt
	return tt
}

func anchorTC(name string, addrs ...string) *config.TunnelConfig {
	return &config.TunnelConfig{Name: name, AnchorOnly: true, Addresses: addrs}
}

// --- §9 test 1: untouched tunnel ⇒ untouched netdev -----------------

func TestTunnelApplySecondApplyNoChurn(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}

	if err := tm.Apply(tcs); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	if len(ops.delNames) != 0 {
		t.Fatalf("first apply deleted links: %v", ops.delNames)
	}
	created := ops.links["gr-0-0-0"]
	if created == nil {
		t.Fatal("anchor not created")
	}
	addAddsAfterFirst := len(ops.addrLinks)

	if err := tm.Apply(tcs); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if len(ops.delNames) != 0 {
		t.Fatalf("second apply deleted links (the #1884 flap): %v", ops.delNames)
	}
	if ops.links["gr-0-0-0"] != created {
		t.Fatal("second apply replaced the anchor link object")
	}
	if got := len(ops.addrLinks); got != addAddsAfterFirst {
		t.Fatalf("second apply re-added addresses: AddrAdd count %d, want %d",
			got, addAddsAfterFirst)
	}
	if got := len(ops.addrDels["gr-0-0-0"]); got != 0 {
		t.Fatalf("second apply deleted addresses: %v", ops.addrDels["gr-0-0-0"])
	}
	if got := len(ops.mtuSet["gr-0-0-0"]); got != 0 {
		t.Fatalf("owned reuse with unconfigured MTU wrote MTU: %v", ops.mtuSet["gr-0-0-0"])
	}
}

// --- §9 test 2: restart adoption + MTU ownership ---------------------

func TestTunnelAnchorRestartAdoptionNormalizesMTU(t *testing.T) {
	ops := newFakeLinkOps()
	seedAnchor(ops, "gr-0-0-0", 42, 1420) // WG-leftover-ish MTU
	tm, _ := newReconcileManager(ops)

	// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
	// ⇒ one-time normalization to the TUN default.
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(ops.delNames) != 0 {
		t.Fatalf("adoption recreated the anchor: %v", ops.delNames)
	}
	if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != 1500 {
		t.Fatalf("adoption MTU writes = %v, want exactly [1500]", got)
	}

	// Owned reuse, tc.MTU == 0, MTU drifted out-of-band ⇒ NOT touched.
	ops.links["gr-0-0-0"].Attrs().MTU = 1400
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 {
		t.Fatalf("owned reuse with tc.MTU==0 wrote MTU: %v", got)
	}
}

func TestTunnelAnchorConfiguredMTUReconciledOnReuse(t *testing.T) {
	ops := newFakeLinkOps()
	seedAnchor(ops, "gr-0-0-0", 42, 1420)
	tm, _ := newReconcileManager(ops)

	tc := anchorTC("gr-0-0-0")
	tc.MTU = 9000
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != 9000 {
		t.Fatalf("adoption with config MTU writes = %v, want [9000]", got)
	}

	// Owned reuse with config MTU and drift ⇒ reconciled (the compiler
	// stage only restores ZONED interfaces; unzoned tunnels have no
	// other MTU writer).
	ops.links["gr-0-0-0"].Attrs().MTU = 1400
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if got := ops.mtuSet["gr-0-0-0"]; len(got) != 2 || got[1] != 9000 {
		t.Fatalf("owned reuse with config MTU writes = %v, want [9000 9000]", got)
	}
}

func TestTunnelAnchorCreateAppliesConfigMTU(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	tc := anchorTC("gr-0-0-0")
	tc.MTU = 9000
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != 9000 {
		t.Fatalf("create with config MTU writes = %v, want [9000]", got)
	}
}

// --- §9 test 3: incompatible existing links are recreated ------------

func TestTunnelAnchorIncompatibleLinksRecreated(t *testing.T) {
	cases := []struct {
		name string
		link netlink.Link
	}{
		{"dummy", &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9}}},
		{"pi-tun", &netlink.Tuntap{
			LinkAttrs: netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9},
			Mode:      netlink.TUNTAP_MODE_TUN, // no NO_PI flag
		}},
		{"tap", &netlink.Tuntap{
			LinkAttrs: netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9},
			Mode:      netlink.TUNTAP_MODE_TAP,
			Flags:     netlink.TUNTAP_NO_PI,
		}},
		{"non-persistent", &netlink.Tuntap{
			LinkAttrs:  netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9},
			Mode:       netlink.TUNTAP_MODE_TUN,
			Flags:      netlink.TUNTAP_NO_PI,
			NonPersist: true,
		}},
	}
	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			ops := newFakeLinkOps()
			ops.links["gr-0-0-0"] = tcase.link
			tm, _ := newReconcileManager(ops)
			if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if len(ops.delNames) != 1 || ops.delNames[0] != "gr-0-0-0" {
				t.Fatalf("incompatible link not deleted: delNames=%v", ops.delNames)
			}
			if ops.links["gr-0-0-0"] == tcase.link {
				t.Fatal("incompatible link not replaced")
			}
			if _, ok := ops.links["gr-0-0-0"].(*netlink.Tuntap); !ok {
				t.Fatalf("replacement is %T, want *netlink.Tuntap", ops.links["gr-0-0-0"])
			}
		})
	}
}

// --- §9 test 4: removal diff + retention on failed delete ------------

func TestTunnelRemovedFromConfigDeleted(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	both := []*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")}
	if err := tm.Apply(both); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	keepA := ops.links["gr-0-0-0"]

	if err := tm.Apply(both[:1]); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if _, ok := ops.links["gr-0-0-1"]; ok {
		t.Fatal("removed tunnel gr-0-0-1 still exists")
	}
	if ops.links["gr-0-0-0"] != keepA {
		t.Fatal("survivor gr-0-0-0 was churned by the removal")
	}
}

func TestTunnelRemovalRetriedAfterFailedDelete(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	both := []*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")}
	if err := tm.Apply(both); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}

	ops.delFail["gr-0-0-1"] = errors.New("EBUSY")
	if err := tm.Apply(both[:1]); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if _, ok := ops.links["gr-0-0-1"]; !ok {
		t.Fatal("link unexpectedly gone despite failed delete")
	}

	// Ownership retained ⇒ the NEXT apply retries and succeeds.
	delete(ops.delFail, "gr-0-0-1")
	if err := tm.Apply(both[:1]); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if _, ok := ops.links["gr-0-0-1"]; ok {
		t.Fatal("removal not retried after ownership retention (r2 Codex F5)")
	}
}

// --- §9 test 5: address reconcile + link-local rules ------------------

func TestTunnelAddressEditReconcilesInPlace(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.9.9.9/32")}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if len(ops.delNames) != 0 {
		t.Fatalf("address edit recreated the link: %v", ops.delNames)
	}
	if ops.hasAddr("gr-0-0-0", "10.1.2.3/32") {
		t.Fatal("stale address not removed")
	}
	if !ops.hasAddr("gr-0-0-0", "10.9.9.9/32") {
		t.Fatal("new address not added")
	}
}

func TestTunnelLinkLocalRules(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)

	// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	// Simulate the kernel's autoconf link-local appearing too.
	kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
	ops.addrs["gr-0-0-0"] = append(ops.addrs["gr-0-0-0"], *kernelLL)

	// Remove the configured fe80: it must be deleted (it is ours), the
	// kernel's autoconf fe80 must survive (r1 Codex F2 split).
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
		t.Fatal("configured fe80 leaked after removal from config")
	}
	if !ops.hasAddr("gr-0-0-0", "fe80::5054:ff:fe12:3456/64") {
		t.Fatal("kernel autoconf fe80 was deleted")
	}
}

func TestTunnelLinkLocalDeleteFailureRetried(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}

	ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if !ops.hasAddr("gr-0-0-0", "fe80::8/64") {
		t.Fatal("address gone despite injected delete failure")
	}

	// Failed delete keeps the LL tracked (r2 Codex F4) ⇒ retried.
	delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
		t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
	}
}

// --- #1905: WG branch shares the applied-address record ---------------

func wgTC(addrs ...string) *config.TunnelConfig {
	return &config.TunnelConfig{Name: "wg0", Mode: "wireguard", Addresses: addrs}
}

// A CONFIGURED fe80 on the persistent wgN TUN, later removed from
// config, must be reconciled away (pre-#1905 it leaked forever via the
// nil applied-set sentinel) — while the kernel's autoconf fe80 on the
// same device survives, exactly the GRE-branch split.
func TestWireguardConfiguredLinkLocalRemoved(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24", "fe80::8/64")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	if !ops.hasAddr("wg0", "fe80::8/64") {
		t.Fatal("configured fe80 not applied")
	}
	// Simulate the kernel's autoconf link-local appearing too.
	kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
	ops.addrs["wg0"] = append(ops.addrs["wg0"], *kernelLL)

	if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24")}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if ops.hasAddr("wg0", "fe80::8/64") {
		t.Fatal("configured fe80 leaked after removal from config (#1905)")
	}
	if !ops.hasAddr("wg0", "fe80::5054:ff:fe12:3456/64") {
		t.Fatal("kernel autoconf fe80 was deleted")
	}
	if !ops.hasAddr("wg0", "10.77.0.1/24") {
		t.Fatal("configured non-LL address lost")
	}
	// The persistent device must not have been recreated by any of this.
	if len(ops.delNames) != 0 {
		t.Fatalf("wg0 was deleted/recreated: %v", ops.delNames)
	}
}

// Adoption pass: an fe80 already on the device before this manager's
// first apply (daemon restart over a persistent wgN) is untracked and
// must never be deleted, even once it is absent from config.
func TestWireguardForeignLinkLocalNeverDeleted(t *testing.T) {
	ops := newFakeLinkOps()
	seedAnchor(ops, "wg0", 7, 1412)
	preLL, _ := netlink.ParseAddr("fe80::dead/64")
	ops.addrs["wg0"] = append(ops.addrs["wg0"], *preLL)
	tm, _ := newReconcileManager(ops)

	for i := 0; i < 2; i++ { // adoption pass AND a tracked second pass
		if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24")}); err != nil {
			t.Fatalf("Apply %d: %v", i+1, err)
		}
		if !ops.hasAddr("wg0", "fe80::dead/64") {
			t.Fatalf("pre-existing fe80 deleted on apply %d", i+1)
		}
	}
}

// Failed fe80 stale-delete on the WG branch stays tracked and is
// retried on the next apply (parity with the GRE-branch r2 Codex F4
// retry).
func TestWireguardLinkLocalDeleteFailureRetried(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{wgTC("fe80::8/64")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}

	ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
	if err := tm.Apply([]*config.TunnelConfig{wgTC()}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if !ops.hasAddr("wg0", "fe80::8/64") {
		t.Fatal("address gone despite injected delete failure")
	}

	delete(ops.addrDelFail, "wg0|fe80::8/64")
	if err := tm.Apply([]*config.TunnelConfig{wgTC()}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if ops.hasAddr("wg0", "fe80::8/64") {
		t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
	}
}

// --- #1919: WireGuard removal address-prune diff ----------------------

// A WG tunnel REMOVED from config must have the kernel addresses this
// manager applied pruned away — while the persistent wgN LINK is kept
// (never LinkDel'd, #1432 S2a) and any kernel autoconf fe80 survives.
func TestWireguardRemovedFromConfigPrunesAddresses(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{wgTC("172.16.0.1/30", "fe80::8/64")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	if !ops.hasAddr("wg0", "172.16.0.1/30") || !ops.hasAddr("wg0", "fe80::8/64") {
		t.Fatal("configured addresses not applied")
	}
	// Kernel autoconf link-local also present on the device.
	kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
	ops.addrs["wg0"] = append(ops.addrs["wg0"], *kernelLL)

	// Remove the WG tunnel entirely from config.
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 2 (removal): %v", err)
	}
	if len(ops.delNames) != 0 {
		t.Fatalf("persistent wgN link was deleted on removal: %v", ops.delNames)
	}
	if _, err := ops.LinkByName("wg0"); err != nil {
		t.Fatalf("wg0 link gone after removal (must be kept): %v", err)
	}
	if ops.hasAddr("wg0", "172.16.0.1/30") {
		t.Fatal("non-link-local address leaked after tunnel removal (#1919)")
	}
	if ops.hasAddr("wg0", "fe80::8/64") {
		t.Fatal("configured fe80 leaked after tunnel removal (#1919)")
	}
	if !ops.hasAddr("wg0", "fe80::5054:ff:fe12:3456/64") {
		t.Fatal("kernel autoconf fe80 was wrongly pruned on removal")
	}
}

// After a clean prune the name is dropped from tracking: a subsequent
// Apply with the tunnel still absent must not re-list / re-AddrDel it.
func TestWireguardRemovalPruneIdempotent(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{wgTC("172.16.0.1/30")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 2 (removal): %v", err)
	}
	if len(ops.addrDels["wg0"]) != 1 {
		t.Fatalf("expected exactly one AddrDel on removal, got %v", ops.addrDels["wg0"])
	}
	lookupsBefore := ops.byNameCount["wg0"]
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 3 (still removed): %v", err)
	}
	if len(ops.addrDels["wg0"]) != 1 {
		t.Fatalf("prune was not idempotent — extra AddrDel: %v", ops.addrDels["wg0"])
	}
	if ops.byNameCount["wg0"] != lookupsBefore {
		t.Fatalf("dropped name re-looked-up: %d→%d", lookupsBefore, ops.byNameCount["wg0"])
	}
}

// A FAILED AddrDel of a NON-link-local address on removal must retain the
// name in tracking and retry on the next Apply (direct guard for the
// #1919 r1 MAJOR — reconcileLinkAddrsLocked's return cannot carry this).
func TestWireguardRemovalAddrDelFailureRetried(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{wgTC("172.16.0.1/30")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	ops.addrDelFail["wg0|172.16.0.1/30"] = errors.New("EBUSY")
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 2 (removal, AddrDel fails): %v", err)
	}
	if !ops.hasAddr("wg0", "172.16.0.1/30") {
		t.Fatal("address gone despite injected AddrDel failure")
	}
	// Retry: AddrDel now succeeds → address pruned, tracking dropped.
	delete(ops.addrDelFail, "wg0|172.16.0.1/30")
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 3 (retry): %v", err)
	}
	if ops.hasAddr("wg0", "172.16.0.1/30") {
		t.Fatal("non-link-local prune not retried (dropped from tracking) — #1919 r1 MAJOR")
	}
	// And idempotent afterward.
	delsAfter := len(ops.addrDels["wg0"])
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 4: %v", err)
	}
	if len(ops.addrDels["wg0"]) != delsAfter {
		t.Fatalf("extra AddrDel after clean prune: %v", ops.addrDels["wg0"])
	}
}

// LinkByName returning a NOT-FOUND error on removal (device manually
// `ip link del`'d) drops tracking with no panic and a no-op next Apply.
func TestWireguardRemovalDeviceNotFoundDropsTracking(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{wgTC("172.16.0.1/30")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	// Device vanished from the kernel.
	delete(ops.links, "wg0")
	delete(ops.addrs, "wg0")
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 2 (removal, device not found): %v", err)
	}
	if len(ops.addrDels["wg0"]) != 0 {
		t.Fatalf("AddrDel attempted on a not-found device: %v", ops.addrDels["wg0"])
	}
	lookupsBefore := ops.byNameCount["wg0"]
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if ops.byNameCount["wg0"] != lookupsBefore {
		t.Fatal("tracking not dropped on not-found removal (name re-visited)")
	}
}

// A TRANSIENT (non-not-found) LinkByName error on removal must RETAIN the
// name in tracking; a later Apply where the link resolves prunes the
// address (direct guard for the #1919 r1 Codex/AGY MAJOR #2).
func TestWireguardRemovalTransientLookupRetained(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{wgTC("172.16.0.1/30")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	ops.byNameHardErr["wg0"] = errors.New("EBUSY: transient netlink error")
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 2 (removal, transient lookup error): %v", err)
	}
	if ops.hasAddr("wg0", "172.16.0.1/30") != true {
		t.Fatal("address pruned despite transient lookup failure (should retry)")
	}
	// Link resolves now → prune proceeds.
	delete(ops.byNameHardErr, "wg0")
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 3 (lookup recovers): %v", err)
	}
	if ops.hasAddr("wg0", "172.16.0.1/30") {
		t.Fatal("address not pruned after transient lookup recovered (tracking lost) — #1919 r1 MAJOR #2")
	}
}

// Re-adding the same WG name after a removal-prune tracks the NEW address
// fresh and does not re-leak the old one.
func TestWireguardReAddAfterRemovalTracksFresh(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{wgTC("172.16.0.1/30")}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 2 (removal): %v", err)
	}
	if ops.hasAddr("wg0", "172.16.0.1/30") {
		t.Fatal("old address not pruned on removal")
	}
	// Re-add with a NEW address.
	if err := tm.Apply([]*config.TunnelConfig{wgTC("172.16.9.1/30")}); err != nil {
		t.Fatalf("Apply 3 (re-add): %v", err)
	}
	if !ops.hasAddr("wg0", "172.16.9.1/30") {
		t.Fatal("re-added address not applied")
	}
	if ops.hasAddr("wg0", "172.16.0.1/30") {
		t.Fatal("old address re-leaked after re-add")
	}
}

// AddrList returning an error on removal (cannot enumerate ⇒ cannot prove
// clean) with an EMPTY applied set must RETAIN the name (retry), no
// panic; a later Apply where AddrList succeeds prunes the address. Proves
// the (failed, retry) decoupling (#1919 r2 Codex MAJOR).
func TestWireguardRemovalAddrListFailureRetained(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	// Configure with NO managed addresses so appliedAddrs["wg0"] is empty,
	// then plant a stale non-link-local address directly in the kernel.
	if err := tm.Apply([]*config.TunnelConfig{wgTC()}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	stale, _ := netlink.ParseAddr("172.16.0.1/30")
	ops.addrs["wg0"] = append(ops.addrs["wg0"], *stale)

	ops.addrListFail["wg0"] = errors.New("EBUSY: cannot enumerate")
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 2 (removal, AddrList fails): %v", err)
	}
	if !ops.hasAddr("wg0", "172.16.0.1/30") {
		t.Fatal("address gone despite AddrList failure")
	}
	// AddrList recovers → the stale address is pruned (name was retained).
	delete(ops.addrListFail, "wg0")
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply 3 (AddrList recovers): %v", err)
	}
	if ops.hasAddr("wg0", "172.16.0.1/30") {
		t.Fatal("stale address not pruned after AddrList recovered — (failed,retry) decoupling broken (#1919 r2 MAJOR)")
	}
}

// Restart-adoption boundary (#1919 R5): a FRESH manager (empty
// wgConfigured) with a wgN already carrying addresses and an empty config
// must NOT prune — the manager only prunes what it tracked applying;
// restart-time removal is #1434 scope. Encodes the deferral.
func TestWireguardRemovedWhileDaemonDownNotPruned(t *testing.T) {
	ops := newFakeLinkOps()
	seedAnchor(ops, "wg0", 7, 1412)
	preAddr, _ := netlink.ParseAddr("172.16.0.1/30")
	ops.addrs["wg0"] = append(ops.addrs["wg0"], *preAddr)
	tm, _ := newReconcileManager(ops)

	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply (fresh manager, empty config): %v", err)
	}
	if len(ops.addrDels["wg0"]) != 0 {
		t.Fatalf("restart-time WG address wrongly pruned: %v", ops.addrDels["wg0"])
	}
	if !ops.hasAddr("wg0", "172.16.0.1/30") {
		t.Fatal("pre-existing address removed at restart (must defer to #1434)")
	}
}

// --- §9 test 6: appliedRI claim state machine -------------------------

func TestTunnelVRFStanzaBindAndUnbind(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "red", 100)
	tm, _ := newReconcileManager(ops)

	tc := anchorTC("gr-0-0-0")
	tc.RoutingInstance = "red"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	if got := ops.links["gr-0-0-0"].Attrs().MasterIndex; got != 100 {
		t.Fatalf("stanza bind did not enslave: master=%d", got)
	}

	// Stanza removed, no list ⇒ identity-gated unbind of OUR master.
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if len(ops.noMaster) != 1 || ops.noMaster[0] != "gr-0-0-0" {
		t.Fatalf("expected exactly one LinkSetNoMaster, got %v", ops.noMaster)
	}
	if tm.appliedRI["gr-0-0-0"] != "" {
		t.Fatalf("claim not cleared after unbind: %q", tm.appliedRI["gr-0-0-0"])
	}

	// Idempotent: nothing further to unbind.
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if len(ops.noMaster) != 1 {
		t.Fatalf("unbind not idempotent: %v", ops.noMaster)
	}
}

func TestTunnelVRFStanzaToListSameVRFVetoed(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "red", 100)
	tm, _ := newReconcileManager(ops)

	tc := anchorTC("gr-0-0-0")
	tc.RoutingInstance = "red"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}

	// Same commit moves the SAME VRF from stanza to RI interface list;
	// step 0a (here: still-enslaved master) bound it before
	// ApplyTunnels. The veto must not strip it (r4 convergent).
	listTC := anchorTC("gr-0-0-0")
	listTC.RIListMember = "red"
	if err := tm.Apply([]*config.TunnelConfig{listTC}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if len(ops.noMaster) != 0 {
		t.Fatalf("stanza→list move unbound the 0a bind: %v", ops.noMaster)
	}
	if tm.appliedRI["gr-0-0-0"] != "red" {
		t.Fatalf("claim not transferred to list RI: %q", tm.appliedRI["gr-0-0-0"])
	}

	// List membership removed too ⇒ the transferred claim unbinds (the
	// v5 clear-on-veto leak, r5 convergent counterexample).
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if len(ops.noMaster) != 1 {
		t.Fatalf("stanza→list→removed did not unbind: %v", ops.noMaster)
	}
}

func TestTunnelVRFForeignMasterNeverUnbound(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "blue", 200)
	anchor := seedAnchor(ops, "gr-0-0-0", 42, 1500)
	anchor.Attrs().MasterIndex = 200 // 0a-style bind, not ours
	tm, _ := newReconcileManager(ops)

	// Fresh manager, no stanza, no list: appliedRI empty ⇒ the foreign
	// master must not be touched (r2 Codex F3).
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(ops.noMaster) != 0 {
		t.Fatalf("foreign master was unbound: %v", ops.noMaster)
	}
}

func TestTunnelVRFDifferentVRFReplacementMismatchClears(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "red", 100)
	seedVRF(ops, "blue", 200)
	tm, _ := newReconcileManager(ops)

	tc := anchorTC("gr-0-0-0")
	tc.RoutingInstance = "red"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}

	// Commit 2: stanza removed; a 0a list bind to a DIFFERENT VRF
	// already re-mastered the link this apply. Observation transfers
	// the claim to blue (master observed).
	ops.links["gr-0-0-0"].Attrs().MasterIndex = 200
	listTC := anchorTC("gr-0-0-0")
	listTC.RIListMember = "blue"
	if err := tm.Apply([]*config.TunnelConfig{listTC}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if len(ops.noMaster) != 0 {
		t.Fatalf("replacement bind was unbound: %v", ops.noMaster)
	}
	if tm.appliedRI["gr-0-0-0"] != "blue" {
		t.Fatalf("claim = %q, want blue", tm.appliedRI["gr-0-0-0"])
	}

	// Commit 3: list removed ⇒ unbind blue via the transferred claim.
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if len(ops.noMaster) != 1 {
		t.Fatalf("transferred claim did not unbind: %v", ops.noMaster)
	}
}

func TestTunnelVRFStanzaBindFailureRetainsClaim(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "red", 100)
	seedVRF(ops, "blue", 200)
	tm, binder := newReconcileManager(ops)

	tc := anchorTC("gr-0-0-0")
	tc.RoutingInstance = "red"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}

	// Commit 2: stanza re-bind red→blue FAILS; kernel stays on vrf-red.
	// A blind claim=blue would mismatch-clear later and strand red
	// (r7 Codex). The claim must stay red.
	binder.fail["blue"] = errors.New("vrf lookup failed")
	tc2 := anchorTC("gr-0-0-0")
	tc2.RoutingInstance = "blue"
	if err := tm.Apply([]*config.TunnelConfig{tc2}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if tm.appliedRI["gr-0-0-0"] != "red" {
		t.Fatalf("claim = %q after failed re-bind, want red", tm.appliedRI["gr-0-0-0"])
	}

	// Commit 3: RI removed entirely ⇒ red (still the real master) is
	// unbound via the retained claim.
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if len(ops.noMaster) != 1 {
		t.Fatalf("retained claim did not unbind red: %v", ops.noMaster)
	}
}

func TestTunnelVRFOverlapStanzaFailObservesList(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "red", 100)
	seedVRF(ops, "blue", 200)
	seedVRF(ops, "green", 300)
	tm, binder := newReconcileManager(ops)

	tc := anchorTC("gr-0-0-0")
	tc.RoutingInstance = "red"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}

	// Commit 2: stanza blue (bind FAILS) + RI-list green, where 0a
	// already bound green this apply. The observation fallback must
	// take the claim to green (r8 Codex overlap counterexample).
	binder.fail["blue"] = errors.New("bind failed")
	ops.links["gr-0-0-0"].Attrs().MasterIndex = 300
	tc2 := anchorTC("gr-0-0-0")
	tc2.RoutingInstance = "blue"
	tc2.RIListMember = "green"
	if err := tm.Apply([]*config.TunnelConfig{tc2}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if tm.appliedRI["gr-0-0-0"] != "green" {
		t.Fatalf("claim = %q, want green (observation fallback)", tm.appliedRI["gr-0-0-0"])
	}

	// Commit 3: everything removed ⇒ green unbound.
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if len(ops.noMaster) != 1 {
		t.Fatalf("observed claim did not unbind green: %v", ops.noMaster)
	}
}

func TestTunnelVRFListVetoWithFailedBindNoClaim(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "blue", 200)
	tm, _ := newReconcileManager(ops)

	// List member configured but 0a's bind failed (master 0) and there
	// is no prior claim ⇒ no claim may be invented (r6 Codex).
	tc := anchorTC("gr-0-0-0")
	tc.RIListMember = "blue"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := tm.appliedRI["gr-0-0-0"]; got != "" {
		t.Fatalf("claim invented from intent: %q", got)
	}
}

func TestTunnelVRFUnbindFailureRetained(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "red", 100)
	tm, _ := newReconcileManager(ops)

	tc := anchorTC("gr-0-0-0")
	tc.RoutingInstance = "red"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}

	ops.noMasterErr = errors.New("ENODEV")
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if tm.appliedRI["gr-0-0-0"] != "red" {
		t.Fatalf("claim lost on transient unbind failure: %q (r4 AGY F4)",
			tm.appliedRI["gr-0-0-0"])
	}

	ops.noMasterErr = nil
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if len(ops.noMaster) != 1 {
		t.Fatalf("unbind not retried after transient failure: %v", ops.noMaster)
	}
}

// --- §9 test 7: legacy non-anchor compare-then-decide -----------------

func legacyTC(name, src, dst string) *config.TunnelConfig {
	return &config.TunnelConfig{Name: name, Mode: "gre", Source: src, Destination: dst}
}

// kernelShapedGre mimics what LinkByName returns for a GRE device the
// previous apply created: 4-byte v4 IPs, defaulted TTL, plus
// kernel-populated fields that must NOT participate in the comparison.
func kernelShapedGre(name string, index int, local, remote string, key uint32) *netlink.Gretun {
	g := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: index},
		Local:     net.ParseIP(local).To4(),
		Remote:    net.ParseIP(remote).To4(),
		Ttl:       64,
		PMtuDisc:  1,
		Tos:       0,
	}
	if key > 0 {
		g.IKey = key
		g.OKey = key
	}
	return g
}

func TestLegacyTunnelUnchangedReused(t *testing.T) {
	ops := newFakeLinkOps()
	existing := kernelShapedGre("gr-0-0-0", 42, "192.0.2.1", "192.0.2.2", 0)
	ops.links["gr-0-0-0"] = existing
	tm, _ := newReconcileManager(ops)

	if err := tm.Apply([]*config.TunnelConfig{legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(ops.delNames) != 0 {
		t.Fatalf("identical legacy tunnel was recreated: %v", ops.delNames)
	}
	if ops.links["gr-0-0-0"] != netlink.Link(existing) {
		t.Fatal("legacy tunnel link replaced despite identical attrs")
	}
	if len(ops.setUpLinks) != 1 || ops.setUpLinks[0].Attrs().Index != 42 {
		t.Fatal("LinkSetUp did not run on the kernel-fetched link")
	}
}

func TestLegacyTunnelChangedAttrsRecreated(t *testing.T) {
	cases := []struct {
		name string
		tc   *config.TunnelConfig
	}{
		{"destination-change", legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.99")},
		{"family-flip", legacyTC("gr-0-0-0", "2001:db8::1", "2001:db8::2")},
		{"key-added", func() *config.TunnelConfig {
			tc := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
			tc.Key = 7
			return tc
		}()},
		{"ttl-change", func() *config.TunnelConfig {
			tc := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
			tc.TTL = 32
			return tc
		}()},
	}
	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			ops := newFakeLinkOps()
			ops.links["gr-0-0-0"] = kernelShapedGre("gr-0-0-0", 42, "192.0.2.1", "192.0.2.2", 0)
			tm, _ := newReconcileManager(ops)
			if err := tm.Apply([]*config.TunnelConfig{tcase.tc}); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if len(ops.delNames) != 1 {
				t.Fatalf("changed attrs did not recreate: delNames=%v", ops.delNames)
			}
		})
	}
}

func TestLegacyTunnelKernelPopulatedFieldsIgnored(t *testing.T) {
	ops := newFakeLinkOps()
	g := kernelShapedGre("gr-0-0-0", 42, "192.0.2.1", "192.0.2.2", 0)
	g.PMtuDisc = 1
	g.Tos = 4 // kernel/operator-populated; NOT config-driven
	ops.links["gr-0-0-0"] = g
	tm, _ := newReconcileManager(ops)

	if err := tm.Apply([]*config.TunnelConfig{legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(ops.delNames) != 0 {
		t.Fatal("kernel-populated field difference re-flapped the tunnel (A.6 exclusion list)")
	}
}

// --- §9 test 8: keepalive identity reconcile (legacy branch only) -----

func TestLegacyKeepaliveRunnerRetainedAcrossApplies(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	tc := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
	tc.Keepalive = 60
	tc.KeepaliveRetry = 0 // normalizes to 3 — must not restart per apply

	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	runner1 := tm.keepalives["gr-0-0-0"]
	if runner1 == nil {
		t.Fatal("keepalive not started")
	}
	defer tm.stopAll()

	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if tm.keepalives["gr-0-0-0"] != runner1 {
		t.Fatal("unchanged keepalive was restarted (r1 Codex F5 normalization)")
	}

	// Changed interval ⇒ restart.
	tc2 := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
	tc2.Keepalive = 30
	if err := tm.Apply([]*config.TunnelConfig{tc2}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if tm.keepalives["gr-0-0-0"] == runner1 {
		t.Fatal("changed keepalive interval did not restart the runner")
	}

	// Keepalive removed ⇒ stopped and map entry deleted (SMR2-2).
	tc3 := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
	if err := tm.Apply([]*config.TunnelConfig{tc3}); err != nil {
		t.Fatalf("Apply 4: %v", err)
	}
	if tm.GetKeepaliveState("gr-0-0-0") != nil {
		t.Fatal("keepalive state survives after keepalive removed from config")
	}
}

func TestLegacyKeepaliveDownSkipsLinkSetUp(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	tc := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
	tc.Keepalive = 60

	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	defer tm.stopAll()
	upsAfterFirst := len(ops.setUpLinks)

	// Keepalive marked the tunnel down. An unrelated re-apply must NOT
	// LinkSetUp the reused link: keepaliveLoop's down-transition is
	// gated on state.Up==true, so re-upping would strand the link admin
	// UP forever while probes keep failing (r1 Codex F1 + AGY trace).
	runner := tm.keepalives["gr-0-0-0"]
	runner.state.mu.Lock()
	runner.state.Up = false
	runner.state.mu.Unlock()

	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if got := len(ops.setUpLinks); got != upsAfterFirst {
		t.Fatalf("LinkSetUp ran on a keepalive-down tunnel: %d ups, want %d",
			got, upsAfterFirst)
	}
}

// --- §9 test 9: EEXIST race adoption does not write MTU on owned names

func TestTunnelAnchorEEXISTRaceOnOwnedNameNoMTUWrite(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0")}
	if err := tm.Apply(tcs); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	// Force the transient race: the reuse-first lookup misses once, the
	// LinkAdd fails EEXIST, the fallback lookup adopts the existing
	// link. The name is OWNED, so the adoption MTU normalization must
	// NOT fire (r2 Codex F1 / SMR2-1).
	existing := ops.links["gr-0-0-0"].(*netlink.Tuntap)
	existing.Attrs().MTU = 1400
	ops.byNameCount["gr-0-0-0"] = 0
	ops.hiddenUntil["gr-0-0-0"] = 1
	ops.addExisting = true

	if err := tm.Apply(tcs); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if got := len(ops.mtuSet["gr-0-0-0"]); got != 0 {
		t.Fatalf("EEXIST reuse on an OWNED name wrote MTU: %v", ops.mtuSet["gr-0-0-0"])
	}
}

// --- restart adoption end-to-end --------------------------------------

func TestTunnelRestartAdoptionStableLink(t *testing.T) {
	ops := newFakeLinkOps()
	tm1, _ := newReconcileManager(ops)
	tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}
	if err := tm1.Apply(tcs); err != nil {
		t.Fatalf("Apply (manager 1): %v", err)
	}
	link := ops.links["gr-0-0-0"]

	// "Daemon restart": a brand-new manager over the same kernel state
	// adopts the anchor without recreating it.
	tm2, _ := newReconcileManager(ops)
	if err := tm2.Apply(tcs); err != nil {
		t.Fatalf("Apply (manager 2): %v", err)
	}
	if len(ops.delNames) != 0 {
		t.Fatalf("restart adoption recreated the anchor: %v", ops.delNames)
	}
	if ops.links["gr-0-0-0"] != link {
		t.Fatal("restart adoption replaced the link object")
	}
}

// --- Codex PR-r1 coverage adds: remaining claim cells + Clear union --

func TestTunnelVRFListOnlyBindThenRemovedUnbinds(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "blue", 200)
	tm, _ := newReconcileManager(ops)

	// List-ONLY tunnel (never stanza-bound): 0a bound it; observation
	// records the claim.
	tc := anchorTC("gr-0-0-0")
	tc.RIListMember = "blue"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	ops.links["gr-0-0-0"].Attrs().MasterIndex = 200 // 0a bind
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if tm.appliedRI["gr-0-0-0"] != "blue" {
		t.Fatalf("observed list claim = %q, want blue", tm.appliedRI["gr-0-0-0"])
	}

	// List membership removed ⇒ unbind via the observed claim.
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if len(ops.noMaster) != 1 {
		t.Fatalf("list-only removal did not unbind: %v", ops.noMaster)
	}
}

func TestTunnelVRFStanzaSuccessWinsOverList(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "red", 100)
	seedVRF(ops, "blue", 200)
	tm, _ := newReconcileManager(ops)

	// Both knobs present, stanza bind SUCCEEDS ⇒ stanza wins the claim
	// (today's effective 0a-then-tunnel-apply order).
	tc := anchorTC("gr-0-0-0")
	tc.RoutingInstance = "red"
	tc.RIListMember = "blue"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if tm.appliedRI["gr-0-0-0"] != "red" {
		t.Fatalf("claim = %q, want red (stanza wins on success)", tm.appliedRI["gr-0-0-0"])
	}
	if got := ops.links["gr-0-0-0"].Attrs().MasterIndex; got != 100 {
		t.Fatalf("master = %d, want vrf-red 100", got)
	}
}

func TestTunnelVRFNotFoundClearsClaim(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "red", 100)
	tm, _ := newReconcileManager(ops)

	tc := anchorTC("gr-0-0-0")
	tc.RoutingInstance = "red"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}

	// VRF device deleted out-of-band (kernel frees slaves; the fake
	// mirrors that by zeroing the master). Claim must CLEAR via the
	// not-found leg, with no unbind issued.
	delete(ops.links, "vrf-red")
	ops.links["gr-0-0-0"].Attrs().MasterIndex = 100 // stale-looking master
	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if len(ops.noMaster) != 0 {
		t.Fatalf("unbind issued despite VRF not-found: %v", ops.noMaster)
	}
	if got := tm.appliedRI["gr-0-0-0"]; got != "" {
		t.Fatalf("claim not cleared on VRF not-found: %q", got)
	}
}

func TestTunnelVRFTransientLookupRetainsClaim(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "red", 100)
	tm, _ := newReconcileManager(ops)

	tc := anchorTC("gr-0-0-0")
	tc.RoutingInstance = "red"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}

	// Drive the unbind decision directly with a TRANSIENT (plain,
	// non-not-found) error on the vrf-red lookup: byNameErrAfter is a
	// global threshold, so pre-load vrf-red's per-name counter past it
	// while the helper performs no other lookups (the tunnel link is
	// passed in). Claim must be RETAINED, no unbind issued.
	link := ops.links["gr-0-0-0"]
	ops.byNameCount["vrf-red"] = 99
	ops.byNameErrAfter = 1
	tm.mu.Lock()
	tm.reconcileVRFClaimLocked(anchorTC("gr-0-0-0"), link)
	tm.mu.Unlock()
	if got := tm.appliedRI["gr-0-0-0"]; got != "red" {
		t.Fatalf("claim lost on transient lookup error: %q", got)
	}
	if len(ops.noMaster) != 0 {
		t.Fatalf("unbind issued despite transient lookup error: %v", ops.noMaster)
	}

	// Error clears ⇒ retry unbinds.
	ops.byNameErrAfter = 0
	tm.mu.Lock()
	tm.reconcileVRFClaimLocked(anchorTC("gr-0-0-0"), link)
	tm.mu.Unlock()
	if len(ops.noMaster) != 1 {
		t.Fatalf("unbind not retried after transient lookup error: %v", ops.noMaster)
	}
}

func TestClearTunnelsDeletesOwnershipUnion(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)

	// Apply where the second tunnel FAILS mid-apply (non-TUN collision
	// whose LinkDel fails): it stays in ownedNames but never reaches
	// t.tunnels.
	ops.links["gr-0-0-1"] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "gr-0-0-1", Index: 9}}
	ops.delFail["gr-0-0-1"] = errors.New("EBUSY")
	tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")}
	if err := tm.Apply(tcs); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// ClearTunnels must delete EVERYTHING it owns — including the
	// failed-apply name once deletable (Codex PR r1 MINOR: union of
	// t.tunnels and ownedNames, not the success list alone).
	delete(ops.delFail, "gr-0-0-1")
	if err := tm.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, ok := ops.links["gr-0-0-0"]; ok {
		t.Fatal("Clear left the successful tunnel behind")
	}
	if _, ok := ops.links["gr-0-0-1"]; ok {
		t.Fatal("Clear left the failed-apply owned link behind (union rule)")
	}
}
