package daemon

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
)

// lifelineSeamState captures everything setupBootstrapLifeline can MUTATE, so a
// test can assert zero side effects rather than only a missing file.
type lifelineSeamState struct {
	linkDir  string
	renamed  *bool
	reloaded *bool
}

// staticLifelineSeams points the bootstrap lifeline at a NIC that is selected
// BY DEFAULT ROUTE (the evidence-bearing case) and stubs every mutating seam.
// The netlink observation seams are left for the caller to set.
func staticLifelineSeams(t *testing.T) lifelineSeamState {
	t.Helper()
	dir := t.TempDir()
	netDir := filepath.Join(dir, "network")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}

	oldLinkDir, oldDetect := linkDir, detectLifelineInterfaceFn
	oldEnum, oldRename, oldReload := enumeratePCINICsFn, renameInterfaceFn, networkctlReloadFn
	oldRecord := lifelineRecordFileForTest
	oldLink, oldAddr, oldRoute := lifelineLinkByName, lifelineAddrList, lifelineRouteList
	t.Cleanup(func() {
		linkDir, detectLifelineInterfaceFn = oldLinkDir, oldDetect
		enumeratePCINICsFn, renameInterfaceFn, networkctlReloadFn = oldEnum, oldRename, oldReload
		lifelineRecordFileForTest = oldRecord
		lifelineLinkByName, lifelineAddrList, lifelineRouteList = oldLink, oldAddr, oldRoute
	})

	linkDir = netDir
	lifelineRecordFileForTest = filepath.Join(dir, "lifeline.json")
	// A DEFAULT ROUTE names the management NIC: this is the evidence-bearing
	// selection path, the one where a failed addressing read is a real loss.
	detectLifelineInterfaceFn = func() (string, bool) { return defaultMgmtInterface, true }
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{{sortKey: 0, busAddr: "0000:05:00.0", name: defaultMgmtInterface}}, nil
	}
	renamed, reloaded := false, false
	renameInterfaceFn = func(_, _ string) error { renamed = true; return nil }
	networkctlReloadFn = func() error { reloaded = true; return nil }

	return lifelineSeamState{linkDir: netDir, renamed: &renamed, reloaded: &reloaded}
}

// okLink is a minimal netlink.Link for the observation seams.
func okLink() netlink.Link {
	return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: defaultMgmtInterface, Index: 2}}
}

// staticAddr is a PERMANENT (ValidLft == forever) global address — a static
// address, the kind whose loss the DHCP branch would cause.
func staticAddr(cidr string) netlink.Addr {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	ipnet.IP = ip
	return netlink.Addr{IPNet: ipnet, ValidLft: 0xffffffff}
}

// TestLifelineObservationFailureProducesZeroSideEffects6789 is the #6789
// fail-on-revert test, and it asserts SIDE EFFECTS rather than a return value.
//
// setupBootstrapLifeline is a chain of fail-closed refusals: no default route,
// NIC enumeration failed, and not-enumeration-index-0 each log and return
// having touched NOTHING. The addressing snapshot was the one observation that
// GUESSED instead. interfaceAddrSnapshot returned empty slices on a LinkByName
// failure and discarded the AddrList error, and the writer asked
// `isDHCPManaged(x) || (len(v4) == 0 && len(v6) == 0)` — so the very failure
// that made isDHCPManaged fail SAFE (toward static, as its comment documents)
// also emptied the address list and drove the OR into the DHCP branch. A
// statically-addressed management NIC then got a `DHCP=yes` .network and was
// renamed, and the rename cycles the link: the static address goes away on a
// box that is reachable only over that NIC, in bootstrap, with no committed
// config to roll back to.
//
// Each arm fails ONE observation. What must be true in every arm is that
// nothing was mutated: no .network written, no rename, no networkctl reload.
//
// FAIL-ON-REVERT: folding any of these errors back into an empty snapshot makes
// the writer emit a DHCP .network and the rename+reload run, reddening all
// three assertions in that arm.
func TestLifelineObservationFailureProducesZeroSideEffects6789(t *testing.T) {
	injected := errors.New("injected: netlink observation failure")

	tests := []struct {
		name  string
		seams func()
	}{
		{
			// The link itself cannot be resolved.
			name: "link-read-fails",
			seams: func() {
				lifelineLinkByName = func(string) (netlink.Link, error) { return nil, injected }
			},
		},
		{
			// The link resolves but its addresses cannot be listed. This is the
			// arm the old code could not distinguish from "has no addresses".
			name: "address-list-fails",
			seams: func() {
				lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
				lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) { return nil, injected }
			},
		},
		{
			// Addresses read fine, but the route dump for a family we HAVE
			// addresses in failed — so a Gateway= line would have been written
			// and its absence leaves management reachable on-link only.
			name: "route-list-fails-for-a-family-with-addresses",
			seams: func() {
				lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
				lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
					return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
				}
				lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
					if family == netlink.FAMILY_V4 {
						return nil, injected
					}
					return nil, nil
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := staticLifelineSeams(t)
			tc.seams()

			d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
			d.setupBootstrapLifeline()

			netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
			if data, err := os.ReadFile(netPath); err == nil {
				t.Errorf("a bootstrap fxp0 .network was written from an INCOMPLETE addressing "+
					"observation; a failed read must never be treated as 'no addresses', because "+
					"the address-less case writes DHCP=yes over a statically-addressed management "+
					"NIC (#6789). content:\n%s", data)
			}
			if *st.renamed {
				t.Error("the management NIC was RENAMED after a failed addressing observation. The " +
					"rename cycles the link, so on a box reached only over that NIC this is the " +
					"lockout (#6789)")
			}
			if *st.reloaded {
				t.Error("networkctl reload ran after a failed addressing observation; every other " +
					"observation failure in setupBootstrapLifeline refuses without touching anything")
			}
		})
	}
}

// TestCompleteObservationStillWritesAndRenames6789 is the tightening control.
// Without it, a fix that refuses on EVERY snapshot — or simply never writes —
// satisfies every assertion above while disabling the bootstrap lifeline
// entirely, which strands management under its kernel name on every boot.
//
// It uses the SAME seams with the only difference being that the observations
// SUCCEED, and asserts the static snapshot is what gets written (not DHCP), so
// it also pins that a permanent address is still classified as static.
func TestCompleteObservationStillWritesAndRenames6789(t *testing.T) {
	st := staticLifelineSeams(t)
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
		}
		return nil, nil
	}

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	data, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatalf("a COMPLETE observation must still write the bootstrap fxp0 .network: %v", err)
	}
	got := string(data)
	if !contains6789(got, "Address=192.0.2.10/24") {
		t.Errorf("the static address must be snapshotted into the .network; got:\n%s", got)
	}
	if !contains6789(got, "Gateway=192.0.2.1") {
		t.Errorf("the default gateway must be snapshotted; got:\n%s", got)
	}
	if contains6789(got, "DHCP=yes") {
		t.Errorf("a PERMANENT (ValidLft==forever) address is STATIC and must not produce a DHCP "+
			".network — that substitution is the lockout #6789 closes; got:\n%s", got)
	}
	if !*st.reloaded {
		t.Error("a complete observation must still reload networkd")
	}
}

// TestRouteFailureForAFamilyWithNoAddressesDoesNotRefuse6789 is the
// ANTI-OVER-REACH control, and it guards the scoping decision.
//
// A route-dump failure only matters when a Gateway= line for that family would
// have been written. Refusing because the IPv6 route dump errored on a box with
// no IPv6 addresses would strand the lifeline over an observation that could
// not have changed a single byte of the output — the kind of over-broad
// fail-closed that turns a conditional hazard into an unconditional outage.
//
// FAIL-ON-REVERT: dropping the `haveAddrs` scope in snapshotLifelineAddrs makes
// this refuse and reds the write/rename assertions.
func TestRouteFailureForAFamilyWithNoAddressesDoesNotRefuse6789(t *testing.T) {
	st := staticLifelineSeams(t)
	injected := errors.New("injected: v6 route dump failed")
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		// v4 only — nothing in the v6 family to write a Gateway= for.
		return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V6 {
			return nil, injected
		}
		return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
	}

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	if _, err := os.ReadFile(netPath); err != nil {
		t.Fatalf("a v6 route-dump failure on a box with NO v6 addresses must NOT refuse the "+
			"lifeline: nothing it could have observed would appear in the output. err=%v", err)
	}
	if !*st.reloaded {
		t.Error("the lifeline must still complete when the failed observation is irrelevant")
	}
}

func contains6789(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

// TestApplianceFactoryBootIsNotRefusedByASnapshotFailure6789 binds the OTHER
// half of the scoping decision, and it is the one that keeps this fix from
// breaking the factory image.
//
// The refusal is conditioned on the lifeline having been chosen BY DEFAULT
// ROUTE, because that is positive evidence the NIC carries live addressing the
// rename must reproduce. The #7114 appliance factory lifeline is chosen
// precisely when there is NO default route — the bake purges cloud-init and
// netplan, so nothing has brought a NIC up — and DHCP is that image's
// documented vNIC#1 -> fxp0 contract. A failed observation there cannot change
// a single byte of what gets written, so refusing would break the factory boot
// to protect information that was never going to be used.
//
// This was not a hypothetical: the first version of the fix refused
// unconditionally and reddened the pre-existing
// TestSetupBootstrapLifelineAppliance.
//
// FAIL-ON-REVERT: removing the hasRouteEvidence scope makes the appliance boot
// refuse and reds the "DHCP .network written" assertion.
func TestApplianceFactoryBootIsNotRefusedByASnapshotFailure6789(t *testing.T) {
	st := staticLifelineSeams(t)
	// #7114 precondition: NO default route, plus the appliance marker.
	detectLifelineInterfaceFn = func() (string, bool) { return "", false }

	dir := t.TempDir()
	oldMarker := applianceMarkerFile
	applianceMarkerFile = filepath.Join(dir, "appliance")
	t.Cleanup(func() { applianceMarkerFile = oldMarker })
	if err := os.WriteFile(applianceMarkerFile, []byte("appliance\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// And the addressing observation fails, exactly as in the refusing arms.
	lifelineLinkByName = func(string) (netlink.Link, error) {
		return nil, errors.New("injected: netlink observation failure")
	}

	d := &Daemon{store: newConfigStore(t, filepath.Join(dir, "xpf.conf"))}
	if d.store.EverCommitted() {
		t.Fatal("premise: a fresh store must report EverCommitted()==false")
	}
	d.setupBootstrapLifeline()

	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	data, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatalf("an appliance FACTORY boot must still claim vNIC#1 as fxp0 with the image's DHCP "+
			".network even when the addressing observation fails: there is no default route and no "+
			"addressing to reproduce, so nothing observable could have changed the output. "+
			"Refusing here breaks the factory image (#7114/#6789). err=%v", err)
	}
	if !contains6789(string(data), "DHCP=yes") {
		t.Errorf("the appliance factory .network must be the DHCP form; got:\n%s", data)
	}
}
