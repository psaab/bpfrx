package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6729 / #6730: `pkg/dataplane/compiler_iface.go` carried TWO raw
// `strings.HasPrefix(name, "st")` tests and treated both as "this is a secure
// tunnel". They are one family and they are fixed together, but the defects
// they caused are different:
//
//   - resolveInterfaceRef ALSO reconstructed the xfrmi device name from the
//     unit REF. The reconciler creates the device under the AUTHORED
//     bind-interface string verbatim (pkg/routing/xfrm.go), so a bare
//     `bind-interface st0` yields a netdev named `st0` while the unit ref is
//     `st0.0` — and the resolver answered `st0.0`, a device that does not
//     exist. mapZoneInterface then logs "interface not found, skipping": the
//     tunnel is dropped from zone programming and from the SNAT
//     egress-address walk.
//   - buildInterfaceNetworkdModels ends its `st` branch in an unconditional
//     `continue`, so a NIC merely named `start0` got no networkd model at all
//     — no addresses, no MTU, no DHCP — and stripUnmanagedInterfaces then
//     brings it DOWN.
//
// Both now use the bounded predicate the xfrmi constructor itself uses.

// stCfg6729 builds a config with one interface and, optionally, one IPsec VPN
// binding the given string. Only the fields the two resolvers read are set.
func stCfg6729(ifName string, units []int, bindInterface string) *config.Config {
	unitMap := map[int]*config.InterfaceUnit{}
	for _, u := range units {
		unitMap[u] = &config.InterfaceUnit{Addresses: []string{"10.5.5.1/30"}}
	}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				ifName: {Name: ifName, Units: unitMap},
			},
		},
	}
	if bindInterface != "" {
		cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
			"v": {Name: "v", BindInterface: bindInterface},
		}
	}
	return cfg
}

// TestResolveInterfaceRefReadsTheAuthoredBindInterface_6729 is the #6729
// fail-on-revert: under the BARE spelling the resolver must answer the device
// the reconciler actually created.
//
// The two spellings are the whole point, and they are asserted TOGETHER: `st0`
// and `st0.0` derive the same if_id but create DIFFERENT device names, while
// the unit ref is `st0.0` either way. A test that only checked the explicit
// spelling would pass against the reconstruct-from-ref bug, because for that
// spelling the reconstruction happens to be right.
func TestResolveInterfaceRefReadsTheAuthoredBindInterface_6729(t *testing.T) {
	cases := []struct {
		name          string
		bindInterface string
		wantPhys      string
	}{
		{
			// The reported shape. The netdev is `st0`; reconstructing from
			// the ref gives `st0.0`, which does not exist.
			name: "bare bind-interface", bindInterface: "st0", wantPhys: "st0",
		},
		{
			// The spelling the old code got right by coincidence — kept so
			// the fix is shown not to have simply inverted the answer.
			name: "explicit unit bind-interface", bindInterface: "st0.0", wantPhys: "st0.0",
		},
		{
			// No VPN binds it: there is no xfrmi, and the verbatim ref is
			// what this returned before #6729. Unchanged on purpose.
			name: "no VPN binds the ref", bindInterface: "", wantPhys: "st0.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := stCfg6729("st0", []int{0}, tc.bindInterface)
			phys, cfgName, unitNum, _ := resolveInterfaceRef("st0.0", cfg)
			if phys != tc.wantPhys {
				t.Fatalf("physName = %q, want %q — the reconciler creates the xfrmi under the "+
					"AUTHORED bind-interface string, so a name reconstructed from the ref "+
					"resolves a device that does not exist and the tunnel is dropped from "+
					"zone programming (#6729)", phys, tc.wantPhys)
			}
			if cfgName != "st0" || unitNum != 0 {
				t.Fatalf("cfgName/unitNum = %q/%d, want st0/0", cfgName, unitNum)
			}
			// Corroboration: the config-reading resolver that already had this
			// right is the one this now agrees with. Asserting the AGREEMENT
			// rather than only the literal is what keeps the two from drifting
			// apart again — they answered differently for exactly one spelling.
			if got := cfg.ResolveKernelIfName("st0.0"); got != phys {
				t.Fatalf("resolveInterfaceRef = %q but Config.ResolveKernelIfName = %q: the "+
					"dataplane resolver and the config resolver disagree about the same ref",
					phys, got)
			}
		})
	}
}

// TestResolveInterfaceRefDoesNotClaimAnStPrefixedNIC_6729 is the second defect
// at the same site: `HasPrefix("st")` is not the secure-tunnel predicate.
//
// `start0` is a legal interface name — names are wildcard-authorable and there
// is no reserved `st` namespace — and its unit must resolve to the ordinary
// base netdev, not to the verbatim ref.
func TestResolveInterfaceRefDoesNotClaimAnStPrefixedNIC_6729(t *testing.T) {
	for _, ifName := range []string{"start0", "stx", "st65536"} {
		t.Run(ifName, func(t *testing.T) {
			cfg := stCfg6729(ifName, []int{0}, "")
			phys, _, _, _ := resolveInterfaceRef(ifName+".0", cfg)
			if phys != ifName {
				t.Fatalf("physName = %q for %q.0, want the base netdev %q — a raw two-letter "+
					"prefix claimed an ordinary NIC as a secure tunnel (#6729/#6730)",
					phys, ifName, ifName)
			}
		})
	}
}

// TestNetworkdModelsCoverAnStPrefixedNIC_6730 is the #6730 fail-on-revert.
//
// The `st` branch in buildInterfaceNetworkdModels ends in an unconditional
// `continue`, so any name it claims never reaches the physical-interface
// handling. For `start0` every unit also failed XFRMIfNameAndID, so the
// interface produced NO model at all and stripUnmanagedInterfaces — running
// against this same `seen` set — brings it down.
//
// FAIL-ON-REVERT: restore `strings.HasPrefix(ifName, "st")` and `start0`
// vanishes from ManagedInterfaces entirely.
func TestNetworkdModelsCoverAnStPrefixedNIC_6730(t *testing.T) {
	for _, ifName := range []string{"start0", "stx", "st65536"} {
		t.Run(ifName, func(t *testing.T) {
			cfg := stCfg6729(ifName, []int{0}, "")
			// Seed the interface cache: the physical path skips a name with
			// no netdev (`if physIface == nil { continue }`), so without this
			// the test would observe THIS HOST rather than the fix, and would
			// red identically before and after it.
			result := &CompileResult{ifCache: map[string]*net.Interface{
				config.LinuxIfName(ifName): {
					Index: 99,
					Name:  config.LinuxIfName(ifName),
					// A MAC is required, not decoration: the physical path
					// does `if mac == "" { continue }`, so a MAC-less stub
					// would skip the append for a reason that has nothing to
					// do with this fix.
					HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
				},
			}}
			buildInterfaceNetworkdModels(cfg, result, map[string]bool{})

			found := false
			for _, m := range result.ManagedInterfaces {
				if m.Name == ifName || m.Name == config.LinuxIfName(ifName) {
					found = true
					break
				}
			}
			if !found {
				names := make([]string, 0, len(result.ManagedInterfaces))
				for _, m := range result.ManagedInterfaces {
					names = append(names, m.Name)
				}
				t.Fatalf("%q produced no networkd model (models: %v) — it is silently "+
					"unconfigured (no addresses, no MTU, no DHCP) and "+
					"stripUnmanagedInterfaces then brings it DOWN (#6730)", ifName, names)
			}
		})
	}
}

// TestNetworkdModelsStillSkipARealSecureTunnel_6730 is the TIGHTENING control.
//
// The fix narrows which names take the tunnel branch, so it owes a proof that
// it did not narrow it to nothing: a genuine in-range `st<N>` must still take
// that branch and must NOT be emitted as an ordinary physical interface — the
// xfrmi is created by pkg/routing, not by networkd.
func TestNetworkdModelsStillSkipARealSecureTunnel_6730(t *testing.T) {
	// #6955 re-pointed this fixture from BOUND to UNBOUND, and the reason is
	// the point of the test rather than a detail.
	//
	// This cell exists to prove a secure-tunnel name does not fall through to
	// the PHYSICAL-interface handling. It used to assert that with a VPN
	// binding the bare `st0`, no model named `st0` was emitted — but that held
	// only because of the #6955 defect: the branch reconstructed the netdev as
	// `st0.0`, missed the lookup, and `continue`d. It was pinning the bug. The
	// DOTTED spelling emitted a model from this same branch even then, so
	// "a real secure tunnel never gets a model" was never the contract.
	//
	// UNBOUND is the shape that tests the stated intent. No VPN binds `st0`,
	// so pkg/routing creates no device and the secure-tunnel branch correctly
	// emits nothing — and if the predicate ever let the name reach the
	// physical path, a model WOULD appear and this fails. The seeded netdev
	// below is what gives that its teeth.
	cfg := stCfg6729("st0", []int{0}, "")
	// Seeded for the same reason, and here it is what gives the control its
	// teeth: with the netdev present, a predicate that wrongly let `st0` reach
	// the physical path WOULD emit a model, so this can actually fail.
	result := &CompileResult{ifCache: map[string]*net.Interface{
		"st0": {
			Index:        98,
			Name:         "st0",
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		},
	}}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})

	for _, m := range result.ManagedInterfaces {
		if m.Name == "st0" {
			t.Fatalf("a real secure tunnel reached the physical-interface handling and was "+
				"emitted as a networkd model (%q) — the xfrmi is created by pkg/routing, "+
				"and the narrowed predicate must not widen this branch's escape hatch", m.Name)
		}
	}
}
