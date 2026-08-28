package dataplane

import (
	"net"
	"testing"
)

// #6955: `buildInterfaceNetworkdModels` derives the xfrmi netdev name from the
// unit REF (`XFRMIfNameAndID("<ifName>.<unit>")`), but the reconciler
// materialises the device under the AUTHORED `bind-interface` string. The two
// agree only for the dotted spelling.
//
// The DISCRIMINATOR is the authored bind string, and nothing else: both cases
// below use interface `st0` with unit 0, so the unit ref is `st0.0` in both.
// Only `BindInterface` differs.
func TestBareBindInterfaceGetsItsAuthoredAddress_6955(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bind      string
		netdev    string // what pkg/routing/xfrm.go actually creates
		wantModel bool
	}{
		// Control: the DOTTED spelling, where reconstructing "<if>.<unit>"
		// happens to equal the authored string. This is the shape every
		// existing fixture uses, which is why the defect stayed green.
		{name: "dotted spelling gets its address", bind: "st0.0", netdev: "st0.0", wantModel: true},
		// The defect: the BARE spelling — the canonical form, the one
		// ValidateSecureTunnelBindInterface advertises first.
		{name: "bare spelling gets its address", bind: "st0", netdev: "st0", wantModel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := stCfg6729("st0", []int{0}, tc.bind)
			// Seed the netdev the reconciler would have created for THIS
			// authored spelling. Without this the lookup fails for a second,
			// unrelated reason and the cell cannot distinguish the defect.
			result := &CompileResult{ifCache: map[string]*net.Interface{
				tc.netdev: {Index: 98, Name: tc.netdev},
			}}
			buildInterfaceNetworkdModels(cfg, result, map[string]bool{})

			var got *string
			var addrs []string
			for i := range result.ManagedInterfaces {
				if result.ManagedInterfaces[i].Name == tc.netdev {
					got = &result.ManagedInterfaces[i].Name
					addrs = result.ManagedInterfaces[i].Addresses
				}
			}
			if tc.wantModel && got == nil {
				t.Fatalf("#6955: no networkd model for the netdev %q that the xfrmi "+
					"reconciler creates from `bind-interface %s` — the authored "+
					"`family inet address` is never applied, so the tunnel comes up "+
					"with no IP and no connected prefix. Models present: %v",
					tc.netdev, tc.bind, modelNames6955(result))
			}
			if tc.wantModel && len(addrs) == 0 {
				t.Fatalf("#6955: model for %q carries no addresses", tc.netdev)
			}
		})
	}
}

func modelNames6955(r *CompileResult) []string {
	out := make([]string, 0, len(r.ManagedInterfaces))
	for _, m := range r.ManagedInterfaces {
		out = append(out, m.Name)
	}
	return out
}
