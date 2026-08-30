package dataplane

import (
	"reflect"
	"strings"
	"testing"
)

// TestRetiredNATWriteSurfaceStaysOff is the precondition guard for #7268.
//
// The deletion rests on a specific argument, and it is NOT "nothing calls
// these". It is that the maps they wrote -- snat_rules, snat_rules_v6,
// static_nat_v4, static_nat_v6, nptv6_rules, nat_pool_*, snat_egress_ips and
// nat64_* -- are not declared by the AF_XDP shim (userspace-xdp/src/lib.rs), so
// on the deployed dataplane there is nowhere for the write to land even if a
// caller returned. #6420 removed the record construction that used to call
// them; a future change could reintroduce one, and it would have to re-add a
// method here to do it.
//
// So this asserts the METHOD SET, by reflection over the interface rather than
// by scanning source. A source scan can be satisfied by a comment that happens
// to contain the name; a reflection assertion cannot.
//
// dnat_table and dnat_table_v6 are deliberately NOT in this list: the shim DOES
// declare them (lib.rs:375, "so dynamic SNAT-return entries are visible here"),
// and SetDNATEntry/SetDNATEntryV6 are called on the HA session-sync receive
// path (session_store.go PutClusterSyncedV4). Those are live writes into a live
// map and must keep working.
func TestRetiredNATWriteSurfaceStaysOff(t *testing.T) {
	retired := []string{
		"SetSNATRule", "SetSNATRuleV6", "ClearSNATRules", "ClearSNATRulesV6",
		"SetStaticNATEntryV4", "SetStaticNATEntryV6", "ClearStaticNATEntries",
		"SetNPTv6Rule", "DeleteStaleNPTv6",
		"SetNATPoolConfig", "SetNATPoolIPV4", "SetNATPoolIPV6",
		"ClearNATPoolConfigs", "ClearNATPoolIPs",
		"SetSNATEgressIP", "ClearSNATEgressIPs",
		"SetNAT64Config", "SetNAT64Count", "ClearNAT64Configs",
		"ClearDNATStatic", "ClearDNATStaticV6",
		"DeleteStaleSNATRules", "DeleteStaleSNATRulesV6",
	}

	dpType := reflect.TypeOf((*DataPlane)(nil)).Elem()

	// ANTI-VACUITY FLOOR. If the reflection ever stopped reaching the real
	// interface -- a rename, a build tag, a moved type -- every membership
	// check below would pass against an empty method set and this test would
	// certify the retirement while measuring nothing.
	if dpType.NumMethod() < 40 {
		t.Fatalf("DataPlane reflects %d methods; the scan is not reaching the real "+
			"interface, so a clean result here would certify nothing", dpType.NumMethod())
	}

	for _, name := range retired {
		if _, ok := dpType.MethodByName(name); ok {
			t.Errorf("DataPlane declares %s again. The maps this wrote are not declared "+
				"by the AF_XDP shim, so re-adding the method means re-adding a write with "+
				"nowhere to land -- if a NAT record constructor came back, it needs a live "+
				"map, not this surface (#7268)", name)
		}
	}

	// POSITIVE CONTROL, and it is what stops the loop above from passing
	// because the names are simply misspelled or the interface is empty: the
	// LIVE DNAT writes must still be declared.
	for _, name := range []string{"SetDNATEntry", "SetDNATEntryV6", "DeleteDNATEntry", "DeleteDNATEntryV6"} {
		if _, ok := dpType.MethodByName(name); !ok {
			t.Errorf("DataPlane no longer declares %s, which the HA session-sync receive "+
				"path calls into the shim-declared dnat_table (#7268)", name)
		}
	}
}

// TestRetiredNATWriteSurfaceGoneFromManager mirrors the check on the concrete
// eBPF writer. The interface and the implementation are separate surfaces: a
// method removed from the interface but left on *Manager is still reachable by
// anyone holding the concrete type, which is exactly how the retired writers
// would come back into use.
func TestRetiredNATWriteSurfaceGoneFromManager(t *testing.T) {
	mType := reflect.TypeOf(&Manager{})
	if mType.NumMethod() < 100 {
		t.Fatalf("*Manager reflects %d methods; the scan is not reaching the real type",
			mType.NumMethod())
	}
	for i := 0; i < mType.NumMethod(); i++ {
		name := mType.Method(i).Name
		switch {
		case strings.HasPrefix(name, "SetSNATRule"),
			strings.HasPrefix(name, "SetStaticNATEntry"),
			strings.HasPrefix(name, "SetNPTv6"),
			strings.HasPrefix(name, "SetNATPool"),
			strings.HasPrefix(name, "SetSNATEgress"),
			strings.HasPrefix(name, "SetNAT64"),
			strings.HasPrefix(name, "DeleteStaleSNATRules"),
			strings.HasPrefix(name, "DeleteStaleNPTv6"):
			t.Errorf("*Manager declares %s again — the retired eBPF NAT writer is back "+
				"on the concrete type even if the interface no longer names it (#7268)", name)
		}
	}
}
