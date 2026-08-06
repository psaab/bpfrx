package dataplane

// #4960 probe: is CompileConfig's ID assignment deterministic across two
// passes with a fresh CompileResult each time?
//
// The additive validate-pre-pass design compiles the config TWICE and discards
// the first result. That is only free if no ID assignment reads or mutates
// state outliving a single CompileResult -- a process-global, a counter on the
// DataPlane, an interned table. A fresh result isolates state IN the result and
// nothing else, so this is measured rather than reasoned about: run the
// ID-assigning phases twice against the same dp and compare every ID map.
//
// The fake embeds the DataPlane interface (the userspace LegacyDataPlaneAdapter
// idiom) so it satisfies all 130 methods while overriding only the 34 the pure
// phases actually call. Any method reached that is NOT overridden nil-panics,
// which is the desired behaviour for a probe: it surfaces an unexpected call
// rather than silently succeeding.

import (
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// idProbeEgressIface is the egress-zone member idProbeConfig declares. It is
// deliberately a name no host carries, so the SNAT-egress branch soft-skips
// everywhere except the one test that seeds a synthetic ifCache entry for it.
const idProbeEgressIface = "xpfp4960e"

type idProbeDP struct{ DataPlane }

func (idProbeDP) IsLoaded() bool { return true }

func (idProbeDP) SetZonePairPolicy(fromZone, toZone uint16, ps PolicySet) error { return nil }
func (idProbeDP) SetPolicyRule(policySetID uint32, ruleIndex uint32, rule PolicyRule) error {
	return nil
}
func (idProbeDP) SetAddressBookEntry(cidr string, addressID uint32) error { return nil }
func (idProbeDP) SetAddressMembership(resolvedID, setID uint32) error     { return nil }
func (idProbeDP) ClearAddressBookV4() error                               { return nil }
func (idProbeDP) ClearAddressBookV6() error                               { return nil }
func (idProbeDP) ClearAddressMembership() error                           { return nil }
func (idProbeDP) SetApplication(protocol uint8, dstPort uint16, appID uint32, timeout uint32, algType uint8, srcPortLow, srcPortHigh uint16) error {
	return nil
}
func (idProbeDP) SetAppRange(index uint32, entry AppRangeEntry) error                     { return nil }
func (idProbeDP) SetDNATEntry(key DNATKey, val DNATValue) error                           { return nil }
func (idProbeDP) SetDNATEntryV6(key DNATKeyV6, val DNATValueV6) error                     { return nil }
func (idProbeDP) SetSNATRule(fromZone, toZone, ruleIdx uint16, val SNATValue) error       { return nil }
func (idProbeDP) SetSNATRuleV6(fromZone, toZone, ruleIdx uint16, val SNATValueV6) error   { return nil }
func (idProbeDP) SetNATPoolConfig(poolID uint32, cfg NATPoolConfig) error                 { return nil }
func (idProbeDP) SetNATPoolIPV4(poolID, index uint32, ip uint32) error                    { return nil }
func (idProbeDP) SetNATPoolIPV6(poolID, index uint32, ip [16]byte) error                  { return nil }
func (idProbeDP) SetSNATEgressIP(key SNATEgressKey, val SNATEgressValue) error            { return nil }
func (idProbeDP) ClearSNATEgressIPs() error                                               { return nil }
func (idProbeDP) SetStaticNATEntryV4(ip uint32, direction uint8, translated uint32) error { return nil }
func (idProbeDP) SetStaticNATEntryV6(ip [16]byte, direction uint8, translated [16]byte) error {
	return nil
}
func (idProbeDP) SetNPTv6Rule(key NPTv6Key, val NPTv6Value) error          { return nil }
func (idProbeDP) DeleteStaleNPTv6(written map[NPTv6Key]bool)               {}
func (idProbeDP) SetNAT64Config(index uint32, cfg NAT64Config) error       { return nil }
func (idProbeDP) SetNAT64Count(count uint32) error                         { return nil }
func (idProbeDP) DeleteStaleZonePairPolicies(written map[ZonePairKey]bool) {}
func (idProbeDP) DeleteStaleApplications(written map[AppKey]bool)          {}
func (idProbeDP) DeleteStaleSNATRules(written map[SNATKey]bool)            {}
func (idProbeDP) DeleteStaleSNATRulesV6(written map[SNATKey]bool)          {}
func (idProbeDP) DeleteStaleDNATStatic(written map[DNATKey]bool)           {}
func (idProbeDP) DeleteStaleDNATStaticV6(written map[DNATKeyV6]bool)       {}
func (idProbeDP) DeleteStaleStaticNAT(writtenV4 map[StaticNATKeyV4]bool, writtenV6 map[StaticNATKeyV6]bool) {
}
func (idProbeDP) DeleteStaleNAT64(count uint32, writtenPrefixes map[NAT64PrefixKey]bool) {}
func (idProbeDP) ZeroStaleNATPoolConfigs(startID uint32)                                 {}
func (idProbeDP) GetPersistentNAT() *PersistentNATTable                                  { var z *PersistentNATTable; return z }

// idProbeConfig exercises every ID-assigning phase that the validate-pre-pass
// would run: zones (ZoneIDs), screen profiles (ScreenIDs), the address book
// (AddrIDs + implicitSets), applications (AppIDs), and NAT (PoolIDs +
// NATCounterIDs, the #5099 collision-order-sensitive family).
//
// It is ALSO the fixture TestPrePassShimCoversTheCalledSurface_4960 drives to
// prove discardingDataPlane's override set is complete, and that second job is
// what sizes it (#6894 r3 F1). Reaching every PHASE is not the same as reaching
// every phase's WRITE SURFACE: measured at r2, this config reached 28 of the 40
// overrides, and nine of them -- SetDNATEntry, SetDNATEntryV6, SetNAT64Config,
// SetNATPoolIPV6, SetNPTv6Rule, SetSNATEgressIP, SetSNATRuleV6,
// SetStaticNATEntryV4, SetStaticNATEntryV6 -- were reached by NO test in the
// package, so any one of them could be deleted with the suite still green while
// an ordinary `security nat destination` config nil-panicked the daemon on
// apply. Every NAT family below exists to close that: destination NAT (v4+v6),
// static NAT (v4+v6), NPTv6, NAT64, an IPv6 source pool with its v6 SNAT rule,
// an interface-SNAT rule that yields an egress IP, and a security policy.
//
// Keep it able to reach all 39 pre-pass-reachable overrides when adding to it;
// the 40th, IsLoaded, is called by CompileConfig itself (compiler.go:182),
// above the pre-pass, so no config can reach it from validateBeforeMutate.
//
// Interface names are deliberately outside the vSRX scheme. The zone interface
// list became load-bearing here when the interface-SNAT rule was added, and
// `ge-0-0-1` is a real link on the standalone test VM and on loss cluster node
// 0 -- so a vSRX-shaped name would make this fixture resolve differently on a
// firewall than on a dev host, and would name a live link in a config that a
// future test could hand to CompileConfig.
func idProbeConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"xpfp4960a.0"}},
		"untrust": {Name: "untrust", Interfaces: []string{"xpfp4960b.0"}},
		"dmz":     {Name: "dmz", Interfaces: []string{"xpfp4960c.0"}},
		// The interface-SNAT egress zone. Its member is declared with a
		// redundancy group so compileNAT reads the egress addresses from the
		// CONFIG rather than querying the live interface -- the only remaining
		// host dependency is then the ifindex lookup, which
		// TestPrePassShimCoversTheCalledSurface_4960 satisfies with a synthetic
		// ifCache entry rather than a real link.
		"egress": {Name: "egress", Interfaces: []string{idProbeEgressIface + ".0"}},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"zeta": {Name: "zeta"}, "alpha": {Name: "alpha"}, "mid": {Name: "mid"},
	}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"web": {Name: "web", Value: "10.1.0.0/16"},
			"db":  {Name: "db", Value: "10.2.0.0/16"},
			"dns": {Name: "dns", Value: "10.3.0.1/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"servers": {Name: "servers", Addresses: []string{"web", "db"}},
		},
	}
	// includeAll mode: CatalogNames collects every predefined + user app, so
	// AppIDs is populated without needing a policy to reference each one. Same
	// config.AssignStableAppIDs path either way.
	cfg.Services.ApplicationIdentification = true
	cfg.Applications.Applications = map[string]*config.Application{
		"app-ssh":  {Name: "app-ssh", Protocol: "tcp", DestinationPort: "22"},
		"app-http": {Name: "app-http", Protocol: "tcp", DestinationPort: "80"},
		"app-dns":  {Name: "app-dns", Protocol: "udp", DestinationPort: "53"},
	}
	// The egress-zone member. RedundancyGroup > 0 routes compileNAT's
	// interface-SNAT branch down the RETH path, which takes the egress IPs from
	// these unit addresses instead of querying the live interface.
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		idProbeEgressIface: {
			Name: idProbeEgressIface, RedundancyGroup: 1,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"203.0.113.7/24", "2001:db8:e::7/64"}},
			},
		},
	}
	// A security policy, so compilePolicies reaches SetZonePairPolicy and
	// SetPolicyRule. Neither was reached by this fixture before r3.
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				{
					Name: "p-probe",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"servers"},
						Applications:         []string{"app-ssh", "app-http"},
					},
					Action: config.PolicyPermit,
				},
			},
		},
	}
	// Source NAT: two pools and three rules across two rule-sets. This is the
	// #5099 dimension -- PoolIDs and the per-rule NATCounterIDs whose streaming
	// assignment was compile-order dependent on a hash collision, which is why
	// finalizeNATCounterIDs exists. Without these the ID comparison is
	// {} == {} and proves nothing about the risk the pre-pass actually carries.
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"pool-b": {Name: "pool-b", Addresses: []string{"192.0.2.10", "192.0.2.11"}},
		"pool-a": {Name: "pool-a", Addresses: []string{"198.51.100.5"}},
		// v6-only pool: hasV6 is what selects the SetSNATRuleV6 write, and the
		// pool addresses are what reach SetNATPoolIPV6.
		"pool-v6": {Name: "pool-v6", Addresses: []string{"2001:db8:6::1", "2001:db8:6::2"}},
		// Referenced only by the NAT64 rule-set below, so compileNAT64 takes its
		// auto-assign branch (a pool defined but never used by an SNAT rule).
		"pool-nat64": {Name: "pool-nat64", Addresses: []string{"192.0.2.64"}},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name: "rs-trust-untrust", FromZone: "trust", ToZone: "untrust",
			Rules: []*config.NATRule{
				{Name: "r-web", Match: config.NATMatch{SourceAddress: "10.1.0.0/16"},
					Then: config.NATThen{Type: config.NATSource, PoolName: "pool-a"}},
				{Name: "r-db", Match: config.NATMatch{SourceAddress: "10.2.0.0/16"},
					Then: config.NATThen{Type: config.NATSource, PoolName: "pool-b"}},
				{Name: "r-v6", Match: config.NATMatch{SourceAddress: "2001:db8:1::/64"},
					Then: config.NATThen{Type: config.NATSource, PoolName: "pool-v6"}},
			},
		},
		{
			Name: "rs-dmz-untrust", FromZone: "dmz", ToZone: "untrust",
			Rules: []*config.NATRule{
				{Name: "r-dmz", Match: config.NATMatch{SourceAddress: "10.3.0.0/16"},
					Then: config.NATThen{Type: config.NATSource, Interface: true}},
			},
		},
		{
			// Interface mode against a to-zone whose member carries configured
			// addresses: this is the SetSNATEgressIP path. It soft-skips unless
			// the interface resolves, which is why the completeness test seeds
			// an ifCache entry for it.
			Name: "rs-trust-egress", FromZone: "trust", ToZone: "egress",
			Rules: []*config.NATRule{
				{Name: "r-egress", Match: config.NATMatch{SourceAddress: "10.1.0.0/16"},
					Then: config.NATThen{Type: config.NATSource, Interface: true}},
			},
		},
	}
	// Destination NAT, v4 and v6. The pool takes `Address` (a single host
	// address) plus `Port`; `Addresses` is source-only and would silently warn
	// "invalid DNAT pool address". The match must be a host address too -- a
	// network prefix is a hard error, not a skip.
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"dpool-v4": {Name: "dpool-v4", Address: "10.4.0.9", Port: 8080},
			"dpool-v6": {Name: "dpool-v6", Address: "2001:db8:d::9", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name: "rs-dnat", FromZone: "untrust",
				Rules: []*config.NATRule{
					{Name: "d-v4", Match: config.NATMatch{
						DestinationAddress: "198.51.100.9/32", DestinationPort: 443, Protocol: "tcp"},
						Then: config.NATThen{Type: config.NATDestination, PoolName: "dpool-v4"}},
					{Name: "d-v6", Match: config.NATMatch{
						DestinationAddress: "2001:db8:9::9/128", DestinationPort: 443, Protocol: "tcp"},
						Then: config.NATThen{Type: config.NATDestination, PoolName: "dpool-v6"}},
				},
			},
		},
	}
	// Static NAT (v4 and v6) plus one NPTv6 rule. compileStaticNAT skips
	// IsNPTv6 rules and compileNPTv6 handles only those, so the three rules
	// below reach three different write surfaces from one rule-set. NPTv6
	// prefixes must be IPv6, equal length, and /48 or /64.
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name: "rs-static", FromZone: "untrust",
			Rules: []*config.StaticNATRule{
				{Name: "s-v4", Match: "198.51.100.20", Then: "10.4.0.20"},
				{Name: "s-v6", Match: "2001:db8:20::20", Then: "fd00:20::20"},
				{Name: "s-npt", IsNPTv6: true,
					Match: "2001:db8:48::/48", Then: "fd00:48::/48"},
			},
		},
	}
	// NAT64: the prefix must be a /96, and the source pool must exist.
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{
		{Name: "rs64", Prefix: "64:ff9b::/96", SourcePool: "pool-nat64"},
	}
	return cfg
}

// compileIDsOnce runs the ID-ASSIGNING phases against a fresh CompileResult
// and returns the assigned IDs. Deliberately NOT the pre-pass's phase set: it
// is the ID-assigning subset PLUS finalizeNATCounterIDs, which the pre-pass
// does not call. The question here is ID stability across two compiles, not
// pre-pass coverage (#6894 r1 F5).
func compileIDsOnce(t *testing.T, cfg *config.Config) map[string]any {
	t.Helper()
	dp := idProbeDP{}
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	screenID := uint16(1)
	names := make([]string, 0, len(cfg.Security.Screen))
	for n := range cfg.Security.Screen {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		result.ScreenIDs[n] = screenID
		screenID++
	}
	if err := compileAddressBook(dp, cfg, result); err != nil {
		t.Fatalf("compileAddressBook: %v", err)
	}
	if err := compileApplications(dp, cfg, result); err != nil {
		t.Fatalf("compileApplications: %v", err)
	}
	if err := compileNAT(dp, cfg, result); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	finalizeNATCounterIDs(result)
	return map[string]any{
		"ZoneIDs":       result.ZoneIDs,
		"ScreenIDs":     result.ScreenIDs,
		"AddrIDs":       result.AddrIDs,
		"AppIDs":        result.AppIDs,
		"PoolIDs":       result.PoolIDs,
		"NATCounterIDs": result.NATCounterIDs,
		"implicitSets":  result.implicitSets,
	}
}

// #4960: the validate-pre-pass compiles the config twice and throws the first
// result away. That is only free if the SECOND pass assigns byte-identical IDs
// to what a single pass would have. If any assignment read or mutated state
// outliving a CompileResult -- a process-global, a counter on the DataPlane, an
// interned table -- pass two would differ and the pre-pass would silently
// change what the live dataplane is programmed with.
//
// Measured rather than reasoned about: #6819's counters also "looked"
// per-instance until someone constructed two instances.
func TestPrePassDoesNotPerturbIDAssignment_4960(t *testing.T) {
	cfg := idProbeConfig()

	first := compileIDsOnce(t, cfg)  // the discarded validate pass
	second := compileIDsOnce(t, cfg) // the real pass that programs the dataplane

	for _, k := range []string{"ZoneIDs", "ScreenIDs", "AddrIDs", "AppIDs",
		"PoolIDs", "NATCounterIDs", "implicitSets"} {
		if !reflect.DeepEqual(first[k], second[k]) {
			t.Errorf("%s differs between pass 1 and pass 2 — a discarded "+
				"validate pre-pass would PERTURB the IDs the live dataplane is "+
				"programmed with (#4960)\n  pass1: %v\n  pass2: %v",
				k, first[k], second[k])
		}
	}
	if len(first["ZoneIDs"].(map[string]uint16)) == 0 {
		t.Fatal("fixture assigned no zone IDs — the comparison would be vacuous")
	}
	if len(first["AppIDs"].(map[string]uint32)) == 0 {
		t.Fatal("fixture assigned no application IDs — comparison vacuous")
	}
	// The NAT counter IDs are THE dimension this probe exists for: #5099 made
	// their streaming assignment compile-order dependent on a hash collision,
	// which is the one place "compile twice" is not obviously free. An empty
	// map compares equal to an empty map, so assert the fixture actually
	// populated them or the DeepEqual above proved nothing here.
	if len(first["NATCounterIDs"].(map[string]uint32)) == 0 {
		t.Fatal("fixture assigned no NAT counter IDs — the #5099 dimension of " +
			"this comparison is VACUOUS; add NAT rules to the fixture")
	}
	if len(first["PoolIDs"].(map[string]uint8)) == 0 {
		t.Fatal("fixture assigned no NAT pool IDs — comparison vacuous there")
	}
}
