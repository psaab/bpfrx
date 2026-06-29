package config

import "testing"

// #3494: ValidateConfig's warning pass dereferences zone-pair sets
// (cfg.Security.Policies), rules (zpp.Policies / cfg.Security.GlobalPolicies),
// and zone map values (cfg.Security.Zones) without nil guards. The tolerant /
// HA-sync config path (#3474/#3476 premise) can deliver nil slots that the
// enforcement/runtime walker (pkg/dataplane/userspace/{policies,zones}.go)
// already tolerates — and operators rely on these warnings to diagnose exactly
// those partially-synchronized configs. This test injects a nil zone-pair set,
// a nil rule (in a real set and in GlobalPolicies), and a nil zone value, then
// runs the warning pass. Reverting any of the compiler_validate_warn.go
// `if zpp == nil` / `if p == nil` / `if zone == nil` guards makes it panic
// (RED on revert). The strict compiler never emits these nils.
func TestValidateConfigNilSlotsNoPanic(t *testing.T) {
	cfg := &Config{}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"trust": {
			Name:          "trust",
			ScreenProfile: "sp", // undefined -> warning, exercises line 186 deref
			Interfaces:    []string{"ge-0/0/0.0"},
		},
		"zz-nil-zone": nil, // #3494: nil zone value (lines 186, 279)
	}
	cfg.Security.Policies = []*ZonePairPolicies{
		{
			FromZone: "trust",
			ToZone:   "untrust", // undefined -> warning
			Policies: []*Policy{
				{Name: "p1", SchedulerName: "sched-x"}, // undefined sched -> warning
				nil,                                    // #3494: nil rule (lines 134, 295)
			},
		},
		nil, // #3494: nil zone-pair set (lines 125, 294)
	}
	cfg.Security.GlobalPolicies = []*Policy{
		{Name: "g1", SchedulerName: "sched-y"},
		nil, // #3494: nil global rule (line 304)
	}

	// #3494 (Codex MERGE-NEEDS-MAJOR fold): the same warning pass derefs NAT
	// rule-sets/rules, applications, address-book entries/sets, and static
	// routes — all nil-tolerant pointer slices/maps. Inject a nil element into
	// each so reverting any added guard panics.
	cfg.Security.NAT.Source = []*NATRuleSet{
		{
			Name:     "snat-rs",
			FromZone: "trust",
			ToZone:   "no-such-zone", // undefined -> warning
			Rules: []*NATRule{
				{Name: "sr1", Then: NATThen{PoolName: "no-such-spool"}}, // undefined pool -> warning
				nil, // #3494: nil NAT rule (source pool loop)
			},
		},
		nil, // #3494: nil NAT rule-set (zone-ref loop + source pool loop)
	}
	cfg.Security.NAT.Destination = &DestinationNATConfig{
		RuleSets: []*NATRuleSet{
			{
				Name: "dnat-rs",
				Rules: []*NATRule{
					{Name: "dr1", Then: NATThen{PoolName: "no-such-dpool"}}, // undefined pool -> warning
					nil, // #3494: nil NAT rule (DNAT pool loop)
				},
			},
			nil, // #3494: nil NAT rule-set (DNAT pool loop)
		},
	}
	cfg.Applications.Applications = map[string]*Application{
		"app1":       {Name: "app1", Protocol: "not-a-proto"}, // invalid proto -> warning
		"zz-nil-app": nil,                                     // #3494: nil application value
	}
	cfg.Security.AddressBook = &AddressBook{
		Addresses: map[string]*Address{
			"a1":          {Name: "a1", Value: ""}, // empty prefix -> warning
			"zz-nil-addr": nil,                     // #3494: nil address value
		},
		AddressSets: map[string]*AddressSet{
			"s1":         {Name: "s1", Addresses: []string{"not-in-book"}}, // unknown member -> warning
			"zz-nil-set": nil,                                              // #3494: nil address-set value
		},
	}
	cfg.RoutingOptions.StaticRoutes = []*StaticRoute{
		{Destination: "not-a-cidr"}, // invalid CIDR -> warning
		nil,                         // #3494: nil static route
	}

	// #3494 (round 3 — exhaustive whole-file sweep): the warning pass also
	// derefs routing-instances, interface configs + units, redundancy-groups,
	// and flow-monitoring template maps — all nil-tolerant pointer
	// slices/maps. Inject a nil element into each so reverting any added guard
	// panics.
	cfg.RoutingInstances = []*RoutingInstanceConfig{
		{Name: "ri1", Interfaces: []string{"ge-0/0/9.0"}}, // unknown iface -> warning
		nil, // #3494: nil routing-instance
	}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/1": {
			Name: "ge-0/0/1",
			Units: map[int]*InterfaceUnit{
				0: {Number: 0, FilterInputV4: "no-such-filter"}, // undefined filter -> warning
				1: nil,                                          // #3494: nil interface unit
			},
		},
		"zz-nil-ifc": nil, // #3494: nil interface value
	}
	cfg.Chassis.Cluster = &ClusterConfig{
		NoRethVRRP: true, // gate the redundancy-group loop on
		RedundancyGroups: []*RedundancyGroup{
			{ID: 1, StrictVIPOwnership: true}, // strict-vip + no-reth-vrrp -> warning
			nil,                               // #3494: nil redundancy-group
		},
	}
	cfg.Services.FlowMonitoring = &FlowMonitoringConfig{
		Version9: &NetFlowV9Config{
			Templates: map[string]*NetFlowV9Template{
				"t9":          {Name: "t9", ExportExtensions: []string{"app-id"}}, // -> warning
				"zz-nil-tmpl": nil,                                                // #3494: nil v9 template
			},
		},
		VersionIPFIX: &NetFlowIPFIXConfig{
			Templates: map[string]*NetFlowIPFIXTemplate{
				"tx":          {Name: "tx", ExportExtensions: []string{"app-id"}}, // -> warning
				"zz-nil-tmpl": nil,                                                // #3494: nil ipfix template
			},
		},
	}

	// Must not panic. We don't assert on exact warning text — only that the
	// pass completes and still emits the warnings for the non-nil slots.
	warnings := ValidateConfig(cfg)
	if len(warnings) == 0 {
		t.Fatalf("expected warnings for the undefined zone/screen/scheduler/NAT/address/" +
			"routing-instance/interface/redundancy-group/template refs, got none")
	}
}
