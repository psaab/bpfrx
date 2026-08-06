package dataplane

// #4960: validate-before-mutate pre-pass.
//
// CompileConfig runs at APPLY time, after the commit has already succeeded --
// `pkg/configstore` has zero imports of `pkg/dataplane`, so `commit check`
// validates only the pure `pkg/config.CompileConfig` and never reaches this
// one (the two share a name, which is much of why this reads as safer than it
// is). Phase 2 `compileZones` then performs the FIRST and ONLY destructive host
// netlink mutation in the whole function -- `ensureVLANSubInterface` creates and
// links up VLAN devices, `reconcileInterfaceAddresses` deletes and adds
// addresses -- and every later phase is a bare `return nil, err` with no undo
// path. An input that passes config-compile and trips a later phase therefore
// leaves VLANs created and addresses reconciled on the live host, the control
// plane reporting failure, and the dataplane on the old snapshot. The codebase
// documents such an input class itself at `userspace/flow.go`: a malformed
// application-set reference or an app_id-space overflow (#3438 H4) makes
// compileApplications -- Phase 4 -- "hard-error and abort the apply".
//
// This pre-pass runs the fallible HOST-PURE phases against a discarding
// dataplane BEFORE compileZones touches the host, so those failures are
// returned with nothing mutated.
//
// It is deliberately ADDITIVE rather than a reordering. Moving the real phases
// ahead of compileZones would be a silent fail-open: compileFirewallFilters and
// compilePortMirroring resolve VLAN SUB-INTERFACE names that exist only because
// Phase 2 created them, and a miss there is `slog.Warn(...); continue` -- so a
// reorder would leave firewall filters unassigned on every apply, trading a
// loud post-mutation abort for a quiet security fail-open. Every existing call
// keeps its current position and preconditions; the only new behaviour is an
// early abort.
//
// Scope: this is NOT the apply-transaction redesign. Making the Go and Rust
// planes re-converge on a dataplane NACK is a separate half of #4960, tracked
// on `research/4960-apply-txn` (twice PLAN-NEEDS-MAJOR). That work is about
// what happens AFTER the dataplane is asked; this is about not wrecking the
// host BEFORE it is asked. The host-netlink purity this relies on is
// independently derived in that plan's section 4.4.

import (
	"fmt"
	"net"
	"sort"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// discardingDataPlane satisfies DataPlane for the validation pre-pass. It
// embeds the interface (the LegacyDataPlaneAdapter idiom) so it satisfies all
// 130 methods while overriding only the ones the validated phases actually
// call. An un-overridden method nil-panics rather than silently succeeding,
// which is the behaviour we want: if a phase starts calling something new, the
// pre-pass must be revisited rather than quietly diverging from the real run.
type discardingDataPlane struct{ DataPlane }

func (discardingDataPlane) IsLoaded() bool                                                { return true }
func (discardingDataPlane) SetZonePairPolicy(fromZone, toZone uint16, ps PolicySet) error { return nil }
func (discardingDataPlane) SetPolicyRule(policySetID uint32, ruleIndex uint32, rule PolicyRule) error {
	return nil
}
func (discardingDataPlane) SetDefaultPolicy(action uint8) error                     { return nil }
func (discardingDataPlane) SetAddressBookEntry(cidr string, addressID uint32) error { return nil }
func (discardingDataPlane) SetAddressMembership(resolvedID, setID uint32) error     { return nil }
func (discardingDataPlane) ClearAddressBookV4() error                               { return nil }
func (discardingDataPlane) ClearAddressBookV6() error                               { return nil }
func (discardingDataPlane) ClearAddressMembership() error                           { return nil }
func (discardingDataPlane) SetApplication(protocol uint8, dstPort uint16, appID uint32, timeout uint32, algType uint8, srcPortLow, srcPortHigh uint16) error {
	return nil
}
func (discardingDataPlane) SetAppRange(index uint32, entry AppRangeEntry) error { return nil }
func (discardingDataPlane) SetDNATEntry(key DNATKey, val DNATValue) error       { return nil }
func (discardingDataPlane) SetDNATEntryV6(key DNATKeyV6, val DNATValueV6) error { return nil }
func (discardingDataPlane) SetSNATRule(fromZone, toZone, ruleIdx uint16, val SNATValue) error {
	return nil
}
func (discardingDataPlane) SetSNATRuleV6(fromZone, toZone, ruleIdx uint16, val SNATValueV6) error {
	return nil
}
func (discardingDataPlane) SetNATPoolConfig(poolID uint32, cfg NATPoolConfig) error      { return nil }
func (discardingDataPlane) SetNATPoolIPV4(poolID, index uint32, ip uint32) error         { return nil }
func (discardingDataPlane) SetNATPoolIPV6(poolID, index uint32, ip [16]byte) error       { return nil }
func (discardingDataPlane) SetSNATEgressIP(key SNATEgressKey, val SNATEgressValue) error { return nil }
func (discardingDataPlane) ClearSNATEgressIPs() error                                    { return nil }
func (discardingDataPlane) SetStaticNATEntryV4(ip uint32, direction uint8, translated uint32) error {
	return nil
}
func (discardingDataPlane) SetStaticNATEntryV6(ip [16]byte, direction uint8, translated [16]byte) error {
	return nil
}
func (discardingDataPlane) SetNPTv6Rule(key NPTv6Key, val NPTv6Value) error          { return nil }
func (discardingDataPlane) DeleteStaleNPTv6(written map[NPTv6Key]bool)               {}
func (discardingDataPlane) SetNAT64Config(index uint32, cfg NAT64Config) error       { return nil }
func (discardingDataPlane) SetNAT64Count(count uint32) error                         { return nil }
func (discardingDataPlane) SetScreenConfig(profileID uint32, cfg ScreenConfig) error { return nil }
func (discardingDataPlane) SetFlowTimeout(idx, seconds uint32) error                 { return nil }
func (discardingDataPlane) SetFlowConfig(cfg FlowConfigValue) error                  { return nil }
func (discardingDataPlane) DeleteStaleZonePairPolicies(written map[ZonePairKey]bool) {}
func (discardingDataPlane) DeleteStaleApplications(written map[AppKey]bool)          {}
func (discardingDataPlane) DeleteStaleSNATRules(written map[SNATKey]bool)            {}
func (discardingDataPlane) DeleteStaleSNATRulesV6(written map[SNATKey]bool)          {}
func (discardingDataPlane) DeleteStaleDNATStatic(written map[DNATKey]bool)           {}
func (discardingDataPlane) DeleteStaleDNATStaticV6(written map[DNATKeyV6]bool)       {}
func (discardingDataPlane) DeleteStaleStaticNAT(writtenV4 map[StaticNATKeyV4]bool, writtenV6 map[StaticNATKeyV6]bool) {
}
func (discardingDataPlane) DeleteStaleNAT64(count uint32, writtenPrefixes map[NAT64PrefixKey]bool) {}
func (discardingDataPlane) ZeroStaleScreenConfigs(maxID uint32)                                    {}
func (discardingDataPlane) ZeroStaleNATPoolConfigs(startID uint32)                                 {}
func (discardingDataPlane) GetPersistentNAT() *PersistentNATTable {
	var z *PersistentNATTable
	return z
}

// validateBeforeMutate runs every fallible HOST-PURE compile phase against a
// discarding dataplane, so a config that trips one of them is rejected before
// Phase 2 mutates the host. It writes nothing: the CompileResult it builds is
// local and discarded, and every dataplane call lands on discardingDataPlane.
//
// COVERAGE, stated precisely because the gap is deliberate. Eleven of the
// thirteen fallible post-zones phases are validated here. The two excluded are
// `compileFirewallFilters` and `compilePortMirroring`: both resolve VLAN
// sub-interface names through `result.cachedInterfaceByName`, and those devices
// do not exist until Phase 2 creates them. Running them here would evaluate a
// different world than the real pass -- every lookup would miss and take the
// `slog.Warn(...); continue` soft skip -- so the pre-pass would emit misleading
// warnings on every successful commit and would still not faithfully predict
// the real run. A hard failure inside those two therefore still occurs
// post-mutation; that residual is named rather than papered over, and closing
// it needs the interface-resolution soft skips addressed first (#6893).
//
// The double compile is safe with respect to ID assignment:
// TestPrePassDoesNotPerturbIDAssignment_4960 measures that two passes with a
// fresh CompileResult assign byte-identical ZoneIDs, ScreenIDs, AddrIDs,
// AppIDs, PoolIDs, NATCounterIDs and implicitSets -- including the #5099
// NAT-counter family whose streaming assignment was once compile-order
// dependent on a hash collision.
func validateBeforeMutate(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}
	dp := discardingDataPlane{}
	result := newValidationResult()

	// Phases 1 / 1.5 are pure and produce the IDs the later phases read.
	assignZoneIDs(result, cfg)
	screenID := uint16(1)
	screenNames := make([]string, 0, len(cfg.Security.Screen))
	for name := range cfg.Security.Screen {
		screenNames = append(screenNames, name)
	}
	sort.Strings(screenNames)
	for _, name := range screenNames {
		result.ScreenIDs[name] = screenID
		screenID++
	}

	// Same order as CompileConfig, so a config that fails several phases
	// reports the same phase it would have reported post-mutation.
	for _, phase := range []struct {
		name string
		run  func() error
	}{
		{"address book", func() error { return compileAddressBook(dp, cfg, result) }},
		{"applications", func() error { return compileApplications(dp, cfg, result) }},
		{"policies", func() error { return compilePolicies(dp, cfg, result) }},
		{"nat", func() error { return compileNAT(dp, cfg, result) }},
		{"static nat", func() error { return compileStaticNAT(dp, cfg, result) }},
		{"nat64", func() error { return compileNAT64(dp, cfg, result) }},
		{"nptv6", func() error { return compileNPTv6(dp, cfg) }},
		{"screen profiles", func() error { return compileScreenProfiles(dp, cfg, result) }},
		{"default policy", func() error { return compileDefaultPolicy(dp, cfg) }},
		{"flow timeouts", func() error { return compileFlowTimeouts(dp, cfg) }},
		{"flow config", func() error { return compileFlowConfig(dp, cfg, result) }},
	} {
		if err := phase.run(); err != nil {
			return fmt.Errorf("validate %s: %w", phase.name, err)
		}
	}
	return nil
}

// newValidationResult builds a zero-valued CompileResult with every map
// allocated. CompileConfig and validateBeforeMutate share it deliberately: if
// the two initialised the struct separately they could drift, and the pre-pass
// would then validate against a differently-shaped result than the real pass
// programs from -- the exact class of divergence this whole change exists to
// avoid.
func newValidationResult() *CompileResult {
	return &CompileResult{
		ZoneIDs:             make(map[string]uint16),
		ScreenIDs:           make(map[string]uint16),
		AddrIDs:             make(map[string]uint32),
		AppIDs:              make(map[string]uint32),
		PoolIDs:             make(map[string]uint8),
		implicitSets:        make(map[string]uint32),
		NATCounterIDs:       make(map[string]uint32),
		FilterSpans:         make(map[string]FilterCounterSpan),
		Lo0FilterV4:         0xFFFFFFFF, // sentinel: no lo0 filter
		Lo0FilterV6:         0xFFFFFFFF,
		ifCache:             make(map[string]*net.Interface),
		linkCache:           make(map[string]netlink.Link),
		linkIdxMap:          make(map[int]netlink.Link),
		rxVlanOffCache:      make(map[string]bool),
		ethtoolApplied:      make(map[string]bool),
		genericXDPIfindexes: make(map[int]bool),
	}
}
