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
//
// That scope line has a STATED boundary, because "before the dataplane is
// asked" is not the same as "before the apply can still fail". Three fallible
// steps run AFTER compileZones has mutated the host and BEFORE the new
// snapshot is published, so by the line above they belong to THIS half, and
// none of them is covered here (#6894 r2 F2):
//
//   - `preflightCheckIfindexCaps` (loader.go, #5836). It CANNOT be hoisted:
//     it consumes `result.pendingXDP`, which only compileZones populates. Its
//     input does not exist until the mutation has already happened, so closing
//     it needs the ifindex set derived without the host pass -- a different
//     change, not an extra row in the table below.
//   - `attachUserspaceShimXDP` (loader.go), whose tail returns
//     `attach userspace XDP shim generic to ifindex %d`. This is the REACHABLE
//     one: an ordinary XDP attach failure on a driver that rejects a generic
//     attach leaves VLANs created and addresses reconciled while the apply
//     reports failure -- exactly the #4960 shape, on a path this pre-pass does
//     not defend.
//   - `buildSnapshotWithSchedulerStateAndNATCounters`
//     (userspace/manager_compile.go), whose builders return errors (#2514,
//     #3438, #3772). The #3438 address-book case specifically IS caught
//     earlier, by `compileApplications` (row 2 below), which is why the
//     headline example above holds; the builder family as a whole is not.
//
// So the guarantee this file provides is bounded to the phases in
// validationPhases. A failure in any of the three above still lands
// post-mutation.

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// discardingDataPlane satisfies DataPlane for the validation pre-pass. It
// embeds the interface and overrides only the methods the validated phases
// actually call.
//
// This is a deliberate INVERSION of the LegacyDataPlaneAdapter pattern, not the
// same thing (#6894 r1 F5): that adapter embeds a NON-nil DataPlane
// (legacy_dataplane.go sets adapter.DataPlane = the shim manager) and delegates
// everything it does not override. This one leaves the embedded interface NIL,
// so an un-overridden method panics rather than silently succeeding against a
// real dataplane -- the pre-pass must never write.
//
// The panic is the desired failure mode but is NOT compile-time enforced: the
// override set is complete for today's call graph, and a newly added,
// CONDITIONALLY reached dp.X() inside a validated phase would ship green and
// panic in production (the only recover() on the apply path is scoped to
// host-auth closeout). TestPrePassShimCoversTheCalledSurface_4960 is what
// enforces it -- it drives the pre-pass over a config reaching every covered
// phase, so a new call surfaces as a test panic. Widen its fixture,
// idProbeConfig, when adding a phase.
//
// "Reaching every covered phase" was not enough, and that is worth stating
// because it took two rounds to notice (#6894 r3 F1). A phase can be entered
// and still leave its WRITE SURFACE untouched: at r2 the fixture reached every
// phase but only 28 of the 40 overrides, and nine -- the destination-NAT,
// static-NAT, NPTv6, NAT64, v6-pool/v6-SNAT and SNAT-egress writes -- were
// called by no test in the package. Any one of them could be deleted with the
// whole suite green, while an ordinary `security nat destination` stanza
// nil-panicked the daemon on apply. The fixture now reaches 39; the 40th,
// IsLoaded, is called by CompileConfig itself (compiler.go:182) above the
// pre-pass and is bound by the CompileConfig-driving tests instead. Adding an
// override without a config shape that REACHES it re-opens the same hole.
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
// COVERAGE, stated precisely because the gap is deliberate. The table below is
// the authority on what is covered; do not restate its size in prose -- the
// count is the part that rots, and it has already gone stale once here.
// `TestValidationPhaseTableMatchesDocumentedCoverage_4960` pins the table's
// length AND its name order, so a row added or removed without updating this
// comment reds.
//
// What is EXCLUDED, which is the part worth stating: `compilePortMirroring`
// entirely, and all of `compileFirewallFilters` EXCEPT its cfg-pure prefix
// `validateFilterProtocols` (hoisted in as its own row -- see below). Both
// resolve VLAN sub-interface names through `result.cachedInterfaceByName`, and
// those devices do not exist until Phase 2 creates them. Running them here would
// evaluate a different world than the real pass -- every lookup would miss and
// take the `slog.Warn(...); continue` soft skip -- so the pre-pass would emit
// misleading warnings on every successful commit and would still not faithfully
// predict the real run. A hard failure inside that excluded remainder therefore
// still occurs post-mutation; that residual is named rather than papered over,
// and closing it needs the interface-resolution soft skips addressed first
//
// One more site sits outside BOTH the table and the exclusion prose above:
// `dp.BumpFIBGeneration()` (compiler.go), which returns an error the caller
// deliberately discards under the fire-and-forget contract documented at
// dataplane.go. It is listed here only so a reader auditing coverage does not
// have to rediscover that it is neither covered nor an omission -- it cannot
// produce a returned CompileConfig error, so it is out of scope by construction
// rather than by choice
// (#6893).
//
// The double compile is safe with respect to ID assignment:
// TestPrePassDoesNotPerturbIDAssignment_4960 measures that two passes with a
// fresh CompileResult assign byte-identical ZoneIDs, ScreenIDs, AddrIDs,
// AppIDs, PoolIDs, NATCounterIDs and implicitSets -- including the #5099
// NAT-counter family whose streaming assignment was once compile-order
// dependent on a hash collision.
func validateBeforeMutate(cfg *config.Config) error {
	return validateBeforeMutateWith(discardingDataPlane{}, cfg)
}

// validateBeforeMutateWith is validateBeforeMutate with the discarding shim
// injectable. Production has exactly one caller and it passes
// discardingDataPlane{}; the seam exists so a test can fail exactly ONE
// dataplane method and prove which ROW of the table surfaces it.
//
// That is not a convenience. Five of the twelve rows -- nptv6, screen
// profiles, default policy, flow timeouts, flow config -- have NO
// config-shaped hard error at all: every bad input inside them is a
// `slog.Warn(...); continue`, so their only `return err` is a dataplane
// failure. Without this seam those five could not be bound to their bodies by
// any config fixture, and `func() error { return nil }` in place of the body
// would stay green (#6894 r2 F3). `validationPhases` was already
// dp-parameterised for the same reason; this completes it.
//
// Any dp passed here MUST embed discardingDataPlane so it keeps the
// xpfValidationPass marker (isValidationPass) and the never-write override
// set. That is enforced rather than asked for (#6894 r3 F4): a dp without the
// marker is rejected below, because a pre-pass running against a REAL
// dataplane would program the live tables from a discarded compile.
func validateBeforeMutateWith(dp DataPlane, cfg *config.Config) error {
	return validateBeforeMutateWithResult(dp, cfg, newValidationResult())
}

// validateBeforeMutateWithResult is validateBeforeMutateWith with the
// CompileResult injectable as well. Production never calls it directly; the
// extra seam exists because one covered write surface is not reachable from
// cfg alone. compileNAT's interface-SNAT branch resolves the egress zone's
// member through result.cachedInterfaceByName, so SetSNATEgressIP is called
// only when that name exists on the host running the test. Seeding a synthetic
// result.ifCache entry reaches it without naming a live link in a fixture --
// which is what TestPrePassShimCoversTheCalledSurface_4960 does, and is why
// that test can cover 39 of the 40 overrides (#6894 r3 F1).
func validateBeforeMutateWithResult(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	if !isValidationPass(dp) {
		return fmt.Errorf("validate pre-pass: dataplane %T does not carry the "+
			"discardingDataPlane marker — the pre-pass would program the live "+
			"tables from a compile whose result is thrown away (#4960)", dp)
	}
	if cfg == nil {
		return nil
	}

	// Phases 1 / 1.5 are pure and produce the IDs the later phases read.
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)

	for _, phase := range validationPhases(dp, cfg, result) {
		if err := phase.run(); err != nil {
			return fmt.Errorf("validate %s: %w", phase.name, err)
		}
	}
	return nil
}

// validationPhase is one entry in the pre-pass table. The table is a named
// function rather than a literal inside validateBeforeMutate so a test can
// assert over its CONTENTS: the call site being bound proves the pre-pass
// RUNS, not that it still covers what the doc comment claims it covers. At
// round 1, ten of the eleven rows then present could be deleted with the whole
// package suite still green, because a single behavioural fixture pins exactly
// one row (#6894 r1 F1).
//
// So the two kinds of binding are DIFFERENT and neither substitutes for the
// other, and BOTH are now present -- stated precisely, because the earlier
// wording here ("no row can vanish silently") claimed more than its guard
// delivered (#6894 r2 F3):
//
//   - `TestValidationPhaseTableMatchesDocumentedCoverage_4960` binds INDEX ->
//     NAME: the row count and the name at each position. It asserts on
//     `got[i].name` ONLY, so it protects the LABEL. Replacing the BODY of a
//     row with `func() error { return nil }` -- names and order untouched --
//     left the whole package green.
//   - `TestEachValidationPhaseRowRunsItsOwnCompiler_4960` binds NAME -> BODY:
//     every row is driven against an input its own compiler rejects, and the
//     error must arrive prefixed `validate <that row's name>: `. A gutted or
//     swapped body reds there.
//
// Together those pin the table: a row cannot be deleted (count/name), cannot
// be renamed (name), cannot be reordered relative to its siblings (index ->
// name), and cannot stop validating (name -> body). The two behavioural
// fixtures (`applications` via an unresolvable application name, `nat` via an
// unresolvable pool) additionally bind that the pre-pass rejects BEFORE
// compileZones, which is the property of the whole change rather than of any
// one row.
type validationPhase struct {
	name string
	run  func() error
}

// validationPhases lists the phases the pre-pass validates, in the same order
// CompileConfig runs them, so a config that fails several reports the same
// phase it would have reported post-mutation.
//
// The name set is asserted by TestValidationPhaseTableMatchesDocumentedCoverage_4960.
// Adding or removing a row without updating that test -- and the coverage
// paragraph above -- is a test failure by construction.
func validationPhases(dp DataPlane, cfg *config.Config, result *CompileResult) []validationPhase {
	return []validationPhase{
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
		// #6894 r1 F2: the ONE config-shape hard error still reachable after the
		// mutation point. validateFilterProtocols is the first FALLIBLE
		// statement of Phase 10 -- one local map init precedes it
		// (compiler_filter.go:19), so it is not literally the first statement --
		// and is purely a function of cfg: no result, no dp, no logging. So
		// validating it here cannot read anything a later phase set up, and the
		// existing in-place call is left untouched. Reachable via the TOLERANT
		// load paths (Store.Load boot, Store.SyncApply HA peer-sync), which
		// downgrade the strict rejection to a warning and then reach
		// CompileConfig.
		//
		// PRECEDENCE, deliberate: hoisting this changes which error an operator
		// SEES when a config carries both a Phase-2 fault and a bad filter
		// protocol. The whole pre-pass runs before compileZones, so a config
		// with an unknown screen-profile ref AND `from protocol bogus-proto`
		// now reports the filter error, where it previously reported
		// `compile zones: screen profile ... not found`. Both are hard errors
		// and both abort the same apply, so nothing reaches the dataplane
		// either way -- only the message changes. Do not "fix" this by moving
		// the row later; the ordering is what keeps the mutation point clean.
		{"firewall filter protocols", func() error { return validateFilterProtocols(cfg) }},
		{"flow config", func() error { return compileFlowConfig(dp, cfg, result) }},
	}
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

// isValidationPass reports whether dp is the pre-pass's discarding shim.
//
// #6894 r1 F3: the covered phases log unconditionally, so running them twice
// repeats their INFO output, and one line printed a value that was FALSE for
// the run the operator cares about:
// compileFlowConfig logs lo0_filter_v4 from a pass where compileFirewallFilters
// has not run, so the sentinel 65535 is emitted immediately before the real
// pass logs the armed id. An operator asking "did my lo0 filter arm?" read NO
// then YES for one apply. CLAUDE.md restricts slog.Info to state transitions and
// one-time events; a discarded validation pass is neither.
//
// SCOPE — this gate is PARTIAL, and reading it as "the pre-pass no longer
// double-logs" is wrong. It suppresses the sites it is wired into; a
// substantial inventory of INFO/WARN sites inside the covered phases still
// logs unconditionally and therefore still emits twice. Measured on a
// composite config: 25 INFO/WARN records, of which eleven distinct
// covered-phase records appeared twice. The known-ungated sites are the
// application compiler (compiler.go), the NAT/DNAT/static-NAT/NPTv6/NAT64
// families (compiler_nat.go), and the flow-timeouts record (compiler.go).
// Tracked as #6903 — do NOT infer from this comment that a duplicate you are
// looking at is impossible.
//
// The marker rides on the DATAPLANE rather than on CompileResult because two of
// the validated phases (compileDefaultPolicy, compileFlowTimeouts) do not take a
// result, so a result field could not gate them without a signature change.
func isValidationPass(dp DataPlane) bool {
	v, ok := dp.(interface{ xpfValidationPass() bool })
	return ok && v.xpfValidationPass()
}

func (discardingDataPlane) xpfValidationPass() bool { return true }
