package dataplane

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/psaab/xpf/pkg/config"
)

// #2114 A3 armed-gate runtime legs (the plan's FIVE-leg oracle set plus the
// named Detach/ownership/continuation legs). The oracle honestly splits:
// the ALWAYS-ON legs prove classification + blocking for every manifest
// entry with sentinel/absent registries (no BPF privileges needed); the
// PRIVILEGED semantic-mutation legs run where BPF map creation works and
// skip elsewhere (the repo's skipIfBPFUnavailable idiom).

// armedGateSentinel seeds the registry into the retained classification
// (nonempty m.maps, loaded=false) without providing any map a method
// actually looks up: every method's own lookup returns present=false, so
// master's armed/retained + ABSENT outcome is exercised without touching
// the kernel.
func armedGateSentinel(m *Manager) {
	m.maps["sentinel_unused"] = nil
}

// armedGateInvoke drives every registry-consuming exported method with a
// benign zero-ish argument set and returns its error (nil for void /
// neutral-value methods). Methods that would touch the kernel or netlink
// past an armed+absent lookup (the attach family) are NOT here — they are
// covered by the carve-out assertions below. The map keys are the method
// names from managerMethodClasses.
func armedGateInvoke() map[string]func(m *Manager) error {
	return map[string]func(m *Manager) error{
		// class 1
		"SetZone":            func(m *Manager) error { return m.SetZone(1, 0, 1, 0, 0, 0, 0) },
		"SetVlanIfaceInfo":   func(m *Manager) error { return m.SetVlanIfaceInfo(2, 1, 10) },
		"ClearIfaceZoneMap":  func(m *Manager) error { return m.ClearIfaceZoneMap() },
		"ClearVlanIfaceMap":  func(m *Manager) error { return m.ClearVlanIfaceMap() },
		"AddTxPort":          func(m *Manager) error { return m.AddTxPort(1) },
		"SwapToUserspaceXDPShimEntryProgram": func(m *Manager) error {
			return m.SwapToUserspaceXDPShimEntryProgram()
		},
		"ReadGlobalCounter":     func(m *Manager) error { _, err := m.ReadGlobalCounter(0); return err },
		"ReadInterfaceCounters": func(m *Manager) error { _, err := m.ReadInterfaceCounters(1); return err },
		"ClearInterfaceCounters": func(m *Manager) error { return m.ClearInterfaceCounters() },
		"UpdateFabricFwd":       func(m *Manager) error { return m.UpdateFabricFwd(FabricFwdInfo{}) },
		"UpdateFabricFwd1":      func(m *Manager) error { return m.UpdateFabricFwd1(FabricFwdInfo{}) },
		"UpdateRGActive":        func(m *Manager) error { return m.UpdateRGActive(0, true) },
		"UpdateHAWatchdog":      func(m *Manager) error { return m.UpdateHAWatchdog(0, 1) },
		"BumpFIBGeneration":     func(m *Manager) error { _, err := m.BumpFIBGeneration(); return err },
		"SetIfaceFilter":        func(m *Manager) error { return m.SetIfaceFilter(IfaceFilterKey{}, 1) },
		"ClearIfaceFilterMap":   func(m *Manager) error { return m.ClearIfaceFilterMap() },
		"SetFilterConfig":       func(m *Manager) error { return m.SetFilterConfig(1, FilterConfig{}) },
		"ReadFilterConfig":      func(m *Manager) error { _, err := m.ReadFilterConfig(1); return err },
		"SetFilterRule":         func(m *Manager) error { return m.SetFilterRule(0, FilterRule{}) },
		"SetPolicerConfig":      func(m *Manager) error { return m.SetPolicerConfig(1, PolicerConfig{}) },
		"ClearPolicerConfigs":   func(m *Manager) error { return m.ClearPolicerConfigs() },
		"ClearFilterConfigs":    func(m *Manager) error { return m.ClearFilterConfigs() },
		"ReadFilterCounters":    func(m *Manager) error { _, err := m.ReadFilterCounters(0); return err },
		"ClearFilterCounters":   func(m *Manager) error { return m.ClearFilterCounters() },
		"SetFlowTimeout":        func(m *Manager) error { return m.SetFlowTimeout(0, 30) },
		"SetFlowConfig":         func(m *Manager) error { return m.SetFlowConfig(FlowConfigValue{}) },
		"SetMirrorConfig":       func(m *Manager) error { return m.SetMirrorConfig(1, 2, 100) },
		"ClearMirrorConfigs":    func(m *Manager) error { return m.ClearMirrorConfigs() },
		"SetDNATEntry":          func(m *Manager) error { return m.SetDNATEntry(DNATKey{}, DNATValue{}) },
		"DeleteDNATEntry":       func(m *Manager) error { return m.DeleteDNATEntry(DNATKey{}) },
		"ClearDNATStatic":       func(m *Manager) error { return m.ClearDNATStatic() },
		"SetSNATRule":           func(m *Manager) error { return m.SetSNATRule(1, 1, 0, SNATValue{}) },
		"ClearSNATRules":        func(m *Manager) error { return m.ClearSNATRules() },
		"SetDNATEntryV6":        func(m *Manager) error { return m.SetDNATEntryV6(DNATKeyV6{}, DNATValueV6{}) },
		"DeleteDNATEntryV6":     func(m *Manager) error { return m.DeleteDNATEntryV6(DNATKeyV6{}) },
		"ClearDNATStaticV6":     func(m *Manager) error { return m.ClearDNATStaticV6() },
		"SetSNATRuleV6":         func(m *Manager) error { return m.SetSNATRuleV6(1, 1, 0, SNATValueV6{}) },
		"ClearSNATRulesV6":      func(m *Manager) error { return m.ClearSNATRulesV6() },
		"SetNATPoolConfig":      func(m *Manager) error { return m.SetNATPoolConfig(0, NATPoolConfig{}) },
		"SetNATPoolIPV4":        func(m *Manager) error { return m.SetNATPoolIPV4(0, 0, 0) },
		"SetNATPoolIPV6":        func(m *Manager) error { return m.SetNATPoolIPV6(0, 0, [16]byte{}) },
		"ClearNATPoolConfigs":   func(m *Manager) error { return m.ClearNATPoolConfigs() },
		"ClearNATPoolIPs":       func(m *Manager) error { return m.ClearNATPoolIPs() },
		"SetSNATEgressIP":       func(m *Manager) error { return m.SetSNATEgressIP(SNATEgressKey{}, SNATEgressValue{}) },
		"ClearSNATEgressIPs":    func(m *Manager) error { return m.ClearSNATEgressIPs() },
		"SetStaticNATEntryV4":   func(m *Manager) error { return m.SetStaticNATEntryV4(0, 0, 0) },
		"SetStaticNATEntryV6":   func(m *Manager) error { return m.SetStaticNATEntryV6([16]byte{}, 0, [16]byte{}) },
		"SetNAT64Config":        func(m *Manager) error { return m.SetNAT64Config(0, NAT64Config{}) },
		"SetNAT64Count":         func(m *Manager) error { return m.SetNAT64Count(0) },
		"ClearNAT64Configs":     func(m *Manager) error { return m.ClearNAT64Configs() },
		"SetNPTv6Rule":          func(m *Manager) error { return m.SetNPTv6Rule(NPTv6Key{}, NPTv6Value{}) },
		"ReadNATPortCounter":    func(m *Manager) error { _, err := m.ReadNATPortCounter(0); return err },
		"SetZoneConfig":         func(m *Manager) error { return m.SetZoneConfig(1, ZoneConfig{}) },
		"SetZonePairPolicy":     func(m *Manager) error { return m.SetZonePairPolicy(1, 1, PolicySet{}) },
		"SetPolicyRule":         func(m *Manager) error { return m.SetPolicyRule(0, 0, PolicyRule{}) },
		"SetAddressBookEntry":   func(m *Manager) error { return m.SetAddressBookEntry("10.0.0.0/8", 1) },
		"SetAddressMembership":  func(m *Manager) error { return m.SetAddressMembership(1, 1) },
		"ClearAddressBookV4":    func(m *Manager) error { return m.ClearAddressBookV4() },
		"ClearAddressBookV6":    func(m *Manager) error { return m.ClearAddressBookV6() },
		"ClearAddressMembership": func(m *Manager) error { return m.ClearAddressMembership() },
		"SetApplication":        func(m *Manager) error { return m.SetApplication(6, 80, 1, 0, 0, 0, 0) },
		"SetAppRange":           func(m *Manager) error { return m.SetAppRange(0, AppRangeEntry{}) },
		"ClearAppRanges":        func(m *Manager) error { return m.ClearAppRanges() },
		"ClearZonePairPolicies": func(m *Manager) error { return m.ClearZonePairPolicies() },
		"ClearApplications":     func(m *Manager) error { return m.ClearApplications() },
		"SetDefaultPolicy":      func(m *Manager) error { return m.SetDefaultPolicy(1) },
		"ReadPolicyCounters":    func(m *Manager) error { _, err := m.ReadPolicyCounters(0); return err },
		"ClearPolicyCounters":   func(m *Manager) error { return m.ClearPolicyCounters() },
		"SetScreenConfig":       func(m *Manager) error { return m.SetScreenConfig(0, ScreenConfig{}) },
		"ClearScreenConfigs":    func(m *Manager) error { return m.ClearScreenConfigs() },
		"UpdateSessionCountSrc": func(m *Manager) error { return m.UpdateSessionCountSrc(SessionCountKey{}, 1) },
		"UpdateSessionCountDst": func(m *Manager) error { return m.UpdateSessionCountDst(SessionCountKey{}, 1) },
		"IterateSessions":       func(m *Manager) error { return m.IterateSessions(func(SessionKey, SessionValue) bool { return false }) },
		"DeleteSession":         func(m *Manager) error { return m.DeleteSession(SessionKey{}) },
		"SetSessionV4":          func(m *Manager) error { return m.SetSessionV4(SessionKey{}, SessionValue{}) },
		"GetSessionV4":          func(m *Manager) error { _, err := m.GetSessionV4(SessionKey{}); return err },
		"GetSessionV6":          func(m *Manager) error { _, err := m.GetSessionV6(SessionKeyV6{}); return err },
		"IterateSessionsV6":     func(m *Manager) error { return m.IterateSessionsV6(func(SessionKeyV6, SessionValueV6) bool { return false }) },
		"IterateSessionsFrom": func(m *Manager) error {
			return m.IterateSessionsFrom(nil, func(SessionKey, SessionValue) bool { return false })
		},
		"IterateSessionsV6From": func(m *Manager) error {
			return m.IterateSessionsV6From(nil, func(SessionKeyV6, SessionValueV6) bool { return false })
		},
		"BatchIterateSessions": func(m *Manager) error {
			return m.BatchIterateSessions(func(SessionKey, SessionValue) bool { return false })
		},
		"BatchIterateSessionsV6": func(m *Manager) error {
			return m.BatchIterateSessionsV6(func(SessionKeyV6, SessionValueV6) bool { return false })
		},
		"BatchDeleteSessions":    func(m *Manager) error { _, err := m.BatchDeleteSessions(nil); return err },
		"BatchDeleteSessionsV6":  func(m *Manager) error { _, err := m.BatchDeleteSessionsV6(nil); return err },
		"DeleteSessionV6":        func(m *Manager) error { return m.DeleteSessionV6(SessionKeyV6{}) },
		"SetSessionV6":           func(m *Manager) error { return m.SetSessionV6(SessionKeyV6{}, SessionValueV6{}) },
		"ClearAllSessions":       func(m *Manager) error { _, _, err := m.ClearAllSessions(); return err },
		"ClearAllSessionsChunked": func(m *Manager) error {
			_, _, err := m.ClearAllSessionsChunked(nil, nil)
			return err
		},

		// class 2 (neutral; error-returning members return nil on fresh)
		"SessionCount":          func(m *Manager) error { m.SessionCount(); return nil },
		"GetMapStats":           func(m *Manager) error { m.GetMapStats(); return nil },
		"ClearSessionCounts":    func(m *Manager) error { return m.ClearSessionCounts() },
		"ClearStaticNATEntries": func(m *Manager) error { return m.ClearStaticNATEntries() },
		"UpdatePolicyScheduleState": func(m *Manager) error {
			return m.UpdatePolicyScheduleState(nil, map[string]bool{})
		},
		"SeedNATPortCounters":   func(m *Manager) error { m.SeedNATPortCounters(); return nil },
		"SeedSessionIDCounter":  func(m *Manager) error { m.SeedSessionIDCounter(0); return nil },
		"DeleteStaleIfaceZone":  func(m *Manager) error { m.DeleteStaleIfaceZone(nil); return nil },
		"DeleteStaleVlanIface":  func(m *Manager) error { m.DeleteStaleVlanIface(nil); return nil },
		"DeleteStaleZonePairPolicies": func(m *Manager) error {
			m.DeleteStaleZonePairPolicies(nil)
			return nil
		},
		"DeleteStaleApplications": func(m *Manager) error { m.DeleteStaleApplications(nil); return nil },
		"DeleteStaleSNATRules":    func(m *Manager) error { m.DeleteStaleSNATRules(nil); return nil },
		"DeleteStaleSNATRulesV6":  func(m *Manager) error { m.DeleteStaleSNATRulesV6(nil); return nil },
		"DeleteStaleDNATStatic":   func(m *Manager) error { m.DeleteStaleDNATStatic(nil); return nil },
		"DeleteStaleDNATStaticV6": func(m *Manager) error { m.DeleteStaleDNATStaticV6(nil); return nil },
		"DeleteStaleStaticNAT":    func(m *Manager) error { m.DeleteStaleStaticNAT(nil, nil); return nil },
		"DeleteStaleNPTv6":        func(m *Manager) error { m.DeleteStaleNPTv6(nil); return nil },
		"DeleteStaleNAT64":        func(m *Manager) error { m.DeleteStaleNAT64(0, nil); return nil },
		"ZeroStaleScreenConfigs":  func(m *Manager) error { m.ZeroStaleScreenConfigs(0); return nil },
		"ZeroStaleNATPoolConfigs": func(m *Manager) error { m.ZeroStaleNATPoolConfigs(0); return nil },
		"DeleteStaleIfaceFilter":  func(m *Manager) error { m.DeleteStaleIfaceFilter(nil); return nil },
		"ZeroStaleFilterConfigs":  func(m *Manager) error { m.ZeroStaleFilterConfigs(0); return nil },

		// class 3 (hybrids: pinned side-effect + legacy outcome in every state)
		"ClearNATRuleCounters": func(m *Manager) error { return m.ClearNATRuleCounters() },
		"ClearGlobalCounters":  func(m *Manager) error { return m.ClearGlobalCounters() },
		"ClearZoneCounters":    func(m *Manager) error { return m.ClearZoneCounters() },
		"ClearAllCounters":     func(m *Manager) error { return m.ClearAllCounters() },
	}
}

// armedGateClass1Hosts returns the helper-consuming class-1 method names
// (everything in armedGateInvoke that the manifest marks class1).
func armedGateClass1Hosts() map[string]bool {
	out := map[string]bool{}
	for name, class := range managerMethodClasses {
		if class == "class1" {
			out[name] = true
		}
	}
	return out
}

// TestManager_ArmedGate_FreshOutcomes is the quiescent FRESH leg (plan leg
// 1): on a never-armed manager every class-1 method returns the typed
// ErrDataplaneNotArmed (replacing master's per-map not-found error), the
// carve-out set keeps master's own pre-registry rejection, class-2 keeps
// master's neutral outcome byte-for-byte, class-3 keeps the pinned legacy
// behavior (ClearAllCounters surfaces the tolerated "interface_counters map
// not found" through the raw composition), and the class-4 getters return
// nil (NewEventSource: the typed error — its signature carries one).
func TestManager_ArmedGate_FreshOutcomes(t *testing.T) {
	m := New()
	invoke := armedGateInvoke()
	class1 := armedGateClass1Hosts()

	for name, call := range invoke {
		err := call(m)
		switch {
		case class1[name]:
			if !errors.Is(err, ErrDataplaneNotArmed) {
				t.Errorf("fresh %s = %v, want errors.Is ErrDataplaneNotArmed", name, err)
			}
		default:
			// class 2: neutral (nil). class 3 handled below.
			if name == "ClearAllCounters" {
				// Pinned legacy text through the raw composition.
				if err == nil || !strings.Contains(err.Error(), "interface_counters map not found") {
					t.Errorf("fresh ClearAllCounters = %v, want the pinned legacy interface_counters text", err)
				}
				if errors.Is(err, ErrDataplaneNotArmed) {
					t.Errorf("fresh ClearAllCounters must NOT surface the typed gate error (nested-call rule)")
				}
				continue
			}
			if managerMethodClasses[name] == "class3" || managerMethodClasses[name] == "class2" {
				if err != nil {
					t.Errorf("fresh %s (%s) = %v, want nil (neutral/pinned)", name, managerMethodClasses[name], err)
				}
			}
		}
	}

	// Carve-out set: master's own pre-registry rejections on the fresh
	// state; the typed error never fires for them.
	if err := m.AttachXDP(1, false); err == nil || err.Error() != "eBPF programs not loaded" {
		t.Errorf("fresh AttachXDP = %v, want master's loaded rejection", err)
	}
	if err := m.AttachTC(1); err == nil || err.Error() != "eBPF programs not loaded" {
		t.Errorf("fresh AttachTC = %v, want master's loaded rejection", err)
	}
	if _, err := m.Compile(nil); err == nil || err.Error() != "nil config" {
		t.Errorf("fresh Compile(nil) = %v, want the nil-config validation error (pure validation precedes the gate)", err)
	}

	// The CompileConfig path's own loaded rejection (the carve-out):
	// fires on the fresh state with master's text.
	if _, err := m.Compile(&config.Config{}); err == nil || err.Error() != "dataplane not loaded" {
		t.Errorf("fresh Compile(empty) = %v, want master's CompileConfig loaded rejection", err)
	}

	// Class 4 getters.
	if got := m.Map("sessions"); got != nil {
		t.Errorf("fresh Map(sessions) = %v, want nil", got)
	}
	if got := m.Program("xdp_userspace_prog"); got != nil {
		t.Errorf("fresh Program = %v, want nil", got)
	}
	if _, err := m.NewEventSource(); !errors.Is(err, ErrDataplaneNotArmed) {
		t.Errorf("fresh NewEventSource = %v, want errors.Is ErrDataplaneNotArmed", err)
	}
}

// TestManager_ArmedGate_RetainedOutcomes is the quiescent RETAINED leg
// (plan leg 2): a seeded-but-unarmed registry (loaded=false, maps present
// — the armed-Close/Teardown-retain shape) makes every class proceed
// EXACTLY as master: class-1 methods return master's per-map not-found
// error (never the typed error), class-2 keep the neutral outcome, class-3
// keep the pinned legacy behavior, the carve-out set still rejects via its
// own loaded check, and the class-4 getters keep master's nil/text
// outcomes.
func TestManager_ArmedGate_RetainedOutcomes(t *testing.T) {
	m := New()
	armedGateSentinel(m)
	m.loaded.Store(false)

	invoke := armedGateInvoke()
	class1 := armedGateClass1Hosts()
	for name, call := range invoke {
		err := call(m)
		switch {
		case class1[name]:
			if errors.Is(err, ErrDataplaneNotArmed) {
				t.Errorf("retained %s = %v, must NOT be the typed gate error (retained proceeds as master)", name, err)
			}
			if err == nil || !strings.Contains(err.Error(), "not found") {
				t.Errorf("retained %s = %v, want master's per-map not-found error", name, err)
			}
		default:
			if name == "ClearAllCounters" {
				if err == nil || !strings.Contains(err.Error(), "interface_counters map not found") {
					t.Errorf("retained ClearAllCounters = %v, want the pinned legacy interface_counters text", err)
				}
				continue
			}
			if managerMethodClasses[name] == "class3" || managerMethodClasses[name] == "class2" {
				if err != nil {
					t.Errorf("retained %s (%s) = %v, want nil (neutral/pinned)", name, managerMethodClasses[name], err)
				}
			}
		}
	}

	// Carve-out set rejects on the retained state too (loaded==false).
	if err := m.AttachXDP(1, false); err == nil || err.Error() != "eBPF programs not loaded" {
		t.Errorf("retained AttachXDP = %v, want master's loaded rejection", err)
	}

	// Class 4: master's missing outcomes.
	if got := m.Map("sessions"); got != nil {
		t.Errorf("retained Map(sessions) = %v, want nil", got)
	}
	if _, err := m.NewEventSource(); err == nil || err.Error() != "events map not loaded" || errors.Is(err, ErrDataplaneNotArmed) {
		t.Errorf("retained NewEventSource = %v, want master's events-map text (not the typed error)", err)
	}
}

// runSyntheticStart drives LoadUserspaceShim with the acquisition seam
// replaced by a synthetic registry (the publisher still runs the
// production code path). Returns a channel receiving the Start result.
// The seam restore is the CALLER's job (defer restoreShimPrePublishLoad)
// and must run only after the Start result is received — an asynchronous
// restore races the next test's seam read (the -race gate caught exactly
// that here).
func runSyntheticStart(t *testing.T, m *Manager, registry map[string]*ebpf.Map) chan error {
	t.Helper()
	shimPrePublishLoad = func(m *Manager) error {
		m.publishShimRegistryLocked(nil, registry, nil)
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- m.LoadUserspaceShim()
	}()
	return done
}

// productionShimPrePublishLoad captures the production loader at package
// init so the restore below can never drift from the loader.go body.
var productionShimPrePublishLoad = shimPrePublishLoad

// restoreShimPrePublishLoad puts the production loader back. Pair with
// runSyntheticStart via defer BEFORE the Start result is consumed.
func restoreShimPrePublishLoad() {
	shimPrePublishLoad = productionShimPrePublishLoad
}

// TestManager_ArmedGate_BlockedStart is the blocked FRESH-Start
// lock-ownership leg (plan leg 3): the whole-batch publication hold
// contains the test hook; helper-consuming readers from every class BLOCK
// until the hold releases, then observe the ARMED state (the in-hold
// Store(true) is the batch's final step).
func TestManager_ArmedGate_BlockedStart(t *testing.T) {
	m := New()
	invoke := armedGateInvoke()

	entered := make(chan struct{})
	release := make(chan struct{})
	shimRegistryPublishHook = func() {
		close(entered)
		<-release
	}
	defer func() { shimRegistryPublishHook = nil }()

	defer restoreShimPrePublishLoad()
	startDone := runSyntheticStart(t, m, map[string]*ebpf.Map{"sentinel_unused": nil})
	<-entered // the publisher holds m.mu, pre-Store(true)

	// Readers from every helper-consuming class block on the hold.
	type pendingCall struct {
		name string
		done chan error
	}
	var pending []pendingCall
	for name, call := range invoke {
		p := pendingCall{name: name, done: make(chan error, 1)}
		go func(c func(m *Manager) error, d chan error) { d <- c(m) }(call, p.done)
		pending = append(pending, p)
	}

	// None may complete during the hold.
	time.Sleep(150 * time.Millisecond)
	for _, p := range pending {
		select {
		case err := <-p.done:
			t.Fatalf("%s completed (%v) during the publication hold — the lookup did not block", p.name, err)
		default:
		}
	}
	if m.IsLoaded() {
		t.Fatal("IsLoaded() = true before the in-hold Store(true) — flag published outside the batch")
	}

	close(release)
	if err := <-startDone; err != nil {
		t.Fatalf("synthetic Start: %v", err)
	}
	if !m.IsLoaded() {
		t.Fatal("IsLoaded() = false after the publication batch")
	}

	// After release every reader observed the ARMED state: class-1 hosts
	// return master's per-map not-found error (never the fresh typed
	// error); class-2/3 keep their neutral/pinned outcomes.
	class1 := armedGateClass1Hosts()
	for _, p := range pending {
		err := <-p.done
		if class1[p.name] && errors.Is(err, ErrDataplaneNotArmed) {
			t.Errorf("post-release %s = %v, must not be the fresh gate error (armed observed)", p.name, err)
		}
	}
}

// TestManager_ArmedGate_RetainedReStartOverlap is the blocked
// RETAINED-re-Start leg (plan leg 4): the retained fixture (registry
// populated, loaded=false — the bootstrap/hitless-restart posture) driven
// through the blocked re-Start; every class's readers block until the hold
// releases and observe the ARMED state after it.
func TestManager_ArmedGate_RetainedReStartOverlap(t *testing.T) {
	m := New()
	armedGateSentinel(m)
	m.loaded.Store(false)

	invoke := armedGateInvoke()
	entered := make(chan struct{})
	release := make(chan struct{})
	shimRegistryPublishHook = func() {
		close(entered)
		<-release
	}
	defer func() { shimRegistryPublishHook = nil }()

	// The re-Start publishes only sentinel names nothing looks up: readers
	// released from the hold observe the ARMED state with their own maps
	// ABSENT (master's not-found outcomes), never a present-but-nil handle
	// — production never publishes nil maps, so no method may proceed
	// against one here.
	defer restoreShimPrePublishLoad()
	startDone := runSyntheticStart(t, m, map[string]*ebpf.Map{"sentinel_restart": nil})
	<-entered

	type pendingCall struct {
		name string
		done chan error
	}
	var pending []pendingCall
	for name, call := range invoke {
		p := pendingCall{name: name, done: make(chan error, 1)}
		go func(c func(m *Manager) error, d chan error) { d <- c(m) }(call, p.done)
		pending = append(pending, p)
	}
	time.Sleep(150 * time.Millisecond)
	for _, p := range pending {
		select {
		case err := <-p.done:
			t.Fatalf("%s completed (%v) during the retained re-Start hold — the lookup did not block", p.name, err)
		default:
		}
	}
	close(release)
	if err := <-startDone; err != nil {
		t.Fatalf("synthetic re-Start: %v", err)
	}
	class1 := armedGateClass1Hosts()
	for _, p := range pending {
		err := <-p.done
		if class1[p.name] && errors.Is(err, ErrDataplaneNotArmed) {
			t.Errorf("post-release %s = %v, must not be the fresh gate error", p.name, err)
		}
	}
}

// TestManager_ArmedGate_CloseWindowIsLoaded is the ISLOADED-WINDOW leg
// (plan leg 5): an armed manager's Close() is held at the test hook
// immediately AFTER the entry Store(false) and BEFORE the link-handle
// closes; a concurrent IsLoaded() read observes false DURING the window,
// where master (flip at the exit) would still report true. The registry
// stays populated (retained) across Close.
func TestManager_ArmedGate_CloseWindowIsLoaded(t *testing.T) {
	m := New()
	armedGateSentinel(m)
	m.loaded.Store(true)

	entered := make(chan struct{})
	release := make(chan struct{})
	closeWindowHook = func() {
		close(entered)
		<-release
	}
	defer func() { closeWindowHook = nil }()

	closeDone := make(chan error, 1)
	go func() { closeDone <- m.Close() }()
	<-entered

	// Inside the window: the externally visible surface already reports
	// unarmed (the intended early-report semantics), and the registry is
	// still populated.
	if m.IsLoaded() {
		t.Fatal("IsLoaded() = true during the Close window — the entry Store(false) did not land first")
	}
	if len(m.maps) == 0 {
		t.Fatal("Close cleared the registry — the hitless-restart retain posture broke")
	}

	close(release)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if m.IsLoaded() {
		t.Fatal("IsLoaded() = true after Close")
	}
	// Post-Close the manager classifies RETAINED: a class-1 method keeps
	// master's not-found outcome rather than the fresh typed error.
	if err := m.UpdateRGActive(0, true); err == nil ||
		!strings.Contains(err.Error(), "rg_active map not found") || errors.Is(err, ErrDataplaneNotArmed) {
		t.Fatalf("post-Close UpdateRGActive = %v, want master's retained not-found", err)
	}
}

// TestManager_ArmedGate_LookupOwnership exercises BOTH typed helpers' lock
// ownership directly (the reverse-schedule guard): while a helper's own
// section holds the test hook, a racing publisher attempt blocks until the
// hold releases — proving the classification + handle selection and the
// publication batch are mutually exclusive under m.mu.
func TestManager_ArmedGate_LookupOwnership(t *testing.T) {
	for _, which := range []string{"map", "program"} {
		t.Run(which, func(t *testing.T) {
			m := New()
			armedGateSentinel(m)

			entered := make(chan struct{})
			release := make(chan struct{})
			registryLookupHook = func() {
				select {
				case <-entered:
				default:
					close(entered)
					<-release
				}
			}
			defer func() { registryLookupHook = nil }()

			lookupDone := make(chan struct{})
			go func() {
				defer close(lookupDone)
				if which == "map" {
					m.lookupMapLocked("sessions")
				} else {
					m.lookupProgramLocked("xdp_userspace_prog")
				}
			}()
			<-entered // the helper holds m.mu

			pubDone := make(chan struct{})
			go func() {
				defer close(pubDone)
				m.publishShimRegistryLocked(nil, map[string]*ebpf.Map{"sessions": nil}, nil)
			}()
			select {
			case <-pubDone:
				t.Fatal("publisher completed while the lookup helper held m.mu")
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			<-lookupDone
			<-pubDone
			if !m.IsLoaded() {
				t.Fatal("publisher did not run after the lookup released m.mu")
			}
		})
	}
}

// TestManager_ArmedGate_SwapXDPEntryProgOwnership pins the entry-program
// swap's field-write lock DIRECTLY: a direct swapXDPEntryProg call with a
// seeded distinct test program (retained fixture: nonempty m.maps AND
// m.programs — a nonempty programs registry alone does NOT classify
// retained) drives the write section while the hook holds it; a concurrent
// XDPEntryProgram() getter blocks until release.
func TestManager_ArmedGate_SwapXDPEntryProgOwnership(t *testing.T) {
	m := New()
	m.maps["sentinel_unused"] = nil       // retained classification reads m.maps emptiness
	m.programs["test_prog"] = nil         // present-but-nil: the swap's lookup passes
	m.xdpEntryProg = "other"              // distinct from the target so the early exits fail
	m.loaded.Store(false)

	entered := make(chan struct{})
	release := make(chan struct{})
	swapXDPEntryProgHook = func() {
		close(entered)
		<-release
	}
	defer func() { swapXDPEntryProgHook = nil }()

	swapDone := make(chan error, 1)
	go func() { swapDone <- m.swapXDPEntryProg("test_prog") }()
	<-entered // the :632 write section holds m.mu

	getterDone := make(chan string, 1)
	go func() { getterDone <- m.XDPEntryProgram() }()
	select {
	case got := <-getterDone:
		t.Fatalf("XDPEntryProgram() = %q during the swap write hold — the getter did not block", got)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-swapDone; err != nil {
		t.Fatalf("swapXDPEntryProg: %v", err)
	}
	if got := <-getterDone; got != "test_prog" {
		t.Fatalf("XDPEntryProgram() after release = %q, want test_prog", got)
	}
}

// TestManager_ArmedGate_XDPSelectorTwoSided drives the LoadUserspaceShim
// selector write (the :154 arm) with getter/predicate driven across it:
// while the selector's m.mu section holds the hook, the public getter
// blocks; after release the getter and the predicate observe the userspace
// shim selection.
func TestManager_ArmedGate_XDPSelectorTwoSided(t *testing.T) {
	m := New()

	entered := make(chan struct{})
	release := make(chan struct{})
	xdpEntryProgSelectorHook = func() {
		select {
		case <-entered:
		default:
			close(entered)
			<-release
		}
	}
	defer func() { xdpEntryProgSelectorHook = nil }()

	defer restoreShimPrePublishLoad()
	shimPrePublishLoad = func(m *Manager) error {
		m.publishShimRegistryLocked(nil, map[string]*ebpf.Map{"sentinel_unused": nil}, nil)
		return nil
	}
	startDone := make(chan error, 1)
	go func() {
		startDone <- m.LoadUserspaceShim()
	}()
	<-entered // the selector write section holds m.mu

	getterDone := make(chan string, 1)
	go func() { getterDone <- m.XDPEntryProgram() }()
	select {
	case got := <-getterDone:
		t.Fatalf("XDPEntryProgram() = %q during the selector write hold — did not block", got)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-startDone; err != nil {
		t.Fatalf("LoadUserspaceShim: %v", err)
	}
	if got := <-getterDone; got != userspaceShimEntryProg {
		t.Fatalf("XDPEntryProgram() after Start = %q, want %q", got, userspaceShimEntryProg)
	}
	if !m.UsingUserspaceXDPShimEntryProgram() {
		t.Fatal("UsingUserspaceXDPShimEntryProgram() = false after Start")
	}
}

// TestManager_ArmedGate_DetachRetainedClaims is the named Detach leg: a
// package-local fake link (overriding Unpin/Close), xdpLinks AND
// xdpFlagClaims seeded, and a usable iface_zone_map seeded; the detach's
// setXDPAttachedFlag(false) delegation target runs the claim cleanup on
// the retained registry (no gate) — claims are deleted and the fake link
// is unpinned+closed, race-free against the concurrent population actor.
// "Cleanup always runs" excludes master's absent-iface_zone_map early-boot
// no-op and any discovery-failure path (those preserve claims for retry).
func TestManager_ArmedGate_DetachRetainedClaims(t *testing.T) {
	zoneMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "iface_zone_map",
		Type:       ebpf.Hash,
		KeySize:    uint32(sizeOf[IfaceZoneKey]()),
		ValueSize:  uint32(sizeOf[IfaceZoneValue]()),
		MaxEntries: 16,
	})
	if err != nil {
		skipIfBPFUnavailable(t, "new iface_zone_map", err)
		return
	}
	defer zoneMap.Close()

	m := New()
	m.maps["iface_zone_map"] = zoneMap
	m.loaded.Store(false) // retained

	fake := &armedGateFakeLink{}
	const ifindex = 42
	m.xdpLinks[ifindex] = fake
	key := IfaceZoneKey{Ifindex: ifindex, VlanID: 0}
	m.xdpFlagClaims[key] = map[int]bool{ifindex: true}

	if err := m.DetachXDP(ifindex); err != nil {
		t.Fatalf("DetachXDP: %v", err)
	}
	if _, still := m.xdpFlagClaims[key]; still {
		t.Fatal("DetachXDP left the stale claim behind (the retained-registry cleanup did not run)")
	}
	if _, still := m.xdpLinks[ifindex]; still {
		t.Fatal("DetachXDP left the link in xdpLinks")
	}
	if !fake.unpinned || !fake.closed {
		t.Fatalf("fake link lifecycle = unpinned:%v closed:%v, want both", fake.unpinned, fake.closed)
	}
}

// armedGateFakeLink embeds link.Link (the interface carries an unexported
// marker, so it cannot be implemented externally) and overrides exactly the
// two methods DetachXDP invokes.
type armedGateFakeLink struct {
	link.Link
	unpinned bool
	closed   bool
}

func (l *armedGateFakeLink) Unpin() error { l.unpinned = true; return nil }
func (l *armedGateFakeLink) Close() error { l.closed = true; return nil }

// TestManager_ArmedGate_AbsentIfaceZoneMapNoOp is continuation leg (iii):
// with iface_zone_map ABSENT (armed or retained), setXDPAttachedFlag
// returns master's early-boot no-op NIL and does NOT touch the claims —
// distinct from the Detach leg's map-present cleanup. Always-on (no BPF
// needed: the early return precedes any map use).
func TestManager_ArmedGate_AbsentIfaceZoneMapNoOp(t *testing.T) {
	for _, armed := range []bool{false, true} {
		m := New()
		armedGateSentinel(m) // retained classification (registry nonempty, map absent)
		m.loaded.Store(armed)
		key := IfaceZoneKey{Ifindex: 7, VlanID: 0}
		m.xdpFlagClaims[key] = map[int]bool{7: true}
		if err := m.setXDPAttachedFlag(7, false); err != nil {
			t.Fatalf("armed=%v: setXDPAttachedFlag = %v, want master's early-boot no-op nil", armed, err)
		}
		if _, still := m.xdpFlagClaims[key]; !still {
			t.Fatalf("armed=%v: absent-iface_zone_map path must not touch the claims", armed)
		}
	}
}

// TestManager_ArmedGate_SeedInterfaceCounterNilGuard is continuation leg
// (ii), absent half (always-on): with interface_counters ABSENT,
// AddTxPort's seed skips silently (master's nil-guard return), NOT a
// spurious error — here on an armed manager with a real tx_ports map so
// the post-seed success is observable. The present half (the seed writes)
// needs a real PERCPU_HASH and joins the privileged set below.
func TestManager_ArmedGate_SeedInterfaceCounterNilGuard(t *testing.T) {
	txPorts, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "tx_ports",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: MaxInterfaces,
	})
	if err != nil {
		skipIfBPFUnavailable(t, "new tx_ports map", err)
		return
	}
	defer txPorts.Close()

	m := New()
	m.maps["tx_ports"] = txPorts // interface_counters deliberately ABSENT
	m.loaded.Store(true)

	if err := m.AddTxPort(1); err != nil {
		t.Fatalf("AddTxPort with absent interface_counters = %v, want nil (the seed's nil-guard skip)", err)
	}
}

// TestManager_ArmedGate_ContinuationLegsPrivileged is the privileged
// semantic-mutation set (plan's oracle split): real-map fixtures assert
// the mixed-method CONTINUATION behavior that a premature optional-miss
// return would break. Skips where BPF map creation is unavailable.
func TestManager_ArmedGate_ContinuationLegsPrivileged(t *testing.T) {
	newArray := func(st *testing.T, name string, valueSize, maxEntries uint32) *ebpf.Map {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name: name, Type: ebpf.Array, KeySize: 4,
			ValueSize: valueSize, MaxEntries: maxEntries,
		})
		if err != nil {
			skipIfBPFUnavailable(st, "new "+name, err)
		}
		st.Cleanup(func() { m.Close() })
		return m
	}
	newHash := func(st *testing.T, name string, keySize, valueSize, maxEntries uint32) *ebpf.Map {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name: name, Type: ebpf.Hash, KeySize: keySize,
			ValueSize: valueSize, MaxEntries: maxEntries,
		})
		if err != nil {
			skipIfBPFUnavailable(st, "new "+name, err)
		}
		st.Cleanup(func() { m.Close() })
		return m
	}

	for _, armed := range []bool{true, false} {
		name := "retained"
		if armed {
			name = "armed"
		}
		t.Run(name+"_ClearNAT64Configs_partial_registry", func(t *testing.T) {
			// The DISCRIMINATING partial-registry leg: required nat64_configs
			// PRESENT with a nonzero nat64_count, OPTIONAL nat64_prefix_map
			// ABSENT — the call must SUCCEED AND the trailing required count
			// write must land. A premature optional-miss return leaves the
			// count non-zero and FAILS this leg.
			m := New()
			m.maps["nat64_configs"] = newArray(t, "nat64_configs", uint32(sizeOf[NAT64Config]()), 4)
			m.maps["nat64_count"] = newArray(t, "nat64_count", 4, 1)
			m.loaded.Store(armed)

			if err := m.SetNAT64Count(2); err != nil {
				t.Fatalf("seed nat64_count: %v", err)
			}
			if err := m.ClearNAT64Configs(); err != nil {
				t.Fatalf("ClearNAT64Configs with optional nat64_prefix_map absent = %v, want success (continuation)", err)
			}
			var got uint32
			if err := m.maps["nat64_count"].Lookup(uint32(0), &got); err != nil {
				t.Fatalf("read back nat64_count: %v", err)
			}
			if got != 0 {
				t.Fatalf("nat64_count after ClearNAT64Configs = %d, want 0 (the trailing required write did not land — premature optional-miss return)", got)
			}
		})

		t.Run(name+"_SetNAT64Config_required_write_lands", func(t *testing.T) {
			// Leg (i): REQUIRED nat64_configs present, OPTIONAL
			// nat64_prefix_map absent — the call succeeds AND the required
			// write is readable back.
			m := New()
			m.maps["nat64_configs"] = newArray(t, "nat64_configs", uint32(sizeOf[NAT64Config]()), 4)
			m.loaded.Store(armed)

			cfg := NAT64Config{Prefix: [3]uint32{0x64ff9b00, 0, 0}}
			if err := m.SetNAT64Config(0, cfg); err != nil {
				t.Fatalf("SetNAT64Config with optional nat64_prefix_map absent = %v, want success", err)
			}
			var back NAT64Config
			if err := m.maps["nat64_configs"].Lookup(uint32(0), &back); err != nil {
				t.Fatalf("read back nat64_configs[0]: %v", err)
			}
			if back != cfg {
				t.Fatalf("nat64_configs[0] = %+v, want the written config (the required write did not land)", back)
			}
		})

		t.Run(name+"_ClearStaticNATEntries_continues_to_v6", func(t *testing.T) {
			// Absent static_nat_v4 must CONTINUE to the v6 clear.
			m := New()
			v6 := newHash(t, "static_nat_v6", uint32(sizeOf[StaticNATKeyV6]()), uint32(sizeOf[StaticNATValueV6]()), 8)
			m.maps["static_nat_v6"] = v6
			m.loaded.Store(armed)

			k := StaticNATKeyV6{Direction: 1}
			if err := v6.Update(k, StaticNATValueV6{}, ebpf.UpdateAny); err != nil {
				t.Fatalf("seed static_nat_v6: %v", err)
			}
			if err := m.ClearStaticNATEntries(); err != nil {
				t.Fatalf("ClearStaticNATEntries = %v", err)
			}
			var out StaticNATValueV6
			if err := v6.Lookup(k, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("static_nat_v6 entry survives (err=%v) — the v4-absent path did not continue to v6", err)
			}
		})

		t.Run(name+"_SessionCount_reports_both_families", func(t *testing.T) {
			m := New()
			v4 := newHash(t, "sessions", uint32(sizeOf[SessionKey]()), ConntrackSessionValueSize, 8)
			v6 := newHash(t, "sessions_v6", uint32(sizeOf[SessionKeyV6]()), ConntrackSessionValueSizeV6, 8)
			m.maps["sessions"] = v4
			m.maps["sessions_v6"] = v6
			m.loaded.Store(armed)

			k4 := SessionKey{Protocol: 6}
			if err := v4.Update(k4, make([]byte, ConntrackSessionValueSize), ebpf.UpdateAny); err != nil {
				t.Fatalf("seed sessions: %v", err)
			}
			k6 := SessionKeyV6{Protocol: 6}
			if err := v6.Update(k6, make([]byte, ConntrackSessionValueSizeV6), ebpf.UpdateAny); err != nil {
				t.Fatalf("seed sessions_v6: %v", err)
			}
			got4, got6 := m.SessionCount()
			if got4 != 1 || got6 != 1 {
				t.Fatalf("SessionCount = (%d,%d), want (1,1) — both families must be reported", got4, got6)
			}
		})

		t.Run(name+"_ClearSessionCounts_clears_both_maps", func(t *testing.T) {
			m := New()
			src := newHash(t, "session_count_src", uint32(sizeOf[SessionCountKey]()), uint32(sizeOf[SessionCountValue]()), 8)
			dst := newHash(t, "session_count_dst", uint32(sizeOf[SessionCountKey]()), uint32(sizeOf[SessionCountValue]()), 8)
			m.maps["session_count_src"] = src
			m.maps["session_count_dst"] = dst
			m.loaded.Store(armed)

			k := SessionCountKey{}
			if err := src.Update(k, SessionCountValue{Count: 3}, ebpf.UpdateAny); err != nil {
				t.Fatalf("seed src: %v", err)
			}
			if err := dst.Update(k, SessionCountValue{Count: 4}, ebpf.UpdateAny); err != nil {
				t.Fatalf("seed dst: %v", err)
			}
			if err := m.ClearSessionCounts(); err != nil {
				t.Fatalf("ClearSessionCounts = %v", err)
			}
			var out SessionCountValue
			if err := src.Lookup(k, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("src entry survives (err=%v) — first-map loop did not clear", err)
			}
			if err := dst.Lookup(k, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("dst entry survives (err=%v) — the loop did not continue to the second map", err)
			}
		})

		t.Run(name+"_SeedNATPortCounters_writes_when_present", func(t *testing.T) {
			// Leg (ii) present half: nat_port_counters present ⇒ the seed
			// writes (distinguishing the nil-guard skip from a spurious
			// error or a silent no-op).
			m := New()
			npc := newArray(t, "nat_port_counters", uint32(sizeOf[NATPortCounter]()), 32)
			m.maps["nat_port_counters"] = npc
			m.loaded.Store(armed)

			m.SeedNATPortCounters()
			var vals []NATPortCounter
			if err := npc.Lookup(uint32(0), &vals); err != nil {
				t.Fatalf("read back nat_port_counters[0]: %v", err)
			}
			// A fresh PERCPU_ARRAY reads back zero-per-CPU before the seed;
			// the seed writes a random offset on CPU 0 (may theoretically be
			// 0 with probability 2^-64 — acceptable).
			nonzero := false
			for _, v := range vals {
				if v.Counter != 0 {
					nonzero = true
				}
			}
			if !nonzero {
				t.Fatal("nat_port_counters[0] all-zero after the seed — the present-map seed did not write")
			}
		})
	}
}
