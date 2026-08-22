package userspace

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildSnapshotIncludesThreeColorPolicerSchema(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.ThreeColorPolicers = map[string]*config.ThreeColorPolicerConfig{
		"sr": {
			Name:       "sr",
			ColorBlind: true,
			CIR:        125000,
			CBS:        50000,
			PBS:        100000,
			ThenAction: "discard",
		},
		"tr": {
			Name:       "tr",
			TwoRate:    true,
			ColorBlind: true,
			CIR:        125000,
			CBS:        50000,
			PIR:        250000,
			PBS:        100000,
			ThenAction: "discard",
		},
	}

	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if !snap.Capabilities.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, want three-color policers admitted. Reasons: %+v", snap.Capabilities.UnsupportedReasons)
	}
	want := []ThreeColorPolicerSnapshot{
		{
			Name:                   "sr",
			Mode:                   "single-rate",
			ColorBlind:             true,
			CommittedRateBytes:     125000,
			CommittedBurstBytes:    50000,
			PeakOrExcessBurstBytes: 100000,
			ThenAction:             "discard",
		},
		{
			Name:                   "tr",
			Mode:                   "two-rate",
			ColorBlind:             true,
			CommittedRateBytes:     125000,
			CommittedBurstBytes:    50000,
			PeakOrExcessRateBytes:  250000,
			PeakOrExcessBurstBytes: 100000,
			ThenAction:             "discard",
		},
	}
	if !reflect.DeepEqual(snap.ThreeColorPolicers, want) {
		t.Fatalf("ThreeColorPolicers = %+v, want %+v", snap.ThreeColorPolicers, want)
	}
}

func TestBuildClassOfServiceSnapshotIncludesTransmitRateExact(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			Schedulers: map[string]*config.CoSScheduler{
				"exact-sched": {
					Name:              "exact-sched",
					TransmitRateBytes: 1_250_000,
					TransmitRateExact: true,
					Priority:          "strict-high",
					BufferSizeBytes:   64_000,
				},
			},
		},
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil class-of-service snapshot")
	}
	if len(snap.Schedulers) != 1 {
		t.Fatalf("Schedulers len = %d, want 1", len(snap.Schedulers))
	}
	if !snap.Schedulers[0].TransmitRateExact {
		t.Fatal("expected transmit_rate_exact in class-of-service snapshot")
	}
	if got := snap.Schedulers[0].TransmitRateBytes; got != 1_250_000 {
		t.Fatalf("TransmitRateBytes = %d, want 1250000", got)
	}
}

// #2409: a scheduler-map entry referencing a forwarding-class that is NOT
// defined in `class-of-service forwarding-classes` is warning-only at commit
// time (compiler_validate_warn.go), so the config commits and the valid
// entries must still install. The snapshot emitter must DEGRADE VISIBLY here
// — skip only the undefined entry (keeping the valid subset) so it never
// reaches the Rust SchedulerMapUnknownClass hard-error and freezes the whole
// dataplane apply on a supported config shape.
//
// fail-on-revert: removing the `cos.ForwardingClasses[...]` membership skip in
// buildClassOfServiceSnapshot puts the undefined entry on the wire, this
// assertion (only the valid entry survives) goes red, and the Rust side would
// then hard-fail the apply.
func TestBuildClassOfServiceSnapshotSkipsUndefinedSchedulerMapClass(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			ForwardingClasses: map[string]*config.CoSForwardingClass{
				"best-effort": {Name: "best-effort", Queue: 0},
			},
			Schedulers: map[string]*config.CoSScheduler{
				"sched-be": {Name: "sched-be", TransmitRateBytes: 1_000_000},
			},
			SchedulerMaps: map[string]*config.CoSSchedulerMap{
				"map1": {
					Name: "map1",
					Entries: map[string]*config.CoSSchedulerMapEntry{
						// valid — best-effort is defined
						"best-effort": {ForwardingClass: "best-effort", Scheduler: "sched-be"},
						// undefined class — warning-only at commit, must be skipped
						"voice": {ForwardingClass: "voice", Scheduler: "sched-be"},
					},
				},
			},
		},
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil class-of-service snapshot")
	}
	if len(snap.SchedulerMaps) != 1 {
		t.Fatalf("SchedulerMaps len = %d, want 1", len(snap.SchedulerMaps))
	}
	entries := snap.SchedulerMaps[0].Entries
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1 (undefined-class entry must be skipped)", len(entries))
	}
	if entries[0].ForwardingClass != "best-effort" {
		t.Fatalf("surviving entry class = %q, want best-effort (the valid subset must install)", entries[0].ForwardingClass)
	}
}

// #2704: a DSCP classifier, 802.1p classifier, or DSCP rewrite-rule entry
// referencing a forwarding-class that is not defined in
// `class-of-service forwarding-classes` is only a NON-FATAL warning at commit
// (compiler_validate_warn.go). The emitter must SKIP such an entry (mirroring
// the scheduler-map skip) so the classifier/rewrite loss is no longer SILENT —
// the pre-fix emitter carried the entry unfiltered and the Rust side then
// silently dropped/no-op'd it. fail-on-revert: removing the filter lets the
// undefined-class entry cross the wire and the surviving-entry asserts go red.
func TestBuildClassOfServiceSnapshotSkipsUndefinedClassifierAndRewriteClass(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			ForwardingClasses: map[string]*config.CoSForwardingClass{
				"best-effort": {Name: "best-effort", Queue: 0},
			},
			DSCPClassifiers: map[string]*config.CoSDSCPClassifier{
				"dscp-cl": {
					Name: "dscp-cl",
					Entries: []*config.CoSDSCPClassifierEntry{
						{ForwardingClass: "best-effort", DSCPValues: []uint8{0}},
						// undefined class — warning-only at commit, must be skipped
						{ForwardingClass: "voice", DSCPValues: []uint8{46}},
					},
				},
			},
			IEEE8021Classifiers: map[string]*config.CoSIEEE8021Classifier{
				"pcp-cl": {
					Name: "pcp-cl",
					Entries: []*config.CoSIEEE8021ClassifierEntry{
						{ForwardingClass: "best-effort", CodePoints: []uint8{0}},
						{ForwardingClass: "voice", CodePoints: []uint8{5}},
					},
				},
			},
			DSCPRewriteRules: map[string]*config.CoSDSCPRewriteRule{
				"rw": {
					Name: "rw",
					Entries: []*config.CoSDSCPRewriteRuleEntry{
						{ForwardingClass: "best-effort", DSCPValue: 0},
						{ForwardingClass: "voice", DSCPValue: 46},
					},
				},
			},
		},
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil class-of-service snapshot")
	}

	if len(snap.DSCPClassifiers) != 1 {
		t.Fatalf("DSCPClassifiers len = %d, want 1", len(snap.DSCPClassifiers))
	}
	dscpEntries := snap.DSCPClassifiers[0].Entries
	if len(dscpEntries) != 1 {
		t.Fatalf("dscp classifier entries = %d, want 1 (undefined-class entry must be skipped)", len(dscpEntries))
	}
	if dscpEntries[0].ForwardingClass != "best-effort" {
		t.Fatalf("dscp surviving class = %q, want best-effort", dscpEntries[0].ForwardingClass)
	}

	if len(snap.IEEE8021Classifiers) != 1 {
		t.Fatalf("IEEE8021Classifiers len = %d, want 1", len(snap.IEEE8021Classifiers))
	}
	pcpEntries := snap.IEEE8021Classifiers[0].Entries
	if len(pcpEntries) != 1 {
		t.Fatalf("802.1p classifier entries = %d, want 1 (undefined-class entry must be skipped)", len(pcpEntries))
	}
	if pcpEntries[0].ForwardingClass != "best-effort" {
		t.Fatalf("802.1p surviving class = %q, want best-effort", pcpEntries[0].ForwardingClass)
	}

	if len(snap.DSCPRewriteRules) != 1 {
		t.Fatalf("DSCPRewriteRules len = %d, want 1", len(snap.DSCPRewriteRules))
	}
	rwEntries := snap.DSCPRewriteRules[0].Entries
	if len(rwEntries) != 1 {
		t.Fatalf("rewrite entries = %d, want 1 (undefined-class entry must be skipped)", len(rwEntries))
	}
	if rwEntries[0].ForwardingClass != "best-effort" {
		t.Fatalf("rewrite surviving class = %q, want best-effort", rwEntries[0].ForwardingClass)
	}
}

// #1746: the equal-flow target policy reaches the scheduler snapshot,
// and an UNSET policy keeps the serialized snapshot byte-identical to
// the pre-#1746 wire (omitempty) — the byte-unchanged-default proof.
func TestBuildClassOfServiceSnapshotIncludesEqualFlowTargetPolicy(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			Schedulers: map[string]*config.CoSScheduler{
				"ef-sched": {
					Name:                  "ef-sched",
					TransmitRateBytes:     125_000_000,
					TransmitRateExact:     true,
					EqualFlowEnforcement:  true,
					EqualFlowTargetPolicy: "mean",
				},
				"plain-sched": {
					Name:                 "plain-sched",
					TransmitRateBytes:    125_000_000,
					TransmitRateExact:    true,
					EqualFlowEnforcement: true,
				},
			},
		},
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil class-of-service snapshot")
	}
	byName := map[string]CoSSchedulerSnapshot{}
	for _, sched := range snap.Schedulers {
		byName[sched.Name] = sched
	}
	if got := byName["ef-sched"].EqualFlowTargetPolicy; got != "mean" {
		t.Fatalf("ef-sched EqualFlowTargetPolicy = %q, want mean", got)
	}
	if got := byName["plain-sched"].EqualFlowTargetPolicy; got != "" {
		t.Fatalf("plain-sched EqualFlowTargetPolicy = %q, want empty", got)
	}

	// omitempty: the unset policy must not appear on the wire at all.
	plain, err := json.Marshal(byName["plain-sched"])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(plain), "equal_flow_target_policy") {
		t.Fatalf("unset policy leaked onto the wire (breaks byte-unchanged default): %s", plain)
	}
	withPolicy, err := json.Marshal(byName["ef-sched"])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(withPolicy), `"equal_flow_target_policy":"mean"`) {
		t.Fatalf("set policy missing from wire: %s", withPolicy)
	}
}

func TestBuildClassOfServiceSnapshotIncludesBufferSizePercent(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			Schedulers: map[string]*config.CoSScheduler{
				"percent-sched": {
					Name:              "percent-sched",
					TransmitRateBytes: 1_250_000,
					BufferSizePercent: 10,
				},
			},
		},
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil class-of-service snapshot")
	}
	if len(snap.Schedulers) != 1 {
		t.Fatalf("Schedulers len = %d, want 1", len(snap.Schedulers))
	}
	if got := snap.Schedulers[0].BufferSizePercent; got != 10 {
		t.Fatalf("BufferSizePercent = %v, want 10", got)
	}
	if got := snap.Schedulers[0].BufferSizeBytes; got != 0 {
		t.Fatalf("BufferSizeBytes = %d, want 0 for percent scheduler", got)
	}
}

// #915: snapshot encoding round-trips the SurplusSharing bool.
func TestBuildClassOfServiceSnapshotIncludesSurplusSharing(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			Schedulers: map[string]*config.CoSScheduler{
				"iperf-a": {
					Name:              "iperf-a",
					TransmitRateBytes: 125_000_000,
					TransmitRateExact: true,
					SurplusSharing:    true,
					Priority:          "low",
				},
				"iperf-b": {
					Name:              "iperf-b",
					TransmitRateBytes: 1_250_000_000,
					TransmitRateExact: true,
					SurplusSharing:    false, // explicit hard-cap, no opt-in
					Priority:          "low",
				},
			},
		},
	}
	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if len(snap.Schedulers) != 2 {
		t.Fatalf("Schedulers len = %d, want 2", len(snap.Schedulers))
	}
	got := map[string]bool{}
	for _, s := range snap.Schedulers {
		got[s.Name] = s.SurplusSharing
	}
	if !got["iperf-a"] {
		t.Errorf("expected SurplusSharing=true on iperf-a; got %v", got)
	}
	if got["iperf-b"] {
		t.Errorf("expected SurplusSharing=false on iperf-b; got %v", got)
	}
}

// #4966: surplus-sharing is a no-op without transmit-rate exact.
// ValidateConfig warns but no longer strips it from the config, so the
// snapshot builder is the effective gate — a scheduler with
// SurplusSharing=true but TransmitRateExact=false must serialize
// SurplusSharing=false so the runtime never receives the inert flag.
func TestBuildClassOfServiceSnapshotGatesSurplusSharingOnExact(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			Schedulers: map[string]*config.CoSScheduler{
				// Configured intent: surplus-sharing set, but the rate
				// is NOT exact, so the effective value must be false.
				"inert": {
					Name:              "inert",
					TransmitRateBytes: 125_000_000,
					TransmitRateExact: false,
					SurplusSharing:    true,
					Priority:          "low",
				},
				// Exact + surplus-sharing: effective value stays true.
				"live": {
					Name:              "live",
					TransmitRateBytes: 125_000_000,
					TransmitRateExact: true,
					SurplusSharing:    true,
					Priority:          "low",
				},
			},
		},
	}
	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	got := map[string]bool{}
	for _, s := range snap.Schedulers {
		got[s.Name] = s.SurplusSharing
	}
	if got["inert"] {
		t.Errorf("expected SurplusSharing gated off on non-exact scheduler; got %v", got)
	}
	if !got["live"] {
		t.Errorf("expected SurplusSharing preserved on exact scheduler; got %v", got)
	}
}

func TestBuildClassOfServiceSnapshotIncludesEqualFlowEnforcement(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			Schedulers: map[string]*config.CoSScheduler{
				"iperf-a": {
					Name:                 "iperf-a",
					TransmitRateBytes:    125_000_000,
					TransmitRateExact:    true,
					EqualFlowEnforcement: true,
					Priority:             "low",
				},
				"iperf-b": {
					Name:              "iperf-b",
					TransmitRateBytes: 1_250_000_000,
					TransmitRateExact: true,
					Priority:          "low",
				},
			},
		},
	}
	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	got := map[string]bool{}
	for _, s := range snap.Schedulers {
		got[s.Name] = s.EqualFlowEnforcement
	}
	if !got["iperf-a"] {
		t.Errorf("expected EqualFlowEnforcement=true on iperf-a; got %v", got)
	}
	if got["iperf-b"] {
		t.Errorf("expected EqualFlowEnforcement=false on iperf-b; got %v", got)
	}
}

func TestBuildClassOfServiceSnapshotIncludesIEEE8021Classifier(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			ForwardingClasses: map[string]*config.CoSForwardingClass{
				"best-effort": {Name: "best-effort", Queue: 0},
				"voice":       {Name: "voice", Queue: 5},
			},
			IEEE8021Classifiers: map[string]*config.CoSIEEE8021Classifier{
				"wan-pcp": {
					Name: "wan-pcp",
					Entries: []*config.CoSIEEE8021ClassifierEntry{
						{
							ForwardingClass: "voice",
							LossPriority:    "low",
							CodePoints:      []uint8{5},
						},
					},
				},
			},
			Interfaces: map[string]*config.CoSInterface{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.CoSInterfaceUnit{
						80: {
							Unit:               80,
							IEEE8021Classifier: "wan-pcp",
						},
					},
				},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						80: {Number: 80},
					},
				},
			},
		},
	}

	interfaces := buildInterfaceSnapshots(cfg)
	var unitSnap *InterfaceSnapshot
	for i := range interfaces {
		if interfaces[i].Name == "reth0.80" {
			unitSnap = &interfaces[i]
			break
		}
	}
	if unitSnap == nil {
		t.Fatal("reth0.80 snapshot not found")
	}
	if got := unitSnap.CoSIEEE8021Classifier; got != "wan-pcp" {
		t.Fatalf("CoSIEEE8021Classifier = %q, want wan-pcp", got)
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil class-of-service snapshot")
	}
	if len(snap.IEEE8021Classifiers) != 1 {
		t.Fatalf("IEEE8021Classifiers len = %d, want 1", len(snap.IEEE8021Classifiers))
	}
	if got := snap.IEEE8021Classifiers[0].Entries[0].CodePoints; len(got) != 1 || got[0] != 5 {
		t.Fatalf("CodePoints = %v, want [5]", got)
	}
}

func TestBuildClassOfServiceSnapshotIncludesDSCPRewriteRule(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			ForwardingClasses: map[string]*config.CoSForwardingClass{
				"best-effort": {Name: "best-effort", Queue: 0},
				"voice":       {Name: "voice", Queue: 5},
			},
			DSCPRewriteRules: map[string]*config.CoSDSCPRewriteRule{
				"wan-rewrite": {
					Name: "wan-rewrite",
					Entries: []*config.CoSDSCPRewriteRuleEntry{
						{
							ForwardingClass: "voice",
							LossPriority:    "low",
							DSCPValue:       46,
						},
					},
				},
			},
			Interfaces: map[string]*config.CoSInterface{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.CoSInterfaceUnit{
						80: {
							Unit:            80,
							DSCPRewriteRule: "wan-rewrite",
						},
					},
				},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						80: {Number: 80},
					},
				},
			},
		},
	}

	interfaces := buildInterfaceSnapshots(cfg)
	var unitSnap *InterfaceSnapshot
	for i := range interfaces {
		if interfaces[i].Name == "reth0.80" {
			unitSnap = &interfaces[i]
			break
		}
	}
	if unitSnap == nil {
		t.Fatal("reth0.80 snapshot not found")
	}
	if got := unitSnap.CoSDSCPRewriteRule; got != "wan-rewrite" {
		t.Fatalf("CoSDSCPRewriteRule = %q, want wan-rewrite", got)
	}

	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil class-of-service snapshot")
	}
	if len(snap.DSCPRewriteRules) != 1 {
		t.Fatalf("DSCPRewriteRules len = %d, want 1", len(snap.DSCPRewriteRules))
	}
	if got := snap.DSCPRewriteRules[0].Entries[0].DSCPValue; got != 46 {
		t.Fatalf("DSCPValue = %d, want 46", got)
	}
}
