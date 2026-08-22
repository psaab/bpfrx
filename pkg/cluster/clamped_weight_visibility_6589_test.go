// #6589: a clamped (inert) monitor weight was visible only in journald — no
// operator-facing surface distinguished it from a working monitor.
//
// The clamp itself is not the defect and was adjudicated during #6586: 0 is
// retained because it is an already-legal, operator-reachable state (an
// interface-monitor with no weight token compiles to exactly 0, "monitor this,
// contribute no debt"), and because clamping to 255 would let a typo'd -100
// arriving over the HA config-sync push make the RECEIVING node resign its
// redundancy group the moment that link flaps — turning config-sync into a
// remote HA denial of service.
//
// What survives is that the clamp is INVISIBLE. And it is invisible in a
// specific way worth naming: every renderer already called
// ClampInterfaceMonitorWeight and threw the signal away — `w, _ := ...` —
// so it printed a plausible 0 or 255 indistinguishable from an
// operator-authored one. A diagnostic that fails to a value that looks healthy.
//
// TWO CLASSES, and they are not equally bad:
//
//   - interface-monitor weights DO reach journald, once per config apply, via
//     reconcileMonitorDebtsLocked. Invisible on every operator surface.
//   - ip-monitoring weights reached NOTHING. ipTargetWeight and the
//     global-threshold aggregate both discarded the clamp signal and no site
//     anywhere logged it, so an out-of-range ip-monitoring weight was invisible
//     including in the log. That is worse than the case #6589 was filed about.
//
// Either way the consequence is the same: a monitor clamped to 0 owes no
// election debt, so its RG does not demote when that link or probe fails, and
// the operator discovers it during a failover that does not happen.
//
// FAIL-ON-REVERT: restore `w, _ :=` at a producer, or drop the render, and the
// clamped monitor becomes indistinguishable from a configured one again.
package cluster

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestClampedInterfaceMonitorIsVisibleInStatus6589(t *testing.T) {
	m := NewManager(0, 1)

	out := m.FormatInterfaces(InterfacesInput{
		Monitors: []InterfaceMonitorInfo{
			// Clamped from a typo'd negative: the runtime bounds it to 0, i.e.
			// "contributes no debt".
			{Interface: "ge-0/0/1", Weight: 0, Up: true, RedundancyGroup: 1,
				ConfiguredWeight: -100, Clamped: true},
			// An ordinary monitor that is legitimately weight 0.
			{Interface: "ge-0/0/2", Weight: 0, Up: true, RedundancyGroup: 1},
		},
	})

	if !strings.Contains(out, "cfg -100") {
		t.Errorf("the clamped monitor's CONFIGURED weight is not shown, so it is "+
			"indistinguishable from a monitor legitimately configured at 0:\n%s", out)
	}
	if !strings.Contains(out, "CLAMPED") {
		t.Errorf("no CLAMPED annotation in the output:\n%s", out)
	}
	// The note must say what it MEANS. "CLAMPED" alone does not tell an
	// operator their RG will not demote.
	if !strings.Contains(out, "NOT demote") {
		t.Errorf("the note does not state the consequence (the RG will not demote), "+
			"so an operator cannot tell whether it matters:\n%s", out)
	}
}

// The discrimination is the property, so it is asserted directly: two monitors
// with the SAME effective weight must render differently when one was clamped.
// A test that only checked "CLAMPED appears" would pass a renderer that
// annotated every monitor.
func TestClampedAnnotationDiscriminates6589(t *testing.T) {
	m := NewManager(0, 1)

	clean := m.FormatInterfaces(InterfacesInput{
		Monitors: []InterfaceMonitorInfo{
			{Interface: "ge-0/0/2", Weight: 0, Up: true, RedundancyGroup: 1},
		},
	})
	if strings.Contains(clean, "CLAMPED") || strings.Contains(clean, "cfg ") {
		t.Fatalf("a monitor that was NOT clamped is annotated as clamped — the "+
			"annotation carries no information:\n%s", clean)
	}

	clamped := m.FormatInterfaces(InterfacesInput{
		Monitors: []InterfaceMonitorInfo{
			{Interface: "ge-0/0/2", Weight: 0, Up: true, RedundancyGroup: 1,
				ConfiguredWeight: 900, Clamped: true},
		},
	})
	if !strings.Contains(clamped, "CLAMPED") {
		t.Fatalf("a clamped monitor is not annotated:\n%s", clamped)
	}
	// Same effective weight in both renders — only the provenance differs.
	if !strings.Contains(clean, "ge-0/0/2") || !strings.Contains(clamped, "ge-0/0/2") {
		t.Fatal("fixture: both renders must contain the monitor row")
	}
}

// TestClampedIPMonitorWeightsAreReported6589 covers the class that reached no
// surface at all — not even the log.
func TestClampedIPMonitorWeightsAreReported6589(t *testing.T) {
	rg := makeRG(2, false, map[int]int{0: 200, 1: 100})
	rg.IPMonitoring = &config.IPMonitoring{
		GlobalWeight: 400, // out of range -> clamped to 255
		Targets: []*config.IPMonitorTarget{
			{Address: "10.0.0.1", Weight: -5},  // clamped to 0
			{Address: "10.0.0.2", Weight: 100}, // fine
			{Address: "10.0.0.3"},              // unset -> inherits global, reported once above
		},
	}
	mon := NewMonitor(NewManager(0, 1), []*config.RedundancyGroup{rg})

	got := mon.ClampedIPMonitorWeights()
	if len(got) != 2 {
		t.Fatalf("reported %d clamped ip weights, want 2 (the global-weight and the "+
			"negative per-target one): %+v", len(got), got)
	}
	var sawGlobal, sawTarget bool
	for _, c := range got {
		switch c.Target {
		case "":
			sawGlobal = true
			if c.Configured != 400 || c.Effective != 255 {
				t.Errorf("global: configured=%d effective=%d, want 400/255", c.Configured, c.Effective)
			}
		case "10.0.0.1":
			sawTarget = true
			if c.Configured != -5 || c.Effective != 0 {
				t.Errorf("10.0.0.1: configured=%d effective=%d, want -5/0", c.Configured, c.Effective)
			}
		default:
			t.Errorf("unexpected clamped entry %+v — an in-range weight must NOT be "+
				"reported, or the surface becomes noise operators learn to ignore", c)
		}
	}
	if !sawGlobal || !sawTarget {
		t.Errorf("missing entries: global=%v target=%v", sawGlobal, sawTarget)
	}
}

// The unset-per-target case is the over-reach control: a target with no weight
// token inherits the global one, which is already reported on its own line.
// Reporting it again would show the operator a per-target clamp they never
// configured.
func TestUnsetIPTargetWeightIsNotReportedAsClamped6589(t *testing.T) {
	rg := makeRG(3, false, map[int]int{0: 200})
	// The global is OUT of range, so it is reported on its own line. The unset
	// target inherits it at election time (ipTargetWeight), and a reporter that
	// mirrored that inheritance would report the SAME clamp a second time as if
	// it were a per-target one the operator configured. An in-range global here
	// would make this control vacuous — nothing would be reported either way.
	rg.IPMonitoring = &config.IPMonitoring{
		GlobalWeight: 900, // out of range -> one report, for the global
		Targets:      []*config.IPMonitorTarget{{Address: "10.0.0.9"}},
	}
	mon := NewMonitor(NewManager(0, 1), []*config.RedundancyGroup{rg})

	got := mon.ClampedIPMonitorWeights()
	if len(got) != 1 {
		t.Fatalf("want exactly 1 report (the global-weight); an unset per-target weight "+
			"must not be reported as a per-target clamp the operator never configured. "+
			"got %d: %+v", len(got), got)
	}
	if got[0].Target != "" {
		t.Errorf("the single report should be the global-weight, got target %q", got[0].Target)
	}
}

// TestNoDisplayProducerDiscardsTheClampSignal6589 binds the WIRING, and it is
// keyed on the exact shape of the defect.
//
// Every test above constructs InterfaceMonitorInfo directly, so all of them
// stay green if a PRODUCER stops carrying the signal — and that is precisely
// what the bug was. The pre-#6589 code did not fail to clamp; it clamped
// correctly and wrote `w, _ := config.ClampInterfaceMonitorWeight(...)`,
// throwing away the one bit that says the operator's value was not the one in
// effect.
//
// So: no display-path producer may use the blank-identifier form. The
// exemptions are written down, and a stale one fails too.
func TestNoDisplayProducerDiscardsTheClampSignal6589(t *testing.T) {
	t.Parallel()

	type exemption struct{ file, why string }
	// Files allowed to discard the signal, with the reason.
	allowed := map[string]string{}
	for _, e := range []exemption{
		{"../cluster/monitor.go",
			"ipTargetWeight and desiredRGIPDebts compute an ELECTION weight, not a " +
				"display value; the display side reads ClampedIPMonitorWeights, which " +
				"keeps the signal"},
	} {
		allowed[e.file] = e.why
	}

	roots := []string{"../cluster", "../cli", "../grpcapi", "../routing"}
	var offenders []string
	found := map[string]bool{}
	scanned := 0

	for _, dir := range roots {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range ents {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			scanned++
			// Whitespace-collapsed so a gofmt line break between the two
			// return values cannot hide the discard — the same wrap-blindness
			// that would have made a line-oriented grep miss the original.
			flat := strings.Join(strings.Fields(string(src)), "")
			if !strings.Contains(flat, ",_:=config.ClampInterfaceMonitorWeight(") {
				continue
			}
			if _, ok := allowed[path]; ok {
				found[path] = true
				continue
			}
			offenders = append(offenders, path)
		}
	}

	if scanned < 40 {
		t.Fatalf("scanned only %d files — the walk is vacuous", scanned)
	}
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s discards the clamp signal (`w, _ := ClampInterfaceMonitorWeight`).\n"+
			"  Capture it and carry ConfiguredWeight/Clamped to the display: the clamped\n"+
			"  value is a plausible 0 or 255, indistinguishable from one the operator\n"+
			"  configured, and a monitor clamped to 0 means its redundancy group will\n"+
			"  never demote when that link fails (#6589).", o)
	}
	for path, why := range allowed {
		if !found[path] {
			t.Errorf("stale exemption: %s no longer discards the clamp signal (%s). "+
				"Remove it — a stale entry silently widens the next real one.", path, why)
		}
	}
}

// TestClampedIPWeightsReachTheOperatorSurface6589 binds the RENDER for the IP
// class. The reporter test above proves ClampedIPMonitorWeights computes the
// right set; it says nothing about whether any operator command prints it, and
// "computed but never displayed" is the exact defect #6589 is about.
func TestClampedIPWeightsReachTheOperatorSurface6589(t *testing.T) {
	m := NewManager(0, 1)
	rg := makeRG(1, false, map[int]int{0: 200})
	rg.IPMonitoring = &config.IPMonitoring{
		GlobalWeight: 700,
		Targets:      []*config.IPMonitorTarget{{Address: "10.9.9.9", Weight: -3}},
	}
	cfg := makeConfig(rg)
	m.UpdateConfig(cfg)
	m.monitor = NewMonitor(m, cfg.RedundancyGroups)

	out := m.FormatIPMonitoringStatus()

	for _, want := range []string{"CLAMPED", "700", "10.9.9.9", "NOT demote"} {
		if !strings.Contains(out, want) {
			t.Errorf("FormatIPMonitoringStatus does not surface %q. The IP class reached "+
				"NO surface at all before #6589 — not even journald — so a weight the "+
				"runtime silently bounded to 0 owed no election debt and the group never "+
				"demoted on probe failure:\n%s", want, out)
		}
	}
}

// The over-reach control for the render: a fully in-range configuration must
// produce NO clamp section, or the annotation becomes noise operators learn to
// skip past.
func TestInRangeIPWeightsProduceNoClampSection6589(t *testing.T) {
	m := NewManager(0, 1)
	rg := makeRG(1, false, map[int]int{0: 200})
	rg.IPMonitoring = &config.IPMonitoring{
		GlobalWeight: 100,
		Targets:      []*config.IPMonitorTarget{{Address: "10.9.9.9", Weight: 50}},
	}
	cfg := makeConfig(rg)
	m.UpdateConfig(cfg)
	m.monitor = NewMonitor(m, cfg.RedundancyGroups)

	out := m.FormatIPMonitoringStatus()
	if strings.Contains(out, "CLAMPED") {
		t.Fatalf("an entirely in-range ip-monitoring config produced a CLAMPED section:\n%s", out)
	}
	if got := m.monitor.ClampedIPMonitorWeights(); len(got) != 0 {
		t.Fatalf("in-range weights reported as clamped: %+v", got)
	}
}

// TestEveryMonitorInfoProducerCarriesTheClampFields6589 is the producer-wiring
// guard, and it keys on the SIGNAL REACHING THE STRUCT rather than on how the
// clamp call is spelled.
//
// A first version searched for the `w, _ :=` discard form. That is the shape
// the original defect took, but it is not the property: a producer can capture
// the boolean and still not put it in the struct, and the mutation matrix
// proved it — a cell that dropped the two fields from a live producer left the
// discard-form check green.
func TestEveryMonitorInfoProducerCarriesTheClampFields6589(t *testing.T) {
	t.Parallel()
	for _, f := range []string{"../cli/cli_helpers.go", "../grpcapi/server_cluster.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		flat := strings.Join(strings.Fields(string(src)), "")
		literals := strings.Count(flat, "cluster.InterfaceMonitorInfo{")
		carried := strings.Count(flat, "Clamped:")
		if literals == 0 {
			t.Fatalf("%s builds no cluster.InterfaceMonitorInfo — this guard is stale", f)
		}
		if carried < literals {
			t.Errorf("%s builds %d cluster.InterfaceMonitorInfo literal(s) but sets Clamped "+
				"on only %d. The unset ones render a clamped weight as though the operator "+
				"configured it (#6589).", f, literals, carried)
		}
	}
}
