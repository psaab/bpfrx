package format

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7080: #6847 made `classifiers inet-precedence` an ENFORCED classifier and no
// operational command showed any of it.
//
// The failure was not a missing detail. With an inet-precedence classifier as
// the only one configured, `show class-of-service classifier` printed
// "No class-of-service classifiers configured" — a statement that contradicts
// the running config, about the object steering the operator's queueing.
func cosCfg7080() *config.Config {
	return &config.Config{ClassOfService: &config.ClassOfServiceConfig{
		INetPrecedenceClassifierDefs: map[string]*config.CoSINetPrecedenceClassifier{
			"prec-cl": {Name: "prec-cl", Entries: []*config.CoSINetPrecedenceClassifierEntry{
				{ForwardingClass: "voice", LossPriority: "low", Precedences: []uint8{5}},
				{ForwardingClass: "be", LossPriority: "high", Precedences: []uint8{0, 1}},
			}},
		},
	}}
}

func TestINetPrecedenceClassifierIsShown_7080(t *testing.T) {
	out := FormatCoSClassifiers(cosCfg7080(), "", "")
	if strings.Contains(out, "No class-of-service classifiers configured") {
		t.Fatalf("an ENFORCED inet-precedence classifier rendered as unconfigured (#7080):\n%s", out)
	}
	for _, want := range []string{"prec-cl", "inet-precedence", "voice", "be"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
}

// The type filter. Without an arm for it the value could be offered by the
// command tree and still match nothing — the two halves of gap 2 have to move
// together, so both are asserted.
func TestINetPrecedenceTypeFilter_7080(t *testing.T) {
	cfg := cosCfg7080()
	if out := FormatCoSClassifiers(cfg, "", "inet-precedence"); !strings.Contains(out, "prec-cl") {
		t.Errorf("type filter `inet-precedence` matched nothing:\n%s", out)
	}
	// The other polarity: a filter naming a DIFFERENT type must not return it,
	// or "the filter works" would be satisfied by ignoring the filter.
	if out := FormatCoSClassifiers(cfg, "", "dscp"); strings.Contains(out, "prec-cl") {
		t.Errorf("type filter `dscp` returned an inet-precedence classifier:\n%s", out)
	}
}

// Gap 3: the unit's binding, printed next to the two that are NOT steering the
// traffic. The golden covers the empty rendering; this covers a populated one,
// because a line that is always "-" would satisfy the golden and show nothing.
func TestINetPrecedenceBindingIsShownOnTheInterface_7080(t *testing.T) {
	var b strings.Builder
	writeCoSInterfaceHeader(&b, cosInterfaceView{cosUnit: &config.CoSInterfaceUnit{
		DSCPClassifier:           "wan-classifier",
		IEEE8021Classifier:       "wan-pcp",
		INetPrecedenceClassifier: "prec-cl",
	}})
	out := b.String()
	if !strings.Contains(out, "prec-cl") {
		t.Errorf("the inet-precedence binding is missing from the interface summary (#7080):\n%s", out)
	}
	// It must be a NAMED line, not an unlabelled value — the operator has to be
	// able to tell which of the three bindings they are looking at.
	if !strings.Contains(out, "IP precedence classifier:") {
		t.Errorf("the binding is shown without a label naming it:\n%s", out)
	}
}
