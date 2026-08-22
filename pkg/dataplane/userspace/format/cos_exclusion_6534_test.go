package format

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6534, CoS family — RENDERER half.
//
// The builder half is pkg/dataplane/userspace/cos_exclusion_6534_test.go. It
// cannot live in the same file: this package imports that one, so a single
// spanning test would be an import cycle. The two compose through the shared
// predicate — the builder cell pins "skips IFF config.CoSForwardingClassUndefined",
// this one pins "annotates IFF the same predicate" — and transitivity gives the
// property: the surface reports as not-installed exactly what the dataplane
// does not install.

func cosRenderExclusionConfig() *config.Config {
	cfg := &config.Config{}
	cfg.ClassOfService = &config.ClassOfServiceConfig{
		ForwardingClasses: map[string]*config.CoSForwardingClass{
			"real": {Name: "real", Queue: 3},
		},
		DSCPClassifiers: map[string]*config.CoSDSCPClassifier{
			"cls": {Name: "cls", Entries: []*config.CoSDSCPClassifierEntry{
				{ForwardingClass: "real", DSCPValues: []uint8{10}},
				{ForwardingClass: "ghost", DSCPValues: []uint8{20}},
			}},
		},
		IEEE8021Classifiers: map[string]*config.CoSIEEE8021Classifier{
			"icls": {Name: "icls", Entries: []*config.CoSIEEE8021ClassifierEntry{
				{ForwardingClass: "real", CodePoints: []uint8{1}},
				{ForwardingClass: "ghost", CodePoints: []uint8{2}},
			}},
		},
		DSCPRewriteRules: map[string]*config.CoSDSCPRewriteRule{
			"rw": {Name: "rw", Entries: []*config.CoSDSCPRewriteRuleEntry{
				{ForwardingClass: "real", DSCPValue: 46},
				{ForwardingClass: "ghost", DSCPValue: 26},
			}},
		},
		Schedulers: map[string]*config.CoSScheduler{"s1": {Name: "s1"}},
		SchedulerMaps: map[string]*config.CoSSchedulerMap{
			"sm": {Name: "sm", Entries: map[string]*config.CoSSchedulerMapEntry{
				"real":  {ForwardingClass: "real", Scheduler: "s1"},
				"ghost": {ForwardingClass: "ghost", Scheduler: "s1"},
			}},
		},
	}
	return cfg
}

// cosHealthyConfig is cosRenderExclusionConfig with "ghost" DEFINED, so every
// entry installs. Used as the anti-false-positive control.
func cosHealthyConfig() *config.Config {
	cfg := cosRenderExclusionConfig()
	cfg.ClassOfService.ForwardingClasses["ghost"] = &config.CoSForwardingClass{Name: "ghost", Queue: 5}
	return cfg
}

// TestCoSRenderersAnnotateSkippedEntries_6534: each of the three renderers that
// displays a collection the builder filters must say so.
//
// Reverting a renderer's noteUninstalledCoSEntries call reds the matching
// subtest and names which surface went back to lying.
func TestCoSRenderersAnnotateSkippedEntries_6534(t *testing.T) {
	cfg := cosRenderExclusionConfig()

	// Pin the fixture to ground truth first: if "ghost" ever became defined,
	// every assertion below would pass over an empty set — a vacuous green.
	if !config.CoSForwardingClassUndefined(cfg.ClassOfService, "ghost") {
		t.Fatal("fixture broken: \"ghost\" must be UNDEFINED for this cell to bind anything")
	}

	cases := []struct {
		surface string
		out     string
	}{
		{"show class-of-service classifiers", FormatCoSClassifiers(cfg, "", "")},
		{"show class-of-service rewrite-rules", FormatCoSRewriteRules(cfg, "", "")},
		{"show class-of-service scheduler-map", FormatCoSSchedulerMaps(cfg, "")},
	}
	for _, c := range cases {
		t.Run(c.surface, func(t *testing.T) {
			if !strings.Contains(c.out, "NOT INSTALLED") {
				t.Fatalf("%s renders an entry for the UNDEFINED forwarding-class "+
					"\"ghost\" with no #6534 annotation — the builder skips that entry, "+
					"so the operator is shown classification/shaping that is not "+
					"happening.\n--- output ---\n%s", c.surface, c.out)
			}
			if !strings.Contains(c.out, "ghost") {
				t.Fatalf("%s annotated something, but not the offending "+
					"forwarding-class \"ghost\" — the annotation must name WHICH "+
					"entry is not installed.\n--- output ---\n%s", c.surface, c.out)
			}
		})
	}
}

// TestCoSHealthyConfigRendersUnannotated_6534 is the anti-false-positive half.
// An annotation that fired unconditionally would satisfy every assertion above,
// so pin the other direction: with every forwarding-class defined, no surface
// may claim anything is uninstalled.
func TestCoSHealthyConfigRendersUnannotated_6534(t *testing.T) {
	cfg := cosHealthyConfig()
	if config.CoSForwardingClassUndefined(cfg.ClassOfService, "ghost") {
		t.Fatal("fixture broken: the healthy control must define every forwarding-class")
	}
	for _, c := range []struct {
		surface string
		out     string
	}{
		{"classifiers", FormatCoSClassifiers(cfg, "", "")},
		{"rewrite-rules", FormatCoSRewriteRules(cfg, "", "")},
		{"scheduler-map", FormatCoSSchedulerMaps(cfg, "")},
	} {
		if strings.Contains(c.out, "NOT INSTALLED") {
			t.Errorf("%s annotated a fully healthy CoS config — crying wolf on entries "+
				"the dataplane installs.\n--- output ---\n%s", c.surface, c.out)
		}
	}
}

// TestCoSIEEE8021RewriteRuleIsNotFalselyAnnotated_6534 guards the one place the
// annotation must NOT reach.
//
// The builder publishes and filters DSCPRewriteRules, but never publishes
// IEEE8021RewriteRules at all — those are unenforced WHOLESALE, not per-entry.
// Annotating an ieee-802.1 entry as a skipped-entry would assert a mechanism
// that does not exist and would misdescribe a bigger gap as a smaller one.
func TestCoSIEEE8021RewriteRuleIsNotFalselyAnnotated_6534(t *testing.T) {
	cfg := &config.Config{}
	cfg.ClassOfService = &config.ClassOfServiceConfig{
		ForwardingClasses: map[string]*config.CoSForwardingClass{"real": {Name: "real", Queue: 3}},
		IEEE8021RewriteRules: map[string]*config.CoSIEEE8021RewriteRule{
			"irw": {Name: "irw", Entries: []*config.CoSIEEE8021RewriteRuleEntry{
				{ForwardingClass: "ghost", PCPValue: 4},
			}},
		},
	}
	out := FormatCoSRewriteRules(cfg, "", "ieee-802.1")
	if strings.Contains(out, "NOT INSTALLED") {
		t.Fatalf("the ieee-802.1 rewrite-rule renderer claimed a per-entry skip, but "+
			"the builder never publishes IEEE8021RewriteRules at all — this "+
			"misreports a wholesale gap as an entry-level one.\n--- output ---\n%s", out)
	}
}
