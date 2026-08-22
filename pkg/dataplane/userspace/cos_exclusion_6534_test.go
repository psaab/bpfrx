package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6534, CoS family — BUILDER half.
//
// The renderer half lives in pkg/dataplane/userspace/format
// (cos_exclusion_6534_test.go) and cannot be merged into this file: that
// package imports THIS one, so a single test spanning both halves would be an
// import cycle. The two are composed through the shared predicate instead —
// this cell pins "the builder skips an entry IFF
// config.CoSForwardingClassUndefined", the renderer cell pins "the renderer
// annotates an entry IFF the same predicate", and transitivity gives the
// property that matters: the builder skips exactly what the surface reports as
// skipped. Both cells must exist; either alone leaves the other free to drift.

// cosExclusionConfig builds a CoS config whose classifiers, rewrite-rule and
// scheduler-map each carry one entry for a DEFINED forwarding-class and one for
// an UNDEFINED one, so every assertion below has both a positive and a negative
// sample and cannot pass by answering the same way to everything.
func cosExclusionConfig() *config.Config {
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
		Schedulers: map[string]*config.CoSScheduler{
			"s1": {Name: "s1"},
		},
		SchedulerMaps: map[string]*config.CoSSchedulerMap{
			"sm": {Name: "sm", Entries: map[string]*config.CoSSchedulerMapEntry{
				"real":  {ForwardingClass: "real", Scheduler: "s1"},
				"ghost": {ForwardingClass: "ghost", Scheduler: "s1"},
			}},
		},
	}
	return cfg
}

// TestCoSBuilderSkipsExactlyTheUndefinedForwardingClass_6534 pins the builder
// half of the agreement across all four PUBLISHED-and-RENDERED collections.
//
// Reverting any one of the five `config.CoSForwardingClassUndefined` guards in
// cos.go reds this and names which collection kept the entry.
func TestCoSBuilderSkipsExactlyTheUndefinedForwardingClass_6534(t *testing.T) {
	cfg := cosExclusionConfig()
	cos := cfg.ClassOfService
	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatal("buildClassOfServiceSnapshot returned nil for a populated CoS config")
	}

	// Guard the fixture before asserting anything about it: if "ghost" ever
	// became a defined class, every check below would pass over an empty set.
	if !config.CoSForwardingClassUndefined(cos, "ghost") {
		t.Fatal("fixture broken: \"ghost\" must be an UNDEFINED forwarding-class")
	}
	if config.CoSForwardingClassUndefined(cos, "real") {
		t.Fatal("fixture broken: \"real\" must be a DEFINED forwarding-class")
	}

	// Each collection reports the forwarding-classes it actually published.
	published := map[string][]string{}
	for _, c := range snap.DSCPClassifiers {
		for _, e := range c.Entries {
			published["DSCPClassifiers"] = append(published["DSCPClassifiers"], e.ForwardingClass)
		}
	}
	for _, c := range snap.IEEE8021Classifiers {
		for _, e := range c.Entries {
			published["IEEE8021Classifiers"] = append(published["IEEE8021Classifiers"], e.ForwardingClass)
		}
	}
	for _, r := range snap.DSCPRewriteRules {
		for _, e := range r.Entries {
			published["DSCPRewriteRules"] = append(published["DSCPRewriteRules"], e.ForwardingClass)
		}
	}
	for _, m := range snap.SchedulerMaps {
		for _, e := range m.Entries {
			published["SchedulerMaps"] = append(published["SchedulerMaps"], e.ForwardingClass)
		}
	}

	if len(published) != 4 {
		t.Fatalf("expected all four published collections to carry entries, got %d: %v",
			len(published), published)
	}

	for collection, fcs := range published {
		sawReal := false
		for _, fc := range fcs {
			if config.CoSForwardingClassUndefined(cos, fc) {
				t.Errorf("%s published an entry for forwarding-class %q, which is "+
					"UNDEFINED — the dataplane cannot install it and the show surface "+
					"would render it as if it could (#6534)", collection, fc)
			}
			if fc == "real" {
				sawReal = true
			}
		}
		// The other direction: the builder must not have thrown away the
		// healthy entry too. Without this a guard that skipped EVERYTHING
		// would satisfy the loop above.
		if !sawReal {
			t.Errorf("%s dropped the DEFINED forwarding-class %q as well — the skip "+
				"guard is over-broad", collection, "real")
		}
	}
}
