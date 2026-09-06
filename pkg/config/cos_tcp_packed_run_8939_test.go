package config

import (
	"reflect"
	"testing"
)

// #8939 at `class-of-service traffic-control-profiles`: a packed run set only
// its FIRST option.
//
//	traffic-control-profiles TCP delay-buffer-rate 100000 guaranteed-rate 200000 scheduler-map M
//	  -> delay-buffer-rate applied; guaranteed-rate and scheduler-map DROPPED
//
// The block asks inst.node.FindChild(...) once per option, and the packed
// spelling is ONE child node carrying all three on its Keys.
//
// A shaper missing its guaranteed-rate or its scheduler-map does not FAIL — it
// shapes differently from what the operator wrote, which is the quiet direction:
// traffic still flows, at the wrong rate, under the wrong scheduler.
func TestCoSTrafficControlProfilePackedRun8939(t *testing.T) {
	build := func(t *testing.T, lines ...string) *Config {
		t.Helper()
		tr := &ConfigTree{}
		for _, l := range lines {
			p, err := ParseSetCommand(l)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", l, err)
			}
			if err := tr.SetPath(p); err != nil {
				t.Fatalf("SetPath: %v", err)
			}
		}
		c, err := CompileConfig(tr)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return c
	}
	pre := []string{
		"set class-of-service schedulers S transmit-rate 1000000",
		"set class-of-service scheduler-maps M forwarding-class best-effort scheduler S",
	}

	split := build(t, append(append([]string{}, pre...),
		"set class-of-service traffic-control-profiles TCP delay-buffer-rate 100000",
		"set class-of-service traffic-control-profiles TCP guaranteed-rate 200000",
		"set class-of-service traffic-control-profiles TCP scheduler-map M")...)
	// REFERENCE ARM: all three must land in the split spelling.
	ref := split.ClassOfService.TrafficControlProfiles["TCP"]
	if ref == nil || ref.DelayBufferRateBytes == 0 || ref.GuaranteedRateBytes == 0 || ref.SchedulerMap == "" {
		t.Fatalf("the SPLIT control did not set all three: %+v — the comparison would prove nothing", ref)
	}

	packed := build(t, append(append([]string{}, pre...),
		"set class-of-service traffic-control-profiles TCP delay-buffer-rate 100000 guaranteed-rate 200000 scheduler-map M")...)
	if !reflect.DeepEqual(packed, split) {
		got := packed.ClassOfService.TrafficControlProfiles["TCP"]
		t.Errorf("packed %+v\nsplit  %+v", got, ref)
	}

	// NARROWNESS: one option alone must set only that one. A fix that filled
	// every field whenever the profile appeared would satisfy the comparison
	// and shape traffic the operator never configured.
	only := build(t, append(append([]string{}, pre...),
		"set class-of-service traffic-control-profiles TCP delay-buffer-rate 100000")...)
	o := only.ClassOfService.TrafficControlProfiles["TCP"]
	if o == nil || o.DelayBufferRateBytes == 0 {
		t.Fatalf("the single-option spelling lost its own option: %+v", o)
	}
	if o.GuaranteedRateBytes != 0 || o.SchedulerMap != "" {
		t.Errorf("`delay-buffer-rate` alone also set guaranteed-rate=%d scheduler-map=%q",
			o.GuaranteedRateBytes, o.SchedulerMap)
	}
}
