package config

import (
	"strings"
	"testing"
)

// #1892: retired DPDK-era `system dataplane` knobs (cores, memory,
// socket-mem, rx-mode, ports) lost their consumer in the #1525 DPDK
// retirement. They must keep PARSING (stored-config compatibility —
// never break an existing stanza) but each present knob must surface a
// commit warning so the operator learns the stanza is inert.

func retiredKnobWarning(cfg *Config, knob string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "system dataplane "+knob+": retired DPDK-era knob") {
			return true
		}
	}
	return false
}

func TestCompileWarnsOnRetiredDataplaneKnobs(t *testing.T) {
	tree := buildTree(t, []string{
		"set system dataplane-type userspace",
		"set system dataplane cores 4",
		"set system dataplane memory 2048",
		"set system dataplane socket-mem 1024,1024",
		"set system dataplane rx-mode idle-threshold 100",
		"set system dataplane ports p0 interface ge-0-0-1",
		// A live knob alongside, to prove the retired cases don't eat it.
		"set system dataplane workers 4",
	})

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig with retired knobs must not error (back-compat): %v", err)
	}
	for _, knob := range []string{"cores", "memory", "socket-mem", "rx-mode", "ports"} {
		if !retiredKnobWarning(cfg, knob) {
			t.Errorf("missing retired-knob warning for %q; warnings: %v", knob, cfg.Warnings)
		}
	}
	if cfg.System.UserspaceDataplane == nil || cfg.System.UserspaceDataplane.Workers != 4 {
		t.Fatalf("live workers knob lost: %+v", cfg.System.UserspaceDataplane)
	}
}

func TestCompileNoRetiredKnobWarningWhenAbsent(t *testing.T) {
	tree := buildTree(t, []string{
		"set system dataplane-type userspace",
		"set system dataplane workers 4",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "retired DPDK-era knob") {
			t.Fatalf("unexpected retired-knob warning: %v", cfg.Warnings)
		}
	}
}

func TestCompileLenientAlsoWarnsOnRetiredDataplaneKnobs(t *testing.T) {
	tree := buildTree(t, []string{
		"set system dataplane-type userspace",
		"set system dataplane socket-mem 512",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if !retiredKnobWarning(cfg, "socket-mem") {
		t.Fatalf("lenient path missing socket-mem warning; warnings: %v", cfg.Warnings)
	}
}
