package config

import (
	"strings"
	"testing"
)

// #8797, second half: `mode packet-based` is now RECORDED, and it still does
// nothing.
//
// The recording fix (PR #8809) made the value reach the compiled config and
// therefore `show forwarding-options`. That is the right fix and it creates a
// new hazard on its own: the operator sets `packet-based`, sees it echoed back,
// and reasonably concludes it took effect. Nothing in the dataplane reads it —
// FamilyInet6Mode has three references in the tree, the compiler that sets it
// and two show renderers that print it, and there is no packet-mode forwarding
// path in userspace-dp or pkg/dataplane at all.
//
// So the advisory is not decoration on top of the recording fix; it is the half
// that keeps the recording from being a stronger lie than the drop was.
//
// WHY WARN RATHER THAN REJECT. `flow-based` is an accurate description of what
// xpf does, so refusing the leaf would fail a commit that is valid Junos and
// that xpf serves correctly. This is the settled shape for accepted-but-
// unenforced knobs here — `allow-dataplane-sleep` sits immediately above it in
// the same function, and `interface-specific` does the same in the firewall.
func TestInet6PacketBasedIsAdvisedUnenforced8797(t *testing.T) {
	compile := func(t *testing.T, mode string) *Config {
		t.Helper()
		text := `forwarding-options { family inet6 { mode ` + mode + `; } }`
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg == nil {
			t.Fatalf("mode %q must COMMIT — rejecting valid Junos is what this "+
				"advisory exists to avoid doing: %v", mode, err)
		}
		return cfg
	}
	advised := func(cfg *Config) bool {
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "family inet6 mode") && strings.Contains(w, "accepted-only") {
				return true
			}
		}
		return false
	}

	pb := compile(t, "packet-based")
	// The value must still be RECORDED — the advisory replaces neither the
	// recording fix nor its cells.
	if pb.ForwardingOptions.FamilyInet6Mode != "packet-based" {
		t.Fatalf("FamilyInet6Mode=%q, want %q — without the recording this cell is "+
			"asserting a warning about a value nobody stored",
			pb.ForwardingOptions.FamilyInet6Mode, "packet-based")
	}
	if !advised(pb) {
		t.Errorf("`mode packet-based` committed with no accepted-only advisory; "+
			"warnings=%v. It is now echoed by `show forwarding-options`, so silence "+
			"here tells the operator it took effect when the dataplane has no "+
			"packet-mode path", pb.Warnings)
	}

	// NEGATIVE CONTROL. `flow-based` is what the dataplane actually does, so it
	// must not warn. Without this the advisory could fire on every value and
	// still satisfy the assertion above — and a warning that fires on correct
	// configuration is how operators learn to skip the warning block.
	fb := compile(t, "flow-based")
	if advised(fb) {
		t.Errorf("`mode flow-based` raised an accepted-only advisory: %v", fb.Warnings)
	}

	// ABSENCE CONTROL: no statement, no advisory.
	tree, _ := NewParser(`forwarding-options { }`).Parse()
	cfg, err := CompileConfig(tree)
	if err != nil || cfg == nil {
		t.Fatalf("empty forwarding-options must compile: %v", err)
	}
	if advised(cfg) {
		t.Errorf("advisory raised with no `mode` statement at all: %v", cfg.Warnings)
	}
}
