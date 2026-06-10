package config

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// #1828 Option C: compile guard for the WAN-SQM cookbook fixture
// (test/incus/sqm-cookbook-config.set, the docs/cos-wan-sqm.md
// validation recipe). The fixture is applied to the loss userspace
// cluster by the wave-end smoke; this guard keeps it from drifting
// into something the compiler rejects (or silently compiles to
// nothing — the #1796/#1797 flat-set-compiles-EMPTY hazard class)
// without anyone noticing before a smoke slot is burned.
//
// The fixture's `set` lines are parsed on the production flat-set
// path (ParseSetCommand + SetPath, never NewParser, per the testing
// gotcha in CLAUDE.md) and compiled standalone — a bare
// class-of-service stanza is exactly what the recipe loads as one
// atomic candidate on the cluster.

const sqmCookbookFixturePath = "../../test/incus/sqm-cookbook-config.set"

// loadFixtureSetLines reads the `set ...` lines from a test/incus
// fixture, mirroring the harness convention (apply-cos-config.sh and
// the cookbook snippet both strip to `^set ` before `load merge`).
func loadFixtureSetLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture %s: %v", path, err)
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if strings.HasPrefix(line, "set ") {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	if len(lines) == 0 {
		t.Fatalf("fixture %s contains no `set` lines", path)
	}
	return lines
}

// TestSQMCookbookFixtureCompiles pins the cookbook recipe end-to-end
// at the typed-config layer: the bare shaping-rate line must compile
// cleanly and produce exactly the state the recipe's claims depend on
// — a positive root shaping rate on reth0 unit 80 with NO
// scheduler-map (the synthetic default best-effort queue and lazy
// MQFQ promotion only exist on that shape).
func TestSQMCookbookFixtureCompiles(t *testing.T) {
	lines := loadFixtureSetLines(t, sqmCookbookFixturePath)

	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig(sqm cookbook fixture): %v", err)
	}
	for _, w := range cfg.Warnings {
		t.Errorf("unexpected compile warning: %s", w)
	}

	iface := cfg.ClassOfService.Interfaces["reth0"]
	if iface == nil {
		t.Fatalf("fixture compiled EMPTY: class-of-service interfaces reth0 missing (flat-set compile gap?)")
	}
	unit := iface.Units[80]
	if unit == nil {
		t.Fatalf("reth0 unit 80 missing from compiled CoS config")
	}
	// `shaping-rate 3g` = 3e9 bits/s = 375,000,000 bytes/s. A positive
	// value is the contributes_usable_cos_state admission gate; the
	// exact value pins the fixture/cookbook agreement.
	const wantShapingBytes = 3_000_000_000 / 8
	if unit.ShapingRateBytes != wantShapingBytes {
		t.Fatalf("reth0 unit 80 ShapingRateBytes = %d, want %d (shaping-rate 3g)",
			unit.ShapingRateBytes, wantShapingBytes)
	}
	// The recipe is the BARE one-knob form: no scheduler-map, so the
	// engine materializes the synthetic default best-effort queue. A
	// scheduler-map sneaking into the fixture would silently test a
	// different engine path than the cookbook documents.
	if unit.SchedulerMap != "" {
		t.Fatalf("fixture must stay bare (no scheduler-map); got scheduler-map %q", unit.SchedulerMap)
	}
	if len(cfg.ClassOfService.Schedulers) != 0 || len(cfg.ClassOfService.SchedulerMaps) != 0 {
		t.Fatalf("fixture must not define schedulers/scheduler-maps (bare recipe); got %d schedulers, %d maps",
			len(cfg.ClassOfService.Schedulers), len(cfg.ClassOfService.SchedulerMaps))
	}
}
