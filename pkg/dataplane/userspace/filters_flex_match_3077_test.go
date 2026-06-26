package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3077: `from flexible-match-range` is parsed + compiled into
// config.FirewallFilterTerm.FlexMatch, but the userspace snapshot builder
// previously dropped it — so the byte-offset constraint never reached the sole
// runtime dataplane and the term matched too broadly (fail-open). These tests
// fail on the pre-fix builder (FlexMatch stays nil on the wire) and pass after
// the wire-through fix.

// TestFilterSnapshotFlexMatchSerialized is the FAIL-ON-REVERT guard at the
// snapshot layer. A term carrying flexible-match-range must serialize its
// offset/length/value/mask into the wire snapshot. REVERT (dropping the
// serialization in filters.go) makes FlexMatch go nil and this assert FAIL.
func TestFilterSnapshotFlexMatchSerialized(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {Name: "edge", Terms: []*config.FirewallFilterTerm{{
			Name:      "flex",
			Protocols: []string{"tcp"},
			Action:    "discard",
			FlexMatch: &config.FlexMatchConfig{
				MatchStart: "layer-3",
				ByteOffset: 6,
				BitLength:  16,
				Value:      0x0800,
				Mask:       0xFFFF,
			},
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	fm := snaps[0].Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("flexible-match-range was dropped from the snapshot (#3077 fail-open)")
	}
	if fm.Offset != 6 {
		t.Errorf("flex offset = %d, want 6", fm.Offset)
	}
	// bit-length 16 -> 2 bytes.
	if fm.Length != 2 {
		t.Errorf("flex length = %d, want 2 (16-bit)", fm.Length)
	}
	if fm.Value != 0x0800 {
		t.Errorf("flex value = 0x%04x, want 0x0800", fm.Value)
	}
	if fm.Mask != 0xFFFF {
		t.Errorf("flex mask = 0x%04x, want 0xFFFF", fm.Mask)
	}
}

// TestFilterSnapshotFlexMatchValuePreMasked checks the compiled value is ANDed
// with the mask on the wire (mirrors the legacy dataplane FlexValue =
// Value & Mask lowering), so a snapshot value can never carry bits outside the
// mask.
func TestFilterSnapshotFlexMatchValuePreMasked(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:   "t",
			Action: "discard",
			FlexMatch: &config.FlexMatchConfig{
				MatchStart: "layer-3",
				ByteOffset: 0,
				BitLength:  16,
				Value:      0xFFFF, // bits outside the mask must be stripped
				Mask:       0x00FF,
			},
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	fm := snaps[0].Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("flexible-match-range dropped (#3077)")
	}
	if fm.Value != 0x00FF {
		t.Errorf("flex value = 0x%04x, want 0x00FF (pre-masked)", fm.Value)
	}
	if fm.Mask != 0x00FF {
		t.Errorf("flex mask = 0x%04x, want 0x00FF", fm.Mask)
	}
}

// TestFilterSnapshotNoFlexMatchStaysNil confirms a term WITHOUT
// flexible-match-range carries no flex constraint on the wire (no regression
// for the common case — an absent flex-match means NO constraint, not a
// degenerate always-fail match).
func TestFilterSnapshotNoFlexMatchStaysNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Protocols: []string{"tcp"}, Action: "accept",
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	if snaps[0].Terms[0].FlexMatch != nil {
		t.Errorf("term without flexible-match-range must have nil FlexMatch, got %#v",
			snaps[0].Terms[0].FlexMatch)
	}
}

// TestFilterSnapshotFlexMatchDefaultLength confirms a flex-match with an unset
// bit-length defaults to a 4-byte (32-bit) window, matching the legacy
// dataplane lowering (FlexLength defaults to 4).
func TestFilterSnapshotFlexMatchDefaultLength(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:   "t",
			Action: "discard",
			FlexMatch: &config.FlexMatchConfig{
				MatchStart: "layer-3",
				ByteOffset: 0,
				BitLength:  0, // unset -> default 32-bit
				Value:      0x12345678,
				Mask:       0xFFFFFFFF,
			},
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	fm := snaps[0].Terms[0].FlexMatch
	if fm == nil {
		t.Fatal("flexible-match-range dropped (#3077)")
	}
	if fm.Length != 4 {
		t.Errorf("flex length = %d, want 4 (default 32-bit)", fm.Length)
	}
}
