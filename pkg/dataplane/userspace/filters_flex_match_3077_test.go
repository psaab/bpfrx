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

// TestFilterSnapshotFlexMatchStart is the #3232 wire guard: a `match-start
// layer-4` term carries MatchStart "layer-4" on the wire so the Rust matcher
// reads from the L4 base; layer-3 (the default) maps to "" so the wire stays
// byte-identical to every pre-#3232 term (omitempty). REVERT (drop MatchStart
// from the snapshot builder) makes the layer-4 case carry "" and this FAILS.
func TestFilterSnapshotFlexMatchStart(t *testing.T) {
	cases := []struct {
		start string
		want  string
	}{
		{"layer-3", ""}, // default base — omitted on the wire (byte-identical)
		{"", ""},        // unset also means layer-3
		{"layer-4", "layer-4"},
	}
	for _, tc := range cases {
		cfg := &config.Config{}
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
			"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
				Name:   "t",
				Action: "discard",
				FlexMatch: &config.FlexMatchConfig{
					MatchStart: tc.start,
					ByteOffset: 0,
					BitLength:  16,
					Value:      0x0800,
					Mask:       0xFFFF,
				},
			}}},
		}
		fm := buildFirewallFilterSnapshots(cfg)[0].Terms[0].FlexMatch
		if fm == nil {
			t.Fatalf("match-start %q: flex dropped", tc.start)
		}
		if fm.MatchStart != tc.want {
			t.Errorf("match-start %q: wire MatchStart = %q, want %q", tc.start, fm.MatchStart, tc.want)
		}
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

// TestFilterSnapshotFlexMatchCeilByteLength is the #3203 #02 guard: a
// non-multiple-of-8 bit-length must round UP to whole bytes so the matcher
// reads enough bytes to cover the field. The old BitLength/8 truncation gave 1
// byte for 12 bits (dropping the trailing nibble) and 2 bytes for 24 bits. The
// byte-aligned 8/16/32-bit cases must stay byte-identical to the #3077 result.
// REVERT (BitLength/8 truncation) -> the 12/24-bit rows FAIL.
func TestFilterSnapshotFlexMatchCeilByteLength(t *testing.T) {
	cases := []struct {
		bits    uint8
		wantLen uint8
	}{
		{8, 1},  // byte-aligned, unchanged
		{12, 2}, // non-multiple-of-8 -> ceil to 2 bytes (was truncated to 1)
		{16, 2}, // byte-aligned, unchanged
		{24, 3}, // byte-aligned, unchanged (was truncated to 2 only if non-mult)
		{20, 3}, // non-multiple-of-8 -> ceil to 3 bytes
		{32, 4}, // byte-aligned, unchanged
	}
	for _, tc := range cases {
		cfg := &config.Config{}
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
			"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
				Name:   "t",
				Action: "discard",
				FlexMatch: &config.FlexMatchConfig{
					MatchStart: "layer-3",
					ByteOffset: 0,
					BitLength:  tc.bits,
					Value:      0x1,
					Mask:       0xFFFFFFFF,
				},
			}}},
		}
		snaps := buildFirewallFilterSnapshots(cfg)
		fm := snaps[0].Terms[0].FlexMatch
		if fm == nil {
			t.Fatalf("bit-length %d: flexible-match-range dropped", tc.bits)
		}
		if fm.Length != tc.wantLen {
			t.Errorf("bit-length %d: flex length = %d, want %d", tc.bits, fm.Length, tc.wantLen)
		}
	}
}
