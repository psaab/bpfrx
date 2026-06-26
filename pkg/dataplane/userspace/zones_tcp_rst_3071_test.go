package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildZoneSnapshotsCarriesTCPRst verifies the #3071 fix: the per-zone
// Junos `tcp-rst` knob (ZoneConfig.TCPRst) is carried into the ZoneSnapshot
// wire struct (TCPRst -> json "tcp_rst") so the userspace dataplane can honor
// it. Before #3071 buildZoneSnapshots dropped the flag entirely, leaving the
// knob inert.
func TestBuildZoneSnapshotsCarriesTCPRst(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust", TCPRst: true},
				"untrust": {Name: "untrust", TCPRst: false},
			},
		},
	}

	snaps := buildZoneSnapshots(cfg)
	if len(snaps) != 2 {
		t.Fatalf("expected 2 zone snapshots, got %d", len(snaps))
	}

	byName := make(map[string]ZoneSnapshot, len(snaps))
	for _, z := range snaps {
		byName[z.Name] = z
	}

	if !byName["trust"].TCPRst {
		t.Fatalf("trust zone tcp-rst must be carried as true, got %+v", byName["trust"])
	}
	if byName["untrust"].TCPRst {
		t.Fatalf("untrust zone tcp-rst must stay false, got %+v", byName["untrust"])
	}
}

// TestZoneSnapshotTCPRstWireField pins the JSON wire contract shared with the
// Rust ZoneSnapshot (#1961 cross-language discipline): the field serializes to
// the byte-identical key "tcp_rst", true only when set, and omitted when false
// (omitempty keeps an old Rust helper at the pre-#3071 silent-drop default).
func TestZoneSnapshotTCPRstWireField(t *testing.T) {
	on, err := json.Marshal(ZoneSnapshot{Name: "trust", ID: 1, TCPRst: true})
	if err != nil {
		t.Fatalf("marshal tcp-rst zone: %v", err)
	}
	if !strings.Contains(string(on), `"tcp_rst":true`) {
		t.Fatalf("expected tcp_rst:true in wire JSON, got %s", on)
	}

	off, err := json.Marshal(ZoneSnapshot{Name: "untrust", ID: 2})
	if err != nil {
		t.Fatalf("marshal non-tcp-rst zone: %v", err)
	}
	if strings.Contains(string(off), "tcp_rst") {
		t.Fatalf("tcp_rst must be omitted when false, got %s", off)
	}

	// Round-trip back through ZoneSnapshot.
	var rt ZoneSnapshot
	if err := json.Unmarshal(on, &rt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !rt.TCPRst {
		t.Fatalf("round-trip lost tcp_rst, got %+v", rt)
	}
}
