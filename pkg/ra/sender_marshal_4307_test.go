package ra

// Regression test for #4307 (fable-review-167 I-2): the RFC 4861 §4.2
// Reachable Time and Retrans Timer header fields were never modeled or set,
// so every RA went on the wire with both = 0 ("unspecified") and hosts could
// not be tuned via RA. The sender now copies the configured milliseconds onto
// the ndp.RouterAdvertisement, which marshals them as ms (Duration /
// time.Millisecond -> uint32).
//
// RED-on-revert: drop the ReachableTime/RetransmitTimer assignments in
// buildRA (or the ReachableTime/RetransTimer config fields) and the round-trip
// reads back 0 for both — the silent-drop this issue fixes.

import (
	"net"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildRA_4307_ReachableAndRetransOnWire(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:     "trust0",
			ReachableTime: 30000, // ms
			RetransTimer:  1000,  // ms
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()
	if ra.ReachableTime != 30000*time.Millisecond {
		t.Errorf("ReachableTime = %v, want 30000ms", ra.ReachableTime)
	}
	if ra.RetransmitTimer != 1000*time.Millisecond {
		t.Errorf("RetransmitTimer = %v, want 1000ms", ra.RetransmitTimer)
	}

	// Marshal + re-parse to confirm the values survive the wire encoding
	// (ndp encodes them as 32-bit millisecond fields).
	raw, err := ndp.MarshalMessage(ra)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	msg, err := ndp.ParseMessage(raw)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	got, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		t.Fatalf("parsed message is %T, want *ndp.RouterAdvertisement", msg)
	}
	if got.ReachableTime != 30000*time.Millisecond {
		t.Errorf("wire ReachableTime = %v, want 30000ms", got.ReachableTime)
	}
	if got.RetransmitTimer != 1000*time.Millisecond {
		t.Errorf("wire RetransmitTimer = %v, want 1000ms", got.RetransmitTimer)
	}
}

// A config that omits both leaves keeps the pre-#4307 "unspecified" (0) wire
// behavior — the fix must not perturb the default.
func TestBuildRA_4307_UnsetStaysZero(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{Interface: "trust0"},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}
	ra := s.buildRA()
	if ra.ReachableTime != 0 {
		t.Errorf("ReachableTime = %v, want 0 (unspecified)", ra.ReachableTime)
	}
	if ra.RetransmitTimer != 0 {
		t.Errorf("RetransmitTimer = %v, want 0 (unspecified)", ra.RetransmitTimer)
	}
}
