package config

import "testing"

// TestExpandAddressRangeFullDomainWrap_5194 is the #5194 A3-b2-F9 fail-on-revert
// guard. The inclusive count highN-lowN+1 was computed in uint32, so the
// full-domain range 0.0.0.0-255.255.255.255 (highN-lowN == 0xFFFFFFFF) wrapped
// +1 to 0: the `> 256` size gate passed, the generation loop ran zero times, and
// the oversized range committed as an EMPTY pool with a nil error instead of the
// promised size error.
//
// Fail-on-revert: change the count back to uint32 and the full-domain leg goes
// RED (err becomes nil and the pool is empty).
func TestExpandAddressRangeFullDomainWrap_5194(t *testing.T) {
	// Full domain must ERROR (too large), never silently return an empty pool.
	got, err := expandAddressRange("0.0.0.0", "255.255.255.255")
	if err == nil {
		t.Fatalf("full-domain range must error as too large, got nil err and %d addresses", len(got))
	}

	// Boundary: exactly 256 IPs accepted.
	got, err = expandAddressRange("10.0.0.0", "10.0.0.255")
	if err != nil {
		t.Fatalf("256-IP range must be accepted: %v", err)
	}
	if len(got) != 256 {
		t.Fatalf("256-IP range produced %d addresses, want 256", len(got))
	}

	// Boundary: 257 IPs rejected.
	if _, err := expandAddressRange("10.0.0.0", "10.0.1.0"); err == nil {
		t.Fatal("257-IP range must be rejected as too large")
	}
}
