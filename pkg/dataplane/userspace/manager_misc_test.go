package userspace

import (
	"net/netip"
	"testing"
	"time"
)

func TestShouldAttemptRSTSuppression(t *testing.T) {
	now := time.Unix(100, 0)
	addrV4 := []netip.Addr{netip.MustParseAddr("172.16.80.8")}

	if !shouldAttemptRSTSuppression(now, addrV4, nil, nil, nil, time.Time{}, false) {
		t.Fatal("shouldAttemptRSTSuppression() = false on first attempt, want true")
	}
	if shouldAttemptRSTSuppression(now, addrV4, nil, addrV4, nil, now, true) {
		t.Fatal("shouldAttemptRSTSuppression() = true for unchanged successful install, want false")
	}
	if !shouldAttemptRSTSuppression(now, addrV4, nil, nil, nil, now, true) {
		t.Fatal("shouldAttemptRSTSuppression() = false for address change, want true")
	}
	if shouldAttemptRSTSuppression(now, addrV4, nil, addrV4, nil, now.Add(-rstSuppressionRetryBackoff+time.Second), false) {
		t.Fatal("shouldAttemptRSTSuppression() = true before failure retry backoff, want false")
	}
	if !shouldAttemptRSTSuppression(now, addrV4, nil, addrV4, nil, now.Add(-rstSuppressionRetryBackoff), false) {
		t.Fatal("shouldAttemptRSTSuppression() = false at failure retry backoff, want true")
	}
}

func TestMacStringSuppressesZeroAndFormatsValue(t *testing.T) {
	if got := macString([]byte{0, 0, 0, 0, 0, 0}); got != "" {
		t.Fatalf("zero MAC = %q, want empty", got)
	}
	if got := macString([]byte{0x02, 0xbf, 0x72, 0x01, 0x01, 0x01}); got != "02:bf:72:01:01:01" {
		t.Fatalf("formatted MAC = %q", got)
	}
}
