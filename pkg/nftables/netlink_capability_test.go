package nftables

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

// TestProbeNFTablesAvailableLive checks the functional probe reports the kernel
// nf_tables subsystem as usable in a private netns (where it is reachable via
// netlink). It SKIPs without CAP_NET_ADMIN.
func TestProbeNFTablesAvailableLive(t *testing.T) {
	enterPrivateNetns(t)
	if err := ProbeNFTablesAvailable(); err != nil {
		t.Fatalf("ProbeNFTablesAvailable reported unavailable in a kernel that has nf_tables: %v", err)
	}
}

// TestIsNFTablesUnavailable is a pure-unit check that the distinct
// subsystem-absent signal is recognized (and a generic error is not), so PR-3
// can branch the CF monitor-failure reason on it.
func TestIsNFTablesUnavailable(t *testing.T) {
	if !IsNFTablesUnavailable(fmt.Errorf("wrap: %w", ErrNFTablesUnavailable)) {
		t.Error("wrapped ErrNFTablesUnavailable not recognized")
	}
	if !IsNFTablesUnavailable(fmt.Errorf("%w: %v", ErrNFTablesUnavailable, unix.EOPNOTSUPP)) {
		t.Error("ErrNFTablesUnavailable with errno detail not recognized")
	}
	if IsNFTablesUnavailable(errors.New("some other error")) {
		t.Error("generic error wrongly classified as nf_tables-unavailable")
	}
	if IsNFTablesUnavailable(nil) {
		t.Error("nil wrongly classified as nf_tables-unavailable")
	}
}

// TestSubsystemUnavailableClassification checks the errno classifier used by the
// probe recognizes the subsystem-absent errnos and nothing else.
func TestSubsystemUnavailableClassification(t *testing.T) {
	for _, e := range []error{unix.EOPNOTSUPP, unix.EAFNOSUPPORT, unix.EPROTONOSUPPORT} {
		if !isSubsystemUnavailable(e) {
			t.Errorf("errno %v should classify as subsystem-unavailable", e)
		}
	}
	for _, e := range []error{unix.EPERM, unix.ENOENT, unix.EINVAL} {
		if isSubsystemUnavailable(e) {
			t.Errorf("errno %v should NOT classify as subsystem-unavailable", e)
		}
	}
}
