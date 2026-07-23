package daemon

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// TestHostInboundInstallNFTablesUnavailableDistinctReason is the #6387 §12.5
// proof: when a netlink install fails AND the functional capability probe reports
// the kernel nf_tables subsystem UNAVAILABLE, applyHostInboundFilter must
//  1. still fail the commit CLOSED (invariant H7 — never downgrade to fail-open),
//  2. keep wrapping the underlying install failure (errors.Is), and
//  3. tag the error with ErrNFTablesUnavailable so BOTH the operator log AND the
//     Config-Sync (CF) monitor-failure reason (Manager.SetConfigSyncHealth is fed
//     applyErr.Error()) name the TRUE cause distinctly, not a generic apply error.
func TestHostInboundInstallNFTablesUnavailableDistinctReason(t *testing.T) {
	origInst := nftInstaller
	origProbe := nftProbeAvailable
	defer func() { nftInstaller = origInst; nftProbeAvailable = origProbe }()

	install := errors.New("nftables flush xpf_hostinbound: operation not supported")
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return install },
	}
	// The functional probe reports the subsystem is absent (nf_tables not loadable).
	nftProbeAvailable = func() error { return fmt.Errorf("%w: EOPNOTSUPP", xnft.ErrNFTablesUnavailable) }

	d := &Daemon{}
	err := d.applyHostInboundFilter(hostInboundTestConfig())
	if err == nil {
		t.Fatal("an nf_tables-unavailable install failure must STILL fail the commit closed (H7), got nil")
	}
	if !errors.Is(err, install) {
		t.Errorf("returned error must still wrap the underlying install failure, got %v", err)
	}
	if !xnft.IsNFTablesUnavailable(err) {
		t.Errorf("returned error must be tagged ErrNFTablesUnavailable so the CF reason names the true cause, got %v", err)
	}
	// The CF reason is applyErr.Error(); it must name the subsystem distinctly.
	if !strings.Contains(err.Error(), "nf_tables subsystem unavailable") {
		t.Errorf("error text must name nf_tables unavailability (the distinct CF reason), got %q", err.Error())
	}
}

// TestHostInboundInstallGenericFailureNotTagged is the counterpart: a per-ruleset
// install failure on a HEALTHY nf_tables subsystem (the probe reports available)
// must fail closed but must NOT be mis-classified as a subsystem-unavailable
// failure — that distinct reason is reserved for a genuinely absent subsystem.
func TestHostInboundInstallGenericFailureNotTagged(t *testing.T) {
	origInst := nftInstaller
	origProbe := nftProbeAvailable
	defer func() { nftInstaller = origInst; nftProbeAvailable = origProbe }()

	install := errors.New("nftables flush xpf_hostinbound: file exists")
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return install },
	}
	nftProbeAvailable = func() error { return nil } // subsystem healthy

	d := &Daemon{}
	err := d.applyHostInboundFilter(hostInboundTestConfig())
	if err == nil {
		t.Fatal("a per-ruleset install failure must still fail the commit closed, got nil")
	}
	if !errors.Is(err, install) {
		t.Errorf("returned error must wrap the underlying install failure, got %v", err)
	}
	if xnft.IsNFTablesUnavailable(err) {
		t.Errorf("a healthy-subsystem install failure must NOT be tagged nf_tables-unavailable, got %v", err)
	}
}
