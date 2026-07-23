package daemon

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestBuildSNMPIfDataSurfacesNetlinkFailure is the #5523 C179-123 guard: when
// the netlink link enumeration fails, buildSNMPIfData must LOG the failure
// rather than silently returning an empty slice that is indistinguishable from
// a healthy 0-interface box. The SetIfDataFn callback contract
// (func() []snmp.IfData) has no error channel, so a silent empty return let an
// SNMP manager read the firewall as having no interfaces while the poll still
// looked successful.
//
// FAIL-ON-REVERT: dropping the slog.Warn (restoring the bare `return nil` on the
// netlink error) makes the failure invisible — the warning-count assertion goes
// RED while the return-value assertion stays green.
func TestBuildSNMPIfDataSurfacesNetlinkFailure(t *testing.T) {
	prevLister := snmpLinkLister
	snmpLinkLister = func() ([]netlink.Link, error) {
		return nil, errors.New("injected: netlink RTM_GETLINK dump failed")
	}
	defer func() { snmpLinkLister = prevLister }()

	rec := &recordingSlogHandler{level: slog.LevelWarn}
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(rec))
	defer slog.SetDefault(prevLogger)

	got := buildSNMPIfData()
	if got != nil {
		t.Fatalf("a failed netlink read must return no interface data, got %d entries", len(got))
	}
	const want = "SNMP ifTable read failed; reporting empty interface table"
	if n := rec.count(want); n != 1 {
		t.Fatalf("a netlink-failure ifTable read must log %q exactly once so the "+
			"empty table is diagnosable and distinguishable from a genuine "+
			"no-interface box (C179-123); got %d", want, n)
	}
}
