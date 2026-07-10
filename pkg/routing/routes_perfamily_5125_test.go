package routing

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// perFamilyFailLister is a routeLister double that succeeds the IPv4 dump
// (returning one static route) and fails the IPv6 dump with a configured
// error, on both the main-table (RouteList) and per-table
// (RouteListFiltered) read paths. It models a transient per-family
// netlink failure so the #5125 tests can assert the failure is surfaced
// rather than swallowed into a partial "no routes" success.
type perFamilyFailLister struct {
	v6err error
}

func (f *perFamilyFailLister) v4Route() netlink.Route {
	_, dst, _ := net.ParseCIDR("10.20.0.0/16")
	return netlink.Route{
		Dst:      dst,
		Gw:       net.ParseIP("10.20.0.1"),
		Protocol: netlink.RouteProtocol(unix.RTPROT_STATIC),
		Priority: 5,
	}
}

func (f *perFamilyFailLister) RouteListFiltered(family int, _ *netlink.Route, _ uint64) ([]netlink.Route, error) {
	if family == netlink.FAMILY_V6 {
		return nil, f.v6err
	}
	return []netlink.Route{f.v4Route()}, nil
}

func (f *perFamilyFailLister) RouteList(_ netlink.Link, family int) ([]netlink.Route, error) {
	if family == netlink.FAMILY_V6 {
		return nil, f.v6err
	}
	return []netlink.Route{f.v4Route()}, nil
}

func (f *perFamilyFailLister) LinkByIndex(index int) (netlink.Link, error) {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-0", Index: index}}, nil
}

func (f *perFamilyFailLister) LinkByName(string) (netlink.Link, error) {
	return nil, errors.New("LinkByName not implemented in perFamilyFailLister")
}

// TestGetRoutesPerFamilyFailureSurfaces proves GetRoutes surfaces a
// per-family netlink failure instead of swallowing it (#5125). Against
// pre-fix code (which `continue`d on the per-family error and returned
// `entries, nil`) this goes RED on the nil-error assertion: a failed
// IPv6 dump alongside a successful IPv4 dump was reported as an
// authoritative success, indistinguishable from a genuinely empty table.
func TestGetRoutesPerFamilyFailureSurfaces(t *testing.T) {
	v6err := errors.New("netlink: RTM_GETROUTE inet6 dump failed")
	rr := &routeReader{ops: &perFamilyFailLister{v6err: v6err}}

	entries, err := rr.GetRoutes()

	if err == nil {
		t.Fatalf("GetRoutes: got nil error on a partial IPv6 dump failure; " +
			"a per-family failure must surface (pre-fix code swallowed it and returned success)")
	}
	if !errors.Is(err, v6err) {
		t.Errorf("GetRoutes error %v does not wrap the underlying netlink failure", err)
	}
	if !strings.Contains(err.Error(), "inet6") {
		t.Errorf("GetRoutes error %q lacks the failing-family (inet6) context", err.Error())
	}
	// The successfully-dumped IPv4 family's entries must still be
	// returned so callers can render what is available.
	if len(entries) != 1 {
		t.Errorf("GetRoutes: got %d entries, want 1 (the successful IPv4 dump must still be returned)", len(entries))
	}
}

// TestGetRoutesForTablePerFamilyFailureSurfaces is the per-table analogue
// of the above: a per-family failure on a specific table must surface,
// tagged with the table id, and still return the successful family's
// entries.
func TestGetRoutesForTablePerFamilyFailureSurfaces(t *testing.T) {
	v6err := errors.New("netlink: RTM_GETROUTE inet6 table dump failed")
	rr := &routeReader{ops: &perFamilyFailLister{v6err: v6err}}

	entries, err := rr.GetRoutesForTable(100)

	if err == nil {
		t.Fatalf("GetRoutesForTable: got nil error on a partial IPv6 dump failure; must surface")
	}
	if !errors.Is(err, v6err) {
		t.Errorf("GetRoutesForTable error %v does not wrap the underlying netlink failure", err)
	}
	if !strings.Contains(err.Error(), "table 100") {
		t.Errorf("GetRoutesForTable error %q lacks the table context", err.Error())
	}
	if len(entries) != 1 {
		t.Errorf("GetRoutesForTable: got %d entries, want 1", len(entries))
	}
}

// TestGetRoutesBothFamiliesOKNoError guards against over-eager error
// reporting: when both family dumps succeed, GetRoutes must return a nil
// error so a genuinely populated table is never flagged as degraded.
func TestGetRoutesBothFamiliesOKNoError(t *testing.T) {
	rr := &routeReader{ops: &perFamilyFailLister{v6err: nil}}

	entries, err := rr.GetRoutes()
	if err != nil {
		t.Fatalf("GetRoutes: got error %v on a fully-successful dump, want nil", err)
	}
	if len(entries) != 1 {
		t.Errorf("GetRoutes: got %d entries, want 1", len(entries))
	}
}
