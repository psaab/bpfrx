package frr

import (
	"errors"
	"strings"
	"testing"
)

// TestGetRouteDetailJSONPerFamilyFailureSurfaces proves that when the
// IPv6 vtysh dump fails but the IPv4 dump succeeds, GetRouteDetailJSON
// surfaces the failure via a joined error (tagged with the failing
// command) instead of swallowing it and returning the IPv4-only result
// as an authoritative success (#5125). RED against pre-fix code, which
// `continue`d on the per-command error and returned (ipv4Routes, nil):
// an operator would see partial output rendered as "No routes"-clean
// during a transient FRR failure, masking real state.
func TestGetRouteDetailJSONPerFamilyFailureSurfaces(t *testing.T) {
	const ipv4JSON = `{"10.0.0.0/24":[{"prefix":"10.0.0.0/24","protocol":"static",` +
		`"selected":true,"installed":true,"distance":1,"metric":0,` +
		`"nexthops":[{"ip":"10.0.0.1","interfaceName":"ge-0-0-0","active":true,"fib":true}]}]}`

	v6err := errors.New("vtysh: connection refused")
	fake := &fakeExecutor{
		// "show ip route json" resolves from the map (success).
		// "show ipv6 route json" misses the map -> returns vtyshErr.
		vtyshResp: map[string]string{"show ip route json": ipv4JSON},
		vtyshErr:  v6err,
	}
	m := &Manager{exec: fake}

	routes, err := m.GetRouteDetailJSON()

	if err == nil {
		t.Fatalf("GetRouteDetailJSON: got nil error on a failed IPv6 dump; " +
			"a per-family failure must surface (pre-fix code swallowed it and returned success)")
	}
	if !errors.Is(err, v6err) {
		t.Errorf("error %v does not wrap the underlying vtysh failure", err)
	}
	if !strings.Contains(err.Error(), "show ipv6 route json") {
		t.Errorf("error %q lacks the failing-command context", err.Error())
	}
	// The successful IPv4 dump's routes are still returned.
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1 (the successful IPv4 dump must still be returned)", len(routes))
	}
	if routes[0].Prefix != "10.0.0.0/24" {
		t.Errorf("routes[0].Prefix = %q, want 10.0.0.0/24", routes[0].Prefix)
	}
}

// TestGetRouteDetailJSONBothFamiliesOKNoError guards against over-eager
// error reporting: when both vtysh dumps succeed, GetRouteDetailJSON must
// return a nil error so a populated FRR RIB is never flagged as degraded.
func TestGetRouteDetailJSONBothFamiliesOKNoError(t *testing.T) {
	const ipv4JSON = `{"10.0.0.0/24":[{"prefix":"10.0.0.0/24","protocol":"static",` +
		`"selected":true,"installed":true,"nexthops":[{"ip":"10.0.0.1","interfaceName":"ge-0-0-0"}]}]}`
	const ipv6JSON = `{"2001:db8::/32":[{"prefix":"2001:db8::/32","protocol":"static",` +
		`"selected":true,"installed":true,"nexthops":[{"ip":"2001:db8::1","interfaceName":"ge-0-0-1"}]}]}`

	fake := &fakeExecutor{
		vtyshResp: map[string]string{
			"show ip route json":   ipv4JSON,
			"show ipv6 route json": ipv6JSON,
		},
	}
	m := &Manager{exec: fake}

	routes, err := m.GetRouteDetailJSON()
	if err != nil {
		t.Fatalf("GetRouteDetailJSON: got error %v on a fully-successful dump, want nil", err)
	}
	if len(routes) != 2 {
		t.Errorf("got %d routes, want 2 (one per family)", len(routes))
	}
}
