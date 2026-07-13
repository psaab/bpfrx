// #5647 (residual, codex-review-182): the LOCAL interactive CLI siblings of
// the remote-CLI clears fixed in #5652 still silently dropped a scoped-looking
// suffix and performed the selector-free global mutation:
//
//	request protocols ospf clear      -> vtysh `clear ip ospf process`
//	request protocols bgp clear       -> vtysh `clear bgp * soft`
//	request security ipsec sa clear   -> strongSwan TerminateAllSAs()
//
// None of these has per-neighbor / per-area / per-SA plumbing, so a trailing
// selector (`... clear neighbor 10.0.0.1`, `... sa clear 42`) was ignored while
// every OSPF adjacency / BGP session / IPsec SA was reset. This mirrors the
// remote-CLI fix (cmd/cli, #5652): reject the scoped-looking suffix BEFORE the
// mutation instead of widening scope silently.
//
// Fail-on-revert design: the handlers run the selector guard BEFORE the
// manager-availability gate. With a zero-value CLI (nil frr/ipsec):
//
//   - A scoped-looking suffix returns the "does not accept a selector"
//     rejection (guard short-circuits before the mutation path).
//   - A bare, unscoped clear falls THROUGH the guard to the nil-manager gate
//     ("... manager not available"), proving the only thing between the parsed
//     command and the global mutation is the manager itself — i.e. a dropped
//     selector would have executed the global reset.
//
// Neutralize the fix (delete the `len(args) > N` guards) and the scoped case
// falls to the same nil-manager gate: it no longer returns "does not accept a
// selector", so TestLocalRequestScopedClearRejected_5647 goes RED.

package cli

import (
	"strings"
	"testing"
)

// A scoped-looking suffix on a global-only local clear must ERROR with the
// selector-rejection reason and must NOT fall through toward the global reset.
func TestLocalRequestScopedClearRejected_5647(t *testing.T) {
	cases := []struct {
		name string
		call func(c *CLI) error
	}{
		{
			name: "ospf clear neighbor",
			call: func(c *CLI) error {
				return c.handleRequestProtocols([]string{"ospf", "clear", "neighbor", "10.0.0.1"})
			},
		},
		{
			name: "bgp clear neighbor",
			call: func(c *CLI) error {
				return c.handleRequestProtocols([]string{"bgp", "clear", "neighbor", "10.0.0.1"})
			},
		},
		{
			name: "ipsec sa clear id",
			call: func(c *CLI) error {
				return c.handleRequestSecurity([]string{"ipsec", "sa", "clear", "42"})
			},
		},
		{
			name: "ipsec sa clear tunnel name",
			call: func(c *CLI) error {
				return c.handleRequestSecurity([]string{"ipsec", "sa", "clear", "tunnel", "gw-a"})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Zero-value CLI: frr and ipsec are nil. The selector guard runs
			// BEFORE the nil-manager gate, so a correct fix returns the
			// selector-rejection error; a reverted fix returns the
			// "... manager not available" error instead.
			c := &CLI{}
			err := tc.call(c)
			if err == nil {
				t.Fatalf("%s: returned nil; expected a rejection error for a "+
					"scoped-looking suffix on a global-only clear", tc.name)
			}
			if !strings.Contains(err.Error(), "does not accept a selector") {
				t.Fatalf("%s: error %q missing the selector-rejection reason — "+
					"a scoped-looking suffix must be refused before the global "+
					"reset, not silently dropped", tc.name, err)
			}
		})
	}
}

// The bare, unscoped clears still proceed past the guard to the manager gate
// (proving the guard is selector-specific, and that an unguarded scoped suffix
// WOULD have reached the global mutation). With nil managers the gate reports
// "... manager not available"; crucially it is NOT the selector rejection.
func TestLocalRequestUnscopedClearProceeds_5647(t *testing.T) {
	cases := []struct {
		name string
		call func(c *CLI) error
	}{
		{
			name: "ospf clear",
			call: func(c *CLI) error { return c.handleRequestProtocols([]string{"ospf", "clear"}) },
		},
		{
			name: "bgp clear",
			call: func(c *CLI) error { return c.handleRequestProtocols([]string{"bgp", "clear"}) },
		},
		{
			name: "ipsec sa clear",
			call: func(c *CLI) error { return c.handleRequestSecurity([]string{"ipsec", "sa", "clear"}) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &CLI{}
			err := tc.call(c)
			if err == nil {
				t.Fatalf("%s: expected the nil-manager gate error, got nil", tc.name)
			}
			if strings.Contains(err.Error(), "does not accept a selector") {
				t.Fatalf("%s: a bare, unscoped clear must NOT be rejected as "+
					"scoped: %v", tc.name, err)
			}
			if !strings.Contains(err.Error(), "manager not available") {
				t.Fatalf("%s: unscoped clear should reach the manager gate, got %v",
					tc.name, err)
			}
		})
	}
}
