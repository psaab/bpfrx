package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
)

// seedDUIDs writes placeholder DHCPv6 DUID state files for the named interfaces
// into a manager's state directory. A subsequent clear is then observed purely
// by which files survive: ClearDUID removes exactly one, ClearAllDUIDs removes
// every file carrying the "dhcpv6-duid-" prefix.
func seedDUIDs(t *testing.T, dir string, ifaces ...string) {
	t.Helper()
	for _, ifn := range ifaces {
		p := filepath.Join(dir, "dhcpv6-duid-"+ifn)
		if err := os.WriteFile(p, []byte("duid"), 0o644); err != nil {
			t.Fatalf("seed DUID %s: %v", ifn, err)
		}
	}
}

func duidPresent(t *testing.T, dir, ifn string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, "dhcpv6-duid-"+ifn))
	return err == nil
}

// TestHandleClearDHCP_MalformedSelectorGuard_5896 locks the in-process CLI's
// `clear dhcp client-identifier` handler to the SAME malformed-selector guard
// the remote CLI already enforces (#4883-E, cmd/cli/clear.go handleClearDHCP).
//
// The bug (#5896): the in-process handler recognized only a fully-formed
// `interface <name>` selector and let EVERY other shape fall through to the
// unscoped ClearAllDUIDs(), so `clear dhcp client-identifier interface` (no
// name), `... interfce ge-0-0-0` (misspelled selector), or a stray trailing
// token wiped every DHCPv6 DUID on the box instead of the one the operator
// scoped. A bare `clear dhcp client-identifier` (no selector) is the ONLY
// intentional clear-all.
//
// Fail-on-revert: delete the guard and the three malformed cases fall back to
// clear-all (files vanish, err is nil) — flipping wantErr AND the survival
// assertions red. The stray-token case additionally regresses to a scoped
// clear of ge-0-0-0 under the old `len(args) >= 3` branch, which the wantA
// assertion catches.
func TestHandleClearDHCP_MalformedSelectorGuard_5896(t *testing.T) {
	const (
		ifA = "ge-0-0-0"
		ifB = "ge-0-0-1"
	)
	cases := []struct {
		name    string
		args    []string
		wantErr bool
		wantA   bool // ge-0-0-0 DUID file survives the call
		wantB   bool // ge-0-0-1 DUID file survives the call
	}{
		{
			name:    "bare client-identifier is the intentional clear-all",
			args:    []string{"client-identifier"},
			wantErr: false,
			wantA:   false,
			wantB:   false,
		},
		{
			name:    "well-formed scoped clears only that interface",
			args:    []string{"client-identifier", "interface", ifA},
			wantErr: false,
			wantA:   false,
			wantB:   true,
		},
		{
			name:    "interface without a name is rejected, nothing cleared",
			args:    []string{"client-identifier", "interface"},
			wantErr: true,
			wantA:   true,
			wantB:   true,
		},
		{
			name:    "unknown selector token is rejected, nothing cleared",
			args:    []string{"client-identifier", "interfce", ifA},
			wantErr: true,
			wantA:   true,
			wantB:   true,
		},
		{
			name:    "stray trailing token is rejected, nothing cleared",
			args:    []string{"client-identifier", "interface", ifA, "extra"},
			wantErr: true,
			wantA:   true,
			wantB:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mgr, err := dhcp.New(dir, nil, nil)
			if err != nil {
				t.Fatalf("dhcp.New: %v", err)
			}
			seedDUIDs(t, dir, ifA, ifB)

			c := &CLI{dhcp: mgr}
			err = c.handleClearDHCP(tc.args)

			if tc.wantErr && err == nil {
				t.Fatalf("args %v: want error (malformed selector must not silently clear), got nil", tc.args)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("args %v: unexpected error: %v", tc.args, err)
			}
			if got := duidPresent(t, dir, ifA); got != tc.wantA {
				t.Errorf("args %v: DUID %s present=%v, want %v", tc.args, ifA, got, tc.wantA)
			}
			if got := duidPresent(t, dir, ifB); got != tc.wantB {
				t.Errorf("args %v: DUID %s present=%v, want %v", tc.args, ifB, got, tc.wantB)
			}
		})
	}
}

// TestHandleClearDHCP_MalformedSelectorRejectedBeforeNilCheck_5896 pins the
// ordering choice: selector validation runs BEFORE the c.dhcp==nil
// short-circuit, so malformed input always errors regardless of DHCP client
// state, matching the remote CLI (which has no nil path). A bare clear-all
// with no running client remains a benign no-op.
func TestHandleClearDHCP_MalformedSelectorRejectedBeforeNilCheck_5896(t *testing.T) {
	c := &CLI{dhcp: nil}
	if err := c.handleClearDHCP([]string{"client-identifier", "interface"}); err == nil {
		t.Fatal("malformed selector with nil dhcp: want error, got nil")
	}
	if err := c.handleClearDHCP([]string{"client-identifier"}); err != nil {
		t.Fatalf("bare clear-all with nil dhcp: unexpected error: %v", err)
	}
}
