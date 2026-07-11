package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4984 (split from the #4884 interface-identity cohort, sub-defect B): the
// `show interfaces` family mixed name spellings for the SAME interface. The
// summary and terse paths print the authored Junos name ("ge-0/0/2"), but the
// netlink-driven detail / extensive / statistics paths walked kernel netdevs
// and printed the Linux dash-form name ("ge-0-0-2") as the interface identity.
// Worse, detail / extensive keyed the zone + description joins by the authored
// name yet looked them up by the kernel name, so both were silently blank, and
// an authored-form filter ("show interfaces ge-0/0/2 detail") reported "not
// found".
//
// These tests pin the single consistent model: the authored Junos name is the
// canonical display identity across every variant, the zone / description joins
// resolve, and an authored-form filter selects the interface.
//
// RED-on-revert: routing detail / extensive / statistics back through
// attrs.Name (kernel form) for the identity, the joins, or the filter fails
// these assertions.

// identityShowCLI builds a CLI whose active config authors a REAL host
// interface in Junos slash form (so it round-trips to the live kernel netdev
// via LinuxIfName), with a description and a zone binding, so the netlink-driven
// presenters have a managed interface to resolve. Skips when the host exposes no
// dash-named interface to exercise the slash<->kernel mapping.
func identityShowCLI(t *testing.T) (c *CLI, junos, kernel string) {
	t.Helper()
	j, k, ok := dashNamedKernelIface(t)
	if !ok {
		t.Skip("no dash-named host interface available to exercise slash->kernel resolution")
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ` + j + ` {
        description "uplink-4984";
        unit 0 { family inet { address 10.49.84.8/24; } }
    }
}
security { zones { security-zone z4984 { interfaces { ` + j + `.0; } } } }
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	// Sanity: the authored name must differ from the kernel name, otherwise the
	// test proves nothing about spelling consistency.
	if config.LinuxIfName(j) != k || j == k {
		t.Fatalf("test interface does not exercise slash->kernel mapping: junos=%q kernel=%q", j, k)
	}
	return &CLI{store: store}, j, k
}

func TestShowInterfacesDetailAuthoredIdentity4984(t *testing.T) {
	c, junos, kernel := identityShowCLI(t)
	out := captureStdout(t, func() {
		if err := c.showInterfacesDetail(""); err != nil {
			t.Fatalf("showInterfacesDetail(\"\"): %v", err)
		}
	})
	// Canonical authored identity, not the kernel dash-form name.
	if !strings.Contains(out, "Physical interface: "+junos) {
		t.Errorf("detail missing authored identity %q:\n%s", "Physical interface: "+junos, out)
	}
	if strings.Contains(out, "Physical interface: "+kernel) {
		t.Errorf("detail leaked kernel identity %q (should render authored %q):\n%s",
			"Physical interface: "+kernel, junos, out)
	}
	// The zone + description joins now resolve (were silently blank before).
	if !strings.Contains(out, "Security zone: z4984") {
		t.Errorf("detail lost zone join for %s:\n%s", junos, out)
	}
	if !strings.Contains(out, "Description: uplink-4984") {
		t.Errorf("detail lost description join for %s:\n%s", junos, out)
	}
}

func TestShowInterfacesDetailAuthoredFilter4984(t *testing.T) {
	c, junos, _ := identityShowCLI(t)
	// Authored-form filter must select the interface (used to report not found).
	out := captureStdout(t, func() {
		if err := c.showInterfacesDetail(junos); err != nil {
			t.Fatalf("showInterfacesDetail(%q): %v", junos, err)
		}
	})
	if strings.Contains(out, "not found") {
		t.Errorf("authored filter %q reported not found:\n%s", junos, out)
	}
	if !strings.Contains(out, "Physical interface: "+junos) {
		t.Errorf("authored filter %q did not render the interface:\n%s", junos, out)
	}
}

func TestShowInterfacesExtensiveAuthoredIdentity4984(t *testing.T) {
	c, junos, kernel := identityShowCLI(t)
	// Authored-form filter must also select the interface on the extensive path.
	out := captureStdout(t, func() {
		if err := c.showInterfacesExtensiveFiltered(junos); err != nil {
			t.Fatalf("showInterfacesExtensiveFiltered(%q): %v", junos, err)
		}
	})
	if !strings.Contains(out, "Physical interface: "+junos) {
		t.Errorf("extensive missing authored identity %q:\n%s", "Physical interface: "+junos, out)
	}
	if strings.Contains(out, "Physical interface: "+kernel) {
		t.Errorf("extensive leaked kernel identity %q:\n%s", "Physical interface: "+kernel, out)
	}
	if !strings.Contains(out, "Security zone: z4984") {
		t.Errorf("extensive lost zone join for %s:\n%s", junos, out)
	}
	if !strings.Contains(out, "Description: uplink-4984") {
		t.Errorf("extensive lost description join for %s:\n%s", junos, out)
	}
}

func TestShowInterfacesStatisticsAuthoredIdentity4984(t *testing.T) {
	c, junos, kernel := identityShowCLI(t)
	out := captureStdout(t, func() {
		if err := c.showInterfacesStatistics(); err != nil {
			t.Fatalf("showInterfacesStatistics(): %v", err)
		}
	})
	if !strings.Contains(out, junos) {
		t.Errorf("statistics missing authored identity %q:\n%s", junos, out)
	}
	if strings.Contains(out, kernel) {
		t.Errorf("statistics leaked kernel identity %q (should render authored %q):\n%s",
			kernel, junos, out)
	}
}
