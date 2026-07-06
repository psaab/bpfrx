package cli

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// dashNamedKernelIface finds a real host interface whose kernel name contains a
// '-' and round-trips through LinuxIfName from its slash form, so a config name
// authored in Junos form ("bpfrx/wan") resolves to a real netdev
// ("bpfrx-wan"). Returns (junosName, kernelName, true) or skips.
func dashNamedKernelIface(t *testing.T) (junos, kernel string, ok bool) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", false
	}
	for _, in := range ifaces {
		if in.Name == "lo" || !strings.Contains(in.Name, "-") || strings.Contains(in.Name, "/") {
			continue
		}
		j := strings.ReplaceAll(in.Name, "-", "/")
		if config.LinuxIfName(j) == in.Name {
			return j, in.Name, true
		}
	}
	return "", "", false
}

// #4328: every operational `show interfaces` variant EXCEPT `terse` failed to
// resolve a bondless reth — the reth has no kernel netdev of its own (no link
// is named "reth0"), and only the terse handler built the physical<->reth maps
// from cfg.RethToPhysical(). `show interfaces reth0` printed
// "Physical interface: reth0, Not present"; `... detail` was empty;
// `... extensive` said "not found". These golden tests assert the summary,
// detail, and extensive paths now render the aggregate over its physical
// member, and that a member surfaces its aenet aggregation.
//
// RED-on-revert: routing any of these back through the raw kernel-netdev
// lookup (no RethShowMaps resolution) drops the reth block entirely — the
// member name and the config addresses vanish, failing the assertions.

func rethShowCLI(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/2 {
        gigether-options { redundant-parent reth0; }
    }
    reth0 {
        vlan-tagging;
        unit 50 {
            vlan-id 50;
            family inet { address 172.16.50.8/24; }
            family inet6 { address 2001:559:8585:50::8/64; }
        }
        unit 80 {
            vlan-id 80;
            family inet { address 172.16.80.8/24; }
        }
    }
    ge-0/0/9 {
        unit 0 { family inet { address 10.20.30.40/24; } }
    }
}
security {
    zones {
        security-zone wan {
            interfaces { reth0.50; reth0.80; }
        }
        security-zone trust {
            interfaces { ge-0/0/9.0; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &CLI{store: store} // dp nil: exercise the display walk only
}

func TestShowInterfacesRethSummary4328(t *testing.T) {
	c := rethShowCLI(t)
	out := captureStdout(t, func() {
		if err := c.showInterfaces([]string{"reth0"}); err != nil {
			t.Fatalf("showInterfaces(reth0): %v", err)
		}
	})
	if strings.Contains(out, "Not present") {
		t.Errorf("reth0 summary still reports Not present:\n%s", out)
	}
	for _, want := range []string{
		"Physical interface: reth0",
		"ge-0/0/2",       // names the resolved physical member (RED on revert)
		"172.16.50.8/24", // reth0.50 config address
		"172.16.80.8/24", // reth0.80 config address
		"2001:559:8585:50::8/64",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("reth0 summary missing %q\n%s", want, out)
		}
	}
}

func TestShowInterfacesRethSummaryUnit4328(t *testing.T) {
	c := rethShowCLI(t)
	out := captureStdout(t, func() {
		if err := c.showInterfaces([]string{"reth0.50"}); err != nil {
			t.Fatalf("showInterfaces(reth0.50): %v", err)
		}
	})
	if strings.TrimSpace(out) == "" || strings.Contains(out, "Not present") {
		t.Fatalf("reth0.50 summary empty / Not present:\n%s", out)
	}
	for _, want := range []string{"reth0.50", "ge-0/0/2", "172.16.50.8/24"} {
		if !strings.Contains(out, want) {
			t.Errorf("reth0.50 summary missing %q\n%s", want, out)
		}
	}
}

func TestShowInterfacesRethDetail4328(t *testing.T) {
	c := rethShowCLI(t)
	out := captureStdout(t, func() {
		if err := c.showInterfacesDetail("reth0"); err != nil {
			t.Fatalf("showInterfacesDetail(reth0): %v", err)
		}
	})
	if strings.TrimSpace(out) == "" || strings.Contains(out, "not found") {
		t.Fatalf("reth0 detail empty / not found:\n%s", out)
	}
	for _, want := range []string{
		"Physical interface: reth0",
		"aggregate over member ge-0/0/2",
		"172.16.50.8/24",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("reth0 detail missing %q\n%s", want, out)
		}
	}
}

func TestShowInterfacesRethExtensive4328(t *testing.T) {
	c := rethShowCLI(t)
	out := captureStdout(t, func() {
		if err := c.showInterfacesExtensiveFiltered("reth0"); err != nil {
			t.Fatalf("showInterfacesExtensiveFiltered(reth0): %v", err)
		}
	})
	if strings.TrimSpace(out) == "" {
		t.Fatalf("reth0 extensive empty:\n%s", out)
	}
	for _, want := range []string{"Physical interface: reth0", "ge-0/0/2", "172.16.50.8/24"} {
		if !strings.Contains(out, want) {
			t.Errorf("reth0 extensive missing %q\n%s", want, out)
		}
	}
}

// A physical reth member surfaces its aenet aggregation on the detail path.
func TestShowInterfacesRethMemberDetail4328(t *testing.T) {
	c := rethShowCLI(t)
	out := captureStdout(t, func() {
		if err := c.showInterfacesDetail("ge-0-0-2"); err != nil {
			t.Fatalf("showInterfacesDetail(ge-0-0-2): %v", err)
		}
	})
	if strings.Contains(out, "not found") || strings.TrimSpace(out) == "" {
		t.Fatalf("member detail empty / not found:\n%s", out)
	}
	for _, want := range []string{
		"member of reth0",
		"aenet reth0.50",
		"aenet reth0.80",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("member detail missing %q\n%s", want, out)
		}
	}
}

// The summary path names the reth parent for a physical member queried by name.
func TestShowInterfacesRethMemberSummary4328(t *testing.T) {
	c := rethShowCLI(t)
	out := captureStdout(t, func() {
		if err := c.showInterfaces([]string{"ge-0/0/2"}); err != nil {
			t.Fatalf("showInterfaces(ge-0/0/2): %v", err)
		}
	})
	for _, want := range []string{"member of reth0", "aenet --> reth0.50"} {
		if !strings.Contains(out, want) {
			t.Errorf("member summary missing %q\n%s", want, out)
		}
	}
}

// A NON-reth interface authored in Junos slash form ("bpfrx/wan") must resolve
// to its kernel netdev ("bpfrx-wan") — the raw config-name lookup returned
// "Not present" for a valid interface (#4328 Copilot follow-up; the same class
// of name-resolution gap #3460 fixed for the structured GetInterfaces RPC).
//
// RED-on-revert: routing the summary lookup back through the raw `physName`
// (LinkByName("bpfrx/wan") — no such kernel device) prints "Not present".
func TestShowInterfacesNonRethKernelName4328(t *testing.T) {
	junos, kernel, ok := dashNamedKernelIface(t)
	if !ok {
		t.Skip("no dash-named host interface available to exercise slash->kernel resolution")
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ` + junos + ` { unit 0 { family inet { address 10.9.9.9/24; } } }
}
security { zones { security-zone z { interfaces { ` + junos + `.0; } } } }
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	c := &CLI{store: store}
	out := captureStdout(t, func() {
		if err := c.showInterfaces([]string{junos}); err != nil {
			t.Fatalf("showInterfaces(%s): %v", junos, err)
		}
	})
	if strings.Contains(out, "Not present") {
		t.Errorf("valid interface %s (kernel %s) rendered Not present:\n%s", junos, kernel, out)
	}
	if !strings.Contains(out, junos) {
		t.Errorf("summary missing interface name %s:\n%s", junos, out)
	}
}

// A normal (non-reth) interface must render exactly as before — no reth
// annotations, and the absent-device path still reports "Not present" (this
// test host has no ge-0-0-9). Guards against the reth branch leaking into the
// normal path.
func TestShowInterfacesNormalUnchanged4328(t *testing.T) {
	c := rethShowCLI(t)
	out := captureStdout(t, func() {
		if err := c.showInterfaces([]string{"ge-0/0/9"}); err != nil {
			t.Fatalf("showInterfaces(ge-0/0/9): %v", err)
		}
	})
	if !strings.Contains(out, "ge-0/0/9") {
		t.Errorf("normal interface missing its own name:\n%s", out)
	}
	if strings.Contains(out, "Redundant-ethernet") || strings.Contains(out, "aenet") {
		t.Errorf("normal interface leaked reth annotations:\n%s", out)
	}
}
