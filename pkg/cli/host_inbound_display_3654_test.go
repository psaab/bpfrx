package cli

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// #3654: the local-CLI text surfaces (`show security zones`, `show interfaces`,
// `test security-zone interface`) rendered ONLY the zone-level host-inbound set
// and silently dropped the per-interface override (#3362) and the no-stanza
// default-deny posture (#3405). These golden tests assert each surface now
// surfaces the override and the posture line.
//
// RED-on-revert: routing the surfaces back through the old
// `if zone.HostInboundTraffic != nil { ... }` block (no override iteration, no
// posture line) drops the override block and the "default deny" line, failing
// the matching assertions below.

func hostInboundCLIStore(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            host-inbound-traffic {
                system-services { ssh; ping; }
                protocols { ospf; }
            }
        }
        security-zone edge {
            interfaces {
                ge-0/0/9.0 {
                    host-inbound-traffic { system-services { https; } }
                }
            }
        }
        security-zone plain {
            interfaces {
                ge-0/0/1.0;
            }
        }
        security-zone open;
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &CLI{store: store} // dp nil: skip counter reads, exercise the display walk
}

func TestShowSecurityZonesHostInbound3654(t *testing.T) {
	c := hostInboundCLIStore(t)
	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(c.store.ActiveConfig(), false, ""); err != nil {
			t.Fatalf("showZonesDisplay: %v", err)
		}
	})
	for _, want := range []string{
		// zone-level set preserved
		"Allowed host-inbound traffic: ssh ping",
		"Allowed host-inbound protocols: ospf",
		// per-interface override block (H04 — previously hidden)
		"Host-inbound interface overrides:",
		"ge-0/0/9.0:",
		"override system-services: https",
		"effective system-services: https",
		// no-stanza default-deny posture (M03 — previously blank)
		"Host-inbound: default deny (no stanza)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("show security zones output missing %q\n%s", want, out)
		}
	}
}

func TestTestSecurityZoneHostInbound3654(t *testing.T) {
	// Overridden interface: the diagnostic must flag the override + effective set.
	c := hostInboundCLIStore(t)
	out := captureStdout(t, func() {
		if err := c.testSecurityZone([]string{"interface", "ge-0/0/9.0"}); err != nil {
			t.Fatalf("testSecurityZone: %v", err)
		}
	})
	for _, want := range []string{
		"Interface ge-0/0/9.0 belongs to zone: edge",
		"Host-inbound interface override on ge-0/0/9.0:",
		"effective host-inbound services: https",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("test security-zone (override) output missing %q\n%s", want, out)
		}
	}

	// No-stanza zone interface: default-deny posture line.
	out = captureStdout(t, func() {
		if err := c.testSecurityZone([]string{"interface", "ge-0/0/1.0"}); err != nil {
			t.Fatalf("testSecurityZone: %v", err)
		}
	})
	if !strings.Contains(out, "Host-inbound: default deny (no stanza)") {
		t.Errorf("test security-zone (no-stanza) output missing posture line\n%s", out)
	}
}

// TestShowSecurityZonesZonePostureWithOverride3671 is the surface-level peer of
// the presenter test TestHostInboundViewRenderZonePostureWithOverride3671. The
// `edge` zone in hostInboundCLIStore has an interface override but NO zone-level
// host-inbound stanza; filtering `show security zones` to just that zone proves
// the zone-level default-deny posture line is emitted alongside the override
// block (#3671 / H08).
//
// This is discriminating where TestShowSecurityZonesHostInbound3654 is not: that
// test's "default deny (no stanza)" assertion is satisfied by the unrelated
// `open` zone, so it passes even with the #3671 bug present. Filtering to `edge`
// removes that other source, so reverting the fix (the old
// `&& len(v.Interfaces) == 0` guard) drops the posture line here and fails.
func TestShowSecurityZonesZonePostureWithOverride3671(t *testing.T) {
	c := hostInboundCLIStore(t)
	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(c.store.ActiveConfig(), false, "edge"); err != nil {
			t.Fatalf("showZonesDisplay: %v", err)
		}
	})
	if strings.Contains(out, "Security zone: trust") || strings.Contains(out, "Security zone: open") {
		t.Fatalf("filter to edge leaked another zone into output\n%s", out)
	}
	for _, want := range []string{
		// zone-level default-deny posture — governs the non-overridden
		// interfaces of edge and MUST remain visible despite the override
		"Host-inbound: default deny (no stanza)",
		// override block still rendered
		"Host-inbound interface overrides:",
		"ge-0/0/9.0:",
		"override system-services: https",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("edge zone (override, no zone stanza) output missing %q\n%s", want, out)
		}
	}
}

func TestShowInterfacesHostInbound3654(t *testing.T) {
	// show interfaces reaches the host-inbound block only for a PRESENT kernel
	// interface, so bind the override to the always-present loopback.
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("loopback interface not present; skipping show interfaces golden test")
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone lan {
            interfaces {
                lo {
                    host-inbound-traffic { system-services { https; } }
                }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	c := &CLI{store: store}
	out := captureStdout(t, func() {
		if err := c.showInterfaces(nil); err != nil {
			t.Fatalf("showInterfaces: %v", err)
		}
	})
	for _, want := range []string{
		"Host-inbound: interface-specific override (effective set below)",
		"Allowed host-inbound traffic : https",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("show interfaces output missing %q\n%s", want, out)
		}
	}
}
