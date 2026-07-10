package cli

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #5068: the local CLI `show interfaces` presenter family (terse / detail /
// extensive / vlans / the summary walk) and the interface-name / unit-number
// value-hint completers dereference present-but-nil InterfaceConfig and
// InterfaceUnit map values. Those nil slots are admitted on the tolerant /
// HA-sync config path that the compiler warn-pass already tolerates
// (compiler_validate_warn_nil_3494_test.go codifies "zz-nil-ifc": nil and a
// nil Units[N] value). CLI.Run has no panic recovery, so a nil-deref there
// exits the in-process xpfd. This test injects a nil interface value AND a
// nil unit value into the live ActiveConfig and drives every show-interfaces
// surface; reverting any of the added nil guards makes the matching call
// panic (RED on revert).

func nilInterfaceCLIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/9 {
        unit 0 { family inet { address 10.20.30.40/24; } }
    }
    ge-0/0/8 {
        unit 0 { family inet { address 10.20.31.40/24; } }
    }
}
security {
    zones {
        security-zone trust {
            interfaces { ge-0/0/8.0; ge-0/0/9.0; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatalf("fixture missing active config")
	}
	real := cfg.Interfaces.Interfaces["ge-0/0/9"]
	if real == nil || real.Units == nil {
		t.Fatalf("fixture missing ge-0/0/9 units")
	}
	// nil InterfaceConfig value (present key, nil pointer) — tolerated by the
	// compiler warn-pass (#3494); reachable in every range-all presenter.
	cfg.Interfaces.Interfaces["zz-nil-ifc"] = nil
	// nil InterfaceConfig value referenced by a security zone — drives the
	// summary walk's cfg.Interfaces.Interfaces[physName] deref (line ~139/365).
	cfg.Interfaces.Interfaces["ge-0/0/8"] = nil
	// nil InterfaceUnit value on an otherwise real interface — reachable in
	// every unit-iterating presenter and the unit-number completer.
	real.Units[7] = nil
	return store
}

func TestShowInterfacesNilMapValuesNoPanic5068(t *testing.T) {
	store := nilInterfaceCLIStore(t)
	c := &CLI{store: store} // dp nil: exercise the config-display walk only

	// A panic in any presenter unwinds through captureStdout and fails the
	// test; each reverts RED without its nil guard.
	//
	// Output is kept tiny on purpose. captureStdout drains its os.Pipe only
	// AFTER the callback returns, so a presenter that writes past the pipe
	// buffer would deadlock. The detail/extensive presenters build their
	// interface maps by iterating EVERY interface config value (the nil-deref
	// site) BEFORE filtering by name, so a filter that matches no host netdev
	// still exercises the guard while skipping the whole-host link dump. The
	// summary walk derefs the config only for zone-referenced logicals, so it
	// takes a filter that MATCHES the nil zone member (ge-0/0/8).
	const noMatch = "zz-no-such-netdev-5068"
	cases := []struct {
		name string
		fn   func() error
	}{
		{"terse", c.showInterfacesTerse},
		{"detail", func() error { return c.showInterfacesDetail(noMatch) }},
		{"extensive", func() error { return c.showInterfacesExtensiveFiltered(noMatch) }},
		{"vlans", c.showVlans},
		{"summary", func() error { return c.showInterfaces([]string{"ge-0/0/8"}) }},
	}
	for _, tc := range cases {
		captureStdout(t, func() {
			if err := tc.fn(); err != nil {
				t.Fatalf("show interfaces %s: %v", tc.name, err)
			}
		})
	}
}

func TestValueProviderInterfaceNilMapValuesNoPanic5068(t *testing.T) {
	c := &CLI{store: nilInterfaceCLIStore(t)}

	// Interface-name completion iterates every interface value — panics on the
	// nil InterfaceConfig without the completion.go guard.
	_ = c.valueProvider(config.ValueHintInterfaceName,
		[]string{"interfaces"})
	// Unit-number completion iterates one interface's units — panics on the
	// nil InterfaceUnit without the completion.go guard.
	_ = c.valueProvider(config.ValueHintUnitNumber,
		[]string{"interfaces", "ge-0/0/9", "unit"})
}
