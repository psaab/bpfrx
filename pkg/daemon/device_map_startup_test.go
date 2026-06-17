package daemon

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// commitConfigForStartup mirrors bootstrapFromFile (daemon_apply.go): enter
// configure, load the text config, commit. After Commit the store has promoted
// the compiled config to ActiveConfig() — exactly the state the startup naming
// decision at daemon_run.go reads. Returns the compiled active config.
func commitConfigForStartup(t *testing.T, text string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s.ExitConfigure()
	cfg := s.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() is nil immediately after Commit — the startup " +
			"naming decision would fall to positional; bootstrap/commit must " +
			"promote the compiled config synchronously")
	}
	return cfg
}

func withStartupNamingStubs(t *testing.T) (mappedCalls, positionalCalls *int) {
	t.Helper()
	savedMapped := enumerateAndRenameMappedFn
	savedPositional := enumerateAndRenameInterfacesFn
	var mapped, positional int
	enumerateAndRenameMappedFn = func(*config.DeviceMapConfig, *config.Config, map[string]bool) error {
		mapped++
		return nil
	}
	enumerateAndRenameInterfacesFn = func(int, bool, int, bool, []string) error {
		positional++
		return nil
	}
	t.Cleanup(func() {
		enumerateAndRenameMappedFn = savedMapped
		enumerateAndRenameInterfacesFn = savedPositional
	})
	return &mapped, &positional
}

// TestDeviceMapNamingActiveStartupDecision is the #1956 regression guard the
// feature shipped WITHOUT: the original tests exercised enumerateAndRenameMapped
// in isolation, so a device-map could be silently ignored at boot (the startup
// branch never selected) and every unit test still passed. This now pins the
// real startup naming helper both boot sites use.
//
// It exercises the exact helper both rename sites use (applyStartupNamingPolicy)
// over a config produced by the same EnterConfigure→LoadOverride→Commit
// sequence the boot path runs (bootstrapFromFile) — so it proves end-to-end
// that:
//   - a committed/bootstrapped config carrying an active `chassis device-map`
//     promotes to ActiveConfig() and dispatches the device-map branch;
//   - a config with no device-map selects positional (bit-identical default);
//   - an empty `device-map {}` block stays positional (R-7);
//   - a nil config selects positional.
//
// A future change that drops or inverts the ACTUAL branch inside the helper —
// or breaks synchronous promotion so ActiveConfig() is nil at naming time —
// fails here, without a live VM.
func TestDeviceMapNamingActiveStartupDecision(t *testing.T) {
	const withMap = `
chassis {
    device-map {
        interface fxp0 {
            mac 10:66:6a:a4:df:5c;
        }
        interface ge-0/0/0 {
            mac 10:66:6a:92:b7:e9;
            key mac;
        }
        unmapped-interface-policy leave-alone;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.1.10/24;
            }
        }
    }
}
`
	const noMap = `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.1.10/24;
            }
        }
    }
}
`
	const emptyMapBlock = `
chassis {
    device-map {
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.1.10/24;
            }
        }
    }
}
`

	t.Run("committed device-map selects device-map branch", func(t *testing.T) {
		cfg := commitConfigForStartup(t, withMap)
		mappedCalls, positionalCalls := withStartupNamingStubs(t)
		if cfg.Chassis.DeviceMap == nil || len(cfg.Chassis.DeviceMap.Entries) == 0 {
			t.Fatal("committed device-map did not compile into ActiveConfig()")
		}
		if err := applyStartupNamingPolicy(cfg, 0, false, 0, true, nil, nil); err != nil {
			t.Fatalf("applyStartupNamingPolicy: %v", err)
		}
		if *mappedCalls != 1 || *positionalCalls != 0 {
			t.Fatalf("startup naming dispatched mapped=%d positional=%d, want mapped=1 positional=0",
				*mappedCalls, *positionalCalls)
		}
	})

	t.Run("no device-map selects positional", func(t *testing.T) {
		cfg := commitConfigForStartup(t, noMap)
		mappedCalls, positionalCalls := withStartupNamingStubs(t)
		if err := applyStartupNamingPolicy(cfg, 0, false, 0, true, nil, nil); err != nil {
			t.Fatalf("applyStartupNamingPolicy: %v", err)
		}
		if *mappedCalls != 0 || *positionalCalls != 1 {
			t.Fatalf("startup naming dispatched mapped=%d positional=%d, want mapped=0 positional=1",
				*mappedCalls, *positionalCalls)
		}
	})

	t.Run("empty device-map block stays positional", func(t *testing.T) {
		cfg := commitConfigForStartup(t, emptyMapBlock)
		mappedCalls, positionalCalls := withStartupNamingStubs(t)
		if err := applyStartupNamingPolicy(cfg, 0, false, 0, true, nil, nil); err != nil {
			t.Fatalf("applyStartupNamingPolicy: %v", err)
		}
		if *mappedCalls != 0 || *positionalCalls != 1 {
			t.Fatalf("startup naming dispatched mapped=%d positional=%d, want mapped=0 positional=1",
				*mappedCalls, *positionalCalls)
		}
	})

	t.Run("nil config selects positional", func(t *testing.T) {
		mappedCalls, positionalCalls := withStartupNamingStubs(t)
		if err := applyStartupNamingPolicy(nil, 0, false, 0, true, nil, nil); err != nil {
			t.Fatalf("applyStartupNamingPolicy: %v", err)
		}
		if *mappedCalls != 0 || *positionalCalls != 1 {
			t.Fatalf("startup naming dispatched mapped=%d positional=%d, want mapped=0 positional=1",
				*mappedCalls, *positionalCalls)
		}
	})
}
