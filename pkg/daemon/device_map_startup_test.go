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

// TestDeviceMapNamingActiveStartupDecision is the #1956 regression guard the
// feature shipped WITHOUT: the original tests exercised enumerateAndRenameMapped
// in isolation, so a device-map could be silently ignored at boot (the naming
// branch never selected) and every unit test still passed. This locks in the
// STARTUP DECISION itself.
//
// It exercises the exact seam both rename sites use (deviceMapNamingActive) over
// a config produced by the same EnterConfigure→LoadOverride→Commit sequence the
// boot path runs (bootstrapFromFile) — so it proves end-to-end that:
//   - a committed/bootstrapped config carrying an active `chassis device-map`
//     promotes to ActiveConfig() and selects the device-map branch;
//   - a config with no device-map selects positional (bit-identical default);
//   - an empty `device-map {}` block stays positional (R-7);
//   - a nil config selects positional.
//
// A future change that drops or inverts the branch — or breaks synchronous
// promotion so ActiveConfig() is nil at naming time — fails here, without a
// live VM.
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
		if cfg.Chassis.DeviceMap == nil || len(cfg.Chassis.DeviceMap.Entries) == 0 {
			t.Fatal("committed device-map did not compile into ActiveConfig()")
		}
		if !deviceMapNamingActive(cfg) {
			t.Fatal("startup naming must select the device-map branch for a " +
				"committed active device-map — the positional path silently " +
				"ignores the map (#1956 boot bug)")
		}
	})

	t.Run("no device-map selects positional", func(t *testing.T) {
		cfg := commitConfigForStartup(t, noMap)
		if deviceMapNamingActive(cfg) {
			t.Fatal("no-device-map config must select positional naming " +
				"(bit-identical to pre-#1956)")
		}
	})

	t.Run("empty device-map block stays positional", func(t *testing.T) {
		cfg := commitConfigForStartup(t, emptyMapBlock)
		if deviceMapNamingActive(cfg) {
			t.Fatal("an empty `device-map {}` block is positional mode (R-7), " +
				"not device-map mode")
		}
	})

	t.Run("nil config selects positional", func(t *testing.T) {
		if deviceMapNamingActive(nil) {
			t.Fatal("nil config must select positional naming, never device-map")
		}
	})
}
