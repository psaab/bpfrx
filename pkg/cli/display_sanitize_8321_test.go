package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #8321 grouped-cohort items 7 and 8, both in `show` renderers that print
// values this daemon does not author.
//
// Item 8 — a core-dump FILENAME was printed raw. systemd-coredump derives the
// name from the crashing process's `comm`, so influencing it needs only the
// ability to run a binary with a chosen name and crash it, not root. An ANSI
// escape in that name is INTERPRETED by the operator's terminal, so it can
// clear the screen or overwrite lines the CLI already wrote — forging what the
// operator believes the firewall reported.
//
// Item 7 — sub-zero thermal readings rendered with a second minus sign, or lost
// the sign entirely: `-12.-5 C` and `0.-5 C`.
//
// Both cells drive the REAL renderer through a path seam, not the helper. A
// cell calling `sanitizeTerminalText` or `formatMilliCelsius` directly would
// pass against a call site that had stopped using them — which is exactly the
// defect being fixed, a correct helper one caller does not reach.

func TestShowCoreDumpsSanitizesFilenames_8321(t *testing.T) {
	dir := t.TempDir()
	// A name carrying a real ANSI erase-display sequence plus a bell.
	hostile := "core.evil\x1b[2J\x07.1000.abc.500.1700000000"
	if err := os.WriteFile(filepath.Join(dir, hostile), []byte("x"), 0o600); err != nil {
		t.Fatalf("write hostile core file: %v", err)
	}
	benign := "core.xpfd.0.def.501.1700000001"
	if err := os.WriteFile(filepath.Join(dir, benign), []byte("x"), 0o600); err != nil {
		t.Fatalf("write benign core file: %v", err)
	}

	old := coreDumpDirs
	coreDumpDirs = []string{dir}
	t.Cleanup(func() { coreDumpDirs = old })

	c := &CLI{}
	out := captureStdout(t, func() {
		if err := c.showCoreDumps(); err != nil {
			t.Fatalf("showCoreDumps: %v", err)
		}
	})

	if strings.Contains(out, "\x1b") || strings.Contains(out, "\x07") {
		t.Fatalf("#8321 item 8: `show system core-dumps` emitted a raw control character from a "+
			"filesystem-controlled filename. The terminal INTERPRETS it, so a crafted core-dump "+
			"name can overwrite what the operator just read.\noutput: %q", out)
	}
	// Non-vacuity: the hostile entry must actually have been rendered. If the
	// renderer silently skipped it, the assertion above would pass for the
	// wrong reason.
	if !strings.Contains(out, "core.evil") {
		t.Fatalf("#8321 item 8: the hostile entry was not rendered at all, so the absence of "+
			"escapes proves nothing.\noutput: %q", out)
	}
	// Control: an ordinary name must survive byte-identically. A sanitizer that
	// rewrites normal output is a display bug of its own.
	if !strings.Contains(out, benign) {
		t.Fatalf("#8321 item 8: an ordinary core-dump name must render unchanged; %q not found in\n%s",
			benign, out)
	}
}

func TestShowChassisEnvironmentRendersSubZero_8321(t *testing.T) {
	for _, tc := range []struct {
		name   string
		milli  string
		want   string
		reject string
	}{
		// The SUBJECT: a whole part of zero is where the sign is lost outright.
		{name: "minus-half-degree", milli: "-500", want: "-0.5 C", reject: "0.-5"},
		// A sub-zero reading with a non-zero whole part: the sign belongs to the
		// whole part and must not be repeated on the fraction.
		{name: "minus-twelve-point-five", milli: "-12500", want: "-12.5 C", reject: "-12.-5"},
		// POSITIVE CONTROL: the ordinary case must be unchanged. If this arm
		// ever fails the fix has broken the common path and the two above are
		// measuring a renderer nobody would ship.
		{name: "positive", milli: "41500", want: "41.5 C", reject: "41.-5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			zone := filepath.Join(root, "thermal_zone0")
			if err := os.MkdirAll(zone, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(zone, "temp"), []byte(tc.milli+"\n"), 0o600); err != nil {
				t.Fatalf("write temp: %v", err)
			}
			if err := os.WriteFile(filepath.Join(zone, "type"), []byte("acpitz\n"), 0o600); err != nil {
				t.Fatalf("write type: %v", err)
			}

			old := thermalZoneGlob
			thermalZoneGlob = filepath.Join(root, "thermal_zone*", "temp")
			t.Cleanup(func() { thermalZoneGlob = old })

			c := &CLI{}
			out := captureStdout(t, func() {
				if err := c.showChassisEnvironment(); err != nil {
					t.Fatalf("showChassisEnvironment: %v", err)
				}
			})

			if !strings.Contains(out, tc.want) {
				t.Fatalf("#8321 item 7: %s millidegrees must render as %q; got\n%s", tc.milli, tc.want, out)
			}
			if strings.Contains(out, tc.reject) {
				t.Fatalf("#8321 item 7: output still contains the malformed form %q:\n%s", tc.reject, out)
			}
		})
	}
}
