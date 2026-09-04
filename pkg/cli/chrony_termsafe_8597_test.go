package cli

import (
	"os"
	"strings"
	"testing"
)

// #8597 (muse-004 K46) — `chronyc tracking` output reached the operator's
// terminal unsanitized, and the #6584 allowlist entry that covered it was
// scoped to a different invocation.
//
// showSystemNTP forks FOUR commands. Three are numeric-mode or fixed-property
// (`chronyc -n sources`, `ntpq -pn`, `timedatectl show --property=... --value`)
// and are what the allowlist reason described. The fourth, `chronyc tracking`,
// carries NO `-n`, so its `Reference ID` parenthetical is a REVERSE-DNS-RESOLVED
// hostname:
//
//	Reference ID    : C0248F97 (time.example.com)
//
// A hostile or compromised NTP server whose PTR record carries OSC 52
// (clipboard write), OSC 8 or CSI gets that text printed to the terminal — the
// class #6468/#6579/#6584 exist for. The exemption was not wrong about what it
// described; it was silent about the one fork it did not.

// chronyTrackingOutput builds a `chronyc tracking` block with the given
// Reference ID line, in the real format the parser splits on (" : ").
func chronyTrackingOutput(refID string) string {
	return strings.Join([]string{
		"Reference ID    : " + refID,
		"Stratum         : 3",
		"Ref time (UTC)  : Thu Sep 04 12:00:00 2026",
		"System time     : 0.000000123 seconds slow of NTP time",
		"Last offset     : +0.000000456 seconds",
		"RMS offset      : 0.000000789 seconds",
		"Frequency       : 1.234 ppm slow",
		"Root delay      : 0.001234 seconds",
		"Root dispersion : 0.005678 seconds",
		"Update interval : 64.2 seconds",
		"Leap status     : Normal",
	}, "\n")
}

// TestChronyTrackingSanitizesTheResolvedHostname_8597 is the RED-on-revert
// core. The payload is an OSC 52 clipboard write wrapped in the parenthetical
// where chrony puts the reverse-DNS name.
func TestChronyTrackingSanitizesTheResolvedHostname_8597(t *testing.T) {
	const payload = "\x1b]52;c;cGF5bG9hZA==\x07"
	out := captureStdout(t, func() {
		printChronyTracking(chronyTrackingOutput("C0248F97 (evil" + payload + ".example)"))
	})

	if strings.Contains(out, "\x1b") {
		t.Errorf("an ESC byte from the NTP server's reverse-DNS name reached the "+
			"terminal: %q\nOSC 52 is a clipboard WRITE — the operator's paste buffer is "+
			"set by a host they are diagnosing (#8597/K46)", out)
	}
	for _, b := range []string{"\x07", "\x00", "\r"} {
		if strings.Contains(out, b) {
			t.Errorf("control byte %q reached the terminal in: %q", b, out)
		}
	}
	// Non-vacuity: the field must actually have been PRINTED. An empty render
	// contains no ESC either, and would pass every assertion above.
	if !strings.Contains(out, "Reference:") {
		t.Fatalf("the Reference line was not printed at all, so the assertions above "+
			"are about an empty string:\n%s", out)
	}
	if !strings.Contains(out, "evil") {
		t.Errorf("the sanitizer removed the whole value rather than escaping the "+
			"control bytes; the operator must still see WHAT the name was:\n%s", out)
	}
}

// TestEveryChronyTrackingFieldIsSanitized_8597 covers the other ten. chrony
// controls all of them and only the Reference ID is documented as
// reverse-DNS-derived — but "only one field is attacker-shaped" is a claim
// about today's chrony, and the parser prints whatever the block contains.
func TestEveryChronyTrackingFieldIsSanitized_8597(t *testing.T) {
	const payload = "\x1b]8;;http://evil\x07"
	fields := []string{
		"Reference ID", "Stratum", "Ref time (UTC)", "System time", "Last offset",
		"RMS offset", "Frequency", "Root delay", "Root dispersion",
		"Update interval", "Leap status",
	}
	for _, f := range fields {
		lines := make([]string, 0, len(fields))
		for _, g := range fields {
			v := "1"
			if g == f {
				v = "tainted" + payload
			}
			lines = append(lines, g+" : "+v)
		}
		out := captureStdout(t, func() { printChronyTracking(strings.Join(lines, "\n")) })
		if strings.Contains(out, "\x1b") {
			t.Errorf("field %q printed an ESC byte: %q", f, out)
		}
		if !strings.Contains(out, "tainted") {
			t.Errorf("field %q was not printed at all, so this row is vacuous:\n%s", f, out)
		}
	}
}

// TestChronyTrackingLeavesCleanOutputAlone_8597 is the OVER-BROAD control.
// SanitizeForDisplay is a pass-through for clean input, and the operator-facing
// text must be unchanged for the ordinary case — including the parenthetical
// hostname form, which is the shape the sanitizer is being applied to.
func TestChronyTrackingLeavesCleanOutputAlone_8597(t *testing.T) {
	out := captureStdout(t, func() {
		printChronyTracking(chronyTrackingOutput("C0248F97 (time.example.com)"))
	})
	for _, want := range []string{
		"  Reference: C0248F97 (time.example.com)\n",
		"  Stratum: 3\n",
		"  System time offset: 0.000000123 seconds slow of NTP time\n",
		"  Frequency: 1.234 ppm slow\n",
		"  Leap status: Normal\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ordinary output changed; missing %q in:\n%s", want, out)
		}
	}
}

// TestTrackingForkCarriesNoNumericFlag_8597 pins the PREMISE the exemption
// rested on, so it cannot be quietly restored.
//
// The #6584 allowlist reason was "chronyc -n / ntpq -pn / timedatectl —
// numeric-mode NTP status". It is true of three of showSystemNTP's four forks.
// If someone later adds `-n` to the tracking call, the sanitizer becomes
// belt-and-braces rather than load-bearing and this cell says so — and if
// someone removes `-n` from the sources call, it fails for the opposite reason.
func TestTrackingForkCarriesNoNumericFlag_8597(t *testing.T) {
	src := readCLISource(t, "cli_show_system.go")
	if !strings.Contains(src, `exec.Command("chronyc", "tracking")`) {
		t.Fatal("the `chronyc tracking` fork is gone or spelled differently; re-derive " +
			"why printChronyTracking sanitizes before assuming it still needs to")
	}
	if !strings.Contains(src, `exec.Command("chronyc", "-n", "sources")`) {
		t.Error("the `chronyc -n sources` fork is gone or no longer numeric-mode; the " +
			"#6584 allowlist reason names it as exempt and would now be wrong")
	}
}

func readCLISource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
