// chronyc-tracking output parser used by `show system ntp ...` presenters.
package cli

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/termsafe"
)

// printChronyTracking parses `chronyc tracking` output and prints a
// Junos-style NTP sync status block.
//
// #8597 (muse-004 K46): every printed value is routed through
// termsafe.SanitizeForDisplay.
//
// showSystemNTP is on the #6584 fork allowlist with the reason "chronyc -n /
// ntpq -pn / timedatectl — numeric-mode NTP status". That reason names THREE
// invocations and the function makes FOUR: `chronyc tracking` (cli_show_system.go)
// carries no `-n`, so its `Reference ID` parenthetical is a REVERSE-DNS-RESOLVED
// hostname, not a number. A hostile or compromised NTP server whose PTR record
// carries OSC 52 (clipboard write), OSC 8 or CSI gets that text printed to the
// operator's terminal, which is exactly the class #6468/#6579/#6584 exist for.
//
// The exemption was not wrong about what it described — it was scoped to the
// numeric-mode calls and silent about the one that is not. The allowlist entry
// now names all four.
//
// Sanitizing here rather than at the call site keeps the guard next to the
// values it protects: the parser owns which fields are printed, so a future
// field added below is covered by construction instead of by remembering.
func printChronyTracking(output string) {
	fields := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if idx := strings.Index(line, " : "); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+3:])
			fields[key] = val
		}
	}

	fmt.Println("NTP sync status:")
	if v, ok := fields["Reference ID"]; ok {
		fmt.Printf("  Reference: %s\n", termsafe.SanitizeForDisplay(v))
	}
	if v, ok := fields["Stratum"]; ok {
		fmt.Printf("  Stratum: %s\n", termsafe.SanitizeForDisplay(v))
	}
	if v, ok := fields["Ref time (UTC)"]; ok {
		fmt.Printf("  Reference time: %s\n", termsafe.SanitizeForDisplay(v))
	}
	if v, ok := fields["System time"]; ok {
		fmt.Printf("  System time offset: %s\n", termsafe.SanitizeForDisplay(v))
	}
	if v, ok := fields["Last offset"]; ok {
		fmt.Printf("  Last offset: %s\n", termsafe.SanitizeForDisplay(v))
	}
	if v, ok := fields["RMS offset"]; ok {
		fmt.Printf("  RMS offset: %s\n", termsafe.SanitizeForDisplay(v))
	}
	if v, ok := fields["Frequency"]; ok {
		fmt.Printf("  Frequency: %s\n", termsafe.SanitizeForDisplay(v))
	}
	if v, ok := fields["Root delay"]; ok {
		fmt.Printf("  Root delay: %s\n", termsafe.SanitizeForDisplay(v))
	}
	if v, ok := fields["Root dispersion"]; ok {
		fmt.Printf("  Root dispersion: %s\n", termsafe.SanitizeForDisplay(v))
	}
	if v, ok := fields["Update interval"]; ok {
		fmt.Printf("  Poll interval: %s\n", termsafe.SanitizeForDisplay(v))
	}
	if v, ok := fields["Leap status"]; ok {
		fmt.Printf("  Leap status: %s\n", termsafe.SanitizeForDisplay(v))
	}
}
