// chronyc-tracking output parser used by `show system ntp ...` presenters.
package cli

import (
	"fmt"
	"strings"
)

// printChronyTracking parses `chronyc tracking` output and prints a
// Junos-style NTP sync status block.
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
		fmt.Printf("  Reference: %s\n", v)
	}
	if v, ok := fields["Stratum"]; ok {
		fmt.Printf("  Stratum: %s\n", v)
	}
	if v, ok := fields["Ref time (UTC)"]; ok {
		fmt.Printf("  Reference time: %s\n", v)
	}
	if v, ok := fields["System time"]; ok {
		fmt.Printf("  System time offset: %s\n", v)
	}
	if v, ok := fields["Last offset"]; ok {
		fmt.Printf("  Last offset: %s\n", v)
	}
	if v, ok := fields["RMS offset"]; ok {
		fmt.Printf("  RMS offset: %s\n", v)
	}
	if v, ok := fields["Frequency"]; ok {
		fmt.Printf("  Frequency: %s\n", v)
	}
	if v, ok := fields["Root delay"]; ok {
		fmt.Printf("  Root delay: %s\n", v)
	}
	if v, ok := fields["Root dispersion"]; ok {
		fmt.Printf("  Root dispersion: %s\n", v)
	}
	if v, ok := fields["Update interval"]; ok {
		fmt.Printf("  Poll interval: %s\n", v)
	}
	if v, ok := fields["Leap status"]; ok {
		fmt.Printf("  Leap status: %s\n", v)
	}
}
