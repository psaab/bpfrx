package ipmon

import (
	"fmt"
	"io"
	"time"
)

// FormatStatus renders `show services ip-monitoring status` so the
// local CLI and the gRPC text-show surface stay byte-identical.
func FormatStatus(w io.Writer, statuses []PolicyStatus) {
	if len(statuses) == 0 {
		fmt.Fprintln(w, "No IP monitoring policies configured")
		return
	}
	for _, ps := range statuses {
		state := "PASS"
		if ps.Failed {
			state = "FAIL"
		}
		fmt.Fprintf(w, "Policy - %s (Status: %s)\n", ps.Name, state)
		fmt.Fprintf(w, "  RPM Probes:\n")
		fmt.Fprintf(w, "    Probe name           Test Name        Address          Status\n")
		fmt.Fprintf(w, "    ---------------------- --------------- ---------------- ---------\n")
		if len(ps.FailingTests) == 0 {
			fmt.Fprintf(w, "    %-22s %-15s %-16s %s\n", ps.Probe, "*", "-", "PASS")
		} else {
			for _, test := range ps.FailingTests {
				fmt.Fprintf(w, "    %-22s %-15s %-16s %s\n", ps.Probe, test, "-", "FAIL")
			}
		}
		fmt.Fprintf(w, "  Route-Action%s:\n", pluralSuffix(len(ps.Routes)))
		if len(ps.Routes) == 0 {
			fmt.Fprintf(w, "    (none applied)\n")
		} else {
			fmt.Fprintf(w, "    route-instance    route             next-hop         state\n")
			fmt.Fprintf(w, "    ----------------- ----------------- ---------------- -------------\n")
			for _, r := range ps.Routes {
				inst := r.RoutingInstance
				if inst == "" {
					inst = "inet.0"
				}
				fmt.Fprintf(w, "    %-17s %-17s %-16s %s\n", inst, r.Destination, r.NextHop, "APPLIED")
			}
		}
		if !ps.Since.IsZero() {
			fmt.Fprintf(w, "  Last state change: %s\n", ps.Since.Format("2006-01-02 15:04:05"))
		}
		if !ps.PendingRecoveryAt.IsZero() {
			fmt.Fprintf(w, "  Recovery hold-down expires in %s\n",
				time.Until(ps.PendingRecoveryAt).Round(time.Second))
		}
		fmt.Fprintf(w, "  Transitions: %d\n", ps.Transitions)
		fmt.Fprintln(w)
	}
}

func pluralSuffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
