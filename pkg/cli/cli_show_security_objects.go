package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
)

func (c *CLI) showAddressBook(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Security.AddressBook == nil {
		fmt.Println("No address book configured")
		return nil
	}
	ab := cfg.Security.AddressBook

	// Optional filter by name
	filterName := ""
	if len(args) > 0 {
		filterName = args[0]
	}

	if len(ab.Addresses) > 0 {
		if filterName == "" {
			fmt.Println("Addresses:")
		}
		for _, addr := range ab.Addresses {
			if addr == nil {
				// #7197: a present-but-nil *Address map value is admitted by
				// the tolerant-load / peer-sync path (#1960) — the SAME
				// nil-tolerant class #3494 codifies for AddressBook.Addresses
				// itself (compiler_validate_warn_nil_3494_test.go injects
				// "zz-nil-addr": nil as part of that contract) and the one
				// the #5221 guard above already skips for application sets.
				// Skip it rather than dereferencing addr.Name / addr.Value
				// and panicking the CLI display.
				continue
			}
			if filterName != "" && addr.Name != filterName {
				continue
			}
			fmt.Printf("  %-24s %s\n", addr.Name, addr.Value)
		}
	}

	if len(ab.AddressSets) > 0 {
		if filterName == "" {
			fmt.Println("Address sets:")
		}
		for _, as := range ab.AddressSets {
			if as == nil {
				// #7197: mirrors the #3494 nil-tolerant contract for
				// AddressBook.AddressSets ("zz-nil-set": nil in the same
				// compiler_validate_warn_nil_3494_test.go fixture) and the
				// #5221 application-set guard's shape. Skip rather than
				// dereferencing as.Name / as.Addresses / as.AddressSets.
				continue
			}
			if filterName != "" && as.Name != filterName {
				continue
			}
			var parts []string
			for _, a := range as.Addresses {
				parts = append(parts, a)
			}
			for _, s := range as.AddressSets {
				parts = append(parts, "set:"+s)
			}
			fmt.Printf("  %-24s members: %s\n", as.Name, strings.Join(parts, ", "))
			// If filtering by name, show member details. ab.Addresses is keyed
			// by address NAME, so a direct map lookup replaces the O(n*m)
			// nested scan the pre-fix code ran (an inner range over every
			// address book entry, for every member, with no early exit even
			// after a match) — #6218 item 13.
			if filterName != "" {
				for _, a := range as.Addresses {
					if addr, ok := ab.Addresses[a]; ok && addr != nil {
						fmt.Printf("    %-22s %s\n", addr.Name, addr.Value)
					}
				}
			}
		}
	}

	if filterName == "" && len(ab.Addresses) == 0 && len(ab.AddressSets) == 0 {
		fmt.Println("Address book is empty")
	}

	return nil
}

func (c *CLI) showApplications(args []string) error {
	cfg := c.store.ActiveConfig()

	// Parse sub-commands: detail, <name>
	detail := false
	filterName := ""
	for _, a := range args {
		switch a {
		case "detail":
			detail = true
		default:
			filterName = a
		}
	}

	// Helper to print application detail
	printApp := func(app *config.Application, indent string) {
		if detail || filterName != "" {
			fmt.Printf("%sApplication: %s\n", indent, app.Name)
			if app.Description != "" {
				fmt.Printf("%s  Description: %s\n", indent, app.Description)
			}
			if app.Protocol != "" {
				fmt.Printf("%s  IP protocol: %s\n", indent, app.Protocol)
			}
			if app.DestinationPort != "" {
				fmt.Printf("%s  Destination port: %s\n", indent, app.DestinationPort)
			}
			if app.SourcePort != "" {
				fmt.Printf("%s  Source port: %s\n", indent, app.SourcePort)
			}
			if app.InactivityTimeout > 0 {
				fmt.Printf("%s  Inactivity timeout: %ds\n", indent, app.InactivityTimeout)
			}
			if app.ALG != "" {
				fmt.Printf("%s  ALG: %s\n", indent, app.ALG)
			}
		} else {
			port := app.DestinationPort
			if port == "" {
				port = "-"
			}
			fmt.Printf("%s%-24s protocol: %-6s port: %s\n", indent, app.Name, app.Protocol, port)
		}
	}

	// User-defined applications
	if cfg != nil && len(cfg.Applications.Applications) > 0 {
		if filterName == "" {
			fmt.Println("User-defined applications:")
		}
		names := make([]string, 0, len(cfg.Applications.Applications))
		for name := range cfg.Applications.Applications {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			app := cfg.Applications.Applications[name]
			if filterName != "" && app.Name != filterName {
				continue
			}
			printApp(app, "  ")
		}
		if filterName == "" {
			fmt.Println()
		}
	}

	// User-defined application-sets
	if cfg != nil && len(cfg.Applications.ApplicationSets) > 0 {
		names := make([]string, 0, len(cfg.Applications.ApplicationSets))
		for name := range cfg.Applications.ApplicationSets {
			names = append(names, name)
		}
		sort.Strings(names)

		if filterName == "" {
			fmt.Println("Application sets:")
		}
		for _, name := range names {
			as := cfg.Applications.ApplicationSets[name]
			if as == nil {
				// #5221: a present-but-nil application-set map value is admitted
				// by the tolerant-load / peer-sync path (#1960) that the resolver
				// (#5179) already tolerates. Skip it rather than dereferencing
				// as.Name / as.Applications and panicking the CLI display.
				continue
			}
			if filterName != "" && as.Name != filterName {
				continue
			}
			if detail || filterName != "" {
				fmt.Printf("  Application set: %s\n", as.Name)
				fmt.Printf("    Members:\n")
				for _, member := range as.Applications {
					fmt.Printf("      %s\n", member)
					// Show member details if filtering by set name
					if filterName != "" {
						if cfg != nil {
							if app, ok := cfg.Applications.Applications[member]; ok {
								printApp(app, "        ")
							}
						}
					}
				}
			} else {
				fmt.Printf("  %-24s members: %s\n", as.Name, strings.Join(as.Applications, ", "))
			}
		}
		if filterName == "" {
			fmt.Println()
		}
	}

	// Show matching predefined application if filtering by name
	if filterName != "" {
		for _, app := range config.PredefinedApplications {
			if app.Name == filterName {
				fmt.Println("Predefined application:")
				printApp(app, "  ")
				return nil
			}
		}
		return nil
	}

	// Predefined applications (only in list mode)
	fmt.Println("Predefined applications:")
	for _, app := range config.PredefinedApplications {
		printApp(app, "  ")
	}

	return nil
}

func (c *CLI) showDynamicAddress() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	if len(cfg.Security.DynamicAddress.FeedServers) == 0 {
		fmt.Println("No dynamic address feeds configured")
		return nil
	}

	// Get runtime feed status if available.
	var runtimeFeeds map[string]feeds.FeedInfo
	if c.feedsFn != nil {
		runtimeFeeds = c.feedsFn()
	}

	fmt.Println("Dynamic Address Feed Servers:")
	for name, fs := range cfg.Security.DynamicAddress.FeedServers {
		updateInt := fs.UpdateInterval
		if updateInt == 0 {
			updateInt = 3600
		}
		holdInt := fs.HoldInterval
		if holdInt == 0 {
			holdInt = 7200
		}
		fmt.Printf("  Feed Server: %s\n", name)
		if fs.URL != "" {
			// Redact embedded basic-auth userinfo / query-string token before
			// printing to the on-box console — the credentialed feed URL would
			// otherwise land in terminal scrollback / support bundles (#5521).
			fmt.Printf("    URL: %s\n", config.RedactURL(fs.URL))
		}
		if fs.FeedName != "" {
			fmt.Printf("    Feed name: %s\n", fs.FeedName)
		}
		fmt.Printf("    Update interval: %d seconds\n", updateInt)
		fmt.Printf("    Hold interval:   %d seconds\n", holdInt)

		if fi, ok := runtimeFeeds[name]; ok {
			fmt.Printf("    Prefixes: %d\n", fi.Prefixes)
			if !fi.LastFetch.IsZero() {
				age := time.Since(fi.LastFetch).Truncate(time.Second)
				fmt.Printf("    Last fetch: %s (%s ago)\n", fi.LastFetch.Format("2006-01-02 15:04:05"), age)
			} else {
				fmt.Printf("    Last fetch: never\n")
			}
			if fi.Degraded {
				fmt.Printf("    DEGRADED: %d invalid line(s) skipped (partial set installed)\n", fi.InvalidLines)
				if len(fi.InvalidSample) > 0 {
					fmt.Printf("      Sample: %s\n", strings.Join(fi.InvalidSample, ", "))
				}
			}
		}
	}

	return nil
}

func (c *CLI) showALG() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	renderALG(os.Stdout, &cfg.Security.ALG)
	return nil
}

// renderALG writes the `show security alg` body.
//
// #7423 row 6: this used to print SIXTEEN rows, twelve of them hard-coded
// literals with no config behind them — eight of those claiming `Enabled` for
// ALGs (H323, MGCP, MSRPC, PPTP, RTSP, SCCP, SUNRPC, TALK) that do not exist
// anywhere in this product. `security alg` has exactly four schema children,
// and the gRPC and REST surfaces render only those four, so the fabrication
// was CLI-only.
//
// The four real ones are also reported more carefully than "Enabled". Nothing
// in the userspace dataplane does data-channel pinholing: the ALG bits reach
// exactly one consumer, `alg_type_for_session`, which stamps a tag on the
// conntrack row for `show security flow session` and nothing else. So
// "enabled" would overstate three of them, and TFTP has no `alg_type` at all —
// its wire bit is `#[allow(dead_code)]` in the Rust helper, whose own comment
// says it "has no consumer here".
//
// Failure direction is availability, not a security hole: an operator
// believing an ALG is inspecting traffic may leave a pinhole unconfigured.
//
// Deleting the ghost rows alone would have introduced a SECOND honesty defect
// in the opposite direction. `security alg <proto>` for a proto outside the
// four is ACCEPTED at commit and recorded in UnsupportedProtos (#4232), which
// drives an accepted-but-inert advisory — so an operator can have `alg h323`
// in the running config. Printing only the four would make that stanza
// invisible here, where before it at least appeared (as a fabricated
// `Enabled`). Those protos are therefore rendered too, marked as what they
// are, which is also what makes the closing note true.
//
// It takes an io.Writer rather than printing directly so the rows can be
// asserted without a configstore round-trip.
func renderALG(w io.Writer, alg *config.ALGConfig) {
	fmt.Fprintln(w, "ALG Status:")

	printALG := func(name, status string) {
		fmt.Fprintf(w, "  %-9s: %s\n", name, status)
	}
	for _, proto := range config.ALGModeledProtos() {
		printALG(config.ALGDisplayName(proto), config.ALGStatusText(proto, alg.ALGDisabled(proto)))
	}
	for _, proto := range alg.ALGUnmodeledConfigured() {
		printALG(config.ALGDisplayName(proto), config.ALGStatusUnmodeled())
	}
	fmt.Fprintln(w, "  (DNS, FTP, SIP and TFTP are the only ALGs this product models)")
}
