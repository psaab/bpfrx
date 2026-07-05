package natshow

import (
	"fmt"
	"io"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// RenderStatic renders `show security nat static` — static NAT and
// NPTv6 rule-sets from configuration.
func RenderStatic(w io.Writer, cfg *config.Config) {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		io.WriteString(w, "No static NAT rules configured.\n")
		return
	}
	for _, rs := range cfg.Security.NAT.Static {
		fmt.Fprintf(w, "Static NAT rule-set: %s\n", rs.Name)
		fmt.Fprintf(w, "  From zone: %s\n", rs.FromZone)
		for _, rule := range rs.Rules {
			fmt.Fprintf(w, "  Rule: %s\n", rule.Name)
			fmt.Fprintf(w, "    Match destination-address: %s\n", rule.Match)
			if rule.IsNPTv6 {
				fmt.Fprintf(w, "    Then nptv6-prefix:         %s\n", rule.Then)
			} else {
				fmt.Fprintf(w, "    Then static-nat prefix:    %s\n", rule.Then)
			}
		}
		io.WriteString(w, "\n")
	}
}

// RenderStaticRule renders `show security nat static rule [detail]` — the
// per-rule drill-down that mirrors source/destination NAT's `rule [detail]`
// (fable-167 C-1b, #4314). Without detail it lists each rule's match/then
// prefixes; with detail it also surfaces the source-address restriction,
// destination-port / mapped-port translation, prefix-name reference, and the
// translation-target routing-instance — fields already carried on
// config.StaticNATRule that the plain `static` view omits.
func RenderStaticRule(w io.Writer, cfg *config.Config, detail bool) {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		io.WriteString(w, "No static NAT rules configured.\n")
		return
	}
	for _, rs := range cfg.Security.NAT.Static {
		fmt.Fprintf(w, "Static NAT rule-set: %s\n", rs.Name)
		if rs.FromZone != "" {
			fmt.Fprintf(w, "  From zone: %s\n", rs.FromZone)
		}
		if detail && rs.FromInterface != "" {
			fmt.Fprintf(w, "  From interface: %s\n", rs.FromInterface)
		}
		if detail && rs.FromRoutingInstance != "" {
			fmt.Fprintf(w, "  From routing-instance: %s\n", rs.FromRoutingInstance)
		}
		for _, rule := range rs.Rules {
			fmt.Fprintf(w, "  Rule: %s\n", rule.Name)
			fmt.Fprintf(w, "    Match destination-address: %s\n", rule.Match)
			if rule.IsNPTv6 {
				fmt.Fprintf(w, "    Then nptv6-prefix:         %s\n", rule.Then)
			} else {
				fmt.Fprintf(w, "    Then static-nat prefix:    %s\n", rule.Then)
			}
			if !detail {
				continue
			}
			if len(rule.SourceAddresses) > 0 {
				fmt.Fprintf(w, "    Match source-address:      %s\n", strings.Join(rule.SourceAddresses, ", "))
			}
			if rule.MatchDestinationPort > 0 {
				fmt.Fprintf(w, "    Match destination-port:    %d\n", rule.MatchDestinationPort)
			}
			if rule.MappedPort > 0 {
				fmt.Fprintf(w, "    Then mapped-port:          %d\n", rule.MappedPort)
			}
			if rule.ThenPrefixName != "" {
				fmt.Fprintf(w, "    Then prefix-name:          %s\n", rule.ThenPrefixName)
			}
			if rule.ThenRoutingInstance != "" {
				fmt.Fprintf(w, "    Then routing-instance:     %s (accepted; cross-VRF post-translation routing not enforced)\n", rule.ThenRoutingInstance)
			}
		}
		io.WriteString(w, "\n")
	}
}

// RenderNPTv6 renders `show security nat nptv6` — only the NPTv6 rules
// within the static rule-sets.
func RenderNPTv6(w io.Writer, cfg *config.Config) {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		io.WriteString(w, "No NPTv6 rules configured.\n")
		return
	}
	found := false
	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if !rule.IsNPTv6 {
				continue
			}
			if !found {
				fmt.Fprintf(w, "%-20s %-20s %-50s %-50s\n",
					"Rule-set", "Rule", "External prefix", "Internal prefix")
				found = true
			}
			fmt.Fprintf(w, "%-20s %-20s %-50s %-50s\n",
				rs.Name, rule.Name, rule.Match, rule.Then)
		}
	}
	if !found {
		io.WriteString(w, "No NPTv6 rules configured.\n")
	}
}
