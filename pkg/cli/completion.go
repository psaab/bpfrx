package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// completionNode is an alias for the canonical cmdtree.Node type.
type completionNode = cmdtree.Node

// operationalTree references the canonical tree in pkg/cmdtree.
var operationalTree = cmdtree.OperationalTree

// configTopLevel references the canonical config tree in pkg/cmdtree.
var configTopLevel = cmdtree.ConfigTopLevel

// completionCandidate holds a command name and its description.
type completionCandidate struct {
	name string
	desc string
}

// cliCompleter implements readline.AutoCompleter.
type cliCompleter struct {
	cli         *CLI
	helpWritten bool // set by ? Listener to suppress duplicate help from Do()
}

func (cc *cliCompleter) Do(line []rune, pos int) ([][]rune, int) {
	// If the ? Listener already wrote help, suppress duplicate output.
	if cc.helpWritten {
		cc.helpWritten = false
		return nil, 0
	}

	text := string(line[:pos])

	// Pipe filter completion: "show ... | <tab>"
	if pipeCandidates, handled := completePipeFilter(text); handled {
		if len(pipeCandidates) == 0 {
			return nil, 0
		}
		// Determine partial (text after "| ")
		idx := strings.LastIndex(text, "|")
		after := strings.TrimLeft(text[idx+1:], " ")
		partial := after

		sort.Slice(pipeCandidates, func(i, j int) bool { return pipeCandidates[i].name < pipeCandidates[j].name })
		if len(pipeCandidates) == 1 {
			suffix := pipeCandidates[0].name[len(partial):]
			return [][]rune{[]rune(suffix + " ")}, len(partial)
		}
		writeCompletionHelp(cc.cli.rl.Stdout(), pipeCandidates)
		names := make([]string, len(pipeCandidates))
		for i, c := range pipeCandidates {
			names[i] = c.name
		}
		cp := commonPrefix(names)
		suffix := cp[len(partial):]
		if suffix == "" {
			return nil, 0
		}
		return [][]rune{[]rune(suffix)}, len(partial)
	}

	words := strings.Fields(text)
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	var partial string
	if !trailingSpace && len(words) > 0 {
		partial = words[len(words)-1]
		words = words[:len(words)-1]
	}

	var candidates []completionCandidate
	if cc.cli.store.InConfigMode() {
		candidates = cc.cli.completeConfigWithDesc(words, partial)
	} else {
		// "show configuration <path>" — delegate sub-path to config schema
		if subPath, ok := showConfigurationSubPath(words); ok {
			if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
				subPath = resolvedPath
			}
			schemaCompletions := config.CompleteSetPathWithValues(subPath, cc.cli.valueProvider)
			if schemaCompletions != nil {
				for _, sc := range schemaCompletions {
					if partial == "" || strings.HasPrefix(sc.Name, partial) {
						candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
					}
				}
			}
		}
		if len(candidates) == 0 {
			candidates = completeFromTreeWithDesc(operationalTree, words, partial, cc.cli.store.ActiveConfig())
		}
	}
	if len(candidates) == 0 {
		return nil, 0
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })

	if len(candidates) == 1 {
		suffix := candidates[0].name[len(partial):]
		return [][]rune{[]rune(suffix + " ")}, len(partial)
	}

	// Multiple matches: show descriptions above prompt.
	writeCompletionHelp(cc.cli.rl.Stdout(), candidates)

	// Complete common prefix.
	names := make([]string, len(candidates))
	for i, c := range candidates {
		names[i] = c.name
	}
	cp := commonPrefix(names)
	suffix := cp[len(partial):]
	if suffix == "" {
		return nil, 0
	}
	return [][]rune{[]rune(suffix)}, len(partial)
}

func (c *CLI) completeConfigWithDesc(words []string, partial string) []completionCandidate {
	if len(words) == 0 {
		return filterTreeCandidates(configTopLevel, partial)
	}

	resolvedTop, ok := resolveUniqueTreePrefix(configTopLevel, words[0])
	if !ok {
		if len(words) == 1 {
			return filterTreeCandidates(configTopLevel, words[0])
		}
		return nil
	}

	switch resolvedTop {
	case "set", "delete", "show", "edit":
		pathWords := words[1:]
		if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(pathWords); resolved {
			pathWords = resolvedPath
		}
		schemaCompletions := config.CompleteSetPathWithValues(pathWords, c.valueProvider)
		if schemaCompletions == nil {
			return nil
		}
		var candidates []completionCandidate
		for _, sc := range schemaCompletions {
			if strings.HasPrefix(sc.Name, partial) {
				candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
			}
		}
		return candidates

	case "run":
		return completeFromTreeWithDesc(operationalTree, words[1:], partial, c.store.ActiveConfig())

	case "commit", "load":
		if len(words) == 1 {
			node := configTopLevel[resolvedTop]
			if node == nil || node.Children == nil {
				return nil
			}
			var candidates []completionCandidate
			for name, child := range node.Children {
				if strings.HasPrefix(name, partial) {
					candidates = append(candidates, completionCandidate{name: name, desc: child.Desc})
				}
			}
			return candidates
		}
		return nil

	default:
		return nil
	}
}

// resolveCommand performs Junos-style prefix matching.
// Given a partial input and a list of valid commands, it returns:
// - The full command name if exactly one match
// - "" and an error if ambiguous (multiple matches)
// - "" and an error if no match
func resolveCommand(input string, validCommands []string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("missing command")
	}
	// Exact match first
	for _, cmd := range validCommands {
		if cmd == input {
			return cmd, nil
		}
	}
	// Prefix match
	var matches []string
	for _, cmd := range validCommands {
		if strings.HasPrefix(cmd, input) {
			matches = append(matches, cmd)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("unknown command: %s", input)
	case 1:
		return matches[0], nil
	default:
		sort.Strings(matches)
		return "", fmt.Errorf("'%s' is ambiguous.\nPossible completions:\n%s",
			input, formatAmbiguousMatches(matches))
	}
}

func formatAmbiguousMatches(matches []string) string {
	var sb strings.Builder
	maxWidth := 0
	for _, m := range matches {
		if len(m) > maxWidth {
			maxWidth = len(m)
		}
	}
	for _, m := range matches {
		sb.WriteString(fmt.Sprintf("  %s\n", m))
	}
	return sb.String()
}

// completeFromTreeWithDesc mirrors completeFromTree but returns name+desc pairs.
func completeFromTreeWithDesc(tree map[string]*completionNode, words []string, partial string, cfg *config.Config) []completionCandidate {
	treeCands := cmdtree.CompleteFromTreeWithDesc(tree, words, partial, cfg)
	candidates := make([]completionCandidate, 0, len(treeCands))
	for _, c := range treeCands {
		candidates = append(candidates, completionCandidate{name: c.Name, desc: c.Desc})
	}
	return candidates
}

// writeCompletionHelp prints aligned completion candidates to w.
// The entire output is built as a single string and written in one call
// so that the readline wrapWriter triggers only one Refresh cycle,
// cleanly re-drawing the prompt+line below.
func writeCompletionHelp(w io.Writer, candidates []completionCandidate) {
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })
	maxWidth := 20
	for _, c := range candidates {
		if len(c.name)+2 > maxWidth {
			maxWidth = len(c.name) + 2
		}
	}
	var sb strings.Builder
	sb.WriteString("Possible completions:\n")
	for _, c := range candidates {
		if c.desc != "" {
			fmt.Fprintf(&sb, "  %-*s %s\n", maxWidth, c.name, c.desc)
		} else {
			fmt.Fprintf(&sb, "  %s\n", c.name)
		}
	}
	io.WriteString(w, sb.String())
}

// keysFromTree returns a sorted list of keys from a completionNode map.
// Delegates to cmdtree.KeysFromTree.
func keysFromTree(tree map[string]*completionNode) []string {
	return cmdtree.KeysFromTree(tree)
}

// treeHelpCandidates returns completionCandidates from a tree's children.
func treeHelpCandidates(tree map[string]*completionNode) []completionCandidate {
	candidates := make([]completionCandidate, 0, len(tree))
	for name, node := range tree {
		candidates = append(candidates, completionCandidate{name: name, desc: node.Desc})
	}
	return candidates
}

func filterTreeCandidates(tree map[string]*completionNode, prefix string) []completionCandidate {
	candidates := make([]completionCandidate, 0, len(tree))
	for name, node := range tree {
		if prefix == "" || strings.HasPrefix(name, prefix) {
			candidates = append(candidates, completionCandidate{name: name, desc: node.Desc})
		}
	}
	return candidates
}

func resolveUniqueTreePrefix(tree map[string]*completionNode, input string) (string, bool) {
	return cmdtree.ResolveUniquePrefix(keysFromTree(tree), input)
}

func showConfigurationSubPath(words []string) ([]string, bool) {
	if len(words) < 2 {
		return nil, false
	}
	show, ok := resolveUniqueTreePrefix(operationalTree, words[0])
	if !ok || show != "show" {
		return nil, false
	}
	showNode := operationalTree[show]
	if showNode == nil || showNode.Children == nil {
		return nil, false
	}
	conf, ok := resolveUniqueTreePrefix(showNode.Children, words[1])
	if !ok || conf != "configuration" {
		return nil, false
	}
	return words[2:], true
}

// commonPrefix returns the longest shared prefix among the given strings.
func commonPrefix(items []string) string {
	return cmdtree.CommonPrefix(items)
}

// pipeFilters defines the available pipe filter names and descriptions.
var pipeFilters = []completionCandidate{
	{name: "count", desc: "Count occurrences"},
	{name: "display", desc: "Show additional kinds of information"},
	{name: "except", desc: "Show only text that does not match a pattern"},
	{name: "find", desc: "Search for first occurrence of pattern"},
	{name: "grep", desc: "Show only text that matches a pattern"},
	{name: "last", desc: "Display end of output only"},
	{name: "match", desc: "Show only text that matches a pattern"},
	{name: "no-more", desc: "Don't paginate output"},
}

// completePipeFilter returns pipe filter candidates matching the partial prefix.
// Returns nil if the line doesn't contain a pipe.
func completePipeFilter(text string) (candidates []completionCandidate, handled bool) {
	idx := strings.LastIndex(text, "|")
	if idx < 0 {
		return nil, false
	}
	after := strings.TrimSpace(text[idx+1:])
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	// Right after "|" or "| " — show all filters
	if after == "" || (trailingSpace && after == "") {
		return pipeFilters, true
	}

	// If trailing space, user has already typed a complete filter name —
	// no more completion (the filter argument is freeform text).
	if trailingSpace {
		return nil, true
	}

	// Partial filter name typed
	for _, f := range pipeFilters {
		if strings.HasPrefix(f.name, after) {
			candidates = append(candidates, f)
		}
	}
	return candidates, true
}

// #1044c Phase 1: valueProvider relocated from cli.go (no behavior change).
func (c *CLI) valueProvider(hint config.ValueHint, path []string) []config.SchemaCompletion {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		return nil
	}
	switch hint {
	case config.ValueHintZoneName:
		var out []config.SchemaCompletion
		for name, zone := range cfg.Security.Zones {
			desc := zone.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
		}
		return out
	case config.ValueHintAddressName:
		var out []config.SchemaCompletion
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
			}
		}
		return out
	case config.ValueHintAppName:
		var out []config.SchemaCompletion
		for _, app := range cfg.Applications.Applications {
			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
		}
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		for name := range config.PredefinedApplications {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
		}
		return out
	case config.ValueHintAppSetName:
		var out []config.SchemaCompletion
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		return out
	case config.ValueHintPoolName:
		var out []config.SchemaCompletion
		for name := range cfg.Security.NAT.SourcePools {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "source pool"})
		}
		if cfg.Security.NAT.Destination != nil {
			for name := range cfg.Security.NAT.Destination.Pools {
				out = append(out, config.SchemaCompletion{Name: name, Desc: "destination pool"})
			}
		}
		return out
	case config.ValueHintScreenProfile:
		var out []config.SchemaCompletion
		for name := range cfg.Security.Screen {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "screen profile"})
		}
		return out
	case config.ValueHintStreamName:
		var out []config.SchemaCompletion
		for name := range cfg.Security.Log.Streams {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "log stream"})
		}
		return out
	case config.ValueHintInterfaceName:
		var out []config.SchemaCompletion
		for name, iface := range cfg.Interfaces.Interfaces {
			desc := iface.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: name, Desc: desc})
		}
		return out
	case config.ValueHintPolicyAddress:
		out := []config.SchemaCompletion{
			{Name: "any", Desc: "Any IPv4 or IPv6 address"},
			{Name: "any-ipv4", Desc: "Any IPv4 address"},
			{Name: "any-ipv6", Desc: "Any IPv6 address"},
		}
		if cfg.Security.AddressBook != nil {
			for _, addr := range cfg.Security.AddressBook.Addresses {
				out = append(out, config.SchemaCompletion{Name: addr.Name, Desc: addr.Value})
			}
			for _, as := range cfg.Security.AddressBook.AddressSets {
				out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "address-set"})
			}
		}
		return out
	case config.ValueHintPolicyApp:
		out := []config.SchemaCompletion{
			{Name: "any", Desc: "Any application"},
		}
		for _, app := range cfg.Applications.Applications {
			out = append(out, config.SchemaCompletion{Name: app.Name, Desc: app.Description})
		}
		for _, as := range cfg.Applications.ApplicationSets {
			out = append(out, config.SchemaCompletion{Name: as.Name, Desc: "application-set"})
		}
		for name := range config.PredefinedApplications {
			out = append(out, config.SchemaCompletion{Name: name, Desc: "predefined"})
		}
		return out
	case config.ValueHintPolicyName:
		// Extract zone pair from path: ["security","policies","from-zone","X","to-zone","Y","policy"]
		// or global: ["security","policies","global","policy"]
		var policies []*config.Policy
		for i, tok := range path {
			if tok == "from-zone" && i+3 < len(path) && path[i+2] == "to-zone" {
				fromZone := path[i+1]
				toZone := path[i+3]
				for _, zpp := range cfg.Security.Policies {
					if zpp.FromZone == fromZone && zpp.ToZone == toZone {
						policies = zpp.Policies
						break
					}
				}
				break
			}
			if tok == "global" {
				policies = cfg.Security.GlobalPolicies
				break
			}
		}
		var out []config.SchemaCompletion
		for _, pol := range policies {
			desc := pol.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: pol.Name, Desc: desc})
		}
		return out
	case config.ValueHintUnitNumber:
		// Find the interface name from the path context.
		var ifaceName string
		for i, tok := range path {
			if tok == "interfaces" && i+1 < len(path) {
				ifaceName = path[i+1]
				break
			}
		}
		if ifaceName == "" {
			return nil
		}
		iface := cfg.Interfaces.Interfaces[ifaceName]
		if iface == nil {
			return nil
		}
		var out []config.SchemaCompletion
		for num, unit := range iface.Units {
			desc := unit.Description
			if desc == "" {
				desc = "(configured)"
			}
			out = append(out, config.SchemaCompletion{Name: fmt.Sprintf("%d", num), Desc: desc})
		}
		return out
	}
	return nil
}
