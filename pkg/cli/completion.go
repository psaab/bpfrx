package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/psaab/bpfrx/pkg/cmdtree"
	"github.com/psaab/bpfrx/pkg/config"
)

// completionCandidate holds a command name and its description.
type completionCandidate struct {
	name string
	desc string
}

// completeFromTreeWithDesc mirrors completeFromTree but returns name+desc pairs.
func completeFromTreeWithDesc(tree map[string]*completionNode, words []string, partial string, cfg *config.Config) []completionCandidate {
	current := tree
	var currentNode *completionNode
	dynamicConsumed := false // true when last word was a dynamic value
	for wi, w := range words {
		dynamicConsumed = false
		node, ok := current[w]
		if !ok {
			if currentNode != nil && currentNode.HasDynamic() {
				dynamicConsumed = true
				continue
			}
			return nil
		}
		currentNode = node
		if node.Children == nil {
			if node.HasDynamic() && wi < len(words)-1 {
				dynamicConsumed = true
				continue
			}
			if node.HasDynamic() && cfg != nil {
				var candidates []completionCandidate
				for _, name := range node.DynamicValues(cfg, words) {
					if strings.HasPrefix(name, partial) {
						candidates = append(candidates, completionCandidate{name: name, desc: "(configured)"})
					}
				}
				return candidates
			}
			return nil
		}
		current = node.Children
	}

	var candidates []completionCandidate
	for name, node := range current {
		if strings.HasPrefix(name, partial) {
			candidates = append(candidates, completionCandidate{name: name, desc: node.Desc})
		}
	}
	if !dynamicConsumed && currentNode != nil && currentNode.HasDynamic() && cfg != nil {
		for _, name := range currentNode.DynamicValues(cfg, words) {
			if strings.HasPrefix(name, partial) {
				candidates = append(candidates, completionCandidate{name: name, desc: "(configured)"})
			}
		}
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
