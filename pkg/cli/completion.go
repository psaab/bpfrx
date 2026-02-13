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
	for _, w := range words {
		node, ok := current[w]
		if !ok {
			return nil
		}
		currentNode = node
		if node.Children == nil {
			if node.DynamicFn != nil && cfg != nil {
				var candidates []completionCandidate
				for _, name := range node.DynamicFn(cfg) {
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
	if currentNode != nil && currentNode.DynamicFn != nil && cfg != nil {
		for _, name := range currentNode.DynamicFn(cfg) {
			if strings.HasPrefix(name, partial) {
				candidates = append(candidates, completionCandidate{name: name, desc: "(configured)"})
			}
		}
	}
	return candidates
}

// writeCompletionHelp prints aligned completion candidates to w.
func writeCompletionHelp(w io.Writer, candidates []completionCandidate) {
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })
	maxWidth := 20
	for _, c := range candidates {
		if len(c.name)+2 > maxWidth {
			maxWidth = len(c.name) + 2
		}
	}
	fmt.Fprintln(w, "Possible completions:")
	for _, c := range candidates {
		if c.desc != "" {
			fmt.Fprintf(w, "  %-*s %s\n", maxWidth, c.name, c.desc)
		} else {
			fmt.Fprintf(w, "  %s\n", c.name)
		}
	}
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
