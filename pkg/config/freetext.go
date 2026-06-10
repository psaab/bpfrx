package config

import (
	"fmt"
	"strings"
)

// #1798: free-text config values (interface/zone/policy descriptions,
// annotations, auth keys, IKE secrets) flow verbatim into generated
// config files — systemd-networkd units, frr.conf, swanctl.conf. The
// lexer maps the `\n` escape inside a quoted string to a real newline
// (lexer.go readString), so a value like "lan\nDHCP=ipv4" injects an
// arbitrary directive into the generated file. Two config-level layers
// defend against this:
//
//   - The STRICT compile path (CompileConfig / CompileConfigForNode,
//     reached only via commit / commit-check — Store.compileTree)
//     hard-rejects any tree value or annotation containing an ASCII
//     control character, so a new operator edit fails loudly at commit
//     time. This check deliberately does NOT live in SchemaValidate:
//     the lenient boot/peer-sync paths need the value scrubbed IN
//     PLACE, which the read-only schema walk cannot do. (Since #1319
//     PR 2, SchemaValidate violations are themselves downgraded to a
//     warning on those tolerant paths — configstore.compileTreeLenient
//     — so a bad persisted typed leaf cannot fail boot either.)
//
//   - The LENIENT compile path (CompileConfigLenient /
//     CompileConfigForNodeLenient — Store.Load, Store.SyncApply, and
//     read-only peer-interface display) sanitizes the values in place
//     with a warning instead, and the configstore migration helper
//     SanitizeTreeControlChars cleans the stored tree itself so an
//     already-persisted bad value can neither fail boot nor make the
//     operator's next unrelated commit fail mysteriously.
//
// The render-side belt (sanitizers in pkg/networkd, pkg/frr, pkg/ipsec
// at each free-text file interpolation) is the third, independent
// layer.

// hasControlChars reports whether s contains any ASCII control
// character: the full C0 set (0x00–0x1F, which includes \n, \r and \t)
// or DEL (0x7F). The byte-wise scan is correct for UTF-8 input because
// multi-byte sequences never contain bytes below 0x80.
func hasControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// sanitizeControlChars returns s with every ASCII control character
// (C0 set and DEL) replaced by a single space. Replacing rather than
// deleting keeps adjacent words readable ("lan\nDHCP=ipv4" becomes
// "lan DHCP=ipv4", not "lanDHCP=ipv4").
func sanitizeControlChars(s string) string {
	if !hasControlChars(s) {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] < 0x20 || b[i] == 0x7f {
			b[i] = ' '
		}
	}
	return string(b)
}

// joinNodePath builds a human-readable config path for error/warning
// messages. Key values are sanitized for display so a path containing
// the offending newline does not itself produce a multi-line message.
func joinNodePath(prefix string, keys []string) string {
	clean := make([]string, len(keys))
	for i, k := range keys {
		clean[i] = sanitizeControlChars(k)
	}
	joined := strings.Join(clean, " ")
	if prefix == "" {
		return joined
	}
	return prefix + " " + joined
}

// validateNodesControlChars walks the (group-expanded) AST and returns
// an error for the first value or annotation containing a control
// character. Strict commit-path only — see the package comment above.
func validateNodesControlChars(nodes []*Node, prefix string) error {
	for _, n := range nodes {
		nodePath := joinNodePath(prefix, n.Keys)
		for _, k := range n.Keys {
			if hasControlChars(k) {
				return fmt.Errorf("%s: value %q contains control characters (newlines and other control characters are not allowed in configuration values)", nodePath, k)
			}
		}
		if hasControlChars(n.Annotation) {
			return fmt.Errorf("%s: annotation %q contains control characters (newlines and other control characters are not allowed in annotations)", nodePath, n.Annotation)
		}
		if err := validateNodesControlChars(n.Children, nodePath); err != nil {
			return err
		}
	}
	return nil
}

// sanitizeNodesControlChars walks the AST replacing control characters
// in values and annotations in place, returning one human-readable
// config path per modified node. Lenient-path counterpart of
// validateNodesControlChars.
func sanitizeNodesControlChars(nodes []*Node, prefix string) []string {
	var warnings []string
	for _, n := range nodes {
		changed := false
		for i, k := range n.Keys {
			if hasControlChars(k) {
				n.Keys[i] = sanitizeControlChars(k)
				changed = true
			}
		}
		if hasControlChars(n.Annotation) {
			n.Annotation = sanitizeControlChars(n.Annotation)
			changed = true
		}
		nodePath := joinNodePath(prefix, n.Keys)
		if changed {
			warnings = append(warnings, nodePath)
		}
		warnings = append(warnings, sanitizeNodesControlChars(n.Children, nodePath)...)
	}
	return warnings
}

// SanitizeTreeControlChars replaces ASCII control characters (C0 set
// and DEL) with spaces in every value and annotation of the tree, in
// place, and returns one human-readable config path per modified node.
//
// This is the #1798 migration helper for the tolerant ingest paths
// (Store.Load on boot, Store.SyncApply on HA peer-sync): it cleans the
// tree that will become the active/candidate config so an
// already-persisted bad value cannot fail boot now or fail the
// operator's next unrelated strict commit later. Callers should log
// each returned path as a warning.
func SanitizeTreeControlChars(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	return sanitizeNodesControlChars(tree.Children, "")
}
