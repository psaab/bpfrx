// Package configstore: rewriteRetiredDataplaneType bridges the gap
// between the strict commit-time validator (which rejects retired
// dataplane backends) and the persisted-config / peer-sync Load
// paths (which must tolerate retired values so an operational node
// boots through the migration window).
//
// Both #1525 (DPDK) and #1373 (legacy eBPF) intentionally keep
// dpdk and ebpf as recognized parser tokens so old configs do not
// syntax-error. After the commit-time validator landed, two
// load-time surfaces still call CompileConfig on a raw tree with
// no sentinel pre-handling:
//
//   - Store.Load() — local boot reads the persisted active config
//     from disk. Without this rewrite, daemon startup hits
//     ErrEBPFDataplaneRetired / ErrDPDKDataplaneRetired inside
//     compileTree, returns nil compiled, and bootstraps from the
//     text-config file (which may carry the same retired value)
//     or starts with an empty config — operational blackout.
//
//   - Store.SyncApply() — HA peer-sync ingress. The standby
//     receives a config text from the primary, parses it, and
//     compiles it. If the primary is un-upgraded and still
//     persists the retired value, the standby fails sync in a
//     retry loop. AGY r4 surfaced this as the symmetric path
//     that Store.Load() alone does not cover.
//
// The rewrite runs after parse, before compile: it walks the
// `system { dataplane-type X }` leaf, and if X is a retired value
// it removes the leaf entirely. The compiler then sees empty
// system.dataplane-type which EffectiveType resolves to userspace.
// A loud slog.Warn fires per rewritten retired value so operators
// see the migration recommendation in journald.
//
// Once the operator commits any change, the persisted tree no
// longer carries the retired leaf; the rewrite becomes a no-op.
package configstore

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

// retiredDataplaneTypes lists dataplane-type values that the parser
// still accepts (so historical configs don't fail to parse) but
// that the runtime cannot satisfy after their retirement phases.
//
// Each entry: the literal token operators may have persisted, plus
// a one-line operator-facing rationale used in slog.Warn output.
var retiredDataplaneTypes = map[string]string{
	"dpdk": "DPDK dataplane retired (see #1525); rewriting to userspace default",
	"ebpf": "legacy eBPF dataplane retired (see #1373); rewriting to userspace default",
}

// rewriteRetiredDataplaneType walks tree looking for any
// `system { dataplane-type X; }` leaf whose X is a retired
// value. Each match is removed from the tree and a structured
// WARN is logged with the operator-facing rationale.
//
// The walk inspects BOTH:
//
//  1. The top-level `system` node (the common case).
//  2. Any `system { ... }` node nested inside a
//     `groups { <groupName> { ... } }` definition. Without this
//     second pass, a config that hides the retired value behind
//     `apply-groups <name>` slips through the rewrite and trips
//     `validateDataplaneTypeStrict` inside `compileExpanded`
//     (which runs against the post-expansion tree). Codex r1 of
//     PR #1558 surfaced this gap.
//
// Both passes are needed even though `compileTree` later expands
// groups, because the rewrite runs BEFORE compile and the canary
// is whether the rewritten tree compiles cleanly without firing
// the retirement-strict validator.
//
// `caller` selects the log-message phrasing so operators see the
// right remediation hint depending on which Store entry point
// invoked the rewrite:
//
//   - LoadCaller ("Store.Load()"):       review and `commit` locally.
//   - SyncCaller ("Store.SyncApply()"):  update the un-upgraded
//     primary's config so HA sync converges cleanly.
//
// Returns the number of leaves rewritten. The rewrite is
// in-memory only; the persisted config on disk is unchanged
// until the next normal commit path runs.
//
// Safe to call with a nil tree (no-op).
//
// Tested by TestRewriteRetiredDataplaneType in this package.
func rewriteRetiredDataplaneType(tree *config.ConfigTree, caller retireRewriteCaller) int {
	if tree == nil {
		return 0
	}
	rewrites := 0

	// Pass 1: top-level `system` node.
	if system := tree.FindChild("system"); system != nil {
		rewrites += rewriteRetiredLeavesIn(system, caller)
	}

	// Pass 2: every `system { ... }` block nested inside a
	// `groups { <name> { ... } }` definition. The AST shape is:
	//
	//   tree.Children:
	//     Node{Keys: ["groups"]}
	//       .Children: [Node{Keys: ["legacy"]} ...]
	//                     .Children: [Node{Keys: ["system"]}]
	//                                   .Children: [Node{Keys: ["dataplane-type", "ebpf"]}]
	//
	// Walk into groups → group-name → system → leaf.
	if groupsRoot := tree.FindChild("groups"); groupsRoot != nil {
		for _, group := range groupsRoot.Children {
			if group == nil {
				continue
			}
			groupSystem := group.FindChild("system")
			if groupSystem == nil {
				continue
			}
			rewrites += rewriteRetiredLeavesIn(groupSystem, caller)
		}
	}

	return rewrites
}

// rewriteRetiredLeavesIn drops every `dataplane-type X` leaf whose
// X is in the retired set from the given system-shaped node, and
// logs a WARN per match. Returns the count.
func rewriteRetiredLeavesIn(system *config.Node, caller retireRewriteCaller) int {
	if system == nil {
		return 0
	}
	rewrites := 0
	filtered := make([]*config.Node, 0, len(system.Children))
	for _, child := range system.Children {
		if isRetiredDataplaneLeaf(child) {
			retired := child.Keys[1]
			slog.Warn(
				caller.warnMessage(),
				"dataplane_type", retired,
				"rationale", retiredDataplaneTypes[retired],
				"remediation", caller.remediation(),
			)
			rewrites++
			continue
		}
		filtered = append(filtered, child)
	}
	if rewrites > 0 {
		system.Children = filtered
	}
	return rewrites
}

// isRetiredDataplaneLeaf reports whether child is a
// `dataplane-type X` leaf whose X is in the retired set.
func isRetiredDataplaneLeaf(child *config.Node) bool {
	if child == nil || len(child.Keys) < 2 {
		return false
	}
	if child.Keys[0] != "dataplane-type" {
		return false
	}
	_, ok := retiredDataplaneTypes[child.Keys[1]]
	return ok
}

// retireRewriteCaller tags which Store entry point invoked the
// rewrite so the log message and remediation hint can address the
// right operator audience. Codex r1 of PR #1558 flagged that a
// generic "review and commit" message is wrong on the SyncApply
// path: the upgraded standby cannot fix the persisted config of an
// un-upgraded primary by committing locally.
type retireRewriteCaller int

const (
	// LoadCaller: rewrite invoked from Store.Load() during local
	// daemon boot. Operator remediation is local: `commit` after
	// startup to persist the cleanup.
	LoadCaller retireRewriteCaller = iota

	// SyncCaller: rewrite invoked from Store.SyncApply() during
	// HA peer-sync ingress. The retired value originated on the
	// un-upgraded primary, so local `commit` is insufficient —
	// the operator must update the primary's config so future
	// sync rounds converge cleanly.
	SyncCaller
)

func (c retireRewriteCaller) warnMessage() string {
	switch c {
	case SyncCaller:
		return "HA peer-synced config selects retired dataplane backend; rewriting to userspace default before compile"
	default:
		return "persisted active-config selects retired dataplane backend; rewriting to userspace default"
	}
}

func (c retireRewriteCaller) remediation() string {
	switch c {
	case SyncCaller:
		return "the un-upgraded primary is still pushing the retired value; update its config and `commit` there so future sync rounds converge"
	default:
		return "review and `commit` after daemon comes up to persist the cleanup"
	}
}
