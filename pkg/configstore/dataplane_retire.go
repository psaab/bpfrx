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

// rewriteRetiredDataplaneType walks tree looking for
// `system { dataplane-type X; }` leaves whose X is a retired
// value. Each match is removed from the tree and a structured
// WARN is logged with the operator-facing rationale.
//
// Returns the number of leaves rewritten so callers can decide
// whether to commit-persist the cleanup. Note that the rewrite
// is in-memory only; the persisted config on disk is unchanged
// until the next normal commit path runs.
//
// Safe to call with a nil tree (no-op).
//
// Tested by TestRewriteRetiredDataplaneType in this package.
func rewriteRetiredDataplaneType(tree *config.ConfigTree) int {
	if tree == nil {
		return 0
	}
	system := tree.FindChild("system")
	if system == nil {
		return 0
	}
	// Walk children, build a filtered list dropping every
	// `dataplane-type X` whose X is retired. There can in
	// principle be multiple such leaves if a config carries
	// stray duplicates; remove all of them.
	rewrites := 0
	filtered := make([]*config.Node, 0, len(system.Children))
	for _, child := range system.Children {
		if isRetiredDataplaneLeaf(child) {
			retired := child.Keys[1]
			slog.Warn(
				"persisted active-config selects retired dataplane backend; rewriting to userspace default",
				"dataplane_type", retired,
				"rationale", retiredDataplaneTypes[retired],
				"remediation", "review and `commit` after daemon comes up to persist the cleanup",
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
