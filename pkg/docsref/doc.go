// Package docsref hosts the repo-wide dangling documentation-citation gate.
//
// It contains no runtime code. Like pkg/refactoraudit, its sole purpose is to
// give `go test ./...` a home for a property that is global to the repository
// rather than local to any one package.
//
// # The property
//
// Production source, module READMEs and design docs cite research and PR plans
// by path (docs/research/<slug>/plan.md, docs/pr/<slug>/plan.md). Those are not
// decorative: a reader who hits a non-obvious invariant follows the citation to
// learn WHY the code is shaped that way. When the cited path does not exist on
// master — because the plan lives only on an unmerged branch, or was renamed —
// the rationale is unreachable, and the next engineer either re-derives it or
// changes the code believing no rationale exists.
//
// #6615 was filed after that produced a real, compounding defect: a shipped
// README cited a plan that existed only on an unmerged branch, AND the claim
// that plan carried was wrong, and the wrong claim is what kept an issue
// deferred. An unreachable citation is bad; an unreachable citation carrying a
// wrong claim is how a bug stays parked.
//
// pkg/api/zone_counter_doc_ref_test.go already guarded exactly ONE such
// reference, written after it happened for #3643. The class is repo-wide, so
// the guard is too.
//
// # Why a baseline rather than a clean gate
//
// The issue named six dangling citations. A sweep at the time this package
// landed found ONE HUNDRED AND TWELVE distinct dangling paths across 191
// (citing-file, cited-path) pairs — the enumeration in the issue was a floor,
// not a census. Most point at research that was never merged, so there is no
// correct path to substitute and no honest way to repair them in bulk without
// inventing content.
//
// So the gate is a RATCHET, not a clean assertion:
//
//   - a citation to a path that does not exist and is NOT in the baseline
//     fails — no NEW rot can land;
//   - a baseline entry that now RESOLVES fails, demanding its removal, so the
//     census tightens as plans merge and never silently over-permits;
//   - a baseline entry nothing cites any more fails, so the file cannot
//     accumulate dead grandfathering.
//
// The baseline (testdata/known_dangling.txt) is therefore also the thing the
// issue observed was missing: a checkable, enumerated list of where the
// codebase's explanation of itself is unreachable.
package docsref
