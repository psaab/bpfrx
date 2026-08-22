package config

// CoSForwardingClassUndefined reports whether a class-of-service classifier,
// rewrite-rule or scheduler-map ENTRY names a forwarding-class that
// `class-of-service forwarding-classes` does not define.
//
// #6534: the userspace snapshot builder SKIPS such an entry at five sites in
// pkg/dataplane/userspace/cos.go — the DSCP, IEEE 802.1 and inet-precedence
// classifiers, the DSCP rewrite-rule, and the scheduler-map — so the object
// installs a PARTIAL table: some code points classify, the ones naming an
// undefined class do not, and shaping for that class silently degrades to
// best-effort. Every one of those objects has a `show class-of-service`
// renderer that printed the skipped entry exactly like an installed one.
//
// This is a committable, SUPPORTED config shape, not corruption: an undefined
// forwarding-class reference is only a commit-time WARNING
// (compiler_validate_warn.go), never a strict rejection. So unlike the NAT
// exclusions in nat_exclusion_reason.go — which are lenient-path-only — this
// one is reachable through an ordinary `commit`, which makes the surfaces
// lying about it more likely to be seen, not less.
//
// Callers, which must not drift (see nat_exclusion_reason.go for why the
// builder and the renderer share one predicate rather than keeping a copy
// each):
//
//  1. buildCoSSnapshots and its four sibling loops (pkg/dataplane/userspace)
//     skip the entry, and
//  2. FormatCoSClassifiers / FormatCoSRewriteRules / FormatCoSSchedulerMaps
//     (pkg/dataplane/userspace/format) annotate it as not installed.
//
// Note the deliberately narrow scope: this asks ONLY about the
// forwarding-class reference. A scheduler-map entry naming an undefined
// SCHEDULER is a different edge with the opposite disposition — the builder
// KEEPS that entry on the wire so the class's queue still materializes, and
// the Rust side degrades the scheduler rather than dropping the entry — so it
// is not an exclusion and must not be annotated as one.
//
// A nil CoS config reports false (defined / installed): callers reach this only
// with a non-nil config, and "installed" is the direction that cannot make a
// renderer annotate an entry that is in fact armed.
func CoSForwardingClassUndefined(cos *ClassOfServiceConfig, forwardingClass string) bool {
	if cos == nil {
		return false
	}
	_, ok := cos.ForwardingClasses[forwardingClass]
	return !ok
}
