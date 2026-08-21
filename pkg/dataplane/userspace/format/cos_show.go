package format

// #4228 Gap 7: Junos-style CoS `show` command formatters. These render the
// four vSRX class-of-service operational commands whose backing data already
// exists but had no operational-tree surface:
//
//   - `show interfaces queue [<interface>]`      (from CoSQueueStatus)
//   - `show class-of-service classifier ...`     (from cfg.ClassOfService)
//   - `show class-of-service scheduler-map [n]`  (from cfg.ClassOfService)
//   - `show class-of-service forwarding-class`   (from cfg.ClassOfService)
//   - `show class-of-service rewrite-rule ...`   (from cfg.ClassOfService)
//
// The renderers reuse the shared helpers in cos.go (formatCoSRate,
// formatCoSBytes, emptyDash, yesNo). No dataplane change — the four commands
// are pure presentation over data the config compiler and userspace status
// already carry.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/psaab/xpf/pkg/config"
	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// FormatInterfacesQueue renders `show interfaces queue [<interface>]` from the
// live userspace CoS runtime snapshot. Junos reports per-egress-queue Queued /
// Transmitted / Dropped counters; xpf sources the equivalent fields from
// CoSQueueStatus (QueuedPackets/Bytes, DrainSentBytes, the admission-drop
// counters aggregated across worker instances by the Rust coordinator). An
// empty selector renders every CoS interface reported by the dataplane.
//
// The renderer distinguishes three states so operator uncertainty is never
// laundered into "no CoS" (#5326):
//
//   - statusErr != nil — the status fetch FAILED (helper down, control socket
//     unavailable, decode error). The CoS runtime state is UNKNOWN, not empty,
//     so surface the error instead of the empty-snapshot message. This upholds
//     the appliance invariant that uncertainty must not render as zero/empty
//     health.
//   - statusErr == nil, empty snapshot — a legitimately empty CoS runtime;
//     render the "No class-of-service queues active" message unchanged.
//   - statusErr == nil, non-empty snapshot — render the per-queue counters.
//
// Callers MUST pass the error returned alongside the status snapshot; a nil
// status with a nil error is still treated as the legitimate empty case.
func FormatInterfacesQueue(status *userspace.ProcessStatus, statusErr error, selector string) string {
	selector = strings.TrimSpace(selector)
	if statusErr != nil {
		if selector == "" {
			return fmt.Sprintf("error retrieving class-of-service queue status: %v\n", statusErr)
		}
		return fmt.Sprintf("error retrieving class-of-service queue status on %s: %v\n", selector, statusErr)
	}
	if status == nil || len(status.CoSInterfaces) == 0 {
		if selector == "" {
			return "No class-of-service queues active\n"
		}
		return fmt.Sprintf("No class-of-service queues active on %s\n", selector)
	}

	ifaces := make([]userspace.CoSInterfaceStatus, 0, len(status.CoSInterfaces))
	for _, iface := range status.CoSInterfaces {
		if selector != "" && !cosInterfaceMatchesSelector(iface.InterfaceName, selector) {
			continue
		}
		ifaces = append(ifaces, iface)
	}
	if len(ifaces) == 0 {
		return fmt.Sprintf("No class-of-service queues active on %s\n", selector)
	}
	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].InterfaceName < ifaces[j].InterfaceName })

	var b strings.Builder
	for idx, iface := range ifaces {
		if idx > 0 {
			b.WriteString("\n")
		}
		name := iface.InterfaceName
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(&b, "Physical interface: %s\n", name)
		queues := append([]userspace.CoSQueueStatus(nil), iface.Queues...)
		sort.Slice(queues, func(i, j int) bool { return queues[i].QueueID < queues[j].QueueID })
		// vSRX egress-queue space is 3-bit (queue IDs 0..7); report the
		// in-use count against that supported ceiling.
		fmt.Fprintf(&b, "  Egress queues: 8 supported, %d in use\n", len(queues))
		if len(queues) == 0 {
			b.WriteString("  No egress queues\n")
			continue
		}
		for _, q := range queues {
			fmt.Fprintf(&b, "  Queue: %d, Forwarding classes: %s\n", q.QueueID, emptyDash(q.ForwardingClass))
			b.WriteString("    Queued:\n")
			fmt.Fprintf(&b, "      Packets              : %20d\n", q.QueuedPackets)
			fmt.Fprintf(&b, "      Bytes                : %20d\n", q.QueuedBytes)
			b.WriteString("    Transmitted:\n")
			fmt.Fprintf(&b, "      Bytes                : %20d\n", q.DrainSentBytes)
			b.WriteString("    Dropped:\n")
			fmt.Fprintf(&b, "      Buffer-drop packets  : %20d\n", q.AdmissionBufferDrops)
			fmt.Fprintf(&b, "      Flow-share packets   : %20d\n", q.AdmissionFlowShareDrops)
			fmt.Fprintf(&b, "      ECN-marked packets   : %20d\n", q.AdmissionEcnMarked)
		}
	}
	return b.String()
}

// cosInterfaceMatchesSelector matches a runtime CoS interface name against an
// operator-supplied selector, tolerant of the vSRX-style name, its Linux
// kernel name, and a physical-name prefix of a unit-qualified runtime label
// (e.g. selector "ge-0-0-2" matches runtime "ge-0-0-2.80").
func cosInterfaceMatchesSelector(name, selector string) bool {
	if name == "" {
		return false
	}
	if name == selector || config.LinuxIfName(name) == selector {
		return true
	}
	return strings.HasPrefix(name, selector+".") ||
		strings.HasPrefix(config.LinuxIfName(name), selector+".")
}

// FormatCoSClassifiers renders `show class-of-service classifier [name <n>]
// [type <dscp|ieee-802.1>]` from the compiled classifiers. DSCP code points
// render as 6-bit binary and 802.1p PCP as 3-bit binary, matching the vSRX
// "Code point" column. A queue's loss priority defaults to "low" (the Junos
// classifier default) when the config omits it.
func FormatCoSClassifiers(cfg *config.Config, nameFilter, typeFilter string) string {
	if cfg == nil || cfg.ClassOfService == nil {
		return "No class-of-service classifiers configured\n"
	}
	cos := cfg.ClassOfService
	nameFilter = strings.TrimSpace(nameFilter)
	typeFilter = strings.TrimSpace(strings.ToLower(typeFilter))

	type cpRow struct {
		value uint16
		bits  int
		fc    string
		lp    string
	}
	type classifierBlock struct {
		name   string
		cpType string
		rows   []cpRow
	}
	var blocks []classifierBlock

	if typeFilter == "" || typeFilter == "dscp" {
		for _, name := range sortedMapKeys(cos.DSCPClassifiers) {
			if nameFilter != "" && name != nameFilter {
				continue
			}
			c := cos.DSCPClassifiers[name]
			blk := classifierBlock{name: name, cpType: "dscp"}
			for _, e := range c.Entries {
				for _, dscp := range e.DSCPValues {
					blk.rows = append(blk.rows, cpRow{
						value: uint16(dscp),
						bits:  6,
						fc:    e.ForwardingClass,
						lp:    lossPriorityOrDefault(e.LossPriority),
					})
				}
			}
			blocks = append(blocks, blk)
		}
	}
	if typeFilter == "" || typeFilter == "ieee-802.1" {
		for _, name := range sortedMapKeys(cos.IEEE8021Classifiers) {
			if nameFilter != "" && name != nameFilter {
				continue
			}
			c := cos.IEEE8021Classifiers[name]
			blk := classifierBlock{name: name, cpType: "ieee-802.1"}
			for _, e := range c.Entries {
				for _, cp := range e.CodePoints {
					blk.rows = append(blk.rows, cpRow{
						value: uint16(cp),
						bits:  3,
						fc:    e.ForwardingClass,
						lp:    lossPriorityOrDefault(e.LossPriority),
					})
				}
			}
			blocks = append(blocks, blk)
		}
	}

	if len(blocks) == 0 {
		if nameFilter != "" || typeFilter != "" {
			return "No class-of-service classifier matches the given filter\n"
		}
		return "No class-of-service classifiers configured\n"
	}

	var b strings.Builder
	for idx, blk := range blocks {
		if idx > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Classifier: %s, Code point type: %s\n", blk.name, blk.cpType)
		sort.SliceStable(blk.rows, func(i, j int) bool { return blk.rows[i].value < blk.rows[j].value })
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  Code point\tForwarding class\tLoss priority")
		for _, r := range blk.rows {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n",
				codePointBinary(r.value, r.bits), emptyDash(r.fc), r.lp)
		}
		_ = tw.Flush()
	}
	return b.String()
}

// CoSRewriteRuleTypes is the set of `type` filter values FormatCoSRewriteRules
// accepts, in the order rules are rendered. It is exported so the cmdtree
// `type` completion node can be checked against it across the package
// boundary.
//
// It is NOT the SSOT, and the comment that used to say so was false in the
// load-bearing direction (#6858). The family list exists in three places: these
// values, the cmdtree `type` completion children, and the renderer's own
// hardcoded per-family branches below — and nothing in the renderer reads this
// variable, so pinning it against cmdtree alone was a closed loop that a
// deleted renderer branch walked straight through.
//
// The authority is the config schema: schemaClassOfService["rewrite-rules"]
// children in pkg/config/schema_cos.go, which is what an operator can commit.
// pkg/config cannot import this package (format imports config), so the
// three-way check lives in pkg/cmdtree, which can see all of them:
// TestCoSRewriteRuleTypeChildrenMatchRenderer holds these values and the
// completion children against the schema, and
// TestCoSRewriteRuleRendererCoversEverySchemaFamily renders a committed rule of
// every schema family, which is the only way to observe the branches.
var CoSRewriteRuleTypes = []string{"dscp", "ieee-802.1", "inet-precedence", "exp"}

// cosBoundDSCPRewriteRules returns the set of dscp rewrite-rule NAMES that at
// least one logical unit actually binds (#6858 fold).
//
// Scanning Units alone is sufficient and is not an oversight: the compiler
// folds an interface-level binding into every configured unit
// (applyCoSInterfaceLevelBindings), which `CoSInterface.Level` documents —
// "the dataplane snapshot and `show class-of-service` — which both iterate
// Units — need no interface-level awareness".
func cosBoundDSCPRewriteRules(cfg *config.Config) map[string]bool {
	bound := map[string]bool{}
	if cfg == nil || cfg.ClassOfService == nil {
		return bound
	}
	for _, iface := range cfg.ClassOfService.Interfaces {
		if iface == nil {
			continue
		}
		for _, unit := range iface.Units {
			if unit == nil || unit.DSCPRewriteRule == "" {
				continue
			}
			bound[unit.DSCPRewriteRule] = true
		}
	}
	return bound
}

// cosRewriteRuleEnforcement renders the `Enforced:` value for one rewrite rule.
//
// There are THREE states, not two, and collapsing the middle one into
// "enforced" is the defect this function exists to prevent (#6858 gate MAJOR):
//
//  1. `dscp` AND bound by some unit — actually applied on egress.
//  2. `dscp` and bound by NOTHING — configured, but no runtime effect. The
//     rewrite table is populated only for the rule an interface references
//     (`tables.dscp_rewrite_rules.get(&iface.cos_dscp_rewrite_rule)`,
//     forwarding_build/cos.rs), so an unbound rule rewrites nothing.
//  3. Any other code-point type — the dataplane rewrites dscp only. Each
//     carries an accepted-but-inert commit advisory
//     (compiler_validate_warn.go: ieee-802.1 :1360, inet-precedence :1346,
//     exp :1350) that fires ONCE at commit.
//
// State 2 was originally reported as state 1: an unbound rule printed
// "Enforced: yes". That is strictly worse than having no command, because it
// converts an unanswered question into a confidently wrong answer — and it is
// the accepted-but-inert failure class one level in, inside the very command
// written to expose that class.
//
// For an unsupported TYPE the type reason is reported even if the rule also
// happens to be unbound: the type is the dominant, actionable fact, and such a
// rule would not act however it were bound.
//
// A type that starts being enforced must flip here in the SAME change that
// drops its commit advisory, or this command reports a working rewrite as
// inert. That is not left to a comment — see
// TestCoSInertAdvisoryAgreesWithRenderedEnforcement6858, which asserts the
// biconditional over every committable family: the commit emits an
// accepted-but-inert advisory if and only if this function returns the
// unsupported-TYPE reason. Deleting an advisory without flipping this function
// reds, and flipping this function without dropping the advisory reds too.
func cosRewriteRuleEnforcement(cpType string, bound bool) string {
	if cpType != "dscp" {
		return "no (accepted for Junos compatibility; the dataplane rewrites dscp only)"
	}
	if !bound {
		return "no (not bound — no interface unit references this rule)"
	}
	return "yes"
}

// FormatCoSRewriteRules renders `show class-of-service rewrite-rule [name <n>]
// [type <t>]` from the compiled config (#6848, #4228 Gap 7 residual).
//
// Four rewrite-rule families are modeled, and they do NOT all carry the same
// depth of data — the renderer must not paper over that:
//
//   - `dscp` and `ieee-802.1` compile to full entry lists
//     (forwarding-class, loss-priority, code-point), so their code points are
//     rendered.
//   - `inet-precedence` and `exp` record only rule NAMES
//     (ClassOfServiceConfig.INetPrecedenceRewriteRules / EXPRewriteRules,
//     #4316) — the compiler builds no runtime structure for them because
//     nothing consumes one. There are no code points to print, and inventing a
//     table for them would imply a fidelity the config does not have, so they
//     render as a name + an explicit "code points not modeled" line.
//
// A nil/empty config yields the Junos-style "no rules configured" line rather
// than an error: an unconfigured rewrite-rule set is a normal state.
func FormatCoSRewriteRules(cfg *config.Config, nameFilter, typeFilter string) string {
	if cfg == nil || cfg.ClassOfService == nil {
		return "No class-of-service rewrite-rules configured\n"
	}
	cos := cfg.ClassOfService
	nameFilter = strings.TrimSpace(nameFilter)
	typeFilter = strings.TrimSpace(strings.ToLower(typeFilter))

	type cpRow struct {
		fc    string
		lp    string
		value uint16
		bits  int
	}
	type ruleBlock struct {
		name   string
		cpType string
		rows   []cpRow
		// modeled is false for the name-only families: the block renders its
		// header and an explanatory line instead of an empty code-point table.
		modeled bool
	}
	var blocks []ruleBlock

	wantType := func(t string) bool { return typeFilter == "" || typeFilter == t }
	wantName := func(n string) bool { return nameFilter == "" || n == nameFilter }

	if wantType("dscp") {
		for _, name := range sortedMapKeys(cos.DSCPRewriteRules) {
			if !wantName(name) {
				continue
			}
			blk := ruleBlock{name: name, cpType: "dscp", modeled: true}
			for _, e := range cos.DSCPRewriteRules[name].Entries {
				if e == nil {
					continue
				}
				blk.rows = append(blk.rows, cpRow{
					fc: e.ForwardingClass, lp: lossPriorityOrDefault(e.LossPriority),
					value: uint16(e.DSCPValue), bits: 6,
				})
			}
			blocks = append(blocks, blk)
		}
	}
	if wantType("ieee-802.1") {
		for _, name := range sortedMapKeys(cos.IEEE8021RewriteRules) {
			if !wantName(name) {
				continue
			}
			blk := ruleBlock{name: name, cpType: "ieee-802.1", modeled: true}
			for _, e := range cos.IEEE8021RewriteRules[name].Entries {
				if e == nil {
					continue
				}
				blk.rows = append(blk.rows, cpRow{
					fc: e.ForwardingClass, lp: lossPriorityOrDefault(e.LossPriority),
					value: uint16(e.PCPValue), bits: 3,
				})
			}
			blocks = append(blocks, blk)
		}
	}
	// Name-only families. Sorted independently so the output order is stable
	// regardless of config-file order (the slices preserve parse order).
	appendNameOnly := func(cpType string, names []string) {
		if !wantType(cpType) {
			return
		}
		sorted := append([]string(nil), names...)
		sort.Strings(sorted)
		for _, name := range sorted {
			if !wantName(name) {
				continue
			}
			blocks = append(blocks, ruleBlock{name: name, cpType: cpType})
		}
	}
	appendNameOnly("inet-precedence", cos.INetPrecedenceRewriteRules)
	appendNameOnly("exp", cos.EXPRewriteRules)

	if len(blocks) == 0 {
		if nameFilter != "" || typeFilter != "" {
			return "No class-of-service rewrite-rule matches the given filter\n"
		}
		return "No class-of-service rewrite-rules configured\n"
	}

	boundDSCP := cosBoundDSCPRewriteRules(cfg)

	var b strings.Builder
	for idx, blk := range blocks {
		if idx > 0 {
			b.WriteString("\n")
		}
		// Say what the operator loses, not just that a flag is off. This line
		// is the whole point of the command: it answers "will this rule act?".
		enforced := cosRewriteRuleEnforcement(blk.cpType, boundDSCP[blk.name])
		fmt.Fprintf(&b, "Rewrite rule: %s, Code point type: %s, Enforced: %s\n",
			blk.name, blk.cpType, enforced)
		if !blk.modeled {
			fmt.Fprintf(&b, "  Code points not modeled — only the rule name is recorded\n")
			continue
		}
		sort.SliceStable(blk.rows, func(i, j int) bool {
			if blk.rows[i].fc != blk.rows[j].fc {
				return blk.rows[i].fc < blk.rows[j].fc
			}
			return blk.rows[i].lp < blk.rows[j].lp
		})
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  Forwarding class\tLoss priority\tCode point")
		for _, r := range blk.rows {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n",
				emptyDash(r.fc), r.lp, codePointBinary(r.value, r.bits))
		}
		_ = tw.Flush()
	}
	return b.String()
}

// FormatCoSSchedulerMaps renders `show class-of-service scheduler-map [<name>]`
// from the compiled scheduler-maps, resolving each forwarding-class binding to
// its scheduler knobs (transmit rate, priority, buffer, exact) and the queue
// the forwarding class maps to.
func FormatCoSSchedulerMaps(cfg *config.Config, nameFilter string) string {
	if cfg == nil || cfg.ClassOfService == nil || len(cfg.ClassOfService.SchedulerMaps) == 0 {
		return "No class-of-service scheduler-maps configured\n"
	}
	cos := cfg.ClassOfService
	nameFilter = strings.TrimSpace(nameFilter)

	var b strings.Builder
	rendered := 0
	for _, name := range sortedMapKeys(cos.SchedulerMaps) {
		if nameFilter != "" && name != nameFilter {
			continue
		}
		sm := cos.SchedulerMaps[name]
		if rendered > 0 {
			b.WriteString("\n")
		}
		rendered++
		fmt.Fprintf(&b, "Scheduler map: %s\n", name)

		type mapRow struct {
			fc    string
			queue int
			hasQ  bool
		}
		rows := make([]mapRow, 0, len(sm.Entries))
		for fc := range sm.Entries {
			row := mapRow{fc: fc}
			if class := cos.ForwardingClasses[fc]; class != nil {
				row.queue = class.Queue
				row.hasQ = true
			}
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].hasQ != rows[j].hasQ {
				return rows[i].hasQ // configured-queue rows first
			}
			if rows[i].hasQ && rows[i].queue != rows[j].queue {
				return rows[i].queue < rows[j].queue
			}
			return rows[i].fc < rows[j].fc
		})

		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  Forwarding class\tScheduler\tQueue\tPriority\tTransmit rate\tBuffer\tExact")
		for _, row := range rows {
			entry := sm.Entries[row.fc]
			queue := "-"
			if row.hasQ {
				queue = strconv.Itoa(row.queue)
			}
			schedName := "-"
			priority := "-"
			rate := "-"
			buffer := "-"
			exact := "no"
			if entry != nil {
				schedName = emptyDash(entry.Scheduler)
				if sched := cos.Schedulers[entry.Scheduler]; sched != nil {
					if sched.Priority != "" {
						priority = sched.Priority
					}
					rate = formatCoSRate(sched.TransmitRateBytes)
					buffer = formatSchedulerBuffer(sched)
					exact = yesNo(sched.TransmitRateExact)
				}
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				emptyDash(row.fc), schedName, queue, priority, rate, buffer, exact)
		}
		_ = tw.Flush()
	}
	if rendered == 0 {
		return fmt.Sprintf("No class-of-service scheduler-map matches %s\n", nameFilter)
	}
	return b.String()
}

// FormatCoSForwardingClasses renders `show class-of-service forwarding-class`
// — the forwarding-class -> queue table. xpf's forwarding-class ID is its
// queue number (the FC<->queue bijection enforced by the compiler), so ID and
// Queue render identically.
func FormatCoSForwardingClasses(cfg *config.Config) string {
	if cfg == nil || cfg.ClassOfService == nil || len(cfg.ClassOfService.ForwardingClasses) == 0 {
		return "No class-of-service forwarding-classes configured\n"
	}
	classes := make([]*config.CoSForwardingClass, 0, len(cfg.ClassOfService.ForwardingClasses))
	for _, c := range cfg.ClassOfService.ForwardingClasses {
		classes = append(classes, c)
	}
	sort.Slice(classes, func(i, j int) bool {
		if classes[i].Queue != classes[j].Queue {
			return classes[i].Queue < classes[j].Queue
		}
		return classes[i].Name < classes[j].Name
	})

	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "Forwarding class\tID\tQueue")
	for _, c := range classes {
		fmt.Fprintf(tw, "%s\t%d\t%d\n", emptyDash(c.Name), c.Queue, c.Queue)
	}
	_ = tw.Flush()
	return b.String()
}

// formatSchedulerBuffer renders a scheduler's buffer sizing for display: an
// explicit byte size, the Junos percent form, or "-" when unset.
func formatSchedulerBuffer(sched *config.CoSScheduler) string {
	if sched == nil {
		return "-"
	}
	if sched.BufferSizeBytes > 0 {
		return formatCoSBytes(sched.BufferSizeBytes)
	}
	if sched.BufferSizePercent > 0 {
		return strconv.FormatFloat(sched.BufferSizePercent, 'f', -1, 64) + "%"
	}
	return "-"
}

// codePointBinary renders a classifier code point as a fixed-width binary
// string (6 bits for DSCP, 3 bits for IP precedence / 802.1p), matching the
// vSRX "Code point" column.
func codePointBinary(value uint16, bits int) string {
	return fmt.Sprintf("%0*b", bits, value)
}

// lossPriorityOrDefault returns the configured loss priority, defaulting to
// "low" (the Junos classifier default) when the config omits it.
func lossPriorityOrDefault(lp string) string {
	if strings.TrimSpace(lp) == "" {
		return "low"
	}
	return lp
}

// sortedMapKeys returns the keys of a string-keyed map in sorted order.
func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
