package daemon

import (
	"fmt"
	"log/slog"
	"reflect"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// #5858: an established transit session does NOT get re-evaluated against a
// newly attached or tightened interface INPUT firewall filter.
//
// The session-hit fast path re-evaluates an input filter only when its match
// semantics genuinely vary per packet — `interface_input_filter_varies_per_packet`
// in the Rust dataplane, i.e. DSCP or per-packet L4 terms. A purely STATIC
// address/protocol/port `then discard` added after a session was created is
// never rechecked, so that flow keeps forwarding until it idles out.
//
// The asymmetry is the sharp part: tightening a *policy* revokes established
// sessions at commit (clearSessionsForPolicyChanges — the #4234 deletion clear,
// the modified-policy re-eval, the #4342 default-policy clear), and tightening
// an interface *filter* does not, though the exposure is the same class.
//
// WHY THIS IS AN ADVISORY AND NOT THE POLICY-STYLE CLEAR. The obvious symmetry
// — reuse clearSessionsForPolicyIDs, keyed on interface instead of policy — is
// not safe, for a reason established by two rounds of hostile plan review on
// #5858 and re-verified in the tree:
//
//   - The policy clear drops sessions ATTRIBUTED to the changed policy. An
//     interface clear would drop every session INGRESSING that interface,
//     related to the filter's terms or not. On a WAN interface that is all
//     transit traffic, for a filter change that may deny none of it.
//   - Dropping permitted flows is not free. The non-persistent PAT allocator
//     hands out a fresh monotonic-cursor port first and only drains the recycle
//     FIFO after the fresh range is spent, so a purged-then-recreated permitted
//     SNAT flow reinstalls on a DIFFERENT translated port and breaks. Revoking
//     authorization the operator removed is correct; breaking flows the
//     operator did not touch is not.
//
// The correct fix drops only NEWLY-DENIED sessions, which needs per-tuple
// revalidation in the dataplane (a per-session ingress stamp with the reverse
// direction captured on first reply, pair-aware teardown, all-binding flow-cache
// eviction, a side-effect-free static evaluator, and an authoritative HA
// resync). That is a Rust dataplane feature and is tracked separately.
//
// Until it lands, the gap must not be SILENT. An operator who tightens a filter
// and sees a clean commit reasonably believes the deny is in force. This says
// otherwise, at commit, on the surface they are already looking at, and names
// the command that revokes the sessions immediately.

// filterCanDeny reports whether f contains any term that can DENY a packet.
// A filter made only of `accept` terms cannot revoke an established session no
// matter how it changed, so warning about it would be a false alarm on a
// correct config — and a commit-time warning nobody can act on is one an
// operator learns to ignore, which costs the warnings that matter.
//
// Both Action and TerminalActions are consulted: Action is single-valued and
// last-write-wins, while TerminalActions records EVERY terminating keyword the
// term's `then` blocks carried. A term with `then accept` AND `then discard`
// resolves Action to one of them and keeps both here, so reading Action alone
// could miss a deny.
func filterCanDeny(f *config.FirewallFilter) bool {
	if f == nil {
		return false
	}
	deny := func(a string) bool { return a == "discard" || a == "reject" }
	for _, t := range f.Terms {
		if t == nil {
			continue
		}
		if deny(t.Action) {
			return true
		}
		for _, a := range t.TerminalActions {
			if deny(a) {
				return true
			}
		}
	}
	return false
}

// inputFilterFor returns the input filter NAME attached to unit u for the given
// family, and the filter DEFINITION that name resolves to in cfg.
func inputFilterFor(cfg *config.Config, u *config.InterfaceUnit, v6 bool) (string, *config.FirewallFilter) {
	if u == nil {
		return "", nil
	}
	name := u.FilterInputV4
	table := cfg.Firewall.FiltersInet
	if v6 {
		name = u.FilterInputV6
		table = cfg.Firewall.FiltersInet6
	}
	if name == "" {
		return "", nil
	}
	return name, table[name]
}

// inputFilterRevocationChanges returns, sorted, a descriptor per interface unit
// whose effective INPUT filter changed in a way that could newly DENY traffic.
//
// Two kinds of change count, because a filter can tighten either way:
//
//   - the attached NAME changed to a different filter that can deny (including
//     an attach from none);
//   - the name is unchanged but its DEFINITION changed and the new definition
//     can deny — the case a name comparison alone misses entirely, and the more
//     common one, since operators edit a filter far more often than they
//     re-point an interface at a different one.
//
// A DETACH (a filter removed and nothing attached) is strictly loosening and is
// deliberately not reported: no session can be newly denied by the absence of a
// filter.
func inputFilterRevocationChanges(oldCfg, newCfg *config.Config) []string {
	if newCfg == nil {
		return nil
	}
	var out []string
	for ifName, iface := range newCfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		for unitNum, u := range iface.Units {
			if u == nil {
				continue
			}
			var oldUnit *config.InterfaceUnit
			if oldCfg != nil {
				if oi := oldCfg.Interfaces.Interfaces[ifName]; oi != nil {
					oldUnit = oi.Units[unitNum]
				}
			}
			for _, fam := range []struct {
				v6    bool
				label string
			}{{false, "inet"}, {true, "inet6"}} {
				newName, newFilter := inputFilterFor(newCfg, u, fam.v6)
				if newName == "" || !filterCanDeny(newFilter) {
					// Nothing attached, or nothing it could deny.
					continue
				}
				oldName, oldFilter := "", (*config.FirewallFilter)(nil)
				if oldCfg != nil {
					oldName, oldFilter = inputFilterFor(oldCfg, oldUnit, fam.v6)
				}
				if oldName == newName && reflect.DeepEqual(oldFilter, newFilter) {
					continue // unchanged — established sessions were already subject to it
				}
				out = append(out, fmt.Sprintf("%s.%d family %s filter %q",
					ifName, unitNum, fam.label, newName))
			}
		}
	}
	sort.Strings(out)
	return out
}

// warnInputFilterRevocationGap appends the #5858 advisory to newCfg.Warnings
// when a commit attaches or tightens an interface input filter that can deny.
//
// Warnings is the channel the operator is already reading: CommitResponse,
// CommitConfirmedResponse and the REST commit response all carry it
// (configWarnings / commitResponseFromConfig), so this lands on the terminal at
// commit rather than only in the journal.
//
// Appends AFTER applyConfigLocked has logged cfg.Warnings, so the advisory is
// not double-emitted to the log; the explicit slog.Warn below is its log copy.
//
// Caller must hold d.applySem, like the sibling policy invalidation.
func (d *Daemon) warnInputFilterRevocationGap(oldCfg, newCfg *config.Config) {
	changed := inputFilterRevocationChanges(oldCfg, newCfg)
	if len(changed) == 0 {
		return
	}
	// One line naming every affected unit, plus the remedy. Naming the exact
	// command matters: the operator's alternative is to discover the gap from
	// traffic that should have stopped.
	ifaces := make([]string, 0, len(changed))
	seen := map[string]bool{}
	for _, c := range changed {
		name := c
		if i := indexByte(c, '.'); i > 0 {
			name = c[:i]
		}
		if !seen[name] {
			seen[name] = true
			ifaces = append(ifaces, name)
		}
	}
	sort.Strings(ifaces)

	w := fmt.Sprintf(
		"interface input filter attached or tightened (%s) — ESTABLISHED sessions are NOT "+
			"revoked and keep forwarding under the previous filter until they idle out; the new "+
			"filter applies to sessions created from now on. Run `clear security flow session "+
			"interface <name>` (%s) to revoke them immediately (#5858)",
		joinComma(changed), joinComma(ifaces))
	newCfg.Warnings = append(newCfg.Warnings, w)
	slog.Warn("interface input filter changed: established sessions are not revoked",
		"units", joinComma(changed), "remedy", "clear security flow session interface <name>",
		"issue", "#5858")
}

// indexByte is strings.IndexByte, kept local so this file does not pull the
// strings import for one call.
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// joinComma renders a descriptor list for one operator-facing line.
func joinComma(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// reportSessionAuthorizationChanges is the ONE commit-time entry point for
// "authorization the operator just changed, versus sessions already
// established". It runs the policy invalidation (which actually clears) and
// the input-filter advisory (which cannot, and says so).
//
// It exists as a single function rather than two calls at each site because the
// two halves cover the same hazard on different objects, and a commit path that
// wired one without the other would reintroduce exactly the asymmetry #5858
// reports — a tightening that silently does not apply to live traffic. There
// are three such sites (commit, commit-confirmed, confirmed-rollback) and a
// fourth would be easy to add; binding them together makes that a compile-time
// impossibility rather than a review item.
//
// Returns the policy invalidation's error contract unchanged (#5578): non-nil
// means a PARTIAL clear, so some traffic may keep forwarding under stale
// authorization. The advisory has no error — it is a warning appended to
// newCfg.Warnings, which the commit response carries to the operator.
//
// Caller must hold d.applySem.
func (d *Daemon) reportSessionAuthorizationChanges(oldCfg, newCfg *config.Config) error {
	d.warnInputFilterRevocationGap(oldCfg, newCfg)
	return d.clearSessionsForPolicyChanges(oldCfg, newCfg)
}
