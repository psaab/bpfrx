package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// compiler_interface_unit_alias.go carries the #5631 (codex-review-181 M23)
// reject-at-commit gate for numeric interface-unit ALIASES — two distinct
// unit-number spellings under one interface that canonicalize to the SAME
// logical unit.
//
// The compiler keys logical units by the numeric value: compileInterfaces
// (compiler_interfaces.go) iterates `namedInstances(child.FindChildren("unit"))`
// and canonicalizes each RAW spelling through `strconv.Atoi` — but only AFTER
// the AST has already split `unit 00` and `unit 0` into two SEPARATE named
// instances. The two instances then collide on the same `ifc.Units[unitNum]`
// key, and the two side effects disagree:
//
//   - `ifc.Units[unitNum] = unit` is LAST-WRITER-WINS: the later spelling's
//     unit (its filter, its addresses, its flags) completely REPLACES the
//     earlier one — so the interface's input/output firewall filter is decided
//     by config order.
//   - the interface-level tunnel address collection
//     (`ifc.Tunnel.Addresses = append(ifc.Tunnel.Addresses, unit.Addresses...)`)
//     is APPEND-ONLY: it accumulates the addresses of EVERY spelling, so a
//     stale address from the spelling that LOST the filter race still survives
//     on the tunnel.
//
// The observable result is order-dependent AND self-inconsistent: compiling
// `unit 00` then `unit 0` versus the reverse order yields a different final
// filter, a different unit address set, and a different tunnel-address set
// (see interface_unit_alias_5631_test.go). Because the winning filter flips
// with config order, an operator who reorders two otherwise-equivalent set
// lines can silently disarm the interface's firewall filter — a fail-open on
// a security hook — while the tunnel keeps forwarding on the stale address.
//
// Junos treats a logical unit as an integer identity: `unit 00` and `unit 0`
// are the SAME unit, and there is no meaningful configuration in which two
// numeric aliases of one unit carry DIFFERENT security state. Rather than pick
// an arbitrary winner (which spelling's filter survives is exactly the
// order-dependent ambiguity that makes this unsafe), this gate REJECTS the
// aliased config at commit so the operator authors a single canonical
// `unit <n>`. This matches how the rest of the compiler resolves unit
// identity (numeric) and the reject-at-commit / warn-on-load doctrine used by
// the sibling silent-inconsistency gates (validateApplicationNameCollisionsAST,
// validateFirewallFilterFamilyCollisionsAST, #1960 / #3261).
//
// Strict path (commit / commit-check, lenient=false): the first interface with
// a numeric unit-alias collision is a hard compile error naming the interface,
// the colliding spellings, and the canonical unit number.
//
// Lenient path (load / peer-sync, lenient=true): every collision is returned as
// a warning and compilation continues with the (arbitrary but deterministic-
// for-a-fixed-config) last-writer result, so an already-persisted or peer-
// synced config an older binary silently accepted still BOOTS. The operator
// gets the warning as the signal to collapse the aliases.
//
// This is an AST pre-walk (not a SchemaValidate typed leaf) for the same
// reason as validateUnsupportedInterfaceStanzasAST: the colliding instances
// are merged away by last-writer-wins by the time the typed `ifc.Units` map
// exists — only the raw AST still carries every spelling. It runs on the
// group-expanded, inactive-pruned tree (runPreWalkGates), so an
// apply-groups-inherited or interface-range-expanded unit alias is caught and
// an `inactive:` unit is ignored for free.
//
// Detection is scoped to DISTINCT spellings that canonicalize to the same
// number: a single canonical `unit 0` (the overwhelming common case) never
// trips it, and flat-set `set` lines with the SAME spelling merge into one AST
// node upstream (they are the same unit, not an alias). A non-numeric unit
// token is skipped — the compiler `continue`s on the identical Atoi error, so
// it never reaches `ifc.Units` and cannot collide.
func validateInterfaceUnitAliasCollisionsAST(nodes []*Node, lenient bool) ([]string, error) {
	var ifaces *Node
	for _, n := range nodes {
		if n.Name() == "interfaces" {
			ifaces = n
			break
		}
	}
	if ifaces == nil {
		return nil, nil
	}

	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	for _, iface := range ifaces.Children {
		ifName := iface.Name()
		if ifName == "" {
			continue
		}

		// Group the distinct raw unit spellings by their canonical numeric
		// value, mirroring the compiler's namedInstances + strconv.Atoi split
		// exactly so detection matches what compileInterfaces consumes.
		distinct := make(map[int]map[string]bool)
		for _, inst := range namedInstances(iface.FindChildren("unit")) {
			num, err := strconv.Atoi(inst.name)
			if err != nil {
				continue
			}
			if distinct[num] == nil {
				distinct[num] = make(map[string]bool)
			}
			distinct[num][inst.name] = true
		}

		// Report the lowest colliding unit number first so the strict
		// first-error is order-independent (both config orders reject with the
		// same message).
		nums := make([]int, 0, len(distinct))
		for num := range distinct {
			if len(distinct[num]) >= 2 {
				nums = append(nums, num)
			}
		}
		sort.Ints(nums)

		for _, num := range nums {
			spellings := make([]string, 0, len(distinct[num]))
			for s := range distinct[num] {
				spellings = append(spellings, s)
			}
			sort.Strings(spellings)
			quoted := make([]string, len(spellings))
			for i, s := range spellings {
				quoted[i] = "`unit " + s + "`"
			}
			if err := emit(
				"interfaces %s: %s all name the same logical unit %d — numeric "+
					"unit aliases collapse to one unit whose firewall-filter and "+
					"address ownership then depends on config order (the later "+
					"spelling wins the unit filter while tunnel-address side "+
					"effects accumulate from every spelling, a fail-open on the "+
					"security filter) — use a single canonical `unit %d` (#5631)",
				ifName, strings.Join(quoted, ", "), num, num); err != nil {
				return nil, err
			}
		}
	}
	return warnings, nil
}
