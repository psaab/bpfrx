package config

import (
	"sort"
	"strings"
	"testing"
)

// #6932: `ipipAnchorOnlyText`'s unit branch names `tunnel mode wireguard` as the
// specific cause. That is correct today, but until now nothing MECHANICAL held
// it: the only guard was a comment saying the wording needs revisiting if
// another mode gains a short-circuit.
//
// WHAT THE RISK ACTUALLY IS, measured rather than restated. The issue frames it
// as a future mode producing the WireGuard WORDING. That cannot happen: the call
// site passes `iface.Tunnel != nil && iface.Tunnel.Mode == "wireguard"`, a
// literal comparison, so any other short-circuiting mode yields false and takes
// the `case isUnit:` arm — which says the cause "is not one this check
// recognises". The failure mode is therefore an HONEST-BUT-USELESS advisory, not
// a confidently wrong one.
//
// That is still worth guarding, and these two tests split the property:
// this one pins WHICH modes suppress, and the one below pins what the
// unrecognised-cause arm actually renders.
//
// NOTE on the mode space: #6932 reasoned over "exactly three values — gre, ipip,
// wireguard". #6924 has since declared the set as TunnelModeNames =
// {gre, ip6gre, wireguard} — ipip is deliberately NOT in it, and ip6gre is. This
// enumeration is keyed on suppression behaviour rather than on that list, so it
// does not need updating when the list changes; but do not read the rows below
// as a copy of the declared set.

// unitIpipSuppressedUnder reports whether an interface-level stanza in the named
// mode suppresses a COMPLETE unit-level `ipip` endpoint.
//
// The discriminator is compile success, and it is exact rather than incidental.
// A unit `ipip` endpoint that IS emitted reaches the #4785 rejection ("IPIP
// (ip-in-ip) is NOT implemented"), so the compile fails. One that is SUPPRESSED
// never reaches it, so the compile succeeds and the anchor advisory fires
// instead. So "compiled" and "suppressed" are the same fact here.
func unitIpipSuppressedUnder(t *testing.T, ifaceStanza []string, ifName string) bool {
	t.Helper()
	lines := append(append([]string{}, ifaceStanza...),
		// unit 1 carries NO tunnel stanza, so it is the LOWEST unit and resolves
		// to the interface's shared device. Without it the interface-level
		// endpoint keys to unit 3 and resolves to unit 3's OWN device, so unit 3
		// is not orphaned and nothing is suppressed — the shape #6861 F1b proved
		// is not dead. Present in every row so the rows differ only in mode.
		"set interfaces "+ifName+" unit 1 family inet address 10.9.9.1/30",
		"set interfaces "+ifName+" unit 3 tunnel mode ipip",
		"set interfaces "+ifName+" unit 3 tunnel source 10.0.0.5",
		"set interfaces "+ifName+" unit 3 tunnel destination 10.0.0.6",
	)
	cfg, err := CompileConfig(ipipTree(t, lines...))
	if err != nil {
		// Emitted, and rejected by #4785. Assert that is WHY, so a compile
		// failing for an unrelated reason cannot masquerade as "not suppressed".
		if !strings.Contains(err.Error(), "is NOT implemented in the userspace dataplane") {
			t.Fatalf("%s: compile failed for a reason unrelated to ipip emission, so this "+
				"row measures nothing: %v", ifName, err)
		}
		return false
	}
	for _, w := range ipipAnchorOnlyWarnings(cfg) {
		if strings.Contains(w, "unit 3") {
			return true
		}
	}
	t.Fatalf("%s: compiled without emitting the unit ipip endpoint AND without an anchor "+
		"advisory naming it — the endpoint vanished with no diagnosis at all", ifName)
	return false
}

// TestOnlyWireguardSuppressesACompleteUnitIpip_6932 is the mechanical guard the
// comment asked for.
//
// RED-on-change: give any other interface-level mode a short-circuit and its row
// flips to suppressed, the computed set stops equalling {wireguard}, and this
// fails NAMING the new mode — so whoever adds it is told to revisit the advisory
// wording instead of shipping a "cause not recognised" for a cause that is now
// perfectly well known.
func TestOnlyWireguardSuppressesACompleteUnitIpip_6932(t *testing.T) {
	modes := map[string][]string{
		"wireguard": ipipWgIfaceStanza(),
		"gre": {
			"set interfaces gr-0/0/0 tunnel mode gre",
			"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
		},
		// A mode outside the declared set. #6924 has since added
		// `validator: ValidateEnum(TunnelModeNames)` to the `mode` leaf, so
		// `mode banana` no longer COMMITS — but that validator runs in
		// SchemaValidate at commit-check, and this row drives CompileConfig
		// directly, which does not consult it.
		//
		// That is the row's justification now, and it is stronger than the
		// original "this is a real input today": CompileConfig is reachable from
		// paths that never pass schema validation — the tolerant/programmatic
		// load and HA peer sync, the same paths compiler_iface.go names when it
		// guards against a nil zone slot. So an undeclared mode remains a real
		// input to THIS function, and it must not short-circuit.
		"unvalidated": {
			"set interfaces gr-0/0/1 tunnel mode banana",
			"set interfaces gr-0/0/1 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/1 tunnel destination 10.0.0.2",
		},
	}
	ifNames := map[string]string{"wireguard": "wg0", "gre": "gr-0/0/0", "unvalidated": "gr-0/0/1"}

	var suppressing []string
	for mode, stanza := range modes {
		if unitIpipSuppressedUnder(t, stanza, ifNames[mode]) {
			suppressing = append(suppressing, mode)
		}
	}
	sort.Strings(suppressing)

	got := strings.Join(suppressing, ",")
	if got != "wireguard" {
		t.Fatalf("the set of interface-level modes that suppress a complete unit-level "+
			"ipip endpoint is {%s}, want exactly {wireguard}.\n"+
			"ipipAnchorOnlyText names `tunnel mode wireguard` as THE cause for the unit "+
			"branch. If another mode suppresses too, units under it now get "+
			"\"the reason is not one this check recognises\" for a reason that is in fact "+
			"known — update the advisory alongside the new short-circuit.", got)
	}
}

// TestIpipAnchorUnrecognisedCauseArmIsHonest_6932 pins what the fallback arm
// renders. That arm is unreachable through config today — which is exactly why
// it needs a direct test: an unreachable arm with no coverage is free to rot
// into saying something wrong, and it only becomes reachable at the moment a new
// short-circuit lands, which is the worst time to discover its wording is stale.
//
// It must NOT inherit WireGuard's explanation — that is the wrong-cause defect
// #6861 was folded to fix, one layer in.
func TestIpipAnchorUnrecognisedCauseArmIsHonest_6932(t *testing.T) {
	// Both endpoint halves set, so ipipMissingEndpointHalves returns "" and the
	// COMPLETE fallback renders rather than the missing-half wording.
	tun := &TunnelConfig{Name: "x", Mode: "ipip", Source: "10.0.0.5", Destination: "10.0.0.6"}
	got := ipipAnchorOnlyText(`interfaces "gr-0/0/0" unit 3`, tun, true, false)

	if strings.Contains(got, "wireguard") {
		t.Fatalf("the unrecognised-cause arm names WireGuard, which is the wrong cause by "+
			"construction — this arm is reached precisely when the suppressor is NOT "+
			"WireGuard: %q", got)
	}
	if !strings.Contains(got, "not one this check recognises") {
		t.Fatalf("the unrecognised-cause arm must say the cause is unknown rather than "+
			"guessing: %q", got)
	}
	if !strings.Contains(got, "Do not delete either before") {
		t.Fatalf("the unrecognised-cause arm must not recommend deleting a stanza before "+
			"the operator knows which one suppresses the other: %q", got)
	}
}
