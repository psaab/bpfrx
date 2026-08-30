package config

import "fmt"

// compiler_validate_strict_nested_zonepair_7523.go — #7523.
//
// `security policies from-zone X { to-zone Y { ... } }` -- a NESTED pair of
// containers -- was accepted at commit and then silently omitted from the
// compiled policy set. Measured at e01427aef: the nested spelling compiles to
// ZERO zone-pairs and ZERO policies, while the supported combined spelling of
// the same intent compiles to one and one.
//
// THIS IS AN HONESTY GAP, NOT A PARITY GAP. Junos documents ONE combined
// `from-zone X to-zone Y` hierarchy, so the nested shape is not something xpf
// is missing -- it is a shape xpf accepts and does not implement. #4313 supplies
// the closed-world doctrine; this is its concrete application to this domain.
//
// The failure mode is the dangerous one for a security policy: the operator
// wrote a permit-or-deny rule, the box said nothing, and the zone pair falls
// through to the default policy. The contrast with the supported spelling makes
// it worse -- an undefined zone in the COMBINED form already gets a precise
// commit error (validatePolicyZoneReferencesStrict), so an operator has every
// reason to read silence as acceptance.
//
// WHY THE DISCRIMINATOR IS "HAS A to-zone CHILD" AND NOT A Keys LENGTH. The
// spellings were dumped rather than reasoned about, because the obvious
// reasoning is wrong twice over:
//
//	NESTED       Keys=[from-zone trust]                  children=[to-zone]
//	COMBINED     Keys=[from-zone trust to-zone untrust]  children=[policy]
//	FLAT-SET     Keys=[from-zone trust to-zone untrust]  children=[policy]
//	FZ-CONTAINER Keys=[from-zone]                        children=[trust]
//
// First, flat-set collapses to the SAME node shape as the combined block form,
// so a `len(Keys)` gate cannot tell those two apart -- there is no distinction
// there to key on.
//
// Second, and this is the one that matters: the fully-nested container spelling
// `from-zone { X { to-zone { Y { ... } } } }` is SUPPORTED and compiles, and it
// carries `len(Keys) == 1`. A gate written as "reject when len(Keys) < 4" would
// therefore refuse a valid configuration. The mutation matrix found this: that
// exact rewrite passed every test until a positive control for this fourth
// shape was added, which is what TestFromZoneContainerSpellingStillCompiles7523
// now pins.
//
// A `to-zone` CHILD appears in exactly one of the four.
//
// Reject-only: this changes nothing about what compiles, only about what is
// refused. A bug here can produce a false rejection -- loud, and caught by the
// positive controls -- never a silently wrong policy.
func validateNestedZonePairStrict(tree *ConfigTree) error {
	if tree == nil {
		return nil
	}
	for _, root := range tree.Children {
		if root.Name() != "security" {
			continue
		}
		for _, policies := range root.Children {
			if policies.Name() != "policies" {
				continue
			}
			for _, fz := range policies.Children {
				if fz.Name() != "from-zone" {
					continue
				}
				for _, sub := range fz.Children {
					if sub.Name() != "to-zone" {
						continue
					}
					from := ""
					if len(fz.Keys) >= 2 {
						from = fz.Keys[1]
					}
					to := ""
					if len(sub.Keys) >= 2 {
						to = sub.Keys[1]
					}
					return fmt.Errorf(
						"security policies from-zone %q contains a NESTED `to-zone %s { ... }` "+
							"block. Junos models one COMBINED hierarchy, so this spelling is not "+
							"implemented: it compiles to zero zone-pairs and zero policies, and the "+
							"pair falls through to the default policy with nothing said. Write it as "+
							"`set security policies from-zone %s to-zone %s policy <name> ...` "+
							"(or the block form `from-zone %s to-zone %s { ... }`) (#7523)",
						from, to, from, to, from, to)
				}
			}
		}
	}
	return nil
}
