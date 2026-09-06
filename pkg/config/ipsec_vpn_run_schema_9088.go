package config

// ipsecVPNRunSchema9088 is the schema `expandFlatRun` reads when segmenting a
// packed run under `security ipsec vpn <name>`.
//
// #9088: this is a SCHEMA-BEHIND-COMPILER site, and that gap is what made the
// packed spelling operator-reachable rather than merely tolerable.
//
//	set security ipsec vpn v1 gateway G                     |
//	set security ipsec vpn v1 ipsec-policy P                | -> gw=G policy=P bind=st0.1
//	set security ipsec vpn v1 bind-interface st0.1          |
//
//	set security ipsec vpn v1 gateway G ipsec-policy P bind-interface st0.1
//	                                    -> gw=G  policy=""  bind=""
//
// Both COMMIT. `show configuration` renders what the operator typed. Two values
// are gone, and both losses are silent and severe: a dropped `ipsec-policy`
// negotiates the strongSwan default proposal set instead of the configured
// crypto, and a dropped `bind-interface` leaves `xfrmiIfID()` at 0, so a
// route-based VPN commits with no XFRM interface -- the silent-tunnel-down
// condition #5297 exists to prevent, reached by a path #5297 does not watch.
//
// WHY THE EXISTING expandFlatRun CALL DID NOT ALREADY FIX IT. The call site has
// been there since #9090. It could not cut, because it cuts at tokens the
// CONTAINER declares as leaves and `security ipsec vpn <name>` declares neither
// `gateway` nor `ipsec-policy` in setSchema -- the compiler reads both, the
// schema knows neither. So the run started at an unrecognised head and was
// passed through whole. The declaration is not decoration for the split; it IS
// the split's only source of cut points.
//
// WHY THIS AUGMENTS RATHER THAN EDITING setSchema. #9088 asks for the compiler
// walk and says explicitly not to declare these leaves in setSchema as the
// first move. Editing setSchema changes three things at once -- run
// segmentation, SchemaValidate admission, and `?` completion -- and only the
// first is needed to stop the loss. Declaring them there is the right FOLLOW-UP
// now that the walk works (it is what would make completion offer `gateway`),
// but it is a separate change with a separate blast radius, and doing it here
// would mean a commit that fixes a data loss also silently alters what the
// completer offers.
//
// The children map is a shallow copy with two entries added. A shallow copy is
// correct here and a deep one would be wrong: every value in it is a real
// setSchema subtree that must stay IDENTICAL to the declared one, because a
// census or completer that dedups by node identity has to see the same node
// (the #9017 lesson, where sharing was the bug and copying was the fix, points
// the other way -- there a second PATH was being minted; here the path is the
// same one and only the local cut set is being widened).
func ipsecVPNRunSchema9088() *schemaNode {
	base := ipsecVPNLeafSchema8939()
	if base == nil {
		return nil
	}
	children := make(map[string]*schemaNode, len(base.children)+2)
	for k, v := range base.children {
		children[k] = v
	}
	// Both take exactly one value token, like `bind-interface` beside them.
	for _, name := range []string{"gateway", "ipsec-policy"} {
		if _, declared := children[name]; !declared {
			children[name] = &schemaNode{args: 1}
		}
	}
	return &schemaNode{
		args:        base.args,
		children:    children,
		wildcard:    base.wildcard,
		multi:       base.multi,
		valueList:   base.valueList,
		closedWorld: base.closedWorld,
	}
}
