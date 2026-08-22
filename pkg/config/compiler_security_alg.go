package config

// algDisabled reports whether `security alg <proto>` carries a `disable`
// statement, in EITHER AST shape (#6564).
//
// `alg { dns { disable; } }` gives a "dns" child with a "disable" child, but
// `alg { dns disable; }` is ONE leaf with Keys=["dns","disable"] and no
// children at all — the parser packs a `;`-terminated statement onto a single
// node. Reading Children alone (the pre-#6564 form) was blind to the second
// spelling, so an operator-disabled ALG silently stayed ENABLED with no
// warning: the #4232 unsupported-proto advisory does not fire either, because
// the four protos here ARE wired.
//
// This is the same accumulate-both-sides discipline as firewallMatchValues /
// addressSetMemberValues.
func algDisabled(algNode *Node, proto string) bool {
	protoNode := algNode.FindChild(proto)
	if protoNode == nil {
		return false
	}
	if protoNode.FindChild("disable") != nil {
		return true
	}
	for _, k := range protoNode.Keys[1:] {
		if k == "disable" {
			return true
		}
	}
	return false
}

func compileALG(node *Node, sec *SecurityConfig) error {
	sec.ALG.DNSDisable = sec.ALG.DNSDisable || algDisabled(node, "dns")
	sec.ALG.FTPDisable = sec.ALG.FTPDisable || algDisabled(node, "ftp")
	sec.ALG.SIPDisable = sec.ALG.SIPDisable || algDisabled(node, "sip")
	sec.ALG.TFTPDisable = sec.ALG.TFTPDisable || algDisabled(node, "tftp")
	// #4232 (fable-167 P-4a): record any `security alg <proto>` whose proto is
	// not one of the four the dataplane wires. The whole stanza (bare `disable`
	// or a richer child like `h323 gatekeeper ...`) was previously dropped
	// silently; recording the proto lets the compiler emit an accepted-but-inert
	// advisory (validateSecurityAcceptedOnly). Iterate node.Children in config
	// order for a deterministic warning.
	for _, child := range node.Children {
		switch child.Name() {
		case "dns", "ftp", "sip", "tftp":
			// wired above
		default:
			sec.ALG.UnsupportedProtos = append(sec.ALG.UnsupportedProtos, child.Name())
		}
	}
	return nil
}
