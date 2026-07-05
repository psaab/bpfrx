package config

func compileALG(node *Node, sec *SecurityConfig) error {
	if dnsNode := node.FindChild("dns"); dnsNode != nil {
		if dnsNode.FindChild("disable") != nil {
			sec.ALG.DNSDisable = true
		}
	}
	if ftpNode := node.FindChild("ftp"); ftpNode != nil {
		if ftpNode.FindChild("disable") != nil {
			sec.ALG.FTPDisable = true
		}
	}
	if sipNode := node.FindChild("sip"); sipNode != nil {
		if sipNode.FindChild("disable") != nil {
			sec.ALG.SIPDisable = true
		}
	}
	if tftpNode := node.FindChild("tftp"); tftpNode != nil {
		if tftpNode.FindChild("disable") != nil {
			sec.ALG.TFTPDisable = true
		}
	}
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
