package config

// dhcpRelayOverridesSchema8939 resolves the
// `forwarding-options dhcp-relay group <name> overrides` container so
// expandFlatRun knows which tokens on a packed node are siblings.
//
// The same container is reachable under `group <g> interface <if> overrides`
// too, and both readers share this schema — the override keywords are the same
// set at either depth.
func dhcpRelayOverridesSchema8939() *schemaNode {
	fo := resolveSchemaChild(setSchema, "forwarding-options")
	if fo == nil {
		return nil
	}
	dr := resolveSchemaChild(fo, "dhcp-relay")
	if dr == nil {
		return nil
	}
	grp := resolveSchemaChild(dr, "group")
	if grp == nil {
		return nil
	}
	if grp.wildcard != nil {
		grp = grp.wildcard
	}
	return resolveSchemaChild(grp, "overrides")
}
