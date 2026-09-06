package config

// cosTrafficControlProfileSchema8939 resolves the
// `class-of-service traffic-control-profiles <name>` body so expandFlatRun knows
// which tokens on a packed node are siblings rather than values.
func cosTrafficControlProfileSchema8939() *schemaNode {
	cos := resolveSchemaChild(setSchema, "class-of-service")
	if cos == nil {
		return nil
	}
	tcp := resolveSchemaChild(cos, "traffic-control-profiles")
	if tcp == nil {
		return nil
	}
	if tcp.wildcard != nil {
		return tcp.wildcard
	}
	return tcp
}
