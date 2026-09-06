package config

// securityFlowSchema8939 resolves the `security flow` container so expandFlatRun
// knows which tokens on a packed node are siblings rather than values.
func securityFlowSchema8939() *schemaNode {
	sec := resolveSchemaChild(setSchema, "security")
	if sec == nil {
		return nil
	}
	return resolveSchemaChild(sec, "flow")
}
