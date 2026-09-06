package config

// natSourcePoolSchema8939 resolves `security nat source pool <name>`.
func natSourcePoolSchema8939() *schemaNode {
	sec := resolveSchemaChild(setSchema, "security")
	if sec == nil {
		return nil
	}
	nat := resolveSchemaChild(sec, "nat")
	if nat == nil {
		return nil
	}
	src := resolveSchemaChild(nat, "source")
	if src == nil {
		return nil
	}
	pool := resolveSchemaChild(src, "pool")
	if pool == nil {
		return nil
	}
	if pool.wildcard != nil {
		return pool.wildcard
	}
	return pool
}

// samplingOutputSchema8939 resolves
// `forwarding-options sampling instance <i> family inet output`. The inet and
// inet6 bodies are the same shape, so one resolution serves both readers.
func samplingOutputSchema8939() *schemaNode {
	fo := resolveSchemaChild(setSchema, "forwarding-options")
	if fo == nil {
		return nil
	}
	sm := resolveSchemaChild(fo, "sampling")
	if sm == nil {
		return nil
	}
	inst := resolveSchemaChild(sm, "instance")
	if inst == nil {
		return nil
	}
	if inst.wildcard != nil {
		inst = inst.wildcard
	}
	fam := resolveSchemaChild(inst, "family")
	if fam == nil {
		return nil
	}
	inet := resolveSchemaChild(fam, "inet")
	if inet == nil {
		return nil
	}
	return resolveSchemaChild(inet, "output")
}
