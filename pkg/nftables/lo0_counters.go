package nftables

// lo0CounterPrefix namespaces every named counter object attached to a kernel
// lo0 input-filter rule (the `inet xpf_lo0` table) so the object is recognizably
// xpf-managed and always begins with a letter. A bare nft identifier may not
// start with a digit, but a Junos firewall-filter `then count <name>` may, so
// the prefix also guarantees the declaration parses (#3445).
const lo0CounterPrefix = "xpflo0_"

// Lo0CounterName returns the nft named-counter object name that mirrors a
// firewall-filter term's `then count <name>` modifier onto the kernel lo0 input
// chain (#3445). The Junos counter name is passed through sanitizeNftIdent so
// the result is a valid BARE nft identifier — the counter DECLARATION
// (`counter <n> { }`) must be unquoted, which nft v1.1.6 requires (a quoted
// declaration is a hard syntax error, #3578) — and prefixed so it can never
// begin with a digit. The same string is referenced (quoted, `counter name
// "<n>"`) on the rule, so declaration and reference match byte-for-byte.
//
// Two Junos count names that differ only in bytes outside [A-Za-z0-9_.-] (rare;
// Junos count names are normally bare) sanitize to the same object and their
// kernel counts merge. That is a counting artifact ONLY: the lo0 verdict rules
// are independent of the counter object, so no forwarding or verdict effect can
// change. Without sanitization an exotic name would make the whole atomic lo0
// table fail to load, so the lossy name is strictly better than no mirror.
func Lo0CounterName(name string) string {
	return lo0CounterPrefix + sanitizeNftIdent(name)
}
