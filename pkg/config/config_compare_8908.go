package config

import "encoding/json"

// ConfigFingerprint renders a compiled Config for COMPARISON.
//
// USE THIS INSTEAD OF fmt.Sprintf("%v", cfg) OR reflect.DeepEqual.
//
// The Config graph is full of pointers, so `%v` and `%+v` print ADDRESSES for
// every nested struct, map value and slice element. Two structurally identical
// configs therefore render DIFFERENTLY on every compile, and two structurally
// different ones can render identically if the difference is behind a pointer
// whose address happens to repeat.
//
// The failure is silent and it is STABLE, which is what makes it dangerous: a
// comparison built on `%v` reports a difference every run, so re-running
// confirms it. Repeat-run stability is a check against non-determinism and
// nothing else.
//
// This has cost this codebase three separate wrong measurements:
//   - a NAT sampling row filed as a defect because map[string]*SamplingInstance
//     printed addresses (the row is not a defect);
//   - a leaf-contingency guard that reported ZERO contingent pairs against the
//     sweep's seven, because every site compared unequal and so every pair
//     agreed;
//   - and the same trap documented, broadcast to another lane as a warning, and
//     then committed again hours later by the author of the warning.
//
// Warnings are cleared before rendering: they are an out-of-band channel and a
// caller comparing two compiles almost never wants them in the comparison. A
// caller who DOES want them should compare cfg.Warnings explicitly, which makes
// that intent visible at the call site.
func ConfigFingerprint(c *Config) string {
	if c == nil {
		return "<nil>"
	}
	dup := *c
	dup.Warnings = nil
	b, err := json.Marshal(&dup)
	if err != nil {
		// A marshal failure must not read as "equal to another failure".
		return "<unmarshalable: " + err.Error() + ">"
	}
	return string(b)
}

// ConfigsIdentical reports whether two compiled Configs are structurally the
// same, ignoring warnings. It exists so that the correct comparison is shorter
// to write than the incorrect one.
func ConfigsIdentical(a, b *Config) bool {
	return ConfigFingerprint(a) == ConfigFingerprint(b)
}
