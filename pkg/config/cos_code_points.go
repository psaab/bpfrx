package config

import (
	"strconv"
	"strings"
)

// CoS code-point token -> value resolution.
//
// #7080/#7084: this file is the production counterpart of the seam
// cos_code_points_spellings_6697_test.go already names. It starts with the
// inet-precedence resolver because that is what #7084 added; the DSCP alias
// table and the two collectors in compiler_class_of_service.go belong here too
// and can follow in a change whose subject is that motion. Splitting them out
// in a change about four unrelated CoS defects would bury the defects in a
// refactor.

// coSINetPrecedenceCodePointValue resolves one `classifiers inet-precedence`
// code-point token to its 0..7 value.
//
// #7084: the collector accepted DECIMAL 0..7 only, so the two spellings Junos
// actually uses for this classifier were rejected at commit — a loud refusal of
// a legal config, never a silent misclassification, which is why #6877 shipped
// without it.
//
// THREE-BIT BINARY is unambiguous and needs no table. `000`..`111` is the
// natural spelling for a 3-bit field and is how Junos documents it. Reading a
// 3-character [01] token as binary can only WIDEN what is accepted: `000` and
// `001` mean 0 and 1 under either reading, and `010`/`011`/`100`/`101`/`110`/
// `111` are 10/11/100/101/110/111 in decimal — every one already out of range
// and rejected today. So no token that compiles now changes meaning.
//
// THE ALIASES ARE A TRANSCRIBED TABLE, and that deserves a note. They are the
// RFC 791 IP-precedence names, which is what `cs0`..`cs7` in coSDSCPValues
// above are the DSCP encoding of (precedence << 3). #7084 enumerated SEVEN of
// them and omitted the value-0 name; `routine` is included here because a table
// missing an entry rejects a legal config, which is the defect being fixed.
//
// The risk asymmetry is worth stating, because it is what makes adding an entry
// on a transcription safe: an alias Junos does not use is INERT — nobody types
// it — whereas a MISSING alias refuses a legal config, and a MIS-MAPPED alias is
// the only dangerous outcome. The 1..7 mappings here are corroborated by the
// issue's independently-written list; 0 is the one added.
func coSINetPrecedenceCodePointValue(raw string) (int, bool) {
	if v, ok := coSINetPrecedenceAliases[raw]; ok {
		return int(v), true
	}
	if len(raw) == 3 && strings.Trim(raw, "01") == "" {
		v, err := strconv.ParseUint(raw, 2, 8)
		if err != nil {
			return 0, false
		}
		return int(v), true
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return v, true
}

// coSINetPrecedenceAliases is the RFC 791 IP-precedence naming, lowercase.
// See coSINetPrecedenceCodePointValue for provenance and the risk asymmetry.
var coSINetPrecedenceAliases = map[string]uint8{
	"routine":          0,
	"priority":         1,
	"immediate":        2,
	"flash":            3,
	"flash-override":   4,
	"critical-ecp":     5,
	"internet-control": 6,
	"net-control":      7,
}
