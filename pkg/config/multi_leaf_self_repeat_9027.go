package config

import (
	"fmt"
	"log/slog"
	"strings"
)

// #9027: A MISSING SEMICOLON IN A MULTI-VALUE RUN INJECTED THE LEAF'S OWN
// KEYWORD AS A VALUE, and at one site that value is a CREDENTIAL.
//
//	system { services { web-management { api-auth {
//	    api-key AAA api-key BBB;                       <- one statement
//	} } } }
//
//	  key[0] = "AAA"
//	  key[1] = "api-key"      <- authenticates
//	  key[2] = "BBB"
//
// The braced spelling of the same intent yields two keys. The injected
// credential is not a random artefact: it is a PREDICTABLE, PUBLICLY-KNOWN
// ENGLISH LITERAL, so anyone who can reach the management listener can present
// `X-API-Key: api-key`.
//
// THE TWO READERS OF THIS SHAPE DISAGREED, which is why neither could be
// trusted to settle it:
//
//	firewallMatchValues        SKIPS a repeat of the leaf's own keyword (#8883,
//	                           labelled an EXPERIMENT) -- so it silently DROPS a
//	                           legitimately-named object (#9029)
//	multiLeafAuthoredValues    ACCEPTS it as a value -- so it INJECTS (#9027)
//
// Each is a guess at what the operator meant, and the guesses are opposite.
// They are opposite because the input is genuinely ambiguous: `api-key AAA
// api-key BBB` is either two statements missing a semicolon, or one statement
// listing three values one of which is named after the keyword.
//
// SO THIS REFUSES RATHER THAN GUESSING. The operator is the only one who knows,
// the question is cheap for them to answer, and both guesses are wrong in a way
// that is invisible from `show configuration` -- which renders exactly what was
// typed in either reading.
//
// Lenient WARNS rather than refusing (#1960): a config an older binary accepted
// must still boot. On that path the readers keep their existing behaviour, and
// the warning is what tells the operator which of the two they are getting.

// validateMultiLeafSelfRepeat9027 refuses a multi-value leaf whose authored
// value run repeats the leaf's own keyword.
func validateMultiLeafSelfRepeat9027(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	var warnings []string
	var walk func(nodes []*Node, schema *schemaNode, path []string, depth int) error
	walk = func(nodes []*Node, schema *schemaNode, path []string, depth int) error {
		if schema == nil || depth > 12 {
			return nil
		}
		for _, n := range nodes {
			if n == nil || len(n.Keys) == 0 {
				continue
			}
			child := resolveSchemaChild(schema, n.Keys[0])
			if child == nil {
				continue
			}
			here := append(append([]string{}, path...), n.Keys[0])
			if child.multi && child.children == nil {
				// THE SCAN STARTS PAST THE LEAF'S DECLARED ARITY, and getting
				// this wrong over-reaches in a way that looks like the defect.
				//
				// Keys[1..args] are the leaf's FIRST value — or, for a leaf
				// that names an object, its NAME. `address address 10.0.0.0/8`
				// defines an address legitimately CALLED "address", and
				// flagging Keys[1] there refused a definition rather than a
				// repeat. Only a keyword appearing AFTER the first value can be
				// a second statement's head. Same arity discipline as #9124.
				start := 1 + child.args
				if start < 1 {
					start = 1
				}
				if start > len(n.Keys) {
					continue
				}
				for i, v := range n.Keys[start:] {
					if v != n.Keys[0] {
						continue
					}
					// #9029: A QUOTED REPEAT IS NOT AMBIGUOUS. The operator
					// wrote `address "address"`, which says in the grammar
					// itself that this token is a NAME and not a keyword — and
					// KeysQuoted is exactly that bit, recorded by #6673 as "the
					// one bit about a key that its TEXT cannot carry".
					//
					// Without this the gate refuses a legitimately-named
					// object, which is the same over-reach #8883's `k == self`
					// skip made in the other direction: it DROPPED the name
					// silently. Both mistakes come from treating a spelling
					// question as unanswerable when the AST already answers it.
					//
					// So the refusal is now scoped to the BARE repeat, which is
					// the missing-semicolon shape and nothing else, and the
					// message can offer quoting as the remedy rather than only
					// describing the ambiguity.
					if n.KeyQuoted(i + start) {
						continue
					}
					msg := fmt.Sprintf(
						"`%s` repeats its own keyword %q among its values. That is ambiguous "+
							"and this build refuses to guess: it is either TWO statements "+
							"missing a semicolon (`%s <a>; %s <b>;`), or ONE statement listing "+
							"a value that happens to be named %q — in which case QUOTE it "+
							"(`%s %q`), which says so in the grammar itself (#9027, #9029)",
						strings.Join(here, " "), v, n.Keys[0], n.Keys[0], v, n.Keys[0], v)
					if lenient {
						slog.Warn("config: a multi-value leaf repeats its own keyword among its values",
							"path", strings.Join(here, " "), "issue", "#9027")
						warnings = append(warnings, msg)
						continue
					}
					return fmt.Errorf("%s", msg)
				}
			}
			// DESCEND CORRECTLY, which is not the same as descending. A node's
			// identity can consume more than one key, and getting this wrong
			// makes the walk stop silently rather than loudly:
			//
			//   compoundKey  `family inet` is ONE node whose schema is
			//                family.children["inet"]; handing its children the
			//                `family` schema advances the schema one level
			//                where the node advanced two, and nothing beneath
			//                is ever visited. This is #8763's finding, and my
			//                first version of this gate reproduced it — the
			//                firewall row of the test below was ACCEPTED
			//                because the walk never reached `from`.
			//   args         a named container (`filter <name>`) consumes its
			//                instance name, and the wildcard holds the body.
			nextSchema := child
			consumed := 1 + child.args
			if child.compoundKey && len(n.Keys) > consumed {
				if sub := resolveSchemaChild(child, n.Keys[consumed]); sub != nil {
					nextSchema = sub
					consumed++
				}
			}
			if nextSchema.wildcard != nil && len(n.Keys) >= consumed && child.args > 0 {
				nextSchema = nextSchema.wildcard
			}
			if err := walk(n.Children, nextSchema, here, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(tree.Children, setSchema, nil, 0); err != nil {
		return warnings, err
	}
	return warnings, nil
}
