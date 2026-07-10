package config

import "fmt"

// ParseError represents a configuration parse error with location.
type ParseError struct {
	Line    int
	Column  int
	Message string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("line %d, column %d: %s", e.Line, e.Column, e.Message)
}

// maxParseDepth caps recursive-descent block nesting. parseStatement recurses
// into parseStatements for every `{ ... }` block, so a payload of deeply nested
// braces (`a{a{a{…}`) would otherwise grow the goroutine stack past Go's 1 GiB
// maxstacksize and abort xpfd with an unrecoverable `fatal error: stack
// overflow` (fable-review-164 H-2). 256 levels is far above any real Junos
// configuration; past it the parser records a ParseError and stops descending
// rather than recursing.
const maxParseDepth = 256

// Parser implements a recursive descent parser for Junos configuration syntax.
type Parser struct {
	lexer  *Lexer
	errors []ParseError
	depth  int // current block-nesting depth (bounded by maxParseDepth)
}

// NewParser creates a new Parser for the given configuration text.
func NewParser(input string) *Parser {
	return &Parser{
		lexer: NewLexer(input),
	}
}

// Parse parses the input and returns the configuration tree.
//
// After the top-level statement list, the lexer MUST be at EOF. parseStatements
// breaks on a top-level TokenRBrace (a stray unmatched '}') identically to EOF,
// so historically a single stray brace made Parse return the partial tree with
// ZERO errors and silently drop every statement after the brace — a fail-open
// config-acceptance path (#4862): LoadOverride / CheckText only gate on
// len(errs)==0, so a truncated config (missing its security/default-policy
// tail) committed as if it were the authored file. Assert EOF here. A leftover
// '}' (or any other stray token) is a ParseError naming its position; rather
// than discard the trailing config on the floor we consume the stray token and
// resume parsing so BOTH the error and the remaining statements surface (the
// error still fails the commit — the tree is never silently truncated). Every
// iteration consumes at least the one stray token, so the loop always
// terminates. Correctly nested '{ ... }' blocks are unaffected: parseStatement
// consumes each block's own closing '}', so only an unmatched top-level '}'
// reaches this check.
func (p *Parser) Parse() (*ConfigTree, []ParseError) {
	children := p.parseStatements()
	for {
		tok := p.lexer.Peek()
		if tok.Type == TokenEOF {
			break
		}
		p.addError(tok.Line, tok.Column,
			fmt.Sprintf("unexpected %s at top level (unmatched '}'?)", tok))
		p.lexer.Next() // consume the stray token to guarantee forward progress
		children = append(children, p.parseStatements()...)
	}
	tree := &ConfigTree{Children: children}
	return tree, p.errors
}

// Config-edit verbs recognized at the start of a flat command line
// (ParseSetVerb). `set`/`delete` are the historical verbs; `deactivate`/
// `activate` (#2008 H1) toggle Node.Inactive so that `show | display set`
// output — which emits a `deactivate <path>` line for every inactive node
// (ast_format.go) — round-trips back to an inactive node on reload. A line
// with no recognized verb is treated as a bare path (verb "set").
const (
	verbSet        = "set"
	verbDelete     = "delete"
	verbDeactivate = "deactivate"
	verbActivate   = "activate"
)

// ParseSetCommand parses a single flat command and returns the path
// components, discarding the verb. Input: "set security zones
// security-zone trust interfaces eth0" returns ["security", "zones",
// "security-zone", "trust", "interfaces", "eth0"]. It accepts a `set`,
// `delete`, `deactivate`, or `activate` prefix (or no prefix). Callers that
// must apply the correct edit for a `deactivate`/`activate` line MUST use
// ParseSetVerb instead — ParseSetCommand collapses every verb to its path,
// so feeding it a `deactivate ...` line and then calling SetPath would
// re-add the node as ACTIVE.
func ParseSetCommand(input string) ([]string, error) {
	_, path, err := ParseSetVerb(input)
	return path, err
}

// ParseSetVerb parses a single flat command into its verb and path. The
// verb is one of "set", "delete", "deactivate", or "activate"; a line with
// no recognized leading verb is reported as "set" with the whole line as
// the path (preserving the historical ParseSetCommand behavior where an
// unprefixed line is a bare path). #2008 H1: the `deactivate`/`activate`
// verbs make `show | display set` output round-trippable — the replay
// callers (configstore LoadSet / LoadMerge) switch on the returned verb to
// flip Node.Inactive instead of re-adding an active node.
func ParseSetVerb(input string) (verb string, path []string, err error) {
	lexer := NewLexer(input)

	tok := lexer.Next()
	if tok.Type != TokenIdentifier {
		return "", nil, fmt.Errorf("expected identifier, got %s", tok.Type)
	}

	switch tok.Value {
	case verbSet, verbDelete, verbDeactivate, verbActivate:
		verb = tok.Value
	default:
		// No recognized prefix -- the first token is part of the path and
		// the verb defaults to set (a bare path).
		verb = verbSet
		path = append(path, tok.Value)
	}

	for {
		tok = lexer.Next()
		if tok.Type == TokenEOF {
			break
		}
		if tok.Type == TokenSemicolon {
			// #5194 A3-b3-F7: a single trailing semicolon terminates the flat
			// command, but any token AFTER it is a second statement crammed onto
			// one line (e.g. `set system host-name fw; delete security policies`).
			// The pre-fix loop broke on the semicolon and SILENTLY discarded the
			// remainder while the caller (LoadSet applyEditLine) reported the line
			// applied — so the trailing `delete` never ran yet commit reported
			// success. Permit at most one terminating semicolon, then require EOF;
			// reject any subsequent token with its line/column.
			if next := lexer.Next(); next.Type != TokenEOF {
				return "", nil, fmt.Errorf(
					"unexpected token %s after ';' at line %d, column %d (only one statement per line)",
					next.Type, next.Line, next.Column)
			}
			break
		}
		if tok.Type == TokenIdentifier || tok.Type == TokenString {
			path = append(path, tok.Value)
		} else {
			return "", nil, fmt.Errorf("unexpected token %s at line %d, column %d",
				tok.Type, tok.Line, tok.Column)
		}
	}

	if len(path) == 0 {
		return "", nil, fmt.Errorf("empty path")
	}
	return verb, path, nil
}

// parseStatements parses zero or more statements until EOF or '}'.
func (p *Parser) parseStatements() []*Node {
	// Bound block-nesting recursion (H-2). parseStatement recurses back into
	// parseStatements for every `{` block; without this guard a deeply nested
	// brace payload overflows the goroutine stack (an unrecoverable throw, not
	// a panic). Past the cap we record a ParseError at the current position and
	// stop descending. The caller's error-recovery path then drains the
	// remaining tokens linearly (parseKeys yields nothing on `{`/`}`, so each
	// parseStatement consumes one token), so parsing terminates cleanly with an
	// error instead of crashing.
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxParseDepth {
		tok := p.lexer.Peek()
		p.addError(tok.Line, tok.Column,
			fmt.Sprintf("configuration nesting exceeds maximum depth of %d", maxParseDepth))
		// Drain the remainder of this over-deep block iteratively (no
		// recursion) so a pathological payload records exactly one error and
		// leaves the caller's matching '}' in place, rather than spamming one
		// error per leftover token and holding O(N) ParseError structs.
		p.skipToBlockClose()
		return nil
	}

	var nodes []*Node
	for {
		tok := p.lexer.Peek()
		if tok.Type == TokenEOF || tok.Type == TokenRBrace {
			break
		}
		if tok.Type == TokenError {
			p.addError(tok.Line, tok.Column, tok.Value)
			p.lexer.Next() // consume error token
			continue
		}
		node := p.parseStatement()
		if node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// skipToBlockClose consumes tokens until the '}' that closes the block whose
// opening '{' the caller already consumed (or EOF), tracking brace balance
// iteratively so it never recurses. The closing '}' at balance 0 is left in
// place for the caller to consume. It is used only on the depth-cap path so a
// maliciously deep payload is drained in O(remaining) with no additional
// goroutine-stack growth (H-2).
func (p *Parser) skipToBlockClose() {
	balance := 0
	for {
		tok := p.lexer.Peek()
		switch tok.Type {
		case TokenEOF:
			return
		case TokenLBrace:
			balance++
			p.lexer.Next()
		case TokenRBrace:
			if balance == 0 {
				return // closes the caller's block; leave it for the caller
			}
			balance--
			p.lexer.Next()
		default:
			p.lexer.Next()
		}
	}
}

// inactiveMarker is the Junos `inactive:` statement prefix (#2008 H1).
// Because `:` is an identifier character (lexer.isIdentChar), the lexer
// tokenizes `inactive:` as a single identifier; the parser detects it as
// the leading key of a statement and lifts it into Node.Inactive rather
// than letting it mangle the node's identity (Keys[0]).
//
// The marker is recognized ONLY when the source token is a bare
// TokenIdentifier. A QUOTED `"inactive:"` (TokenString) is a literal value
// that merely equals the marker text (e.g. `description "inactive:";`) and
// must be preserved, so parseStatement gates both the leading and inline
// marker checks on the parallel token-kind slice from parseKeys (#4348).
const inactiveMarker = "inactive:"

// parseStatement parses one statement: keys followed by ; or { block }.
// A leading `inactive:` marker is stripped from the keys and recorded on
// the returned Node so the statement's real identity (Keys) is unchanged
// and key matching, schema walks, and group merge keep working unmodified.
func (p *Parser) parseStatement() *Node {
	statementStart := p.lexer.Peek()
	keys, kinds := p.parseKeys()
	if len(keys) == 0 {
		// Recovery: skip unexpected token
		tok := p.lexer.Next()
		if tok.Type != TokenEOF {
			p.addError(tok.Line, tok.Column,
				fmt.Sprintf("unexpected %s", tok))
		}
		return nil
	}

	// Detect a leading `inactive:` deactivation marker and lift it off the
	// keys. A lone `inactive:` with no following statement is a parse error
	// (Junos requires a statement to deactivate). The marker is recognized
	// ONLY as a bare identifier token — a QUOTED `"inactive:"` (TokenString)
	// is a literal value (e.g. `description "inactive:";`) and must be
	// preserved, never treated as a deactivation marker (#4348).
	inactive := false
	markerLine, markerCol := statementStart.Line, statementStart.Column
	if kinds[0] == TokenIdentifier && keys[0] == inactiveMarker {
		inactive = true
		keys = keys[1:]
		kinds = kinds[1:]
		if len(keys) == 0 {
			p.addError(markerLine, markerCol,
				"inactive: marker must be followed by a statement")
			// Consume a trailing terminator if present so we don't loop.
			if t := p.lexer.Peek(); t.Type == TokenSemicolon || t.Type == TokenLBrace {
				p.skipStatementBody()
			}
			return nil
		}
	}

	// Detect an INLINE `inactive:` marker (#4335). Junos also collapses a
	// deactivated sub-statement onto its parent statement's line, e.g.
	//   address 2001:db8::7aef/128 inactive: port 32400;
	// where the `inactive:` deactivates the `port 32400` modifier, NOT the
	// address. Because `:` is an identifier character the lexer tokenizes
	// `inactive:` as one identifier, so it lands mid-keys instead of leading.
	// A node carries a single Inactive flag for its whole identity and cannot
	// mark only part of a flat leaf inactive; consistent with the #2008 H1
	// doctrine that a deactivated statement behaves as if it were absent, drop
	// the marker and every token it governs (the remainder of this statement)
	// from the active keys. The parent statement (here the address) stays
	// active; the governed sub-statement (the port) is simply absent, exactly
	// as a deactivated leaf would be for compilation. A leading marker is
	// already lifted above, so any remaining marker is strictly inline (index
	// > 0) and leaves at least the statement's identity key intact.
	// As with the leading marker, only a bare identifier `inactive:` counts;
	// a quoted `"inactive:"` value (TokenString) is preserved (#4348).
	for i, k := range keys {
		if i > 0 && kinds[i] == TokenIdentifier && k == inactiveMarker {
			keys = keys[:i]
			// The governed tokens were only on the key line of a leaf; a
			// trailing `{ ... }` cannot follow an inline marker in valid
			// Junos, so nothing more to consume here.
			break
		}
	}

	line := p.lexer.Peek().Line
	col := p.lexer.Peek().Column

	tok := p.lexer.Peek()
	switch tok.Type {
	case TokenLBrace:
		// Block: { children }
		p.lexer.Next() // consume {
		children := p.parseStatements()
		closeTok := p.lexer.Peek()
		if closeTok.Type == TokenRBrace {
			p.lexer.Next() // consume }
		} else {
			p.addError(closeTok.Line, closeTok.Column,
				fmt.Sprintf("expected '}', got %s", closeTok))
		}
		return &Node{
			Keys:     keys,
			Children: children,
			Inactive: inactive,
			Line:     line,
			Column:   col,
		}

	case TokenSemicolon:
		// Leaf: keys ;
		p.lexer.Next() // consume ;
		return &Node{
			Keys:     keys,
			IsLeaf:   true,
			Inactive: inactive,
			Line:     line,
			Column:   col,
		}

	default:
		// No semicolon or brace -- treat as implicit leaf
		// (some Junos statements can omit trailing semicolon at EOF)
		return &Node{
			Keys:     keys,
			IsLeaf:   true,
			Inactive: inactive,
			Line:     line,
			Column:   col,
		}
	}
}

// skipStatementBody consumes a `;` or a balanced `{ ... }` block so error
// recovery after a malformed `inactive:` marker does not desync the parser.
func (p *Parser) skipStatementBody() {
	tok := p.lexer.Peek()
	switch tok.Type {
	case TokenSemicolon:
		p.lexer.Next()
	case TokenLBrace:
		p.lexer.Next() // consume {
		p.parseStatements()
		if p.lexer.Peek().Type == TokenRBrace {
			p.lexer.Next() // consume }
		}
	}
}

// parseKeys reads one or more identifiers/strings until { or ; or } or EOF.
// It returns the token VALUES and a parallel slice of the source token KINDS
// (TokenIdentifier vs TokenString). The kinds let the caller distinguish a
// bare identifier `inactive:` (a deactivation marker) from a quoted
// `"inactive:"` value that happens to equal the marker text (#4348) — the
// []string alone flattens the two into an indistinguishable string.
func (p *Parser) parseKeys() ([]string, []TokenType) {
	var keys []string
	var kinds []TokenType
	for {
		tok := p.lexer.Peek()
		if tok.Type == TokenIdentifier || tok.Type == TokenString {
			p.lexer.Next()
			keys = append(keys, tok.Value)
			kinds = append(kinds, tok.Type)
		} else {
			break
		}
	}
	return keys, kinds
}

func (p *Parser) addError(line, col int, msg string) {
	p.errors = append(p.errors, ParseError{
		Line:    line,
		Column:  col,
		Message: msg,
	})
}
