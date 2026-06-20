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

// Parser implements a recursive descent parser for Junos configuration syntax.
type Parser struct {
	lexer  *Lexer
	errors []ParseError
}

// NewParser creates a new Parser for the given configuration text.
func NewParser(input string) *Parser {
	return &Parser{
		lexer: NewLexer(input),
	}
}

// Parse parses the input and returns the configuration tree.
func (p *Parser) Parse() (*ConfigTree, []ParseError) {
	children := p.parseStatements()
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
		if tok.Type == TokenEOF || tok.Type == TokenSemicolon {
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

// inactiveMarker is the Junos `inactive:` statement prefix (#2008 H1).
// Because `:` is an identifier character (lexer.isIdentChar), the lexer
// tokenizes `inactive:` as a single identifier; the parser detects it as
// the leading key of a statement and lifts it into Node.Inactive rather
// than letting it mangle the node's identity (Keys[0]).
const inactiveMarker = "inactive:"

// parseStatement parses one statement: keys followed by ; or { block }.
// A leading `inactive:` marker is stripped from the keys and recorded on
// the returned Node so the statement's real identity (Keys) is unchanged
// and key matching, schema walks, and group merge keep working unmodified.
func (p *Parser) parseStatement() *Node {
	statementStart := p.lexer.Peek()
	keys := p.parseKeys()
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
	// (Junos requires a statement to deactivate).
	inactive := false
	markerLine, markerCol := statementStart.Line, statementStart.Column
	if keys[0] == inactiveMarker {
		inactive = true
		keys = keys[1:]
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
func (p *Parser) parseKeys() []string {
	var keys []string
	for {
		tok := p.lexer.Peek()
		if tok.Type == TokenIdentifier || tok.Type == TokenString {
			p.lexer.Next()
			keys = append(keys, tok.Value)
		} else {
			break
		}
	}
	return keys
}

func (p *Parser) addError(line, col int, msg string) {
	p.errors = append(p.errors, ParseError{
		Line:    line,
		Column:  col,
		Message: msg,
	})
}
