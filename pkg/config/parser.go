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

// ParseSet parses a single "set" command and returns the path components.
// Input: "set security zones security-zone trust interfaces eth0"
// Returns: ["security", "zones", "security-zone", "trust", "interfaces", "eth0"]
func ParseSetCommand(input string) ([]string, error) {
	lexer := NewLexer(input)

	// Consume "set" keyword if present
	tok := lexer.Next()
	if tok.Type != TokenIdentifier {
		return nil, fmt.Errorf("expected identifier, got %s", tok.Type)
	}

	var path []string
	if tok.Value == "set" || tok.Value == "delete" {
		// "set" or "delete" prefix -- read the rest as path
	} else {
		// No prefix -- first token is part of the path
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
			return nil, fmt.Errorf("unexpected token %s at line %d, column %d",
				tok.Type, tok.Line, tok.Column)
		}
	}

	if len(path) == 0 {
		return nil, fmt.Errorf("empty path")
	}
	return path, nil
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
	markerLine, markerCol := p.lexer.Peek().Line, p.lexer.Peek().Column
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
