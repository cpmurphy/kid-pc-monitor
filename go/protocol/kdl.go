package protocol

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxNestingDepth bounds how deeply blocks may nest.
const MaxNestingDepth = 32

// Node is a single KDL node: a name, zero or more scalar args, and children.
type Node struct {
	Name     string
	Args     []Value
	Children []Node
}

// N builds a node with the given args (a convenience for literals).
func N(name string, args ...Value) Node {
	n := Node{Name: name}
	for _, a := range args {
		n.Args = append(n.Args, normalize(a))
	}
	return n
}

// Block builds a node with children.
func Block(name string, children ...Node) Node {
	return Node{Name: name, Children: children}
}

// Arg returns the first argument, or nil.
func (n Node) Arg() Value {
	if len(n.Args) == 0 {
		return nil
	}
	return n.Args[0]
}

// ChildMap maps child names to their first argument (the last duplicate wins).
func (n Node) ChildMap() map[string]Value {
	m := make(map[string]Value, len(n.Children))
	for _, c := range n.Children {
		m[c.Name] = c.Arg()
	}
	return m
}

func isBare(s string) bool {
	if s == "" || s == "true" || s == "false" || s == "null" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		letter := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'
		if i == 0 {
			if !letter {
				return false
			}
			continue
		}
		if !letter && !(c >= '0' && c <= '9') && !strings.ContainsRune(".:+-", rune(c)) {
			return false
		}
	}
	return true
}

func escape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`, "\r", `\r`)
	return r.Replace(s)
}

// FormatValue renders a scalar as a KDL token.
func FormatValue(v Value) string {
	switch x := normalize(v).(type) {
	case nil:
		return "null"
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int64:
		return strconv.FormatInt(x, 10)
	case string:
		if isBare(x) {
			return x
		}
		return `"` + escape(x) + `"`
	}
	return FormatValue(pyStr(v))
}

// Serialize renders nodes as a KDL-subset document body (no trailing newline).
// The output is also the canonical string that frame signatures cover.
func Serialize(nodes []Node) string {
	var lines []string
	serializeInto(nodes, 0, &lines)
	return strings.Join(lines, "\n")
}

func serializeInto(nodes []Node, indent int, lines *[]string) {
	pad := strings.Repeat(" ", indent)
	for _, n := range nodes {
		parts := make([]string, 0, 1+len(n.Args))
		parts = append(parts, n.Name)
		for _, a := range n.Args {
			parts = append(parts, FormatValue(a))
		}
		prefix := pad + strings.Join(parts, " ")
		if len(n.Children) > 0 {
			*lines = append(*lines, prefix+" {")
			serializeInto(n.Children, indent+2, lines)
			*lines = append(*lines, pad+"}")
		} else {
			*lines = append(*lines, prefix)
		}
	}
}

type tokKind int

const (
	tokNL tokKind = iota
	tokLB
	tokRB
	tokVal
)

type token struct {
	kind tokKind
	val  Value
}

func bad(msg string) *ProtocolError { return perr(InvalidRequest, msg, nil) }

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// unescape decodes the escape sequence whose first character is at text[start]
// (the backslash is at start-1). It returns the decoded text and the index
// after the sequence.
func unescape(text string, start int) (string, int, error) {
	if start >= len(text) {
		return "", 0, bad("unterminated string")
	}
	switch text[start] {
	case 'n':
		return "\n", start + 1, nil
	case 't':
		return "\t", start + 1, nil
	case 'r':
		return "\r", start + 1, nil
	case '"':
		return `"`, start + 1, nil
	case '\\':
		return `\`, start + 1, nil
	case '/':
		return "/", start + 1, nil
	case 'u':
		if start+1 < len(text) && text[start+1] == '{' {
			end := strings.IndexByte(text[start+2:], '}')
			if end == -1 {
				return "", 0, bad("unterminated unicode escape")
			}
			end += start + 2
			digits := text[start+2 : end]
			if digits == "" || len(digits) > 8 {
				return "", 0, bad("bad unicode escape")
			}
			for i := 0; i < len(digits); i++ {
				if !isHex(digits[i]) {
					return "", 0, bad("bad unicode escape")
				}
			}
			cp, _ := strconv.ParseUint(digits, 16, 32)
			if cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) {
				return "", 0, bad("bad unicode escape")
			}
			return string(rune(cp)), end + 1, nil
		}
	}
	return "", 0, bad("unsupported escape: \\" + string(text[start]))
}

func parseBare(word string) (Value, error) {
	switch word {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null":
		return nil, nil
	}
	digits := strings.TrimLeft(word, "+-")
	if len(word)-len(digits) <= 1 && asciiDigits(digits) {
		n, err := strconv.ParseInt(word, 10, 64)
		if err != nil {
			return nil, bad("integer out of range")
		}
		return n, nil
	}
	return word, nil
}

func isDelim(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '{', '}', ';', '"':
		return true
	}
	return false
}

func tokenize(text string) ([]token, error) {
	var tokens []token
	i, n := 0, len(text)
	for i < n {
		switch ch := text[i]; ch {
		case ' ', '\t':
			i++
		case '\n', '\r', ';':
			tokens = append(tokens, token{kind: tokNL})
			i++
		case '{':
			tokens = append(tokens, token{kind: tokLB})
			i++
		case '}':
			tokens = append(tokens, token{kind: tokRB})
			i++
		case '"':
			i++
			var buf strings.Builder
			for i < n && text[i] != '"' {
				if text[i] == '\\' {
					decoded, next, err := unescape(text, i+1)
					if err != nil {
						return nil, err
					}
					buf.WriteString(decoded)
					i = next
				} else {
					buf.WriteByte(text[i])
					i++
				}
			}
			if i >= n {
				return nil, bad("unterminated string")
			}
			i++ // closing quote
			tokens = append(tokens, token{kind: tokVal, val: buf.String()})
		default:
			start := i
			for i < n && !isDelim(text[i]) {
				i++
			}
			v, err := parseBare(text[start:i])
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token{kind: tokVal, val: v})
		}
	}
	return tokens, nil
}

// Parse parses a KDL-subset document body into nodes. Errors are
// *ProtocolError with code invalid_request.
func Parse(text string) ([]Node, error) {
	if !utf8.ValidString(text) {
		return nil, bad("body is not valid UTF-8")
	}
	tokens, err := tokenize(text)
	if err != nil {
		return nil, err
	}
	pos := 0
	var parseNodes func(depth int) ([]Node, error)
	parseNodes = func(depth int) ([]Node, error) {
		inBlock := depth > 0
		var nodes []Node
		for pos < len(tokens) {
			t := tokens[pos]
			switch t.kind {
			case tokNL:
				pos++
				continue
			case tokRB:
				if !inBlock {
					return nil, bad("unexpected '}'")
				}
				pos++
				return nodes, nil
			case tokLB:
				return nil, bad("unexpected '{'")
			}
			name, ok := t.val.(string)
			if !ok {
				return nil, bad("node name must be an identifier")
			}
			pos++
			node := Node{Name: name}
			for pos < len(tokens) && tokens[pos].kind == tokVal {
				node.Args = append(node.Args, tokens[pos].val)
				pos++
			}
			if pos < len(tokens) && tokens[pos].kind == tokLB {
				if depth >= MaxNestingDepth {
					return nil, bad("blocks nested too deeply")
				}
				pos++
				children, err := parseNodes(depth + 1)
				if err != nil {
					return nil, err
				}
				node.Children = children
			}
			nodes = append(nodes, node)
		}
		if inBlock {
			return nil, bad("missing '}'")
		}
		return nodes, nil
	}
	return parseNodes(0)
}

// PeekVersion makes a best-effort read of "v" for error responses when a full
// parse fails. Only a supported version is echoed; anything else is answered
// at the default version.
func PeekVersion(body string) int64 {
	nodes, err := Parse(body)
	if err != nil {
		return ClientDefaultVersion
	}
	for _, n := range nodes {
		if n.Name == "v" && len(n.Args) > 0 {
			if v, ok := n.Args[0].(int64); ok && SupportedVersion(v) {
				return v
			}
		}
	}
	return ClientDefaultVersion
}
