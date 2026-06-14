// Package sqlgate is an optional, pre-execution validator for the SQL a client
// submits. The server's primary security boundary is the database (a
// least-privilege role, a read-only transaction, and row-level security), but
// "send SQL, get JSON" still hands the caller a large surface that those
// controls do not fully cover: stacked statements, read-but-dangerous statement
// types (SET, SHOW, COPY, EXPLAIN), and the system catalogs (pg_class,
// pg_authid, pg_stat_activity, information_schema) which RLS does not protect.
//
// The gate narrows that surface to a closed shape - a single read-only
// statement over non-catalog objects - before any database work happens. It is
// defense in depth layered on top of the read-only transaction and the grants,
// not a replacement for them.
//
// It is off by default and enabled per deployment. The mode is a string so new,
// stricter modes (table/column allowlists, a forced LIMIT, a planner-cost
// ceiling) can be added later without breaking existing configs.
package sqlgate

import (
	"errors"
	"strings"
)

// Mode is the SQL gate enforcement level.
type Mode string

const (
	// ModeOff disables the gate: every query is allowed (the historical
	// behaviour). The read-only transaction and grants are still in effect.
	ModeOff Mode = "off"
	// ModeOn enforces the baseline policy documented on Check.
	ModeOn Mode = "on"
)

// ValidMode reports whether s names a known gate mode.
func ValidMode(s string) bool {
	switch Mode(s) {
	case ModeOff, ModeOn:
		return true
	default:
		return false
	}
}

// readStarters are the statement-leading keywords the gate treats as read-only.
// Anything else as the first keyword (INSERT/UPDATE/DELETE, DDL, SET, SHOW,
// EXPLAIN, COPY, CALL, DO, ...) is rejected at the edge. A WITH query may still
// wrap a data-modifying CTE; that residual case is caught by the read-only
// transaction, which is why the gate is defense in depth rather than the sole
// write barrier.
var readStarters = map[string]bool{
	"select": true,
	"with":   true,
	"table":  true,
	"values": true,
}

// Rejection reasons. They describe the shape of the request, never server
// internals or data, so they are safe to return to the client verbatim.
var (
	errEmpty    = errors.New("query rejected: empty query")
	errNotRead  = errors.New("query rejected: only read-only SELECT queries are allowed")
	errMultiple = errors.New("query rejected: multiple statements are not allowed")
	errCatalog  = errors.New("query rejected: access to system catalogs is not allowed")
)

// Check validates query under mode. It returns nil when the query is allowed,
// or an error whose message is safe to surface to the client. ModeOff (and only
// ModeOff) allows everything; any other mode applies the baseline policy, so an
// unrecognised mode fails closed to the strict checks.
//
// The baseline policy (ModeOn) enforces three rules, each closing a gap the
// database-level controls leave open:
//
//  1. Single statement - at most one statement, so stacked queries
//     ("SELECT ...; DROP ...") are rejected even where a driver would run them.
//  2. Read-only statement type - the query must begin with SELECT, WITH, TABLE
//     or VALUES, rejecting SET/SHOW/EXPLAIN/COPY/CALL/DO and DDL/DML at the
//     edge; several of those execute even inside a READ ONLY transaction.
//  3. No system catalogs - no identifier may name information_schema or start
//     with the reserved pg_ prefix, closing off catalog enumeration that
//     row-level security does not cover.
func Check(query string, mode Mode) error {
	if mode == ModeOff {
		return nil
	}

	toks := tokenize(query)

	// Rule 2: first significant token, skipping any leading "(" (a parenthesised
	// or set-operation query is valid), must be a read-only statement starter.
	first := 0
	for first < len(toks) && toks[first].kind == tPunct && toks[first].text == "(" {
		first++
	}
	if first >= len(toks) {
		return errEmpty
	}
	if ft := toks[first]; ft.kind != tWord || !readStarters[ft.text] {
		return errNotRead
	}

	// Rules 1 and 3 in a single pass over the token stream.
	for i, t := range toks {
		switch {
		case t.kind == tPunct && t.text == ";":
			// A semicolon is allowed only as the final significant token (a bare
			// trailing terminator); anything after it is a second statement.
			if i != len(toks)-1 {
				return errMultiple
			}
		case t.kind == tWord || t.kind == tIdent:
			if isCatalogIdent(t.text) {
				return errCatalog
			}
		}
	}
	return nil
}

// isCatalogIdent reports whether a (lower-cased) identifier names a system
// catalog. The pg_ prefix is reserved by PostgreSQL for system schemas, tables,
// and functions; information_schema is the SQL-standard catalog. Both are
// readable regardless of row-level security, so the gate blocks them.
func isCatalogIdent(name string) bool {
	return name == "information_schema" || strings.HasPrefix(name, "pg_")
}

// --- tokenizer ---------------------------------------------------------------
//
// The tokenizer is deliberately lightweight: it does not parse SQL, it
// classifies the lexical structure well enough to apply the rules above without
// being fooled by content inside comments, string literals, dollar-quoted
// bodies, or quoted identifiers. Whitespace, comments, strings, and dollar
// quotes are dropped; words, quoted identifiers, and single-character
// punctuation are emitted.

type tokKind int

const (
	tWord  tokKind = iota // unquoted identifier or keyword (text is lower-cased)
	tIdent                // "quoted identifier" (text is the inner name, lower-cased)
	tPunct                // a single punctuation byte such as ; ( ) . ,
)

type token struct {
	kind tokKind
	text string
}

func tokenize(s string) []token {
	var toks []token
	n := len(s)
	for i := 0; i < n; {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < n && s[i+1] == '-':
			// line comment to end of line
			i += 2
			for i < n && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && s[i+1] == '*':
			i = skipBlockComment(s, i)
		case c == '\'':
			// standard string literal: only '' escapes a quote
			i = skipString(s, i, false)
		case (c == 'e' || c == 'E') && i+1 < n && s[i+1] == '\'':
			// escape string E'...': backslash also escapes
			i = skipString(s, i+1, true)
		case c == '"':
			j, text := scanQuotedIdent(s, i)
			toks = append(toks, token{tIdent, strings.ToLower(text)})
			i = j
		case c == '$':
			if end, ok := dollarQuote(s, i); ok {
				i = end
			} else {
				// positional parameter ($1) or a $ inside an identifier: skip the
				// $ and any following identifier bytes so it cannot form a word.
				i++
				for i < n && isWordByte(s[i]) {
					i++
				}
			}
		case isWordStart(c):
			j := i + 1
			for j < n && isWordByte(s[j]) {
				j++
			}
			toks = append(toks, token{tWord, strings.ToLower(s[i:j])})
			i = j
		default:
			toks = append(toks, token{tPunct, string(c)})
			i++
		}
	}
	return toks
}

// skipBlockComment returns the index past a /* ... */ comment that starts at
// s[i]. PostgreSQL block comments nest, so it tracks depth.
func skipBlockComment(s string, i int) int {
	n := len(s)
	depth := 1
	i += 2
	for i < n && depth > 0 {
		if i+1 < n && s[i] == '/' && s[i+1] == '*' {
			depth++
			i += 2
			continue
		}
		if i+1 < n && s[i] == '*' && s[i+1] == '/' {
			depth--
			i += 2
			continue
		}
		i++
	}
	return i
}

// skipString returns the index past a single-quoted string literal whose
// opening quote is at s[q]. A doubled ” is always an escaped quote; when
// backslash is true (an E'...' escape string) a backslash escapes the next
// byte. An unterminated literal consumes to end of input.
func skipString(s string, q int, backslash bool) int {
	n := len(s)
	for i := q + 1; i < n; {
		c := s[i]
		if backslash && c == '\\' {
			i += 2
			continue
		}
		if c == '\'' {
			if i+1 < n && s[i+1] == '\'' {
				i += 2
				continue
			}
			return i + 1
		}
		i++
	}
	return n
}

// scanQuotedIdent returns the index past a "quoted identifier" whose opening
// quote is at s[q], and its unescaped inner text (a doubled "" is a literal
// quote). An unterminated identifier consumes to end of input.
func scanQuotedIdent(s string, q int) (int, string) {
	n := len(s)
	var b strings.Builder
	for i := q + 1; i < n; {
		c := s[i]
		if c == '"' {
			if i+1 < n && s[i+1] == '"' {
				b.WriteByte('"')
				i += 2
				continue
			}
			return i + 1, b.String()
		}
		b.WriteByte(c)
		i++
	}
	return n, b.String()
}

// dollarQuote detects a PostgreSQL dollar-quoted string opening at s[i]=='$'.
// It returns the index past the closing delimiter and true for a valid
// $tag$...$tag$ (or $$...$$) literal. A $ that begins a positional parameter
// ($1) or is otherwise not a dollar quote returns ok=false. An unterminated
// literal consumes to end of input.
func dollarQuote(s string, i int) (int, bool) {
	n := len(s)
	j := i + 1
	// optional tag: [A-Za-z_][A-Za-z0-9_]* (may not start with a digit)
	if j < n && (isLetter(s[j]) || s[j] == '_') {
		j++
		for j < n && (isLetter(s[j]) || isDigit(s[j]) || s[j] == '_') {
			j++
		}
	}
	if j >= n || s[j] != '$' {
		return 0, false
	}
	tag := s[i : j+1] // e.g. "$$" or "$tag$"
	rest := s[j+1:]
	if k := strings.Index(rest, tag); k >= 0 {
		return j + 1 + k + len(tag), true
	}
	return n, true
}

func isLetter(c byte) bool    { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool     { return c >= '0' && c <= '9' }
func isWordStart(c byte) bool { return isLetter(c) || c == '_' || c >= 0x80 }
func isWordByte(c byte) bool  { return isLetter(c) || isDigit(c) || c == '_' || c >= 0x80 }
