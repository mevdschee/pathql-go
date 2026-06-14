package main

// hasMultipleStatements reports whether sql contains more than one SQL
// statement, used to enforce the security.block_multiple_statements policy.
//
// It is a conservative lexical scan, not a full parser: it counts semicolons
// that are not inside a single-quoted string, a double-quoted identifier, a
// dollar-quoted string, a line comment (-- ... newline) or a block comment
// (/* ... */). A single optional trailing semicolon (possibly followed by
// whitespace) is allowed. Any additional statement-separating semicolon makes
// the query multi-statement.
//
// Because it is conservative it can only ever over-count separators it is
// unsure about toward "multiple"; it never silently allows a stacked query. The
// known limitation is that exotic constructs (e.g. dollar-quoted tags with the
// same body) are treated by their delimiters, which is safe for rejection.
func hasMultipleStatements(sql string) bool {
	const (
		stNormal = iota
		stSingle // inside '...'
		stDouble // inside "..."
		stLine   // inside -- ... to end of line
		stBlock  // inside /* ... */
		stDollar // inside $tag$ ... $tag$
	)

	state := stNormal
	dollarTag := "" // the active $tag$ delimiter when state == stDollar

	// trailing tracks whether everything after the last seen ';' has been only
	// whitespace, so a single terminating ';' is permitted.
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		switch state {
		case stNormal:
			switch {
			case c == '\'':
				state = stSingle
			case c == '"':
				state = stDouble
			case c == '-' && i+1 < len(sql) && sql[i+1] == '-':
				state = stLine
				i++
			case c == '/' && i+1 < len(sql) && sql[i+1] == '*':
				state = stBlock
				i++
			case c == '$':
				if tag, ok := dollarTagAt(sql, i); ok {
					dollarTag = tag
					state = stDollar
					i += len(tag) - 1
				}
			case c == ';':
				// A separator. If anything other than whitespace and comments
				// follows, this is a multi-statement query.
				if !onlyTrailing(sql[i+1:]) {
					return true
				}
				return false
			}
		case stSingle:
			if c == '\'' {
				// '' is an escaped quote inside a single-quoted string.
				if i+1 < len(sql) && sql[i+1] == '\'' {
					i++
					continue
				}
				state = stNormal
			}
		case stDouble:
			if c == '"' {
				if i+1 < len(sql) && sql[i+1] == '"' {
					i++
					continue
				}
				state = stNormal
			}
		case stLine:
			if c == '\n' {
				state = stNormal
			}
		case stBlock:
			if c == '*' && i+1 < len(sql) && sql[i+1] == '/' {
				state = stNormal
				i++
			}
		case stDollar:
			if c == '$' {
				if tag, ok := dollarTagAt(sql, i); ok && tag == dollarTag {
					state = stNormal
					dollarTag = ""
					i += len(tag) - 1
				}
			}
		}
	}
	return false
}

// dollarTagAt returns the dollar-quote tag (e.g. "$$" or "$body$") starting at
// position i in sql, if sql[i] begins a valid dollar-quote delimiter. The tag
// is "$" + optional identifier + "$".
func dollarTagAt(sql string, i int) (string, bool) {
	if i >= len(sql) || sql[i] != '$' {
		return "", false
	}
	j := i + 1
	for j < len(sql) {
		c := sql[j]
		if c == '$' {
			return sql[i : j+1], true
		}
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return "", false
		}
		j++
	}
	return "", false
}

// onlyTrailing reports whether the remainder after a semicolon is only
// whitespace and/or comments, in which case the semicolon is a permitted
// terminator rather than a statement separator.
func onlyTrailing(rest string) bool {
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f':
			continue
		case c == '-' && i+1 < len(rest) && rest[i+1] == '-':
			// Line comment to end of line.
			for i < len(rest) && rest[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(rest) && rest[i+1] == '*':
			// Block comment to its close.
			i += 2
			for i+1 < len(rest) && !(rest[i] == '*' && rest[i+1] == '/') {
				i++
			}
			i++ // consume the '/'
		case c == ';':
			// A second terminator: e.g. "SELECT 1;;" - the empty statement
			// between them still makes this more than one statement.
			return false
		default:
			return false
		}
	}
	return true
}
