// Package web ships the http handlers and the small gmail-style filter
// parser that backs the packages table. Operators supported in this first
// slice: `field:value` (equals / LIKE for strings), `field:>N`, `field:<N`,
// `field:>=N`, `field:<=N`, `-field:value` (NOT), and free-text terms with
// no field prefix match against the table's text-search columns.
//
// The DSL stays small on purpose. Adding operators later is a parser-only
// change; column discovery already comes from the GORM schema.
package web

import (
	"fmt"
	"regexp"
	"strings"
)

// FilterTerm is one parsed clause from the filter bar.
type FilterTerm struct {
	Field    string // empty for free-text terms
	Op       string // ":" "=" ">" "<" ">=" "<="
	Value    string
	Negate   bool
	FreeText bool
}

// Filter parses a filter string and returns SQL-ready (whereClause, args).
// columnSet is the allowed column names for the target table; unknown
// fields become free-text terms so users get a forgiving experience while
// typing.
type Column struct {
	Name      string
	Type      string // "string" | "int" | "float" | "bool" | "time"
	TextMatch bool   // include in free-text search

	// Subquery, when non-empty, makes this a virtual cross-table column.
	// The filter `name:value` emits `id IN (<Subquery>)` instead of
	// `name = ?`. The template must contain exactly one `?` placeholder
	// for the user-supplied value. Used for relationships that don't live
	// on the target row, like packages → maintainers → maintainer_id.
	Subquery string
}

var termRE = regexp.MustCompile(`("[^"]*")|(\S+)`)

// opSpaceRE collapses whitespace around comparison operators so users can
// type `field > 1` or `field>1` and get the same result as `field:>1`.
// Order matters: two-char ops before one-char.
var opSpaceRE = regexp.MustCompile(`\s*(>=|<=|>|<|=)\s*`)

// fieldOpRE turns `field>value` (no colon) into `field:>value` for any
// recognized comparison operator, so the main parser handles it.
var fieldOpRE = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)(>=|<=|>|<|=)`)

// normaliseOperators rewrites loose comparison forms so the tokeniser sees
// the canonical `field:op value` shape regardless of where the user put
// whitespace. We only touch operators preceded by a likely field name to
// avoid mangling free-text terms that happen to contain `>` or `=`.
func normaliseOperators(s string) string {
	// Collapse whitespace around comparison operators when both sides are
	// non-empty. Trim leading whitespace on the operator so `field > 1`
	// becomes `field>1`.
	s = opSpaceRE.ReplaceAllStringFunc(s, func(m string) string {
		// preserve the operator, drop surrounding whitespace
		op := strings.TrimSpace(m)
		return op
	})
	// Inject the `:` separator: `field>1` → `field:>1`.
	s = fieldOpRE.ReplaceAllString(s, "$1:$2")
	return s
}

// Parse splits the input into terms.
func ParseFilter(input string) []FilterTerm {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	input = normaliseOperators(input)
	matches := termRE.FindAllString(input, -1)
	out := make([]FilterTerm, 0, len(matches))
	for _, raw := range matches {
		raw = strings.Trim(raw, "\"")
		if raw == "" {
			continue
		}
		t := FilterTerm{}
		if strings.HasPrefix(raw, "-") {
			t.Negate = true
			raw = raw[1:]
		}
		idx := strings.Index(raw, ":")
		if idx < 0 {
			t.FreeText = true
			t.Value = raw
			out = append(out, t)
			continue
		}
		field := raw[:idx]
		val := raw[idx+1:]
		op := ":"
		switch {
		case strings.HasPrefix(val, ">="):
			op = ">="
			val = val[2:]
		case strings.HasPrefix(val, "<="):
			op = "<="
			val = val[2:]
		case strings.HasPrefix(val, ">"):
			op = ">"
			val = val[1:]
		case strings.HasPrefix(val, "<"):
			op = "<"
			val = val[1:]
		case strings.HasPrefix(val, "="):
			op = "="
			val = val[1:]
		}
		t.Field = field
		t.Op = op
		t.Value = val
		out = append(out, t)
	}
	return out
}

// BuildSQL turns parsed terms into a "WHERE ..." fragment plus the args
// slice for parameterised execution. Unknown fields drop to free-text.
func BuildSQL(terms []FilterTerm, cols map[string]Column) (string, []interface{}) {
	if len(terms) == 0 {
		return "", nil
	}
	var clauses []string
	var args []interface{}

	textCols := []string{}
	for _, c := range cols {
		if c.TextMatch {
			textCols = append(textCols, c.Name)
		}
	}

	for _, t := range terms {
		col, known := cols[t.Field]
		if t.FreeText || !known {
			if len(textCols) == 0 {
				continue
			}
			needle := t.Value
			if !t.FreeText && t.Field != "" {
				// Reattach the unrecognized field as part of the search term
				// rather than silently dropping it.
				needle = t.Field + ":" + t.Value
			}
			ors := make([]string, len(textCols))
			for i, c := range textCols {
				ors[i] = fmt.Sprintf("%s LIKE ?", c)
				args = append(args, "%"+needle+"%")
			}
			clause := "(" + strings.Join(ors, " OR ") + ")"
			if t.Negate {
				clause = "NOT " + clause
			}
			clauses = append(clauses, clause)
			continue
		}

		clause, a := termClause(col, t)
		if clause == "" {
			continue
		}
		clauses = append(clauses, clause)
		args = append(args, a...)
	}

	if len(clauses) == 0 {
		return "", nil
	}
	return strings.Join(clauses, " AND "), args
}

func termClause(col Column, t FilterTerm) (string, []interface{}) {
	negate := ""
	if t.Negate {
		negate = "NOT "
	}
	if col.Subquery != "" {
		// Subqueries with a `?` placeholder bind the term value as an arg
		// (e.g. maintainer_id:42 → ... WHERE maintainer_id = ?). Subqueries
		// without `?` are flag-style filters: the value just flips IN/NOT IN.
		args := []interface{}{}
		if strings.Contains(col.Subquery, "?") {
			args = []interface{}{t.Value}
		}
		return fmt.Sprintf("id %sIN (%s)", negate, col.Subquery), args
	}
	switch col.Type {
	case "string":
		if t.Op == ":" {
			return fmt.Sprintf("%s%s LIKE ?", negate, col.Name), []interface{}{"%" + t.Value + "%"}
		}
		return fmt.Sprintf("%s%s %s ?", negate, col.Name, t.Op), []interface{}{t.Value}
	case "int", "float":
		op := t.Op
		if op == ":" {
			op = "="
		}
		return fmt.Sprintf("%s%s %s ?", negate, col.Name, op), []interface{}{t.Value}
	case "bool":
		v := strings.EqualFold(t.Value, "true") || t.Value == "1"
		op := "="
		if t.Negate {
			return fmt.Sprintf("%s = ?", col.Name), []interface{}{!v}
		}
		return fmt.Sprintf("%s %s ?", col.Name, op), []interface{}{v}
	case "time":
		op := t.Op
		if op == ":" {
			op = "="
		}
		return fmt.Sprintf("%s%s %s ?", negate, col.Name, op), []interface{}{t.Value}
	}
	return "", nil
}
