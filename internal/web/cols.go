package web

import (
	"net/http"
	"strings"
)

// applyColsRedirect is the shared body of every /<section>/cols POST. The
// per-section handlers are thin wrappers that fix the target path so the
// route mux still gets distinct registrations and tests can target them
// individually. Replaces four near-identical copies that linters were
// flagging.
func applyColsRedirect(w http.ResponseWriter, r *http.Request, basePath string) {
	q := r.URL.Query()
	cols := q["col"]
	cleaned := make([]string, 0, len(cols))
	for _, c := range cols {
		c = strings.TrimSpace(c)
		if c != "" {
			cleaned = append(cleaned, c)
		}
	}
	target := basePath
	parts := []string{}
	if v := q.Get("q"); v != "" {
		parts = append(parts, "q="+escape(v))
	}
	if v := q.Get("sort"); v != "" {
		parts = append(parts, "sort="+v)
	}
	if v := q.Get("dir"); v != "" {
		parts = append(parts, "dir="+v)
	}
	if len(cleaned) > 0 {
		parts = append(parts, "cols="+strings.Join(cleaned, ","))
	}
	if len(parts) > 0 {
		target += "?" + strings.Join(parts, "&")
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
