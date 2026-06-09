package web

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/alpha-omega-security/marshal/internal/db"
)

func advisoryColumns() map[string]Column {
	return map[string]Column{
		"uuid":           {Name: "uuid", Type: "string", TextMatch: true},
		"url":            {Name: "url", Type: "string"},
		"title":          {Name: "title", Type: "string", TextMatch: true},
		"description":    {Name: "description", Type: "string", TextMatch: true},
		"origin":         {Name: "origin", Type: "string"},
		"severity":       {Name: "severity", Type: "string"},
		"classification": {Name: "classification", Type: "string"},
		"source_kind":    {Name: "source_kind", Type: "string"},
		"cvss_score":     {Name: "cvss_score", Type: "float"},
		"published_at":   {Name: "published_at", Type: "time"},
		"withdrawn_at":   {Name: "withdrawn_at", Type: "time"},
		"local_packages_count": {Name: "local_packages_count", Type: "int"},

		// virtual cross-table: filter to advisories affecting a given package
		"package_id": {
			Name:     "package_id",
			Type:     "int",
			Subquery: "SELECT advisory_id FROM package_advisories WHERE package_id = ?",
		},
		// two-hop: advisories affecting any package belonging to this repo
		"repository_id": {
			Name:     "repository_id",
			Type:     "int",
			Subquery: "SELECT pa.advisory_id FROM package_advisories pa JOIN packages p ON p.id = pa.package_id WHERE p.repository_id = ?",
		},
		// flag-style virtual: advisories with at least one package whose
		// first_patched_version is empty. Value-agnostic; presence flips
		// IN, NOT (via `-unpatched:true`) flips to NOT IN.
		"unpatched": {
			Name:     "unpatched",
			Type:     "bool",
			Subquery: "SELECT advisory_id FROM package_advisories WHERE first_patched_version IS NULL OR first_patched_version = ''",
		},
		// flag-style virtual: advisories whose vulnerable range actually
		// matches at least one observed version in the loaded SBOMs.
		"effective": {
			Name:     "effective",
			Type:     "bool",
			Subquery: "SELECT advisory_id FROM package_advisories WHERE effective = 1",
		},
		"import_id": {
			Name:     "import_id",
			Type:     "int",
			Subquery: "SELECT DISTINCT pa.advisory_id FROM package_advisories pa JOIN package_imports pi ON pi.package_id = pa.package_id WHERE pi.import_id = ?",
		},
	}
}

type advisoryView struct {
	Theme         string
	Nav           string
	FilterInput   string
	Sort          string
	Dir           string
	ColsParam     string
	Rows          [][]Cell
	Total         int64
	Columns       []columnView
	FilterColumns []filterHint
	CannedFilters []cannedFilterView
	SavedFilters  []savedFilterView
	ColumnChoices []colChoice
	Pagination    Pagination
}

func cannedAdvisoryFilters() []cannedFilterView {
	return []cannedFilterView{
		{
			Label: "Affecting loaded versions",
			Query: "effective:true",
			Cols:  "uuid,severity,cvss_score,title,published_at,local_packages_count",
			Sort:  "cvss_score",
			Dir:   "desc",
			Icon:  "target",
		},
		{
			Label: "Critical",
			Query: "effective:true severity:CRITICAL",
			Cols:  "uuid,severity,cvss_score,title,published_at,local_packages_count",
			Sort:  "cvss_score",
			Dir:   "desc",
			Icon:  "siren",
		},
		{
			Label: "High severity",
			Query: "effective:true severity:HIGH",
			Cols:  "uuid,severity,cvss_score,title,published_at,local_packages_count",
			Sort:  "cvss_score",
			Dir:   "desc",
			Icon:  "shield-alert",
		},
		{
			Label: "Unpatched",
			Query: "effective:true unpatched:true",
			Cols:  "uuid,severity,cvss_score,title,local_packages_count",
			Sort:  "cvss_score",
			Dir:   "desc",
			Icon:  "alert-triangle",
		},
		{
			Label: "All (incl. non-matching versions)",
			Query: "",
			Cols:  "uuid,severity,cvss_score,title,published_at,local_packages_count",
			Sort:  "cvss_score",
			Dir:   "desc",
			Icon:  "list",
		},
	}
}

func buildCannedHrefAdvisories(c cannedFilterView) template.URL {
	parts := []string{"q=" + url.QueryEscape(c.Query)}
	if c.Cols != "" {
		parts = append(parts, "cols="+url.QueryEscape(c.Cols))
	}
	if c.Sort != "" {
		parts = append(parts, "sort="+url.QueryEscape(c.Sort))
		dir := c.Dir
		if dir == "" {
			dir = "asc"
		}
		parts = append(parts, "dir="+dir)
	}
	return template.URL("/advisories?" + strings.Join(parts, "&"))
}

func parseAdvisoryColsParam(s string, fallback []string) []string {
	if s == "" {
		return fallback
	}
	known := advisoryColumns()
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if _, ok := known[p]; p != "" && ok {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

func (s *Server) applyColsAdvisories(w http.ResponseWriter, r *http.Request) {
	applyColsRedirect(w, r, "/advisories")
}

func (s *Server) advisories(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filterInput := q.Get("q")
	sort := q.Get("sort")
	dir := strings.ToLower(q.Get("dir"))
	if dir != "asc" && dir != "desc" {
		dir = "asc"
	}
	colsParam := q.Get("cols")

	cols := advisoryColumns()
	terms := ParseFilter(filterInput)
	where, args := BuildSQL(terms, cols)

	gq := s.g.Model(&db.Advisory{})
	if where != "" {
		gq = gq.Where(where, args...)
	}

	var total int64
	if err := gq.Count(&total).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if sort != "" {
		if _, ok := cols[sort]; ok {
			gq = gq.Order(sort + " " + dir)
		}
	} else {
		gq = gq.Order("cvss_score desc")
	}

	offset, limit, pagination := parsePagination(q, total, "/advisories")
	gq = gq.Offset(offset).Limit(limit)

	var rows []db.Advisory
	if err := gq.Find(&rows).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	allDisplay := []struct {
		name, label string
		numeric     bool
	}{
		{"uuid", "ID", false},
		{"severity", "Severity", false},
		{"cvss_score", "CVSS", true},
		{"title", "Title", false},
		{"origin", "Origin", false},
		{"classification", "Classification", false},
		{"source_kind", "Source", false},
		{"published_at", "Published", false},
		{"withdrawn_at", "Withdrawn", false},
		{"local_packages_count", "Pkgs here", true},
	}
	defaultCols := []string{
		"uuid", "severity", "cvss_score", "title", "published_at", "local_packages_count",
	}
	visible := parseAdvisoryColsParam(colsParam, defaultCols)
	visibleSet := make(map[string]bool, len(visible))
	for _, c := range visible {
		visibleSet[c] = true
	}
	display := make([]struct {
		name, label string
		numeric     bool
	}, 0, len(visible))
	byName := make(map[string]int, len(allDisplay))
	for i, d := range allDisplay {
		byName[d.name] = i
	}
	if colsParam != "" {
		for _, name := range visible {
			if i, ok := byName[name]; ok {
				display = append(display, allDisplay[i])
			}
		}
	} else {
		for _, d := range allDisplay {
			if visibleSet[d.name] {
				display = append(display, d)
			}
		}
	}

	colviews := make([]columnView, 0, len(display))
	for _, d := range display {
		nextDir := "desc"
		icon := ""
		if sort == d.name {
			if dir == "desc" {
				nextDir = "asc"
				icon = "arrow-down"
			} else {
				icon = "arrow-up"
			}
		}
		link := "/advisories?sort=" + d.name + "&dir=" + nextDir
		if filterInput != "" {
			link += "&q=" + escape(filterInput)
		}
		if colsParam != "" {
			link += "&cols=" + colsParam
		}
		colviews = append(colviews, columnView{
			Name:     d.name,
			Label:    d.label,
			SortLink: link,
			Numeric:  d.numeric,
			SortIcon: icon,
		})
	}

	hints := make([]filterHint, 0, len(cols))
	for name, c := range cols {
		hints = append(hints, filterHint{Name: name, Type: c.Type})
	}

	canned := cannedAdvisoryFilters()
	normInput := normaliseOperators(strings.TrimSpace(filterInput))
	for i := range canned {
		canned[i].Active = normaliseOperators(canned[i].Query) == normInput && normInput != ""
		canned[i].Href = buildCannedHrefAdvisories(canned[i])
	}

	colChoices := make([]colChoice, len(allDisplay))
	for i, d := range allDisplay {
		colChoices[i] = colChoice{Name: d.name, Label: d.label, Visible: visibleSet[d.name]}
	}

	renderers := advisoriesCellRenderers()
	rowCells := make([][]Cell, len(rows))
	for i, a := range rows {
		cells := make([]Cell, len(display))
		for j, d := range display {
			if fn, ok := renderers[d.name]; ok {
				cells[j] = fn(a)
			}
		}
		rowCells[i] = cells
	}

	view := advisoryView{
		Theme:         "marshal",
		Nav:           "advisories",
		FilterInput:   filterInput,
		Sort:          sort,
		Dir:           dir,
		ColsParam:     colsParam,
		Rows:          rowCells,
		Total:         total,
		Columns:       colviews,
		FilterColumns: hints,
		CannedFilters: canned,
		SavedFilters:  s.listSavedFilters("advisories", filterInput, sort, dir, colsParam),
		ColumnChoices: colChoices,
		Pagination:    pagination,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, "advisories.html", view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

