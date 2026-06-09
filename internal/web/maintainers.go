package web

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/alpha-omega-security/marshal/internal/db"
)

func maintainerColumns() map[string]Column {
	return map[string]Column{
		"login":           {Name: "login", Type: "string", TextMatch: true},
		"name":            {Name: "name", Type: "string", TextMatch: true},
		"email":           {Name: "email", Type: "string", TextMatch: true},
		"ecosystem":       {Name: "ecosystem", Type: "string"},
		"role":            {Name: "role", Type: "string"},
		"packages_count":       {Name: "packages_count", Type: "int"},
		"local_packages_count": {Name: "local_packages_count", Type: "int"},
		"total_downloads":      {Name: "total_downloads", Type: "int"},
	}
}

type maintainerView struct {
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

func cannedMaintainerFilters() []cannedFilterView {
	return []cannedFilterView{
		{
			Label: "Heavy hitters",
			Query: "local_packages_count:>10",
			Cols:  "login,ecosystem,local_packages_count,packages_count",
			Sort:  "local_packages_count",
			Dir:   "desc",
			Icon:  "trophy",
		},
		{
			Label: "Solo here",
			Query: "local_packages_count:1",
			Cols:  "login,ecosystem,local_packages_count,packages_count,email",
			Sort:  "login",
			Dir:   "asc",
			Icon:  "user",
		},
		{
			Label: "Globally tiny",
			Query: "packages_count:1",
			Cols:  "login,ecosystem,local_packages_count,packages_count,email",
			Sort:  "login",
			Dir:   "asc",
			Icon:  "minus",
		},
	}
}

func buildCannedHrefMaintainers(c cannedFilterView) template.URL {
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
	return template.URL("/maintainers?" + strings.Join(parts, "&"))
}

func parseMaintainerColsParam(s string, fallback []string) []string {
	if s == "" {
		return fallback
	}
	known := maintainerColumns()
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

func (s *Server) applyColsMaintainers(w http.ResponseWriter, r *http.Request) {
	applyColsRedirect(w, r, "/maintainers")
}

func (s *Server) maintainers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filterInput := q.Get("q")
	sort := q.Get("sort")
	dir := strings.ToLower(q.Get("dir"))
	if dir != "asc" && dir != "desc" {
		dir = "asc"
	}
	colsParam := q.Get("cols")

	cols := maintainerColumns()
	terms := ParseFilter(filterInput)
	where, args := BuildSQL(terms, cols)

	gq := s.g.Model(&db.Maintainer{})
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
		gq = gq.Order("login asc")
	}

	offset, limit, pagination := parsePagination(q, total, "/maintainers")
	gq = gq.Offset(offset).Limit(limit)

	var rows []db.Maintainer
	if err := gq.Find(&rows).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	allDisplay := []struct {
		name, label string
		numeric     bool
	}{
		{"login", "Login", false},
		{"name", "Name", false},
		{"ecosystem", "Ecosystem", false},
		{"role", "Role", false},
		{"local_packages_count", "Pkgs here", true},
		{"packages_count", "Pkgs total", true},
		{"total_downloads", "Downloads", true},
		{"email", "Email", false},
	}
	defaultCols := []string{
		"login", "ecosystem", "local_packages_count", "packages_count",
	}
	visible := parseMaintainerColsParam(colsParam, defaultCols)
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
		link := "/maintainers?sort=" + d.name + "&dir=" + nextDir
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

	canned := cannedMaintainerFilters()
	normInput := normaliseOperators(strings.TrimSpace(filterInput))
	for i := range canned {
		canned[i].Active = normaliseOperators(canned[i].Query) == normInput && normInput != ""
		canned[i].Href = buildCannedHrefMaintainers(canned[i])
	}

	colChoices := make([]colChoice, len(allDisplay))
	for i, d := range allDisplay {
		colChoices[i] = colChoice{Name: d.name, Label: d.label, Visible: visibleSet[d.name]}
	}

	renderers := maintainersCellRenderers()
	rowCells := make([][]Cell, len(rows))
	for i, m := range rows {
		cells := make([]Cell, len(display))
		for j, d := range display {
			if fn, ok := renderers[d.name]; ok {
				cells[j] = fn(m)
			}
		}
		rowCells[i] = cells
	}

	view := maintainerView{
		Theme:         "marshal",
		Nav:           "maintainers",
		FilterInput:   filterInput,
		Sort:          sort,
		Dir:           dir,
		ColsParam:     colsParam,
		Rows:          rowCells,
		Total:         total,
		Columns:       colviews,
		FilterColumns: hints,
		CannedFilters: canned,
		SavedFilters:  s.listSavedFilters("maintainers", filterInput, sort, dir, colsParam),
		ColumnChoices: colChoices,
		Pagination:    pagination,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, "maintainers.html", view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
