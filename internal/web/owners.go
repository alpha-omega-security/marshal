package web

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/alpha-omega-security/marshal/internal/db"
)

func ownerColumns() map[string]Column {
	return map[string]Column{
		"login":              {Name: "login", Type: "string", TextMatch: true},
		"name":               {Name: "name", Type: "string", TextMatch: true},
		"description":        {Name: "description", Type: "string", TextMatch: true},
		"host":               {Name: "host", Type: "string"},
		"kind":               {Name: "kind", Type: "string"},
		"company":            {Name: "company", Type: "string"},
		"location":           {Name: "location", Type: "string"},
		"website":            {Name: "website", Type: "string"},
		"twitter":            {Name: "twitter", Type: "string"},
		"repositories_count": {Name: "repositories_count", Type: "int"},
		"local_repos_count":  {Name: "local_repos_count", Type: "int"},
		"total_stars":        {Name: "total_stars", Type: "int"},
		"followers":          {Name: "followers", Type: "int"},
		"following":          {Name: "following", Type: "int"},
		"hidden":             {Name: "hidden", Type: "bool"},
		"import_id": {
			Name:     "import_id",
			Type:     "int",
			Subquery: "SELECT DISTINCT r.owner_id FROM repositories r JOIN packages p ON p.repository_id = r.id JOIN package_imports pi ON pi.package_id = p.id WHERE pi.import_id = ? AND r.owner_id IS NOT NULL",
		},
	}
}

type ownerView struct {
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

func cannedOwnerFilters() []cannedFilterView {
	return []cannedFilterView{
		{
			Label: "Organizations",
			Query: "kind:organization",
			Cols:  "login,name,host,kind,local_repos_count,total_stars,followers,location",
			Sort:  "local_repos_count",
			Dir:   "desc",
			Icon:  "building",
		},
		{
			Label: "Users",
			Query: "kind:user",
			Cols:  "login,name,host,kind,local_repos_count,total_stars,followers,location",
			Sort:  "local_repos_count",
			Dir:   "desc",
			Icon:  "user",
		},
		{
			Label: "Top here",
			Query: "local_repos_count:>1",
			Cols:  "login,name,host,kind,local_repos_count,repositories_count,total_stars",
			Sort:  "local_repos_count",
			Dir:   "desc",
			Icon:  "building-2",
		},
	}
}

func buildCannedHrefOwners(c cannedFilterView) template.URL {
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
	return template.URL("/owners?" + strings.Join(parts, "&"))
}

// parseOwnerColsParam validates the cols= query param against the known
// column set. Unknown names are dropped silently so users can play with
// URL params without 500ing the page.
func parseOwnerColsParam(s string, fallback []string) []string {
	if s == "" {
		return fallback
	}
	known := ownerColumns()
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

func (s *Server) applyColsOwners(w http.ResponseWriter, r *http.Request) {
	applyColsRedirect(w, r, "/owners")
}

func (s *Server) owners(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filterInput := q.Get("q")
	sort := q.Get("sort")
	dir := strings.ToLower(q.Get("dir"))
	if dir != "asc" && dir != "desc" {
		dir = "asc"
	}
	colsParam := q.Get("cols")

	cols := ownerColumns()
	terms := ParseFilter(filterInput)
	where, args := BuildSQL(terms, cols)

	gq := s.g.Model(&db.Owner{})
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

	offset, limit, pagination := parsePagination(q, total, "/owners")
	gq = gq.Offset(offset).Limit(limit)

	var rows []db.Owner
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
		{"host", "Host", false},
		{"kind", "Kind", false},
		{"local_repos_count", "Repos here", true},
		{"repositories_count", "Repos total", true},
		{"total_stars", "Stars", true},
		{"followers", "Followers", true},
		{"following", "Following", true},
		{"company", "Company", false},
		{"location", "Location", false},
		{"website", "Website", false},
		{"twitter", "Twitter", false},
	}
	defaultCols := []string{
		"login", "name", "host", "kind", "local_repos_count", "repositories_count", "total_stars", "followers", "location",
	}
	visible := parseOwnerColsParam(colsParam, defaultCols)
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
		link := "/owners?sort=" + d.name + "&dir=" + nextDir
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

	canned := cannedOwnerFilters()
	normInput := normaliseOperators(strings.TrimSpace(filterInput))
	for i := range canned {
		canned[i].Active = normaliseOperators(canned[i].Query) == normInput && normInput != ""
		canned[i].Href = buildCannedHrefOwners(canned[i])
	}

	colChoices := make([]colChoice, len(allDisplay))
	for i, d := range allDisplay {
		colChoices[i] = colChoice{Name: d.name, Label: d.label, Visible: visibleSet[d.name]}
	}

	renderers := ownersCellRenderers()
	rowCells := make([][]Cell, len(rows))
	for i, o := range rows {
		cells := make([]Cell, len(display))
		for j, d := range display {
			if fn, ok := renderers[d.name]; ok {
				cells[j] = fn(o)
			}
		}
		rowCells[i] = cells
	}

	view := ownerView{
		Theme:         "marshal",
		Nav:           "owners",
		FilterInput:   filterInput,
		Sort:          sort,
		Dir:           dir,
		ColsParam:     colsParam,
		Rows:          rowCells,
		Total:         total,
		Columns:       colviews,
		FilterColumns: hints,
		CannedFilters: canned,
		SavedFilters:  s.listSavedFilters("owners", filterInput, sort, dir, colsParam),
		ColumnChoices: colChoices,
		Pagination:    pagination,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, "owners.html", view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
