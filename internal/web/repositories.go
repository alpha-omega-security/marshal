package web

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/alpha-omega-security/marshal/internal/db"
)

// repoColumns is the filterable column set for /repositories. Mirrors the
// shape of packageColumns; when a third section lands we'll lift the
// common scaffolding into a per-section descriptor and stop duplicating.
func repoColumns() map[string]Column {
	return map[string]Column{
		"url":                    {Name: "url", Type: "string", TextMatch: true},
		"full_name":              {Name: "full_name", Type: "string", TextMatch: true},
		"host":                   {Name: "host", Type: "string"},
		"owner":                  {Name: "owner", Type: "string"},
		"description":            {Name: "description", Type: "string", TextMatch: true},
		"homepage":               {Name: "homepage", Type: "string"},
		"default_branch":         {Name: "default_branch", Type: "string"},
		"language":               {Name: "language", Type: "string"},
		"license":                {Name: "license", Type: "string"},
		"archived":               {Name: "archived", Type: "bool"},
		"fork":                   {Name: "fork", Type: "bool"},
		"status":                 {Name: "status", Type: "string"},
		"stargazers_count":       {Name: "stargazers_count", Type: "int"},
		"forks_count":            {Name: "forks_count", Type: "int"},
		"subscribers_count":      {Name: "subscribers_count", Type: "int"},
		"open_issues_count":      {Name: "open_issues_count", Type: "int"},
		"size":                   {Name: "size", Type: "int"},
		"pushed_at":              {Name: "pushed_at", Type: "time"},
		"latest_tag_published_at": {Name: "latest_tag_published_at", Type: "time"},
		"local_packages_count":             {Name: "local_packages_count", Type: "int"},
		"local_advisory_count":             {Name: "local_advisory_count", Type: "int"},
		"local_unpatched_advisory_count":   {Name: "local_unpatched_advisory_count", Type: "int"},
		"local_effective_advisory_count":   {Name: "local_effective_advisory_count", Type: "int"},
		"import_id": {
			Name:     "import_id",
			Type:     "int",
			Subquery: "SELECT DISTINCT p.repository_id FROM packages p JOIN package_imports pi ON pi.package_id = p.id WHERE pi.import_id = ? AND p.repository_id IS NOT NULL",
		},
		// lifecycle + bernies inputs
		"lifecycle":                {Name: "lifecycle", Type: "string"},
		"dds":                      {Name: "dds", Type: "float"},
		"total_commits":            {Name: "total_commits", Type: "int"},
		"total_committers":         {Name: "total_committers", Type: "int"},
		"past_year_commits":        {Name: "past_year_commits", Type: "int"},
		"past_year_committers":     {Name: "past_year_committers", Type: "int"},
		"past_year_bot_commits":    {Name: "past_year_bot_commits", Type: "int"},
		"past_year_issues":         {Name: "past_year_issues", Type: "int"},
		"past_year_pull_requests":  {Name: "past_year_pull_requests", Type: "int"},
		"past_year_issues_closed":  {Name: "past_year_issues_closed", Type: "int"},
		"past_year_pull_requests_merged": {Name: "past_year_pull_requests_merged", Type: "int"},
		"active_maintainers_count": {Name: "active_maintainers_count", Type: "int"},
		"last_commit_at":           {Name: "last_commit_at", Type: "time"},
		"days_since_push":          {Name: "days_since_push", Type: "int"},
		"days_since_commit":        {Name: "days_since_commit", Type: "int"},
		"days_since_release":       {Name: "days_since_release", Type: "int"},
	}
}

type repoView struct {
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

func cannedRepoFilters() []cannedFilterView {
	// Columns chosen so the verdict is auditable: each one is a direct
	// input to the lifecycle CASE expression in db/lifecycle.go. The user
	// can see whether "dead" came from `archived`, or from the "asked
	// last year and nobody answered" compound rule (past_year_issues +
	// past_year_pull_requests > 0 plus all the zero-response conditions),
	// or from `days_since_push` exceeding 365. Empty columns are
	// themselves a signal that one of the inputs we'd ideally use isn't
	// in the cache yet (`past_year_commits`, `active_maintainers_count`
	// land via the v2 commits/issues enrichers).
	bernies := "full_name,lifecycle,language,local_packages_count,archived," +
		"past_year_issues,past_year_pull_requests," +
		"past_year_issues_closed,past_year_pull_requests_merged," +
		"active_maintainers_count,past_year_commits,days_since_push,stargazers_count"
	return []cannedFilterView{
		{
			Label: "Bernies (dead)",
			Query: "lifecycle:dead",
			Cols:  bernies,
			Sort:  "local_packages_count",
			Dir:   "desc",
			Icon:  "skull",
		},
		{
			Label: "Dormant",
			Query: "lifecycle:dormant",
			Cols:  bernies,
			Sort:  "local_packages_count",
			Dir:   "desc",
			Icon:  "moon",
		},
		{
			Label: "Active",
			Query: "lifecycle:active",
			Cols:  bernies,
			Sort:  "local_packages_count",
			Dir:   "desc",
			Icon:  "activity",
		},
		{
			Label: "Unknown",
			Query: "lifecycle:unknown",
			Cols:  bernies,
			Sort:  "local_packages_count",
			Dir:   "desc",
			Icon:  "circle-help",
		},
		{
			Label: "Archived",
			Query: "archived:true",
			Cols:  "full_name,host,language,stargazers_count,forks_count,pushed_at,archived",
			Sort:  "stargazers_count",
			Dir:   "desc",
			Icon:  "archive",
		},
		{
			Label: "Forks",
			Query: "fork:true",
			Cols:  "full_name,host,language,stargazers_count,forks_count,pushed_at,fork",
			Sort:  "stargazers_count",
			Dir:   "desc",
			Icon:  "git-fork",
		},
	}
}

func buildCannedHrefRepos(c cannedFilterView) template.URL {
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
	return template.URL("/repositories?" + strings.Join(parts, "&"))
}

func parseRepoColsParam(s string, fallback []string) []string {
	if s == "" {
		return fallback
	}
	known := repoColumns()
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

func (s *Server) applyColsRepos(w http.ResponseWriter, r *http.Request) {
	applyColsRedirect(w, r, "/repositories")
}

func (s *Server) repositories(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filterInput := q.Get("q")
	sort := q.Get("sort")
	dir := strings.ToLower(q.Get("dir"))
	if dir != "asc" && dir != "desc" {
		dir = "asc"
	}
	colsParam := q.Get("cols")

	cols := repoColumns()
	terms := ParseFilter(filterInput)
	where, args := BuildSQL(terms, cols)

	gq := s.g.Model(&db.Repository{})
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
		gq = gq.Order("full_name asc")
	}

	offset, limit, pagination := parsePagination(q, total, "/repositories")
	gq = gq.Offset(offset).Limit(limit)

	var rows []db.Repository
	if err := gq.Find(&rows).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	allDisplay := []struct {
		name, label string
		numeric     bool
	}{
		{"full_name", "Repository", false},
		{"host", "Host", false},
		{"owner", "Owner", false},
		{"language", "Language", false},
		{"license", "License", false},
		{"lifecycle", "Lifecycle", false},
		{"local_packages_count", "Pkgs here", true},
		{"local_effective_advisory_count", "Affecting", true},
		{"local_unpatched_advisory_count", "Unpatched", true},
		{"local_advisory_count", "All advisories", true},
		{"dds", "DDS", true},
		{"total_commits", "Commits", true},
		{"total_committers", "Committers", true},
		{"past_year_commits", "Commits/yr", true},
		{"past_year_issues", "Issues/yr", true},
		{"past_year_pull_requests", "PRs/yr", true},
		{"past_year_issues_closed", "Closed/yr", true},
		{"past_year_pull_requests_merged", "Merged/yr", true},
		{"active_maintainers_count", "Active maint.", true},
		{"days_since_push", "Days since push", true},
		{"days_since_commit", "Days since commit", true},
		{"days_since_release", "Days since release", true},
		{"stargazers_count", "Stars", true},
		{"forks_count", "Forks", true},
		{"subscribers_count", "Subs", true},
		{"open_issues_count", "Open issues", true},
		{"pushed_at", "Pushed", false},
		{"latest_tag_published_at", "Latest tag", false},
		{"archived", "Archived", false},
		{"fork", "Fork", false},
	}
	defaultCols := []string{
		"full_name", "lifecycle", "language",
		"local_packages_count", "local_effective_advisory_count", "local_unpatched_advisory_count",
		"dds", "past_year_commits", "active_maintainers_count",
		"stargazers_count", "pushed_at", "archived",
	}
	visible := parseRepoColsParam(colsParam, defaultCols)
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
		link := "/repositories?sort=" + d.name + "&dir=" + nextDir
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

	canned := cannedRepoFilters()
	normInput := normaliseOperators(strings.TrimSpace(filterInput))
	for i := range canned {
		canned[i].Active = normaliseOperators(canned[i].Query) == normInput && normInput != ""
		canned[i].Href = buildCannedHrefRepos(canned[i])
	}

	colChoices := make([]colChoice, len(allDisplay))
	for i, d := range allDisplay {
		colChoices[i] = colChoice{Name: d.name, Label: d.label, Visible: visibleSet[d.name]}
	}

	renderers := reposCellRenderers()
	rowCells := make([][]Cell, len(rows))
	for i, repo := range rows {
		cells := make([]Cell, len(display))
		for j, d := range display {
			if fn, ok := renderers[d.name]; ok {
				cells[j] = fn(repo)
			}
		}
		rowCells[i] = cells
	}

	view := repoView{
		Theme:         "marshal",
		Nav:           "repositories",
		FilterInput:   filterInput,
		Sort:          sort,
		Dir:           dir,
		ColsParam:     colsParam,
		Rows:          rowCells,
		Total:         total,
		Columns:       colviews,
		FilterColumns: hints,
		CannedFilters: canned,
		SavedFilters:  s.listSavedFilters("repositories", filterInput, sort, dir, colsParam),
		ColumnChoices: colChoices,
		Pagination:    pagination,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, "repositories.html", view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
