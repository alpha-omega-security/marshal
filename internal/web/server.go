package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/alpha-omega-security/marshal/internal/db"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	g   *gorm.DB
	tpl *template.Template
}

func NewServer(g *gorm.DB) (*Server, error) {
	tpl, err := template.New("").Funcs(template.FuncMap{
		"truncate":    truncate,
		"short":       shortNum,
		"renderValue": renderValue,
		"saveCtx": func(section, q, sortc, dirc, cols string) saveViewCtx {
			return saveViewCtx{Section: section, Q: q, Sort: sortc, Dir: dirc, Cols: cols}
		},
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{g: g, tpl: tpl}, nil
}

// saveViewCtx is the small struct the "Save view" popover template needs.
// Kept local because no other template touches it.
type saveViewCtx struct {
	Section string
	Q       string
	Sort    string
	Dir     string
	Cols    string
}

// maxFormBytes caps request body size for every POST handler so a peer on
// 127.0.0.1 (or a co-located tab) can't blow up RAM with a giant form.
// Big enough for the longest legitimate filter strings; small enough that
// nobody mistakes a /sboms/add path field for an upload endpoint.
const maxFormBytes = 64 << 10

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	mux.HandleFunc("/", s.packages)
	mux.HandleFunc("/packages", s.packages)
	mux.HandleFunc("/packages/cols", s.applyCols)
	mux.HandleFunc("/packages/{id}", s.packageShow)
	mux.HandleFunc("/repositories", s.repositories)
	mux.HandleFunc("/repositories/cols", s.applyColsRepos)
	mux.HandleFunc("/repositories/{id}", s.repositoryShow)
	mux.HandleFunc("/owners", s.owners)
	mux.HandleFunc("/owners/cols", s.applyColsOwners)
	mux.HandleFunc("/owners/{id}", s.ownerShow)
	mux.HandleFunc("/maintainers", s.maintainers)
	mux.HandleFunc("/maintainers/cols", s.applyColsMaintainers)
	mux.HandleFunc("/maintainers/{id}", s.maintainerShow)
	mux.HandleFunc("/advisories", s.advisories)
	mux.HandleFunc("/advisories/cols", s.applyColsAdvisories)
	mux.HandleFunc("/advisories/{id}", s.advisoryShow)
	mux.HandleFunc("/sboms", s.sboms)
	mux.HandleFunc("/sboms/add", s.sbomsAdd)
	mux.HandleFunc("/sboms/delete", s.sbomsDelete)
	mux.HandleFunc("/sboms/{id}", s.sbomShow)
	mux.HandleFunc("/filters/save", s.saveFilter)
	mux.HandleFunc("/filters/delete", s.deleteFilter)

	return withBodyLimit(mux)
}

// withBodyLimit wraps the handler to cap request body size on every POST.
// GET handlers are unaffected (Go's MaxBytesReader is a no-op without a
// Body). The SBOM upload route bypasses this so it can apply its own
// MaxInputBytes-sized limit instead of the small form cap.
func withBodyLimit(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path != "/sboms/add" {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) applyCols(w http.ResponseWriter, r *http.Request) {
	applyColsRedirect(w, r, "/packages")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// shortNum formats large integers as 1.2K, 3.4M, 5.6B for table display.
// Numbers under 1000 render plainly. Accepts any signed integer width.
func shortNum(v any) string {
	var n int64
	switch x := v.(type) {
	case int:
		n = int64(x)
	case int32:
		n = int64(x)
	case int64:
		n = x
	case uint:
		n = int64(x)
	case uint32:
		n = int64(x)
	case uint64:
		n = int64(x)
	default:
		return ""
	}
	if n == 0 {
		return ""
	}
	neg := ""
	if n < 0 {
		neg = "-"
		n = -n
	}
	switch {
	case n >= 1_000_000_000:
		return neg + trimTrailingZero(float64(n)/1_000_000_000) + "B"
	case n >= 1_000_000:
		return neg + trimTrailingZero(float64(n)/1_000_000) + "M"
	case n >= 1_000:
		return neg + trimTrailingZero(float64(n)/1_000) + "K"
	}
	return neg + strconv.FormatInt(n, 10)
}

func trimTrailingZero(f float64) string {
	return strings.TrimSuffix(strconv.FormatFloat(f, 'f', 1, 64), ".0")
}

// packageColumns maps the filterable column names users can type in the
// gmail-style bar to their SQL columns and types. The set comes from the
// GORM model; promoting another field to filterable is a one-line addition.
func packageColumns() map[string]Column {
	return map[string]Column{
		"purl":                      {Name: "purl", Type: "string", TextMatch: true},
		"name":                      {Name: "name", Type: "string", TextMatch: true},
		"ecosystem":                 {Name: "ecosystem", Type: "string"},
		"namespace":                 {Name: "namespace", Type: "string"},
		"description":               {Name: "description", Type: "string", TextMatch: true},
		"homepage":                  {Name: "homepage", Type: "string"},
		"language":                  {Name: "language", Type: "string"},
		"licenses":                  {Name: "licenses", Type: "string"},
		"latest_release_number":     {Name: "latest_release_number", Type: "string"},
		"latest_release_published_at": {Name: "latest_release_published_at", Type: "time"},
		"first_release_published_at":  {Name: "first_release_published_at", Type: "time"},
		"versions_count":            {Name: "versions_count", Type: "int"},
		"downloads":                 {Name: "downloads", Type: "int"},
		"dependent_packages_count":  {Name: "dependent_packages_count", Type: "int"},
		"dependent_repos_count":     {Name: "dependent_repos_count", Type: "int"},
		"docker_dependents_count":   {Name: "docker_dependents_count", Type: "int"},
		"docker_downloads_count":    {Name: "docker_downloads_count", Type: "int"},
		"rankings_average":          {Name: "rankings_average", Type: "float"},
		"maintainers_count":         {Name: "maintainers_count", Type: "int"},
		"status":                    {Name: "status", Type: "string"},
		"critical":                  {Name: "critical", Type: "bool"},
		"advisory_count":            {Name: "advisory_count", Type: "int"},
		"unpatched_advisory_count":  {Name: "unpatched_advisory_count", Type: "int"},
		"max_cvss_score":            {Name: "max_cvss_score", Type: "float"},
		"local_imports_count":       {Name: "local_imports_count", Type: "int"},
		"repository_id":             {Name: "repository_id", Type: "int"},
		"maintainer_id": {
			Name:     "maintainer_id",
			Type:     "int",
			Subquery: "SELECT package_id FROM package_maintainers WHERE maintainer_id = ?",
		},
		"import_id": {
			Name:     "import_id",
			Type:     "int",
			Subquery: "SELECT package_id FROM package_imports WHERE import_id = ?",
		},
		"advisory_id": {
			Name:     "advisory_id",
			Type:     "int",
			Subquery: "SELECT package_id FROM package_advisories WHERE advisory_id = ?",
		},
	}
}

type packageView struct {
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

type colChoice struct {
	Name    string
	Label   string
	Visible bool
}

// Cell is one rendered table cell, aligned with the visible columns.
// Templates iterate the row's []Cell and emit <td class="{{.Class}}"...>
// for each. Pre-rendering in Go means body cell count is always equal to
// header cell count by construction.
type Cell struct {
	HTML  template.HTML
	Class string
	Title string // optional, becomes title="..."
}

type cannedFilterView struct {
	Label  string
	Query  string
	Cols   string // comma-separated, optional column set tailored to the filter
	Sort   string // optional default sort column
	Dir    string // "asc" | "desc"
	Active bool
	Icon   string
	Href   template.URL // computed at render time; the full URL for the sidebar link
}

// cannedPackageFilters is the v0.1 starter set. Each entry maps to a single
// filter expression, an optional column set, and an optional default sort.
// Clicking the sidebar item replaces all three (gmail-style: clicking
// replaces). Move to YAML packs when the extensions system lands.
func cannedPackageFilters() []cannedFilterView {
	return []cannedFilterView{
		{
			Label: "Single-maintainer",
			Query: "maintainers_count:1",
			Cols:  "name,ecosystem,latest_release_number,maintainers_count,dependent_repos_count,downloads",
			Sort:  "dependent_repos_count",
			Dir:   "desc",
			Icon:  "user",
		},
		{
			Label: "Critical",
			Query: "critical:true",
			Cols:  "name,ecosystem,downloads,dependent_repos_count,dependent_packages_count,rankings_average,critical",
			Sort:  "dependent_repos_count",
			Dir:   "desc",
			Icon:  "shield-alert",
		},
		{
			Label: "Has advisories",
			Query: "advisory_count:>0",
			Cols:  "name,ecosystem,latest_release_number,advisory_count,max_cvss_score,downloads,dependent_repos_count",
			Sort:  "max_cvss_score",
			Dir:   "desc",
			Icon:  "bug",
		},
		{
			Label: "High CVSS",
			Query: "max_cvss_score:>=7",
			Cols:  "name,ecosystem,latest_release_number,max_cvss_score,advisory_count,dependent_repos_count",
			Sort:  "max_cvss_score",
			Dir:   "desc",
			Icon:  "siren",
		},
		{
			Label: "Yanked",
			Query: "status:yanked",
			Cols:  "name,ecosystem,status,latest_release_number,latest_release_published_at,dependent_repos_count",
			Sort:  "dependent_repos_count",
			Dir:   "desc",
			Icon:  "trash-2",
		},
		{
			Label: "Deprecated",
			Query: "status:deprecated",
			Cols:  "name,ecosystem,status,latest_release_number,latest_release_published_at,dependent_repos_count",
			Sort:  "dependent_repos_count",
			Dir:   "desc",
			Icon:  "archive",
		},
	}
}

// buildCannedHref composes the sidebar URL for a canned filter. Returned
// as template.URL so html/template treats the &-separators as already-safe
// rather than escaping them to &amp;. Filter expression values are
// URL-encoded so characters like `>` land as `%3E` rather than being
// HTML-escaped in the attribute context.
func buildCannedHref(c cannedFilterView) template.URL {
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
	return template.URL("/packages?" + strings.Join(parts, "&"))
}

type columnView struct {
	Name     string
	Label    string
	SortLink string
	Numeric  bool
	SortIcon string // "arrow-up" | "arrow-down" | "" (not the active sort)
}

type filterHint struct {
	Name string
	Type string
}

func (s *Server) packages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filterInput := q.Get("q")
	sort := q.Get("sort")
	dir := strings.ToLower(q.Get("dir"))
	if dir != "asc" && dir != "desc" {
		dir = "asc"
	}
	colsParam := q.Get("cols")

	cols := packageColumns()
	terms := ParseFilter(filterInput)
	where, args := BuildSQL(terms, cols)

	gq := s.g.Model(&db.Package{})
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
		gq = gq.Order("name asc")
	}

	offset, limit, pagination := parsePagination(q, total, "/packages")
	gq = gq.Offset(offset).Limit(limit)

	var rows []db.Package
	if err := gq.Find(&rows).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	renderers := packagesCellRenderers()

	allDisplay := []struct {
		name, label string
		numeric     bool
	}{
		{"name", "Name", false},
		{"ecosystem", "Ecosystem", false},
		{"latest_release_number", "Latest", false},
		{"latest_release_published_at", "Latest release", false},
		{"local_imports_count", "SBOMs", true},
		{"downloads", "Downloads", true},
		{"dependent_repos_count", "Dep. repos", true},
		{"dependent_packages_count", "Dep. pkgs", true},
		{"maintainers_count", "Maintainers", true},
		{"advisory_count", "Advisories", true},
		{"max_cvss_score", "Max CVSS", true},
		{"rankings_average", "Rank", true},
		{"critical", "Critical", false},
		{"status", "Status", false},
		{"licenses", "License", false},
		{"versions_count", "Versions", true},
	}
	defaultCols := []string{
		"name", "ecosystem", "latest_release_number", "latest_release_published_at",
		"local_imports_count", "downloads", "dependent_repos_count", "maintainers_count",
		"advisory_count", "max_cvss_score", "rankings_average", "critical",
	}
	visible := parseColsParam(colsParam, defaultCols)
	visibleSet := make(map[string]bool, len(visible))
	for _, c := range visible {
		visibleSet[c] = true
	}
	// preserve user's column order when provided, otherwise allDisplay order
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
		link := "/packages?sort=" + d.name + "&dir=" + nextDir
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

	canned := cannedPackageFilters()
	normInput := normaliseOperators(strings.TrimSpace(filterInput))
	for i := range canned {
		canned[i].Active = normaliseOperators(canned[i].Query) == normInput && normInput != ""
		canned[i].Href = buildCannedHref(canned[i])
	}

	colChoices := make([]colChoice, len(allDisplay))
	for i, d := range allDisplay {
		colChoices[i] = colChoice{Name: d.name, Label: d.label, Visible: visibleSet[d.name]}
	}

	rowCells := make([][]Cell, len(rows))
	for i, p := range rows {
		cells := make([]Cell, len(display))
		for j, d := range display {
			if fn, ok := renderers[d.name]; ok {
				cells[j] = fn(p)
			}
		}
		rowCells[i] = cells
	}

	view := packageView{
		Theme:         "marshal",
		Nav:           "packages",
		FilterInput:   filterInput,
		Sort:          sort,
		Dir:           dir,
		ColsParam:     colsParam,
		Rows:          rowCells,
		Total:         total,
		Columns:       colviews,
		FilterColumns: hints,
		CannedFilters: canned,
		SavedFilters:  s.listSavedFilters("packages", filterInput, sort, dir, colsParam),
		ColumnChoices: colChoices,
		Pagination:    pagination,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, "packages.html", view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// parseColsParam takes a comma-separated columns string and returns the
// validated list. Empty falls back to defaults. Unknown column names are
// silently dropped.
func parseColsParam(s string, fallback []string) []string {
	if s == "" {
		return fallback
	}
	known := map[string]bool{
		"name": true, "ecosystem": true, "latest_release_number": true,
		"latest_release_published_at": true, "downloads": true,
		"dependent_repos_count": true, "dependent_packages_count": true,
		"maintainers_count": true, "advisory_count": true, "max_cvss_score": true,
		"rankings_average": true, "critical": true, "status": true,
		"licenses": true, "versions_count": true,
		"local_imports_count": true,
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" && known[p] {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

func escape(s string) string {
	// minimal URL escaping for the filter input round-trip; we deliberately
	// avoid pulling in net/url's full escaping because it mangles the
	// human-readable filter syntax for the common case.
	r := strings.NewReplacer(" ", "+", "&", "%26", "=", "%3D")
	return r.Replace(s)
}
