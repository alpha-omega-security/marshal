package web

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/alpha-omega-security/marshal/internal/db"
)

// FieldRow is one (label, value) pair on a show page. The handler builds a
// slice of these from the entity struct using reflection so adding a column
// to the model automatically gets rendered on the show page.
type FieldRow struct {
	Label    string
	Value    string
	IsTime   bool
	Time     time.Time
	IsLink   bool
	LinkHref string
}

type showView struct {
	Theme         string
	Nav           string
	Title         string
	Heading       string
	Subhead       string       // small line under the heading (e.g. PURL or URL)
	Icon          string       // optional lucide icon name
	ExternalHref  string       // optional "Open" button target (homepage etc.)
	Fields        []FieldRow   // legacy flat-list path; kept for entities without a grouper yet
	Groups        []FieldGroup // preferred path: grouped fields with section headings
	Related       []RelatedSection
	AffectedPackages []AffectedPackageRow // populated on advisory show
	VersionsInSBOMs  []PackageVersionRow  // populated on package show
	FilterInput   string             // sidebar active-state check, always empty here
	CannedFilters []cannedFilterView // sidebar canned-filter list, empty on show pages
	SavedFilters  []savedFilterView  // sidebar saved-filter list, empty on show pages
}

// PackageVersionRow is one entry in the package show page's
// "Versions across SBOMs" table. One row per (sbom, observed version) so
// the user can see which loaded input brought in which version.
type PackageVersionRow struct {
	ImportID   uint
	ImportPath string
	ImportBase string
	Version    string
	LoadedAt   string
}

// AffectedPackageRow is one entry in the advisory show page's affected-
// packages table. Carries enough to show range + first-patched + the
// versions we've observed locally, plus an effective flag so the user can
// see which rows actually hit their loaded SBOMs.
type AffectedPackageRow struct {
	PackageID         uint
	Name              string
	Namespace         string
	Ecosystem         string
	VulnerableRange   string
	FirstPatched      string
	Effective         bool
	ObservedVersions  string // comma-separated, may be empty
}

// RelatedSection is a labelled list of cross-links displayed below the
// field grid. Used for "Packages in this repo", "Repositories owned",
// "Repository for this package", etc.
type RelatedSection struct {
	Heading string
	Links   []RelatedLink

	// FilteredListHref, when set, is rendered as a "View all in <section> →"
	// link next to the heading. Points at the filtered index page so the
	// user can keep composing the filter from there.
	FilteredListHref string
	FilteredListLabel string
}

type RelatedLink struct {
	Href  string
	Label string
	Sub   string
}

func (s *Server) packageShow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var pkg db.Package
	if err := s.g.First(&pkg, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	heading := pkg.Name
	if pkg.Namespace != "" {
		heading = pkg.Namespace + "/" + pkg.Name
	}

	view := showView{
		Theme:        "marshal",
		Nav:          "packages",
		Title:        pkg.PURL,
		Heading:      heading,
		Subhead:      pkg.PURL,
		Icon:         "package",
		ExternalHref: pkg.Homepage,
		Groups:       packageGroups(pkg),
	}

	if pkg.RepositoryID != nil {
		var repo db.Repository
		if err := s.g.First(&repo, *pkg.RepositoryID).Error; err == nil {
			link := RelatedLink{
				Href:  "/repositories/" + strconv.FormatUint(uint64(repo.ID), 10),
				Label: fallback(repo.FullName, repo.URL),
				Sub:   repo.URL,
			}
			view.Related = append(view.Related, RelatedSection{
				Heading: "Repository",
				Links:   []RelatedLink{link},
			})
		}
	}

	var maints []db.Maintainer
	if err := s.g.Raw(`
		SELECT m.* FROM maintainers m
		JOIN package_maintainers pm ON pm.maintainer_id = m.id
		WHERE pm.package_id = ?
		ORDER BY m.login
	`, pkg.ID).Scan(&maints).Error; err == nil && len(maints) > 0 {
		links := make([]RelatedLink, len(maints))
		for i, m := range maints {
			links[i] = RelatedLink{
				Href:  "/maintainers/" + strconv.FormatUint(uint64(m.ID), 10),
				Label: fallback(m.Login, m.Name),
				Sub:   m.Role,
			}
		}
		view.Related = append(view.Related, RelatedSection{
			Heading: "Maintainers",
			Links:   links,
		})
	}

	if pkg.AdvisoryCount > 0 {
		// Prefer the effective count (advisories whose vulnerable range hits
		// at least one observed version of this package). Show the "all"
		// count in parens when it differs so the user can see what's been
		// filtered out.
		eff := pkg.EffectiveAdvisoryCount
		var label string
		switch {
		case eff == pkg.AdvisoryCount && eff == 1:
			label = "1 advisory"
		case eff == pkg.AdvisoryCount:
			label = strconv.Itoa(eff) + " advisories"
		default:
			label = fmt.Sprintf("%d affecting (of %d)", eff, pkg.AdvisoryCount)
		}
		view.Related = append(view.Related, RelatedSection{
			Heading:           "Advisories",
			FilteredListHref:  "/advisories?q=" + queryEscape("package_id:"+strconv.FormatUint(uint64(pkg.ID), 10)+" effective:true"),
			FilteredListLabel: label,
		})
	}

	view.VersionsInSBOMs = loadPackageVersionsInSBOMs(s, pkg.ID)

	renderShow(w, s, view)
}

// loadPackageVersionsInSBOMs returns one row per (import, observed version)
// for this package, newest-first. Lets the show page render a small table
// showing exactly which version landed from which SBOM.
func loadPackageVersionsInSBOMs(s *Server, packageID uint) []PackageVersionRow {
	type raw struct {
		ImportID uint
		Path     string
		Version  string
		LoadedAt time.Time
	}
	var rows []raw
	if err := s.g.Raw(`
		SELECT i.id AS import_id, i.path, pi.version, i.loaded_at
		FROM package_imports pi
		JOIN imports i ON i.id = pi.import_id
		WHERE pi.package_id = ?
		ORDER BY i.loaded_at DESC
	`, packageID).Scan(&rows).Error; err != nil {
		return nil
	}
	out := make([]PackageVersionRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, PackageVersionRow{
			ImportID:   r.ImportID,
			ImportPath: r.Path,
			ImportBase: filepathBase(r.Path),
			Version:    r.Version,
			LoadedAt:   r.LoadedAt.Format("2006-01-02 15:04"),
		})
	}
	return out
}

func (s *Server) repositoryShow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var repo db.Repository
	if err := s.g.First(&repo, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	view := showView{
		Theme:        "marshal",
		Nav:          "repositories",
		Title:        fallback(repo.FullName, repo.URL),
		Heading:      fallback(repo.FullName, repo.URL),
		Subhead:      repo.URL,
		Icon:         "folder-git-2",
		ExternalHref: repo.URL,
		Groups:       repoGroups(repo),
	}

	if repo.OwnerID != nil {
		var owner db.Owner
		if err := s.g.First(&owner, *repo.OwnerID).Error; err == nil {
			view.Related = append(view.Related, RelatedSection{
				Heading: "Owner",
				Links: []RelatedLink{{
					Href:  "/owners/" + strconv.FormatUint(uint64(owner.ID), 10),
					Label: fallback(owner.Login, owner.Name),
					Sub:   owner.Kind,
				}},
			})
		}
	}

	if repo.LocalPackagesCount > 0 {
		view.Related = append(view.Related, RelatedSection{
			Heading:           "Packages",
			FilteredListHref:  "/packages?q=" + queryEscape("repository_id:"+strconv.FormatUint(uint64(repo.ID), 10)),
			FilteredListLabel: pluralize(repo.LocalPackagesCount, "package"),
		})
	}

	if repo.LocalAdvisoryCount > 0 {
		eff := repo.LocalEffectiveAdvisoryCount
		var label string
		switch {
		case eff == repo.LocalAdvisoryCount && eff == 1:
			label = "1 advisory"
		case eff == repo.LocalAdvisoryCount:
			label = strconv.Itoa(eff) + " advisories"
		default:
			label = fmt.Sprintf("%d affecting (of %d)", eff, repo.LocalAdvisoryCount)
		}
		view.Related = append(view.Related, RelatedSection{
			Heading:           "Advisories",
			FilteredListHref:  "/advisories?q=" + queryEscape("repository_id:"+strconv.FormatUint(uint64(repo.ID), 10)+" effective:true"),
			FilteredListLabel: label,
		})
	}

	renderShow(w, s, view)
}

func (s *Server) advisoryShow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var a db.Advisory
	if err := s.g.First(&a, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	heading := a.Title
	if heading == "" {
		heading = a.UUID
	}
	view := showView{
		Theme:   "marshal",
		Nav:     "advisories",
		Title:   a.UUID,
		Heading: heading,
		Fields:  structFields(a),
	}

	view.AffectedPackages = loadAffectedPackages(s, a.ID)

	if a.LocalPackagesCount > 0 {
		view.Related = append(view.Related, RelatedSection{
			Heading:           "All affected packages",
			FilteredListHref:  "/packages?q=" + queryEscape("advisory_id:"+strconv.FormatUint(uint64(a.ID), 10)),
			FilteredListLabel: pluralize(a.LocalPackagesCount, "package"),
		})
	}

	renderShow(w, s, view)
}

// loadAffectedPackages joins package_advisories → packages → package_imports
// for one advisory and emits a row per affected package with its range,
// patched marker, effective flag, and observed versions (when any).
func loadAffectedPackages(s *Server, advisoryID uint) []AffectedPackageRow {
	type raw struct {
		PackageID              uint
		Name                   string
		Namespace              string
		Ecosystem              string
		VulnerableVersionRange string
		FirstPatchedVersion    string
		Effective              bool
		Observed               *string
	}
	var rows []raw
	if err := s.g.Raw(`
		SELECT p.id AS package_id, p.name, p.namespace, p.ecosystem,
		       pa.vulnerable_version_range, pa.first_patched_version, pa.effective,
		       (SELECT GROUP_CONCAT(DISTINCT pi.version)
		          FROM package_imports pi
		         WHERE pi.package_id = p.id AND pi.version <> '') AS observed
		FROM package_advisories pa
		JOIN packages p ON p.id = pa.package_id
		WHERE pa.advisory_id = ?
		ORDER BY p.ecosystem, p.namespace, p.name
	`, advisoryID).Scan(&rows).Error; err != nil {
		return nil
	}
	out := make([]AffectedPackageRow, 0, len(rows))
	for _, r := range rows {
		obs := ""
		if r.Observed != nil {
			obs = *r.Observed
		}
		out = append(out, AffectedPackageRow{
			PackageID:        r.PackageID,
			Name:             r.Name,
			Namespace:        r.Namespace,
			Ecosystem:        r.Ecosystem,
			VulnerableRange:  r.VulnerableVersionRange,
			FirstPatched:     r.FirstPatchedVersion,
			Effective:        r.Effective,
			ObservedVersions: obs,
		})
	}
	return out
}

func (s *Server) sbomShow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var imp db.Import
	if err := s.g.First(&imp, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	heading := imp.Subject
	if heading == "" {
		heading = filepathBase(imp.Path)
	}
	view := showView{
		Theme:   "marshal",
		Nav:     "sboms",
		Title:   imp.Path,
		Heading: heading,
		Subhead: imp.Path,
		Icon:    "file-json",
		Groups:  sbomGroups(imp),
	}

	idStr := strconv.FormatUint(uint64(imp.ID), 10)

	if imp.PackageCount > 0 {
		view.Related = append(view.Related, RelatedSection{
			Heading:           "Packages",
			FilteredListHref:  "/packages?q=" + queryEscape("import_id:"+idStr),
			FilteredListLabel: pluralize(imp.PackageCount, "package"),
		})
	}

	// counts scoped to this import. One query per metric so we can drop
	// rows where the count is zero rather than render empty cross-links.
	var repoCount, ownerCount, advTotal, advEffective int64
	s.g.Raw(`
		SELECT COUNT(DISTINCT p.repository_id)
		FROM packages p
		JOIN package_imports pi ON pi.package_id = p.id
		WHERE pi.import_id = ? AND p.repository_id IS NOT NULL
	`, imp.ID).Scan(&repoCount)
	s.g.Raw(`
		SELECT COUNT(DISTINCT r.owner_id)
		FROM repositories r
		JOIN packages p ON p.repository_id = r.id
		JOIN package_imports pi ON pi.package_id = p.id
		WHERE pi.import_id = ? AND r.owner_id IS NOT NULL
	`, imp.ID).Scan(&ownerCount)
	s.g.Raw(`
		SELECT COUNT(DISTINCT pa.advisory_id)
		FROM package_advisories pa
		JOIN package_imports pi ON pi.package_id = pa.package_id
		WHERE pi.import_id = ?
	`, imp.ID).Scan(&advTotal)
	s.g.Raw(`
		SELECT COUNT(DISTINCT pa.advisory_id)
		FROM package_advisories pa
		JOIN package_imports pi ON pi.package_id = pa.package_id
		WHERE pi.import_id = ? AND pa.effective = 1
	`, imp.ID).Scan(&advEffective)

	if repoCount > 0 {
		view.Related = append(view.Related, RelatedSection{
			Heading:           "Repositories",
			FilteredListHref:  "/repositories?q=" + queryEscape("import_id:"+idStr),
			FilteredListLabel: pluralize(int(repoCount), "repository"),
		})
	}
	if ownerCount > 0 {
		view.Related = append(view.Related, RelatedSection{
			Heading:           "Owners",
			FilteredListHref:  "/owners?q=" + queryEscape("import_id:"+idStr),
			FilteredListLabel: pluralize(int(ownerCount), "owner"),
		})
	}
	if advTotal > 0 {
		var label string
		switch {
		case advEffective == advTotal && advTotal == 1:
			label = "1 advisory"
		case advEffective == advTotal:
			label = fmt.Sprintf("%d advisories", advTotal)
		default:
			label = fmt.Sprintf("%d affecting (of %d)", advEffective, advTotal)
		}
		view.Related = append(view.Related, RelatedSection{
			Heading:           "Advisories",
			FilteredListHref:  "/advisories?q=" + queryEscape("import_id:"+idStr+" effective:true"),
			FilteredListLabel: label,
		})
	}

	renderShow(w, s, view)
}

// pluralize is shorthand for the "View N packages" link text.
func pluralize(n int, singular string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + singular + "s"
}

func queryEscape(s string) string { return url.QueryEscape(s) }

// filepathBase pulls the last path segment without importing path/filepath
// just for one call. SBOM paths in the DB use forward slashes on the host
// we're running on; covers the macOS/Linux dev case.
func filepathBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}

func (s *Server) maintainerShow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var m db.Maintainer
	if err := s.g.First(&m, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	view := showView{
		Theme:   "marshal",
		Nav:     "maintainers",
		Title:   m.Login + " (" + m.Ecosystem + ")",
		Heading: fallback(m.Name, m.Login),
		Fields:  structFields(m),
	}

	// list packages this maintainer is on (via the join table)
	if m.LocalPackagesCount > 0 {
		view.Related = append(view.Related, RelatedSection{
			Heading:           "Packages",
			FilteredListHref:  "/packages?q=" + queryEscape("maintainer_id:"+strconv.FormatUint(uint64(m.ID), 10)),
			FilteredListLabel: pluralize(m.LocalPackagesCount, "package"),
		})
	}

	renderShow(w, s, view)
}

func (s *Server) ownerShow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var owner db.Owner
	if err := s.g.First(&owner, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	view := showView{
		Theme:   "marshal",
		Nav:     "owners",
		Title:   owner.Login,
		Heading: fallback(owner.Name, owner.Login),
		Fields:  structFields(owner),
	}

	var repos []db.Repository
	if err := s.g.Where("owner_id = ?", owner.ID).Order("stargazers_count desc").Limit(50).Find(&repos).Error; err == nil && len(repos) > 0 {
		links := make([]RelatedLink, len(repos))
		for i, repo := range repos {
			links[i] = RelatedLink{
				Href:  "/repositories/" + strconv.FormatUint(uint64(repo.ID), 10),
				Label: fallback(repo.FullName, repo.URL),
				Sub:   repo.Language,
			}
		}
		view.Related = append(view.Related, RelatedSection{
			Heading:           "Repositories owned",
			Links:             links,
			FilteredListHref:  "/repositories?q=" + queryEscape("owner:"+owner.Login),
			FilteredListLabel: "Open in Repositories",
		})
	}

	renderShow(w, s, view)
}

func renderShow(w http.ResponseWriter, s *Server, view showView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, "show.html", view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func fallback(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// structFields reflects over v and emits a FieldRow per exported field
// other than ID and the timestamp bookkeeping. Pointer time fields render
// as dates; zero values are skipped to keep the show page tight.
func structFields(v any) []FieldRow {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	rt := rv.Type()
	out := make([]FieldRow, 0, rt.NumField())
	skip := map[string]bool{"ID": true, "CreatedAt": true, "UpdatedAt": true, "PackagesSyncedAt": true, "LastSyncedAt": true}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() || skip[f.Name] {
			continue
		}
		fv := rv.Field(i)
		switch fv.Kind() {
		case reflect.String:
			if fv.String() == "" {
				continue
			}
			out = append(out, FieldRow{Label: f.Name, Value: fv.String()})
		case reflect.Int, reflect.Int32, reflect.Int64:
			if fv.Int() == 0 {
				continue
			}
			out = append(out, FieldRow{Label: f.Name, Value: strconv.FormatInt(fv.Int(), 10)})
		case reflect.Uint, reflect.Uint32, reflect.Uint64:
			if fv.Uint() == 0 {
				continue
			}
			out = append(out, FieldRow{Label: f.Name, Value: strconv.FormatUint(fv.Uint(), 10)})
		case reflect.Float32, reflect.Float64:
			if fv.Float() == 0 {
				continue
			}
			out = append(out, FieldRow{Label: f.Name, Value: strconv.FormatFloat(fv.Float(), 'f', -1, 64)})
		case reflect.Bool:
			if !fv.Bool() {
				continue
			}
			out = append(out, FieldRow{Label: f.Name, Value: "yes"})
		case reflect.Pointer:
			if fv.IsNil() {
				continue
			}
			if t, ok := fv.Interface().(*time.Time); ok && t != nil {
				out = append(out, FieldRow{Label: f.Name, IsTime: true, Time: *t})
				continue
			}
		}
	}
	return out
}
