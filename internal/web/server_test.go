package web

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/alpha-omega-security/marshal/internal/db"
)

// TestRoutesRender ensures every primary page renders without a template
// resolution error. Catches the failure mode where two pages both define
// `{{define "body"}}` and the last parsed one shadows the others, which
// only surfaces when you actually hit the alternate page.
// TestSBOMUpload exercises the multipart upload path on /sboms/add. A real
// CycloneDX file goes in via the file form field; we assert that the
// Import row lands with the original filename as Path and at least one
// package is ingested.
func TestSBOMUpload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	sbom := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {"component": {"name": "upload-test"}},
		"components": [
			{"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
		]
	}`)

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, err := mw.CreateFormFile("file", "upload-test.cdx.json")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(sbom); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/sboms/add", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}

	var imp db.Import
	if err := g.First(&imp).Error; err != nil {
		t.Fatalf("import not recorded: %v", err)
	}
	if imp.Path != "upload-test.cdx.json" {
		t.Errorf("Path = %q, want upload-test.cdx.json", imp.Path)
	}
	if imp.PackageCount != 1 {
		t.Errorf("PackageCount = %d, want 1", imp.PackageCount)
	}

	// the SBOMs index form should be multipart and have a file input
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/sboms", nil))
	body2 := rec2.Body.String()
	if !strings.Contains(body2, `enctype="multipart/form-data"`) {
		t.Errorf("sboms form is not multipart")
	}
	if !strings.Contains(body2, `type="file"`) {
		t.Errorf("sboms form missing file input")
	}
}

func TestRoutesRender(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	h := srv.Handler()

	for _, path := range []string{"/", "/packages", "/sboms", "/repositories", "/owners", "/maintainers", "/advisories"} {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, "executing") && strings.Contains(body, "can't evaluate") {
				t.Fatalf("template error in body: %s", body)
			}
			if !strings.Contains(body, "<html") {
				t.Fatalf("body is not HTML: %s", body[:200])
			}
		})
	}
}

// TestPackagesPageContent checks that the canned filters and column picker
// land where expected, so refactors that move the sidebar plumbing don't
// silently regress.
func TestPackagesPageContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/packages", nil))
	body := rec.Body.String()

	for _, want := range []string{
		"Single-maintainer",
		"Critical",
		"Has advisories",
		"High CVSS",
		"Yanked",
		"Deprecated",
		"Columns shown",
		"Available filter columns",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("packages body missing %q", want)
		}
	}
}

// TestCannedFiltersCarryColumnsAndSort ensures the sidebar links each
// canned filter to its query, tailored column set, and default sort, so
// clicking a canned view actually shows the data in the shape the view
// was designed around.
func TestCannedFiltersCarryColumnsAndSort(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/packages", nil))
	body := rec.Body.String()

	for _, c := range cannedPackageFilters() {
		// html/template escapes `&` to `&amp;` in href attribute context;
		// browsers decode it back. Match the rendered form.
		wantHref := strings.ReplaceAll(string(buildCannedHref(c)), "&", "&amp;")
		if !strings.Contains(body, wantHref) {
			t.Errorf("canned filter %q sidebar link missing:\n  want: %s", c.Label, wantHref)
		}
		// safety net: at least one of cols/sort must be set on every canned
		// filter, otherwise it's just a query and the user could have typed it.
		if c.Cols == "" && c.Sort == "" {
			t.Errorf("canned filter %q has neither cols nor sort", c.Label)
		}
	}
}

// TestColumnAlignment guards against the bug where the body row hardcodes a
// fixed number of <td> cells but the header iterates the visible-column
// set. As soon as the user toggles a column off, header and body diverge
// and rows look skewed. Every entity table must keep body cell count
// matched to header cell count.
func TestColumnAlignment(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := g.Create(&db.Repository{URL: "https://github.com/foo/bar", FullName: "foo/bar"}).Error; err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	if err := g.Create(&db.Owner{Host: "github", Login: "foo", Name: "Foo", Kind: "organization"}).Error; err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if err := g.Create(&db.Package{PURL: "pkg:npm/lodash", Name: "lodash", Ecosystem: "npm"}).Error; err != nil {
		t.Fatalf("seed pkg: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	if err := g.Create(&db.Maintainer{Ecosystem: "npm", Login: "alice", Name: "Alice"}).Error; err != nil {
		t.Fatalf("seed maintainer: %v", err)
	}
	for _, c := range []struct{ path, label string }{
		{"/packages", "packages"},
		{"/repositories", "repositories"},
		{"/owners", "owners"},
		{"/maintainers", "maintainers"},
	} {
		c := c
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
			body := rec.Body.String()
			ths := strings.Count(body, "<th ")
			// count <td in the first <tr> that's not in <thead>
			tbodyIdx := strings.Index(body, "<tbody>")
			if tbodyIdx < 0 {
				t.Fatalf("no <tbody>")
			}
			rest := body[tbodyIdx:]
			trIdx := strings.Index(rest, "<tr>")
			endIdx := strings.Index(rest[trIdx:], "</tr>")
			row := rest[trIdx : trIdx+endIdx]
			tds := strings.Count(row, "<td")
			if ths != tds {
				t.Errorf("%s: header has %d <th>, first body row has %d <td> (must match)", c.path, ths, tds)
			}
		})
	}
}

func TestAdvisoriesPageContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/advisories", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "<h1 class=\"text-2xl font-medium\">Advisories</h1>") {
		t.Errorf("advisories page missing heading")
	}
	for _, want := range []string{"Critical", "High severity", "Unpatched"} {
		if !strings.Contains(body, want) {
			t.Errorf("advisories body missing canned filter %q", want)
		}
	}
}

func TestMaintainersPageContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/maintainers", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "<h1 class=\"text-2xl font-medium\">Maintainers</h1>") {
		t.Errorf("maintainers page missing Maintainers heading")
	}
	for _, want := range []string{"Heavy hitters", "Solo"} {
		if !strings.Contains(body, want) {
			t.Errorf("maintainers body missing canned filter %q", want)
		}
	}
	// "Downloads" should appear in the column picker but not as a default
	// table header. Check only the <thead>...</thead> region.
	if start := strings.Index(body, "<thead>"); start >= 0 {
		if end := strings.Index(body[start:], "</thead>"); end >= 0 {
			if strings.Contains(body[start:start+end], "Downloads") {
				t.Errorf("maintainers default columns shouldn't include Downloads (data is unreliable)")
			}
		}
	}
}

func TestOwnersPageContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/owners", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "<h1 class=\"text-2xl font-medium\">Owners</h1>") {
		t.Errorf("owners page missing Owners heading")
	}
	for _, want := range []string{"Organizations", "Users"} {
		if !strings.Contains(body, want) {
			t.Errorf("owners body missing canned filter %q", want)
		}
	}
}

func TestRepositoriesPageContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/repositories", nil))
	body := rec.Body.String()
	// Catch the false-green where /repositories falls through to /packages
	// via the catch-all "/": the page must mention Repositories in its
	// heading and the empty-state row should reference repos, not pkgs.
	if !strings.Contains(body, "<h1 class=\"text-2xl font-medium\">Repositories</h1>") {
		t.Errorf("repositories page missing Repositories heading")
	}
}

func TestShowPagesAndLinkedRows(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	owner := db.Owner{Host: "github", Login: "foo", Name: "Foo Inc", Kind: "organization"}
	if err := g.Create(&owner).Error; err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	repo := db.Repository{URL: "https://github.com/foo/bar", FullName: "foo/bar", Host: "github", Owner: "foo", OwnerID: &owner.ID}
	if err := g.Create(&repo).Error; err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	pkg := db.Package{PURL: "pkg:npm/bar", Name: "bar", Ecosystem: "npm", RepositoryID: &repo.ID}
	if err := g.Create(&pkg).Error; err != nil {
		t.Fatalf("seed pkg: %v", err)
	}
	maint := db.Maintainer{Ecosystem: "npm", Login: "alice", Name: "Alice"}
	if err := g.Create(&maint).Error; err != nil {
		t.Fatalf("seed maintainer: %v", err)
	}
	if err := g.Create(&db.PackageMaintainer{PackageID: pkg.ID, MaintainerID: maint.ID, Role: "owner"}).Error; err != nil {
		t.Fatalf("seed pkg-maintainer: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	t.Run("package row links to show", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/packages", nil))
		body := rec.Body.String()
		want := `href="/packages/` + strconv.FormatUint(uint64(pkg.ID), 10) + `"`
		if !strings.Contains(body, want) {
			t.Errorf("packages list missing show-page link: want %q", want)
		}
	})
	t.Run("repository row links to show", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/repositories", nil))
		body := rec.Body.String()
		want := `href="/repositories/` + strconv.FormatUint(uint64(repo.ID), 10) + `"`
		if !strings.Contains(body, want) {
			t.Errorf("repos list missing show-page link: want %q", want)
		}
	})
	t.Run("owner row links to show", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/owners", nil))
		body := rec.Body.String()
		want := `href="/owners/` + strconv.FormatUint(uint64(owner.ID), 10) + `"`
		if !strings.Contains(body, want) {
			t.Errorf("owners list missing show-page link: want %q", want)
		}
	})
	t.Run("maintainer row links to show", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/maintainers", nil))
		body := rec.Body.String()
		want := `href="/maintainers/` + strconv.FormatUint(uint64(maint.ID), 10) + `"`
		if !strings.Contains(body, want) {
			t.Errorf("maintainers list missing show-page link: want %q", want)
		}
	})
	imp := db.Import{Path: "/tmp/test.cdx.json", Format: "cyclonedx", Subject: "test", PackageCount: 1}
	if err := g.Create(&imp).Error; err != nil {
		t.Fatalf("seed import: %v", err)
	}
	if err := g.Create(&db.PackageImport{PackageID: pkg.ID, ImportID: imp.ID}).Error; err != nil {
		t.Fatalf("seed pkg-import: %v", err)
	}
	t.Run("sbom row links to show", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sboms", nil))
		body := rec.Body.String()
		want := `href="/sboms/` + strconv.FormatUint(uint64(imp.ID), 10) + `"`
		if !strings.Contains(body, want) {
			t.Errorf("sboms list missing show-page link: want %q", want)
		}
	})
	t.Run("sbom show page renders", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sboms/"+strconv.FormatUint(uint64(imp.ID), 10), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, imp.Path) {
			t.Errorf("sbom show missing path")
		}
		// Should link to the filtered packages list rather than inline rows.
		// The href is URL-encoded then HTML-escaped, so `:` becomes %3A and
		// `&` becomes &amp;. We only assert on the encoded path-and-query.
		wantHref := `/packages?q=import_id%3A` + strconv.FormatUint(uint64(imp.ID), 10)
		if !strings.Contains(body, wantHref) {
			t.Errorf("sbom show missing filtered-list link: want substring %q", wantHref)
		}
	})

	for _, c := range []struct {
		path, mustContain string
	}{
		{fmt.Sprintf("/packages/%d", pkg.ID), pkg.PURL},
		{fmt.Sprintf("/repositories/%d", repo.ID), repo.FullName},
		{fmt.Sprintf("/owners/%d", owner.ID), owner.Login},
		{fmt.Sprintf("/maintainers/%d", maint.ID), maint.Login},
	} {
		c := c
		t.Run("show "+c.path, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), c.mustContain) {
				t.Errorf("%s page missing identity %q", c.path, c.mustContain)
			}
		})
	}
}

// TestSaveFormNotNestedInFilterForm guards against the bug where the
// "Save view" button lives inside the filter <form>. Nested forms get
// flattened by browsers and clicking Save submits the outer filter
// instead, so saves silently disappear.
func TestSaveFormNotNestedInFilterForm(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	for _, path := range []string{"/packages", "/repositories", "/owners"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		body := rec.Body.String()
		filterIdx := strings.Index(body, `action="`+path+`"`)
		if filterIdx < 0 {
			t.Errorf("%s: filter form not found", path)
			continue
		}
		// look forward from the filter form's opening <form> tag to find the
		// next </form>. Then check whether the save form's action shows up
		// before that closing tag.
		closeIdx := strings.Index(body[filterIdx:], "</form>")
		if closeIdx < 0 {
			t.Errorf("%s: filter form has no closing tag", path)
			continue
		}
		segment := body[filterIdx : filterIdx+closeIdx]
		if strings.Contains(segment, `action="/filters/save"`) {
			t.Errorf("%s: save view form is nested inside the filter form (clicking Save will submit the filter instead)", path)
		}
	}
}

func TestSavedFiltersRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	h := srv.Handler()

	// POST /filters/save creates a row and redirects back
	form := "section=packages&name=My+highrisk&q=critical%3Atrue&cols=name%2Cecosystem&sort=downloads&dir=desc"
	req := httptest.NewRequest(http.MethodPost, "/filters/save", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save status = %d, body: %s", rec.Code, rec.Body.String())
	}

	var rows []db.SavedFilter
	if err := g.Find(&rows).Error; err != nil {
		t.Fatalf("query saved: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 saved filter, got %d", len(rows))
	}
	if rows[0].Section != "packages" || rows[0].Name != "My highrisk" {
		t.Fatalf("unexpected saved filter: %+v", rows[0])
	}

	// the saved filter should appear in the packages sidebar
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/packages", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "My highrisk") {
		t.Errorf("saved filter not in packages sidebar")
	}
	wantHref := "/packages?q=critical%3Atrue&amp;cols=name%2Cecosystem&amp;sort=downloads&amp;dir=desc"
	if !strings.Contains(body, wantHref) {
		t.Errorf("saved filter href missing: want substring %s", wantHref)
	}

	// POST /filters/delete drops the row
	delForm := "id=" + strconv.FormatUint(uint64(rows[0].ID), 10)
	req = httptest.NewRequest(http.MethodPost, "/filters/delete", strings.NewReader(delForm))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete status = %d", rec.Code)
	}
	var n int64
	g.Model(&db.SavedFilter{}).Count(&n)
	if n != 0 {
		t.Errorf("saved filter not deleted, count=%d", n)
	}
}

func TestSBOMsPageContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	srv, err := NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sboms", nil))
	body := rec.Body.String()

	for _, want := range []string{
		"SBOMs",
		"Upload",
		"No SBOMs loaded",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("sboms body missing %q", want)
		}
	}
}
