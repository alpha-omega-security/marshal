package web

import (
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/alpha-omega-security/marshal/internal/db"
)

// savedFilterView is the sidebar-rendered form. Mirrors cannedFilterView so
// the layout template can render saved and canned with the same partial.
type savedFilterView struct {
	ID     uint
	Label  string
	Href   template.URL
	Active bool
}

func (s *Server) listSavedFilters(section, filterInput, sort, dir, colsParam string) []savedFilterView {
	var rows []db.SavedFilter
	if err := s.g.Where("section = ?", section).Order("position asc, id asc").Find(&rows).Error; err != nil {
		return nil
	}
	out := make([]savedFilterView, len(rows))
	for i, r := range rows {
		href := buildSavedHref(section, r)
		active := r.Query == filterInput && r.Sort == sort && r.Dir == dir && r.Cols == colsParam
		out[i] = savedFilterView{
			ID:     r.ID,
			Label:  r.Name,
			Href:   href,
			Active: active,
		}
	}
	return out
}

func buildSavedHref(section string, r db.SavedFilter) template.URL {
	parts := []string{}
	if r.Query != "" {
		parts = append(parts, "q="+url.QueryEscape(r.Query))
	}
	if r.Cols != "" {
		parts = append(parts, "cols="+url.QueryEscape(r.Cols))
	}
	if r.Sort != "" {
		parts = append(parts, "sort="+url.QueryEscape(r.Sort))
		dir := r.Dir
		if dir == "" {
			dir = "asc"
		}
		parts = append(parts, "dir="+dir)
	}
	base := "/" + section
	if len(parts) == 0 {
		return template.URL(base)
	}
	return template.URL(base + "?" + strings.Join(parts, "&"))
}

func (s *Server) saveFilter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	section := r.FormValue("section")
	name := strings.TrimSpace(r.FormValue("name"))
	if !validSection(section) || name == "" {
		http.Error(w, "section and name required", http.StatusBadRequest)
		return
	}
	saved := db.SavedFilter{
		Section: section,
		Name:    name,
		Query:   r.FormValue("q"),
		Cols:    r.FormValue("cols"),
		Sort:    r.FormValue("sort"),
		Dir:     r.FormValue("dir"),
	}
	// upsert on (section, name): re-saving with the same name updates in place
	var existing db.SavedFilter
	if err := s.g.Where("section = ? AND name = ?", section, name).First(&existing).Error; err == nil {
		existing.Query = saved.Query
		existing.Cols = saved.Cols
		existing.Sort = saved.Sort
		existing.Dir = saved.Dir
		if err := s.g.Save(&existing).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := s.g.Create(&saved).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/"+section, http.StatusSeeOther)
}

func (s *Server) deleteFilter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseUint(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var f db.SavedFilter
	if err := s.g.First(&f, id).Error; err != nil {
		http.Redirect(w, r, "/packages", http.StatusSeeOther)
		return
	}
	if err := s.g.Delete(&f).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/"+f.Section, http.StatusSeeOther)
}

func validSection(s string) bool {
	switch s {
	case "packages", "repositories", "owners", "maintainers", "advisories":
		return true
	}
	return false
}
