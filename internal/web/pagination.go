package web

import (
	"html/template"
	"net/url"
	"strconv"
)

// Pagination is the small struct each list view passes to the template's
// pager partial. Centralised so /packages, /repositories, etc. all expose
// the same controls without per-section copies of the logic.
type Pagination struct {
	Page       int
	PerPage    int
	Total      int64
	TotalPages int
	HasPrev    bool
	HasNext    bool
	PrevHref   template.URL
	NextHref   template.URL
}

// defaultPerPage / maxPerPage cap how many rows we render at once. Aligned
// with the previous hardcoded LIMIT 200 so existing bookmarks still render
// the same set on page 1.
const (
	defaultPerPage = 50
	maxPerPage     = 500
)

// parsePagination extracts &page=N&per_page=M from the URL, applies safe
// defaults, and returns the offset+limit GORM needs along with a Pagination
// struct ready for the template. The basePath + extraParams form lets us
// preserve the rest of the URL state (q, sort, dir, cols) in the prev/next
// links.
func parsePagination(q url.Values, total int64, basePath string) (offset, limit int, p Pagination) {
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	per, _ := strconv.Atoi(q.Get("per_page"))
	if per <= 0 {
		per = defaultPerPage
	}
	if per > maxPerPage {
		per = maxPerPage
	}

	totalPages := int((total + int64(per) - 1) / int64(per))
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	p = Pagination{
		Page:       page,
		PerPage:    per,
		Total:      total,
		TotalPages: totalPages,
		HasPrev:    page > 1,
		HasNext:    page < totalPages,
	}

	// rebuild prev/next URLs preserving everything except page itself.
	build := func(target int) template.URL {
		q2 := url.Values{}
		for k, vs := range q {
			if k == "page" {
				continue
			}
			for _, v := range vs {
				q2.Add(k, v)
			}
		}
		q2.Set("page", strconv.Itoa(target))
		return template.URL(basePath + "?" + q2.Encode())
	}
	if p.HasPrev {
		p.PrevHref = build(page - 1)
	}
	if p.HasNext {
		p.NextHref = build(page + 1)
	}

	offset = (page - 1) * per
	limit = per
	return
}
