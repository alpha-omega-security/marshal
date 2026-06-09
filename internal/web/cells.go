package web

import (
	"fmt"
	"html"
	"html/template"
	"strconv"
	"time"

	"github.com/alpha-omega-security/marshal/internal/db"
)

// Each section has a map of column name -> cell renderer. The handler
// iterates the visible columns in display order, calls the matching
// renderer for each row, and stores the result as a Cell. Templates emit
// the cell verbatim so body cells always align with the visible-column
// header set.

func cellText(class, s string) Cell {
	return Cell{HTML: template.HTML(html.EscapeString(s)), Class: class}
}

func cellNum(n int64) Cell {
	if n == 0 {
		return Cell{Class: "text-right tabular-nums"}
	}
	return Cell{
		HTML:  template.HTML(shortNum(n)),
		Class: "text-right tabular-nums",
		Title: strconv.FormatInt(n, 10),
	}
}

func cellInt(n int) Cell { return cellNum(int64(n)) }

// cellIntPtr renders a *int as a count. Nil → blank, 0 → blank, otherwise
// short-formatted with the full value in the title attribute.
func cellIntPtr(n *int) Cell {
	if n == nil {
		return Cell{Class: "text-right tabular-nums text-muted-foreground"}
	}
	return cellInt(*n)
}

// lifecycleColor maps a bernies bucket to a muted tone. Avoids pill badges
// per project preference; just hints the cell text.
func lifecycleColor(lc string) string {
	switch lc {
	case "active":
		return "text-foreground"
	case "dormant":
		return "text-muted-foreground"
	case "dead":
		return "text-destructive"
	}
	return "text-muted-foreground"
}

func cellDate(t *time.Time) Cell {
	if t == nil {
		return Cell{Class: "text-xs text-muted-foreground"}
	}
	return Cell{HTML: template.HTML(t.Format("2006-01-02")), Class: "text-xs text-muted-foreground"}
}

// cellBoolYes renders true as plain "yes" muted text, false as empty. No
// badges — value pills draw the eye to flags that aren't actually warnings.
func cellBoolYes(b bool) Cell {
	if !b {
		return Cell{}
	}
	return Cell{HTML: template.HTML("yes"), Class: "text-xs text-muted-foreground"}
}

// packagesCellRenderers maps every package column we know how to display.
// Unknown columns render as an empty cell rather than a panic, so adding a
// column to the filter-DSL set without wiring a renderer just gives empty
// cells until someone fills it in.
func packagesCellRenderers() map[string]func(db.Package) Cell {
	return map[string]func(db.Package) Cell{
		"name": func(p db.Package) Cell {
			disp := p.Name
			if p.Namespace != "" {
				disp = p.Namespace + "/" + p.Name
			}
			href := `/packages/` + strconv.FormatUint(uint64(p.ID), 10)
			h := `<a href="` + href + `" class="hover:underline">` + html.EscapeString(disp) + `</a>` +
				`<div class="text-muted-foreground text-[10px]">` + escape80(p.PURL) + `</div>`
			return Cell{HTML: template.HTML(h), Class: "font-mono text-xs"}
		},
		"ecosystem":             func(p db.Package) Cell { return cellText("", p.Ecosystem) },
		"latest_release_number": func(p db.Package) Cell { return cellText("font-mono text-xs", p.LatestReleaseNumber) },
		"latest_release_published_at": func(p db.Package) Cell {
			return cellDate(p.LatestReleasePublishedAt)
		},
		"first_release_published_at": func(p db.Package) Cell {
			return cellDate(p.FirstReleasePublishedAt)
		},
		"downloads":                func(p db.Package) Cell { return cellNum(p.Downloads) },
		"dependent_repos_count":    func(p db.Package) Cell { return cellInt(p.DependentReposCount) },
		"dependent_packages_count": func(p db.Package) Cell { return cellInt(p.DependentPackagesCount) },
		"docker_dependents_count":  func(p db.Package) Cell { return cellInt(p.DockerDependentsCount) },
		"docker_downloads_count":   func(p db.Package) Cell { return cellNum(p.DockerDownloadsCount) },
		"maintainers_count":        func(p db.Package) Cell { return cellInt(p.MaintainersCount) },
		"advisory_count": func(p db.Package) Cell {
			return Cell{HTML: template.HTML(strconv.Itoa(p.AdvisoryCount)), Class: "text-right tabular-nums"}
		},
		"local_imports_count": func(p db.Package) Cell { return cellInt(p.LocalImportsCount) },
		"max_cvss_score": func(p db.Package) Cell {
			if p.MaxCVSSScore <= 0 {
				return Cell{Class: "text-right tabular-nums"}
			}
			return Cell{HTML: template.HTML(fmt.Sprintf("%.1f", p.MaxCVSSScore)), Class: "text-right tabular-nums"}
		},
		"rankings_average": func(p db.Package) Cell {
			if p.RankingsAverage <= 0 {
				return Cell{Class: "text-right tabular-nums"}
			}
			return Cell{HTML: template.HTML(fmt.Sprintf("%.1f", p.RankingsAverage)), Class: "text-right tabular-nums"}
		},
		"critical": func(p db.Package) Cell { return cellBoolYes(p.Critical) },
		"status":   func(p db.Package) Cell { return cellText("text-xs text-muted-foreground", p.Status) },
		"licenses": func(p db.Package) Cell { return cellText("text-xs", p.Licenses) },
		"versions_count": func(p db.Package) Cell { return cellInt(p.VersionsCount) },
	}
}

func reposCellRenderers() map[string]func(db.Repository) Cell {
	return map[string]func(db.Repository) Cell{
		"full_name": func(r db.Repository) Cell {
			disp := r.FullName
			if disp == "" {
				disp = r.URL
			}
			href := `/repositories/` + strconv.FormatUint(uint64(r.ID), 10)
			h := `<a href="` + href + `" class="hover:underline">` + html.EscapeString(disp) + `</a>` +
				`<div class="text-muted-foreground text-[10px]">` + escape80(r.URL) + `</div>`
			return Cell{HTML: template.HTML(h), Class: "font-mono text-xs"}
		},
		"url":               func(r db.Repository) Cell { return cellText("font-mono text-xs", r.URL) },
		"host":              func(r db.Repository) Cell { return cellText("", r.Host) },
		"owner":             func(r db.Repository) Cell { return cellText("", r.Owner) },
		"language":          func(r db.Repository) Cell { return cellText("", r.Language) },
		"license":           func(r db.Repository) Cell { return cellText("text-xs", r.License) },
		"local_packages_count":             func(r db.Repository) Cell { return cellInt(r.LocalPackagesCount) },
		"local_advisory_count":             func(r db.Repository) Cell { return cellInt(r.LocalAdvisoryCount) },
		"local_unpatched_advisory_count":   func(r db.Repository) Cell { return cellInt(r.LocalUnpatchedAdvisoryCount) },
		"local_effective_advisory_count":   func(r db.Repository) Cell { return cellInt(r.LocalEffectiveAdvisoryCount) },
		"lifecycle": func(r db.Repository) Cell {
			if r.Lifecycle == "" {
				return Cell{Class: "text-xs text-muted-foreground"}
			}
			return Cell{HTML: template.HTML(html.EscapeString(r.Lifecycle)), Class: "text-xs " + lifecycleColor(r.Lifecycle)}
		},
		"dds": func(r db.Repository) Cell {
			if r.DDS <= 0 {
				return Cell{Class: "text-right tabular-nums"}
			}
			return Cell{HTML: template.HTML(fmt.Sprintf("%.2f", r.DDS)), Class: "text-right tabular-nums"}
		},
		"total_commits":            func(r db.Repository) Cell { return cellInt(r.TotalCommits) },
		"total_committers":         func(r db.Repository) Cell { return cellInt(r.TotalCommitters) },
		"past_year_commits":        func(r db.Repository) Cell { return cellInt(r.PastYearCommits) },
		"past_year_committers":     func(r db.Repository) Cell { return cellInt(r.PastYearCommitters) },
		"past_year_bot_commits":    func(r db.Repository) Cell { return cellInt(r.PastYearBotCommits) },
		"past_year_issues":         func(r db.Repository) Cell { return cellInt(r.PastYearIssues) },
		"past_year_pull_requests":  func(r db.Repository) Cell { return cellInt(r.PastYearPullRequests) },
		"past_year_issues_closed":  func(r db.Repository) Cell { return cellInt(r.PastYearIssuesClosed) },
		"past_year_pull_requests_merged": func(r db.Repository) Cell { return cellInt(r.PastYearPullRequestsMerged) },
		"active_maintainers_count": func(r db.Repository) Cell { return cellInt(r.ActiveMaintainersCount) },
		"last_commit_at":           func(r db.Repository) Cell { return cellDate(r.LastCommitAt) },
		"days_since_push":          func(r db.Repository) Cell { return cellIntPtr(r.DaysSincePush) },
		"days_since_commit":        func(r db.Repository) Cell { return cellIntPtr(r.DaysSinceCommit) },
		"days_since_release":       func(r db.Repository) Cell { return cellIntPtr(r.DaysSinceRelease) },
		"stargazers_count":     func(r db.Repository) Cell { return cellInt(r.StargazersCount) },
		"forks_count":       func(r db.Repository) Cell { return cellInt(r.ForksCount) },
		"subscribers_count": func(r db.Repository) Cell { return cellInt(r.SubscribersCount) },
		"open_issues_count": func(r db.Repository) Cell {
			if r.OpenIssuesCount == 0 {
				return Cell{Class: "text-right tabular-nums"}
			}
			return Cell{HTML: template.HTML(strconv.Itoa(r.OpenIssuesCount)), Class: "text-right tabular-nums"}
		},
		"pushed_at":               func(r db.Repository) Cell { return cellDate(r.PushedAt) },
		"latest_tag_published_at": func(r db.Repository) Cell { return cellDate(r.LatestTagPublishedAt) },
		"archived":                func(r db.Repository) Cell { return cellBoolYes(r.Archived) },
		"fork":                    func(r db.Repository) Cell { return cellBoolYes(r.Fork) },
		"description":             func(r db.Repository) Cell { return cellText("text-xs", r.Description) },
		"default_branch":          func(r db.Repository) Cell { return cellText("font-mono text-xs", r.DefaultBranch) },
		"homepage":                func(r db.Repository) Cell { return cellText("text-xs", r.Homepage) },
		"size":                    func(r db.Repository) Cell { return cellInt(r.Size) },
		"status":                  func(r db.Repository) Cell { return cellText("text-xs text-muted-foreground", r.Status) },
	}
}

func ownersCellRenderers() map[string]func(db.Owner) Cell {
	return map[string]func(db.Owner) Cell{
		"login": func(o db.Owner) Cell {
			href := `/owners/` + strconv.FormatUint(uint64(o.ID), 10)
			h := `<a href="` + href + `" class="hover:underline">` + html.EscapeString(o.Login) + `</a>`
			return Cell{HTML: template.HTML(h), Class: "font-mono text-xs"}
		},
		"name":               func(o db.Owner) Cell { return cellText("", o.Name) },
		"host":               func(o db.Owner) Cell { return cellText("", o.Host) },
		"kind":               func(o db.Owner) Cell { return cellText("text-xs text-muted-foreground", o.Kind) },
		"repositories_count": func(o db.Owner) Cell { return cellInt(o.RepositoriesCount) },
		"local_repos_count":  func(o db.Owner) Cell { return cellInt(o.LocalReposCount) },
		"total_stars":        func(o db.Owner) Cell { return cellNum(o.TotalStars) },
		"followers":          func(o db.Owner) Cell { return cellInt(o.Followers) },
		"following":          func(o db.Owner) Cell { return cellInt(o.Following) },
		"company":            func(o db.Owner) Cell { return cellText("", o.Company) },
		"location":           func(o db.Owner) Cell { return cellText("", o.Location) },
		"website": func(o db.Owner) Cell {
			if o.Website == "" {
				return Cell{}
			}
			h := `<a href="` + html.EscapeString(o.Website) + `" class="hover:underline" rel="noopener noreferrer" target="_blank">` + escape80(o.Website) + `</a>`
			return Cell{HTML: template.HTML(h), Class: "font-mono text-xs"}
		},
		"twitter": func(o db.Owner) Cell {
			if o.Twitter == "" {
				return Cell{}
			}
			return Cell{HTML: template.HTML("@" + html.EscapeString(o.Twitter))}
		},
		"description": func(o db.Owner) Cell { return cellText("text-xs", o.Description) },
	}
}

func maintainersCellRenderers() map[string]func(db.Maintainer) Cell {
	return map[string]func(db.Maintainer) Cell{
		"login": func(m db.Maintainer) Cell {
			href := `/maintainers/` + strconv.FormatUint(uint64(m.ID), 10)
			h := `<a href="` + href + `" class="hover:underline">` + html.EscapeString(m.Login) + `</a>`
			return Cell{HTML: template.HTML(h), Class: "font-mono text-xs"}
		},
		"name":            func(m db.Maintainer) Cell { return cellText("", m.Name) },
		"ecosystem":       func(m db.Maintainer) Cell { return cellText("text-xs text-muted-foreground", m.Ecosystem) },
		"role":            func(m db.Maintainer) Cell { return cellText("text-xs text-muted-foreground", m.Role) },
		"packages_count":       func(m db.Maintainer) Cell { return cellInt(m.PackagesCount) },
		"local_packages_count": func(m db.Maintainer) Cell { return cellInt(m.LocalPackagesCount) },
		"total_downloads":      func(m db.Maintainer) Cell { return cellNum(m.TotalDownloads) },
		"email":           func(m db.Maintainer) Cell { return cellText("text-xs text-muted-foreground font-mono", m.Email) },
	}
}

func advisoriesCellRenderers() map[string]func(db.Advisory) Cell {
	return map[string]func(db.Advisory) Cell{
		"uuid": func(a db.Advisory) Cell {
			href := `/advisories/` + strconv.FormatUint(uint64(a.ID), 10)
			label := a.UUID
			if len(label) > 16 {
				label = label[:16] + "..."
			}
			h := `<a href="` + href + `" class="hover:underline">` + html.EscapeString(label) + `</a>`
			return Cell{HTML: template.HTML(h), Class: "font-mono text-xs"}
		},
		"severity":       func(a db.Advisory) Cell { return cellText("text-xs", a.Severity) },
		"classification": func(a db.Advisory) Cell { return cellText("text-xs text-muted-foreground", a.Classification) },
		"source_kind":    func(a db.Advisory) Cell { return cellText("text-xs text-muted-foreground", a.SourceKind) },
		"origin":         func(a db.Advisory) Cell { return cellText("text-xs text-muted-foreground", a.Origin) },
		"title":          func(a db.Advisory) Cell { return cellText("text-xs", truncateString(a.Title, 80)) },
		"cvss_score": func(a db.Advisory) Cell {
			if a.CVSSScore <= 0 {
				return Cell{Class: "text-right tabular-nums"}
			}
			return Cell{HTML: template.HTML(fmt.Sprintf("%.1f", a.CVSSScore)), Class: "text-right tabular-nums"}
		},
		"url":          func(a db.Advisory) Cell { return cellText("font-mono text-xs", a.URL) },
		"published_at": func(a db.Advisory) Cell { return cellDate(a.PublishedAt) },
		"withdrawn_at": func(a db.Advisory) Cell { return cellDate(a.WithdrawnAt) },
		"description":  func(a db.Advisory) Cell { return cellText("text-xs", truncateString(a.Description, 80)) },
		"local_packages_count": func(a db.Advisory) Cell { return cellInt(a.LocalPackagesCount) },
	}
}

// truncateString trims s to a max length for table display. Used inside
// cellText since the escape80 helper already HTML-escapes too.
func truncateString(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// escape80 truncates a string to 80 characters and HTML-escapes it for
// inline display in the secondary line of an identity cell.
func escape80(s string) string {
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return html.EscapeString(s)
}
