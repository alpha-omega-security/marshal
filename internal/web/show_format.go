package web

import (
	"fmt"
	"html"
	"html/template"
	"strconv"
	"strings"
	"time"

	"github.com/alpha-omega-security/marshal/internal/db"
)

// FieldGroup is a named bundle of FieldRows on a show page. Per-entity
// builders construct these so each show page can have a sensible grouping
// (Identity / Activity / Counts / etc.) rather than one flat list of every
// model field, and so labels can read like "Default branch" instead of
// "DefaultBranch".
type FieldGroup struct {
	Heading string
	Fields  []FieldRow
}

// kv builds a string-valued FieldRow. Empty values are skipped.
func kv(label, v string) FieldRow {
	if v == "" {
		return FieldRow{}
	}
	return FieldRow{Label: label, Value: v}
}

// kvNum builds an int-valued FieldRow. Zero is rendered as "0" rather
// than skipped, because on a show page "0 advisories" is meaningful.
func kvNum(label string, n int64) FieldRow {
	return FieldRow{Label: label, Value: strconv.FormatInt(n, 10)}
}

// kvNumOmitZero skips when zero.
func kvNumOmitZero(label string, n int64) FieldRow {
	if n == 0 {
		return FieldRow{}
	}
	return FieldRow{Label: label, Value: strconv.FormatInt(n, 10)}
}

// kvFloat formats with one decimal place when nonzero.
func kvFloat(label string, f float64) FieldRow {
	if f == 0 {
		return FieldRow{}
	}
	return FieldRow{Label: label, Value: fmt.Sprintf("%.2f", f)}
}

func kvBool(label string, b bool) FieldRow {
	if !b {
		return FieldRow{}
	}
	return FieldRow{Label: label, Value: "Yes"}
}

func kvTime(label string, t *time.Time) FieldRow {
	if t == nil || t.IsZero() {
		return FieldRow{}
	}
	return FieldRow{Label: label, Value: t.Format("2006-01-02"), IsTime: true, Time: *t}
}

func kvLink(label, href, displayText string) FieldRow {
	if href == "" {
		return FieldRow{}
	}
	if displayText == "" {
		displayText = href
	}
	return FieldRow{
		Label:    label,
		Value:    displayText,
		IsLink:   true,
		LinkHref: href,
	}
}

func kvLifecycle(lc string) FieldRow {
	if lc == "" {
		return FieldRow{}
	}
	// the renderer reads Value for the label content, and we want a coloured
	// span. Smuggle via Value as plain text; the template wraps it.
	return FieldRow{Label: "Lifecycle", Value: lc}
}

// nonempty filters out zero-valued FieldRows. Builders compose with this so
// "if v != """ branches don't pollute the per-entity functions.
func nonempty(rows ...FieldRow) []FieldRow {
	out := make([]FieldRow, 0, len(rows))
	for _, r := range rows {
		if r.Label != "" {
			out = append(out, r)
		}
	}
	return out
}

func packageGroups(p db.Package) []FieldGroup {
	groups := []FieldGroup{
		{Heading: "Identity", Fields: nonempty(
			kv("PURL", p.PURL),
			kv("Ecosystem", p.Ecosystem),
			kv("Name", p.Name),
			kv("Namespace", p.Namespace),
			kv("Description", p.Description),
			kvLink("Registry", p.RegistryURL, ""),
			kvLink("Homepage", p.Homepage, ""),
			kv("Language", p.Language),
			kv("Licenses", p.Licenses),
			kv("Status", p.Status),
			kvBool("Critical (ecosyste.ms flag)", p.Critical),
		)},
		{Heading: "Versions", Fields: nonempty(
			kv("Latest", p.LatestReleaseNumber),
			kvTime("Latest release", p.LatestReleasePublishedAt),
			kvTime("First release", p.FirstReleasePublishedAt),
			kvNumOmitZero("Total versions", int64(p.VersionsCount)),
		)},
		{Heading: "Popularity", Fields: nonempty(
			kvNumOmitZero("Downloads", p.Downloads),
			kv("Period", p.DownloadsPeriod),
			kvNumOmitZero("Dependent packages", int64(p.DependentPackagesCount)),
			kvNumOmitZero("Dependent repos", int64(p.DependentReposCount)),
			kvNumOmitZero("Docker dependents", int64(p.DockerDependentsCount)),
			kvNumOmitZero("Docker downloads", p.DockerDownloadsCount),
			kvFloat("Rankings average", p.RankingsAverage),
		)},
		{Heading: "Risk", Fields: nonempty(
			kvNum("Affecting loaded versions", int64(p.EffectiveAdvisoryCount)),
			kvNum("Effective unpatched", int64(p.EffectiveUnpatchedAdvisoryCount)),
			kvNum("All known advisories", int64(p.AdvisoryCount)),
			kvNum("All unpatched", int64(p.UnpatchedAdvisoryCount)),
			kvFloat("Max CVSS", float64(p.MaxCVSSScore)),
		)},
		{Heading: "Local counts", Fields: nonempty(
			kvNumOmitZero("Maintainers", int64(p.MaintainersCount)),
			kvNumOmitZero("SBOMs containing this", int64(p.LocalImportsCount)),
		)},
	}
	return dropEmptyGroups(groups)
}

func repoGroups(r db.Repository) []FieldGroup {
	owner := r.Owner
	groups := []FieldGroup{
		{Heading: "Identity", Fields: nonempty(
			kvLink("URL", r.URL, r.URL),
			kv("Full name", r.FullName),
			kv("Host", r.Host),
			kv("Owner", owner),
			kv("Description", r.Description),
			kvLink("Homepage", r.Homepage, ""),
			kv("Default branch", r.DefaultBranch),
			kv("Language", r.Language),
			kv("License", r.License),
			kvBool("Archived", r.Archived),
			kvBool("Fork", r.Fork),
			kv("Status", r.Status),
		)},
		{Heading: "Lifecycle", Fields: nonempty(
			kvLifecycle(r.Lifecycle),
			kvTime("Pushed", r.PushedAt),
			kvTime("Last commit", r.LastCommitAt),
			kvTime("Latest tag", r.LatestTagPublishedAt),
			daysCell("Days since push", r.DaysSincePush),
			daysCell("Days since commit", r.DaysSinceCommit),
			daysCell("Days since release", r.DaysSinceRelease),
		)},
		{Heading: "Activity", Fields: nonempty(
			kvFloat("DDS (bus factor)", r.DDS),
			kvNumOmitZero("Total commits", int64(r.TotalCommits)),
			kvNumOmitZero("Total committers", int64(r.TotalCommitters)),
			kvNumOmitZero("Past-year commits", int64(r.PastYearCommits)),
			kvNumOmitZero("Past-year committers", int64(r.PastYearCommitters)),
			kvNumOmitZero("Past-year bot commits", int64(r.PastYearBotCommits)),
			kvNumOmitZero("Past-year issues", int64(r.PastYearIssues)),
			kvNumOmitZero("Past-year PRs", int64(r.PastYearPullRequests)),
			kvNumOmitZero("Past-year issues closed", int64(r.PastYearIssuesClosed)),
			kvNumOmitZero("Past-year PRs merged", int64(r.PastYearPullRequestsMerged)),
			kvNumOmitZero("Active maintainers", int64(r.ActiveMaintainersCount)),
		)},
		{Heading: "Forge counts", Fields: nonempty(
			kvNumOmitZero("Stars", int64(r.StargazersCount)),
			kvNumOmitZero("Forks", int64(r.ForksCount)),
			kvNumOmitZero("Subscribers", int64(r.SubscribersCount)),
			kvNumOmitZero("Open issues", int64(r.OpenIssuesCount)),
			kvNumOmitZero("Size (KB)", int64(r.Size)),
		)},
		{Heading: "Local counts", Fields: nonempty(
			kvNumOmitZero("Packages here", int64(r.LocalPackagesCount)),
			kvNumOmitZero("Advisories affecting loaded", int64(r.LocalEffectiveAdvisoryCount)),
			kvNumOmitZero("Unpatched (overall)", int64(r.LocalUnpatchedAdvisoryCount)),
			kvNumOmitZero("All known advisories", int64(r.LocalAdvisoryCount)),
		)},
	}
	return dropEmptyGroups(groups)
}

func daysCell(label string, n *int) FieldRow {
	if n == nil {
		return FieldRow{}
	}
	return FieldRow{Label: label, Value: strconv.Itoa(*n) + " d"}
}

func sbomGroups(imp db.Import) []FieldGroup {
	var status FieldRow
	switch imp.EnrichmentStatus {
	case "":
		status = FieldRow{}
	default:
		v := imp.EnrichmentStatus
		if imp.EnrichmentStatus == "done" && imp.EnrichmentFinishedAt != nil && imp.EnrichmentStartedAt != nil {
			v = "done (" + imp.EnrichmentFinishedAt.Sub(*imp.EnrichmentStartedAt).Round(time.Second).String() + ")"
		}
		status = FieldRow{Label: "Enrichment", Value: v}
	}
	groups := []FieldGroup{
		{Heading: "Source", Fields: nonempty(
			kv("File", imp.Path),
			kv("Format", imp.Format),
			kv("Spec version", imp.SpecVersion),
			kv("Subject", imp.Subject),
			kv("Owner tag", imp.Owner),
			kv("Label", imp.Label),
		)},
		{Heading: "Status", Fields: nonempty(
			kvTime("Loaded at", &imp.LoadedAt),
			status,
			kv("Last error", imp.EnrichmentError),
			kvTime("Enrichment started", imp.EnrichmentStartedAt),
			kvTime("Enrichment finished", imp.EnrichmentFinishedAt),
		)},
	}
	return dropEmptyGroups(groups)
}

func dropEmptyGroups(groups []FieldGroup) []FieldGroup {
	out := make([]FieldGroup, 0, len(groups))
	for _, g := range groups {
		if len(g.Fields) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// renderValue formats a FieldRow value into HTML so the template stays
// dumb. Links become <a>, lifecycle gets a coloured span, plain text gets
// escaped. Time fields are handled by the template directly since the
// {{.Time.Format}} expression is more readable inline.
func renderValue(f FieldRow) template.HTML {
	if f.IsTime {
		return template.HTML(html.EscapeString(f.Time.Format("2006-01-02 15:04")))
	}
	if f.IsLink {
		return template.HTML(`<a href="` + html.EscapeString(f.LinkHref) +
			`" class="hover:underline" rel="noopener noreferrer" target="_blank">` +
			html.EscapeString(f.Value) + `</a>`)
	}
	// lifecycle row gets coloured by the cell's existing convention
	if f.Label == "Lifecycle" {
		return template.HTML(`<span class="` + lifecycleColor(f.Value) + `">` +
			html.EscapeString(strings.ToUpper(f.Value)) + `</span>`)
	}
	return template.HTML(html.EscapeString(f.Value))
}
