// Package packages is the v1 mainline enricher. It calls packages.ecosyste.ms
// BulkLookup for every package row whose packages_synced_at is null or
// older than the staleness threshold, then populates typed columns on
// packages and stub rows on repositories.
package packages

import (
	"context"
	"fmt"
	"time"

	ecosystems "github.com/ecosyste-ms/ecosystems-go"
	ecopackages "github.com/ecosyste-ms/ecosystems-go/packages"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/alpha-omega-security/marshal/internal/db"
)

const userAgent = "marshal/0.1 (+https://github.com/alpha-omega-security/marshal)"

// Enrich runs the packages enricher across every package row.
// onlyStale skips rows enriched within the last `stale` window.
func Enrich(ctx context.Context, g *gorm.DB, onlyStale bool, stale time.Duration) (int, error) {
	client, err := ecosystems.NewClient(userAgent)
	if err != nil {
		return 0, fmt.Errorf("ecosystems client: %w", err)
	}

	var rows []db.Package
	q := g.WithContext(ctx).Order("id")
	if onlyStale {
		cutoff := time.Now().Add(-stale)
		q = q.Where("packages_synced_at IS NULL OR packages_synced_at < ?", cutoff)
	}
	if err := q.Find(&rows).Error; err != nil {
		return 0, fmt.Errorf("select packages: %w", err)
	}
	if len(rows) == 0 {
		return 0, nil
	}

	updated := 0
	const batch = 100
	for i := 0; i < len(rows); i += batch {
		end := i + batch
		if end > len(rows) {
			end = len(rows)
		}
		purls := make([]string, 0, end-i)
		for j := i; j < end; j++ {
			purls = append(purls, rows[j].PURL)
		}
		results, err := client.BulkLookup(ctx, purls)
		if err != nil {
			return updated, fmt.Errorf("bulk lookup batch %d: %w", i, err)
		}
		now := time.Now()
		for j := i; j < end; j++ {
			pkg := &rows[j]
			info := results[pkg.PURL]
			if info == nil {
				pkg.PackagesSyncedAt = &now
				if err := g.WithContext(ctx).Save(pkg).Error; err != nil {
					return updated, fmt.Errorf("save %s: %w", pkg.PURL, err)
				}
				continue
			}
			applyPackage(pkg, info)
			pkg.PackagesSyncedAt = &now
			if err := upsertRepoStub(ctx, g, pkg, info); err != nil {
				return updated, fmt.Errorf("repo stub for %s: %w", pkg.PURL, err)
			}
			if err := g.WithContext(ctx).Save(pkg).Error; err != nil {
				return updated, fmt.Errorf("save %s: %w", pkg.PURL, err)
			}
			if err := syncMaintainers(ctx, g, pkg, info); err != nil {
				return updated, fmt.Errorf("maintainers for %s: %w", pkg.PURL, err)
			}
			if err := syncAdvisories(ctx, g, pkg, info); err != nil {
				return updated, fmt.Errorf("advisories for %s: %w", pkg.PURL, err)
			}
			updated++
		}
	}
	if err := recomputeCounts(ctx, g); err != nil {
		return updated, err
	}
	return updated, nil
}

func applyPackage(pkg *db.Package, info *ecopackages.PackageWithRegistry) {
	pkg.Ecosystem = info.Ecosystem
	pkg.Name = info.Name
	if info.Namespace != nil {
		pkg.Namespace = *info.Namespace
	}
	if info.RegistryUrl != nil {
		pkg.RegistryURL = *info.RegistryUrl
	}
	if info.Homepage != nil {
		pkg.Homepage = *info.Homepage
	}
	if info.Description != nil {
		pkg.Description = *info.Description
	}
	if info.Licenses != nil {
		pkg.Licenses = *info.Licenses
	}
	if info.LatestReleaseNumber != nil {
		pkg.LatestReleaseNumber = *info.LatestReleaseNumber
	}
	pkg.LatestReleasePublishedAt = info.LatestReleasePublishedAt
	pkg.FirstReleasePublishedAt = info.FirstReleasePublishedAt
	pkg.VersionsCount = info.VersionsCount
	pkg.Downloads = int64(info.Downloads)
	if info.DownloadsPeriod != nil {
		pkg.DownloadsPeriod = *info.DownloadsPeriod
	}
	pkg.DependentPackagesCount = info.DependentPackagesCount
	pkg.DependentReposCount = info.DependentReposCount
	pkg.DockerDependentsCount = info.DockerDependentsCount
	pkg.DockerDownloadsCount = int64(info.DockerDownloadsCount)
	pkg.MaintainersCount = len(info.Maintainers)
	if info.Status != nil {
		pkg.Status = *info.Status
	}
	pkg.Critical = info.Critical
	if v, ok := info.Rankings["average"].(float64); ok {
		pkg.RankingsAverage = v
	}
	pkg.AdvisoryCount = len(info.Advisories)
	pkg.MaxCVSSScore = maxCVSS(info.Advisories)
	pkg.LastSyncedAt = info.LastSyncedAt
}

func maxCVSS(adv []ecopackages.Advisory) float32 {
	var m float32
	for i := range adv {
		if adv[i].CvssScore != nil && *adv[i].CvssScore > m {
			m = *adv[i].CvssScore
		}
	}
	return m
}

// upsertRepoStub creates or refreshes the repository row pointed at by the
// package, populating the slice of fields that come straight from
// info.RepoMetadata. Other repos.ecosyste.ms-only fields are left for the
// dedicated repos enricher.
func upsertRepoStub(ctx context.Context, g *gorm.DB, pkg *db.Package, info *ecopackages.PackageWithRegistry) error {
	if info.RepositoryUrl == nil || *info.RepositoryUrl == "" {
		return nil
	}
	repo := db.Repository{URL: normalizeRepoURL(*info.RepositoryUrl)}
	if rm := info.RepoMetadata; rm != nil {
		applyRepoMetadata(&repo, *rm)
		if ownerID, err := upsertOwnerFromRepoMetadata(ctx, g, *rm); err != nil {
			return err
		} else if ownerID != nil {
			repo.OwnerID = ownerID
		}
	}
	applyIssueMetadata(&repo, info.IssueMetadata)
	if err := g.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "url"}},
		DoUpdates: clause.AssignmentColumns(repoUpdateColumns()),
	}).Create(&repo).Error; err != nil {
		return err
	}
	pkg.RepositoryID = &repo.ID
	return nil
}

// syncMaintainers upserts every Maintainer from info.Maintainers, then
// replaces the package_maintainers join rows so the current set is
// authoritative. Roles flow through verbatim from ecosyste.ms.
func syncMaintainers(ctx context.Context, g *gorm.DB, pkg *db.Package, info *ecopackages.PackageWithRegistry) error {
	if err := g.WithContext(ctx).Where("package_id = ?", pkg.ID).Delete(&db.PackageMaintainer{}).Error; err != nil {
		return err
	}
	for _, m := range info.Maintainers {
		login := ""
		if m.Login != nil {
			login = *m.Login
		}
		if login == "" {
			// some npm authors arrive as name-only with no registry login;
			// fall back to name so we don't drop them on the floor
			if m.Name != nil {
				login = *m.Name
			}
		}
		if login == "" {
			continue
		}
		mr := db.Maintainer{
			UUID:      m.Uuid,
			Ecosystem: pkg.Ecosystem,
			Login:     login,
			Role:      defaultRole(m.Role),
		}
		if m.Name != nil {
			mr.Name = *m.Name
		}
		if m.Email != nil {
			mr.Email = *m.Email
		}
		if m.Url != nil {
			mr.URL = *m.Url
		}
		if m.HtmlUrl != nil {
			mr.HTMLURL = *m.HtmlUrl
		}
		mr.PackagesCount = m.PackagesCount
		mr.TotalDownloads = int64(m.TotalDownloads)
		now := time.Now()
		mr.PackagesSyncedAt = &now

		if err := g.WithContext(ctx).Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "ecosystem"}, {Name: "login"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"uuid", "name", "email", "url", "html_url",
				"packages_count", "total_downloads", "role",
				"packages_synced_at", "updated_at",
			}),
		}).Create(&mr).Error; err != nil {
			return err
		}

		if err := g.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&db.PackageMaintainer{
			PackageID:    pkg.ID,
			MaintainerID: mr.ID,
			Role:         defaultRole(m.Role),
		}).Error; err != nil {
			return err
		}
	}
	return nil
}

func defaultRole(role *string) string {
	if role == nil {
		return ""
	}
	return *role
}

// upsertOwnerFromRepoMetadata reads repo_metadata.owner_record and upserts
// the corresponding Owner row. Returns the row ID so the repository row can
// link back via OwnerID. Returns nil owner ID (no error) when owner_record
// is missing.
func upsertOwnerFromRepoMetadata(ctx context.Context, g *gorm.DB, rm map[string]interface{}) (*uint, error) {
	rec, ok := rm["owner_record"].(map[string]interface{})
	if !ok {
		return nil, nil
	}
	login := strField(rec, "login")
	host := upsertOwnerHost(rm)
	if login == "" {
		return nil, nil
	}

	owner := db.Owner{
		UUID:              strField(rec, "uuid"),
		Host:              host,
		Login:             login,
		Kind:              strField(rec, "kind"),
		Name:              strField(rec, "name"),
		Description:       strField(rec, "description"),
		Email:             strField(rec, "email"),
		Company:           strField(rec, "company"),
		Location:          strField(rec, "location"),
		Website:           strField(rec, "website"),
		Twitter:           strField(rec, "twitter"),
		AvatarURL:         strField(rec, "avatar_url"),
		HTMLURL:           strField(rec, "html_url"),
		RepositoriesCount: intField(rec, "repositories_count"),
		TotalStars:        int64Field(rec, "total_stars"),
		Followers:         intField(rec, "followers"),
		Following:         intField(rec, "following"),
		Hidden:            boolField(rec, "hidden"),
	}
	now := time.Now()
	owner.PackagesSyncedAt = &now

	if err := g.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "host"}, {Name: "login"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"uuid", "kind", "name", "description", "email", "company",
			"location", "website", "twitter", "avatar_url", "html_url",
			"repositories_count", "total_stars", "followers", "following",
			"hidden", "packages_synced_at", "updated_at",
		}),
	}).Create(&owner).Error; err != nil {
		return nil, err
	}
	return &owner.ID, nil
}

func repoUpdateColumns() []string {
	return []string{
		"host", "owner", "owner_id", "full_name", "description", "homepage",
		"default_branch", "language", "license",
		"archived", "fork", "status",
		"stargazers_count", "forks_count", "subscribers_count",
		"open_issues_count", "size",
		"pushed_at", "latest_tag_published_at",
		// commit_stats slice
		"dds", "total_commits", "total_committers", "mean_commits",
		"past_year_commits", "past_year_committers", "past_year_bot_commits",
		"last_commit_at",
		// issue_metadata slice
		"issues_count", "pull_requests_count", "merged_pull_requests_count",
		"past_year_issues", "past_year_pull_requests",
		"past_year_issues_closed", "past_year_pull_requests_closed",
		"past_year_pull_requests_merged",
		"past_year_bot_issues", "past_year_bot_pull_requests",
		"active_maintainers_count",
		"avg_time_to_close_issue", "avg_time_to_close_pull_request",
		"packages_synced_at", "updated_at",
	}
}

func applyRepoMetadata(r *db.Repository, m map[string]interface{}) {
	now := time.Now()
	r.PackagesSyncedAt = &now
	r.Host = hostNameField(m)
	r.Owner = strField(m, "owner")
	r.FullName = strField(m, "full_name")
	r.Description = strField(m, "description")
	r.Homepage = strField(m, "homepage")
	r.DefaultBranch = strField(m, "default_branch")
	r.Language = strField(m, "language")
	r.License = strField(m, "license")
	r.Status = strField(m, "status")
	r.Archived = boolField(m, "archived")
	r.Fork = boolField(m, "fork")
	r.StargazersCount = intField(m, "stargazers_count")
	r.ForksCount = intField(m, "forks_count")
	r.SubscribersCount = intField(m, "subscribers_count")
	r.OpenIssuesCount = intField(m, "open_issues_count")
	r.Size = intField(m, "size")
	r.PushedAt = timeField(m, "pushed_at")
	r.LatestTagPublishedAt = timeField(m, "latest_tag_published_at")

	// commit_stats lives nested in repo_metadata; ecosyste.ms caches it
	// here verbatim from commits.ecosyste.ms.
	if cs, ok := m["commit_stats"].(map[string]interface{}); ok {
		r.DDS = floatField(cs, "dds")
		r.TotalCommits = intField(cs, "total_commits")
		r.TotalCommitters = intField(cs, "total_committers")
		r.MeanCommits = floatField(cs, "mean_commits")
		r.PastYearCommits = intField(cs, "past_year_commits")
		r.PastYearCommitters = intField(cs, "past_year_committers")
		r.PastYearBotCommits = intField(cs, "past_year_bot_commits")
		r.LastCommitAt = timeField(cs, "last_commit_at")
	}
}

// applyIssueMetadata pulls active_maintainers, past_year_* counts and avg
// close-times from the cached issue_metadata blob. Lives on the package
// response (not nested in repo_metadata). ecosyste.ms suffixes its
// past_year counters with `_count`; we expose them without the suffix on
// our side to keep the schema readable.
func applyIssueMetadata(r *db.Repository, im map[string]interface{}) {
	if im == nil {
		return
	}
	r.IssuesCount = intField(im, "issues_count")
	r.PullRequestsCount = intField(im, "pull_requests_count")
	r.MergedPullRequestsCount = intField(im, "merged_pull_requests_count")
	r.PastYearIssues = intField(im, "past_year_issues_count")
	r.PastYearPullRequests = intField(im, "past_year_pull_requests_count")
	r.PastYearIssuesClosed = intField(im, "past_year_issues_closed_count")
	r.PastYearPullRequestsClosed = intField(im, "past_year_pull_requests_closed_count")
	r.PastYearPullRequestsMerged = intField(im, "past_year_merged_pull_requests_count")
	r.PastYearBotIssues = intField(im, "past_year_bot_issues_count")
	r.PastYearBotPullRequests = intField(im, "past_year_bot_pull_requests_count")
	r.AvgTimeToCloseIssue = floatField(im, "avg_time_to_close_issue")
	r.AvgTimeToClosePullRequest = floatField(im, "avg_time_to_close_pull_request")
	// active_maintainers is an array of {login, count}; we only need the count.
	if arr, ok := im["active_maintainers"].([]interface{}); ok {
		r.ActiveMaintainersCount = len(arr)
	}
}

// hostNameField pulls the host name from repo_metadata, handling both the
// nested `host.name` shape (current shape) and a flat `host_type` fallback
// for older payloads.
func hostNameField(m map[string]interface{}) string {
	if host, ok := m["host"].(map[string]interface{}); ok {
		if name, ok := host["name"].(string); ok {
			return name
		}
	}
	if v, ok := m["host_type"].(string); ok {
		return v
	}
	return ""
}

// Same fix for the owner_record host: it's keyed on host_id (int), so we
// can't read host directly from owner_record. Inherit it from the
// surrounding repo_metadata.
func upsertOwnerHost(rm map[string]interface{}) string {
	return hostNameField(rm)
}

func strField(m map[string]interface{}, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func boolField(m map[string]interface{}, k string) bool {
	if v, ok := m[k].(bool); ok {
		return v
	}
	return false
}

func intField(m map[string]interface{}, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

func floatField(m map[string]interface{}, k string) float64 {
	switch v := m[k].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return 0
}

func int64Field(m map[string]interface{}, k string) int64 {
	switch v := m[k].(type) {
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	}
	return 0
}

func timeField(m map[string]interface{}, k string) *time.Time {
	s, ok := m[k].(string)
	if !ok || s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}
