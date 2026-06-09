package db

import (
	"fmt"

	"gorm.io/gorm"
)

// RecomputeLocalCounts refreshes every `local_*` column on owners,
// maintainers, repositories, and packages from the join tables. Cheap:
// scalar subqueries against indexed FK columns. Called from both ingest
// (after a load adds package_imports rows) and enrich (after a refresh
// rewrites package_maintainers + repositories.owner_id).
func RecomputeLocalCounts(g *gorm.DB) error {
	stmts := []string{
		`UPDATE owners SET local_repos_count = (
			SELECT COUNT(*) FROM repositories WHERE repositories.owner_id = owners.id
		)`,
		`UPDATE maintainers SET local_packages_count = (
			SELECT COUNT(*) FROM package_maintainers WHERE package_maintainers.maintainer_id = maintainers.id
		)`,
		`UPDATE packages SET local_imports_count = (
			SELECT COUNT(DISTINCT import_id) FROM package_imports WHERE package_imports.package_id = packages.id
		)`,
		`UPDATE repositories SET local_packages_count = (
			SELECT COUNT(*) FROM packages WHERE packages.repository_id = repositories.id
		)`,
		`UPDATE advisories SET local_packages_count = (
			SELECT COUNT(DISTINCT package_id) FROM package_advisories WHERE package_advisories.advisory_id = advisories.id
		)`,
		`UPDATE repositories SET local_advisory_count = (
			SELECT COUNT(DISTINCT pa.advisory_id)
			FROM package_advisories pa
			JOIN packages p ON p.id = pa.package_id
			WHERE p.repository_id = repositories.id
		)`,
		`UPDATE repositories SET local_unpatched_advisory_count = (
			SELECT COUNT(DISTINCT pa.advisory_id)
			FROM package_advisories pa
			JOIN packages p ON p.id = pa.package_id
			WHERE p.repository_id = repositories.id
			  AND (pa.first_patched_version IS NULL OR pa.first_patched_version = '')
		)`,
		// "effective" rollups: only count advisories where at least one
		// observed version of a package in this repo is in the vulnerable
		// range. Mirrors the local_* shape so list pages can default to it.
		`UPDATE repositories SET local_effective_advisory_count = (
			SELECT COUNT(DISTINCT pa.advisory_id)
			FROM package_advisories pa
			JOIN packages p ON p.id = pa.package_id
			WHERE p.repository_id = repositories.id
			  AND pa.effective = 1
		)`,
	}
	for _, s := range stmts {
		if err := g.Exec(s).Error; err != nil {
			return fmt.Errorf("recompute counts: %w", err)
		}
	}
	return nil
}
