package db

import (
	"fmt"

	"gorm.io/gorm"
)

// RecomputeLifecycle ports weekend-at-bernies' classify.rb: buckets every
// repo into active / dormant / dead / unknown based on positive signals of
// maintenance vs evidence of unresponsiveness. Runs at the end of every
// enrich after the underlying commit_stats and issue_metadata fields are
// fresh.
//
// Three updates: derived day counts (push/commit/release), the lifecycle
// label, and a one-line signals string used for debug/inspection.
//
// Constants match classify.rb so test fixtures from bernies' data map
// across cleanly:
//   ACTIVE_COMMITS_PER_YEAR = 12
//   STALE_RELEASE_DAYS      = 365
//
// Logic:
//   archived → dead
//   asked (issues+prs filed past year) AND no human activity → dead
//   human commits >= 12 OR recent release → active
//   any maintainer responding → dormant
//   else unknown
//
// "Human commits" = past_year_commits minus past_year_bot_commits.
func RecomputeLifecycle(g *gorm.DB) error {
	stmts := []string{
		`UPDATE repositories SET
			days_since_push = CASE WHEN pushed_at IS NULL THEN NULL
				ELSE CAST((julianday('now') - julianday(pushed_at)) AS INTEGER) END,
			days_since_commit = CASE WHEN last_commit_at IS NULL THEN NULL
				ELSE CAST((julianday('now') - julianday(last_commit_at)) AS INTEGER) END,
			days_since_release = CASE WHEN latest_tag_published_at IS NULL THEN NULL
				ELSE CAST((julianday('now') - julianday(latest_tag_published_at)) AS INTEGER) END
		`,
		// "recent" = within STALE_RELEASE_DAYS (365). We accept any of three
		// timestamp sources because the packages.ecosyste.ms cache rarely
		// populates last_commit_at and latest_tag_published_at; pushed_at
		// (set by the forge directly) is the only one consistently present.
		// The v2 commits/repos enrichers will tighten this with real data.
		`UPDATE repositories SET lifecycle = CASE
			WHEN archived = 1 THEN 'dead'
			WHEN (COALESCE(past_year_issues, 0) + COALESCE(past_year_pull_requests, 0)) > 0
			  AND COALESCE(past_year_commits, 0) - COALESCE(past_year_bot_commits, 0) <= 0
			  AND COALESCE(active_maintainers_count, 0) = 0
			  AND (COALESCE(past_year_issues_closed, 0) + COALESCE(past_year_pull_requests_merged, 0)) = 0
			  AND (pushed_at IS NULL OR julianday('now') - julianday(pushed_at) > 365)
			  AND (latest_tag_published_at IS NULL OR julianday('now') - julianday(latest_tag_published_at) > 365)
			THEN 'dead'
			WHEN (COALESCE(past_year_commits, 0) - COALESCE(past_year_bot_commits, 0)) >= 12
			  OR (latest_tag_published_at IS NOT NULL AND julianday('now') - julianday(latest_tag_published_at) <= 365)
			  OR (last_commit_at IS NOT NULL AND julianday('now') - julianday(last_commit_at) <= 365)
			  OR (pushed_at IS NOT NULL AND julianday('now') - julianday(pushed_at) <= 365)
			THEN 'active'
			WHEN COALESCE(active_maintainers_count, 0) > 0
			  OR (COALESCE(past_year_issues_closed, 0) + COALESCE(past_year_pull_requests_merged, 0)) > 0
			THEN 'dormant'
			ELSE 'unknown'
		END`,
	}
	for _, s := range stmts {
		if err := g.Exec(s).Error; err != nil {
			return fmt.Errorf("recompute lifecycle: %w", err)
		}
	}
	return nil
}
