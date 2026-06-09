package db

import (
	"path/filepath"
	"testing"
	"time"
)

// TestLifecycleBuckets exercises classify.rb's four buckets. We seed
// repositories with the inputs that drive each branch, recompute, and
// assert the label. Constants match classify.rb (12 commits/year, 365d
// stale release).
func TestLifecycleBuckets(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := Open(filepath.Join(dir, "m.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	twoYearsAgo := time.Now().AddDate(-2, 0, 0)
	threeMonthsAgo := time.Now().AddDate(0, -3, 0)

	type row struct {
		URL                       string
		Archived                  bool
		PastYearIssues            int
		PastYearPullRequests      int
		PastYearIssuesClosed      int
		PastYearPullRequestsMerged int
		PastYearCommits           int
		PastYearBotCommits        int
		ActiveMaintainersCount    int
		LatestTagPublishedAt      *time.Time
		LastCommitAt              *time.Time
		Want                      string
	}
	cases := []row{
		{URL: "https://example/archived", Archived: true, Want: "dead"},
		{
			URL:                    "https://example/dead-asked-unresponsive",
			PastYearIssues:         5,
			LatestTagPublishedAt:   &twoYearsAgo,
			Want:                   "dead",
		},
		{
			URL:                  "https://example/active-many-commits",
			PastYearCommits:      30,
			PastYearBotCommits:   0,
			Want:                 "active",
		},
		{
			URL:                  "https://example/active-recent-release",
			LatestTagPublishedAt: &threeMonthsAgo,
			Want:                 "active",
		},
		{
			URL:                       "https://example/dormant-responding",
			PastYearIssuesClosed:      4,
			PastYearPullRequestsMerged: 2,
			LatestTagPublishedAt:      &twoYearsAgo,
			Want:                      "dormant",
		},
		{URL: "https://example/unknown-no-signals", Want: "unknown"},
		{
			URL:                "https://example/bot-only-not-active",
			PastYearCommits:    30,
			PastYearBotCommits: 30,
			Want:               "unknown",
		},
	}

	for _, c := range cases {
		r := Repository{
			URL:                        c.URL,
			Archived:                   c.Archived,
			PastYearIssues:             c.PastYearIssues,
			PastYearPullRequests:       c.PastYearPullRequests,
			PastYearIssuesClosed:       c.PastYearIssuesClosed,
			PastYearPullRequestsMerged: c.PastYearPullRequestsMerged,
			PastYearCommits:            c.PastYearCommits,
			PastYearBotCommits:         c.PastYearBotCommits,
			ActiveMaintainersCount:     c.ActiveMaintainersCount,
			LatestTagPublishedAt:       c.LatestTagPublishedAt,
			LastCommitAt:               c.LastCommitAt,
		}
		if err := g.Create(&r).Error; err != nil {
			t.Fatalf("seed %s: %v", c.URL, err)
		}
	}

	if err := RecomputeLifecycle(g); err != nil {
		t.Fatalf("recompute: %v", err)
	}

	for _, c := range cases {
		var got Repository
		if err := g.Where("url = ?", c.URL).First(&got).Error; err != nil {
			t.Fatalf("read %s: %v", c.URL, err)
		}
		if got.Lifecycle != c.Want {
			t.Errorf("%s: lifecycle = %q, want %q", c.URL, got.Lifecycle, c.Want)
		}
	}
}
