package db

import (
	"time"
)

type Package struct {
	ID        uint   `gorm:"primaryKey"`
	PURL      string `gorm:"column:purl;uniqueIndex"`
	Ecosystem string `gorm:"index"`
	Name      string `gorm:"index"`
	Namespace string

	RepositoryID *uint `gorm:"index"`

	RegistryURL string `gorm:"column:registry_url"`
	Homepage    string
	Description string
	Language    string
	Licenses    string

	LatestReleaseNumber       string
	LatestReleasePublishedAt  *time.Time
	FirstReleasePublishedAt   *time.Time
	VersionsCount             int

	Downloads               int64
	DownloadsPeriod         string
	DependentPackagesCount  int
	DependentReposCount     int
	DockerDependentsCount   int
	DockerDownloadsCount    int64
	RankingsAverage         float64

	MaintainersCount int
	Status           string
	Critical         bool

	AdvisoryCount          int
	UnpatchedAdvisoryCount int
	// EffectiveAdvisoryCount: advisories whose vulnerable_version_range
	// matches at least one observed version of this package. Use this for
	// "does this loaded package actually have a known vuln" queries.
	EffectiveAdvisoryCount         int
	EffectiveUnpatchedAdvisoryCount int
	MaxCVSSScore                    float32

	// LocalImportsCount is how many SBOM/PURL-list imports this package
	// appears in within *this* database. Refreshed at the end of every
	// enrich via recomputeCounts.
	LocalImportsCount int

	PackagesSyncedAt *time.Time

	LastSyncedAt *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// SavedFilter is a user-named view (the URL state for a list page) stored
// so it can be re-summoned from the sidebar. Lives in the DB rather than
// in the URL so it survives clearing cookies and is shared across devices
// pointed at the same marshal.db.
type SavedFilter struct {
	ID        uint   `gorm:"primaryKey"`
	Section   string `gorm:"index:idx_saved_section_name,unique"`
	Name      string `gorm:"index:idx_saved_section_name,unique"`
	Query     string
	Cols      string
	Sort      string
	Dir       string
	Position  int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PackageImport links a package to the import event that brought it in.
// Many-to-many: a package can land via many imports, and an import covers
// many packages. Re-loading the same file generates new join rows; we don't
// dedup on (package, import) because re-loads bump the same import_id.
type PackageImport struct {
	PackageID uint `gorm:"primaryKey;index"`
	ImportID  uint `gorm:"primaryKey;index"`
	Direct    bool // set when the SBOM marked this as a top-level component

	// Version captures the version fragment of the original versioned PURL
	// as it appeared in the SBOM (e.g. "4.17.21"). Empty when the input
	// gave us a PURL without a version. Used to decide whether an advisory's
	// vulnerable_version_range actually intersects the version we loaded.
	Version string `gorm:"index"`
}

// Import records one load event — an SBOM file, a PURL list, or whatever
// source descriptor we accept. Provenance for the packages that came in
// during that load. Stays named `imports` per the PRD; UI labels it SBOMs
// for now since SBOMs are the only input format wired up.
type Import struct {
	ID           uint   `gorm:"primaryKey"`
	Path         string `gorm:"index"`
	Format       string // "cyclonedx" | "spdx" | "purl-list"
	SpecVersion  string
	Subject      string
	Owner        string
	Label        string
	PackageCount int
	LoadedAt     time.Time

	// EnrichmentStatus surfaces the state of the auto-enrich the upload
	// triggered. "" / "pending" before it runs, "running" while in flight,
	// "done" on success, "failed" with the message in EnrichmentError.
	EnrichmentStatus    string
	EnrichmentStartedAt *time.Time
	EnrichmentFinishedAt *time.Time
	EnrichmentError     string
}

// Owner is one forge owner (GitHub org/user, GitLab group, etc.). Global
// lookup, no snapshot scope. Populated by the packages enricher reading
// repo_metadata.owner_record from packages.ecosyste.ms.
// Advisory is one security advisory. Stable identity via uuid; CVE/GHSA
// IDs live in Identifiers (JSON array) since one advisory can carry many.
// Populated by the packages enricher from the cached advisories[] blob on
// each Package response.
type Advisory struct {
	ID             uint   `gorm:"primaryKey"`
	UUID           string `gorm:"column:uuid;uniqueIndex"`
	URL            string `gorm:"column:url"`
	Title          string
	Description    string
	Origin         string
	Severity       string `gorm:"index"`
	Classification string
	SourceKind     string
	CVSSScore      float32 `gorm:"column:cvss_score;index"`
	CVSSVector     string  `gorm:"column:cvss_vector"`
	PublishedAt    *time.Time
	WithdrawnAt    *time.Time
	Identifiers    string // JSON array, queryable via json_each
	References     string // JSON array

	// LocalPackagesCount: how many packages in this DB are linked to this
	// advisory via package_advisories. Refreshed by RecomputeLocalCounts.
	LocalPackagesCount int

	LastSyncedAt *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// PackageAdvisory is the many-to-many join. Vulnerable range and first
// patched version belong on the relationship, not the advisory itself,
// because they're per-package within a single advisory.
type PackageAdvisory struct {
	PackageID              uint `gorm:"primaryKey;index"`
	AdvisoryID             uint `gorm:"primaryKey;index"`
	VulnerableVersionRange string
	FirstPatchedVersion    string

	// Effective is true when at least one observed version of the package
	// (from package_imports.version) falls inside VulnerableVersionRange.
	// Computed by RecomputeAdvisoryEffectiveness; defaults to true when no
	// observed versions exist or the range can't be parsed (conservative).
	Effective bool `gorm:"index"`
}

// Maintainer is a registry-level publisher (npm author, PyPI owner, etc.)
// for one ecosystem. The same human appearing on multiple ecosystems lives
// as separate rows because the (ecosystem, login) tuple is what ecosyste.ms
// returns and what users reason about.
type Maintainer struct {
	ID             uint   `gorm:"primaryKey"`
	UUID           string `gorm:"column:uuid;index"`
	Ecosystem      string `gorm:"index:idx_maintainer_eco_login,unique"`
	Login          string `gorm:"index:idx_maintainer_eco_login,unique"`
	Name           string
	Email          string
	URL            string `gorm:"column:url"`
	HTMLURL        string `gorm:"column:html_url"`
	Role           string
	PackagesCount  int
	TotalDownloads int64

	// LocalPackagesCount is the count of packages in *this* database joined
	// to this maintainer via package_maintainers. Refreshed at the end of
	// every enrich; distinct from PackagesCount (upstream global figure).
	LocalPackagesCount int

	PackagesSyncedAt *time.Time
	LastSyncedAt     *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// PackageMaintainer is the many-to-many join between packages and registry
// maintainers. Role captures the relationship (owner/maintainer/etc.) so
// we can tell who actually has publish rights vs who just contributed.
type PackageMaintainer struct {
	PackageID    uint `gorm:"primaryKey;index"`
	MaintainerID uint `gorm:"primaryKey;index"`
	Role         string
}

type Owner struct {
	ID    uint   `gorm:"primaryKey"`
	UUID  string `gorm:"column:uuid;index"`
	Host  string `gorm:"index:idx_owner_host_login,unique"`
	Login string `gorm:"index:idx_owner_host_login,unique"`
	Kind  string `gorm:"index"` // "organization" | "user"

	Name        string
	Description string
	Email       string
	Company     string
	Location    string
	Website     string
	Twitter     string
	AvatarURL   string `gorm:"column:avatar_url"`
	HTMLURL     string `gorm:"column:html_url"`

	RepositoriesCount int
	TotalStars        int64
	Followers         int
	Following         int
	Hidden            bool

	// LocalReposCount is the count of repositories in *this* database with
	// owner_id = this owner. Refreshed by recomputeCounts at the end of
	// every enrich. Distinct from RepositoriesCount which is the upstream
	// global figure.
	LocalReposCount int

	PackagesSyncedAt *time.Time
	LastSyncedAt     *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Repository struct {
	ID       uint   `gorm:"primaryKey"`
	URL      string `gorm:"uniqueIndex"`
	Host     string `gorm:"index"`
	Owner    string `gorm:"index"`
	OwnerID  *uint  `gorm:"index"`
	FullName string `gorm:"index"`

	Description   string
	Homepage      string
	DefaultBranch string
	Language      string
	License       string

	Archived bool `gorm:"index"`
	Fork     bool
	Status   string

	StargazersCount   int `gorm:"index"`
	ForksCount        int
	SubscribersCount  int
	OpenIssuesCount   int
	Size              int

	PushedAt              *time.Time
	LatestTagPublishedAt  *time.Time

	// LocalPackagesCount is how many Package rows point at this repository
	// via packages.repository_id. Recomputed at the end of every enrich.
	LocalPackagesCount int

	// LocalAdvisoryCount: distinct advisories affecting any package whose
	// repository_id is this repo. Two-hop subquery; refreshed by
	// RecomputeLocalCounts.
	LocalAdvisoryCount          int
	LocalUnpatchedAdvisoryCount int
	// LocalEffectiveAdvisoryCount: same denominator filtered to advisories
	// whose vulnerable range hits at least one observed version.
	LocalEffectiveAdvisoryCount int

	// commit_stats (from packages.ecosyste.ms's cached commit_stats blob,
	// originally from commits.ecosyste.ms). The bernies authors flag this
	// cache as lag-prone; v2 dedicated commits enricher will refresh.
	DDS                  float64 `gorm:"column:dds"`
	TotalCommits         int
	TotalCommitters      int
	MeanCommits          float64
	PastYearCommits      int
	PastYearCommitters   int
	PastYearBotCommits   int
	LastCommitAt         *time.Time

	// issue_metadata (from packages.ecosyste.ms's cached issue_metadata blob,
	// originally from issues.ecosyste.ms).
	IssuesCount                  int
	PullRequestsCount            int
	MergedPullRequestsCount      int
	PastYearIssues               int
	PastYearPullRequests         int
	PastYearIssuesClosed         int
	PastYearPullRequestsClosed   int
	PastYearPullRequestsMerged   int
	PastYearBotIssues            int
	PastYearBotPullRequests      int
	ActiveMaintainersCount       int
	AvgTimeToCloseIssue          float64
	AvgTimeToClosePullRequest    float64

	// Derived columns (filled by RecomputeLifecycle from the inputs above):
	DaysSincePush       *int
	DaysSinceCommit     *int
	DaysSinceRelease    *int

	// Lifecycle is the bernies classification: active | dormant | dead | unknown.
	// Recomputed after every enrich. Empty until enrich has run.
	Lifecycle string `gorm:"index"`

	PackagesSyncedAt *time.Time

	LastSyncedAt *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
