# marshal

A local data lake for open source package data. Load an SBOM (CycloneDX or SPDX), and marshal fetches everything it can about every package, repository, owner, maintainer, and security advisory involved via the ecosyste.ms APIs. The result is a local SQLite database designed for power users who want to write their own queries.

Not a compliance tool. Not a vulnerability scanner. A schema you can ask anything of, with a thin UI on top for the common views.

## Status

v0.3 working slice. Sidebar sections for packages, repositories, owners, maintainers, advisories, and SBOMs — all sortable, filterable, paginated. Lifecycle classification (bernies port). Version-aware advisory effectiveness. Show pages with field grouping + cross-links into filtered list views. Saved filters per section. Single-file SQLite, no external dependencies at runtime.

## Install

Go 1.26+ required.

    git clone https://github.com/alpha-omega-security/marshal
    cd marshal
    go build -o marshal ./cmd/marshal

## Quick start

    ./marshal load path/to/your.cdx.json     # CycloneDX or SPDX
    ./marshal enrich                          # hit packages.ecosyste.ms
    ./marshal serve                           # open http://127.0.0.1:8080

DB lives at `./marshal.db` by default. Override with `--db /some/where.db` on any subcommand.

Or skip the CLI: run `./marshal serve`, hit http://127.0.0.1:8080/sboms, and upload the file. Auto-enrich kicks off in the background after upload; the SBOMs page shows running/done/failed per import.

## Commands

### `marshal load <path>`

Parses an SBOM via `git-pkgs/sbom` and upserts one row per un-versioned PURL into `packages`. Idempotent. Also creates a `package_imports` link row connecting each package to the load event and captures the **versioned** PURL fragment so advisory effectiveness can later match the actual loaded version against known vulnerable ranges.

Accepts `-` for stdin. CycloneDX (JSON or XML) and SPDX JSON both work today.

Input is capped at 100 MiB. Lift `MaxInputBytes` in `internal/ingest/ingest.go` if that bites.

### `marshal enrich [--only-stale] [--stale-days N]`

Calls `BulkLookup` on packages.ecosyste.ms in batches of 100 for every package row. One enricher populates five tables from one API response, then refreshes derived columns:

- **packages**: ecosystem, name, namespace, registry_url, homepage, description, language, licenses, latest_release_*, versions_count, downloads, dependent_packages_count, dependent_repos_count, rankings_average, maintainers_count, status, critical, advisory_count, max_cvss_score
- **repositories**: created or updated from the cached `repo_metadata` blob. Forge-level fields (full_name, host, owner, stargazers_count, forks_count, archived, fork, pushed_at, etc.) plus `commit_stats` (dds, total_commits, total_committers) and `issue_metadata` (past_year_issues, past_year_pull_requests_merged, active_maintainers_count, etc.) extracted from nested blobs
- **owners**: created or updated from `repo_metadata.owner_record` (uuid, login, kind, name, description, company, location, repositories_count, total_stars, followers, etc.)
- **maintainers**: registry-level publishers from the `maintainers[]` array. Joined to packages via `package_maintainers`
- **advisories**: stored from the cached `advisories[]` array with stable CVE/GHSA IDs. Joined to packages via `package_advisories` with `vulnerable_version_range`, `first_patched_version`, and a per-(package, advisory) `effective` flag set by matching the range against observed versions through `git-pkgs/vers`
- **Derived passes**: `RecomputeLocalCounts` (every `local_*` count), `RecomputeAdvisoryEffectiveness` (vers parser walks ranges vs observed versions), `RecomputeLifecycle` (ports weekend-at-bernies' `classify.rb` into a SQL CASE)

`--only-stale` skips packages whose `packages_synced_at` is within the last N days (default 7).

The cached `commit_stats` / `issue_metadata` / `advisory` blobs on packages.ecosyste.ms can lag relative to the dedicated commits.ecosyste.ms / issues.ecosyste.ms / advisories.ecosyste.ms services. Dedicated v2 enrichers (planned) refresh these directly.

### `marshal serve [--addr 127.0.0.1:8080]`

Web UI. List sections + per-entity show pages + SBOMs upload:

- `/packages` — sortable table, gmail-style filter, column picker, canned filters, saved filters, pagination
- `/repositories` — same shape; canned filters cover lifecycle buckets (Bernies/Dormant/Active/Unknown) plus Archived and Forks
- `/owners` — same; Organizations / Users / Top here canned filters
- `/maintainers` — same; Heavy hitters / Solo
- `/advisories` — same; Affecting loaded versions / Critical / High severity / Unpatched / All
- `/sboms` — list of loaded inputs with enrichment status, drag-and-drop file upload, remove
- `/{section}/{id}` — show page per entity, with grouped field cards, cross-links, and rich tables (versions across SBOMs on packages; affected packages with vulnerable ranges + observed versions on advisories; counts to all four lists scoped via `import_id:N` on SBOMs)

Defaults to `127.0.0.1` so nothing on the local network can poke it. Treat the deployed mode as a separate project; v0.3 ships no auth, no CSRF tokens, no per-tenant scoping.

## Lifecycle classification (bernies)

Repositories carry a `lifecycle` column populated by `db.RecomputeLifecycle`. Ported from `classify.rb` in `weekend-at-bernies`:

- **dead** — `archived = 1` OR (issues/PRs filed in the last year AND zero human commits AND zero active maintainers AND zero closed/merged AND pushed > 365 days ago)
- **active** — past-year human commits ≥ 12 OR recent release/commit/push (within 365 days)
- **dormant** — at least one responsive signal (active maintainers, closed issues, merged PRs)
- **unknown** — not enough data to decide

The bernies canned filter on `/repositories` shows the inputs the classifier used, so the verdict is auditable per row. With the current packages.ecosyste.ms cache, `past_year_issues`, `past_year_pull_requests`, `pushed_at`, and `archived` are the reliable signals; `past_year_commits`, `active_maintainers_count`, and `last_commit_at` are sparse until the dedicated v2 enrichers land.

## Advisory effectiveness

Every `(package, advisory)` join carries an `effective` boolean. `git-pkgs/vers` parses each `vulnerable_version_range` against the package's ecosystem (npm, gem, pypi, etc.) and tests every observed version stored in `package_imports`. If any loaded version satisfies the range, `effective = true`. Conservative defaults: empty range or no observed versions → effective (err toward showing).

The advisories list defaults to "Affecting loaded versions" so historical CVEs against versions you don't have don't drown out what actually matters. The full list is one click away. Effective counts also roll up to `packages.effective_advisory_count` and `repositories.local_effective_advisory_count` so the count columns and show-page cross-links lead with the number you care about ("12 affecting (of 24)" when both counts differ).

## Filter syntax

Per-section gmail-style filter bar. AND between terms. Supports:

| Form                | Meaning                              | Example                          |
|---------------------|---------------------------------------|-----------------------------------|
| `field:value`       | equals (numeric/bool), LIKE-contains (text) | `ecosystem:npm`            |
| `field:>N`          | greater than                          | `downloads:>1000000`              |
| `field:<N`          | less than                             | `max_cvss_score:<5`               |
| `field:>=N`         | greater or equal                      | `dependent_repos_count:>=100`     |
| `field:<=N`         | less or equal                         | `maintainers_count:<=2`           |
| `field:true` `field:false` | boolean                       | `critical:true`                   |
| `-term`             | NOT                                   | `-effective:true`                 |
| `"quoted phrase"`   | exact substring across text columns   | `"rate limit"`                    |
| bare word           | substring search across text columns  | `babel`                           |
| `field > N` (with spaces) | normalised to `field:>N`        | `maintainers_count > 1`           |

The "Available filter columns" picker under each filter bar lists what's filterable for that section. Unknown fields fall through to free-text rather than erroring.

**Virtual cross-table columns** let you scope across joins without writing SQL:

| Section        | Virtual column   | Resolves to                                      |
|----------------|------------------|--------------------------------------------------|
| packages       | `repository_id`  | packages whose repository_id matches             |
| packages       | `maintainer_id`  | packages this maintainer is on                   |
| packages       | `import_id`      | packages from this SBOM                          |
| packages       | `advisory_id`    | packages affected by this advisory               |
| repositories   | `import_id`      | repos backing any package in this SBOM           |
| owners         | `import_id`      | owners of any repo in this SBOM                  |
| advisories     | `package_id`     | advisories affecting this package                |
| advisories     | `repository_id`  | advisories on any package in this repo           |
| advisories     | `import_id`      | advisories on any package in this SBOM           |
| advisories     | `effective`      | flag-style: advisories that hit a loaded version |
| advisories     | `unpatched`      | flag-style: advisories with no first_patched     |

These power the "Open in Packages → N" cross-links on show pages. The query string is the saved-view format: bookmark any filtered URL to recall, sort and column visibility ride along.

### Saved filters

Each section has a **Save** button next to Filter/Clear. Save the current URL state with a name, and it shows up nested under the section in the sidebar, separated from the built-in canned filters under a small "Saved" header. Hover to delete.

Saved filters are kept in the `saved_filters` table — DB-resident, not browser-stored, so they persist across sessions.

## Show pages

`/packages/{id}`, `/repositories/{id}`, `/owners/{id}`, `/maintainers/{id}`, `/sboms/{id}`, `/advisories/{id}` — every entity has one. Header bar with icon + title + identifier + external "Open" button. Fields grouped into named cards (Identity / Versions / Popularity / Risk / Local counts on packages; Identity / Lifecycle / Activity / Forge counts on repositories; etc.). Plus relational tables where useful:

- **Package show**: "Versions across SBOMs" table showing which version came from which uploaded file
- **Advisory show**: "Affected packages" table with vulnerable range, first patched, observed-here version, and an "affecting" marker on rows where a loaded version is actually in range
- **SBOM show**: cross-links scoped via `import_id` to every list — N packages, N repositories, N owners, N affecting advisories

Clicking the name cell on any list row goes to that entity's show page.

## Schema

Single SQLite file, WAL mode. AutoMigrated on startup.

- **packages** — one row per un-versioned canonical PURL. Identity, popularity, advisory rollup (advisory_count, effective_advisory_count, effective_unpatched_advisory_count, max_cvss_score). Sync state per enricher
- **repositories** — one row per git URL. Cached forge-level data plus commit_stats / issue_metadata fields. Lifecycle column (active/dormant/dead/unknown). Local rollup counts including `local_effective_advisory_count`
- **owners** — one row per forge owner (host + login unique). Populated from `repo_metadata.owner_record`. Global lookup, not snapshotted
- **maintainers** — one row per registry publisher (ecosystem + login unique). Joined to packages via `package_maintainers`
- **advisories** — one row per security advisory (uuid unique). CVE/GHSA in `identifiers` JSON array. Severity, CVSS score, CVSS vector, published_at, withdrawn_at
- **imports** — one row per load event. Carries `enrichment_status`, `enrichment_started_at`, `enrichment_finished_at`, `enrichment_error` for upload-triggered auto-enrich state
- **package_imports** — join from packages to imports + `version` column capturing the original versioned PURL fragment per (package, import). The `import_id` here is what advisory effectiveness joins through
- **package_maintainers** — join from packages to maintainers
- **package_advisories** — join from packages to advisories with `vulnerable_version_range`, `first_patched_version`, `effective`
- **saved_filters** — user-saved URL states per section

Column names mirror ecosyste.ms canonical naming where the field exists upstream (`latest_release_number`, `stargazers_count`, `dependent_repos_count`, etc.). Local-only counts (`local_repos_count`, `local_packages_count`, `local_imports_count`, `local_advisory_count`, `local_effective_advisory_count`, `effective_advisory_count`, …) live separately so the upstream global figures are preserved alongside.

Inspect with the `sqlite3` CLI:

    sqlite3 marshal.db
    .schema repositories
    SELECT full_name, lifecycle, local_packages_count, local_effective_advisory_count
      FROM repositories
      WHERE lifecycle = 'dead'
      ORDER BY local_packages_count DESC
      LIMIT 20;

## Architecture

    cmd/marshal/                   # CLI entrypoint, flag parsing
    internal/
      db/                          # GORM models, sqlite open + migrate
        counts.go                  # RecomputeLocalCounts
        lifecycle.go               # RecomputeLifecycle (classify.rb port)
        effectiveness.go           # RecomputeAdvisoryEffectiveness (vers matcher)
      ingest/                      # SBOM parsing, PURL canonicalisation, package + import upsert
      enrich/packages/             # packages.ecosyste.ms enricher
        normalize.go               # git://, ssh://, .git, scp-style → https://
        packages.go                # main enrich loop + sync helpers
        advisories.go              # syncAdvisories + per-package range pick
        counts.go                  # wrapper that runs the three Recompute* in sequence
      web/                         # http handlers, filter DSL parser, templates, vendored assets
        advisories.go, owners.go, repositories.go, maintainers.go, sboms.go
        cells.go                   # per-section row cell renderers
        cols.go                    # shared /<section>/cols redirect handler
        filter.go                  # gmail-style DSL: ParseFilter + BuildSQL (with subquery columns)
        saved.go                   # POST /filters/save, /filters/delete
        show.go                    # show-page handlers + cross-link composition
        show_format.go             # per-entity field-group builders, value renderer
        pagination.go              # shared Pagination + parsePagination
        static/                    # theme.css + vendored frontend libs
        templates/                 # layout + page templates
    scripts/
      vendor-assets.sh             # refreshes static/vendor/

Frontend stack matches scrutineer at the same vendored versions: Tailwind v4.3 (browser JIT), Basecoat v0.3.11 (shadcn-style components), HTMX v2.0.6, Lucide v0.545 icons. Theme is `marshal` (honeydew + steel blue + strawberry red palette); other themes from scrutineer (`claude`, `ocean-breeze`, etc.) remain available via `data-theme` on `<html>`.

## Security posture

v0.3 ships local-first. Treat anything network-reachable as separate work.

- **Bind defaults to 127.0.0.1.** Pointing `--addr 0.0.0.0:N` exposes `/sboms/add` (file upload to disk-via-RAM), `/filters/save`, `/sboms/delete`, `/filters/delete`. No auth, no CSRF tokens
- **Request bodies capped at 64 KiB on normal POSTs**, SBOM upload capped at 100 MiB. ParseMultipartForm + `http.MaxBytesReader` + `io.LimitReader` belt-and-braces
- **HTTP read/write timeouts** set on the server (10s headers, 30s read, 60s write, 120s idle)
- **SQL goes through GORM with parameterised queries.** Raw SQL in `show.go`, `counts.go`, `lifecycle.go`, `effectiveness.go` uses `?` placeholders; user values are never string-concatenated. The filter DSL builds parameterised WHERE clauses including the virtual-column subqueries
- **html/template auto-escapes** everywhere. Cell renderers wrap user data with `html.EscapeString`. URLs use `template.URL` for trusted internal hrefs only
- **SBOM upload reads file content, not host paths.** The old path-text-field route was removed when the web upload landed
- **`file://` URLs and SSH-style refs** in SBOM PURLs get rewritten to canonical https through `enrich/packages/normalize.go`

## Performance posture

- Indexes on every FK (`packages.repository_id`, `repositories.owner_id`, `package_imports.*`, `package_maintainers.*`, `package_advisories.*`) and on the filter-friendly columns (`packages.purl` unique, `packages.ecosystem`, `repositories.archived`, `repositories.lifecycle`, `advisories.severity`, `advisories.cvss_score`)
- List pages paginate at 50 rows by default (override with `?per_page=N`, max 500). URL state preserved across pagination links
- Show pages do bounded `LIMIT N` subqueries
- `RecomputeLocalCounts` / `RecomputeAdvisoryEffectiveness` / `RecomputeLifecycle` each run after every ingest and every enrich. Effectiveness walks the join, parses ranges with `git-pkgs/vers`, sets the per-row flag, then rolls up per-package counts in one UPDATE

## What's not here yet

- `marshal scan <repo>` — clone via git-pkgs and generate the SBOM in-process
- Dedicated v2 enrichers for repos.ecosyste.ms, commits.ecosyste.ms, issues.ecosyste.ms, advisories.ecosyste.ms (the cached blobs in packages.ecosyste.ms lag, especially for the lifecycle inputs like `past_year_commits` and `last_commit_at`)
- `versions` enricher (per-version metadata in `package_versions`)
- `scorecard` enricher (OSSF Scorecard)
- Annotations system (`marshal annotate <yaml>`)
- YAML extension packs (derived columns + views)
- Snapshots, change detection, dependency-graph edges
- Group-by-aggregate UI; SQL workspace section
- Authn/authz / CSRF tokens for any deployed mode

## Development

    go build ./...
    go test ./...
    golangci-lint run --enable gocritic,gocognit,gocyclo,maintidx,dupl,mnd,unparam,ireturn,goconst,errcheck ./...
    govulncheck ./...
    deadcode ./...

To bump a vendored frontend asset, edit `scripts/vendor-assets.sh`, rerun it, commit the new file. The `<script>`/`<link>` tags in `internal/web/templates/layout.html` reference the version in the filename — update both.

## License

MIT. See [`LICENSE`](LICENSE).
