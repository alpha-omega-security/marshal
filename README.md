# marshal

A local data lake for open source package data. Load an SBOM (CycloneDX or SPDX), and marshal fetches everything it can about every package, repository, owner, and maintainer involved via the ecosyste.ms APIs. The result is a local SQLite database designed for power users who want to write their own queries.

Not a compliance tool. Not a vulnerability scanner. A schema you can ask anything of, with a thin UI on top for the common views.

## Status

v0.2 working slice. Five sidebar sections (Packages, Repositories, Owners, Maintainers, SBOMs), all sortable and filterable. Show pages for every entity with cross-links into filtered list views. Saved filters per section. Single-file SQLite, no external dependencies at runtime.

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

## Commands

### `marshal load <path>`

Parses an SBOM via `git-pkgs/sbom` and upserts one row per un-versioned PURL into `packages`. Idempotent. Also creates a `package_imports` link row connecting each package to the load event, so you can later answer "which SBOM does this package come from".

Accepts `-` for stdin. CycloneDX (JSON or XML) and SPDX JSON both work today.

Input is capped at 100 MiB. Lift `MaxInputBytes` in `internal/ingest/ingest.go` if that bites.

### `marshal enrich [--only-stale] [--stale-days N]`

Calls `BulkLookup` on packages.ecosyste.ms in batches of 100 for every package row. For each match it populates:

- packages: ecosystem, name, namespace, registry_url, homepage, description, language, licenses, latest_release_*, versions_count, downloads, dependent_packages_count, dependent_repos_count, rankings_average, maintainers_count, status, critical, advisory_count, max_cvss_score
- repositories: created or updated from `repo_metadata`. Forge-level fields (full_name, host, owner, stargazers_count, forks_count, archived, fork, pushed_at, latest_tag_published_at, etc.) come from the cached blob inside packages.ecosyste.ms's response.
- owners: created or updated from `repo_metadata.owner_record` (uuid, login, kind, name, description, company, location, repositories_count, total_stars, followers, etc.).
- maintainers: registry-level publishers from the `maintainers[]` array. Joined to packages via `package_maintainers`.
- local_*: count of repos/packages/maintainers/imports that live in *this* database, separate from the upstream global counts. Refreshed at the end of every enrich and every web ingest.

`--only-stale` skips packages whose `packages_synced_at` is within the last N days (default 7).

### `marshal serve [--addr 127.0.0.1:8080]`

Web UI. Six routes:

- `/packages` — sortable table, gmail-style filter, column picker, canned filters, saved filters
- `/repositories` — same shape
- `/owners` — same
- `/maintainers` — same
- `/sboms` — list of loaded inputs; add a new one by pasting a host path; remove an import (packages stay)
- `/{section}/{id}` — show page per entity, reflection-driven field grid, cross-linked to the related sections via filtered list views

Defaults to `127.0.0.1` so nothing on the local network can poke it. Treat the deployed mode as a separate project; v0.2 ships no auth, no CSRF tokens, no per-tenant scoping.

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
| `-term`             | NOT                                   | `-critical:true`                  |
| `"quoted phrase"`   | exact substring across text columns   | `"rate limit"`                    |
| bare word           | substring search across text columns  | `babel`                           |
| `field > N` (with spaces) | normalised to `field:>N`        | `maintainers_count > 1`           |

The "Available filter columns" picker under each filter bar lists what's filterable for that section. Unknown fields fall through to free-text rather than erroring.

**Virtual cross-table columns** on packages let you scope through joins without writing SQL:

- `repository_id:N` — packages whose repository_id matches (FK)
- `maintainer_id:N` — packages this maintainer is on (via `package_maintainers`)
- `import_id:N` — packages from this SBOM (via `package_imports`)

These power the "Open in Packages →" links on show pages.

URLs are the saved-query format. Bookmark any filtered view to share or recall. Sort and visible columns ride along (`?q=...&sort=...&dir=desc&cols=name,ecosystem,downloads`).

### Saved filters

Each section has a **Save** button next to Filter/Clear. Save the current URL state with a name, and it shows up nested under the section in the sidebar, separated from the built-in canned filters under a small "Saved" header. Hover any saved filter to delete it.

Saved filters are kept in the `saved_filters` table — they're DB-resident, not stored in the browser, so they persist across sessions and survive cookie clearing.

## Show pages

`/packages/{id}`, `/repositories/{id}`, `/owners/{id}`, `/maintainers/{id}`, `/sboms/{id}` all render the entity's fields via reflection (any new column on the model automatically appears) plus a Related section that links to filtered list views. So from an owner's show page, "Open in Repositories → N repositories" lands you on `/repositories?q=owner:<login>` and you can keep composing the filter from there.

Clicking the name cell on any list row goes to the show page.

## Schema

Single SQLite file, WAL mode. AutoMigrated on startup.

- **packages** — one row per un-versioned canonical PURL. Identity, popularity, advisory rollup. Sync state.
- **package_versions** — TBD; versioned PURLs live here when implemented.
- **repositories** — one row per git URL. Cached forge-level data from `repo_metadata`. Linked to owners via `owner_id` FK.
- **owners** — one row per forge owner (host + login unique). Populated from `repo_metadata.owner_record`. Global lookup, not snapshotted.
- **maintainers** — one row per registry publisher (ecosystem + login unique). Joined to packages via `package_maintainers`.
- **imports** — one row per load event.
- **package_imports** — join from packages to imports for "which SBOM is this in" queries.
- **package_maintainers** — join from packages to maintainers.
- **saved_filters** — user-saved URL states per section.

Column names mirror ecosyste.ms canonical naming where the field exists upstream (`latest_release_number`, `stargazers_count`, `dependent_repos_count`, etc.). Local-only counts (`local_repos_count`, `local_packages_count`, `local_imports_count`) live separately so the upstream global figures are preserved alongside.

Inspect with the `sqlite3` CLI:

    sqlite3 marshal.db
    .schema packages
    SELECT name, ecosystem, downloads, max_cvss_score, critical
      FROM packages
      WHERE critical = 1
      ORDER BY dependent_repos_count DESC
      LIMIT 20;

## Architecture

    cmd/marshal/                   # CLI entrypoint, flag parsing
    internal/
      db/                          # GORM models, sqlite open + migrate, RecomputeLocalCounts
      ingest/                      # SBOM parsing, PURL canonicalisation, package + import upsert
      enrich/packages/             # packages.ecosyste.ms enricher
        normalize.go               # git://, ssh://, .git, scp-style → https://
        packages.go                # main enrich loop + sync helpers
        counts.go                  # wrapper around db.RecomputeLocalCounts
      web/                         # http handlers, filter DSL parser, templates, vendored assets
        cells.go                   # per-section row cell renderers
        cols.go                    # shared /<section>/cols redirect handler
        filter.go                  # gmail-style DSL: ParseFilter + BuildSQL (with subquery columns)
        saved.go                   # POST /filters/save, /filters/delete
        show.go                    # reflection-based show-page renderer + cross-links
        static/                    # theme.css + vendored frontend libs
        templates/                 # layout + page templates
    scripts/
      vendor-assets.sh             # refreshes static/vendor/

Frontend stack matches scrutineer at the same vendored versions: Tailwind v4.3 (browser JIT), Basecoat v0.3.11 (shadcn-style components), HTMX v2.0.6, Lucide v0.545 icons.

## Security posture

v0.2 ships local-first. Treat anything network-reachable as separate work.

- **Bind defaults to 127.0.0.1.** Pointing `--addr 0.0.0.0:N` exposes /sboms/add (arbitrary file read on the host), /filters/save, /sboms/delete, /filters/delete. No auth, no CSRF tokens.
- **Request bodies capped at 64 KiB**, ingest input at 100 MiB. ParseForm and stdin reads use LimitReader.
- **HTTP read/write timeouts** set on the server (10s headers, 30s read, 60s write, 120s idle).
- **SQL goes through GORM with parameterised queries.** Raw SQL in `show.go` and `counts.go` uses `?` placeholders; user values are never string-concatenated. The filter DSL builds parameterised WHERE clauses including the virtual-column subqueries.
- **html/template auto-escapes** everywhere. Cell renderers wrap user data with `html.EscapeString`. URLs use `template.URL` for trusted internal hrefs only.
- **SBOM ingest reads host files** under the user the marshal process runs as. Don't run marshal as root.
- **`file://` URLs and SSH-style refs** in SBOM PURLs get rewritten to canonical https through `enrich/packages/normalize.go`.

## Performance posture

- Indexes on every FK (`packages.repository_id`, `repositories.owner_id`, `package_imports.*`, `package_maintainers.*`) and on the filter-friendly columns (`packages.purl` unique, `packages.ecosystem`, `repositories.archived`, etc.).
- List pages paginate at 50 rows by default (override with `?per_page=N`, max 500).
- Show pages do bounded `LIMIT N` subqueries.
- `RecomputeLocalCounts` runs four `UPDATE ... = (SELECT COUNT(*) ...)` statements after each ingest and each enrich. Cheap; whole DB scan but tiny in practice.

## What's not here yet

Highlights:

- `marshal scan <repo>` — clone via git-pkgs and generate the SBOM in-process
- Dedicated enrichers for repos.ecosyste.ms, commits.ecosyste.ms, issues.ecosyste.ms (current implementation uses the cached blobs inside packages.ecosyste.ms, which is lag-prone for lifecycle classification)
- `lifecycle` derived column (port of weekend-at-bernies' `classify.rb`)
- Advisories sidebar section
- Snapshots, change detection, dependency edges
- YAML extension packs
- Pagination on list pages
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
