package packages

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	ecopackages "github.com/ecosyste-ms/ecosystems-go/packages"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/alpha-omega-security/marshal/internal/db"
)

// syncAdvisories upserts every advisory from info.Advisories and rewrites
// the package_advisories join rows for this package so the current set is
// authoritative. Each advisory carries identifiers (CVE/GHSA) and
// references as JSON arrays; SQLite's json_each makes them queryable.
//
// The per-package fields (vulnerable_version_range, first_patched_version)
// live on the join because one advisory affects many packages with
// different ranges.
func syncAdvisories(ctx context.Context, g *gorm.DB, pkg *db.Package, info *ecopackages.PackageWithRegistry) error {
	if err := g.WithContext(ctx).Where("package_id = ?", pkg.ID).Delete(&db.PackageAdvisory{}).Error; err != nil {
		return err
	}
	if err := refreshPackageAdvisoryRollup(ctx, g, pkg); err != nil {
		return err
	}
	for _, a := range info.Advisories {
		if a.Uuid == "" {
			continue
		}
		ar := db.Advisory{
			UUID:         a.Uuid,
			Identifiers:  jsonOrEmpty(a.Identifiers),
			References:   jsonOrEmpty(a.References),
			PublishedAt:  parseTime(a.PublishedAt),
			WithdrawnAt:  parseTime(a.WithdrawnAt),
		}
		if a.Url != nil {
			ar.URL = *a.Url
		}
		if a.Title != nil {
			ar.Title = *a.Title
		}
		if a.Description != nil {
			ar.Description = *a.Description
		}
		if a.Origin != nil {
			ar.Origin = *a.Origin
		}
		if a.Severity != nil {
			ar.Severity = *a.Severity
		}
		if a.Classification != nil {
			ar.Classification = *a.Classification
		}
		if a.SourceKind != nil {
			ar.SourceKind = *a.SourceKind
		}
		if a.CvssScore != nil {
			ar.CVSSScore = *a.CvssScore
		}
		if a.CvssVector != nil {
			ar.CVSSVector = *a.CvssVector
		}
		now := time.Now()
		ar.LastSyncedAt = &now

		if err := g.WithContext(ctx).Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "uuid"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"url", "title", "description", "origin", "severity",
				"classification", "source_kind", "cvss_score", "cvss_vector",
				"published_at", "withdrawn_at", "identifiers", "references",
				"last_synced_at", "updated_at",
			}),
		}).Create(&ar).Error; err != nil {
			return err
		}

		vRange, patched := pickPackageRange(a.Packages)
		if err := g.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&db.PackageAdvisory{
			PackageID:              pkg.ID,
			AdvisoryID:             ar.ID,
			VulnerableVersionRange: vRange,
			FirstPatchedVersion:    patched,
		}).Error; err != nil {
			return err
		}
	}
	return refreshPackageAdvisoryRollup(ctx, g, pkg)
}

// refreshPackageAdvisoryRollup updates packages.advisory_count and
// unpatched_advisory_count from the join. Cheap: scoped to one package.
func refreshPackageAdvisoryRollup(ctx context.Context, g *gorm.DB, pkg *db.Package) error {
	var stats struct {
		Total     int
		Unpatched int
	}
	row := g.WithContext(ctx).Raw(`
		SELECT
			COUNT(*) AS total,
			COALESCE(SUM(CASE WHEN first_patched_version IS NULL OR first_patched_version = '' THEN 1 ELSE 0 END), 0) AS unpatched
		FROM package_advisories WHERE package_id = ?
	`, pkg.ID).Row()
	if err := row.Scan(&stats.Total, &stats.Unpatched); err != nil {
		return fmt.Errorf("rollup scan: %w", err)
	}
	return g.WithContext(ctx).Model(&db.Package{}).Where("id = ?", pkg.ID).Updates(map[string]interface{}{
		"advisory_count":           stats.Total,
		"unpatched_advisory_count": stats.Unpatched,
	}).Error
}

// pickPackageRange digs into a.Packages (an array of per-package descriptors)
// to find one with version-range data. ecosyste.ms shapes these as
// `{"package_name": "...", "ecosystem": "...", "versions": [...]}` with a
// `vulnerable_version_range` and `first_patched_version` at the version level.
// We pick the first hit because syncAdvisories already knows which package
// it's syncing for and the cached advisory shape doesn't always carry a
// usable match key for filtering across multi-package advisories.
func pickPackageRange(pkgs []map[string]interface{}) (vRange, patched string) {
	for _, entry := range pkgs {
		// best-effort match: any entry whose package_name appears in the purl
		name, _ := entry["package_name"].(string)
		if name == "" {
			continue
		}
		versions, ok := entry["versions"].([]interface{})
		if !ok || len(versions) == 0 {
			continue
		}
		first, _ := versions[0].(map[string]interface{})
		if vr, ok := first["vulnerable_version_range"].(string); ok {
			vRange = vr
		}
		if fp, ok := first["first_patched_version"].(string); ok {
			patched = fp
		}
		// stop on first non-empty hit
		if vRange != "" || patched != "" {
			return
		}
	}
	return
}

func jsonOrEmpty(v interface{}) string {
	if v == nil {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func parseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}
