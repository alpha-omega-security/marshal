package db

import (
	"fmt"

	"github.com/git-pkgs/vers"
	"gorm.io/gorm"
)

// RecomputeAdvisoryEffectiveness sets package_advisories.effective per
// (package, advisory) based on whether any observed version of the package
// in package_imports.version falls inside vulnerable_version_range. The
// matcher is ecosystem-aware via git-pkgs/vers.
//
// Conservative defaults: empty range or unparseable range → effective=true.
// No observed versions for the package → effective=true (we don't know
// which version the user has).
//
// After flipping the per-join flags, we roll counts up onto
// packages.effective_advisory_count and packages.effective_unpatched_advisory_count
// in one UPDATE so list pages can default to the loaded-version view
// cheaply.
func RecomputeAdvisoryEffectiveness(g *gorm.DB) error {
	type joinRow struct {
		PackageID              uint
		AdvisoryID             uint
		VulnerableVersionRange string
		FirstPatchedVersion    string
		Ecosystem              string
	}
	var rows []joinRow
	if err := g.Raw(`
		SELECT pa.package_id, pa.advisory_id,
		       pa.vulnerable_version_range, pa.first_patched_version,
		       p.ecosystem
		FROM package_advisories pa
		JOIN packages p ON p.id = pa.package_id
	`).Scan(&rows).Error; err != nil {
		return fmt.Errorf("scan joins: %w", err)
	}

	// gather observed versions per package once, since many advisories may
	// share the same package and parsing the imports per (pkg, advisory)
	// would be wasted work.
	versionsByPkg := map[uint][]string{}
	{
		type vrow struct {
			PackageID uint
			Version   string
		}
		var vs []vrow
		if err := g.Raw(`
			SELECT DISTINCT package_id, version
			FROM package_imports
			WHERE version <> ''
		`).Scan(&vs).Error; err != nil {
			return fmt.Errorf("scan versions: %w", err)
		}
		for _, v := range vs {
			versionsByPkg[v.PackageID] = append(versionsByPkg[v.PackageID], v.Version)
		}
	}

	for _, r := range rows {
		effective := isEffective(r.VulnerableVersionRange, r.Ecosystem, versionsByPkg[r.PackageID])
		if err := g.Exec(
			`UPDATE package_advisories SET effective = ? WHERE package_id = ? AND advisory_id = ?`,
			effective, r.PackageID, r.AdvisoryID,
		).Error; err != nil {
			return fmt.Errorf("update join: %w", err)
		}
	}

	// roll up effective counts on packages
	if err := g.Exec(`
		UPDATE packages SET
			effective_advisory_count = (
				SELECT COUNT(*) FROM package_advisories pa
				WHERE pa.package_id = packages.id AND pa.effective = 1
			),
			effective_unpatched_advisory_count = (
				SELECT COUNT(*) FROM package_advisories pa
				WHERE pa.package_id = packages.id AND pa.effective = 1
				  AND (pa.first_patched_version IS NULL OR pa.first_patched_version = '')
			)
	`).Error; err != nil {
		return fmt.Errorf("rollup packages: %w", err)
	}
	return nil
}

// isEffective returns true when at least one observed version satisfies
// the vulnerable range. Empty range, no observed versions, or parse
// failure all return true: better to surface an advisory you might dismiss
// than silently hide one you should look at.
func isEffective(rangeStr, ecosystem string, observed []string) bool {
	if rangeStr == "" || len(observed) == 0 {
		return true
	}
	r, err := vers.ParseNative(rangeStr, ecosystem)
	if err != nil || r == nil {
		return true
	}
	for _, v := range observed {
		if r.Contains(v) {
			return true
		}
	}
	return false
}
