package ingest

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	sbomlib "github.com/git-pkgs/sbom"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/alpha-omega-security/marshal/internal/db"
)

// MaxInputBytes caps ingest input size to defend against pathological
// SBOMs. 100 MiB is enough for very large enterprise SBOMs (typical real
// SBOMs are well under 10 MiB) and small enough that an attacker can't
// blow up RAM by pointing the web ingest at /dev/zero.
const MaxInputBytes = 100 << 20

// LoadFile parses an SBOM file and upserts package rows for every component
// that has a resolvable PURL. Records an Import row for provenance.
// Returns the number of packages inserted plus the number already known.
func LoadFile(g *gorm.DB, path string) (inserted, existing int, err error) {
	var data []byte
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, MaxInputBytes+1))
	} else {
		var f *os.File
		f, err = os.Open(path)
		if err != nil {
			return 0, 0, fmt.Errorf("read %s: %w", path, err)
		}
		defer func() { _ = f.Close() }()
		data, err = io.ReadAll(io.LimitReader(f, MaxInputBytes+1))
	}
	if err != nil {
		return 0, 0, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > MaxInputBytes {
		return 0, 0, fmt.Errorf("input larger than %d bytes; raise MaxInputBytes if this is intentional", MaxInputBytes)
	}
	return LoadBytes(g, data, path)
}

func LoadBytes(g *gorm.DB, data []byte, sourcePath string) (inserted, existing int, err error) {
	doc, err := sbomlib.Parse(data)
	if err != nil {
		return 0, 0, fmt.Errorf("parse sbom: %w", err)
	}

	imp := db.Import{
		Path:        sourcePath,
		Format:      string(doc.Type),
		SpecVersion: doc.SpecVersion,
		Subject:     doc.Document.Name,
		LoadedAt:    timeNow(),
	}
	if err := g.Create(&imp).Error; err != nil {
		return 0, 0, fmt.Errorf("record import: %w", err)
	}

	for i := range doc.Packages {
		raw := doc.Packages[i].PURL()
		if raw == "" {
			continue
		}
		purl, version := splitPURL(raw)
		pkg := db.Package{
			PURL: purl,
			Name: doc.Packages[i].Name,
		}
		res := g.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "purl"}},
			DoNothing: true,
		}).Create(&pkg)
		if res.Error != nil {
			return inserted, existing, fmt.Errorf("upsert %s: %w", purl, res.Error)
		}
		if res.RowsAffected == 1 {
			inserted++
		} else {
			existing++
			// fetch existing row to get its ID for the join
			if err := g.Where("purl = ?", purl).First(&pkg).Error; err != nil {
				return inserted, existing, fmt.Errorf("lookup %s: %w", purl, err)
			}
		}
		// record the package <-> import link, ignore conflicts so re-running
		// the same SBOM file within one load doesn't duplicate. The version
		// comes from the original versioned PURL so advisory matching can
		// later test the actual loaded version against vulnerable ranges.
		if err := g.Clauses(clause.OnConflict{DoNothing: true}).Create(&db.PackageImport{
			PackageID: pkg.ID,
			ImportID:  imp.ID,
			Version:   version,
		}).Error; err != nil {
			return inserted, existing, fmt.Errorf("link %s to import: %w", purl, err)
		}
	}

	imp.PackageCount = inserted + existing
	if err := g.Save(&imp).Error; err != nil {
		return inserted, existing, fmt.Errorf("update import count: %w", err)
	}
	if err := db.RecomputeLocalCounts(g); err != nil {
		return inserted, existing, err
	}
	return inserted, existing, nil
}

// timeNow indirection so tests can swap it later if needed.
var timeNow = time.Now

// splitPURL splits a versioned PURL into (un-versioned PURL, version).
// PURL syntax: pkg:type/namespace/name@version?qualifiers#subpath
// The version is everything between the @ and the next ? or #. Returns
// empty version when none is present.
func splitPURL(purl string) (string, string) {
	slash := strings.LastIndex(purl, "/")
	if slash < 0 {
		slash = strings.Index(purl, ":")
	}
	at := strings.Index(purl[slash+1:], "@")
	if at < 0 {
		return purl, ""
	}
	at += slash + 1
	endVer := len(purl)
	for _, c := range []string{"?", "#"} {
		if i := strings.Index(purl[at:], c); i >= 0 && at+i < endVer {
			endVer = at + i
		}
	}
	version := purl[at+1 : endVer]
	return purl[:at] + purl[endVer:], version
}

// stripVersion is the legacy un-versioned-only helper. New code should
// prefer splitPURL, which keeps the version for downstream consumers.
func stripVersion(purl string) string {
	out, _ := splitPURL(purl)
	return out
}
