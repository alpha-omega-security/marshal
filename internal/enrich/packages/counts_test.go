package packages

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alpha-omega-security/marshal/internal/db"
)

func TestRecomputeCounts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g, err := db.Open(filepath.Join(dir, "marshal.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	owner := db.Owner{Host: "github", Login: "octo", Kind: "user", RepositoriesCount: 999} // upstream says 999
	if err := g.Create(&owner).Error; err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	for i := 0; i < 3; i++ {
		repo := db.Repository{URL: "https://github.com/octo/r" + string(rune('a'+i)), OwnerID: &owner.ID}
		if err := g.Create(&repo).Error; err != nil {
			t.Fatalf("seed repo: %v", err)
		}
	}

	m := db.Maintainer{Ecosystem: "npm", Login: "alice", PackagesCount: 999}
	if err := g.Create(&m).Error; err != nil {
		t.Fatalf("seed maintainer: %v", err)
	}
	for i := 0; i < 5; i++ {
		pkg := db.Package{PURL: "pkg:npm/p" + string(rune('a'+i)), Name: "p", Ecosystem: "npm"}
		if err := g.Create(&pkg).Error; err != nil {
			t.Fatalf("seed pkg: %v", err)
		}
		if err := g.Create(&db.PackageMaintainer{PackageID: pkg.ID, MaintainerID: m.ID}).Error; err != nil {
			t.Fatalf("seed join: %v", err)
		}
	}

	if err := recomputeCounts(context.Background(), g); err != nil {
		t.Fatalf("recompute: %v", err)
	}

	var refreshed db.Owner
	if err := g.First(&refreshed, owner.ID).Error; err != nil {
		t.Fatalf("read owner: %v", err)
	}
	if refreshed.LocalReposCount != 3 {
		t.Errorf("owner LocalReposCount = %d, want 3", refreshed.LocalReposCount)
	}
	if refreshed.RepositoriesCount != 999 {
		t.Errorf("owner RepositoriesCount (upstream) should be preserved, got %d", refreshed.RepositoriesCount)
	}

	var rm db.Maintainer
	if err := g.First(&rm, m.ID).Error; err != nil {
		t.Fatalf("read maintainer: %v", err)
	}
	if rm.LocalPackagesCount != 5 {
		t.Errorf("maintainer LocalPackagesCount = %d, want 5", rm.LocalPackagesCount)
	}
	if rm.PackagesCount != 999 {
		t.Errorf("maintainer PackagesCount (upstream) should be preserved, got %d", rm.PackagesCount)
	}
}
