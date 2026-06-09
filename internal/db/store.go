package db

import (
	"fmt"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Open(path string) (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
	g, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if err := g.AutoMigrate(&Package{}, &Repository{}, &Import{}, &PackageImport{}, &Owner{}, &Maintainer{}, &PackageMaintainer{}, &Advisory{}, &PackageAdvisory{}, &SavedFilter{}); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return g, nil
}
