package packages

import (
	"context"

	"gorm.io/gorm"

	"github.com/alpha-omega-security/marshal/internal/db"
)

// recomputeCounts wraps db.RecomputeLocalCounts + db.RecomputeLifecycle
// with a context-aware DB handle so we can cancel during long enrich runs.
// Order matters: counts first (so lifecycle sees fresh local_* fields if
// it ever depends on them; today it doesn't, but the path stays clean).
func recomputeCounts(ctx context.Context, g *gorm.DB) error {
	cg := g.WithContext(ctx)
	if err := db.RecomputeAdvisoryEffectiveness(cg); err != nil {
		return err
	}
	if err := db.RecomputeLocalCounts(cg); err != nil {
		return err
	}
	return db.RecomputeLifecycle(cg)
}
