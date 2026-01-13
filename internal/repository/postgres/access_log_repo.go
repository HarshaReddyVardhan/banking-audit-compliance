package postgres

import (
	"context"
	"fmt"

	"github.com/banking/audit-compliance/internal/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AccessLogRepository implements repository for access logs
type AccessLogRepository struct {
	pool *pgxpool.Pool
}

// NewAccessLogRepository creates a new access log repository
func NewAccessLogRepository(pool *pgxpool.Pool) *AccessLogRepository {
	return &AccessLogRepository{
		pool: pool,
	}
}

// LogAccess records who accessed the audit data
func (r *AccessLogRepository) LogAccess(ctx context.Context, entry *domain.AuditAccessLog) error {
	const query = `
		INSERT INTO access_logs (
			access_id, accessor_id, accessor_role, access_type, 
			query_filter, records_viewed, ip_address, timestamp, purpose
		) VALUES (
			$1, $2, $3, $4, 
			$5, $6, $7, $8, $9
		)
	`
	_, err := r.pool.Exec(ctx, query,
		entry.AccessID, entry.AccessorID, entry.AccessorRole, entry.AccessType,
		entry.QueryFilter, entry.RecordsViewed, entry.IPAddress, entry.Timestamp, entry.Purpose,
	)
	if err != nil {
		return fmt.Errorf("failed to insert access log: %w", err)
	}
	return nil
}
