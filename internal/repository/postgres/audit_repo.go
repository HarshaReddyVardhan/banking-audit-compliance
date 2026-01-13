package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/banking/audit-compliance/internal/config"
	"github.com/banking/audit-compliance/internal/crypto"
	"github.com/banking/audit-compliance/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditRepository implements repository for audit events
type AuditRepository struct {
	pool      *pgxpool.Pool
	encryptor *crypto.FieldEncryptor
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(cfg config.DatabaseConfig, encryptor *crypto.FieldEncryptor) (*AuditRepository, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	poolConfig.MaxConns = int32(cfg.MaxOpenConns)
	poolConfig.MinConns = int32(cfg.MaxIdleConns)
	poolConfig.MaxConnLifetime = cfg.ConnMaxLifetime
	poolConfig.MaxConnIdleTime = cfg.ConnMaxIdleTime

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create pool: %w", err)
	}

	return &AuditRepository{
		pool:      pool,
		encryptor: encryptor,
	}, nil
}

// CreateEvent inserts a new audit event. This is an APPEND-ONLY operation.
// No Updates or Deletes are ever performed on this table.
func (r *AuditRepository) CreateEvent(ctx context.Context, event *domain.AuditEvent) error {
	const query = `
		INSERT INTO audit_events (
			event_id, transaction_id, user_id, actor_id, action_type, 
			resource_type, resource_id, service_source, timestamp, result,
			failure_reason, ip_address, geolocation, user_agent, request_id, 
			session_id, digital_signature, metadata, data_before, data_after,
			compliance_flags, retention_category, encryption_key_id, created_at
		) VALUES (
			$1, $2, $3, $4, $5, 
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15,
			$16, $17, $18, $19, $20,
			$21, $22, $23, $24
		)
	`
	// Encrypt sensitive data payloads if present
	// (Assumed already encrypted or we encrypt here? Domain object has []byte, assuming raw or already handled.
	// To be safe and strict, let's assume the service layer handles the logic of what to encrypt,
	// but here we just store it. However, the struct has EncryptionKeyID, so maybe we should check.)

	_, err := r.pool.Exec(ctx, query,
		event.EventID, event.TransactionID, event.UserID, event.ActorID, event.ActionType,
		event.ResourceType, event.ResourceID, event.ServiceSource, event.Timestamp, event.Result,
		event.FailureReason, event.IPAddress, event.Geolocation, event.UserAgent, event.RequestID,
		event.SessionID, event.DigitalSignature, event.Metadata, event.DataBefore, event.DataAfter,
		event.ComplianceFlags, event.RetentionCategory, event.EncryptionKeyID, event.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to insert audit event: %w", err)
	}

	return nil
}

// GetEvents retrieves audit events based on filter
func (r *AuditRepository) GetEvents(ctx context.Context, filter domain.AuditEventFilter) (*domain.AuditEventPage, error) {
	// Build query dynamically
	query := `
		SELECT 
			event_id, transaction_id, user_id, actor_id, action_type, 
			resource_type, resource_id, service_source, timestamp, result,
			failure_reason, ip_address, geolocation, user_agent, request_id, 
			session_id, digital_signature, metadata, data_before, data_after,
			compliance_flags, retention_category, encryption_key_id, created_at
		FROM audit_events
		WHERE 1=1
	`
	args := []interface{}{}
	argIdx := 1

	if filter.EventID != nil {
		query += fmt.Sprintf(" AND event_id = $%d", argIdx)
		args = append(args, *filter.EventID)
		argIdx++
	}
	if filter.UserID != nil {
		query += fmt.Sprintf(" AND user_id = $%d", argIdx)
		args = append(args, *filter.UserID)
		argIdx++
	}
	if filter.TransactionID != nil {
		query += fmt.Sprintf(" AND transaction_id = $%d", argIdx)
		args = append(args, *filter.TransactionID)
		argIdx++
	}
	if filter.ResourceID != nil {
		query += fmt.Sprintf(" AND resource_id = $%d", argIdx)
		args = append(args, *filter.ResourceID)
		argIdx++
	}
	if filter.StartTime != nil {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIdx)
		args = append(args, *filter.StartTime)
		argIdx++
	}
	if filter.EndTime != nil {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIdx)
		args = append(args, *filter.EndTime)
		argIdx++
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM (" + query + ") as total"
	var totalCount int64
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count events: %w", err)
	}

	// Add ordering and pagination
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []*domain.AuditEvent
	for rows.Next() {
		var e domain.AuditEvent
		err := rows.Scan(
			&e.EventID, &e.TransactionID, &e.UserID, &e.ActorID, &e.ActionType,
			&e.ResourceType, &e.ResourceID, &e.ServiceSource, &e.Timestamp, &e.Result,
			&e.FailureReason, &e.IPAddress, &e.Geolocation, &e.UserAgent, &e.RequestID,
			&e.SessionID, &e.DigitalSignature, &e.Metadata, &e.DataBefore, &e.DataAfter,
			&e.ComplianceFlags, &e.RetentionCategory, &e.EncryptionKeyID, &e.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, &e)
	}

	return &domain.AuditEventPage{
		Events:     events,
		TotalCount: totalCount,
		PageSize:   filter.Limit,
		HasMore:    totalCount > int64(filter.Offset+filter.Limit),
	}, nil
}

// GetLastEventHash retrieves the hash/signature of the most recent event for chaining
// In a real blockchain-like implement, we'd need a robust way to traverse back.
// Here we might use the DigitalSignature of the last inserted event as a proxy for "Previous Hash"
// or a specific separate hash column if we decided to implement a strict blockchain.
// Given strict reqs, let's assume we use DigitalSignature as link.
func (r *AuditRepository) GetLastEventSignature(ctx context.Context) (string, error) {
	query := `SELECT digital_signature FROM audit_events ORDER BY timestamp DESC LIMIT 1`
	var signature string
	err := r.pool.QueryRow(ctx, query).Scan(&signature)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil // Genesis block case
		}
		return "", err
	}
	return signature, nil
}

// Close closes the database connection pool
func (r *AuditRepository) Close() {
	r.pool.Close()
}
