package service

import (
	"context"
	"fmt"
	"time"

	"github.com/banking/audit-compliance/internal/crypto"
	"github.com/banking/audit-compliance/internal/domain"
	"github.com/banking/audit-compliance/internal/repository/elasticsearch"
	"github.com/banking/audit-compliance/internal/repository/postgres"
	"github.com/banking/audit-compliance/internal/repository/s3"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AuditService struct {
	pgRepo    *postgres.AuditRepository
	esRepo    *elasticsearch.SearchRepository
	s3Repo    *s3.ArchiveRepository
	encryptor *crypto.FieldEncryptor
	logger    *zap.Logger
}

func NewAuditService(
	pgRepo *postgres.AuditRepository,
	esRepo *elasticsearch.SearchRepository,
	s3Repo *s3.ArchiveRepository,
	encryptor *crypto.FieldEncryptor,
	logger *zap.Logger,
) *AuditService {
	return &AuditService{
		pgRepo:    pgRepo,
		esRepo:    esRepo,
		s3Repo:    s3Repo,
		encryptor: encryptor,
		logger:    logger,
	}
}

// ProcessAndStoreEvent is the main entry point for ingesting audit events
func (s *AuditService) ProcessAndStoreEvent(ctx context.Context, event *domain.AuditEvent) error {
	// 1. Ensure IDs and Timestamps
	if event.EventID == uuid.Nil {
		event.EventID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = event.CreatedAt
	}

	// 2. Cryptographic Signing
	// Sign critical fields to ensure non-repudiation
	sig := s.encryptor.GenerateDigitalSignature(
		event.EventID.String(),
		event.UserID.String(),
		string(event.ActionType),
		event.Timestamp.Format(time.RFC3339),
		string(event.Result),
	)
	event.DigitalSignature = sig
	event.EncryptionKeyID = s.encryptor.CurrentKeyVersion()

	// 3. Store in Immutable Ledger (PostgreSQL) - Critical Path
	// This must succeed. If this fails, we cannot proceed.
	if err := s.pgRepo.CreateEvent(ctx, event); err != nil {
		s.logger.Error("Failed to persist audit event to ledger",
			zap.String("event_id", event.EventID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("ledger persistence failed: %w", err)
	}

	// 4. Index in Elasticsearch (Async/Best Effort)
	// We don't want to fail the whole process if search indexing fails temporarily
	s.asyncIndexEvent(event)

	// 5. Archival (Async - usually batch, but here maybe per event for simplicity or queue)
	// For high throughput, we wouldn't upload every single event to S3 individually.
	// We would assume an external worker does batching or we rely on the DB/Kafka retention.
	// However, for critical events, we might want immediate backup.
	// Leaving this as a placeholder or specific high-value event logic.

	return nil
}

// asyncIndexEvent handles background indexing with panic protection
func (s *AuditService) asyncIndexEvent(event *domain.AuditEvent) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Error("Panic in async index event", zap.Any("panic", r))
			}
		}()

		// Use a detached context for async operations
		asyncCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.esRepo.IndexEvent(asyncCtx, event); err != nil {
			s.logger.Error("Failed to index audit event",
				zap.String("event_id", event.EventID.String()),
				zap.Error(err),
			)
			// TODO: Push to a dead-letter queue or retry table
		}
	}()
}

// GetAuditTrail retrieves the full history for a transaction or entity
func (s *AuditService) GetAuditTrail(ctx context.Context, filter domain.AuditEventFilter) (*domain.AuditEventPage, error) {
	// 1. Try to search in Elasticsearch for performance if it's a complex query
	// Ideally, recent/simple queries go to DB, text search/aggregations go to ES.
	// For now, let's route essentially everything to DB for strong consistency assurance
	// unless it's a full-text search scenario which isn't strictly defined in filter yet.
	// Actually, the requirement says "Fast search", so let's default to DB for now for simplicity of "Get"
	// and use ES for "Search".

	// Direct DB access for Audit Trail to ensure we see the immutable truth
	page, err := s.pgRepo.GetEvents(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Verify signatures for the retrieved events (On-the-fly verification)
	for _, event := range page.Events {
		valid := s.encryptor.VerifyDigitalSignature(
			event.EventID.String(),
			event.UserID.String(),
			string(event.ActionType),
			event.Timestamp.Format(time.RFC3339),
			string(event.Result),
			event.DigitalSignature,
		)
		if !valid {
			s.logger.Error("CRYPTOGRAPHIC VALIDATION FAILURE",
				zap.String("event_id", event.EventID.String()),
				zap.String("reason", "Signature mismatch - POTENTIAL TAMPERING DETECTED"),
			)
			// In production, this might trigger a massive alert or panic the service
			// For now, we log Error instead of Fatal so the service kept running
			return nil, fmt.Errorf("audit integrity failure: event %s signature invalid", event.EventID)
		}
	}

	return page, nil
}

// SearchEvents uses Elasticsearch for broader queries
func (s *AuditService) SearchEvents(ctx context.Context, query string, from, size int) (*domain.AuditEventPage, error) {
	return s.esRepo.SearchEvents(ctx, query, from, size)
}

// VerifyEventIntegrity allows manual verification of a specific event
func (s *AuditService) VerifyEventIntegrity(ctx context.Context, eventID string) (bool, error) {
	uuidVal, err := uuid.Parse(eventID)
	if err != nil {
		return false, fmt.Errorf("invalid event ID: %w", err)
	}

	filter := domain.AuditEventFilter{
		EventID: &uuidVal,
		Limit:   1,
	}

	page, err := s.GetAuditTrail(ctx, filter)
	if err != nil {
		return false, err
	}

	if len(page.Events) == 0 {
		return false, fmt.Errorf("event not found")
	}

	// GetAuditTrail already verifies signature
	return true, nil
}
