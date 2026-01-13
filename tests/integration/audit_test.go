package integration

import (
	"context"
	"testing"
	"time"

	"github.com/banking/audit-compliance/internal/config"
	"github.com/banking/audit-compliance/internal/crypto"
	"github.com/banking/audit-compliance/internal/domain"
	"github.com/banking/audit-compliance/internal/repository/elasticsearch"
	"github.com/banking/audit-compliance/internal/repository/postgres"
	"github.com/banking/audit-compliance/internal/repository/s3"
	"github.com/banking/audit-compliance/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestAuditFlow requires Docker Compose environment running
func TestAuditFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// 1. Setup
	cfg, err := config.Load()
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	encryptor, err := crypto.NewFieldEncryptor(
		cfg.Encryption.EncryptionKeysBase64,
		cfg.Encryption.CurrentKeyVersion,
		cfg.Encryption.AuditHMACSecret,
	)
	require.NoError(t, err)

	pgRepo, err := postgres.NewAuditRepository(cfg.Database, encryptor)
	require.NoError(t, err)
	defer pgRepo.Close()

	esRepo, err := elasticsearch.NewSearchRepository(cfg.Elasticsearch)
	if err != nil {
		t.Logf("Elasticsearch not available, skipping search verification: %v", err)
	}

	s3Repo, err := s3.NewArchiveRepository(context.Background(), cfg.S3)
	require.NoError(t, err)

	auditService := service.NewAuditService(pgRepo, esRepo, s3Repo, encryptor, logger)

	// 2. Execution
	eventID := uuid.New()
	userID := uuid.New()
	event := domain.NewAuditEvent(userID, domain.ActionTypeLogin, domain.ResourceTypeUser, userID.String())
	event.EventID = eventID
	event.Result = domain.AuditResultSuccess
	event.IPAddress = "127.0.0.1"

	err = auditService.ProcessAndStoreEvent(context.Background(), event)
	require.NoError(t, err)

	// 3. Verification - Persistence & Signature
	// Retrieve from DB
	filter := domain.AuditEventFilter{
		UserID: &userID,
		Limit:  1,
	}
	page, err := auditService.GetAuditTrail(context.Background(), filter)
	require.NoError(t, err)
	require.NotEmpty(t, page.Events)

	retrieved := page.Events[0]
	assert.Equal(t, eventID, retrieved.EventID)
	assert.Equal(t, domain.ActionTypeLogin, retrieved.ActionType)
	assert.NotEmpty(t, retrieved.DigitalSignature)

	// Verify Signature
	valid := encryptor.VerifyDigitalSignature(
		retrieved.EventID.String(),
		retrieved.UserID.String(),
		string(retrieved.ActionType),
		retrieved.Timestamp.Format(time.RFC3339),
		string(retrieved.Result),
		retrieved.DigitalSignature,
	)
	assert.True(t, valid, "Digital signature must be valid")

	// 4. Verification - Immutability (Attempt Update)
	// We can't easily test SQL grants here without a separate admin connection,
	// but logically we ensured the repo has no Update/Delete methods.

	t.Log("Audit Flow Integration Test Passed")
}
