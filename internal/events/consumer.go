package events

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"github.com/banking/audit-compliance/internal/config"
	"github.com/banking/audit-compliance/internal/domain"
	"github.com/banking/audit-compliance/internal/service"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AuditConsumer struct {
	consumerGroup sarama.ConsumerGroup
	auditService  *service.AuditService
	topics        []string
	logger        *zap.Logger
}

func NewAuditConsumer(cfg config.KafkaConfig, auditService *service.AuditService, logger *zap.Logger) (*AuditConsumer, error) {
	config := sarama.NewConfig()
	config.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRoundRobin
	config.Consumer.Offsets.Initial = sarama.OffsetOldest
	config.Version = sarama.V2_8_0_0

	consumerGroup, err := sarama.NewConsumerGroup(cfg.Brokers, cfg.ConsumerGroup, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer group: %w", err)
	}

	topics := []string{cfg.AuditTopic, cfg.TransactionTopic, cfg.UserTopic, cfg.AlertTopic}

	return &AuditConsumer{
		consumerGroup: consumerGroup,
		auditService:  auditService,
		topics:        topics,
		logger:        logger,
	}, nil
}

func (c *AuditConsumer) Start(ctx context.Context) error {
	handler := &auditConsumerHandler{
		auditService: c.auditService,
		logger:       c.logger,
	}

	for {
		if err := c.consumerGroup.Consume(ctx, c.topics, handler); err != nil {
			if ctx.Err() != nil {
				return nil // Context canceled
			}
			c.logger.Error("Error from consumer", zap.Error(err))
			time.Sleep(time.Second * 5) // Retry backoff
		}
	}
}

func (c *AuditConsumer) Close() error {
	return c.consumerGroup.Close()
}

type auditConsumerHandler struct {
	auditService *service.AuditService
	logger       *zap.Logger
}

func (h *auditConsumerHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (h *auditConsumerHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }
func (h *auditConsumerHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for message := range claim.Messages() {
		h.processMessage(session.Context(), message)
		session.MarkMessage(message, "")
	}
	return nil
}

func (h *auditConsumerHandler) processMessage(ctx context.Context, msg *sarama.ConsumerMessage) {
	// Generic event structure to peek at fields
	var genericEvent map[string]interface{}
	if err := json.Unmarshal(msg.Value, &genericEvent); err != nil {
		h.logger.Error("Failed to unmarshal event", zap.Error(err))
		return // Skip malformed
	}

	// Transform to AuditDomain
	auditEvent := h.mapToAuditEvent(genericEvent, msg.Topic)

	// Retry mechanism for persistence
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		if err := h.auditService.ProcessAndStoreEvent(ctx, auditEvent); err != nil {
			h.logger.Error("Failed to process audit event",
				zap.String("topic", msg.Topic),
				zap.Error(err),
				zap.Int("retry", i+1),
			)
			if i < maxRetries-1 {
				time.Sleep(time.Duration(i+1) * time.Second) // Simple backoff
				continue
			}
			// If we exhausted retries, log failure and potentially move to DLQ (future)
			h.logger.Error("Dropping event after retries", zap.String("event_id", auditEvent.EventID.String()))
		}
		break // Success
	}
}

// mapToAuditEvent transforms various event formats into a standardized AuditEvent
func (h *auditConsumerHandler) mapToAuditEvent(raw map[string]interface{}, topic string) *domain.AuditEvent {
	// Defaults
	event := domain.NewAuditEvent(uuid.Nil, domain.ActionType("UNKNOWN"), domain.ResourceType("UNKNOWN"), "0")
	event.ServiceSource = topic // Proxy for service name for now

	// Extract standard fields if they exist
	if idStr, ok := raw["event_id"].(string); ok {
		if uid, err := uuid.Parse(idStr); err == nil {
			event.EventID = uid
		}
	}

	if typeStr, ok := raw["event_type"].(string); ok {
		// Map detailed event type to generic ActionType if possible, or just store it
		// For now, we use the raw string or map common ones
		event.ActionType = domain.ActionType(typeStr) // Dynamic casting
	}

	if userIDStr, ok := raw["user_id"].(string); ok {
		if uid, err := uuid.Parse(userIDStr); err == nil {
			event.UserID = uid
		}
	}

	// Payload handling
	// Store the entire raw event as Metadata JSON
	if metaBytes, err := json.Marshal(raw); err == nil {
		event.Metadata = metaBytes
	}

	return event
}
