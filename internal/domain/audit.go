package domain

import (
	"time"

	"github.com/google/uuid"
)

// ActionType represents the type of action being audited
type ActionType string

const (
	ActionTypeCreate      ActionType = "CREATE"
	ActionTypeRead        ActionType = "READ"
	ActionTypeUpdate      ActionType = "UPDATE"
	ActionTypeDelete      ActionType = "DELETE"
	ActionTypeLogin       ActionType = "LOGIN"
	ActionTypeLogout      ActionType = "LOGOUT"
	ActionTypeTransfer    ActionType = "TRANSFER"
	ActionTypeApprove     ActionType = "APPROVE"
	ActionTypeReject      ActionType = "REJECT"
	ActionTypeFreeze      ActionType = "FREEZE"
	ActionTypeUnfreeze    ActionType = "UNFREEZE"
	ActionTypeExport      ActionType = "EXPORT"
	ActionTypeConsent     ActionType = "CONSENT"
	ActionTypeRevoke      ActionType = "REVOKE"
	ActionTypeEscalate    ActionType = "ESCALATE"
	ActionTypeInvestigate ActionType = "INVESTIGATE"
)

// ResourceType represents the type of resource being accessed
type ResourceType string

const (
	ResourceTypeAccount     ResourceType = "ACCOUNT"
	ResourceTypeUser        ResourceType = "USER"
	ResourceTypeTransfer    ResourceType = "TRANSFER"
	ResourceTypeTransaction ResourceType = "TRANSACTION"
	ResourceTypeKYC         ResourceType = "KYC"
	ResourceTypeAMLFlag     ResourceType = "AML_FLAG"
	ResourceTypeReport      ResourceType = "REPORT"
	ResourceTypeConsent     ResourceType = "CONSENT"
	ResourceTypeSession     ResourceType = "SESSION"
	ResourceTypeDevice      ResourceType = "DEVICE"
	ResourceTypeAddress     ResourceType = "ADDRESS"
	ResourceTypeDocument    ResourceType = "DOCUMENT"
)

// AuditResult represents the result of an audited action
type AuditResult string

const (
	AuditResultSuccess AuditResult = "SUCCESS"
	AuditResultFailure AuditResult = "FAILURE"
	AuditResultPending AuditResult = "PENDING"
	AuditResultDenied  AuditResult = "DENIED"
)

// AuditEvent represents an immutable audit log entry
// This record can NEVER be modified or deleted - core regulatory requirement
type AuditEvent struct {
	EventID           uuid.UUID    `json:"event_id" db:"event_id"`
	TransactionID     *uuid.UUID   `json:"transaction_id,omitempty" db:"transaction_id"`
	UserID            uuid.UUID    `json:"user_id" db:"user_id"`
	ActorID           *uuid.UUID   `json:"actor_id,omitempty" db:"actor_id"` // System/Admin who performed action
	ActionType        ActionType   `json:"action_type" db:"action_type"`
	ResourceType      ResourceType `json:"resource_type" db:"resource_type"`
	ResourceID        string       `json:"resource_id" db:"resource_id"`
	ServiceSource     string       `json:"service_source" db:"service_source"`
	Timestamp         time.Time    `json:"timestamp" db:"timestamp"`
	Result            AuditResult  `json:"result" db:"result"`
	FailureReason     *string      `json:"failure_reason,omitempty" db:"failure_reason"`
	IPAddress         string       `json:"ip_address" db:"ip_address"`
	Geolocation       *string      `json:"geolocation,omitempty" db:"geolocation"`
	UserAgent         *string      `json:"user_agent,omitempty" db:"user_agent"`
	RequestID         string       `json:"request_id" db:"request_id"`
	SessionID         *string      `json:"session_id,omitempty" db:"session_id"`
	DigitalSignature  string       `json:"digital_signature" db:"digital_signature"` // HMAC signature for non-repudiation
	Metadata          []byte       `json:"metadata,omitempty" db:"metadata"`         // JSON blob for additional context
	DataBefore        []byte       `json:"-" db:"data_before"`                       // Encrypted state before change
	DataAfter         []byte       `json:"-" db:"data_after"`                        // Encrypted state after change
	ComplianceFlags   []string     `json:"compliance_flags,omitempty" db:"compliance_flags"`
	RetentionCategory string       `json:"retention_category" db:"retention_category"`
	EncryptionKeyID   int          `json:"-" db:"encryption_key_id"`
	CreatedAt         time.Time    `json:"created_at" db:"created_at"`
}

// NewAuditEvent creates a new audit event with auto-generated ID and timestamp
func NewAuditEvent(userID uuid.UUID, action ActionType, resource ResourceType, resourceID string) *AuditEvent {
	return &AuditEvent{
		EventID:           uuid.New(),
		UserID:            userID,
		ActionType:        action,
		ResourceType:      resource,
		ResourceID:        resourceID,
		Timestamp:         time.Now().UTC(),
		Result:            AuditResultPending,
		RetentionCategory: "STANDARD", // 7 years default
		CreatedAt:         time.Now().UTC(),
	}
}

// AuditEventFilter for querying audit logs
type AuditEventFilter struct {
	EventID       *uuid.UUID
	UserID        *uuid.UUID
	TransactionID *uuid.UUID
	ActionTypes   []ActionType
	ResourceTypes []ResourceType
	ResourceID    *string
	StartTime     *time.Time
	EndTime       *time.Time
	Result        *AuditResult
	ServiceSource *string
	IPAddress     *string
	Limit         int
	Offset        int
}

// AuditEventPage represents paginated audit events
type AuditEventPage struct {
	Events     []*AuditEvent `json:"events"`
	TotalCount int64         `json:"total_count"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
	HasMore    bool          `json:"has_more"`
}

// RetentionPolicy defines data retention rules
type RetentionPolicy struct {
	Category        string        `json:"category" db:"category"`
	RetentionPeriod time.Duration `json:"retention_period" db:"retention_period"`
	Description     string        `json:"description" db:"description"`
	Regulation      string        `json:"regulation" db:"regulation"`       // SOX, GDPR, etc.
	DeleteAction    string        `json:"delete_action" db:"delete_action"` // ARCHIVE, ANONYMIZE, DELETE
	IsActive        bool          `json:"is_active" db:"is_active"`
	CreatedAt       time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at" db:"updated_at"`
}

// Standard retention policies based on regulation requirements
var StandardRetentionPolicies = map[string]RetentionPolicy{
	"TRANSACTION": {
		Category:        "TRANSACTION",
		RetentionPeriod: 7 * 365 * 24 * time.Hour, // 7 years
		Description:     "Transaction records for SOX compliance",
		Regulation:      "SOX",
		DeleteAction:    "ARCHIVE",
		IsActive:        true,
	},
	"KYC_VERIFICATION": {
		Category:        "KYC_VERIFICATION",
		RetentionPeriod: 7 * 365 * 24 * time.Hour, // 7 years after account closure
		Description:     "KYC documents for AML compliance",
		Regulation:      "AML/KYC",
		DeleteAction:    "ARCHIVE",
		IsActive:        true,
	},
	"LOGIN_EVENTS": {
		Category:        "LOGIN_EVENTS",
		RetentionPeriod: 365 * 24 * time.Hour, // 1 year
		Description:     "Login/session events for fraud investigation",
		Regulation:      "SECURITY",
		DeleteAction:    "DELETE",
		IsActive:        true,
	},
	"COMPLIANCE_REPORTS": {
		Category:        "COMPLIANCE_REPORTS",
		RetentionPeriod: 10 * 365 * 24 * time.Hour, // 10 years
		Description:     "Filed compliance reports",
		Regulation:      "BSA",
		DeleteAction:    "ARCHIVE",
		IsActive:        true,
	},
	"DELETED_USER_DATA": {
		Category:        "DELETED_USER_DATA",
		RetentionPeriod: 30 * 24 * time.Hour, // 30 days grace period
		Description:     "GDPR right to be forgotten grace period",
		Regulation:      "GDPR",
		DeleteAction:    "DELETE",
		IsActive:        true,
	},
}

// AuditAccessLog tracks who accessed audit logs (audit of audits)
type AuditAccessLog struct {
	AccessID      uuid.UUID `json:"access_id" db:"access_id"`
	AccessorID    uuid.UUID `json:"accessor_id" db:"accessor_id"`
	AccessorRole  string    `json:"accessor_role" db:"accessor_role"`
	AccessType    string    `json:"access_type" db:"access_type"` // VIEW, EXPORT, SEARCH
	QueryFilter   string    `json:"query_filter" db:"query_filter"`
	RecordsViewed int       `json:"records_viewed" db:"records_viewed"`
	IPAddress     string    `json:"ip_address" db:"ip_address"`
	Timestamp     time.Time `json:"timestamp" db:"timestamp"`
	Purpose       string    `json:"purpose" db:"purpose"`
}
