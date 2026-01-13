package domain

import (
	"time"

	"github.com/google/uuid"
)

// KYCVerificationType represents types of KYC verification
type KYCVerificationType string

const (
	KYCTypeIDCheck      KYCVerificationType = "ID_CHECK"
	KYCTypeAddressCheck KYCVerificationType = "ADDRESS_CHECK"
	KYCTypePEPCheck     KYCVerificationType = "PEP_CHECK"
	KYCTypeOFACCheck    KYCVerificationType = "OFAC_CHECK"
	KYCTypeEDDInterview KYCVerificationType = "EDD_INTERVIEW"
	KYCTypeDocumentScan KYCVerificationType = "DOCUMENT_SCAN"
	KYCTypeBiometric    KYCVerificationType = "BIOMETRIC"
)

// KYCVerificationStatus represents the status of a KYC verification
type KYCVerificationStatus string

const (
	KYCStatusPending      KYCVerificationStatus = "PENDING"
	KYCStatusVerified     KYCVerificationStatus = "VERIFIED"
	KYCStatusFailed       KYCVerificationStatus = "FAILED"
	KYCStatusExpired      KYCVerificationStatus = "EXPIRED"
	KYCStatusManualReview KYCVerificationStatus = "MANUAL_REVIEW"
)

// CustomerRiskLevel represents the risk classification of a customer
type CustomerRiskLevel string

const (
	RiskLevelLow    CustomerRiskLevel = "LOW"
	RiskLevelMedium CustomerRiskLevel = "MEDIUM"
	RiskLevelHigh   CustomerRiskLevel = "HIGH"
)

// KYCVerification represents a single KYC verification record
type KYCVerification struct {
	VerificationID   uuid.UUID             `json:"verification_id" db:"verification_id"`
	UserID           uuid.UUID             `json:"user_id" db:"user_id"`
	VerificationType KYCVerificationType   `json:"verification_type" db:"verification_type"`
	Status           KYCVerificationStatus `json:"status" db:"status"`
	VerifiedBy       *uuid.UUID            `json:"verified_by,omitempty" db:"verified_by"`
	VerifiedByName   *string               `json:"verified_by_name,omitempty" db:"verified_by_name"`
	VerificationDate *time.Time            `json:"verification_date,omitempty" db:"verification_date"`
	ExpirationDate   *time.Time            `json:"expiration_date,omitempty" db:"expiration_date"`
	DocumentRef      *string               `json:"document_ref,omitempty" db:"document_ref"` // S3 path
	DocumentHash     *string               `json:"-" db:"document_hash"`                     // For integrity verification
	Notes            *string               `json:"notes,omitempty" db:"notes"`
	FailureReason    *string               `json:"failure_reason,omitempty" db:"failure_reason"`
	RiskScore        int                   `json:"risk_score" db:"risk_score"` // 0-100
	SourceSystem     string                `json:"source_system" db:"source_system"`
	ExternalRef      *string               `json:"external_ref,omitempty" db:"external_ref"` // Third-party verification ID
	CreatedAt        time.Time             `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time             `json:"updated_at" db:"updated_at"`
}

// IsValid returns true if the verification is currently valid
func (k *KYCVerification) IsValid() bool {
	if k.Status != KYCStatusVerified {
		return false
	}
	if k.ExpirationDate != nil && time.Now().After(*k.ExpirationDate) {
		return false
	}
	return true
}

// CustomerKYCProfile represents the complete KYC profile for a customer
type CustomerKYCProfile struct {
	UserID             uuid.UUID             `json:"user_id" db:"user_id"`
	RiskLevel          CustomerRiskLevel     `json:"risk_level" db:"risk_level"`
	OverallStatus      KYCVerificationStatus `json:"overall_status" db:"overall_status"`
	Verifications      []*KYCVerification    `json:"verifications" db:"-"`
	DailyLimit         int64                 `json:"daily_limit" db:"daily_limit"`             // In cents
	TransactionLimit   int64                 `json:"transaction_limit" db:"transaction_limit"` // Single transaction limit
	RequiresReview     bool                  `json:"requires_review" db:"requires_review"`
	NextReviewDate     *time.Time            `json:"next_review_date,omitempty" db:"next_review_date"`
	IsPEP              bool                  `json:"is_pep" db:"is_pep"` // Politically Exposed Person
	IsOnWatchlist      bool                  `json:"is_on_watchlist" db:"is_on_watchlist"`
	WatchlistMatches   []string              `json:"watchlist_matches,omitempty" db:"watchlist_matches"`
	CountryOfResidence string                `json:"country_of_residence" db:"country_of_residence"`
	Citizenship        string                `json:"citizenship" db:"citizenship"`
	EmploymentStatus   string                `json:"employment_status" db:"employment_status"`
	SourceOfFunds      string                `json:"source_of_funds" db:"source_of_funds"`
	CreatedAt          time.Time             `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time             `json:"updated_at" db:"updated_at"`
}

// GetDailyLimitByRisk returns the daily limit based on risk level
func GetDailyLimitByRisk(level CustomerRiskLevel) int64 {
	limits := map[CustomerRiskLevel]int64{
		RiskLevelLow:    1000000,  // $10,000 in cents
		RiskLevelMedium: 5000000,  // $50,000 in cents
		RiskLevelHigh:   10000000, // Custom/restricted - $100,000 default
	}
	return limits[level]
}

// KYCReviewRequest represents a request for KYC review (periodic or triggered)
type KYCReviewRequest struct {
	ReviewID          uuid.UUID          `json:"review_id" db:"review_id"`
	UserID            uuid.UUID          `json:"user_id" db:"user_id"`
	ReviewType        string             `json:"review_type" db:"review_type"` // PERIODIC, TRIGGERED, ESCALATION
	TriggerReason     string             `json:"trigger_reason" db:"trigger_reason"`
	AssignedTo        *uuid.UUID         `json:"assigned_to,omitempty" db:"assigned_to"`
	Status            string             `json:"status" db:"status"`     // PENDING, IN_PROGRESS, COMPLETED, ESCALATED
	Priority          string             `json:"priority" db:"priority"` // LOW, MEDIUM, HIGH, CRITICAL
	DueDate           time.Time          `json:"due_date" db:"due_date"`
	CompletedAt       *time.Time         `json:"completed_at,omitempty" db:"completed_at"`
	Findings          *string            `json:"findings,omitempty" db:"findings"`
	Recommendation    *string            `json:"recommendation,omitempty" db:"recommendation"`
	PreviousRiskLevel CustomerRiskLevel  `json:"previous_risk_level" db:"previous_risk_level"`
	NewRiskLevel      *CustomerRiskLevel `json:"new_risk_level,omitempty" db:"new_risk_level"`
	CreatedAt         time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at" db:"updated_at"`
}

// KYCDocument represents a document uploaded for KYC verification
type KYCDocument struct {
	DocumentID     uuid.UUID `json:"document_id" db:"document_id"`
	UserID         uuid.UUID `json:"user_id" db:"user_id"`
	VerificationID uuid.UUID `json:"verification_id" db:"verification_id"`
	DocumentType   string    `json:"document_type" db:"document_type"` // PASSPORT, DRIVERS_LICENSE, UTILITY_BILL, etc.
	FileName       string    `json:"file_name" db:"file_name"`
	S3Path         string    `json:"-" db:"s3_path"`
	ContentType    string    `json:"content_type" db:"content_type"`
	FileSize       int64     `json:"file_size" db:"file_size"`
	Hash           string    `json:"-" db:"hash"` // SHA-256 for integrity
	EncryptionKey  string    `json:"-" db:"encryption_key"`
	UploadedAt     time.Time `json:"uploaded_at" db:"uploaded_at"`
	ExpiresAt      time.Time `json:"expires_at" db:"expires_at"` // Based on retention policy
	IsArchived     bool      `json:"is_archived" db:"is_archived"`
}

// Red flags for triggering KYC re-verification
var KYCRedFlags = []string{
	"MULTIPLE_FAILED_LOGINS_NEW_LOCATION",
	"TRANSACTION_VELOCITY_SPIKE",
	"TRANSFERS_TO_UNKNOWN_RECIPIENTS",
	"ADDRESS_CHANGE",
	"PHONE_CHANGE",
	"EMPLOYMENT_STATUS_CHANGE",
	"HIGH_RISK_COUNTRY_TRANSFER",
	"LARGE_CASH_EQUIVALENT",
	"SUSPECTED_STRUCTURING",
	"BEHAVIOR_ANOMALY",
}

// KYCCheckResult represents the result of a KYC check
type KYCCheckResult struct {
	UserID      uuid.UUID         `json:"user_id"`
	Passed      bool              `json:"passed"`
	RiskLevel   CustomerRiskLevel `json:"risk_level"`
	RiskScore   int               `json:"risk_score"`
	Flags       []string          `json:"flags,omitempty"`
	RequiresEDD bool              `json:"requires_edd"` // Enhanced Due Diligence
	BlockReason *string           `json:"block_reason,omitempty"`
	CheckedAt   time.Time         `json:"checked_at"`
}
