package domain

import (
	"time"

	"github.com/google/uuid"
)

// ConsentType represents the type of user consent
type ConsentType string

const (
	ConsentTypeMarketingEmail ConsentType = "MARKETING_EMAIL"
	ConsentTypeSMS            ConsentType = "SMS"
	ConsentTypePush           ConsentType = "PUSH_NOTIFICATION"
	ConsentTypeProfiling      ConsentType = "PROFILING"
	ConsentTypeDataSharing    ConsentType = "DATA_SHARING"
	ConsentTypeCookies        ConsentType = "COOKIES"
	ConsentTypeAnalytics      ConsentType = "ANALYTICS"
	ConsentTypeThirdParty     ConsentType = "THIRD_PARTY"
)

// ConsentSource represents where consent was given
type ConsentSource string

const (
	ConsentSourceWeb        ConsentSource = "WEB"
	ConsentSourceMobile     ConsentSource = "MOBILE"
	ConsentSourceCallCenter ConsentSource = "CALL_CENTER"
	ConsentSourceBranch     ConsentSource = "BRANCH"
	ConsentSourceAPI        ConsentSource = "API"
)

// UserConsent represents a consent record
type UserConsent struct {
	ConsentID   uuid.UUID     `json:"consent_id" db:"consent_id"`
	UserID      uuid.UUID     `json:"user_id" db:"user_id"`
	ConsentType ConsentType   `json:"consent_type" db:"consent_type"`
	IsGranted   bool          `json:"is_granted" db:"is_granted"`
	Version     string        `json:"version" db:"version"` // Consent policy version
	GrantedAt   *time.Time    `json:"granted_at,omitempty" db:"granted_at"`
	RevokedAt   *time.Time    `json:"revoked_at,omitempty" db:"revoked_at"`
	ExpiresAt   *time.Time    `json:"expires_at,omitempty" db:"expires_at"`
	Source      ConsentSource `json:"source" db:"source"`
	IPAddress   string        `json:"ip_address" db:"ip_address"`
	UserAgent   *string       `json:"user_agent,omitempty" db:"user_agent"`
	ConsentText string        `json:"-" db:"consent_text"` // Exact text user agreed to
	ConsentHash string        `json:"-" db:"consent_hash"` // Hash for integrity
	CreatedAt   time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at" db:"updated_at"`
}

// IsActive returns true if consent is currently active
func (c *UserConsent) IsActive() bool {
	if !c.IsGranted || c.RevokedAt != nil {
		return false
	}
	if c.ExpiresAt != nil && time.Now().After(*c.ExpiresAt) {
		return false
	}
	return true
}

// GDPRRequestType represents type of GDPR request
type GDPRRequestType string

const (
	GDPRRequestAccess        GDPRRequestType = "ACCESS"        // Right to access
	GDPRRequestErasure       GDPRRequestType = "ERASURE"       // Right to be forgotten
	GDPRRequestPortability   GDPRRequestType = "PORTABILITY"   // Right to data portability
	GDPRRequestRectification GDPRRequestType = "RECTIFICATION" // Right to rectify
	GDPRRequestRestriction   GDPRRequestType = "RESTRICTION"   // Right to restrict processing
	GDPRRequestObjection     GDPRRequestType = "OBJECTION"     // Right to object
)

// GDPRRequestStatus represents the status of a GDPR request
type GDPRRequestStatus string

const (
	GDPRStatusPending     GDPRRequestStatus = "PENDING"
	GDPRStatusInProgress  GDPRRequestStatus = "IN_PROGRESS"
	GDPRStatusGracePeriod GDPRRequestStatus = "GRACE_PERIOD" // For erasure
	GDPRStatusCompleted   GDPRRequestStatus = "COMPLETED"
	GDPRStatusRejected    GDPRRequestStatus = "REJECTED" // Invalid request
	GDPRStatusExpired     GDPRRequestStatus = "EXPIRED"
)

// GDPRRequest represents a GDPR data subject request
type GDPRRequest struct {
	RequestID        uuid.UUID         `json:"request_id" db:"request_id"`
	UserID           uuid.UUID         `json:"user_id" db:"user_id"`
	RequestType      GDPRRequestType   `json:"request_type" db:"request_type"`
	Status           GDPRRequestStatus `json:"status" db:"status"`
	RequestedAt      time.Time         `json:"requested_at" db:"requested_at"`
	Deadline         time.Time         `json:"deadline" db:"deadline"` // 30 days from request
	IdentityVerified bool              `json:"identity_verified" db:"identity_verified"`
	VerifiedAt       *time.Time        `json:"verified_at,omitempty" db:"verified_at"`
	VerifiedBy       *uuid.UUID        `json:"verified_by,omitempty" db:"verified_by"`
	ProcessedBy      *uuid.UUID        `json:"processed_by,omitempty" db:"processed_by"`
	ProcessedAt      *time.Time        `json:"processed_at,omitempty" db:"processed_at"`
	CompletedAt      *time.Time        `json:"completed_at,omitempty" db:"completed_at"`
	GracePeriodEnd   *time.Time        `json:"grace_period_end,omitempty" db:"grace_period_end"` // For erasure
	ResponseS3Path   *string           `json:"-" db:"response_s3_path"`                          // Path to generated data export
	RejectionReason  *string           `json:"rejection_reason,omitempty" db:"rejection_reason"`
	Notes            *string           `json:"notes,omitempty" db:"notes"`
	SourceChannel    ConsentSource     `json:"source_channel" db:"source_channel"`
	IPAddress        string            `json:"ip_address" db:"ip_address"`
	CreatedAt        time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at" db:"updated_at"`
}

// DataExport represents an exported user data package
type DataExport struct {
	ExportID       uuid.UUID  `json:"export_id" db:"export_id"`
	UserID         uuid.UUID  `json:"user_id" db:"user_id"`
	RequestID      uuid.UUID  `json:"request_id" db:"request_id"`
	Format         string     `json:"format" db:"format"` // JSON, CSV, ZIP
	S3Path         string     `json:"-" db:"s3_path"`
	SizeBytes      int64      `json:"size_bytes" db:"size_bytes"`
	Hash           string     `json:"-" db:"hash"` // SHA-256
	EncryptionKey  string     `json:"-" db:"encryption_key"`
	GeneratedAt    time.Time  `json:"generated_at" db:"generated_at"`
	ExpiresAt      time.Time  `json:"expires_at" db:"expires_at"` // Auto-delete after expiry
	DownloadCount  int        `json:"download_count" db:"download_count"`
	LastDownloadAt *time.Time `json:"last_download_at,omitempty" db:"last_download_at"`
}

// DataAnonymization represents anonymization of a user's data
type DataAnonymization struct {
	AnonymizationID  uuid.UUID `json:"anonymization_id" db:"anonymization_id"`
	OriginalUserID   uuid.UUID `json:"original_user_id" db:"original_user_id"`
	AnonymizedID     string    `json:"anonymized_id" db:"anonymized_id"` // e.g., "User_12345"
	RequestID        uuid.UUID `json:"request_id" db:"request_id"`
	AnonymizedAt     time.Time `json:"anonymized_at" db:"anonymized_at"`
	AnonymizedBy     uuid.UUID `json:"anonymized_by" db:"anonymized_by"`
	TablesAffected   []string  `json:"tables_affected" db:"tables_affected"`
	RecordsAffected  int       `json:"records_affected" db:"records_affected"`
	RetainedRecords  int       `json:"retained_records" db:"retained_records"` // Transaction records kept for compliance
	VerificationHash string    `json:"-" db:"verification_hash"`               // Prove anonymization completed
	IsComplete       bool      `json:"is_complete" db:"is_complete"`
}

// PrivacySettings represents user privacy preferences
type PrivacySettings struct {
	UserID                  uuid.UUID `json:"user_id" db:"user_id"`
	AllowProfiling          bool      `json:"allow_profiling" db:"allow_profiling"`
	AllowThirdPartySharing  bool      `json:"allow_third_party_sharing" db:"allow_third_party_sharing"`
	AllowAnalytics          bool      `json:"allow_analytics" db:"allow_analytics"`
	DataRetentionPreference string    `json:"data_retention_preference" db:"data_retention_preference"` // MINIMUM, STANDARD, EXTENDED
	ConsentedPurposes       []string  `json:"consented_purposes" db:"consented_purposes"`
	RestrictedCountries     []string  `json:"restricted_countries" db:"restricted_countries"` // Countries where data must not be processed
	UpdatedAt               time.Time `json:"updated_at" db:"updated_at"`
}

// GDPR data categories for access requests
var GDPRDataCategories = []string{
	"PERSONAL_IDENTIFICATION", // Name, DOB, SSN
	"CONTACT_INFORMATION",     // Email, phone, address
	"FINANCIAL_INFORMATION",   // Account details, transactions
	"LOGIN_HISTORY",           // Session logs, device info
	"PREFERENCES",             // User settings, notification prefs
	"CONSENT_HISTORY",         // All consent records
	"COMMUNICATION_HISTORY",   // Emails, SMS sent
	"SUPPORT_INTERACTIONS",    // Customer service records
	"MARKETING_PROFILE",       // Profiling data if any
	"KYC_DOCUMENTS",           // Uploaded verification docs
}

// UserDataExportContent represents the structure of a GDPR data export
type UserDataExportContent struct {
	ExportedAt           time.Time                `json:"exported_at"`
	UserID               string                   `json:"user_id"`
	PersonalInfo         map[string]interface{}   `json:"personal_info"`
	ContactInfo          map[string]interface{}   `json:"contact_info"`
	Addresses            []map[string]interface{} `json:"addresses"`
	Devices              []map[string]interface{} `json:"devices"`
	Preferences          map[string]interface{}   `json:"preferences"`
	Transactions         []map[string]interface{} `json:"transactions"`
	LoginHistory         []map[string]interface{} `json:"login_history"`
	ConsentHistory       []map[string]interface{} `json:"consent_history"`
	CommunicationHistory []map[string]interface{} `json:"communication_history"`
	KYCDocuments         []map[string]interface{} `json:"kyc_documents"` // Metadata only
}
