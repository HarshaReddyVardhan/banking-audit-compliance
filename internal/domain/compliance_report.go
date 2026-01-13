package domain

import (
	"time"

	"github.com/google/uuid"
)

// ComplianceReportType represents the type of compliance report
type ComplianceReportType string

const (
	ReportTypeCTR           ComplianceReportType = "CTR"            // Currency Transaction Report
	ReportTypeSAR           ComplianceReportType = "SAR"            // Suspicious Activity Report
	ReportTypeAMLMonthly    ComplianceReportType = "AML_MONTHLY"    // Monthly AML Summary
	ReportTypeAMLQuarterly  ComplianceReportType = "AML_QUARTERLY"  // Quarterly Risk Assessment
	ReportTypeKYCStatus     ComplianceReportType = "KYC_STATUS"     // KYC Compliance Status
	ReportTypeGDPRAccess    ComplianceReportType = "GDPR_ACCESS"    // GDPR Data Access Request
	ReportTypeGDPRErasure   ComplianceReportType = "GDPR_ERASURE"   // GDPR Erasure Request
	ReportTypeAuditExport   ComplianceReportType = "AUDIT_EXPORT"   // Audit Log Export
	ReportTypeSOXCompliance ComplianceReportType = "SOX_COMPLIANCE" // SOX Compliance Report
	ReportTypePCIDSS        ComplianceReportType = "PCI_DSS"        // PCI-DSS Compliance
)

// ComplianceReportStatus represents the status of a report
type ComplianceReportStatus string

const (
	ReportStatusPending    ComplianceReportStatus = "PENDING"
	ReportStatusGenerating ComplianceReportStatus = "GENERATING"
	ReportStatusReady      ComplianceReportStatus = "READY"
	ReportStatusFiled      ComplianceReportStatus = "FILED"
	ReportStatusFailed     ComplianceReportStatus = "FAILED"
	ReportStatusArchived   ComplianceReportStatus = "ARCHIVED"
)

// ComplianceReport represents a generated compliance report
type ComplianceReport struct {
	ReportID                 uuid.UUID              `json:"report_id" db:"report_id"`
	ReportType               ComplianceReportType   `json:"report_type" db:"report_type"`
	ReportNumber             string                 `json:"report_number" db:"report_number"`
	Status                   ComplianceReportStatus `json:"status" db:"status"`
	Period                   string                 `json:"period" db:"period"` // e.g., "2025-01", "2025-Q1"
	PeriodStart              time.Time              `json:"period_start" db:"period_start"`
	PeriodEnd                time.Time              `json:"period_end" db:"period_end"`
	GeneratedAt              time.Time              `json:"generated_at" db:"generated_at"`
	GeneratedBy              uuid.UUID              `json:"generated_by" db:"generated_by"`
	FiledWith                *string                `json:"filed_with,omitempty" db:"filed_with"` // FinCEN, Regulator, etc.
	FiledAt                  *time.Time             `json:"filed_at,omitempty" db:"filed_at"`
	FilingConfirmationNumber *string                `json:"filing_confirmation_number,omitempty" db:"filing_confirmation_number"`
	S3Path                   string                 `json:"-" db:"s3_path"`
	FileFormat               string                 `json:"file_format" db:"file_format"` // PDF, CSV, JSON
	FileSizeBytes            int64                  `json:"file_size_bytes" db:"file_size_bytes"`
	Hash                     string                 `json:"-" db:"hash"` // SHA-256 for integrity
	Summary                  string                 `json:"summary" db:"summary"`
	RecordCount              int                    `json:"record_count" db:"record_count"`
	ErrorMessage             *string                `json:"error_message,omitempty" db:"error_message"`
	RetentionUntil           time.Time              `json:"retention_until" db:"retention_until"`
	IsEncrypted              bool                   `json:"is_encrypted" db:"is_encrypted"`
	AccessLog                []ReportAccessEntry    `json:"access_log,omitempty" db:"-"`
	CreatedAt                time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt                time.Time              `json:"updated_at" db:"updated_at"`
}

// ReportAccessEntry tracks who accessed a report
type ReportAccessEntry struct {
	AccessedBy uuid.UUID `json:"accessed_by"`
	AccessedAt time.Time `json:"accessed_at"`
	Action     string    `json:"action"` // VIEW, DOWNLOAD, EXPORT
	IPAddress  string    `json:"ip_address"`
}

// CTRReportData represents Currency Transaction Report data
type CTRReportData struct {
	ReportID        uuid.UUID `json:"report_id"`
	TransactionID   uuid.UUID `json:"transaction_id"`
	TransactionDate time.Time `json:"transaction_date"`
	Amount          int64     `json:"amount"`
	Currency        string    `json:"currency"`
	TransactionType string    `json:"transaction_type"`
	UserID          uuid.UUID `json:"user_id"`
	UserName        string    `json:"user_name"` // For filing purposes
	UserAddress     string    `json:"user_address"`
	UserSSN         string    `json:"-"` // Encrypted
	UserDOB         time.Time `json:"-"`
	AccountNumber   string    `json:"account_number"`
	BankName        string    `json:"bank_name"`
	ConductedBy     string    `json:"conducted_by"` // If different from user
	CashIn          int64     `json:"cash_in"`
	CashOut         int64     `json:"cash_out"`
	FilingDeadline  time.Time `json:"filing_deadline"` // 15 days from transaction
}

// SARReportData represents Suspicious Activity Report data
type SARReportData struct {
	ReportID               uuid.UUID   `json:"report_id"`
	SubjectUserID          uuid.UUID   `json:"subject_user_id"`
	SubjectName            string      `json:"subject_name"`
	SubjectAddress         string      `json:"subject_address"`
	SubjectSSN             string      `json:"-"` // Encrypted
	SubjectDOB             time.Time   `json:"-"`
	InstitutionName        string      `json:"institution_name"`
	InstitutionAddress     string      `json:"institution_address"`
	SuspiciousActivityType string      `json:"suspicious_activity_type"`
	SuspiciousActivityDate time.Time   `json:"suspicious_activity_date"`
	AmountInvolved         int64       `json:"amount_involved"`
	TransactionIDs         []uuid.UUID `json:"transaction_ids"`
	NarrativeDescription   string      `json:"narrative_description"`
	ContactName            string      `json:"contact_name"`
	ContactPhone           string      `json:"contact_phone"`
	FilingDeadline         time.Time   `json:"filing_deadline"` // 30 days from detection
}

// AMLMonthlyReportData represents monthly AML summary data
type AMLMonthlyReportData struct {
	ReportPeriod          string         `json:"report_period"`
	TotalTransactions     int            `json:"total_transactions"`
	TotalAmount           int64          `json:"total_amount"`
	FlaggedCount          int            `json:"flagged_count"`
	CTRsFiled             int            `json:"ctrs_filed"`
	SARsFiled             int            `json:"sars_filed"`
	InvestigationsOpened  int            `json:"investigations_opened"`
	InvestigationsClosed  int            `json:"investigations_closed"`
	AccountsFrozen        int            `json:"accounts_frozen"`
	FalsePositiveRate     float64        `json:"false_positive_rate"`
	AverageResolutionTime time.Duration  `json:"average_resolution_time"`
	TopFlagTypes          map[string]int `json:"top_flag_types"`
	HighRiskCountryTxns   map[string]int `json:"high_risk_country_txns"`
	TrainingCompliance    float64        `json:"training_compliance"` // % staff completed training
	SystemUptime          float64        `json:"system_uptime"`
	Recommendations       []string       `json:"recommendations"`
	GeneratedAt           time.Time      `json:"generated_at"`
}

// ReportGenerationRequest represents a request to generate a report
type ReportGenerationRequest struct {
	ReportType  ComplianceReportType `json:"report_type" validate:"required"`
	PeriodStart time.Time            `json:"period_start" validate:"required"`
	PeriodEnd   time.Time            `json:"period_end" validate:"required"`
	UserID      *uuid.UUID           `json:"user_id,omitempty"` // For user-specific reports
	Format      string               `json:"format" validate:"required,oneof=PDF CSV JSON"`
	RequestedBy uuid.UUID            `json:"requested_by" validate:"required"`
	Purpose     string               `json:"purpose" validate:"required"`
	Urgent      bool                 `json:"urgent"`
}

// ComplianceDeadline represents a compliance deadline
type ComplianceDeadline struct {
	DeadlineID   uuid.UUID            `json:"deadline_id" db:"deadline_id"`
	ReportType   ComplianceReportType `json:"report_type" db:"report_type"`
	RelatedID    *uuid.UUID           `json:"related_id,omitempty" db:"related_id"` // Transaction, User, etc.
	DueDate      time.Time            `json:"due_date" db:"due_date"`
	Regulation   string               `json:"regulation" db:"regulation"`
	Description  string               `json:"description" db:"description"`
	Status       string               `json:"status" db:"status"` // PENDING, MET, MISSED
	AssignedTo   *uuid.UUID           `json:"assigned_to,omitempty" db:"assigned_to"`
	CompletedAt  *time.Time           `json:"completed_at,omitempty" db:"completed_at"`
	ReportID     *uuid.UUID           `json:"report_id,omitempty" db:"report_id"`
	ReminderSent bool                 `json:"reminder_sent" db:"reminder_sent"`
	EscalatedAt  *time.Time           `json:"escalated_at,omitempty" db:"escalated_at"`
	CreatedAt    time.Time            `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time            `json:"updated_at" db:"updated_at"`
}

// Standard filing deadlines
var FilingDeadlines = map[ComplianceReportType]time.Duration{
	ReportTypeCTR:         15 * 24 * time.Hour, // 15 days from transaction
	ReportTypeSAR:         30 * 24 * time.Hour, // 30 days from detection
	ReportTypeGDPRAccess:  30 * 24 * time.Hour, // 30 days from request
	ReportTypeGDPRErasure: 30 * 24 * time.Hour, // 30 days from request
}
