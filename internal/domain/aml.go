package domain

import (
	"time"

	"github.com/google/uuid"
)

// AMLFlagType represents the type of AML flag
type AMLFlagType string

const (
	AMLFlagStructuring     AMLFlagType = "STRUCTURING"      // Multiple small transfers to avoid reporting
	AMLFlagVelocity        AMLFlagType = "VELOCITY"         // Unusual transaction velocity
	AMLFlagGeographic      AMLFlagType = "GEOGRAPHIC"       // High-risk country transfers
	AMLFlagAmount          AMLFlagType = "AMOUNT"           // Large single transfer > threshold
	AMLFlagRapidSuccession AMLFlagType = "RAPID_SUCCESSION" // Same amount repeated quickly
	AMLFlagOFACMatch       AMLFlagType = "OFAC_MATCH"       // Sanctioned list match
	AMLFlagPEPTransaction  AMLFlagType = "PEP_TRANSACTION"  // Transaction involving PEP
	AMLFlagBehaviorAnomaly AMLFlagType = "BEHAVIOR_ANOMALY" // Unusual behavior pattern
	AMLFlagThirdParty      AMLFlagType = "THIRD_PARTY"      // Suspicious third-party involvement
	AMLFlagLayering        AMLFlagType = "LAYERING"         // Complex transaction chains
)

// AMLFlagStatus represents the investigation status of an AML flag
type AMLFlagStatus string

const (
	AMLStatusPending       AMLFlagStatus = "PENDING"       // Awaiting review
	AMLStatusInvestigating AMLFlagStatus = "INVESTIGATING" // Under investigation
	AMLStatusEscalated     AMLFlagStatus = "ESCALATED"     // Escalated to senior analyst
	AMLStatusFiled         AMLFlagStatus = "FILED"         // SAR/CTR filed with FinCEN
	AMLStatusDismissed     AMLFlagStatus = "DISMISSED"     // False positive
	AMLStatusFrozen        AMLFlagStatus = "FROZEN"        // Account frozen
	AMLStatusCleared       AMLFlagStatus = "CLEARED"       // Investigation complete, no action
)

// AMLFlag represents a flagged suspicious activity
type AMLFlag struct {
	FlagID             uuid.UUID     `json:"flag_id" db:"flag_id"`
	TransactionID      uuid.UUID     `json:"transaction_id" db:"transaction_id"`
	UserID             uuid.UUID     `json:"user_id" db:"user_id"`
	AccountID          uuid.UUID     `json:"account_id" db:"account_id"`
	FlagType           AMLFlagType   `json:"flag_type" db:"flag_type"`
	RiskScore          int           `json:"risk_score" db:"risk_score"` // 0-100
	Status             AMLFlagStatus `json:"status" db:"status"`
	DetectedAt         time.Time     `json:"detected_at" db:"detected_at"`
	DetectionMethod    string        `json:"detection_method" db:"detection_method"` // RULE, ML_MODEL, MANUAL
	DetectionRule      *string       `json:"detection_rule,omitempty" db:"detection_rule"`
	TransactionAmount  int64         `json:"transaction_amount" db:"transaction_amount"`
	Currency           string        `json:"currency" db:"currency"`
	SourceCountry      string        `json:"source_country" db:"source_country"`
	DestCountry        string        `json:"dest_country" db:"dest_country"`
	AssignedTo         *uuid.UUID    `json:"assigned_to,omitempty" db:"assigned_to"`
	AssignedAt         *time.Time    `json:"assigned_at,omitempty" db:"assigned_at"`
	InvestigationNotes *string       `json:"investigation_notes,omitempty" db:"investigation_notes"`
	Resolution         *string       `json:"resolution,omitempty" db:"resolution"`
	ResolvedAt         *time.Time    `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolvedBy         *uuid.UUID    `json:"resolved_by,omitempty" db:"resolved_by"`
	FiledWithFinCEN    bool          `json:"filed_with_fincen" db:"filed_with_fincen"`
	SARNumber          *string       `json:"sar_number,omitempty" db:"sar_number"`
	CTRNumber          *string       `json:"ctr_number,omitempty" db:"ctr_number"`
	RelatedFlags       []uuid.UUID   `json:"related_flags,omitempty" db:"related_flags"`
	Priority           string        `json:"priority" db:"priority"` // LOW, MEDIUM, HIGH, CRITICAL
	DueDate            *time.Time    `json:"due_date,omitempty" db:"due_date"`
	CreatedAt          time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time     `json:"updated_at" db:"updated_at"`
}

// SuspiciousActivityThresholds for automatic detection
var SuspiciousActivityThresholds = struct {
	CTRThreshold           int64 // Amount triggering Currency Transaction Report
	StructuringThreshold   int64 // Amount just below CTR threshold (suspicious)
	VelocityCountPerHour   int   // Max transfers per hour before flagging
	RapidSuccessionCount   int   // Same amount repeated N times
	RapidSuccessionWindow  time.Duration
	HighRiskScoreThreshold int // Score above which manual review required
}{
	CTRThreshold:           1000000, // $10,000 in cents
	StructuringThreshold:   999900,  // $9,999 in cents
	VelocityCountPerHour:   20,
	RapidSuccessionCount:   5,
	RapidSuccessionWindow:  15 * time.Minute,
	HighRiskScoreThreshold: 70,
}

// HighRiskCountries for geographic risk scoring
var HighRiskCountries = map[string]int{
	// Sanctioned - Blocked
	"IR": 100, // Iran
	"KP": 100, // North Korea
	"SY": 100, // Syria
	"CU": 100, // Cuba
	"RU": 90,  // Russia (elevated due to sanctions)
	// High Risk
	"AF": 50, // Afghanistan
	"MM": 45, // Myanmar
	"BY": 40, // Belarus
	"VE": 35, // Venezuela
	// Medium Risk
	"TR": 25, // Turkey
	"AE": 25, // UAE
	"HK": 20, // Hong Kong
	"PK": 30, // Pakistan
	// Most countries: 5-15 (low risk)
}

// GetCountryRiskScore returns the risk score for a country
func GetCountryRiskScore(isoCode string) int {
	if score, exists := HighRiskCountries[isoCode]; exists {
		return score
	}
	return 5 // Default low risk
}

// IsBlockedCountry returns true if the country is completely blocked
func IsBlockedCountry(isoCode string) bool {
	score := GetCountryRiskScore(isoCode)
	return score >= 100
}

// AMLVelocityCheck represents a velocity check result
type AMLVelocityCheck struct {
	UserID           uuid.UUID `json:"user_id"`
	WindowStart      time.Time `json:"window_start"`
	WindowEnd        time.Time `json:"window_end"`
	TransactionCount int       `json:"transaction_count"`
	TotalAmount      int64     `json:"total_amount"`
	UniqueRecipients int       `json:"unique_recipients"`
	AverageAmount    int64     `json:"average_amount"`
	IsSuspicious     bool      `json:"is_suspicious"`
	RiskScore        int       `json:"risk_score"`
	Flags            []string  `json:"flags,omitempty"`
}

// StructuringPattern represents a detected structuring pattern
type StructuringPattern struct {
	PatternID        uuid.UUID     `json:"pattern_id"`
	UserID           uuid.UUID     `json:"user_id"`
	TransactionIDs   []uuid.UUID   `json:"transaction_ids"`
	TotalAmount      int64         `json:"total_amount"`
	TransactionCount int           `json:"transaction_count"`
	TimeSpan         time.Duration `json:"time_span"`
	DetectedAt       time.Time     `json:"detected_at"`
	Confidence       float64       `json:"confidence"` // 0.0 - 1.0
}

// OFACCheckResult represents the result of an OFAC sanctions check
type OFACCheckResult struct {
	CheckID      uuid.UUID `json:"check_id"`
	EntityName   string    `json:"entity_name"`
	EntityType   string    `json:"entity_type"` // INDIVIDUAL, ORGANIZATION
	IsMatch      bool      `json:"is_match"`
	MatchScore   float64   `json:"match_score"`            // 0.0 - 1.0
	MatchedList  string    `json:"matched_list,omitempty"` // SDN, etc.
	MatchedEntry *string   `json:"matched_entry,omitempty"`
	CheckedAt    time.Time `json:"checked_at"`
}

// PEPCheckResult represents the result of a PEP (Politically Exposed Person) check
type PEPCheckResult struct {
	CheckID     uuid.UUID `json:"check_id"`
	UserID      uuid.UUID `json:"user_id"`
	IsPEP       bool      `json:"is_pep"`
	PEPCategory *string   `json:"pep_category,omitempty"` // FOREIGN_OFFICIAL, DOMESTIC_OFFICIAL, etc.
	Position    *string   `json:"position,omitempty"`
	Country     *string   `json:"country,omitempty"`
	RiskLevel   string    `json:"risk_level"`
	MatchScore  float64   `json:"match_score"`
	Source      string    `json:"source"` // Database used
	CheckedAt   time.Time `json:"checked_at"`
}

// AMLInvestigation represents a full AML investigation
type AMLInvestigation struct {
	InvestigationID        uuid.UUID   `json:"investigation_id" db:"investigation_id"`
	CaseNumber             string      `json:"case_number" db:"case_number"`
	UserID                 uuid.UUID   `json:"user_id" db:"user_id"`
	RelatedFlags           []uuid.UUID `json:"related_flags" db:"related_flags"`
	Status                 string      `json:"status" db:"status"` // OPEN, IN_PROGRESS, PENDING_REVIEW, CLOSED
	Priority               string      `json:"priority" db:"priority"`
	AssignedTo             uuid.UUID   `json:"assigned_to" db:"assigned_to"`
	SupervisorID           *uuid.UUID  `json:"supervisor_id,omitempty" db:"supervisor_id"`
	OpenedAt               time.Time   `json:"opened_at" db:"opened_at"`
	DueDate                time.Time   `json:"due_date" db:"due_date"`
	Description            string      `json:"description" db:"description"`
	Findings               *string     `json:"findings,omitempty" db:"findings"`
	Recommendation         *string     `json:"recommendation,omitempty" db:"recommendation"`
	ActionTaken            *string     `json:"action_taken,omitempty" db:"action_taken"`
	ClosedAt               *time.Time  `json:"closed_at,omitempty" db:"closed_at"`
	ClosedBy               *uuid.UUID  `json:"closed_by,omitempty" db:"closed_by"`
	SARFiled               bool        `json:"sar_filed" db:"sar_filed"`
	SARFilingDate          *time.Time  `json:"sar_filing_date,omitempty" db:"sar_filing_date"`
	CTRFiled               bool        `json:"ctr_filed" db:"ctr_filed"`
	AccountFrozen          bool        `json:"account_frozen" db:"account_frozen"`
	LawEnforcementNotified bool        `json:"law_enforcement_notified" db:"law_enforcement_notified"`
	CreatedAt              time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time   `json:"updated_at" db:"updated_at"`
}
