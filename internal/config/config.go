package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the audit compliance service
type Config struct {
	Server        ServerConfig
	Database      DatabaseConfig
	Elasticsearch ElasticsearchConfig
	Redis         RedisConfig
	Kafka         KafkaConfig
	S3            S3Config
	Encryption    EncryptionConfig
	Auth          AuthConfig
	Logging       LoggingConfig
	Tracing       TracingConfig
	Compliance    ComplianceConfig
	Detection     DetectionConfig
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	GRPCPort        int           `mapstructure:"grpc_port"`
}

// DatabaseConfig holds PostgreSQL configuration
type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	DBName          string        `mapstructure:"dbname"`
	SSLMode         string        `mapstructure:"sslmode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
}

// DSN returns the database connection string
func (c DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode,
	)
}

// ElasticsearchConfig holds Elasticsearch configuration
type ElasticsearchConfig struct {
	Addresses []string `mapstructure:"addresses"`
	Username  string   `mapstructure:"username"`
	Password  string   `mapstructure:"password"`
	Index     string   `mapstructure:"index"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	DefaultTTL   time.Duration `mapstructure:"default_ttl"`
}

// Addr returns the Redis address
func (c RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// KafkaConfig holds Kafka configuration
type KafkaConfig struct {
	Brokers          []string `mapstructure:"brokers"`
	ConsumerGroup    string   `mapstructure:"consumer_group"`
	AuditTopic       string   `mapstructure:"audit_topic"`
	TransactionTopic string   `mapstructure:"transaction_topic"`
	UserTopic        string   `mapstructure:"user_topic"`
	AlertTopic       string   `mapstructure:"alert_topic"`
	EnableIdempotent bool     `mapstructure:"enable_idempotent"`
}

// S3Config holds AWS S3 configuration for archival storage
type S3Config struct {
	Region             string `mapstructure:"region"`
	Bucket             string `mapstructure:"bucket"`
	ArchiveBucket      string `mapstructure:"archive_bucket"`
	KYCDocumentsBucket string `mapstructure:"kyc_documents_bucket"`
	ReportsBucket      string `mapstructure:"reports_bucket"`
	Endpoint           string `mapstructure:"endpoint"` // For local testing with MinIO
	AccessKey          string `mapstructure:"access_key"`
	SecretKey          string `mapstructure:"secret_key"`
	UseSSL             bool   `mapstructure:"use_ssl"`
}

// EncryptionConfig holds encryption settings
type EncryptionConfig struct {
	EncryptionKeysBase64  []string `mapstructure:"keys"`
	CurrentKeyVersion     int      `mapstructure:"current_key_version"`
	AuditHMACSecret       string   `mapstructure:"audit_hmac_secret"`
	DocumentEncryptionKey string   `mapstructure:"document_encryption_key"`
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	JWTPublicKeyPath string `mapstructure:"jwt_public_key_path"`
	JWTIssuer        string `mapstructure:"jwt_issuer"`
	ServiceAPIKey    string `mapstructure:"service_api_key"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level           string `mapstructure:"level"`
	Format          string `mapstructure:"format"`
	OutputPath      string `mapstructure:"output_path"`
	EnablePIIMask   bool   `mapstructure:"enable_pii_mask"`
	EnableRequestID bool   `mapstructure:"enable_request_id"`
}

// TracingConfig holds OpenTelemetry tracing settings
type TracingConfig struct {
	Enabled      bool    `mapstructure:"enabled"`
	ServiceName  string  `mapstructure:"service_name"`
	OTLPEndpoint string  `mapstructure:"otlp_endpoint"`
	SampleRate   float64 `mapstructure:"sample_rate"`
}

// ComplianceConfig holds compliance-specific settings
type ComplianceConfig struct {
	CTRThresholdCents         int64  `mapstructure:"ctr_threshold_cents"`
	SARFilingDeadlineDays     int    `mapstructure:"sar_filing_deadline_days"`
	CTRFilingDeadlineDays     int    `mapstructure:"ctr_filing_deadline_days"`
	GDPRResponseDeadlineDays  int    `mapstructure:"gdpr_response_deadline_days"`
	GDPRErasureGraceDays      int    `mapstructure:"gdpr_erasure_grace_days"`
	TransactionRetentionYears int    `mapstructure:"transaction_retention_years"`
	LoginRetentionDays        int    `mapstructure:"login_retention_days"`
	ReportRetentionYears      int    `mapstructure:"report_retention_years"`
	EnableAutoArchive         bool   `mapstructure:"enable_auto_archive"`
	ArchiveSchedule           string `mapstructure:"archive_schedule"` // Cron expression
}

// DetectionConfig holds AML detection settings
type DetectionConfig struct {
	VelocityWindowMinutes     int    `mapstructure:"velocity_window_minutes"`
	VelocityThreshold         int    `mapstructure:"velocity_threshold"`
	RapidSuccessionCount      int    `mapstructure:"rapid_succession_count"`
	RapidSuccessionWindowMins int    `mapstructure:"rapid_succession_window_mins"`
	HighRiskScoreThreshold    int    `mapstructure:"high_risk_score_threshold"`
	EnableMLModels            bool   `mapstructure:"enable_ml_models"`
	MLModelEndpoint           string `mapstructure:"ml_model_endpoint"`
	OFACAPIEndpoint           string `mapstructure:"ofac_api_endpoint"`
	PEPAPIEndpoint            string `mapstructure:"pep_api_endpoint"`
}

// Load loads configuration from environment and config files
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Read from environment variables
	v.SetEnvPrefix("AUDIT")
	v.AutomaticEnv()

	// Read config file if exists
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./configs")
	v.AddConfigPath(".")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	// Server
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8085)
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.shutdown_timeout", "30s")
	v.SetDefault("server.grpc_port", 9085)

	// Database
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "postgres")
	v.SetDefault("database.dbname", "compliance_db")
	v.SetDefault("database.sslmode", "disable")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", "5m")
	v.SetDefault("database.conn_max_idle_time", "5m")

	// Elasticsearch
	v.SetDefault("elasticsearch.addresses", []string{"http://localhost:9200"})
	v.SetDefault("elasticsearch.username", "elastic")
	v.SetDefault("elasticsearch.password", "changeme")
	v.SetDefault("elasticsearch.index", "audit-events")

	// Redis
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.min_idle_conns", 3)
	v.SetDefault("redis.default_ttl", "1h")

	// Kafka
	v.SetDefault("kafka.brokers", []string{"localhost:9092"})
	v.SetDefault("kafka.consumer_group", "audit-compliance-service")
	v.SetDefault("kafka.audit_topic", "banking.audit.events")
	v.SetDefault("kafka.transaction_topic", "banking.transactions")
	v.SetDefault("kafka.user_topic", "banking.users")
	v.SetDefault("kafka.alert_topic", "banking.compliance.alerts")
	v.SetDefault("kafka.enable_idempotent", true)

	// S3
	v.SetDefault("s3.region", "us-east-1")
	v.SetDefault("s3.bucket", "banking-audit-logs")
	v.SetDefault("s3.archive_bucket", "banking-compliance-archive")
	v.SetDefault("s3.kyc_documents_bucket", "banking-kyc-documents")
	v.SetDefault("s3.reports_bucket", "banking-compliance-reports")
	v.SetDefault("s3.use_ssl", true)

	// Encryption
	v.SetDefault("encryption.current_key_version", 1)

	// Auth
	v.SetDefault("auth.jwt_public_key_path", "./keys/jwt_public.pem")
	v.SetDefault("auth.jwt_issuer", "banking-auth-service")

	// Logging
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output_path", "stdout")
	v.SetDefault("logging.enable_pii_mask", true)
	v.SetDefault("logging.enable_request_id", true)

	// Tracing
	v.SetDefault("tracing.enabled", true)
	v.SetDefault("tracing.service_name", "audit-compliance-service")
	v.SetDefault("tracing.sample_rate", 0.1)

	// Compliance
	v.SetDefault("compliance.ctr_threshold_cents", 1000000) // $10,000
	v.SetDefault("compliance.sar_filing_deadline_days", 30)
	v.SetDefault("compliance.ctr_filing_deadline_days", 15)
	v.SetDefault("compliance.gdpr_response_deadline_days", 30)
	v.SetDefault("compliance.gdpr_erasure_grace_days", 30)
	v.SetDefault("compliance.transaction_retention_years", 7)
	v.SetDefault("compliance.login_retention_days", 365)
	v.SetDefault("compliance.report_retention_years", 10)
	v.SetDefault("compliance.enable_auto_archive", true)
	v.SetDefault("compliance.archive_schedule", "0 2 * * *") // 2 AM daily

	// Detection
	v.SetDefault("detection.velocity_window_minutes", 60)
	v.SetDefault("detection.velocity_threshold", 20)
	v.SetDefault("detection.rapid_succession_count", 5)
	v.SetDefault("detection.rapid_succession_window_mins", 15)
	v.SetDefault("detection.high_risk_score_threshold", 70)
	v.SetDefault("detection.enable_ml_models", false)
}
