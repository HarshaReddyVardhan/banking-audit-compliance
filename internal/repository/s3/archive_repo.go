package s3

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	appConfig "github.com/banking/audit-compliance/internal/config"
	"github.com/banking/audit-compliance/internal/domain"
)

type ArchiveRepository struct {
	client *s3.Client
	bucket string
}

// NewArchiveRepository creates a new S3 archive repository
func NewArchiveRepository(ctx context.Context, cfg appConfig.S3Config) (*ArchiveRepository, error) {
	// Custom resolver for MinIO/Localstack support
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if cfg.Endpoint != "" {
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           cfg.Endpoint,
				SigningRegion: cfg.Region,
			}, nil
		}
		// returning EndpointNotFoundError will allow the service to fallback to it's default resolution
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.Region),
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true // Required for MinIO
	})

	return &ArchiveRepository{
		client: client,
		bucket: cfg.ArchiveBucket,
	}, nil
}

// ArchiveBatch uploads a batch of audit events to S3
func (r *ArchiveRepository) ArchiveBatch(ctx context.Context, events []*domain.AuditEvent, batchID string) error {
	if len(events) == 0 {
		return nil
	}

	data, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("failed to marshal events for archive: %w", err)
	}

	// Key format: year/month/day/batchID.json
	now := time.Now().UTC()
	key := fmt.Sprintf("%d/%02d/%02d/%s.json", now.Year(), now.Month(), now.Day(), batchID)

	_, err = r.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})

	if err != nil {
		return fmt.Errorf("failed to upload batch to s3: %w", err)
	}

	return nil
}

// StoreReport uploads a compliance report to S3
func (r *ArchiveRepository) StoreReport(ctx context.Context, reportName string, reportData []byte) error {
	now := time.Now().UTC()
	key := fmt.Sprintf("reports/%d/%02d/%s", now.Year(), now.Month(), reportName)

	_, err := r.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(r.bucket), // Or use separate reports bucket from config
		Key:    aws.String(key),
		Body:   bytes.NewReader(reportData),
	})

	if err != nil {
		return fmt.Errorf("failed to upload report to s3: %w", err)
	}

	return nil
}
