package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/banking/audit-compliance/internal/config"
	"github.com/banking/audit-compliance/internal/domain"
	elastic "github.com/elastic/go-elasticsearch/v8"
)

type SearchRepository struct {
	client *elastic.Client
	index  string
}

// NewSearchRepository creates a new search repository
func NewSearchRepository(cfg config.ElasticsearchConfig) (*SearchRepository, error) {
	client, err := elastic.NewClient(elastic.Config{
		Addresses: cfg.Addresses,
		Username:  cfg.Username,
		Password:  cfg.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create elasticsearch client: %w", err)
	}

	// Verify connection
	_, err = client.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to elasticsearch: %w", err)
	}

	return &SearchRepository{
		client: client,
		index:  cfg.Index,
	}, nil
}

// IndexEvent indexes an audit event for search
func (r *SearchRepository) IndexEvent(ctx context.Context, event *domain.AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	res, err := r.client.Index(
		r.index,
		bytes.NewReader(data),
		r.client.Index.WithContext(ctx),
		r.client.Index.WithDocumentID(event.EventID.String()),
	)
	if err != nil {
		return fmt.Errorf("failed to index event: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("elasticsearch error: %s", res.String())
	}

	return nil
}

// SearchEvents performs a complex search query
func (r *SearchRepository) SearchEvents(ctx context.Context, query string, from, size int) (*domain.AuditEventPage, error) {
	// Simple query string query for now, can be expanded to full DSL
	esQuery := map[string]interface{}{
		"from": from,
		"size": size,
		"query": map[string]interface{}{
			"query_string": map[string]interface{}{
				"query": query,
			},
		},
		"sort": []map[string]interface{}{
			{"timestamp": "desc"},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(esQuery); err != nil {
		return nil, fmt.Errorf("failed to encode query: %w", err)
	}

	res, err := r.client.Search(
		r.client.Search.WithContext(ctx),
		r.client.Search.WithIndex(r.index),
		r.client.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to perform search: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("elasticsearch search error: %s", res.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Transform response to AuditEventPage
	// This part requires careful parsing of the ES response structure
	// { "hits": { "total": { "value": ... }, "hits": [ { "_source": ... } ] } }

	hitsMap, ok := result["hits"].(map[string]interface{})
	if !ok {
		return &domain.AuditEventPage{}, nil // Empty result
	}

	totalMap, ok := hitsMap["total"].(map[string]interface{})
	var total int64
	if ok {
		if val, ok := totalMap["value"].(float64); ok {
			total = int64(val)
		}
	}

	hitsList, ok := hitsMap["hits"].([]interface{})
	if !ok {
		return &domain.AuditEventPage{}, nil
	}

	var events []*domain.AuditEvent
	for _, hit := range hitsList {
		hitMap, ok := hit.(map[string]interface{})
		if !ok {
			continue
		}
		source, ok := hitMap["_source"].(map[string]interface{})
		if !ok {
			continue
		}

		// Parse source into AuditEvent
		// Re-marshal to JSON and Unmarshal to struct is cleaner than manual map parsing
		sourceBytes, _ := json.Marshal(source)
		var evt domain.AuditEvent
		if err := json.Unmarshal(sourceBytes, &evt); err == nil {
			events = append(events, &evt)
		}
	}

	return &domain.AuditEventPage{
		Events:     events,
		TotalCount: total,
		Page:       from/size + 1,
		PageSize:   size,
		HasMore:    total > int64(from+size),
	}, nil
}
