-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- Audit Events Table (Immutable Ledger)
CREATE TABLE IF NOT EXISTS audit_events (
    event_id UUID PRIMARY KEY,
    transaction_id UUID,
    user_id UUID NOT NULL,
    actor_id UUID,
    action_type VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(100) NOT NULL,
    service_source VARCHAR(100),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    result VARCHAR(20) NOT NULL,
    failure_reason TEXT,
    ip_address VARCHAR(45),
    geolocation VARCHAR(100),
    user_agent TEXT,
    request_id VARCHAR(100),
    session_id VARCHAR(100),
    digital_signature TEXT NOT NULL,
    metadata JSONB,
    data_before BYTEA,
    data_after BYTEA,
    compliance_flags TEXT [],
    retention_category VARCHAR(50) NOT NULL DEFAULT 'STANDARD',
    encryption_key_id INT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
-- Access Logs (Audit of Audits)
CREATE TABLE IF NOT EXISTS access_logs (
    access_id UUID PRIMARY KEY,
    accessor_id UUID NOT NULL,
    accessor_role VARCHAR(50),
    access_type VARCHAR(50) NOT NULL,
    query_filter TEXT,
    records_viewed INT,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    purpose TEXT
);
-- Indexes for Query Performance
CREATE INDEX IF NOT EXISTS idx_audit_transaction_id ON audit_events(transaction_id);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action_type ON audit_events(action_type);
-- Constraint to simulate immutability (Trigger would be better but this is a start)
-- In production, we revoke UPDATE/DELETE permissions from the application user.