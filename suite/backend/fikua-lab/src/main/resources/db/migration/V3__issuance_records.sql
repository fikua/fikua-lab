-- Issuance records: abstract credential issuance tracking
-- credential_data stores the full claim set as JSONB, making this
-- extensible to any credential type without schema changes.

CREATE TABLE IF NOT EXISTS issuance_records (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_type VARCHAR(255) NOT NULL,
    credential_data JSONB NOT NULL DEFAULT '{}',
    source_type     VARCHAR(50),
    source_ref      TEXT,
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    pre_auth_code   VARCHAR(255),
    offer_id        VARCHAR(255),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_issuance_records_status ON issuance_records(status);
