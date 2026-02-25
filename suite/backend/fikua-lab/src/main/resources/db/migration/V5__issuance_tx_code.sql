-- Add tx_code column for transaction code persistence.
-- Allows sending tx_code via email when wallet retrieves credential offer.
ALTER TABLE issuance_records ADD COLUMN IF NOT EXISTS tx_code VARCHAR(10);
