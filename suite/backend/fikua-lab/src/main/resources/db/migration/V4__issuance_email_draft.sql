-- Add recipient_email for email-initiated issuance flow (Student ID + OTP).
ALTER TABLE issuance_records ADD COLUMN IF NOT EXISTS recipient_email VARCHAR(320);

-- Index for looking up draft records by email.
CREATE INDEX IF NOT EXISTS idx_issuance_records_email_status ON issuance_records(recipient_email, status);
