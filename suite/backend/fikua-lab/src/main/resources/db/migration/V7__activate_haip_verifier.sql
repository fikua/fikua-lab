-- Activate the HAIP Verifier profile (x509_hash, direct_post.jwt, DCQL) and
-- deactivate the Plain Verifier. HAIP 1.0 requires the x509_hash client_id
-- prefix; the plain profile used x509_san_dns, which HAIP does not define.
--
-- First fix the active-profile uniqueness scope. The original index (V1) was
-- global (UNIQUE (is_active) WHERE is_active), so only ONE profile could be
-- active across the whole system — an active issuer profile blocked any active
-- verifier profile, leaving the verifier permanently on its fallback preset.
-- Make uniqueness per-role so issuer and verifier can each have one active
-- profile. Idempotent.

DROP INDEX IF EXISTS idx_profiles_active;

CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_active_per_role
    ON profiles (role, is_active) WHERE is_active = true;

UPDATE profiles
SET is_active = (name = 'HAIP Verifier')
WHERE role = 'verifier';
