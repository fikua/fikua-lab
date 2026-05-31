-- Activate the HAIP Verifier profile (x509_hash, direct_post.jwt, DCQL) and
-- deactivate the Plain Verifier. HAIP 1.0 requires the x509_hash client_id
-- prefix; the plain profile used x509_san_dns, which HAIP does not define.
-- Idempotent: only touches verifier-role rows.

UPDATE profiles
SET is_active = (name = 'HAIP Verifier')
WHERE role = 'verifier';
