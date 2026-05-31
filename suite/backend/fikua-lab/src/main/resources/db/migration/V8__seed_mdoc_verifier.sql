-- Seed an inactive HAIP mdoc Verifier profile (ISO mdoc / mso_mdoc,
-- x509_hash, direct_post.jwt, DCQL). Inactive by default so the SD-JWT HAIP
-- verifier stays active; activate manually when running the iso_mdl plan:
--
--   UPDATE profiles SET is_active = (name = 'HAIP mdoc Verifier') WHERE role = 'verifier';
--
-- and switch back to 'HAIP Verifier' afterwards. Idempotent: skip if a profile
-- with this name already exists.

INSERT INTO profiles (name, role, config, is_active)
SELECT 'HAIP mdoc Verifier', 'verifier',
       '{"credentialFormat":"mdoc","clientIdPrefix":"x509_hash","responseMode":"direct_post_jwt","queryLanguage":"dcql","requestMethod":"request_uri_signed"}'::jsonb,
       false
WHERE NOT EXISTS (
    SELECT 1 FROM profiles WHERE name = 'HAIP mdoc Verifier' AND role = 'verifier'
);
