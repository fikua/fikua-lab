-- Seed default profiles from presets (idempotent: skip if profiles already exist)

INSERT INTO profiles (name, role, config, is_active)
SELECT name, role, config, is_active
FROM (VALUES
    ('Plain Pre-Auth Issuer', 'issuer',
     '{"grantType":"pre_authorization_code","credentialFormat":"sd_jwt_vc","vciProfile":"plain","credentialOffer":"by_reference","issuanceMode":"immediate","credentialResponseEnc":"plain","requestMethod":"unsigned","authRequestType":"simple"}'::jsonb,
     true),
    ('HAIP Issuer', 'issuer',
     '{"grantType":"authorization_code","senderConstraining":"dpop","clientAuth":"client_attestation","credentialFormat":"sd_jwt_vc","vciProfile":"haip","credentialOffer":"by_reference","issuanceMode":"immediate","credentialResponseEnc":"plain","par":true,"pkce":"S256","requestMethod":"unsigned","authRequestType":"simple"}'::jsonb,
     false),
    ('Plain Verifier', 'verifier',
     '{"credentialFormat":"sd_jwt_vc","clientIdPrefix":"x509_san_dns","responseMode":"direct_post","requestMethod":"request_uri_signed"}'::jsonb,
     false),
    ('HAIP Verifier', 'verifier',
     '{"credentialFormat":"sd_jwt_vc","clientIdPrefix":"x509_hash","responseMode":"direct_post_jwt","queryLanguage":"dcql","requestMethod":"request_uri_signed"}'::jsonb,
     false)
) AS seed(name, role, config, is_active)
WHERE NOT EXISTS (SELECT 1 FROM profiles LIMIT 1);
