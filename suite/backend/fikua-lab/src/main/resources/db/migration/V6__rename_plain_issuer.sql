-- Rename "Plain Pre-Auth Issuer" to "Plain Issuer" and remove fixed grantType
UPDATE profiles
SET name = 'Plain Issuer',
    config = config - 'grantType'
WHERE name = 'Plain Pre-Auth Issuer';
