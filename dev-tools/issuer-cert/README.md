# Issuer test certificate

This directory holds the **test** issuer certificate used by `fikua-issuer` when loading PEM keys from disk (`PemKeyLoader`).

> [!WARNING]
> Test material only. **Do not** use these files (or any key regenerated from this config) to sign real credentials in production.

## What lives here

| File                                  | Tracked in git | Purpose                                                |
| ------------------------------------- | -------------- | ------------------------------------------------------ |
| `issuer-cert.pem`                     | ✅              | X.509 certificate (public, safe to commit)             |
| `issuer-key.pem`                      | ❌ (gitignored) | EC P-256 private key — regenerate locally (see below)  |
| `issuer-provider-eidas-cert.cnf`      | ✅              | OpenSSL config used to generate the cert + key pair    |

## Regenerate the private key + certificate

```bash
cd dev-tools/issuer-cert

# Generate EC P-256 key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out issuer-key.pem

# Self-sign a certificate using the .cnf config
openssl req -new -x509 \
  -key issuer-key.pem \
  -out issuer-cert.pem \
  -days 365 \
  -config issuer-provider-eidas-cert.cnf
```

`PemKeyLoader` will pick them up from `FIKUA_CERTS_DIR`. Tests that depend on this material skip gracefully when the key is absent (see `PemKeyLoaderTest.loadOrGenerate_withPemFiles_loadsFromFiles`).
