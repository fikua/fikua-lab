# Issuer e-Seal certificate (eIDAS, test only)

This directory documents how to issue an **e-Seal** (electronic seal, _sello
electrónico_) following an eIDAS-style profile for **Fikua Lab test purposes**.

The e-Seal is the **legal-person** signing material used by the
`fikua-digital-signature-service` (DSS) to seal data on behalf of the
organization. It is **not** a representative (natural-person) certificate: per
ETSI EN 319 412-3 an e-Seal is issued to and used by the legal entity itself,
so the subject DN carries `O` / `organizationIdentifier` and **no**
`givenName` / `surname` / `(REPRESENTANTE)` `CN`.

> [!WARNING]
> Test material only. This is **not** a qualified e-Seal. Do **not** use these
> files (or any key regenerated from this config) to seal real data in
> production.

## Where the e-Seal is consumed

The DSS loads the cert + key from these paths (see
`fikua-platform-iac/projects/fikua-lab/dss/compose.yaml`):

| Env var     | Value                          | Meaning                  |
| ----------- | ------------------------------ | ------------------------ |
| `CERT_PATH` | `file:/certs/issuer-eseal.crt` | X.509 certificate (PEM)  |
| `KEY_PATH`  | `file:/certs/issuer-eseal.key` | Private key (PKCS#8 PEM) |

On the VPS those map to the host bind-mount:

```
/opt/vps/projects/fikua-lab/dss/certs/issuer-eseal.{crt,key}
```

The DSS `SigningService` supports both EC and RSA keys. We use **EC P-256
(ES256)** here to stay aligned with the rest of the lab (HAIP issuer profile).

## What lives here

| File | Tracked | Purpose |
| ---- | ------- | ------- |
| `issuer-eseal-eidas.cnf` | ✅ | OpenSSL config — e-Seal leaf subject + profile |
| `root-ca-eidas.cnf` | ✅ | OpenSSL config — Root CA + leaf extensions for the chain |
| `generate-chain.sh` | ✅ | Builds the 2-level chain (Root CA → e-Seal leaf) |
| `issuer-eseal.{crt,key}` | ❌ | Single self-signed cert + key (Step 1, quick path) |
| `issuer-cert.pem` / `issuer-key.pem` / `root-ca.{crt,key}` | ❌ | Chain output (Step 1-bis) |

All `❌` files are gitignored (`*.crt`, `*.key`, `*.pem`); regenerate locally.

> All cert + key material is gitignored (`*.crt`, `*.key`, `*.pem`). Only the
> configs and the generator script are committed. Regenerate locally.

## Step 1 — Quick path: single self-signed e-Seal

The `.cnf` produces a self-signed e-Seal cert with the legal-person profile.
Good enough to prove the issuer signs with a provided cert, but **not** HAIP
6.1.1 conformant (the signing cert must not be self-signed).

```bash
cd dev-tools/issuer-eseal

# EC P-256 key + self-signed e-Seal certificate (2-year validity)
openssl req -new -x509 \
  -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout issuer-eseal.key \
  -out issuer-eseal.crt \
  -days 730 -sha256 \
  -config issuer-eseal-eidas.cnf
```

## Step 1-bis — HAIP path: 2-level chain (Root CA → e-Seal leaf)

For the OIDF / HAIP tests the signing cert must be **CA-signed** (not
self-signed) and the trust anchor must **not** appear in the `x5c` header
(HAIP 6.1.1). `generate-chain.sh` builds exactly that — a self-signed Root CA
that signs the e-Seal leaf:

```bash
cd dev-tools/issuer-eseal
./generate-chain.sh            # writes into the current directory
# or: ./generate-chain.sh /path/to/output
```

Outputs:

| File | Role |
| ---- | ---- |
| `root-ca.crt` | **Trust anchor** — paste into the OIDF "Request Object Trust Anchor" / "Signing JWK" field. Never shipped in `x5c`. |
| `issuer-cert.pem` | CA-signed e-Seal **leaf** — loaded by `PemKeyLoader`, goes into `x5c`. |
| `issuer-key.pem` | Leaf private key (PKCS#8). |
| `root-ca.key` | CA private key — keep safe, or discard for a throwaway test CA. |

The script verifies the chain (`openssl verify`) and prints the leaf
subject/issuer so you can confirm they differ (i.e. not self-signed). To use
it as the **verifier** signing material instead, rename the leaf outputs to
`verifier-cert.pem` / `verifier-key.pem` (the verifier role reads those names).

## Step 2 — Inspect the result (optional)

```bash
openssl x509 -in issuer-eseal.crt -text -noout
```

Expected highlights:

- `Subject: C=ES, O=Fikua Lab, organizationIdentifier=VATES-B00000001, CN=Fikua Lab e-Seal (test)`
- `Key Usage: critical, Digital Signature, Non Repudiation`
- `Subject Alternative Name: DNS:dss.fikua.com`
- EC public key, `NIST CURVE: P-256`

## Step 3 — Deploy to the DSS

### Local run

```bash
mkdir -p ../../../fikua-digital-signature-service/certs
cp issuer-eseal.crt issuer-eseal.key \
   ../../../fikua-digital-signature-service/certs/
```

Then point the DSS at them (defaults already match in the deploy compose):

```bash
java -jar fikua-digital-signature-service-*.jar \
  --dss.certificate.cert-path=file:./certs/issuer-eseal.crt \
  --dss.certificate.key-path=file:./certs/issuer-eseal.key
```

### VPS deploy

Copy both files to the DSS cert directory on the host and restart the service:

```bash
scp issuer-eseal.crt issuer-eseal.key \
    <vps>:/opt/vps/projects/fikua-lab/dss/certs/
# on the VPS:
cd /opt/vps/projects/fikua-lab/dss && docker compose up -d --force-recreate dss
```

The DSS `/health` endpoint reports `"status":"UP"` only when the cert + signing
key load correctly, so a bad pair removes the container from Traefik rotation.

## Profile notes (eIDAS / ETSI)

- **e-Seal vs representative cert.** This profile (ETSI EN 319 412-3, legal
  person) differs from `dev-tools/issuer-cert/` and
  `dev-tools/eidas-certification-builder/` (ETSI EN 319 412-2, natural
  person / representative). The e-Seal has no natural-person identity in the
  subject.
- **qcStatements.** A real qualified e-Seal carries `QcCompliance`,
  `QcType = eseal` (`0.4.0.1862.1.6.2`) and (if QSCD-protected) `QcSSCD`.
  `openssl req` does not encode these cleanly, so they are documented in the
  `.cnf` as reference but omitted from the test cert.
