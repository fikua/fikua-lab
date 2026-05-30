#!/usr/bin/env bash
# =============================================================================
# Fikua Lab — generate a 2-level e-Seal chain (Root CA -> e-Seal leaf)
#
# HAIP 6.1.1 wants the signing cert (leaf) to be CA-signed (NOT self-signed),
# and the trust anchor (root CA) to be EXCLUDED from the x5c header. This
# script produces exactly that:
#
#   root-ca.crt        the self-signed trust anchor  -> paste into the OIDF
#                      "Request Object Trust Anchor" / "Signing JWK" field;
#                      NEVER shipped in x5c.
#   issuer-cert.pem    the CA-signed e-Seal leaf      -> the cert PemKeyLoader
#                      loads; goes into x5c (leaf only).
#   issuer-key.pem     the leaf private key (PKCS#8)   -> gitignored.
#
# A subject can be issuer (default) or verifier; the only difference is the
# output dir hint printed at the end. The cryptographic profile is identical.
#
# Usage:
#   ./generate-chain.sh                 # writes into the current directory
#   ./generate-chain.sh /path/to/out    # writes into /path/to/out
#
# Re-run is idempotent: it overwrites the four output files.
# =============================================================================
set -euo pipefail

OUT_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEAF_CNF="${SCRIPT_DIR}/issuer-eseal-eidas.cnf"   # reused for the leaf subject DN
CA_CNF="${SCRIPT_DIR}/root-ca-eidas.cnf"
DAYS_CA=1825   # 5y
DAYS_LEAF=730  # 2y

mkdir -p "${OUT_DIR}"
cd "${OUT_DIR}"

echo "==> 1/4  Root CA key + self-signed CA certificate"
openssl req -new -x509 \
  -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout root-ca.key \
  -out root-ca.crt \
  -days "${DAYS_CA}" -sha256 \
  -config "${CA_CNF}"

echo "==> 2/4  e-Seal leaf key + CSR (subject from issuer-eseal-eidas.cnf)"
openssl req -new \
  -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout issuer-key.pem \
  -out leaf.csr \
  -config "${LEAF_CNF}"

echo "==> 3/4  CA signs the leaf (NOT self-signed; HAIP 6.1.1)"
# A fresh serial each run; the leaf extensions come from the CA cnf section.
openssl x509 -req \
  -in leaf.csr \
  -CA root-ca.crt -CAkey root-ca.key \
  -CAcreateserial \
  -out issuer-cert.pem \
  -days "${DAYS_LEAF}" -sha256 \
  -extfile "${CA_CNF}" -extensions v3_eseal_leaf

echo "==> 4/4  Verify the chain (leaf <- root) and clean up"
openssl verify -CAfile root-ca.crt issuer-cert.pem
rm -f leaf.csr root-ca.srl

# Normalise the leaf key to PKCS#8 (BEGIN PRIVATE KEY) — PemKeyLoader expects it.
openssl pkcs8 -topk8 -nocrypt -in issuer-key.pem -out issuer-key.pkcs8.pem
mv issuer-key.pkcs8.pem issuer-key.pem

echo
echo "Done. Files in ${OUT_DIR}:"
echo "  root-ca.crt      <- TRUST ANCHOR (OIDF field); NOT in x5c"
echo "  issuer-cert.pem  <- CA-signed leaf; goes in x5c"
echo "  issuer-key.pem   <- leaf private key (PKCS#8, gitignored)"
echo "  root-ca.key      <- CA private key (keep safe / discard for a throwaway test CA)"
echo
echo "Leaf subject / issuer (must differ -> not self-signed):"
openssl x509 -in issuer-cert.pem -noout -subject -issuer
