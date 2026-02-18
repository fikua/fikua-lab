# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-02-18

HAIP authorization_code flow for OIDF Test #1 (OID4VCI Issuer Final/HAIP).

### Added
- **P2.1 — PAR persistence:** `InMemoryStore` stores PAR request parameters keyed by `request_uri`, consumed on authorize
- **P2.2 — Authorize resolves PAR:** `GET /authorize` resolves `request_uri` from the PAR store, extracting `client_id`, `redirect_uri`, `code_challenge`, `state`, `issuer_state`
- **P2.3 — PKCE verification:** `handleAuthCodeToken` verifies `code_verifier` against stored `code_challenge` using `PkceUtil.verifyS256()` (RFC 7636)
- **P2.4 — DPoP key binding:** Credential endpoint verifies that the DPoP proof thumbprint matches the key bound at the token endpoint (RFC 9449 §6)
- **P2.5 — Client attestation:** `ClientAttestationValidator` parses `client_assertion` (WIA~PoP format), extracts `client_id`; integrated at PAR and token endpoints
- **P2.6 — Credential response encryption metadata:** `CredentialIssuerMetadata` advertises `credential_response_encryption` with `ECDH-ES` / `A128GCM` / `A256GCM` for HAIP profiles

### Spec references
- RFC 9126 (PAR), RFC 7636 (PKCE), RFC 9449 (DPoP), HAIP 1.0, OAuth Attestation-Based Client Authentication

## [0.1.0] - 2026-02-18

Initial OID4VCI implementation with pre-authorized code flow and metadata conformity.

### Added
- **P0.1 — Credential Issuer Metadata:** `nonce_endpoint` and `notification_endpoint` top-level fields
- **P0.2 — Format migration:** `vc+sd-jwt` → `dc+sd-jwt` across metadata, credential config ID, and scope
- **P0.3 — Credential metadata structure:** Claims migrated to array with `path` format inside `credential_metadata` wrapper (OID4VCI 1.0 Final)
- **P0.4 — AS Metadata cleanup:** Removed `credential_nonce_endpoint` from `AuthServerMetadata`
- **P0.5 — SD-JWT typ header:** Changed from `vc+sd-jwt` to `dc+sd-jwt` (SD-JWT VC draft-13+)
- **P0.6 — x5c chain:** Pass X.509 certificate chain to `SdJwtBuilder` for issuer credential signing
- **Issuance trigger:** `POST /oid4vci/v1/issuance` with abstract `credential_data` JSONB model
- **Profile system:** Seed profiles on startup, profile-based metadata and flow switching
- **Pre-auth flow:** Token endpoint, credential endpoint with SD-JWT VC issuance, nonce management
- **HAIP flow (skeleton):** Authorization endpoint, PAR endpoint, DPoP validation (basic)
- **Infrastructure:** Java 25 + Gradle 9.1.0, PostgreSQL 17 + Flyway, Javalin 6.6.0, Docker deployment, nginx reverse proxy with mTLS

### Spec references
- OID4VCI 1.0 Final, SD-JWT VC draft-14, RFC 8414 (AS Metadata), HAIP 1.0
