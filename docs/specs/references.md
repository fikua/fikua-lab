# References — Fikua Lab Normative and Informative Sources

**Created:** 2026-02-18
**Updated:** 2026-02-19
**Status:** Living document
**Purpose:** Index centralitzat d'especificacions, RFCs, exemples oficials i recursos que Fikua Lab implementa. Consultar sempre aquest document abans de buscar una spec.

---

## Jerarquia normativa

```text
ARF 2.8 (EU regulatory layer)
  └── HAIP 1.0 (technical profile)
       ├── OID4VCI 1.0 Final (issuance)
       ├── OID4VP 1.0 Final (presentation)
       ├── SD-JWT VC draft-14 (credential format)
       ├── Token Status List draft-12 (revocation)
       ├── RFC 9449 (DPoP)
       ├── RFC 7636 (PKCE)
       └── RFC 8414 (AS Metadata)
```

---

## Especificacions principals

### OID4VCI — OpenID for Verifiable Credential Issuance

| Recurs | URL |
|--------|-----|
| OID4VCI 1.0 Final (spec HTML) | https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html |
| OID4VCI 1.0 Exemples oficials (GitHub) | https://github.com/openid/OpenID4VCI/tree/main/1.0/examples |
| Credential Issuer Metadata example (sd-jwt long) | https://github.com/openid/OpenID4VCI/blob/main/1.0/examples/credential_issuer_metadata_sd_jwt_long.json |
| Credential Metadata example (sd-jwt vc) | https://github.com/openid/OpenID4VCI/blob/main/1.0/examples/credential_metadata_sd_jwt_vc.json |
| OID4VCI repo (WG drafts i issues) | https://github.com/openid/OpenID4VCI |

**Seccions clau:**
- §4.1 — Credential Offer
- §4.2 — Credential Offer URIs
- §6 — Token Endpoint (pre-auth i auth code grants)
- §7 — Credential Endpoint
- §7.2.1 — Proof of Possession (JWT proof)
- §8 — Nonce Endpoint
- §9 — Deferred Credential Endpoint
- §10 — Credential Issuer Metadata
- §11 — Notification Endpoint

### OID4VP — OpenID for Verifiable Presentations

| Recurs | URL |
|--------|-----|
| OID4VP 1.0 Final (spec HTML) | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html |
| OID4VP repo (WG drafts i issues) | https://github.com/openid/OpenID4VP |

### HAIP — High Assurance Interoperability Profile

| Recurs | URL |
|--------|-----|
| HAIP 1.0 (spec HTML) | https://openid.github.io/OpenID4VC-HAIP/openid4vc-high-assurance-interoperability-profile-wg-draft.html |
| HAIP repo | https://github.com/openid/OpenID4VC-HAIP |

**Requeriments HAIP rellevants per Fikua Lab:**
- Grant type: `authorization_code` (obligatori)
- DPoP: obligatori (RFC 9449)
- PKCE: `S256` obligatori (RFC 7636)
- PAR: obligatori (RFC 9126)
- Client auth: `attest_jwt_client_auth` (WIA)
- Credential format: `dc+sd-jwt`
- Key binding: `jwk`
- Nonce endpoint: obligatori
- Response encryption: suportat

### SD-JWT VC — SD-JWT-based Verifiable Credentials

| Recurs | URL |
|--------|-----|
| SD-JWT VC draft-14 (IETF datatracker) | https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/ |
| SD-JWT VC draft-14 (text complet) | https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-14.html |
| SD-JWT base spec (RFC 9796) | https://www.rfc-editor.org/rfc/rfc9796 |

**Notes:**
- `typ` header canviat de `vc+sd-jwt` a `dc+sd-jwt` a partir del draft-13
- `vct` (Verifiable Credential Type) és obligatori
- Key binding via `cnf` claim amb `jwk`

### Token Status List (revocació)

| Recurs | URL |
|--------|-----|
| Token Status List draft-12 (IETF datatracker) | https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-12 |
| Token Status List draft-12 (text complet) | https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-12.html |

**Notes:**
- Mecanisme de revocació correcte per SD-JWT VC (NO BitstringStatusList, que és W3C)
- Bit array comprimit (DEFLATE+ZLIB)
- Token format: `statuslist+jwt`
- Claim a la credencial: `status.status_list` amb `idx` i `uri`

---

## RFCs de suport

| RFC | Títol | URL | Rellevància |
|-----|-------|-----|-------------|
| RFC 9449 | DPoP (Demonstrating Proof of Possession) | https://www.rfc-editor.org/rfc/rfc9449 | Sender constraining per HAIP |
| RFC 7636 | PKCE (Proof Key for Code Exchange) | https://www.rfc-editor.org/rfc/rfc7636 | S256 obligatori per HAIP |
| RFC 9126 | PAR (Pushed Authorization Requests) | https://www.rfc-editor.org/rfc/rfc9126 | Obligatori per HAIP |
| RFC 8414 | OAuth 2.0 Authorization Server Metadata | https://www.rfc-editor.org/rfc/rfc8414 | `.well-known/oauth-authorization-server` |
| RFC 6749 | OAuth 2.0 Authorization Framework | https://www.rfc-editor.org/rfc/rfc6749 | Base de tot el flux OAuth |
| RFC 6750 | Bearer Token Usage | https://www.rfc-editor.org/rfc/rfc6750 | Ús de tokens `Authorization: Bearer` |
| RFC 7519 | JSON Web Token (JWT) | https://www.rfc-editor.org/rfc/rfc7519 | Format JWT base |
| RFC 7515 | JSON Web Signature (JWS) | https://www.rfc-editor.org/rfc/rfc7515 | Signatura JWT |
| RFC 7516 | JSON Web Encryption (JWE) | https://www.rfc-editor.org/rfc/rfc7516 | Credential response encryption |
| RFC 7517 | JSON Web Key (JWK) | https://www.rfc-editor.org/rfc/rfc7517 | Format de claus |
| RFC 7518 | JSON Web Algorithms (JWA) | https://www.rfc-editor.org/rfc/rfc7518 | Algoritmes (ES256, etc.) |

---

## EU Regulatory Framework

| Recurs | URL | Descripció |
|--------|-----|------------|
| ARF 2.8 | https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework | Architecture Reference Framework |
| eIDAS 2.0 Regulation | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1183 | Reglament (UE) 2024/1183 |
| EUDI Wallet Toolbox | https://github.com/eu-digital-identity-wallet | Repos oficials EU (referència, libs, demos) |

---

## OIDF Conformance Testing

| Recurs | URL | Descripció |
|--------|-----|------------|
| OIDF Conformance Suite | https://www.certification.openid.net/ | Plataforma de tests de conformitat |
| OIDF Test Plans | https://www.certification.openid.net/plan.html | Configuració de plans de test |

**Tests rellevants per Fikua Lab (12 tests):**

| # | Test | Rol Fikua | Perfil |
|---|------|-----------|--------|
| 1 | OID4VCI Credential Issuer (HAIP) | Issuer | authorization_code + DPoP + PAR + PKCE |
| 2 | OID4VCI Credential Issuer (Plain) | Issuer | pre-authorized_code |
| 3 | OID4VCI Wallet (HAIP) | Wallet | authorization_code + DPoP |
| 4 | OID4VCI Wallet (Plain) | Wallet | pre-authorized_code |
| 5 | OID4VP Verifier (HAIP) | Verifier | DCQL + response encryption |
| 6 | OID4VP Verifier (Plain) | Verifier | presentation_definition |
| 7 | OID4VP Wallet (HAIP) | Wallet | DCQL + response encryption |
| 8 | OID4VP Wallet (Plain) | Wallet | presentation_definition |
| 9 | OID4VCI Credential Issuer (HAIP, auth code, no DPoP) | Issuer | authorization_code sense DPoP |
| 10 | OID4VCI Credential Issuer (Plain, by_reference) | Issuer | pre-authorized_code, offer by_reference |
| 11 | OID4VP Verifier (response_uri) | Verifier | response_uri mode |
| 12 | OID4VP Wallet (response_uri) | Wallet | response_uri mode |

---

## Implementacions de referència

| Projecte | URL | Llenguatge | Notes |
|----------|-----|------------|-------|
| walt.id (SSI Kit) | https://github.com/walt-id/waltid-identity | Kotlin | Issuance, verification, wallet. Bona referència per SD-JWT |
| Sphereon OID4VCI | https://github.com/Sphereon-Opensource/OID4VCI | TypeScript | Client i server OID4VCI. Bona referència per al wallet |
| EUDI Wallet Reference | https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-sdjwt-kt | Kotlin | Lib oficial EU per SD-JWT |
| nimbus-jose-jwt | https://connect2id.com/products/nimbus-jose-jwt | Java | Llibreria que fem servir per JWT/JWS/JWE/JWK |
| nimbus-jose-jwt JavaDoc | https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/latest/index.html | Java | API reference |

---

## Eines de desenvolupament

| Eina | URL | Ús |
|------|-----|-----|
| jwt.io | https://jwt.io/ | Decodificar i inspeccionar JWTs |
| SD-JWT Debugger | https://sdjwt.info/ | Decodificar SD-JWTs amb disclosures |
| Base64 decode | https://www.base64decode.org/ | Decodificar valors base64/base64url |

---

## Documentació interna Fikua Lab

### Specs i anàlisi

| Document | Path | Descripció |
|----------|------|------------|
| Technical Document (source of truth) | `docs/fikua-lab-dt.md` | Arquitectura, decisions, endpoints, deployment |
| Credential Issuance Flow | `docs/specs/credential-issuance-flow.md` | Flux d'emissió en 15 passos, gaps i prioritats |
| References (aquest document) | `docs/specs/references.md` | Index de specs i recursos externs |
| OIDF Test Configurations | `docs/analysis/oidf-test-configurations.md` | 12 tests OIDF amb paràmetres configurables |

### Agents Claude Code

| Agent | Path | Funció |
| ------- | ------ | -------- |
| Entry point | `CLAUDE.md` | Instruccions generals, routing cap als agents, convencions |
| Developer | `.claude/agents/DEVELOPER.md` | Workflow d'implementació, commits, tests |
| Reviewer | `.claude/agents/REVIEWER.md` | Revisió de conformitat, checklist, report format |
