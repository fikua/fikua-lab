# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.2] - 2026-02-24

Wallet QR scanner performance — hybrid BarcodeDetector + Web Worker architecture.

### Changed

- **QR scanner rewritten as hybrid decoder:** Native `BarcodeDetector` API for Chrome/Edge Android (~0ms decode, ~30-60 fps). Web Worker fallback with `qr` library for iOS Safari/Firefox (off main thread, 0ms UI blocking, ~8-10 fps). Previously, `decodeQR` ran synchronously on the main thread blocking rendering for 15-25ms per frame.
- **New `qr-decode-worker.ts`:** Dedicated Web Worker that imports `decodeQR` and processes frames via `postMessage` with `Transferable` buffer (zero-copy). Vite bundles it as a separate chunk automatically.
- **Worker backpressure:** `workerBusy` flag prevents queuing frames while a decode is in progress. Throttle reduced from 150ms to 100ms since decode no longer blocks the main thread.
- **6 Vitest tests** in `qr-scanner.test.ts` (+1 new: worker termination on abort). Tests mock `Worker` and `BarcodeDetector` globals via `vi.stubGlobal`.

## [0.9.1] - 2026-02-24

Wallet QR scanner, protocol logs, and UI polish.

### Fixed

- **QR scanner decoding:** The QR scanner previously only opened the camera but did not decode QR codes — users had to manually paste URIs. Now uses `qr` library (Paul Miller, 0-dep, ~16KB gzipped) with a `requestAnimationFrame` loop throttled to ~7 fps. Canvas downscaled to max 480px for faster decode. `willReadFrequently` hint for optimal `getImageData()`. `AbortController` for clean cancellation. Frame counter status indicator with pulse animation.
- **Greeting simplified:** Removed "User Wallet" / fallback name from the greeting — now shows just "Hello,".

### Added

- **`qr-scanner.ts` module:** `startScanning(video, callbacks) → AbortController` — encapsulates the decode loop, canvas management, frame throttling, and status callbacks (`onResult`, `onStatus`).
- **Protocol Logs tab:** New "Logs" tab with timestamped, color-coded log entries (INFO/STEP/OK/ERROR). Logs OID4VCI flow progress — issuer metadata, token, nonce, proof, credential response. Monospace font, max 200 entries, auto-scroll.
- **`plog()` logging system:** Internal protocol logger integrated into `updateFlowStatus`, `showFlowError`, `handleOfferUri`, and `executeIssuanceFlow`.
- **5 new Vitest tests** in `qr-scanner.test.ts` — AbortController lifecycle, rAF scheduling, abort cancellation, video readyState guard, continuous frame scheduling.

## [0.9.0] - 2026-02-24

Issuer frontend redesign with credential selector, dynamic form, QR/deeplink, and paginated issuance records management.

### Added

- **Issuer credential selector:** Fetches `/.well-known/openid-credential-issuer` and displays all 12 credential configurations as cards with name, format badge (sd-jwt/mdoc), and description. Click selects configuration and opens dynamic form.
- **Dynamic issuance form:** Form fields generated from credential configuration claims metadata. Backend-managed fields (`issuing_authority`, `issuing_country`) are hidden. Supports transaction code option. Submit triggers `POST /oid4vci/v1/issuance` with credential data.
- **QR code + deeplink result:** After successful issuance, shows QR code (via qrcode-generator CDN), copyable offer URI, "Open in Wallet" deeplink (`openid-credential-offer://`), and transaction code badge when applicable.
- **Issuance records management (tab "Records"):** Paginated table with columns ID (short UUID), Subject (extracted from credential data), Type (badge), Status (colored badge), Created. Click-sortable columns. Click row opens `<dialog>` with full record detail including credential data claims.
- **`GET /oid4vci/v1/issuance` endpoint:** Backend paginated listing with `page`, `size`, `sort`, `order` query params. Returns records with `subject_name` extracted from `credential_data` JSON (`given_name` + `family_name`). Whitelist-validated sort fields and order.
- **`IssuanceStore.findAll()` + `count()`:** New port methods for paginated record retrieval. Implemented in `JdbcIssuanceStore` with SQL `ORDER BY` / `LIMIT` / `OFFSET` and safe field/order whitelisting.

### Removed

- **Certificate-based identification flow:** Issuer frontend no longer redirects to `cert.lab.fikua.com` for certificate selection. The identification portal (`identify.lab.fikua.com`) handles user identification for wallet-initiated flows. Issuer UI now directly issues credentials via the admin portal.

## [0.8.0] - 2026-02-24

Wallet mso_mdoc support, full privacy blur, PWA install flow, and responsive fixes.

### Added

- **mso_mdoc credential parsing (ISO 18013-5):** New `cbor.ts` — minimal CBOR decoder (RFC 8949) supporting unsigned/negative ints, byte strings, text strings, arrays, maps, tags (including tag 24 encoded-cbor), and simple values. New `mdoc.ts` — parses base64url-encoded IssuerSigned CBOR into structured `ParsedMdoc` with claims extraction from nameSpaces, docType from MSO, and validity dates from validityInfo.
- **Format-aware credential processing:** `processCredentialResponse()` now dispatches by credential format — `mso_mdoc` uses `parseMdoc()`, `dc+sd-jwt` uses `parseSdJwt()`. Consent dialog and credential storage are format-agnostic.
- **PWA install phase at login:** New first-time user experience — when no passkey exists and the app is not installed, the login screen shows an "Install App" phase with install button and "Continue in browser" skip option. iOS Safari shows Share > Add to Home Screen instructions.
- **PNG PWA icons:** Added `icon-192.png`, `icon-512.png`, and `apple-touch-icon.png` for proper PWA manifest and iOS home screen display. SVG favicon updated to 512x512 with rounded rect.
- **17 new Vitest tests** across 2 test files:
  - `cbor.test.ts` (11) — unsigned/negative ints, text/byte strings, arrays, maps (string + integer keys), tag 24 (encoded-cbor), tag 0 (datetime), simple values, nested structures
  - `mdoc.test.ts` (6) — claims extraction, docType from MSO, validity dates, raw preservation, multiple elements, invalid CBOR error

### Changed

- **Full privacy blur:** Privacy mode now blurs all credential content — title, issuer, format, algorithm, status badge, claim labels, claim values, section headers, activity names, timestamps. Previously only claim values and activity details were blurred.
- **Identify portal responsive:** Added `@media (max-width: 480px)` breakpoints for small mobile screens — stacked layouts, hidden nav name, full-width buttons, smaller icons.

### Spec references

- ISO 18013-5 (IssuerSigned structure, IssuerSignedItem, MSO), RFC 8949 (CBOR), OID4VCI 1.0 Final Appendix A.2.4 (mso_mdoc credential response)

## [0.7.0] - 2026-02-24

Wallet PWA — OID4VCI client with Vite + TypeScript, Web Crypto holder binding, and unit tests.

### Added

- **Wallet PWA (Vite + TypeScript):** Complete rewrite of the holder frontend from vanilla JS to a modular TypeScript application bundled with Vite. Installable as a Progressive Web App with offline caching via Workbox (`vite-plugin-pwa`).
- **OID4VCI client-side protocol engine:** Full implementation of the credential issuance flow — credential offer parsing (by_value / by_reference), issuer metadata discovery, token request, nonce request, proof JWT generation, credential request, and issuer notification. Supports both pre-authorized code (Plain profile) and authorization code (HAIP profile) grant types.
- **Holder binding with Web Crypto API:** EC P-256 key pairs generated per credential. Private keys are non-extractable (`CryptoKey` handles stored in IndexedDB via structured clone). Public keys exported as JWK for proof JWT headers. DPoP/WIA keys are extractable for sessionStorage serialization during auth code redirect.
- **DPoP proof and WIA generation:** `buildDpopProof()` with htm/htu/iat/jti/ath/nonce claims. Self-signed WIA (`wallet-attestation+jwt`) and WIA PoP (`wallet-attestation-pop+jwt`) for HAIP testing.
- **PAR support:** Pushed Authorization Requests with DPoP + client attestation headers, PKCE S256, and state management across browser redirect.
- **SD-JWT VC parser:** Splits SD-JWT by `~`, decodes JWT header + payload, parses disclosures (base64url → [salt, name, value]), merges claims with internal field exclusion (`_sd`, `_sd_alg`, `cnf`, `status`).
- **IndexedDB persistence:** Two object stores — `credentials` (keyed by id, with issuedAt index) and `activity` (auto-increment, with timestamp index). Raw API, no framework.
- **Wallet-initiated issuance:** "Add Credential" button fetches `.well-known/openid-credential-issuer` from the hardcoded issuer (`https://issuer.lab.fikua.com`), lists available credential configurations, and starts the auth code flow on user selection.
- **Issuer-initiated issuance:** Detects `credential_offer` / `credential_offer_uri` in URL query params at init. Offers received before authentication are preserved in sessionStorage.
- **Credential consent UI:** Promise-based accept/reject dialog showing decoded claims and issuer info before storing the credential.
- **Credential detail view:** Click on credential card → full detail with claims, metadata (algorithm, dates, vct, issuer URL), and delete button with issuer notification (`credential_deleted` event).
- **Privacy mode:** Eye icon toggle blurs claim values and personal data in activity. Title + issuer remain visible. Persisted in localStorage.
- **Activity logging:** All issuance/deletion/failure events logged to IndexedDB with action, credential name, issuer identity, type, timestamp, and optional details.
- **QR scanner:** Camera-based QR code scanning with manual URI input fallback for credential offers.
- **PWA install prompt:** Captures `beforeinstallprompt` event, shows "Install App" button, hidden after installation.
- **WebAuthn passkey authentication:** Preserved from previous implementation. Platform authenticator with user verification.
- **60 Vitest unit tests** across 5 test files:
  - `utils.test.ts` (15) — base64url encode/decode round-trip, JSON round-trip, XSS escaping, date formatting, random string generation
  - `crypto.test.ts` (13) — EC P-256 key generation (extractable/non-extractable), export/import round-trip, SHA-256 known vectors, JWT structure (3-part, 64-byte raw signature), PKCE
  - `sdjwt.test.ts` (9) — header/payload parsing, disclosure extraction, claim merging, internal field exclusion, malformed segment handling, numeric/object values
  - `protocol.test.ts` (13) — credential offer parsing (by_value/by_reference/URL-encoded), grant analysis (pre-auth/auth-code/preference/error), getPreAuthCode, getPreAuthTxCode
  - `storage.test.ts` (10) — IndexedDB CRUD (save/get/getAll/delete/upsert), activity logging (details, auto-increment, null handling)

### Technical details

- **Build:** Vite 7.3 + TypeScript 5.9 (strict mode, ES2022 target, bundler module resolution)
- **PWA:** `vite-plugin-pwa` with Workbox — precache statics, NetworkOnly for API routes (`/oid4vci/`, `/oid4vp/`, `/admin/`, `/.well-known/`)
- **Test framework:** Vitest 4.0 with jsdom environment + fake-indexeddb
- **DER-to-raw signature conversion:** Custom `derToRaw()` for ES256 JWT compatibility (WebCrypto returns DER-encoded ECDSA, JWT requires raw R||S 64 bytes)
- **Module structure:** `types.ts`, `constants.ts`, `utils.ts`, `crypto.ts`, `storage.ts`, `sdjwt.ts`, `protocol.ts`, `main.ts`
- **Dev server:** Vite on port 3004 with proxy to backend on port 8090 (`/.well-known`, `/oid4vci`, `/oid4vp`, `/admin`)

### Spec references

- OID4VCI 1.0 Final (Credential Offer §4.1, Token §6, Nonce §7, Credential §8, Notification §10), HAIP 1.0 (DPoP, PAR, PKCE S256, Client Attestation), SD-JWT VC draft-14, RFC 9449 (DPoP), RFC 9126 (PAR), RFC 7636 (PKCE), RFC 7515 (JWS/ES256), OAuth Attestation-Based Client Authentication

## [0.6.2] - 2026-02-24

Credential response returns IssuerSigned CBOR per OID4VCI A.2.4.

### Fixed

- **mso_mdoc credential response (OID4VCI A.2.4):** `MdocBuilder.build()` now returns the `IssuerSigned` CBOR structure (`issuerAuth` + `nameSpaces`) instead of the full ISO 18013-5 `Document` wrapper (which included `docType` at the root level). Per OID4VCI Appendix A.2.4, the credential response value is the base64url-encoded `IssuerSigned`, not the `Document`. Fixes OIDF test `ParseMdocCredentialFromVCIIssuance` / `ValidateMdocIssuerSignedSignature`.
- **issuerAuth field ordering:** `issuerAuth` is now the first field in the `IssuerSigned` CBOR map, matching the OIDF conformance suite expectation.
- **Untagged COSE_Sign1 in IssuerSigned:** `CoseSign1.sign()` no longer wraps the array with CBOR tag 18. When embedded inside the IssuerSigned map, COSE_Sign1 must be an untagged array (confirmed by multipaz reference implementation).
- **MSO payload wrapped in tag 24:** COSE_Sign1 payload is now `#6.24(bstr .cbor MSO)` per ISO 18013-5 `MobileSecurityObjectBytes` definition. Previously the raw MSO bytes were used as payload.

### Spec references

- OID4VCI 1.0 Final Appendix A.2.4 (Credential Response — IssuerSigned structure), ISO 18013-5 §8.3.2.1.2.2, RFC 9052 §4.4 (COSE_Sign1)

## [0.6.1] - 2026-02-23

COSE algorithm identifiers for mso_mdoc metadata.

### Fixed

- **mso_mdoc `credential_signing_alg_values_supported` (OID4VCI A.2.2):** Changed from string `"ES256"` to integer COSE identifier `-7` for mso_mdoc credential configurations. Per OID4VCI Appendix A.2.2, mso_mdoc uses numeric COSE algorithm identifiers (IANA COSE Algorithms Registry), not JWS string identifiers. `dc+sd-jwt` configs correctly use string `"ES256"`. Fixes OIDF test `VCICredentialIssuerMetadataValidation`.

### Spec references

- OID4VCI 1.0 Final Appendix A.2.2 (mso_mdoc Credential Issuer Metadata), IANA COSE Algorithms Registry (ES256 = -7)

## [0.6.0] - 2026-02-23

mso_mdoc PID credential support and 12 OIDF credential configurations.

### Added

- **mso_mdoc credential builder (ISO 18013-5):** New `com.fikua.core.mdoc` package with `CoseSign1` (RFC 9052 §4.4), `MdocBuilder` (ISO 18013-5 Document structure with IssuerSignedItem tag 24, MSO with valueDigests/deviceKeyInfo/validityInfo), and `MdocDocument` record. Supports EC P-256 (ES256) signing with x5c certificate chain.
- **CBOR dependency:** `com.upokecenter:cbor:4.5.2` added to fikua-core (pure Java, zero I/O).
- **SigningKey.signRawBytes():** Raw ECDSA signing (`SHA256withECDSAinP1363Format`) for COSE_Sign1 signatures (r||s 64 bytes for P-256).
- **12 OIDF credential configurations in metadata:** Issuer metadata now exposes all credential configurations the OIDF conformance suite expects — 6 sd-jwt PID variants (base, attestation, jwt.keyattest, attestation.keyattest, jwt_and_attestation.keyattest, nobinding), 4 mdoc PID variants (base, attestation, jwt.keyattest, attestation.keyattest), and 2 mDL variants (base, attestation).
- **Format-aware credential issuance:** `issueCredential()` dispatches by `credential_configuration_id` format — `dc+sd-jwt` builds SD-JWT VC, `mso_mdoc` builds mdoc Document via `MdocBuilder`.
- **21 new tests:** CoseSign1Test (8), MdocBuilderTest (10), CredentialIssuerMetadataTest multi-config (1), IssuanceServiceTest mdoc scope/claims (2).

### Fixed

- **CredentialFormat enum:** `SD_JWT_VC` oid4vciFormat corrected from `vc+sd-jwt` to `dc+sd-jwt`.

### Spec references

- ISO 18013-5 (mobile documents), RFC 9052 §4.4 (COSE_Sign1), RFC 8949 (CBOR), OID4VCI 1.0 Final §10 (credential_configurations_supported)

## [0.5.0] - 2026-02-23

Wallet-initiated issuance flow with identification portal.

### Added

- **Wallet-initiated flow with identification:** Authorize endpoint now supports wallet-initiated issuance (no Credential Offer, no `issuer_state`). When the wallet starts the flow via PAR + authorize without `issuer_state`, the issuer redirects the browser to the identification portal (`identify.lab.fikua.com`) where the user verifies their identity via digital certificate. After identification, the issuer creates an `IssuanceRecord` with real credential data and returns the authorization code to the wallet. Per RFC 6749 §3.1: the AS MUST authenticate the resource owner before issuing an authorization code.
- **Identification portal frontend:** New `identify.lab.fikua.com` mini-app with method selection (digital certificate via cert.lab), certificate data confirmation, and automatic redirect to wallet callback. Extensible for future identification methods (manual form, etc.).
- **`POST /oid4vci/v1/identify/complete` endpoint:** Receives credential data from the identification portal, creates `IssuanceRecord`, generates authorization code, and returns the wallet callback redirect URL.
- **Pending authorization pattern:** `SessionStore.storePendingAuthorization()` / `consumePendingAuthorization()` preserve PAR data while the user identifies at the portal.
- **`identifyBaseUrl` configuration:** New `FIKUA_IDENTIFY_BASE_URL` env var / `identify-base-url` YAML config (default: `https://identify.lab.fikua.com`).
- **Nginx server block:** `identify.lab.fikua.com` with static frontend + `/oid4vci/v1/` proxy to backend.
- **4 tests** in `IssuanceServiceTest` — wallet-initiated redirects to identification portal, issuer-initiated returns code immediately, complete identification creates record and returns code, invalid session throws error (5 → 9 total in fikua-issuer).

### Spec references

- RFC 6749 §3.1 (Authorization Endpoint — resource owner authentication), OID4VCI 1.0 Final §3.4 (wallet-initiated issuance), §5.1.1 (Authorization Request), HAIP 1.0

## [0.4.7] - 2026-02-22

Client attestation robustness and PAR fix.

### Fixed

- **Client attestation optional at PAR/token:** Removed mandatory client attestation check at PAR and token endpoints. The OIDF test does not send `client_assertion` — attestation is now validated when present but not required. The `ClientAttestationValidator.validate()` returns `null` when no attestation is provided. Fixes OIDF test `PAR-2.2/2.3` (`CheckPAREndpointResponse201WithNoError`).
- **Algorithm-agnostic PoP verification (OAuth ATCA):** `ClientAttestationValidator` now supports any asymmetric key type (EC, RSA, OKP) for PoP signature verification via `DefaultJWSVerifierFactory`. Previously, only EC keys with `ECDSAVerifier` were supported.
- **cnf.jkt fallback:** When WIA `cnf` contains `jkt` (JWK Thumbprint) instead of `jwk`, the validator extracts the key from the PoP header and verifies the thumbprint matches.
- **Generic cnf key extraction:** `extractCnfKey()` now uses `JWK.parse()` (was `ECKey.parse()`), accepting any JWK key type.
- **Diagnostic logging:** Detailed logging of WIA/PoP JWT headers and claims on parse for conformance test diagnosis.

### Spec references

- OAuth Attestation-Based Client Authentication §4 (cnf claim), RFC 9126 §2.2/2.3 (PAR success response)

## [0.4.6] - 2026-02-21

PAR endpoint client attestation enforcement and HTTP status fix.

### Fixed

- **PAR requires client attestation (OAuth ATCA §4):** PAR endpoint now rejects requests without `client_assertion` / `client_assertion_type` with HTTP 401 `invalid_client`. Previously, missing attestation was silently accepted and the PAR returned 201. Fixes OIDF test `OAuth2-ATCA07-1` (`EnsureHttpStatusCodeIs400or401`).
- **HTTP 401 for `invalid_client` errors:** `ClientAttestationValidator` now returns HTTP 401 (was 400) for all client authentication failures. Per RFC 6749 §5.2, `invalid_client` indicates failed client authentication which maps to 401.

### Spec references

- OAuth Attestation-Based Client Authentication §4, RFC 6749 §5.2 (invalid_client → 401), RFC 9126 (PAR)

## [0.4.5] - 2026-02-21

Fix credential error response error code per OID4VCI 1.0 Final.

### Fixed

- **Error code `invalid_proof` (OID4VCI §8.3.1):** Renamed `invalid_or_missing_proof` → `invalid_proof` to match OID4VCI 1.0 Final §8.3.1. The old code was from a pre-final draft. Fixes OIDF test `VCIValidateCredentialErrorResponse`.

### Spec references

- OID4VCI 1.0 Final §8.3.1 (Credential Error Response — `invalid_proof` error code)

## [0.4.4] - 2026-02-21

Proof JWT header parameter mutual exclusivity validation per OID4VCI 1.0 Final.

### Fixed

- **Proof key reference exclusivity (OID4VCI Appendix F.1):** `ProofValidator` now enforces that the proof JWT header contains exactly one of `jwk`, `x5c`, or `kid`. Previously, a proof with multiple key references (e.g., both `jwk` and `kid`) was silently accepted. Only `jwk` binding method is currently supported — `x5c` and `kid` alone are rejected with a clear error message.

### Added

- **4 new tests** in `ProofValidatorTest` — no key reference, `jwk`+`kid` combination, `jwk`+`x5c` combination, `kid`-only unsupported (130 → 134 total tests).

### Spec references

- OID4VCI 1.0 Final Appendix F.1 (jwt Proof Type — JOSE header key reference requirements)

## [0.4.3] - 2026-02-21

HAIP 6.1.1 conformance fix — x5c certificate chain in SD-JWT VC header.

### Fixed

- **x5c certificate chain (HAIP-6.1.1):** When no PEM certificate files are found, PemKeyLoader now generates an ephemeral CA + issuer certificate chain instead of a self-signed cert. The issuer cert (CA-signed, not self-signed) is included in the SD-JWT VC x5c header; the CA root is excluded per HAIP. Fixes OIDF test `VCIEnsureX5cHeaderPresentForSdJwtCredential`.

### Added

- **5 PemKeyLoader tests:** First unit tests for `fikua-issuer` module — verify x5c chain present, cert not self-signed, key can sign, SD-JWT header contains x5c, PEM file loading.
- **DEVELOPER.md ad-hoc fixes protocol:** New section documenting the workflow for OIDF conformance fixes not tied to spec gaps (commit format, versioning, documentation requirements).

### Spec references

- HAIP 1.0 §6.1.1 (Issuer identification and key resolution), SD-JWT VC §3.5 (x5c JOSE header)

## [0.4.2] - 2026-02-21

Nonce endpoint fix and OID4VCI 1.0 Final spec alignment.

### Fixed

- **Nonce session binding:** Nonces generated by the Nonce Endpoint (POST /nonce) are now registered in the global nonce store, allowing validation at the Credential Endpoint regardless of whether an access token was provided. Previously, nonces were only stored in the session, causing `invalid_or_missing_proof` errors when the wallet called /nonce without an access token (OID4VCI 1.0 Final §7.1).
- **Nonce response format:** Removed `c_nonce_expires_in` from Nonce Endpoint response — OID4VCI 1.0 Final §7.2 only defines `c_nonce`.
- **PemKeyLoader warning:** When no PEM certificate files are found, log a WARN mentioning HAIP 6.1.1 x5c requirement instead of silently generating a key without x5c. Future: QTSP/Vault integration for certificate management.
- **OAuth error logging:** Added WARN-level logging to `OAuthErrorException` handler with method, path, error code, and description — previously errors were silently swallowed.
- **Request/response logging:** Added structured logging to token, nonce, and credential endpoints for diagnosing conformance test failures.

### Added

- **`invalid_nonce` error code:** OID4VCI 1.0 Final §8.3.1 — returned when the c_nonce in the proof is invalid/expired. Distinct from `invalid_or_missing_proof` (proof is structurally invalid).
- **`SessionStore.registerNonce()`:** New port method to register nonces in the global store without linking to a specific session.

### Changed

- **Nonce validation strategy:** Credential endpoint now validates proof nonce against the global nonce store first (covers nonce endpoint nonces), with fallback to `session.cNonce()` (covers token endpoint nonces). Nonces are single-use (consumed on validation per OID4VCI 1.0 Final §7).
- **Token endpoint nonce handling:** Token endpoints (pre-auth and auth_code) now register their nonces via `registerNonce()` instead of `createNonce(sessionId)`.

### Spec references

- OID4VCI 1.0 Final §7 (Nonce Endpoint), §7.2 (Nonce Response), §8.3.1 (Credential Error Response), HAIP 6.1.1 (x5c requirement)

## [0.4.1] - 2026-02-20

OIDF conformance fixes for credential endpoint, token endpoint, and authorization response.

### Fixed

- **Credential request `proofs` (plural):** Parse OID4VCI 1.0 Final §7.2.2 format `{"proofs": {"jwt": ["eyJ..."]}}` in addition to draft singular `{"proof": {"proof_type": "jwt", "jwt": "eyJ..."}}`. New `extractProofJwt()` method normalizes both formats.
- **`Cache-Control: no-store` header:** Added to `/token` and `/credential` responses (OID4VCI §7.3, RFC 6749 §5.1)
- **`iss` in authorization response:** Added `&iss=<issuer>` URL-encoded parameter to authorize redirect (RFC 9207)
- **`authorization_response_iss_parameter_supported`:** Advertised in AS Metadata for HAIP profile (RFC 9207 §3)

### Added

- **5 new tests** in `CredentialRequestTest` — `proofs` deserialization, `extractProofJwt()` singular/plural/precedence/null
- **1 new assertion** in `AuthServerMetadataTest` — `authorization_response_iss_parameter_supported`

### Spec references

- OID4VCI 1.0 Final §7.2.2, RFC 9207 (Authorization Server Issuer Identification), RFC 6749 §5.1

## [0.4.0] - 2026-02-20

RFC 9457 error handling, comprehensive test coverage, and issuer state management.

### Added

- **RFC 9457 ProblemDetail:** New `com.fikua.core.http.ProblemDetail` record for non-protocol errors (404, 405, 500) with `application/problem+json` content type
- **OAuthError factory methods:** `invalidToken()`, `invalidClient()`, `unsupportedGrantType()`, `unsupportedCredentialFormat()`
- **Issuer state binding:** `storeIssuerState()`/`consumeIssuerState()` on `SessionStore` port — links credential offer to issuance record through the HAIP authorization flow
- **85 new unit tests** (24 → 109 total):
  - `DPoPValidatorTest` (14) — all RFC 9449 validation branches
  - `ProofValidatorTest` (12) — OID4VCI §7.2.1 proof of possession
  - `PkceUtilTest` (9) — RFC 7636 test vector, S256 challenge
  - `OAuthErrorTest` (10) — all error codes, JSON contract
  - `ProblemDetailTest` (7) — RFC 9457 factories, serialization
  - `TokenResponseTest` (4) — Bearer/DPoP, JSON contract
  - `TokenRequestTest` (5) — form parsing, grant type detection
  - `CredentialOfferTest` (6) — pre-auth + auth_code, tx_code
  - `CredentialResponseTest` (4) — JSON contract, NON_NULL
  - `DisclosureTest` (9) — create/digest/parse round-trip
  - `SdJwtVerifierTest` (5) — signature verification, expiry, claim resolution

### Changed

- **Error handlers in `FikuaLab.java`:** 404/405 return `ProblemDetail` (was Javalin HTML), 500 returns `ProblemDetail.internalError()`, 401 includes `WWW-Authenticate: DPoP error="..."` header (RFC 9449 §7.1)
- **`IssuerController.credentialOffer()`:** Throws `OAuthErrorException` (was raw `Map.of()`)
- **`IssuanceService.issueCredential()`:** Fails explicitly when no `issuanceRecordId` or empty `credential_data` (was falling back to hardcoded data)

### Removed

- **`addDefaultClaims()` method** — no more hardcoded credential data
- **`createCredentialOffer()` methods** — replaced by `POST /issuance` trigger flow
- **`GET /oid4vci/v1/credential-offer`** — returns 400 (use `POST /issuance` with `credential_data`)

### Spec references

- RFC 9457 (Problem Details for HTTP APIs), RFC 9449 (DPoP), RFC 7636 (PKCE), RFC 6749 §5.2 (OAuth2 errors)

## [0.3.1] - 2026-02-20

OIDF conformance fixes for HAIP Issuer test.

### Fixed

- **Credential configuration ID:** Align `credential_configuration_id` with OIDF test expectation
- **ATCA metadata:** Add `client_attestation_signing_alg_values_supported` and `client_attestation_pop_signing_alg_values_supported` to Authorization Server Metadata (OAuth Attestation-Based Client Authentication §10.1)

## [0.3.0] - 2026-02-20

Architecture refactor to Infrastructure-Application-Domain pattern.

### Added

- **3-module architecture:** `fikua-core` (domain), `fikua-issuer` (application + infra), `fikua-lab` (orchestrator)
- **Port interfaces:** `SessionStore`, `IssuanceStore`, `ProfileStore` in `fikua-issuer`
- **Infrastructure adapters:** `InMemorySessionStore`, `JdbcIssuanceStore`, `JdbcProfileStore`, `PemKeyLoader`
- **P1 pre-auth spec compliance:** `credential_configuration_id` in token response, `tx_code` validation, `exp` claim in SD-JWT VC

### Changed

- **fikua-core purified:** zero I/O, zero state, zero framework dependencies
- **fikua-server retired:** replaced by `fikua-issuer` + `fikua-lab`

### Spec references

- OID4VCI 1.0 Final, HAIP 1.0, SD-JWT VC draft-14

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
