package com.fikua.issuer.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.core.crypto.JwkUtils;
import com.fikua.core.crypto.SigningKey;
import com.fikua.core.oauth2.*;
import com.fikua.core.oid4vci.*;
import com.fikua.core.profile.ProfileConfig;
import com.fikua.core.profile.enums.CredentialOfferVariant;
import com.fikua.core.sdjwt.SdJwtBuilder;
import com.fikua.issuer.app.port.IssuanceStore;
import com.fikua.issuer.app.port.ProfileStore;
import com.fikua.issuer.app.port.SessionStore;
import com.fikua.issuer.app.port.SessionStore.SessionData;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Issuer application service — orchestrates OID4VCI credential issuance.
 * Pure application logic: no HTTP, no DB, no framework dependencies.
 * All I/O happens through injected ports.
 */
public class IssuanceService {

    private static final Logger log = LoggerFactory.getLogger(IssuanceService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pid.1";
    private static final String API_PREFIX = "/oid4vci/v1";

    private final SigningKey issuerKey;
    private final SessionStore sessionStore;
    private final IssuanceStore issuanceStore;
    private final ProfileStore profileStore;
    private final DPoPValidator dpopValidator;
    private final ClientAttestationValidator clientAttestationValidator;
    private final String baseUrl;

    public IssuanceService(SigningKey issuerKey, SessionStore sessionStore,
                           IssuanceStore issuanceStore, ProfileStore profileStore,
                           DPoPValidator dpopValidator, String baseUrl) {
        this.issuerKey = issuerKey;
        this.sessionStore = sessionStore;
        this.issuanceStore = issuanceStore;
        this.profileStore = profileStore;
        this.dpopValidator = dpopValidator;
        this.clientAttestationValidator = new ClientAttestationValidator();
        this.baseUrl = baseUrl;
    }

    public ProfileConfig getActiveConfig() {
        var active = profileStore.findActive();
        if (active == null) {
            throw new OAuthErrorException(503, OAuthError.invalidRequest(
                    "No active profile configured. Create and activate a profile via /admin/profiles first."));
        }
        return active.config();
    }

    public CredentialIssuerMetadata buildCredentialIssuerMetadata(ProfileConfig config) {
        return CredentialIssuerMetadata.build(
                baseUrl,
                baseUrl + API_PREFIX + "/credential",
                baseUrl + API_PREFIX + "/nonce",
                baseUrl + API_PREFIX + "/notification",
                buildCredentialConfigurations(),
                List.of(Map.<String, Object>of("name", "Fikua Lab Issuer", "locale", "en")),
                config != null && config.isHaip()
        );
    }

    public AuthServerMetadata buildAuthServerMetadata(ProfileConfig config) {
        if (config.isHaip()) {
            return AuthServerMetadata.forHaipProfile(
                    baseUrl,
                    baseUrl + API_PREFIX + "/token",
                    baseUrl + API_PREFIX + "/authorize",
                    baseUrl + API_PREFIX + "/par",
                    baseUrl + API_PREFIX + "/jwks"
            );
        }
        return AuthServerMetadata.forPreAuthProfile(
                baseUrl,
                baseUrl + API_PREFIX + "/token",
                baseUrl + API_PREFIX + "/jwks"
        );
    }

    public String jwksJson() {
        return JwkUtils.jwkSetToJson(issuerKey.jwkSet());
    }

    public String getCredentialOffer(String offerId) {
        return sessionStore.getCredentialOffer(offerId);
    }

    /** Handle pre-authorized code token request. */
    public TokenResponse handlePreAuthToken(Map<String, String> params, ProfileConfig config) {
        TokenRequest request = TokenRequest.fromParams(params);
        log.info("Token request: grant_type={}", request.grantType());

        if (request.preAuthorizedCode() == null) {
            log.warn("Token request rejected: missing pre-authorized_code");
            throw OAuthErrorException.badRequest(OAuthError.INVALID_GRANT, "Missing pre-authorized_code");
        }

        SessionData session = sessionStore.consumePreAuthCode(request.preAuthorizedCode());
        if (session == null) {
            log.warn("Token request rejected: invalid or expired pre-authorized_code");
            throw OAuthErrorException.badRequest(OAuthError.INVALID_GRANT, "Invalid or expired pre-authorized_code");
        }
        log.info("Pre-authorized code consumed: sessionId={}", session.sessionId());

        // Validate tx_code if the session requires it (OID4VCI §4.1.1)
        String expectedTxCode = (String) session.metadata().get("tx_code");
        if (expectedTxCode != null) {
            if (request.txCode() == null || !expectedTxCode.equals(request.txCode())) {
                log.warn("Token request rejected: tx_code mismatch");
                throw OAuthErrorException.badRequest(OAuthError.INVALID_GRANT, "Invalid or missing tx_code");
            }
        }

        String cNonce = sessionStore.generateNonce();
        sessionStore.registerNonce(cNonce);
        SessionData tokenSession = new SessionData(
                session.sessionId(), cNonce, null, Instant.now(), session.metadata()
        );
        String accessToken = sessionStore.createAccessToken(tokenSession);
        log.info("Access token issued: sessionId={}, token_type=bearer", session.sessionId());

        return TokenResponse.bearer(accessToken);
    }

    /** Handle authorization_code token request (HAIP). */
    public TokenResponse handleAuthCodeToken(Map<String, String> params, ProfileConfig config,
                                              String dpopHeader, String attestationHeader,
                                              String attestationPopHeader) {
        TokenRequest request = TokenRequest.fromParams(params);
        log.info("Token request: grant_type={}", request.grantType());

        // Validate client attestation (ATCA draft-07): try headers first, then form params
        String attestedClientId = resolveClientAttestation(attestationHeader, attestationPopHeader, params);
        if (attestedClientId != null) {
            log.info("Client attestation validated at token endpoint: client_id={}", attestedClientId);
        }

        // Validate DPoP if required
        ECKey dpopKey = null;
        if (config.requiresDPoP()) {
            dpopKey = dpopValidator.validate(dpopHeader, "POST", baseUrl + API_PREFIX + "/token", null);
            log.info("DPoP validated at token endpoint");
        }

        // Consume authorization code
        SessionData session = sessionStore.consumeAuthCode(request.code());
        if (session == null) {
            log.warn("Token request rejected: invalid authorization code");
            throw OAuthErrorException.badRequest(OAuthError.INVALID_GRANT, "Invalid authorization code");
        }
        log.info("Authorization code consumed: sessionId={}", session.sessionId());

        // Validate PKCE
        if (config.requiresPkce()) {
            if (request.codeVerifier() == null) {
                log.warn("Token request rejected: missing code_verifier");
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "Missing code_verifier");
            }
            String storedChallenge = (String) session.metadata().get("code_challenge");
            if (storedChallenge == null || !PkceUtil.verifyS256(request.codeVerifier(), storedChallenge)) {
                log.warn("Token request rejected: PKCE verification failed");
                throw OAuthErrorException.badRequest(OAuthError.INVALID_GRANT, "PKCE verification failed");
            }
            log.info("PKCE S256 verified");
        }

        String cNonce = sessionStore.generateNonce();
        sessionStore.registerNonce(cNonce);
        SessionData tokenSession = new SessionData(
                session.sessionId(), cNonce, dpopKey, Instant.now(), session.metadata()
        );
        String accessToken = sessionStore.createAccessToken(tokenSession);
        String tokenType = config.requiresDPoP() ? "DPoP" : "bearer";
        log.info("Access token issued: sessionId={}, token_type={}", session.sessionId(), tokenType);

        if (config.requiresDPoP()) {
            return TokenResponse.dpop(accessToken);
        }
        return TokenResponse.bearer(accessToken);
    }

    /** Handle token request (dispatches to pre-auth or auth_code). */
    public TokenResponse handleToken(Map<String, String> params, ProfileConfig config,
                                      String dpopHeader, String attestationHeader,
                                      String attestationPopHeader) {
        TokenRequest request = TokenRequest.fromParams(params);
        if (request.isPreAuthorizedCode()) {
            return handlePreAuthToken(params, config);
        } else if (request.isAuthorizationCode()) {
            return handleAuthCodeToken(params, config, dpopHeader, attestationHeader, attestationPopHeader);
        }
        log.warn("Token request rejected: unsupported grant_type={}", request.grantType());
        throw OAuthErrorException.badRequest(OAuthError.UNSUPPORTED_GRANT_TYPE,
                "Unsupported grant type: " + request.grantType());
    }

    /**
     * Generate a new nonce (OID4VCI 1.0 Final §7 — Nonce Endpoint).
     * The nonce is always registered in the global nonce store so it can be validated
     * at the credential endpoint regardless of whether an access token was provided.
     * If an access token IS provided, also update the session's c_nonce.
     */
    public Map<String, Object> generateNonce(String accessToken, String dpopHeader) {
        String nonce = sessionStore.generateNonce();

        // Always register nonce in the global store for validation at credential endpoint
        sessionStore.registerNonce(nonce);
        log.info("Nonce generated and registered: accessToken present={}", accessToken != null);

        // If access token provided, validate DPoP and update the session's c_nonce
        if (accessToken != null) {
            SessionData session = sessionStore.getAccessTokenSession(accessToken);
            if (session != null) {
                // H9: Validate DPoP at nonce endpoint if session is DPoP-bound
                if (session.dpopKey() != null && dpopHeader != null) {
                    String ath = computeAth(accessToken);
                    ECKey dpopKey = dpopValidator.validate(dpopHeader, "POST", baseUrl + API_PREFIX + "/nonce", ath);
                    try {
                        String expectedThumbprint = session.dpopKey().computeThumbprint().toString();
                        String actualThumbprint = dpopKey.computeThumbprint().toString();
                        if (!expectedThumbprint.equals(actualThumbprint)) {
                            log.warn("DPoP key mismatch at nonce endpoint");
                            throw OAuthErrorException.unauthorized(OAuthError.INVALID_TOKEN, "DPoP key mismatch at nonce endpoint");
                        }
                        log.info("DPoP validated at nonce endpoint");
                    } catch (OAuthErrorException e) {
                        throw e;
                    } catch (Exception e) {
                        log.warn("DPoP thumbprint verification failed at nonce endpoint", e);
                        throw OAuthErrorException.unauthorized(OAuthError.INVALID_TOKEN, "DPoP thumbprint verification failed");
                    }
                }

                SessionData updated = new SessionData(
                        session.sessionId(), nonce, session.dpopKey(),
                        session.createdAt(), session.metadata()
                );
                sessionStore.updateAccessTokenSession(accessToken, updated);
            }
        }

        // OID4VCI 1.0 Final §7.2: Nonce Response only contains c_nonce (no c_nonce_expires_in)
        return Map.of("c_nonce", nonce);
    }

    /** Issue a credential. */
    public CredentialResponse issueCredential(String accessToken, String body,
                                               ProfileConfig config, String dpopHeader) {
        SessionData session = sessionStore.getAccessTokenSession(accessToken);
        if (session == null) {
            log.warn("Credential request rejected: invalid access token");
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_TOKEN, "Invalid access token");
        }

        // Validate DPoP for resource request if required (RFC 9449 §4.3: ath required)
        if (config.requiresDPoP()) {
            String ath = computeAth(accessToken);
            ECKey resourceDpopKey = dpopValidator.validate(dpopHeader, "POST", baseUrl + API_PREFIX + "/credential", ath);
            if (session.dpopKey() != null) {
                try {
                    String expectedThumbprint = session.dpopKey().computeThumbprint().toString();
                    String actualThumbprint = resourceDpopKey.computeThumbprint().toString();
                    if (!expectedThumbprint.equals(actualThumbprint)) {
                        log.warn("DPoP key mismatch at credential endpoint");
                        throw OAuthErrorException.unauthorized(OAuthError.INVALID_TOKEN, "DPoP key mismatch");
                    }
                } catch (OAuthErrorException e) {
                    throw e;
                } catch (Exception e) {
                    log.warn("DPoP thumbprint verification failed at credential endpoint", e);
                    throw OAuthErrorException.unauthorized(OAuthError.INVALID_TOKEN, "DPoP thumbprint verification failed");
                }
            }
            log.info("DPoP validated at credential endpoint");
        }

        try {
            CredentialRequest request = MAPPER.readValue(body, CredentialRequest.class);
            log.info("Credential request: format={}, credential_configuration_id={}",
                    request.format(), request.credentialConfigurationId());

            // M8: credential_configuration_id or credential_identifier is REQUIRED per OID4VCI 1.0 Final §8.2
            if (request.credentialConfigurationId() == null && request.credentialIdentifier() == null) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_CREDENTIAL_REQUEST,
                        "credential_configuration_id or credential_identifier is required");
            }
            // OID4VCI 1.0 Final §8.3.1.2: unknown_credential_configuration
            if (request.credentialConfigurationId() != null
                    && !CREDENTIAL_CONFIG_ID.equals(request.credentialConfigurationId())) {
                log.warn("Credential request rejected: unknown credential_configuration_id={} (expected={})",
                        request.credentialConfigurationId(), CREDENTIAL_CONFIG_ID);
                throw OAuthErrorException.badRequest(OAuthError.UNKNOWN_CREDENTIAL_CONFIGURATION,
                        "Unknown credential_configuration_id: " + request.credentialConfigurationId());
            }
            // OID4VCI 1.0 Final §8.3.1.2: invalid_credential_identifier (OIDF test expectation)
            if (request.credentialIdentifier() != null) {
                log.warn("Credential request rejected: unknown credential_identifier={}", request.credentialIdentifier());
                throw OAuthErrorException.badRequest(OAuthError.INVALID_CREDENTIAL_IDENTIFIER,
                        "Unknown credential_identifier: " + request.credentialIdentifier());
            }

            String proofJwt = request.extractProofJwt();
            if (proofJwt == null) {
                log.warn("Credential request rejected: missing or non-JWT proof");
                throw OAuthErrorException.badRequest(OAuthError.INVALID_PROOF, "proof_type must be jwt");
            }

            // Validate proof: signature, typ, alg, aud, iat (nonce checked separately below)
            ECKey walletKey = ProofValidator.validateJwt(proofJwt, baseUrl, null);
            log.info("Proof JWT validated: wallet key bound");

            // Validate nonce against the global nonce store (covers both token and nonce endpoint nonces).
            // The wallet may have obtained the nonce from the Nonce Endpoint (§7) without an access token,
            // so we cannot rely solely on session.cNonce() which only tracks the token endpoint nonce.
            String proofNonce = extractProofNonce(proofJwt);
            log.info("Nonce validation: proofNonce={}, session.cNonce={}", proofNonce, session.cNonce());
            boolean nonceValid = proofNonce != null && sessionStore.validateNonce(proofNonce);
            if (!nonceValid) {
                // Fallback: check against session.cNonce() (token endpoint nonce)
                nonceValid = proofNonce != null && proofNonce.equals(session.cNonce());
                if (nonceValid) {
                    log.info("Nonce validated via session.cNonce() fallback");
                }
            } else {
                log.info("Nonce validated via global nonce store");
            }
            if (!nonceValid) {
                log.warn("Nonce validation failed: proofNonce={}, session.cNonce={}", proofNonce, session.cNonce());
                // OID4VCI 1.0 Final §8.3.1: invalid_nonce when c_nonce is invalid/expired
                throw OAuthErrorException.badRequest(OAuthError.INVALID_NONCE,
                        "Proof nonce does not match c_nonce");
            }

            SdJwtBuilder builder = new SdJwtBuilder(issuerKey)
                    .vct("eu.europa.ec.eudi.pid.1")
                    .issuer(baseUrl)
                    .subject("urn:fikua:pid:" + sessionStore.randomToken(8))
                    .holderKey(walletKey)
                    .x5cChain(issuerKey.x5cChain());

            String issuanceRecordId = (String) session.metadata().get("issuanceRecordId");
            if (issuanceRecordId == null) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                        "No issuance record linked to this session. Use POST /oid4vci/v1/issuance to trigger credential issuance.");
            }

            var record = issuanceStore.findById(issuanceRecordId);
            if (record == null || record.credentialData() == null
                    || record.credentialData().equals("{}")) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                        "Issuance record has no credential data. Provide credential_data when triggering issuance.");
            }

            var dataNode = MAPPER.readTree(record.credentialData());
            var fields = dataNode.fields();
            while (fields.hasNext()) {
                var field = fields.next();
                builder.selectiveClaim(field.getKey(), field.getValue().asText());
            }
            builder.plainClaim("issuing_authority", "Fikua Lab");
            builder.plainClaim("issuing_country", "ES");
            issuanceStore.updateStatus(issuanceRecordId, "credential_issued");
            log.info("Credential issued: issuanceId={}", issuanceRecordId);

            String sdJwt = builder.build().serialize();

            // H11: Invalidate nonce after successful issuance (one-time use)
            sessionStore.invalidateNonce(session.cNonce());
            log.info("Nonce invalidated (one-time use): {}", session.cNonce());

            return CredentialResponse.success(sdJwt);

        } catch (OAuthErrorException e) {
            throw e;
        } catch (Exception e) {
            log.error("Credential issuance error", e);
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "Invalid credential request: " + e.getMessage());
        }
    }

    /** Handle authorization request (HAIP). */
    public AuthorizeResult handleAuthorize(String requestUri, String clientId, String redirectUri,
                                            String state, String codeChallenge, String issuerState,
                                            ProfileConfig config) {
        if (!config.isHaip()) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                    "Authorization endpoint not available for this profile");
        }

        // Resolve PAR if request_uri provided
        if (requestUri != null) {
            Map<String, String> parParams = sessionStore.consumeParRequest(requestUri);
            if (parParams == null) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "Invalid or expired request_uri");
            }
            clientId = parParams.get("client_id");
            redirectUri = parParams.get("redirect_uri");
            state = parParams.get("state");
            codeChallenge = parParams.get("code_challenge");
            issuerState = parParams.get("issuer_state");
            log.info("Authorize via PAR: client_id={}, request_uri={}", clientId, requestUri);
        }

        var metadata = new LinkedHashMap<String, Object>();
        if (clientId != null) metadata.put("client_id", clientId);
        if (redirectUri != null) metadata.put("redirect_uri", redirectUri);
        if (codeChallenge != null) metadata.put("code_challenge", codeChallenge);
        if (issuerState != null) {
            metadata.put("issuer_state", issuerState);
            // Resolve issuanceRecordId linked to this issuerState
            Map<String, Object> issuerMeta = sessionStore.consumeIssuerState(issuerState);
            if (issuerMeta != null && issuerMeta.containsKey("issuanceRecordId")) {
                metadata.put("issuanceRecordId", issuerMeta.get("issuanceRecordId"));
            }
        }

        SessionData session = new SessionData(
                sessionStore.randomToken(16), null, null, Instant.now(), metadata
        );
        String authCode = sessionStore.createAuthCode(session);
        log.info("Authorization code issued: client_id={}, has_redirect={}", clientId, redirectUri != null);

        return new AuthorizeResult(authCode, redirectUri, state);
    }

    /** Handle PAR request (HAIP). */
    public Map<String, Object> handlePar(Map<String, String> params, ProfileConfig config,
                                          String attestationHeader, String attestationPopHeader) {
        if (!config.isHaip()) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "PAR not available for this profile");
        }

        // Validate client attestation (ATCA draft-07): try headers first, then form params
        String attestedClientId = resolveClientAttestation(attestationHeader, attestationPopHeader, params);
        if (attestedClientId != null) {
            log.info("Client attestation validated at PAR: client_id={}", attestedClientId);
        } else if (config.requiresClientAttestation()) {
            log.warn("PAR rejected: client attestation required but not provided");
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                    "Client attestation is required");
        }

        // M7: HAIP requires code_challenge_method=S256
        String codeChallengeMethod = params.get("code_challenge_method");
        if (codeChallengeMethod != null && !"S256".equals(codeChallengeMethod)) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                    "Only S256 code_challenge_method is supported");
        }

        String requestUri = "urn:ietf:params:oauth:request_uri:" + sessionStore.randomToken(16);
        sessionStore.storeParRequest(requestUri, params);

        log.info("PAR request stored: request_uri={}", requestUri);

        return Map.of("request_uri", requestUri, "expires_in", 60);
    }

    /** Trigger credential issuance from frontend. */
    public Map<String, Object> triggerIssuance(String body, ProfileConfig config) {
        try {
            var bodyNode = MAPPER.readTree(body);

            String credentialType = bodyNode.has("credential_type")
                    ? bodyNode.get("credential_type").asText()
                    : "eu.europa.ec.eudi.pid.1";

            String credentialData;
            if (bodyNode.has("credential_data")) {
                credentialData = MAPPER.writeValueAsString(bodyNode.get("credential_data"));
            } else {
                credentialData = "{}";
            }

            String sourceType = bodyNode.has("source_type") ? bodyNode.get("source_type").asText() : null;
            String sourceRef = bodyNode.has("source_ref") ? bodyNode.get("source_ref").asText() : null;
            boolean txCodeRequired = bodyNode.has("tx_code_required")
                    && bodyNode.get("tx_code_required").asBoolean(false);

            var record = issuanceStore.create(credentialType, credentialData, sourceType, sourceRef);
            log.info("IssuanceRecord created: id={}, type={}, source={}", record.id(), credentialType, sourceType);

            CredentialOffer offer;
            String txCodeValue = null;
            if (config.isHaip()) {
                log.info("Credential offer: grant_type=authorization_code (HAIP), issuanceId={}", record.id());
                String issuerState = sessionStore.randomToken(16);
                sessionStore.storeIssuerState(issuerState, Map.of("issuanceRecordId", record.id()));
                offer = CredentialOffer.authorizationCode(baseUrl, CREDENTIAL_CONFIG_ID, issuerState);
            } else {
                log.info("Credential offer: grant_type=pre-authorized_code, issuanceId={}", record.id());
                var metadata = new LinkedHashMap<String, Object>();
                metadata.put("issuanceRecordId", record.id());
                if (txCodeRequired) {
                    txCodeValue = generateTxCode();
                    metadata.put("tx_code", txCodeValue);
                }
                SessionData session = new SessionData(
                        sessionStore.randomToken(16), null, null, Instant.now(),
                        Map.copyOf(metadata)
                );
                String preAuthCode = sessionStore.createPreAuthCode(session);
                issuanceStore.updatePreAuthCode(record.id(), preAuthCode);
                offer = CredentialOffer.preAuthorized(baseUrl, CREDENTIAL_CONFIG_ID, preAuthCode, txCodeRequired);
            }

            issuanceStore.updateStatus(record.id(), "offer_created");
            String offerJson = MAPPER.writeValueAsString(offer);

            var result = new LinkedHashMap<String, Object>();
            if (config.credentialOffer() == CredentialOfferVariant.BY_REFERENCE) {
                String offerId = sessionStore.storeCredentialOffer(offerJson);
                issuanceStore.updateOfferId(record.id(), offerId);
                String offerUri = baseUrl + API_PREFIX + "/credential-offer/" + offerId;
                result.put("credential_offer_uri", offerUri);
            } else {
                result.put("credential_offer", MAPPER.readTree(offerJson));
            }
            result.put("issuance_id", record.id());
            if (txCodeValue != null) {
                result.put("tx_code", txCodeValue);
            }
            return result;

        } catch (Exception e) {
            log.error("Issuance trigger error", e);
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                    "Failed to trigger issuance: " + e.getMessage());
        }
    }

    public void resetState() {
        sessionStore.clear();
    }

    // --- Private helpers ---

    /**
     * Resolve client attestation from HTTP headers or form params (ATCA draft-07).
     * Headers take precedence over form params.
     *
     * @return the client_id if attestation is valid, null if no attestation present
     */
    private String resolveClientAttestation(String attestationHeader, String attestationPopHeader,
                                             Map<String, String> params) {
        // Try HTTP headers first (ATCA draft-07 §4)
        String clientId = clientAttestationValidator.validateHeaders(attestationHeader, attestationPopHeader);
        if (clientId != null) {
            return clientId;
        }
        // Fallback to form params (client_assertion_type + client_assertion)
        return clientAttestationValidator.validate(
                params.get("client_assertion_type"), params.get("client_assertion"));
    }

    /** Extract the nonce claim from a JWT proof string. */
    private String extractProofNonce(String jwtString) {
        try {
            var jwt = com.nimbusds.jwt.SignedJWT.parse(jwtString);
            return jwt.getJWTClaimsSet().getStringClaim("nonce");
        } catch (Exception e) {
            return null;
        }
    }

    /** Compute ath = BASE64URL(SHA-256(access_token)) per RFC 9449 §4.3. */
    private String computeAth(String accessToken) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64URL.encode(hash).toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute ath", e);
        }
    }

    private String generateTxCode() {
        // 6-digit numeric code as specified in CredentialOffer.preAuthorized()
        int code = new java.security.SecureRandom().nextInt(900000) + 100000;
        return String.valueOf(code);
    }

    private Map<String, Object> buildCredentialConfigurations() {
        var credConfig = new LinkedHashMap<String, Object>();
        credConfig.put("format", "dc+sd-jwt");
        credConfig.put("scope", "eu.europa.ec.eudi.pid.1");
        credConfig.put("cryptographic_binding_methods_supported", List.of("jwk"));
        credConfig.put("credential_signing_alg_values_supported", List.of("ES256"));
        credConfig.put("proof_types_supported", Map.of(
                "jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))
        ));
        credConfig.put("vct", "eu.europa.ec.eudi.pid.1");

        var claims = List.of(
                Map.of("path", List.of("given_name"), "display", List.of(Map.of("name", "Given Name", "locale", "en"))),
                Map.of("path", List.of("family_name"), "display", List.of(Map.of("name", "Surname", "locale", "en"))),
                Map.of("path", List.of("birth_date"), "display", List.of(Map.of("name", "Date of Birth", "locale", "en"))),
                Map.of("path", List.of("issuing_authority"), "display", List.of(Map.of("name", "Issuing Authority", "locale", "en"))),
                Map.of("path", List.of("issuing_country"), "display", List.of(Map.of("name", "Issuing Country", "locale", "en")))
        );

        var credentialMetadata = new LinkedHashMap<String, Object>();
        credentialMetadata.put("display", List.of(Map.of(
                "name", "EUDI PID",
                "locale", "en",
                "description", "EU Digital Identity Personal Identification Data"
        )));
        credentialMetadata.put("claims", claims);
        credConfig.put("credential_metadata", credentialMetadata);

        return Map.of(CREDENTIAL_CONFIG_ID, credConfig);
    }

    /** Result of the authorize endpoint. */
    public record AuthorizeResult(String code, String redirectUri, String state) {}
}
