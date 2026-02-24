package com.fikua.issuer.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.core.crypto.JwkUtils;
import com.fikua.core.crypto.SigningKey;
import com.fikua.core.mdoc.MdocBuilder;
import com.fikua.core.oauth2.*;
import com.fikua.core.oid4vci.*;
import com.fikua.core.profile.ProfileConfig;
import com.fikua.core.profile.enums.CredentialOfferVariant;
import com.fikua.core.sdjwt.SdJwtBuilder;
import com.fikua.issuer.app.port.EmailService;
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
import java.util.*;

/**
 * Issuer application service — orchestrates OID4VCI credential issuance.
 * Pure application logic: no HTTP, no DB, no framework dependencies.
 * All I/O happens through injected ports.
 */
public class IssuanceService {

    private static final Logger log = LoggerFactory.getLogger(IssuanceService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String API_PREFIX = "/oid4vci/v1";

    // Credential configuration IDs (OIDF conformance suite)
    private static final String PID_SD_JWT = "eu.europa.ec.eudi.pid.1";
    private static final String PID_MDOC = "eu.europa.ec.eudi.pid.mdoc.1";
    private static final String STUDENT_ID_SD_JWT = "student-id.sd-jwt.1";
    private static final String STUDENT_ID_VCT = "VerifiableStudentIDSDJWT";
    private static final String DEFAULT_CONFIG_ID = PID_SD_JWT;
    private static final Set<String> ISSUABLE_CONFIGS = Set.of(PID_SD_JWT, PID_MDOC, STUDENT_ID_SD_JWT);

    private final SigningKey issuerKey;
    private final SessionStore sessionStore;
    private final IssuanceStore issuanceStore;
    private final ProfileStore profileStore;
    private final DPoPValidator dpopValidator;
    private final ClientAttestationValidator clientAttestationValidator;
    private final String baseUrl;
    private final String identifyBaseUrl;
    private final EmailService emailService;
    private final String walletBaseUrl;

    public IssuanceService(SigningKey issuerKey, SessionStore sessionStore,
                           IssuanceStore issuanceStore, ProfileStore profileStore,
                           DPoPValidator dpopValidator, String baseUrl,
                           String identifyBaseUrl, EmailService emailService,
                           String walletBaseUrl) {
        this.issuerKey = issuerKey;
        this.sessionStore = sessionStore;
        this.issuanceStore = issuanceStore;
        this.profileStore = profileStore;
        this.dpopValidator = dpopValidator;
        this.clientAttestationValidator = new ClientAttestationValidator();
        this.baseUrl = baseUrl;
        this.identifyBaseUrl = identifyBaseUrl;
        this.emailService = emailService;
        this.walletBaseUrl = walletBaseUrl;
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
            // OID4VCI 1.0 Final §8.3.1.2: validate credential_configuration_id against known configs
            String configId = request.credentialConfigurationId();
            Map<String, Object> allConfigs = buildCredentialConfigurations();
            if (configId != null && !allConfigs.containsKey(configId)) {
                log.warn("Credential request rejected: unknown credential_configuration_id={}", configId);
                throw OAuthErrorException.badRequest(OAuthError.UNKNOWN_CREDENTIAL_CONFIGURATION,
                        "Unknown credential_configuration_id: " + configId);
            }
            if (configId != null && !ISSUABLE_CONFIGS.contains(configId)) {
                log.warn("Credential request rejected: credential_configuration_id={} is defined but not yet issuable", configId);
                throw OAuthErrorException.badRequest(OAuthError.UNSUPPORTED_CREDENTIAL_TYPE,
                        "Credential configuration '" + configId + "' is defined in metadata but not yet issuable. " +
                        "Supported: " + ISSUABLE_CONFIGS);
            }
            // OID4VCI 1.0 Final §8.3.1.2: unknown_credential_identifier
            if (request.credentialIdentifier() != null) {
                log.warn("Credential request rejected: unknown credential_identifier={}", request.credentialIdentifier());
                throw OAuthErrorException.badRequest(OAuthError.UNKNOWN_CREDENTIAL_IDENTIFIER,
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
            log.debug("Nonce validation: proofNonce present={}, session.cNonce present={}", proofNonce != null, session.cNonce() != null);
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

            // Dispatch by format: sd-jwt or mso_mdoc
            @SuppressWarnings("unchecked")
            Map<String, Object> credConfig = (Map<String, Object>) allConfigs.get(configId != null ? configId : DEFAULT_CONFIG_ID);
            String format = (String) credConfig.get("format");
            String credential;
            if ("mso_mdoc".equals(format)) {
                credential = buildMdocCredential(walletKey, record, credConfig);
            } else {
                credential = buildSdJwtCredential(walletKey, record);
            }

            issuanceStore.updateStatus(issuanceRecordId, "credential_issued");
            log.info("Credential issued: issuanceId={}, format={}", issuanceRecordId, format);

            // H11: Invalidate nonce after successful issuance (one-time use)
            sessionStore.invalidateNonce(session.cNonce());
            log.debug("Nonce invalidated (one-time use)");

            return CredentialResponse.success(credential);

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
        String scope = null;
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
            scope = parParams.get("scope");
            log.info("Authorize via PAR: client_id={}, request_uri={}", clientId, requestUri);
        }

        var metadata = new LinkedHashMap<String, Object>();
        if (clientId != null) metadata.put("client_id", clientId);
        if (redirectUri != null) metadata.put("redirect_uri", redirectUri);
        if (codeChallenge != null) metadata.put("code_challenge", codeChallenge);
        if (issuerState != null) {
            metadata.put("issuer_state", issuerState);
            // Issuer-initiated: resolve issuanceRecordId linked to this issuerState
            Map<String, Object> issuerMeta = sessionStore.consumeIssuerState(issuerState);
            if (issuerMeta != null && issuerMeta.containsKey("issuanceRecordId")) {
                metadata.put("issuanceRecordId", issuerMeta.get("issuanceRecordId"));
            }
        } else {
            // Wallet-initiated: redirect to identification portal (RFC 6749 §3.1)
            String sessionToken = sessionStore.randomToken(16);
            var pendingData = new LinkedHashMap<String, Object>(metadata);
            if (state != null) pendingData.put("state", state);
            if (scope != null) pendingData.put("scope", scope);
            sessionStore.storePendingAuthorization(sessionToken, pendingData);
            String identifyUrl = identifyBaseUrl + "?session=" + sessionToken;
            log.info("Wallet-initiated flow: redirecting to identification portal, session={}", sessionToken);
            return AuthorizeResult.withIdentifyRedirect(identifyUrl);
        }

        SessionData session = new SessionData(
                sessionStore.randomToken(16), null, null, Instant.now(), metadata
        );
        String authCode = sessionStore.createAuthCode(session);
        log.info("Authorization code issued: client_id={}, has_redirect={}", clientId, redirectUri != null);

        return AuthorizeResult.withCode(authCode, redirectUri, state);
    }

    /**
     * Complete wallet-initiated identification.
     * Called after the user identifies at the identification portal.
     * Creates an IssuanceRecord with real data and returns the authorization code.
     *
     * @param sessionToken the pending authorization session token
     * @param credentialDataJson JSON with credential claims (given_name, family_name, birth_date, etc.)
     * @param sourceType identification method (e.g. "x509_cert")
     * @param sourceRef reference to the identification source
     * @return AuthorizeResult with code and redirect URI for the wallet callback
     */
    public AuthorizeResult completeIdentification(String sessionToken, String credentialDataJson,
                                                   String sourceType, String sourceRef) {
        Map<String, Object> pending = sessionStore.consumePendingAuthorization(sessionToken);
        if (pending == null) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                    "Invalid or expired identification session");
        }

        // Resolve credential type from scope (instead of hardcoded constant)
        String scope = (String) pending.get("scope");
        String credentialConfigId = resolveCredentialConfigId(scope);
        var record = issuanceStore.create(credentialConfigId, credentialDataJson, sourceType, sourceRef);
        log.info("Identification complete: issuanceRecordId={}, credentialConfig={}, source={}",
                record.id(), credentialConfigId, sourceType);

        // Rebuild metadata with issuanceRecordId
        var metadata = new LinkedHashMap<String, Object>();
        if (pending.containsKey("client_id")) metadata.put("client_id", pending.get("client_id"));
        if (pending.containsKey("redirect_uri")) metadata.put("redirect_uri", pending.get("redirect_uri"));
        if (pending.containsKey("code_challenge")) metadata.put("code_challenge", pending.get("code_challenge"));
        metadata.put("issuanceRecordId", record.id());

        SessionData session = new SessionData(
                sessionStore.randomToken(16), null, null, Instant.now(), metadata
        );
        String authCode = sessionStore.createAuthCode(session);

        String redirectUri = (String) pending.get("redirect_uri");
        String state = pending.containsKey("state") ? String.valueOf(pending.get("state")) : null;
        log.info("Authorization code issued after identification: client_id={}, issuanceId={}",
                pending.get("client_id"), record.id());

        return AuthorizeResult.withCode(authCode, redirectUri, state);
    }

    /**
     * Get credential claims metadata for a pending identification session.
     * Reads the scope from the pending authorization and returns the claims
     * that the credential type requires, for the frontend to render a dynamic form.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getIdentificationClaims(String sessionToken) {
        Map<String, Object> pending = sessionStore.getPendingAuthorization(sessionToken);
        if (pending == null) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                    "Invalid or expired identification session");
        }
        String scope = (String) pending.get("scope");
        String credentialConfigId = resolveCredentialConfigId(scope);
        Map<String, Object> configs = buildCredentialConfigurations();
        Map<String, Object> credConfig = (Map<String, Object>) configs.get(credentialConfigId);
        Map<String, Object> credentialMetadata = (Map<String, Object>) credConfig.get("credential_metadata");

        var result = new LinkedHashMap<String, Object>();
        result.put("credential_configuration_id", credentialConfigId);
        result.put("claims", credentialMetadata.get("claims"));
        result.put("display", credentialMetadata.get("display"));
        return result;
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
                    : DEFAULT_CONFIG_ID;

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

            // Email-initiated flow: create draft and send invitation email
            String recipientEmail = extractRecipientEmail(credentialData, credentialType);
            if (recipientEmail != null) {
                var draft = issuanceStore.createDraft(credentialType, credentialData, sourceType, sourceRef, recipientEmail);
                log.info("Draft IssuanceRecord created: id={}, type={}, email={}", draft.id(), credentialType, recipientEmail);

                String recipientName = extractRecipientName(credentialData, credentialType);
                String invitationLink = walletBaseUrl;
                emailService.sendCredentialInvitation(recipientEmail, recipientName, invitationLink);

                var result = new LinkedHashMap<String, Object>();
                result.put("issuance_id", draft.id());
                result.put("status", "draft");
                result.put("email_sent_to", recipientEmail);
                return result;
            }

            var record = issuanceStore.create(credentialType, credentialData, sourceType, sourceRef);
            log.info("IssuanceRecord created: id={}, type={}, source={}", record.id(), credentialType, sourceType);

            CredentialOffer offer;
            String txCodeValue = null;
            if (config.isHaip()) {
                log.info("Credential offer: grant_type=authorization_code (HAIP), issuanceId={}", record.id());
                String issuerState = sessionStore.randomToken(16);
                sessionStore.storeIssuerState(issuerState, Map.of("issuanceRecordId", record.id()));
                String offerConfigId = resolveOfferConfigId(credentialType);
                offer = CredentialOffer.authorizationCode(baseUrl, offerConfigId, issuerState);
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
                String offerConfigId = resolveOfferConfigId(credentialType);
                offer = CredentialOffer.preAuthorized(baseUrl, offerConfigId, preAuthCode, txCodeRequired);
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

    public Map<String, Object> listIssuanceRecords(int page, int size, String sort, String order) {
        int offset = (page - 1) * size;
        var records = issuanceStore.findAll(offset, size, sort, order);
        int total = issuanceStore.count();

        var items = new ArrayList<Map<String, Object>>();
        for (var r : records) {
            var item = new LinkedHashMap<String, Object>();
            item.put("id", r.id());
            item.put("credential_type", r.credentialType());
            item.put("status", r.status());
            item.put("source_type", r.sourceType());
            item.put("source_ref", r.sourceRef());
            item.put("pre_auth_code", r.preAuthCode());
            item.put("offer_id", r.offerId());
            item.put("created_at", r.createdAt() != null ? r.createdAt().toInstant().toString() : null);
            item.put("updated_at", r.updatedAt() != null ? r.updatedAt().toInstant().toString() : null);

            // Extract subject name from credentialData JSON
            // PID uses given_name/family_name; Student ID uses firstName/familyName
            String subjectName = null;
            try {
                var data = MAPPER.readTree(r.credentialData());
                String given = data.has("given_name") ? data.get("given_name").asText()
                        : data.has("firstName") ? data.get("firstName").asText() : null;
                String family = data.has("family_name") ? data.get("family_name").asText()
                        : data.has("familyName") ? data.get("familyName").asText() : null;
                if (given != null && family != null) subjectName = given + " " + family;
                else if (given != null) subjectName = given;
                else if (family != null) subjectName = family;
            } catch (Exception ignored) {}
            item.put("subject_name", subjectName);
            item.put("recipient_email", r.recipientEmail());
            item.put("credential_data", r.credentialData());

            items.add(item);
        }

        var result = new LinkedHashMap<String, Object>();
        result.put("records", items);
        result.put("total", total);
        result.put("page", page);
        result.put("size", size);
        return result;
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

    /**
     * Resolve credential_configuration_id from the requested scope.
     * Iterates credential configurations to find the one matching the scope.
     * Falls back to the default when scope is null or no match found.
     */
    private String resolveCredentialConfigId(String scope) {
        if (scope == null) return DEFAULT_CONFIG_ID;
        var configs = buildCredentialConfigurations();
        for (var entry : configs.entrySet()) {
            if (entry.getValue() instanceof Map<?, ?> config) {
                if (scope.equals(config.get("scope"))) return entry.getKey();
            }
        }
        log.warn("No credential configuration found for scope={}, using default", scope);
        return DEFAULT_CONFIG_ID;
    }

    /** Map a credential_type from the trigger request to a known credential_configuration_id. */
    private String resolveOfferConfigId(String credentialType) {
        if (credentialType == null) return DEFAULT_CONFIG_ID;
        var configs = buildCredentialConfigurations();
        if (configs.containsKey(credentialType)) return credentialType;
        return DEFAULT_CONFIG_ID;
    }

    private Map<String, Object> buildCredentialConfigurations() {
        var configs = new LinkedHashMap<String, Object>();

        // --- SD-JWT PID configurations (6) ---
        var pidClaims = pidClaims();
        var pidDisplay = pidDisplay();

        configs.put("eu.europa.ec.eudi.pid.1",
                buildSdJwtConfig("eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.pid.1", pidClaims, pidDisplay));
        configs.put("eu.europa.ec.eudi.pid.1.attestation",
                buildSdJwtConfig("eu.europa.ec.eudi.pid.1.attestation", "eu.europa.ec.eudi.pid.1", pidClaims, pidDisplay));
        configs.put("eu.europa.ec.eudi.pid.1.jwt.keyattest",
                buildSdJwtConfig("eu.europa.ec.eudi.pid.1.jwt.keyattest", "eu.europa.ec.eudi.pid.1", pidClaims, pidDisplay));
        configs.put("eu.europa.ec.eudi.pid.1.attestation.keyattest",
                buildSdJwtConfig("eu.europa.ec.eudi.pid.1.attestation.keyattest", "eu.europa.ec.eudi.pid.1", pidClaims, pidDisplay));
        configs.put("eu.europa.ec.eudi.pid.1.jwt_and_attestation.keyattest",
                buildSdJwtConfig("eu.europa.ec.eudi.pid.1.jwt_and_attestation.keyattest", "eu.europa.ec.eudi.pid.1", pidClaims, pidDisplay));
        configs.put("eu.europa.ec.eudi.pid.1.nobinding",
                buildSdJwtConfig("eu.europa.ec.eudi.pid.1.nobinding", "eu.europa.ec.eudi.pid.1", pidClaims, pidDisplay));

        // --- mdoc PID configurations (4) ---
        var mdocPidClaims = mdocPidClaims();
        var mdocPidDisplay = pidDisplay();

        configs.put("eu.europa.ec.eudi.pid.mdoc.1",
                buildMdocConfig("eu.europa.ec.eudi.pid.mdoc.1", "eu.europa.ec.eudi.pid.1", mdocPidClaims, mdocPidDisplay));
        configs.put("eu.europa.ec.eudi.pid.mdoc.1.attestation",
                buildMdocConfig("eu.europa.ec.eudi.pid.mdoc.1.attestation", "eu.europa.ec.eudi.pid.1", mdocPidClaims, mdocPidDisplay));
        configs.put("eu.europa.ec.eudi.pid.mdoc.1.jwt.keyattest",
                buildMdocConfig("eu.europa.ec.eudi.pid.mdoc.1.jwt.keyattest", "eu.europa.ec.eudi.pid.1", mdocPidClaims, mdocPidDisplay));
        configs.put("eu.europa.ec.eudi.pid.mdoc.1.attestation.keyattest",
                buildMdocConfig("eu.europa.ec.eudi.pid.mdoc.1.attestation.keyattest", "eu.europa.ec.eudi.pid.1", mdocPidClaims, mdocPidDisplay));

        // --- mDL configurations (2) ---
        var mdlClaims = mdlClaims();
        var mdlDisplay = mdlDisplay();

        configs.put("org.iso.18013.5.1.mDL",
                buildMdocConfig("org.iso.18013.5.1.mDL", "org.iso.18013.5.1.mDL", mdlClaims, mdlDisplay));
        configs.put("org.iso.18013.5.1.mDL.attestation",
                buildMdocConfig("org.iso.18013.5.1.mDL.attestation", "org.iso.18013.5.1.mDL", mdlClaims, mdlDisplay));

        // --- Student ID SD-JWT (EWC ds010) ---
        var studentIdClaims = studentIdClaims();
        var studentIdDisplay = studentIdDisplay();
        configs.put(STUDENT_ID_SD_JWT,
                buildSdJwtConfig(STUDENT_ID_SD_JWT, STUDENT_ID_VCT, studentIdClaims, studentIdDisplay));

        return configs;
    }

    private static Map<String, Object> buildSdJwtConfig(String scope, String vct,
                                                         List<Map<String, Object>> claims,
                                                         List<Map<String, Object>> display) {
        var config = new LinkedHashMap<String, Object>();
        config.put("format", "dc+sd-jwt");
        config.put("scope", scope);
        config.put("cryptographic_binding_methods_supported", List.of("jwk"));
        config.put("credential_signing_alg_values_supported", List.of("ES256"));
        config.put("proof_types_supported", Map.of(
                "jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))
        ));
        config.put("vct", vct);

        var credentialMetadata = new LinkedHashMap<String, Object>();
        credentialMetadata.put("display", display);
        credentialMetadata.put("claims", claims);
        config.put("credential_metadata", credentialMetadata);
        return config;
    }

    private static Map<String, Object> buildMdocConfig(String scope, String docType,
                                                        List<Map<String, Object>> claims,
                                                        List<Map<String, Object>> display) {
        var config = new LinkedHashMap<String, Object>();
        config.put("format", "mso_mdoc");
        config.put("scope", scope);
        config.put("doctype", docType);
        config.put("cryptographic_binding_methods_supported", List.of("cose_key"));
        config.put("credential_signing_alg_values_supported", List.of(-7)); // COSE alg ES256 = -7
        config.put("proof_types_supported", Map.of(
                "jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))
        ));

        var credentialMetadata = new LinkedHashMap<String, Object>();
        credentialMetadata.put("display", display);
        credentialMetadata.put("claims", claims);
        config.put("credential_metadata", credentialMetadata);
        return config;
    }

    private static List<Map<String, Object>> pidClaims() {
        return List.of(
                Map.of("path", List.of("given_name"), "display", List.of(Map.of("name", "Given Name", "locale", "en"))),
                Map.of("path", List.of("family_name"), "display", List.of(Map.of("name", "Surname", "locale", "en"))),
                Map.of("path", List.of("birth_date"), "display", List.of(Map.of("name", "Date of Birth", "locale", "en"))),
                Map.of("path", List.of("issuing_authority"), "display", List.of(Map.of("name", "Issuing Authority", "locale", "en"))),
                Map.of("path", List.of("issuing_country"), "display", List.of(Map.of("name", "Issuing Country", "locale", "en")))
        );
    }

    private static List<Map<String, Object>> mdocPidClaims() {
        return List.of(
                Map.of("path", List.of("given_name"), "display", List.of(Map.of("name", "Given Name", "locale", "en"))),
                Map.of("path", List.of("family_name"), "display", List.of(Map.of("name", "Surname", "locale", "en"))),
                Map.of("path", List.of("birth_date"), "display", List.of(Map.of("name", "Date of Birth", "locale", "en"))),
                Map.of("path", List.of("issuing_authority"), "display", List.of(Map.of("name", "Issuing Authority", "locale", "en"))),
                Map.of("path", List.of("issuing_country"), "display", List.of(Map.of("name", "Issuing Country", "locale", "en")))
        );
    }

    private static List<Map<String, Object>> pidDisplay() {
        return List.of(Map.of(
                "name", "EUDI PID",
                "locale", "en",
                "description", "EU Digital Identity Personal Identification Data"
        ));
    }

    private static List<Map<String, Object>> mdlClaims() {
        return List.of(
                Map.of("path", List.of("family_name"), "display", List.of(Map.of("name", "Surname", "locale", "en"))),
                Map.of("path", List.of("given_name"), "display", List.of(Map.of("name", "Given Name", "locale", "en"))),
                Map.of("path", List.of("birth_date"), "display", List.of(Map.of("name", "Date of Birth", "locale", "en"))),
                Map.of("path", List.of("issue_date"), "display", List.of(Map.of("name", "Date of Issue", "locale", "en"))),
                Map.of("path", List.of("expiry_date"), "display", List.of(Map.of("name", "Date of Expiry", "locale", "en"))),
                Map.of("path", List.of("issuing_country"), "display", List.of(Map.of("name", "Issuing Country", "locale", "en"))),
                Map.of("path", List.of("issuing_authority"), "display", List.of(Map.of("name", "Issuing Authority", "locale", "en"))),
                Map.of("path", List.of("document_number"), "display", List.of(Map.of("name", "Licence Number", "locale", "en"))),
                Map.of("path", List.of("driving_privileges"), "display", List.of(Map.of("name", "Categories", "locale", "en")))
        );
    }

    private static List<Map<String, Object>> mdlDisplay() {
        return List.of(Map.of(
                "name", "Mobile Driving Licence",
                "locale", "en",
                "description", "ISO 18013-5 Mobile Driving Licence"
        ));
    }

    private static List<Map<String, Object>> studentIdClaims() {
        return List.of(
                Map.of("path", List.of("identifier"), "display", List.of(Map.of("name", "Identifier", "locale", "en"))),
                Map.of("path", List.of("familyName"), "display", List.of(Map.of("name", "Family Name", "locale", "en"))),
                Map.of("path", List.of("firstName"), "display", List.of(Map.of("name", "First Name", "locale", "en"))),
                Map.of("path", List.of("displayName"), "display", List.of(Map.of("name", "Display Name", "locale", "en"))),
                Map.of("path", List.of("commonName"), "display", List.of(Map.of("name", "Common Name", "locale", "en"))),
                Map.of("path", List.of("dateOfBirth"), "display", List.of(Map.of("name", "Date of Birth", "locale", "en"))),
                Map.of("path", List.of("mail"), "display", List.of(Map.of("name", "Email", "locale", "en"))),
                Map.of("path", List.of("schacPersonalUniqueCode"), "display", List.of(Map.of("name", "SCHAC Unique Code", "locale", "en"))),
                Map.of("path", List.of("schacPersonalUniqueID"), "display", List.of(Map.of("name", "SCHAC Unique ID", "locale", "en"))),
                Map.of("path", List.of("schacHomeOrganization"), "display", List.of(Map.of("name", "Home Organization", "locale", "en"))),
                Map.of("path", List.of("eduPersonPrincipalName"), "display", List.of(Map.of("name", "Principal Name", "locale", "en"))),
                Map.of("path", List.of("eduPersonPrimaryAffiliation"), "display", List.of(Map.of("name", "Primary Affiliation", "locale", "en"))),
                Map.of("path", List.of("eduPersonAffiliation"), "display", List.of(Map.of("name", "Affiliation", "locale", "en"))),
                Map.of("path", List.of("eduPersonScopedAffiliation"), "display", List.of(Map.of("name", "Scoped Affiliation", "locale", "en"))),
                Map.of("path", List.of("eduPersonAssurance"), "display", List.of(Map.of("name", "Assurance Level", "locale", "en")))
        );
    }

    private static List<Map<String, Object>> studentIdDisplay() {
        return List.of(Map.of(
                "name", "Student ID",
                "locale", "en",
                "description", "Verifiable Student ID (EWC ds010)"
        ));
    }

    /** Build an SD-JWT VC credential from the issuance record data. */
    private String buildSdJwtCredential(ECKey walletKey, IssuanceStore.IssuanceRecord record) {
        try {
            String vct = resolveVct(record.credentialType());
            String subjectPrefix = resolveSubjectPrefix(record.credentialType());
            SdJwtBuilder builder = new SdJwtBuilder(issuerKey)
                    .vct(vct)
                    .issuer(baseUrl)
                    .subject(subjectPrefix + sessionStore.randomToken(8))
                    .holderKey(walletKey)
                    .x5cChain(issuerKey.x5cChain());

            var dataNode = MAPPER.readTree(record.credentialData());
            var fields = dataNode.fields();
            while (fields.hasNext()) {
                var field = fields.next();
                builder.selectiveClaim(field.getKey(), field.getValue().asText());
            }
            builder.plainClaim("issuing_authority", "Fikua Lab");
            builder.plainClaim("issuing_country", "ES");

            return builder.build().serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build SD-JWT credential", e);
        }
    }

    /** Build an mso_mdoc credential from the issuance record data. */
    private String buildMdocCredential(ECKey walletKey, IssuanceStore.IssuanceRecord record,
                                        Map<String, Object> credConfig) {
        try {
            String docType = (String) credConfig.get("doctype");
            MdocBuilder builder = new MdocBuilder(issuerKey)
                    .docType(docType)
                    .namespace(docType)
                    .deviceKey(walletKey)
                    .x5cChain(issuerKey.x5cChain());

            var dataNode = MAPPER.readTree(record.credentialData());
            var fields = dataNode.fields();
            while (fields.hasNext()) {
                var field = fields.next();
                builder.element(field.getKey(), field.getValue().asText());
            }
            builder.element("issuing_authority", "Fikua Lab");
            builder.element("issuing_country", "ES");

            return builder.build().toBase64Url();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build mso_mdoc credential", e);
        }
    }

    /** Request an OTP for email-based identification. */
    public Map<String, Object> requestEmailOtp(String sessionToken, String email) {
        var pending = sessionStore.getPendingAuthorization(sessionToken);
        if (pending == null) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                    "Invalid or expired identification session");
        }
        String otp = generateOtpCode();
        sessionStore.storeOtp(email.toLowerCase().trim(), otp, sessionToken);
        emailService.sendOtp(email, otp);
        log.info("OTP sent to {} for session {}", email, sessionToken);
        return Map.of("status", "otp_sent", "email", email);
    }

    /** Validate OTP and complete identification by finding draft IssuanceRecord. */
    public AuthorizeResult validateEmailOtp(String sessionToken, String email, String otp) {
        String normalizedEmail = email.toLowerCase().trim();
        String validatedSession = sessionStore.consumeOtp(normalizedEmail, otp);
        if (validatedSession == null || !validatedSession.equals(sessionToken)) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "Invalid or expired OTP");
        }

        var record = issuanceStore.findDraftByEmail(normalizedEmail);
        if (record == null) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                    "No pending credential found for this email");
        }

        var pending = sessionStore.consumePendingAuthorization(sessionToken);
        if (pending == null) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                    "Invalid or expired identification session");
        }

        issuanceStore.updateStatus(record.id(), "offer_created");

        var metadata = new LinkedHashMap<String, Object>();
        if (pending.containsKey("client_id")) metadata.put("client_id", pending.get("client_id"));
        if (pending.containsKey("redirect_uri")) metadata.put("redirect_uri", pending.get("redirect_uri"));
        if (pending.containsKey("code_challenge")) metadata.put("code_challenge", pending.get("code_challenge"));
        metadata.put("issuanceRecordId", record.id());

        SessionData session = new SessionData(
                sessionStore.randomToken(16), null, null, Instant.now(), metadata);
        String authCode = sessionStore.createAuthCode(session);

        String redirectUri = (String) pending.get("redirect_uri");
        String state = pending.containsKey("state") ? String.valueOf(pending.get("state")) : null;
        return AuthorizeResult.withCode(authCode, redirectUri, state);
    }

    private String generateOtpCode() {
        int code = new java.security.SecureRandom().nextInt(900000) + 100000;
        return String.valueOf(code);
    }

    /** Extract recipient email from credential data for email-initiated flow. */
    private String extractRecipientEmail(String credentialDataJson, String credentialType) {
        if (!STUDENT_ID_SD_JWT.equals(credentialType)) return null;
        try {
            var data = MAPPER.readTree(credentialDataJson);
            if (data.has("mail") && !data.get("mail").asText().isBlank()) {
                return data.get("mail").asText().trim();
            }
        } catch (Exception ignored) {}
        return null;
    }

    /** Extract recipient display name from credential data. */
    private String extractRecipientName(String credentialDataJson, String credentialType) {
        try {
            var data = MAPPER.readTree(credentialDataJson);
            // Student ID uses firstName/familyName; PID uses given_name/family_name
            String first = data.has("firstName") ? data.get("firstName").asText()
                    : data.has("given_name") ? data.get("given_name").asText() : null;
            String last = data.has("familyName") ? data.get("familyName").asText()
                    : data.has("family_name") ? data.get("family_name").asText() : null;
            if (first != null && last != null) return first + " " + last;
            if (first != null) return first;
            if (last != null) return last;
        } catch (Exception ignored) {}
        return "Student";
    }

    private String resolveVct(String credentialType) {
        if (credentialType != null && credentialType.startsWith("student-id")) return STUDENT_ID_VCT;
        return "eu.europa.ec.eudi.pid.1";
    }

    private String resolveSubjectPrefix(String credentialType) {
        if (credentialType != null && credentialType.startsWith("student-id")) return "urn:fikua:student:";
        return "urn:fikua:pid:";
    }

    /** Result of the authorize endpoint. */
    public record AuthorizeResult(String code, String redirectUri, String state, String identifyRedirect) {
        /** Issuer-initiated: immediate code. */
        static AuthorizeResult withCode(String code, String redirectUri, String state) {
            return new AuthorizeResult(code, redirectUri, state, null);
        }

        /** Wallet-initiated: redirect to identification portal. */
        static AuthorizeResult withIdentifyRedirect(String identifyRedirect) {
            return new AuthorizeResult(null, null, null, identifyRedirect);
        }
    }
}
