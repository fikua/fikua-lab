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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private static final String CREDENTIAL_CONFIG_ID = "eu.europa.ec.eudi.pid_dc+sd-jwt";
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

    /** Create a credential offer based on profile config. Returns offer JSON or offer URI map. */
    public Map<String, Object> createCredentialOffer(ProfileConfig config) {
        return createCredentialOffer(config, false);
    }

    /** Create a credential offer with optional tx_code. */
    public Map<String, Object> createCredentialOffer(ProfileConfig config, boolean txCodeRequired) {
        try {
            CredentialOffer offer;
            if (config.isHaip()) {
                String issuerState = sessionStore.randomToken(16);
                offer = CredentialOffer.authorizationCode(baseUrl, CREDENTIAL_CONFIG_ID, issuerState);
            } else {
                var metadata = new LinkedHashMap<String, Object>();
                String txCodeValue = null;
                if (txCodeRequired) {
                    txCodeValue = generateTxCode();
                    metadata.put("tx_code", txCodeValue);
                }
                SessionData session = new SessionData(
                        sessionStore.randomToken(16), null, null, Instant.now(), Map.copyOf(metadata)
                );
                String preAuthCode = sessionStore.createPreAuthCode(session);
                offer = CredentialOffer.preAuthorized(baseUrl, CREDENTIAL_CONFIG_ID, preAuthCode, txCodeRequired);
            }

            String offerJson = MAPPER.writeValueAsString(offer);

            if (config.credentialOffer() == CredentialOfferVariant.BY_REFERENCE) {
                String offerId = sessionStore.storeCredentialOffer(offerJson);
                String offerUri = baseUrl + API_PREFIX + "/credential-offer/" + offerId;
                return Map.of("credential_offer_uri", offerUri);
            } else {
                return Map.of("credential_offer", MAPPER.readTree(offerJson));
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to create offer", e);
        }
    }

    public String getCredentialOffer(String offerId) {
        return sessionStore.getCredentialOffer(offerId);
    }

    /** Handle pre-authorized code token request. */
    public TokenResponse handlePreAuthToken(Map<String, String> params, ProfileConfig config) {
        TokenRequest request = TokenRequest.fromParams(params);
        log.info("Token request: grant_type={}", request.grantType());

        if (request.preAuthorizedCode() == null) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_GRANT, "Missing pre-authorized_code");
        }

        SessionData session = sessionStore.consumePreAuthCode(request.preAuthorizedCode());
        if (session == null) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_GRANT, "Invalid or expired pre-authorized_code");
        }

        // Validate tx_code if the session requires it (OID4VCI §4.1.1)
        String expectedTxCode = (String) session.metadata().get("tx_code");
        if (expectedTxCode != null) {
            if (request.txCode() == null || !expectedTxCode.equals(request.txCode())) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_GRANT, "Invalid or missing tx_code");
            }
        }

        String cNonce = sessionStore.generateNonce();
        SessionData tokenSession = new SessionData(
                session.sessionId(), cNonce, null, Instant.now(), session.metadata()
        );
        String accessToken = sessionStore.createAccessToken(tokenSession);
        sessionStore.createNonce(session.sessionId());

        return TokenResponse.bearer(accessToken, cNonce);
    }

    /** Handle authorization_code token request (HAIP). */
    public TokenResponse handleAuthCodeToken(Map<String, String> params, ProfileConfig config, String dpopHeader) {
        TokenRequest request = TokenRequest.fromParams(params);
        log.info("Token request: grant_type={}", request.grantType());

        // Validate client attestation for HAIP
        clientAttestationValidator.validate(
                params.get("client_assertion_type"),
                params.get("client_assertion")
        );

        // Validate DPoP if required
        ECKey dpopKey = null;
        if (config.requiresDPoP()) {
            dpopKey = dpopValidator.validate(dpopHeader, "POST", baseUrl + API_PREFIX + "/token", null);
        }

        // Consume authorization code
        SessionData session = sessionStore.consumeAuthCode(request.code());
        if (session == null) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_GRANT, "Invalid authorization code");
        }

        // Validate PKCE
        if (config.requiresPkce()) {
            if (request.codeVerifier() == null) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "Missing code_verifier");
            }
            String storedChallenge = (String) session.metadata().get("code_challenge");
            if (storedChallenge == null || !PkceUtil.verifyS256(request.codeVerifier(), storedChallenge)) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_GRANT, "PKCE verification failed");
            }
        }

        String cNonce = sessionStore.generateNonce();
        SessionData tokenSession = new SessionData(
                session.sessionId(), cNonce, dpopKey, Instant.now(), session.metadata()
        );
        String accessToken = sessionStore.createAccessToken(tokenSession);
        sessionStore.createNonce(session.sessionId());

        if (config.requiresDPoP()) {
            return TokenResponse.dpop(accessToken, cNonce);
        }
        return TokenResponse.bearer(accessToken, cNonce);
    }

    /** Handle token request (dispatches to pre-auth or auth_code). */
    public TokenResponse handleToken(Map<String, String> params, ProfileConfig config, String dpopHeader) {
        TokenRequest request = TokenRequest.fromParams(params);
        if (request.isPreAuthorizedCode()) {
            return handlePreAuthToken(params, config);
        } else if (request.isAuthorizationCode()) {
            return handleAuthCodeToken(params, config, dpopHeader);
        }
        throw OAuthErrorException.badRequest(OAuthError.UNSUPPORTED_GRANT_TYPE,
                "Unsupported grant type: " + request.grantType());
    }

    /** Generate a new nonce. */
    public Map<String, Object> generateNonce() {
        String nonce = sessionStore.generateNonce();
        return Map.of("c_nonce", nonce, "c_nonce_expires_in", 86400);
    }

    /** Issue a credential. */
    public CredentialResponse issueCredential(String accessToken, String body,
                                               ProfileConfig config, String dpopHeader) {
        SessionData session = sessionStore.getAccessTokenSession(accessToken);
        if (session == null) {
            throw new OAuthErrorException(401, new OAuthError(OAuthError.INVALID_TOKEN, "Invalid access token"));
        }

        // Validate DPoP for resource request if required
        if (config.requiresDPoP()) {
            ECKey resourceDpopKey = dpopValidator.validate(dpopHeader, "POST", baseUrl + API_PREFIX + "/credential", null);
            if (session.dpopKey() != null) {
                try {
                    String expectedThumbprint = session.dpopKey().computeThumbprint().toString();
                    String actualThumbprint = resourceDpopKey.computeThumbprint().toString();
                    if (!expectedThumbprint.equals(actualThumbprint)) {
                        throw new OAuthErrorException(401, new OAuthError(OAuthError.INVALID_TOKEN, "DPoP key mismatch"));
                    }
                } catch (OAuthErrorException e) {
                    throw e;
                } catch (Exception e) {
                    throw new OAuthErrorException(401, new OAuthError(OAuthError.INVALID_TOKEN, "DPoP thumbprint verification failed"));
                }
            }
        }

        try {
            CredentialRequest request = MAPPER.readValue(body, CredentialRequest.class);
            log.info("Credential request: format={}, credential_configuration_id={}",
                    request.format(), request.credentialConfigurationId());

            // Validate credential_configuration_id (OID4VCI 1.0 Final §7.2)
            if (request.credentialConfigurationId() != null
                    && !CREDENTIAL_CONFIG_ID.equals(request.credentialConfigurationId())) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST,
                        "Unsupported credential_configuration_id: " + request.credentialConfigurationId());
            }

            ECKey walletKey = ProofValidator.validate(request.proof(), baseUrl, session.cNonce());

            SdJwtBuilder builder = new SdJwtBuilder(issuerKey)
                    .vct("eu.europa.ec.eudi.pid.1")
                    .issuer(baseUrl)
                    .subject("urn:fikua:pid:" + sessionStore.randomToken(8))
                    .holderKey(walletKey)
                    .x5cChain(issuerKey.x5cChain());

            String issuanceRecordId = (String) session.metadata().get("issuanceRecordId");
            if (issuanceRecordId != null) {
                var record = issuanceStore.findById(issuanceRecordId);
                if (record != null && record.credentialData() != null) {
                    var dataNode = MAPPER.readTree(record.credentialData());
                    var fields = dataNode.fields();
                    while (fields.hasNext()) {
                        var field = fields.next();
                        builder.selectiveClaim(field.getKey(), field.getValue().asText());
                    }
                    builder.plainClaim("issuing_authority", "Fikua Lab");
                    builder.plainClaim("issuing_country", "ES");
                    issuanceStore.updateStatus(issuanceRecordId, "credential_issued");
                } else {
                    addDefaultClaims(builder);
                }
            } else {
                addDefaultClaims(builder);
            }

            String sdJwt = builder.build().serialize();
            String newNonce = sessionStore.generateNonce();

            return CredentialResponse.success(sdJwt, newNonce);

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
        if (issuerState != null) metadata.put("issuer_state", issuerState);

        SessionData session = new SessionData(
                sessionStore.randomToken(16), null, null, Instant.now(), metadata
        );
        String authCode = sessionStore.createAuthCode(session);

        return new AuthorizeResult(authCode, redirectUri, state);
    }

    /** Handle PAR request (HAIP). */
    public Map<String, Object> handlePar(Map<String, String> params, ProfileConfig config) {
        if (!config.isHaip()) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "PAR not available for this profile");
        }

        clientAttestationValidator.validate(
                params.get("client_assertion_type"),
                params.get("client_assertion")
        );

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
                String issuerState = sessionStore.randomToken(16);
                offer = CredentialOffer.authorizationCode(baseUrl, CREDENTIAL_CONFIG_ID, issuerState);
            } else {
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

    private String generateTxCode() {
        // 6-digit numeric code as specified in CredentialOffer.preAuthorized()
        int code = new java.security.SecureRandom().nextInt(900000) + 100000;
        return String.valueOf(code);
    }

    private void addDefaultClaims(SdJwtBuilder builder) {
        builder.selectiveClaim("given_name", "Jan")
               .selectiveClaim("family_name", "Kowalski")
               .selectiveClaim("birth_date", "1990-01-15")
               .plainClaim("issuing_authority", "Fikua Lab")
               .plainClaim("issuing_country", "EU");
    }

    private Map<String, Object> buildCredentialConfigurations() {
        var credConfig = new LinkedHashMap<String, Object>();
        credConfig.put("format", "dc+sd-jwt");
        credConfig.put("scope", "eu.europa.ec.eudi.pid_dc+sd-jwt");
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
