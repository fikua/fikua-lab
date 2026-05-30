package com.fikua.verifier.app;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.core.crypto.SigningKey;
import com.fikua.core.oid4vp.*;
import com.fikua.core.oid4vp.CredentialQuery.CredentialMeta;
import com.fikua.core.profile.ProfileConfig;
import com.fikua.verifier.app.port.ProfileStore;
import com.fikua.verifier.app.port.SessionStore;
import com.fikua.verifier.app.port.SessionStore.VerificationSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fikua.core.sdjwt.Disclosure;
import com.fikua.core.sdjwt.SdJwt;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Application service for OID4VP verification.
 * Orchestrates session creation, request object generation, and VP token validation.
 * Zero framework dependencies — all I/O via injected ports.
 */
public class VerificationService {

    private static final Logger log = LoggerFactory.getLogger(VerificationService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String API_PREFIX = "/oid4vp/v1";

    private final SigningKey signingKey;
    private final SessionStore sessionStore;
    private final ProfileStore profileStore;
    private final String baseUrl;

    public VerificationService(SigningKey signingKey, SessionStore sessionStore,
                               ProfileStore profileStore, String baseUrl) {
        this.signingKey = signingKey;
        this.sessionStore = sessionStore;
        this.profileStore = profileStore;
        this.baseUrl = baseUrl;
    }

    /** Get the active verifier profile configuration. */
    public ProfileConfig getActiveConfig() {
        ProfileStore.ActiveProfile active = profileStore.findActive();
        if (active != null) {
            return active.config();
        }
        // Fallback to plain verifier preset
        return com.fikua.core.profile.ProfilePresets.plainVerifier();
    }

    /**
     * Create a new verification session with an Authorization Request.
     *
     * @param credentialType the credential type to request (e.g. "eu.europa.ec.eudi.pid.1")
     * @param requestedClaims the claims to request (e.g. ["given_name", "family_name"])
     * @return the created session with request_uri
     */
    public VerificationSession createSession(String credentialType, List<String> requestedClaims) {
        ProfileConfig config = getActiveConfig();

        String sessionId = randomToken(16);
        String state = randomToken(32);
        String nonce = randomToken(32);

        // Build DCQL query
        List<ClaimQuery> claims = requestedClaims.stream()
                .map(name -> new ClaimQuery(List.of(name), null, null))
                .toList();
        DcqlQuery dcqlQuery = new DcqlQuery(List.of(
                new CredentialQuery(
                        "requested_credential",
                        DcqlQuery.FORMAT_DC_SD_JWT,
                        new CredentialMeta(List.of(credentialType)),
                        claims
                )
        ));

        // Determine response mode from profile
        String responseMode = config.responseMode() != null
                ? config.responseMode().protocolValue()
                : "direct_post";

        // Build client_id with prefix
        String clientId = buildClientId(config);

        String responseUri = baseUrl + API_PREFIX + "/response";
        long now = System.currentTimeMillis() / 1000;

        // Serialize DCQL query
        String dcqlQueryJson;
        try {
            dcqlQueryJson = MAPPER.writeValueAsString(dcqlQuery);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize DCQL query", e);
        }

        // Build Authorization Request
        AuthorizationRequest authRequest = new AuthorizationRequest(
                AuthorizationRequest.RESPONSE_TYPE_VP_TOKEN,
                clientId,
                responseMode,
                responseUri,
                nonce,
                state,
                dcqlQuery,
                null, // scope (using DCQL instead)
                null, // client_metadata (will be added in P2 for HAIP)
                "https://self-issued.me/v2",
                clientId,
                now,
                now + 300
        );

        // Sign the Authorization Request as a JAR (RFC 9101): a JWS whose
        // payload is the request parameters, with typ=oauth-authz-req+jwt and
        // the signing cert chain in x5c. HAIP requires a signed request_uri.
        String requestJwt = signRequestObject(authRequest);

        VerificationSession session = new VerificationSession(
                sessionId, state, nonce, dcqlQueryJson, responseMode,
                clientId, responseUri, requestJwt, "pending",
                null, null, null
        );

        sessionStore.store(session);
        log.info("Verification session created: id={}", sessionId);

        return session;
    }

    /**
     * Get the signed Request Object for a session.
     *
     * @param sessionId the session ID
     * @return the signed Request Object JWT string, or null if not found
     */
    public String getRequestObject(String sessionId) {
        VerificationSession session = sessionStore.findById(sessionId);
        if (session == null) {
            return null;
        }
        sessionStore.updateStatus(sessionId, "request_sent");
        return session.requestJwt();
    }

    /**
     * Sign an Authorization Request as a JAR (JWT-Secured Authorization
     * Request, RFC 9101). The request parameters become the JWT payload; the
     * JWS header carries typ=oauth-authz-req+jwt, the kid, and — when the
     * signing key was loaded from a cert — the x5c chain (HAIP 6.1.1). The
     * trust anchor (root CA) is excluded from x5c per HAIP: only the leaf
     * (plus any intermediates) ships in the header.
     */
    private String signRequestObject(AuthorizationRequest authRequest) {
        // Convert the request record to claims, preserving the snake_case
        // @JsonProperty names and dropping null fields.
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = MAPPER.convertValue(authRequest, Map.class);

        var claimsBuilder = new com.nimbusds.jwt.JWTClaimsSet.Builder();
        claims.forEach((k, v) -> {
            if (v != null) {
                claimsBuilder.claim(k, v);
            }
        });

        var headerBuilder = new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                .type(new com.nimbusds.jose.JOSEObjectType(AuthorizationRequest.JAR_TYPE))
                .keyID(signingKey.kid());

        var x5c = signingKey.x5cChain();
        if (x5c != null && !x5c.isEmpty()) {
            headerBuilder.x509CertChain(x5c);
        }

        return signingKey.signJwt(headerBuilder.build(), claimsBuilder.build());
    }

    /**
     * Handle the VP Token response from the wallet.
     *
     * @param state the state parameter from the response
     * @param vpToken the VP Token string
     * @param presentationSubmission the presentation submission JSON (may be null)
     * @return the verification result
     */
    public VerificationResult handleResponse(String state, String vpToken,
                                             String presentationSubmission) {
        VerificationSession session = sessionStore.findByState(state);
        if (session == null) {
            log.warn("No session found for state: {}", state);
            return VerificationResult.error("invalid_request", "Unknown state parameter");
        }

        log.info("VP Token received for session: {}", session.sessionId());

        try {
            // Parse SD-JWT presentation: issuer-jwt~disc1~disc2~...~kb-jwt
            SdJwt sdJwt = SdJwt.parse(vpToken);

            // Extract disclosed claims from disclosures
            Map<String, Object> claims = new LinkedHashMap<>();
            for (Disclosure d : sdJwt.disclosures()) {
                claims.put(d.claimName(), d.claimValue());
            }

            log.info("Extracted {} claims from VP Token: {}", claims.size(), claims.keySet());

            // TODO P1: Verify issuer signature, disclosure hashes, KB-JWT (aud, nonce, sd_hash)

            String claimsJson = MAPPER.writeValueAsString(claims);
            sessionStore.updateResult(session.sessionId(), "verified", vpToken, claimsJson, null);
            return VerificationResult.success(claims);
        } catch (Exception e) {
            log.error("Failed to parse VP Token: {}", e.getMessage());
            sessionStore.updateResult(session.sessionId(), "failed", vpToken, null, e.getMessage());
            return VerificationResult.error("invalid_presentation", "Failed to parse VP Token: " + e.getMessage());
        }
    }

    /**
     * Get the verification result for a session.
     *
     * @param sessionId the session ID
     * @return the verification result, or null if session not found
     */
    public VerificationResult getResult(String sessionId) {
        VerificationSession session = sessionStore.findById(sessionId);
        if (session == null) {
            return null;
        }

        return switch (session.status()) {
            case "verified" -> {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> claims = session.verifiedClaimsJson() != null
                            ? MAPPER.readValue(session.verifiedClaimsJson(), Map.class)
                            : Map.of();
                    yield VerificationResult.success(claims);
                } catch (JsonProcessingException e) {
                    yield VerificationResult.success(Map.of());
                }
            }
            case "failed" -> VerificationResult.error("verification_failed", session.error());
            default -> VerificationResult.error("pending", "Verification not yet completed");
        };
    }

    /** Find a session by its state parameter. */
    public VerificationSession getSessionByState(String state) {
        return sessionStore.findByState(state);
    }

    /** Clear all session state (for dev/test reset). */
    public void resetState() {
        sessionStore.clear();
        log.info("Verification state reset");
    }

    /** Build the request_uri URL for a session. */
    public String buildRequestUri(String sessionId) {
        return baseUrl + API_PREFIX + "/request/" + sessionId;
    }

    private String buildClientId(ProfileConfig config) {
        if (config.clientIdPrefix() != null) {
            return switch (config.clientIdPrefix()) {
                case X509_SAN_DNS -> "x509_san_dns:" + extractDns(baseUrl);
                case X509_HASH -> "x509_hash:" + computeCertHash();
                default -> extractDns(baseUrl);
            };
        }
        return extractDns(baseUrl);
    }

    private String extractDns(String url) {
        try {
            var uri = java.net.URI.create(url);
            return uri.getHost();
        } catch (Exception e) {
            return url;
        }
    }

    private String computeCertHash() {
        // TODO P1: compute SHA-256 hash of verifier certificate DER encoding
        return "stub-cert-hash";
    }

    private static String randomToken(int bytes) {
        byte[] buf = new byte[bytes];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
