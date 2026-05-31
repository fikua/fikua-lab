package com.fikua.verifier.app;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.core.crypto.ResponseEncryptionKey;
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
    private final ResponseEncryptionKey encryptionKey;
    private final SessionStore sessionStore;
    private final ProfileStore profileStore;
    private final String baseUrl;

    public VerificationService(SigningKey signingKey, ResponseEncryptionKey encryptionKey,
                               SessionStore sessionStore, ProfileStore profileStore, String baseUrl) {
        this.signingKey = signingKey;
        this.encryptionKey = encryptionKey;
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

        // For encrypted responses (direct_post.jwt / HAIP §5) the verifier must
        // publish its response-encryption key and supported enc values, plus
        // vp_formats, in client_metadata.
        Map<String, Object> clientMetadata = buildClientMetadata(responseMode);

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
                clientMetadata,
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
    /**
     * Handle an encrypted (direct_post.jwt) response. The JWE is decrypted with
     * the verifier's response-encryption key; vp_token, state and
     * presentation_submission are read from the plaintext, then verified as a
     * normal response. For direct_post.jwt the state lives inside the JWE, so
     * decryption must happen before the session can be resolved.
     */
    /** A verification result paired with the state recovered from the response. */
    public record ResponseOutcome(VerificationResult result, String state) {}

    public ResponseOutcome handleEncryptedResponse(String jwe) {
        Map<String, Object> payload;
        try {
            String plaintext = encryptionKey.decrypt(jwe);
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = MAPPER.readValue(plaintext, Map.class);
            payload = parsed;
        } catch (Exception e) {
            log.error("Failed to decrypt direct_post.jwt response: {}", e.getMessage());
            return new ResponseOutcome(VerificationResult.error("invalid_request",
                    "Failed to decrypt response: " + e.getMessage()), null);
        }

        String state = (String) payload.get("state");
        Object vpTokenRaw = payload.get("vp_token");
        // vp_token may be a string or, for multi-credential responses, a map;
        // single-credential DCQL gives a string (or a single-element structure).
        String vpToken = vpTokenRaw instanceof String s ? s : extractFirstVpToken(vpTokenRaw);
        Object submission = payload.get("presentation_submission");
        String presentationSubmission = submission != null ? submission.toString() : null;

        if (state == null || vpToken == null) {
            return new ResponseOutcome(VerificationResult.error("invalid_request",
                    "Decrypted response missing state or vp_token"), state);
        }
        return new ResponseOutcome(handleResponse(state, vpToken, presentationSubmission), state);
    }

    /** Pull the first vp_token value out of a DCQL map/list shape. */
    private static String extractFirstVpToken(Object raw) {
        if (raw instanceof Map<?, ?> map && !map.isEmpty()) {
            Object first = map.values().iterator().next();
            if (first instanceof List<?> list && !list.isEmpty()) {
                return String.valueOf(list.get(0));
            }
            return String.valueOf(first);
        }
        if (raw instanceof List<?> list && !list.isEmpty()) {
            return String.valueOf(list.get(0));
        }
        return null;
    }

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

    /**
     * Build the client_metadata for the Authorization Request. vp_formats is
     * always included (OID4VP-1FINAL-5.1 mandates it for SD-JWT VC). For
     * encrypted response modes (direct_post.jwt), HAIP §5 additionally requires
     * the response-encryption jwks and encrypted_response_enc_values_supported.
     */
    private Map<String, Object> buildClientMetadata(String responseMode) {
        Map<String, Object> metadata = new LinkedHashMap<>();

        // vp_formats_supported: SD-JWT VC with ES256 for issuer + KB JWTs.
        // The current spec (OpenID4VP PR #233) renamed vp_formats to
        // vp_formats_supported inside client_metadata.
        Map<String, Object> sdJwtFormat = new LinkedHashMap<>();
        sdJwtFormat.put("sd-jwt_alg_values", List.of("ES256"));
        sdJwtFormat.put("kb-jwt_alg_values", List.of("ES256"));
        Map<String, Object> vpFormats = new LinkedHashMap<>();
        vpFormats.put("dc+sd-jwt", sdJwtFormat);
        metadata.put("vp_formats_supported", vpFormats);

        if ("direct_post.jwt".equals(responseMode)) {
            Map<String, Object> jwks = new LinkedHashMap<>();
            jwks.put("keys", List.of(encryptionKey.publicJwk()));
            metadata.put("jwks", jwks);
            // HAIP §5 requires both A128GCM and A256GCM be supported.
            metadata.put("encrypted_response_enc_values_supported",
                    ResponseEncryptionKey.ENC_VALUES_SUPPORTED);
        }

        return metadata;
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

    /**
     * Compute the x509_hash client_id value: base64url(SHA-256(DER of leaf
     * certificate)), no padding, per OID4VP §5.10. The leaf is the first
     * entry of the signing key's x5c chain — the same cert the conformance
     * suite recomputes the hash from.
     */
    private String computeCertHash() {
        var x5c = signingKey.x5cChain();
        if (x5c == null || x5c.isEmpty()) {
            throw new IllegalStateException(
                    "x509_hash client_id requires a certificate, but signing key has no x5c chain");
        }
        try {
            byte[] der = x5c.get(0).decode();
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(der);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }

    private static String randomToken(int bytes) {
        byte[] buf = new byte[bytes];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
