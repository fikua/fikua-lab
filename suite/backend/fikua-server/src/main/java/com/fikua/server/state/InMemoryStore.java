package com.fikua.server.state;

import com.nimbusds.jose.jwk.ECKey;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory store for ephemeral session data during OIDF conformance tests.
 * Stores pre-authorized codes, access tokens, c_nonces, credential offers, etc.
 *
 * Not persisted — designed for single test runs.
 */
public class InMemoryStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    // Pre-authorized codes -> session data
    private final Map<String, SessionData> preAuthCodes = new ConcurrentHashMap<>();

    // Access tokens -> session data
    private final Map<String, SessionData> accessTokens = new ConcurrentHashMap<>();

    // c_nonce -> session ID
    private final Map<String, String> nonces = new ConcurrentHashMap<>();

    // Credential offer IDs -> CredentialOffer JSON
    private final Map<String, String> credentialOffers = new ConcurrentHashMap<>();

    // Authorization codes -> session data (for auth_code flow)
    private final Map<String, SessionData> authCodes = new ConcurrentHashMap<>();

    public record SessionData(
            String sessionId,
            String cNonce,
            ECKey dpopKey,
            Instant createdAt,
            Map<String, Object> metadata
    ) {}

    /** Generate a random base64url string. */
    public static String randomToken(int bytes) {
        byte[] buf = new byte[bytes];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    /** Generate a random c_nonce. */
    public String generateNonce() {
        return randomToken(32);
    }

    // --- Pre-authorized code ---

    public String createPreAuthCode(SessionData session) {
        String code = randomToken(32);
        preAuthCodes.put(code, session);
        return code;
    }

    public SessionData consumePreAuthCode(String code) {
        return preAuthCodes.remove(code);
    }

    // --- Access tokens ---

    public String createAccessToken(SessionData session) {
        String token = randomToken(32);
        accessTokens.put(token, session);
        return token;
    }

    public SessionData getAccessTokenSession(String token) {
        return accessTokens.get(token);
    }

    // --- Nonces ---

    public String createNonce(String sessionId) {
        String nonce = generateNonce();
        nonces.put(nonce, sessionId);
        return nonce;
    }

    public boolean validateNonce(String nonce) {
        return nonces.containsKey(nonce);
    }

    public String consumeNonce(String nonce) {
        return nonces.remove(nonce);
    }

    // --- Credential offers ---

    public String storeCredentialOffer(String offerJson) {
        String offerId = randomToken(16);
        credentialOffers.put(offerId, offerJson);
        return offerId;
    }

    public String getCredentialOffer(String offerId) {
        return credentialOffers.get(offerId);
    }

    // --- Authorization codes ---

    public String createAuthCode(SessionData session) {
        String code = randomToken(32);
        authCodes.put(code, session);
        return code;
    }

    public SessionData consumeAuthCode(String code) {
        return authCodes.remove(code);
    }

    /** Clear all state (useful between test runs). */
    public void clear() {
        preAuthCodes.clear();
        accessTokens.clear();
        nonces.clear();
        credentialOffers.clear();
        authCodes.clear();
    }
}
