package com.fikua.issuer.app.port;

import com.nimbusds.jose.jwk.ECKey;

import java.time.Instant;
import java.util.Map;

/**
 * Port for ephemeral OID4VCI session state.
 * Stores pre-authorized codes, access tokens, nonces, credential offers, etc.
 */
public interface SessionStore {

    /** Session data associated with a token or code. */
    record SessionData(
            String sessionId,
            String cNonce,
            ECKey dpopKey,
            Instant createdAt,
            Map<String, Object> metadata
    ) {}

    /** Generate a random base64url string. */
    String randomToken(int bytes);

    /** Generate a random c_nonce. */
    String generateNonce();

    // --- Pre-authorized code ---
    String createPreAuthCode(SessionData session);
    SessionData consumePreAuthCode(String code);

    // --- Access tokens ---
    String createAccessToken(SessionData session);
    SessionData getAccessTokenSession(String token);
    void updateAccessTokenSession(String token, SessionData session);

    // --- Nonces ---
    String createNonce(String sessionId);
    /** Register a nonce in the global store (not linked to a session). */
    void registerNonce(String nonce);
    boolean validateNonce(String nonce);
    void invalidateNonce(String nonce);

    // --- Credential offers ---
    String storeCredentialOffer(String offerJson);
    String getCredentialOffer(String offerId);

    // --- PAR requests ---
    void storeParRequest(String requestUri, Map<String, String> params);
    Map<String, String> consumeParRequest(String requestUri);

    // --- Issuer state (links credential offer to issuance record) ---
    void storeIssuerState(String issuerState, Map<String, Object> metadata);
    Map<String, Object> consumeIssuerState(String issuerState);

    // --- Authorization codes ---
    String createAuthCode(SessionData session);
    SessionData consumeAuthCode(String code);

    /** Clear all state (useful between test runs). */
    void clear();
}
