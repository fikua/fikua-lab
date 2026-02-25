package com.fikua.verifier.app.port;

/**
 * Port for ephemeral verification session state.
 * Stores authorization request sessions and their lifecycle.
 */
public interface SessionStore {

    record VerificationSession(
            String sessionId,
            String state,
            String nonce,
            String dcqlQueryJson,
            String responseMode,
            String clientId,
            String responseUri,
            String requestJwt,
            String status,
            String vpToken,
            String verifiedClaimsJson,
            String error
    ) {}

    VerificationSession store(VerificationSession session);

    VerificationSession findByState(String state);

    VerificationSession findById(String sessionId);

    void updateStatus(String sessionId, String status);

    void updateResult(String sessionId, String status, String vpToken,
                      String verifiedClaimsJson, String error);

    void clear();
}
