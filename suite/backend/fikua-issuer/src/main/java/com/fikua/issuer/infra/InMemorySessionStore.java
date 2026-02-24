package com.fikua.issuer.infra;

import com.fikua.issuer.app.port.SessionStore;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of SessionStore.
 * Not persisted — designed for single test runs.
 */
public class InMemorySessionStore implements SessionStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, SessionData> preAuthCodes = new ConcurrentHashMap<>();
    private final Map<String, SessionData> accessTokens = new ConcurrentHashMap<>();
    private final Map<String, String> nonces = new ConcurrentHashMap<>();
    private final Map<String, String> credentialOffers = new ConcurrentHashMap<>();
    private final Map<String, SessionData> authCodes = new ConcurrentHashMap<>();
    private final Map<String, Map<String, String>> parRequests = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Object>> issuerStates = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Object>> pendingAuthorizations = new ConcurrentHashMap<>();

    private record OtpEntry(String otp, String sessionToken, Instant createdAt) {}
    private final Map<String, OtpEntry> otpStore = new ConcurrentHashMap<>();
    private static final long OTP_TTL_SECONDS = 300; // 5 minutes

    @Override
    public String randomToken(int bytes) {
        byte[] buf = new byte[bytes];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    @Override
    public String generateNonce() {
        return randomToken(32);
    }

    @Override
    public String createPreAuthCode(SessionData session) {
        String code = randomToken(32);
        preAuthCodes.put(code, session);
        return code;
    }

    @Override
    public SessionData consumePreAuthCode(String code) {
        return preAuthCodes.remove(code);
    }

    @Override
    public String createAccessToken(SessionData session) {
        String token = randomToken(32);
        accessTokens.put(token, session);
        return token;
    }

    @Override
    public SessionData getAccessTokenSession(String token) {
        return accessTokens.get(token);
    }

    @Override
    public void updateAccessTokenSession(String token, SessionData session) {
        accessTokens.put(token, session);
    }

    @Override
    public String createNonce(String sessionId) {
        String nonce = generateNonce();
        nonces.put(nonce, sessionId);
        return nonce;
    }

    @Override
    public void registerNonce(String nonce) {
        nonces.put(nonce, "global");
    }

    @Override
    public boolean validateNonce(String nonce) {
        // M10: Nonce is single-use — consume on validation (OID4VCI 1.0 Final §7)
        return nonces.remove(nonce) != null;
    }

    @Override
    public void invalidateNonce(String nonce) {
        nonces.remove(nonce);
    }

    @Override
    public String storeCredentialOffer(String offerJson) {
        String offerId = randomToken(16);
        credentialOffers.put(offerId, offerJson);
        return offerId;
    }

    @Override
    public String getCredentialOffer(String offerId) {
        return credentialOffers.get(offerId);
    }

    @Override
    public void storeParRequest(String requestUri, Map<String, String> params) {
        parRequests.put(requestUri, params);
    }

    @Override
    public Map<String, String> consumeParRequest(String requestUri) {
        return parRequests.remove(requestUri);
    }

    @Override
    public void storeIssuerState(String issuerState, Map<String, Object> metadata) {
        issuerStates.put(issuerState, metadata);
    }

    @Override
    public Map<String, Object> consumeIssuerState(String issuerState) {
        return issuerStates.remove(issuerState);
    }

    @Override
    public void storePendingAuthorization(String sessionToken, Map<String, Object> authData) {
        pendingAuthorizations.put(sessionToken, authData);
    }

    @Override
    public Map<String, Object> getPendingAuthorization(String sessionToken) {
        return pendingAuthorizations.get(sessionToken);
    }

    @Override
    public Map<String, Object> consumePendingAuthorization(String sessionToken) {
        return pendingAuthorizations.remove(sessionToken);
    }

    @Override
    public String createAuthCode(SessionData session) {
        String code = randomToken(32);
        authCodes.put(code, session);
        return code;
    }

    @Override
    public SessionData consumeAuthCode(String code) {
        return authCodes.remove(code);
    }

    @Override
    public void storeOtp(String email, String otp, String sessionToken) {
        otpStore.put(email.toLowerCase().trim(), new OtpEntry(otp, sessionToken, Instant.now()));
    }

    @Override
    public String consumeOtp(String email, String otp) {
        String key = email.toLowerCase().trim();
        OtpEntry entry = otpStore.remove(key);
        if (entry == null) return null;
        if (Instant.now().isAfter(entry.createdAt().plusSeconds(OTP_TTL_SECONDS))) return null;
        if (!entry.otp().equals(otp)) {
            // Wrong code — put it back so the user can retry (but TTL still counts)
            otpStore.put(key, entry);
            return null;
        }
        return entry.sessionToken();
    }

    @Override
    public void clear() {
        preAuthCodes.clear();
        accessTokens.clear();
        nonces.clear();
        credentialOffers.clear();
        authCodes.clear();
        parRequests.clear();
        issuerStates.clear();
        pendingAuthorizations.clear();
        otpStore.clear();
    }
}
