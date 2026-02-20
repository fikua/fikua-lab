package com.fikua.issuer.infra;

import com.fikua.issuer.app.port.SessionStore;

import java.security.SecureRandom;
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
    public String createNonce(String sessionId) {
        String nonce = generateNonce();
        nonces.put(nonce, sessionId);
        return nonce;
    }

    @Override
    public boolean validateNonce(String nonce) {
        return nonces.containsKey(nonce);
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
    public void clear() {
        preAuthCodes.clear();
        accessTokens.clear();
        nonces.clear();
        credentialOffers.clear();
        authCodes.clear();
        parRequests.clear();
    }
}
