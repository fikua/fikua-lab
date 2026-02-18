package com.fikua.core.oauth2;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * PKCE (RFC 7636) utilities for S256 challenge generation and verification.
 */
public final class PkceUtil {

    private PkceUtil() {}

    private static final SecureRandom RANDOM = new SecureRandom();

    /** Generate a random code verifier (43-128 chars, base64url). */
    public static String generateCodeVerifier() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Compute S256 challenge from verifier: BASE64URL(SHA256(verifier)). */
    public static String computeS256Challenge(String codeVerifier) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute S256 challenge", e);
        }
    }

    /** Verify that a code verifier matches a previously stored S256 challenge. */
    public static boolean verifyS256(String codeVerifier, String storedChallenge) {
        String computed = computeS256Challenge(codeVerifier);
        return computed.equals(storedChallenge);
    }
}
