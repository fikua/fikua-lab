package com.fikua.core.crypto;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;

import java.util.Map;

/**
 * JWK utility methods for serialization and thumbprint computation.
 */
public final class JwkUtils {

    private JwkUtils() {}

    /** Compute JWK thumbprint (SHA-256, base64url) per RFC 7638. */
    public static String thumbprint(ECKey key) {
        try {
            return key.computeThumbprint("SHA-256").toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute JWK thumbprint", e);
        }
    }

    /** Serialize a JWK Set to JSON string (for /jwks endpoint). */
    public static String jwkSetToJson(JWKSet jwkSet) {
        return jwkSet.toJSONObject(true).toString();
    }

    /** Serialize a single public ECKey to JSON map. */
    public static Map<String, Object> publicKeyToMap(ECKey key) {
        return key.toPublicJWK().toJSONObject();
    }
}
