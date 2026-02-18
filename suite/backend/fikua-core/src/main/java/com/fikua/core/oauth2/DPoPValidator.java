package com.fikua.core.oauth2;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * DPoP proof validation per RFC 9449.
 * Validates proof structure, signature, claims, and prevents replay.
 */
public class DPoPValidator {

    private static final long MAX_AGE_SECONDS = 300; // 5 minutes
    private final Set<String> usedJtis = ConcurrentHashMap.newKeySet();

    /**
     * Validate a DPoP proof JWT.
     *
     * @param dpopHeader the DPoP header value from the request
     * @param httpMethod expected HTTP method (e.g., "POST")
     * @param httpUri expected HTTP URI (e.g., "https://issuer.example.com/token")
     * @param accessTokenHash optional access token hash (ath claim) for resource requests
     * @return the validated ECKey (public key) from the DPoP proof
     */
    public ECKey validate(String dpopHeader, String httpMethod, String httpUri, String accessTokenHash) {
        if (dpopHeader == null || dpopHeader.isBlank()) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "Missing DPoP proof");
        }

        try {
            SignedJWT dpop = SignedJWT.parse(dpopHeader);
            JWSHeader header = dpop.getHeader();

            // Must be typ: dpop+jwt
            if (!"dpop+jwt".equals(header.getType().getType())) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP typ must be dpop+jwt");
            }

            // Must have jwk in header
            if (header.getJWK() == null) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP must contain jwk header");
            }

            // Must be ES256
            if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP must use ES256");
            }

            ECKey publicKey = ECKey.parse(header.getJWK().toJSONObject());
            if (publicKey.isPrivate()) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP jwk must be public key only");
            }

            // Verify signature
            if (!dpop.verify(new ECDSAVerifier(publicKey))) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP signature invalid");
            }

            JWTClaimsSet claims = dpop.getJWTClaimsSet();

            // Validate htm (HTTP method)
            if (!httpMethod.equalsIgnoreCase(claims.getStringClaim("htm"))) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP htm mismatch");
            }

            // Validate htu (HTTP URI)
            if (!httpUri.equals(claims.getStringClaim("htu"))) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP htu mismatch");
            }

            // Validate iat (not too old)
            long iat = claims.getIssueTime().getTime() / 1000;
            long now = Instant.now().getEpochSecond();
            if (Math.abs(now - iat) > MAX_AGE_SECONDS) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP proof expired");
            }

            // Validate jti uniqueness (replay protection)
            String jti = claims.getJWTID();
            if (jti == null || !usedJtis.add(jti)) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP jti replay detected");
            }

            // Validate ath if provided (for resource requests)
            if (accessTokenHash != null) {
                String ath = claims.getStringClaim("ath");
                if (!accessTokenHash.equals(ath)) {
                    throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP ath mismatch");
                }
            }

            return publicKey;

        } catch (OAuthErrorException e) {
            throw e;
        } catch (Exception e) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "Invalid DPoP proof: " + e.getMessage());
        }
    }
}
