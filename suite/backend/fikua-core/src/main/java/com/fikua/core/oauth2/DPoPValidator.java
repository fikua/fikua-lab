package com.fikua.core.oauth2;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.function.Predicate;

/**
 * DPoP proof validation per RFC 9449.
 * Validates proof structure, signature, claims, and prevents replay.
 * JTI replay protection is delegated to the caller via a Predicate.
 */
public class DPoPValidator {

    /** RFC 9449 §8: use_dpop_nonce error for DPoP-Nonce enforcement. */
    public static final String USE_DPOP_NONCE = "use_dpop_nonce";

    private static final long MAX_AGE_SECONDS = 300; // 5 minutes
    private final Predicate<String> jtiChecker;
    private final Predicate<String> nonceChecker;

    /**
     * @param jtiChecker returns true if the JTI is new (accepted), false if replayed.
     *                   Typical usage: {@code ConcurrentHashMap.newKeySet()::add}
     */
    public DPoPValidator(Predicate<String> jtiChecker) {
        this.jtiChecker = jtiChecker;
        this.nonceChecker = null; // DPoP-Nonce not enforced
    }

    /**
     * @param jtiChecker returns true if the JTI is new (accepted), false if replayed.
     * @param nonceChecker returns true if the nonce is valid (accepted). Null to disable.
     */
    public DPoPValidator(Predicate<String> jtiChecker, Predicate<String> nonceChecker) {
        this.jtiChecker = jtiChecker;
        this.nonceChecker = nonceChecker;
    }

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
            if (jti == null || !jtiChecker.test(jti)) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP jti replay detected");
            }

            // Validate ath if provided (for resource requests)
            if (accessTokenHash != null) {
                String ath = claims.getStringClaim("ath");
                if (!accessTokenHash.equals(ath)) {
                    throw OAuthErrorException.badRequest(OAuthError.INVALID_REQUEST, "DPoP ath mismatch");
                }
            }

            // H6: Validate DPoP-Nonce if server enforces it (RFC 9449 §8)
            if (nonceChecker != null) {
                String nonce = claims.getStringClaim("nonce");
                if (nonce == null || !nonceChecker.test(nonce)) {
                    throw new DPoPNonceRequiredException();
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
