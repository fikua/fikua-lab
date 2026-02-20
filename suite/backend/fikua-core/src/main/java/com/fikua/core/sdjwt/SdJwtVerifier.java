package com.fikua.core.sdjwt;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.*;

/**
 * Verifies SD-JWT VCs: signature check, expiry validation, disclosure resolution.
 */
public final class SdJwtVerifier {

    private SdJwtVerifier() {}

    /**
     * Verify an SD-JWT and return resolved claims (disclosures merged with JWT claims).
     *
     * @param sdJwt the parsed SD-JWT
     * @param issuerKey the issuer's public key for signature verification
     * @return map of all resolved claims (plain + disclosed)
     */
    public static Map<String, Object> verify(SdJwt sdJwt, ECKey issuerKey) {
        try {
            SignedJWT jwt = SignedJWT.parse(sdJwt.issuerJwt());

            // Verify signature
            if (!jwt.verify(new ECDSAVerifier(issuerKey.toPublicJWK()))) {
                throw new RuntimeException("SD-JWT signature verification failed");
            }

            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // Check expiry
            if (claims.getExpirationTime() != null) {
                if (Instant.now().isAfter(claims.getExpirationTime().toInstant())) {
                    throw new RuntimeException("SD-JWT has expired");
                }
            }

            // H8: Validate that each disclosure's digest is present in the _sd array
            @SuppressWarnings("unchecked")
            List<String> sdDigests = (List<String>) claims.getClaim("_sd");
            if (sdDigests == null) {
                sdDigests = List.of();
            }
            for (Disclosure disclosure : sdJwt.disclosures()) {
                if (!sdDigests.contains(disclosure.digest())) {
                    throw new RuntimeException(
                            "Disclosure digest not found in _sd array: " + disclosure.claimName());
                }
            }

            // Resolve claims
            Map<String, Object> resolved = new LinkedHashMap<>(claims.getClaims());

            // Remove SD-JWT internal claims
            resolved.remove("_sd");
            resolved.remove("_sd_alg");

            // Add disclosed claims
            for (Disclosure disclosure : sdJwt.disclosures()) {
                resolved.put(disclosure.claimName(), disclosure.claimValue());
            }

            return resolved;

        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to verify SD-JWT: " + e.getMessage(), e);
        }
    }
}
