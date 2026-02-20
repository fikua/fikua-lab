package com.fikua.core.oauth2;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

/**
 * Validates client attestation JWTs per OAuth Attestation-Based Client Authentication.
 * Used in HAIP profile where client_assertion_type = jwt-client-attestation.
 *
 * The client_assertion contains two JWTs concatenated with '~':
 *   1. Wallet Instance Attestation (WIA) — signed by the Attestation Service
 *   2. Proof of Possession (PoP) — signed by the wallet instance key
 *
 * WIA signature is NOT verified (we don't have the Attestation Service's public key).
 * PoP signature IS verified using the cnf key from the WIA.
 */
public class ClientAttestationValidator {

    private static final Logger log = LoggerFactory.getLogger(ClientAttestationValidator.class);
    private static final String EXPECTED_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation";
    private static final long MAX_AGE_SECONDS = 300; // 5 minutes

    /**
     * Validate the client attestation from token request parameters.
     *
     * @param clientAssertionType the client_assertion_type parameter
     * @param clientAssertion the client_assertion parameter (WIA~PoP)
     * @return the client_id extracted from the WIA, or null if attestation is not present
     */
    public String validate(String clientAssertionType, String clientAssertion) {
        if (clientAssertionType == null && clientAssertion == null) {
            return null; // No attestation provided
        }

        if (!EXPECTED_ASSERTION_TYPE.equals(clientAssertionType)) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_CLIENT,
                    "Unsupported client_assertion_type: " + clientAssertionType);
        }

        if (clientAssertion == null || clientAssertion.isBlank()) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_CLIENT,
                    "Missing client_assertion");
        }

        // Split WIA~PoP
        String[] parts = clientAssertion.split("~");
        if (parts.length != 2) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_CLIENT,
                    "client_assertion must contain WIA~PoP (two JWTs separated by ~)");
        }

        try {
            // Parse the Wallet Instance Attestation (WIA)
            SignedJWT wia = SignedJWT.parse(parts[0]);
            JWTClaimsSet wiaClaims = wia.getJWTClaimsSet();

            // Extract client_id from sub claim of WIA
            String clientId = wiaClaims.getSubject();
            if (clientId == null) {
                clientId = wiaClaims.getStringClaim("client_id");
            }

            // Extract cnf key from WIA for PoP verification — REQUIRED
            ECKey wiaKey = extractCnfKey(wiaClaims);
            if (wiaKey == null) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_CLIENT,
                        "WIA missing cnf key for PoP verification");
            }

            // Parse and validate the PoP JWT
            SignedJWT pop = SignedJWT.parse(parts[1]);
            JWTClaimsSet popClaims = pop.getJWTClaimsSet();

            // Verify PoP signature using the cnf key from WIA
            if (!pop.verify(new ECDSAVerifier(wiaKey))) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_CLIENT,
                        "PoP signature verification failed");
            }

            // Validate PoP iat (freshness)
            if (popClaims.getIssueTime() != null) {
                long iat = popClaims.getIssueTime().getTime() / 1000;
                long now = Instant.now().getEpochSecond();
                if (Math.abs(now - iat) > MAX_AGE_SECONDS) {
                    throw OAuthErrorException.badRequest(OAuthError.INVALID_CLIENT,
                            "PoP JWT expired (iat too old)");
                }
            }

            // Validate PoP exp if present
            if (popClaims.getExpirationTime() != null) {
                if (Instant.now().isAfter(popClaims.getExpirationTime().toInstant())) {
                    throw OAuthErrorException.badRequest(OAuthError.INVALID_CLIENT,
                            "PoP JWT has expired");
                }
            }

            log.info("Client attestation validated: client_id={}, wia_iss={}, pop_aud={}",
                    clientId, wiaClaims.getIssuer(), popClaims.getAudience());

            return clientId;

        } catch (OAuthErrorException e) {
            throw e;
        } catch (Exception e) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_CLIENT,
                    "Invalid client_assertion: " + e.getMessage());
        }
    }

    /** Extract the EC public key from the cnf claim of the WIA. */
    @SuppressWarnings("unchecked")
    private ECKey extractCnfKey(JWTClaimsSet wiaClaims) {
        try {
            var cnf = wiaClaims.getJSONObjectClaim("cnf");
            if (cnf == null) return null;
            var jwkMap = (java.util.Map<String, Object>) cnf.get("jwk");
            if (jwkMap == null) return null;
            // Serialize to JSON string then parse — avoids direct json-smart dependency
            String jwkJson = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(jwkMap);
            return ECKey.parse(jwkJson);
        } catch (Exception e) {
            log.warn("Could not extract cnf key from WIA: {}", e.getMessage());
            return null;
        }
    }
}
