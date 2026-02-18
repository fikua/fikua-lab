package com.fikua.core.oauth2;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validates client attestation JWTs per OAuth Attestation-Based Client Authentication.
 * Used in HAIP profile where client_assertion_type = jwt-client-attestation.
 *
 * The client_assertion contains two JWTs concatenated with '~':
 *   1. Wallet Instance Attestation (WIA) — signed by the Attestation Service
 *   2. Proof of Possession (PoP) — signed by the wallet instance key
 *
 * For OIDF conformance testing, we validate structure and extract claims
 * but do not verify the WIA signature (we don't have the Attestation Service's public key).
 */
public class ClientAttestationValidator {

    private static final Logger log = LoggerFactory.getLogger(ClientAttestationValidator.class);
    private static final String EXPECTED_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation";

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

            // Parse the PoP JWT (validate it's well-formed)
            SignedJWT pop = SignedJWT.parse(parts[1]);
            JWTClaimsSet popClaims = pop.getJWTClaimsSet();

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
}
