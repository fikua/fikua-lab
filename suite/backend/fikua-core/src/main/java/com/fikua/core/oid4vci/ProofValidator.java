package com.fikua.core.oid4vci;

import com.fikua.core.oauth2.OAuthError;
import com.fikua.core.oauth2.OAuthErrorException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;

/**
 * Validates JWT proof of possession in credential requests per OID4VCI Section 7.2.1.
 * The wallet proves control of the key that should be bound to the credential.
 */
public final class ProofValidator {

    private ProofValidator() {}

    /**
     * Validate a JWT proof and return the wallet's public key.
     *
     * @param proof the proof object from the credential request
     * @param expectedIssuer expected credential issuer URL (aud claim)
     * @param expectedNonce expected c_nonce (nonce claim)
     * @return the wallet's ECKey (public key) extracted from the proof
     */
    public static ECKey validate(CredentialRequest.Proof proof, String expectedIssuer, String expectedNonce) {
        if (proof == null || !"jwt".equals(proof.proofType())) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_PROOF, "proof_type must be jwt");
        }

        if (proof.jwt() == null) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_PROOF, "Missing jwt in proof");
        }

        try {
            SignedJWT jwt = SignedJWT.parse(proof.jwt());
            JWSHeader header = jwt.getHeader();

            // Must be typ: openid4vci-proof+jwt
            JOSEObjectType expectedType = new JOSEObjectType("openid4vci-proof+jwt");
            if (!expectedType.equals(header.getType())) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_PROOF,
                        "Proof typ must be openid4vci-proof+jwt");
            }

            // Must use ES256
            if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_PROOF, "Proof must use ES256");
            }

            // Must have jwk in header (for jwk binding method)
            if (header.getJWK() == null) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_PROOF,
                        "Proof must contain jwk header parameter");
            }

            ECKey walletKey = ECKey.parse(header.getJWK().toJSONObject());

            // Verify signature
            if (!jwt.verify(new ECDSAVerifier(walletKey))) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_PROOF, "Proof signature invalid");
            }

            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // Validate aud = credential issuer
            if (claims.getAudience() == null || !claims.getAudience().contains(expectedIssuer)) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_PROOF,
                        "Proof aud must be the credential issuer");
            }

            // Validate nonce = c_nonce
            String nonce = claims.getStringClaim("nonce");
            if (expectedNonce != null && !expectedNonce.equals(nonce)) {
                throw OAuthErrorException.badRequest(OAuthError.INVALID_PROOF,
                        "Proof nonce does not match c_nonce");
            }

            // Validate iat (not too old: 5 minutes)
            if (claims.getIssueTime() != null) {
                long iat = claims.getIssueTime().getTime() / 1000;
                long now = Instant.now().getEpochSecond();
                if (Math.abs(now - iat) > 300) {
                    throw OAuthErrorException.badRequest(OAuthError.INVALID_PROOF, "Proof expired");
                }
            }

            return walletKey;

        } catch (OAuthErrorException e) {
            throw e;
        } catch (Exception e) {
            throw OAuthErrorException.badRequest(OAuthError.INVALID_PROOF,
                    "Invalid proof: " + e.getMessage());
        }
    }
}
