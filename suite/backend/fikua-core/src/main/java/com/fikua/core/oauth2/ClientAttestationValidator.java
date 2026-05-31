package com.fikua.core.oauth2;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Validates client attestation JWTs per OAuth Attestation-Based Client Authentication
 * (draft-ietf-oauth-attestation-based-client-auth-07).
 *
 * Supports two transport mechanisms:
 * 1. HTTP headers: OAuth-Client-Attestation (WIA) + OAuth-Client-Attestation-PoP (PoP)
 * 2. Form params: client_assertion_type + client_assertion (WIA~PoP concatenated with ~)
 *
 * WIA signature is NOT verified (we don't have the Attestation Service's public key).
 * PoP signature IS verified using the cnf key from the WIA.
 */
public class ClientAttestationValidator {

    private static final Logger log = LoggerFactory.getLogger(ClientAttestationValidator.class);
    public static final String HEADER_CLIENT_ATTESTATION = "OAuth-Client-Attestation";
    public static final String HEADER_CLIENT_ATTESTATION_POP = "OAuth-Client-Attestation-PoP";
    private static final String EXPECTED_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation";
    private static final long MAX_AGE_SECONDS = 300; // 5 minutes
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Trusted Wallet Provider anchors. When non-empty, a WIA presented with an
     * x5c chain MUST chain to one of these (the WIA was issued by a trusted
     * Wallet Provider). When empty, x5c pinning is skipped (back-compat: a
     * self-signed WIA is still accepted on its own key).
     */
    private final List<X509Certificate> walletProviderAnchors;

    /** No anchors: accept any self-consistent WIA (legacy behaviour). */
    public ClientAttestationValidator() {
        this.walletProviderAnchors = List.of();
    }

    /** Pin x5c-bearing WIAs to the given Wallet Provider trust anchors. */
    public ClientAttestationValidator(List<X509Certificate> walletProviderAnchors) {
        this.walletProviderAnchors = walletProviderAnchors != null
                ? List.copyOf(walletProviderAnchors) : List.of();
    }

    /**
     * Validate client attestation from HTTP headers (ATCA draft-07 §4).
     *
     * @param wiaJwt the OAuth-Client-Attestation header value (WIA JWT)
     * @param popJwt the OAuth-Client-Attestation-PoP header value (PoP JWT)
     * @return the client_id extracted from the WIA, or null if no headers present
     */
    public String validateHeaders(String wiaJwt, String popJwt) {
        if (wiaJwt == null && popJwt == null) {
            return null; // No attestation provided via headers
        }

        if (wiaJwt == null || wiaJwt.isBlank()) {
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                    "Missing OAuth-Client-Attestation header");
        }
        if (popJwt == null || popJwt.isBlank()) {
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                    "Missing OAuth-Client-Attestation-PoP header");
        }

        return validateWiaAndPop(wiaJwt, popJwt);
    }

    /**
     * Validate client attestation from form parameters (client_assertion_type + client_assertion).
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
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                    "Unsupported client_assertion_type: " + clientAssertionType);
        }

        if (clientAssertion == null || clientAssertion.isBlank()) {
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                    "Missing client_assertion");
        }

        // Split WIA~PoP
        String[] parts = clientAssertion.split("~");
        if (parts.length != 2) {
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                    "client_assertion must contain WIA~PoP (two JWTs separated by ~)");
        }

        return validateWiaAndPop(parts[0], parts[1]);
    }

    /** Common WIA + PoP validation logic. */
    private String validateWiaAndPop(String wiaJwtString, String popJwtString) {
        try {
            // Parse the Wallet Instance Attestation (WIA)
            SignedJWT wia = SignedJWT.parse(wiaJwtString);
            JWTClaimsSet wiaClaims = wia.getJWTClaimsSet();
            log.info("WIA parsed: alg={}, typ={}, sub={}, iss={}, claims={}, x5c={}",
                    wia.getHeader().getAlgorithm(), wia.getHeader().getType(),
                    wiaClaims.getSubject(), wiaClaims.getIssuer(), wiaClaims.getClaims().keySet(),
                    wia.getHeader().getX509CertChain() != null ? wia.getHeader().getX509CertChain().size() : "none");

            // Verify WIA signature (ATCA §9: "verifies with the public key of a known and trusted Attester")
            verifyWiaSignature(wia);

            // Validate WIA freshness
            if (wiaClaims.getExpirationTime() != null) {
                if (Instant.now().isAfter(wiaClaims.getExpirationTime().toInstant())) {
                    throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                            "Client Attestation JWT has expired");
                }
            }

            // Extract client_id from sub claim of WIA
            String clientId = wiaClaims.getSubject();
            if (clientId == null) {
                clientId = wiaClaims.getStringClaim("client_id");
            }

            // Parse the PoP JWT
            SignedJWT pop = SignedJWT.parse(popJwtString);
            JWTClaimsSet popClaims = pop.getJWTClaimsSet();
            log.info("PoP parsed: alg={}, typ={}, iss={}, aud={}, jwk_in_header={}",
                    pop.getHeader().getAlgorithm(), pop.getHeader().getType(),
                    popClaims.getIssuer(), popClaims.getAudience(),
                    pop.getHeader().getJWK() != null);

            // Extract cnf key from WIA (cnf.jwk) for PoP verification
            JWK cnfKey = extractCnfKey(wiaClaims);

            // Fallback: if cnf.jwk not present, try cnf.jkt + PoP header key
            if (cnfKey == null) {
                cnfKey = extractKeyViaJkt(wiaClaims, pop);
            }

            if (cnfKey == null) {
                log.warn("WIA cnf claim: {}", wiaClaims.getJSONObjectClaim("cnf"));
                throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                        "WIA missing cnf key for PoP verification");
            }

            // Verify PoP signature using the cnf key (supports any asymmetric alg)
            if (!(cnfKey instanceof AsymmetricJWK asymmetricKey)) {
                throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                        "cnf key must be an asymmetric key (EC, RSA, or OKP)");
            }
            PublicKey publicKey = asymmetricKey.toPublicKey();
            JWSVerifier verifier = new DefaultJWSVerifierFactory()
                    .createJWSVerifier(pop.getHeader(), publicKey);
            if (!pop.verify(verifier)) {
                throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                        "PoP signature verification failed");
            }

            // Validate PoP iat (freshness)
            if (popClaims.getIssueTime() != null) {
                long iat = popClaims.getIssueTime().getTime() / 1000;
                long now = Instant.now().getEpochSecond();
                if (Math.abs(now - iat) > MAX_AGE_SECONDS) {
                    throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                            "PoP JWT expired (iat too old)");
                }
            }

            // Validate PoP exp if present
            if (popClaims.getExpirationTime() != null) {
                if (Instant.now().isAfter(popClaims.getExpirationTime().toInstant())) {
                    throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                            "PoP JWT has expired");
                }
            }

            log.info("Client attestation validated: client_id={}, wia_iss={}, pop_aud={}",
                    clientId, wiaClaims.getIssuer(), popClaims.getAudience());

            return clientId;

        } catch (OAuthErrorException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Client attestation validation failed: {}", e.getMessage(), e);
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                    "Invalid client attestation: " + e.getMessage());
        }
    }

    /**
     * Verify the WIA signature using the key from x5c header or JWK header.
     * Per ATCA §9: "The signature of the Client Attestation JWT verifies with
     * the public key of a known and trusted Attester."
     */
    private void verifyWiaSignature(SignedJWT wia) throws Exception {
        PublicKey wiaKey = null;

        // Try x5c certificate chain first
        List<Base64> x5c = wia.getHeader().getX509CertChain();
        if (x5c != null && !x5c.isEmpty()) {
            byte[] certBytes = x5c.getFirst().decode();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            wiaKey = cert.getPublicKey();
            log.info("WIA x5c cert: subject={}, issuer={}", cert.getSubjectX500Principal(), cert.getIssuerX500Principal());

            // Pin the leaf to a trusted Wallet Provider anchor (if configured).
            if (!walletProviderAnchors.isEmpty() && !chainsToTrustedWalletProvider(cert)) {
                throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                        "WIA is not issued by a trusted Wallet Provider");
            }
        }

        // Fallback to JWK in header
        if (wiaKey == null && wia.getHeader().getJWK() != null) {
            JWK headerJwk = wia.getHeader().getJWK();
            if (headerJwk instanceof AsymmetricJWK asymmetric) {
                wiaKey = asymmetric.toPublicKey();
            }
        }

        if (wiaKey == null) {
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                    "Cannot verify WIA signature: no x5c or jwk in header");
        }

        JWSVerifier wiaVerifier = new DefaultJWSVerifierFactory()
                .createJWSVerifier(wia.getHeader(), wiaKey);
        if (!wia.verify(wiaVerifier)) {
            throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                    "Client Attestation JWT signature verification failed");
        }
        log.info("WIA signature verified");
    }

    /** True if the WIA leaf cert was signed by one of the trusted WP anchors. */
    private boolean chainsToTrustedWalletProvider(X509Certificate leaf) {
        List<X509Certificate> tried = new ArrayList<>();
        for (X509Certificate anchor : walletProviderAnchors) {
            tried.add(anchor);
            try {
                leaf.verify(anchor.getPublicKey());
                return true;
            } catch (Exception ignored) {
                // not signed by this anchor; try the next
            }
        }
        log.warn("WIA leaf {} did not chain to any of {} trusted WP anchors",
                leaf.getSubjectX500Principal(), tried.size());
        return false;
    }

    /** Extract the public key from the cnf.jwk claim of the WIA. Supports any JWK key type. */
    @SuppressWarnings("unchecked")
    private JWK extractCnfKey(JWTClaimsSet wiaClaims) {
        try {
            var cnf = wiaClaims.getJSONObjectClaim("cnf");
            if (cnf == null) return null;
            var jwkMap = (java.util.Map<String, Object>) cnf.get("jwk");
            if (jwkMap == null) return null;
            String jwkJson = MAPPER.writeValueAsString(jwkMap);
            return JWK.parse(jwkJson);
        } catch (Exception e) {
            log.warn("Could not extract cnf key from WIA: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Fallback: if WIA cnf contains jkt (JWK Thumbprint) instead of jwk,
     * extract the key from the PoP JWT header and verify the thumbprint matches.
     * Requires cnf.jkt — without it, the PoP key has no binding to the WIA.
     */
    private JWK extractKeyViaJkt(JWTClaimsSet wiaClaims, SignedJWT pop) {
        try {
            var cnf = wiaClaims.getJSONObjectClaim("cnf");
            if (cnf == null) return null;
            String jkt = (String) cnf.get("jkt");
            if (jkt == null) return null;

            JWK popHeaderKey = pop.getHeader().getJWK();
            if (popHeaderKey == null) {
                log.warn("WIA cnf.jkt present but PoP header has no jwk");
                return null;
            }

            // Verify PoP header key thumbprint matches cnf.jkt
            String thumbprint = popHeaderKey.computeThumbprint().toString();
            if (!jkt.equals(thumbprint)) {
                log.warn("cnf.jkt mismatch: expected={}, actual={}", jkt, thumbprint);
                throw OAuthErrorException.unauthorized(OAuthError.INVALID_CLIENT,
                        "PoP key thumbprint does not match WIA cnf.jkt");
            }
            log.info("PoP key matched via cnf.jkt thumbprint");

            return popHeaderKey.toPublicJWK();
        } catch (OAuthErrorException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Could not extract key via jkt: {}", e.getMessage());
            return null;
        }
    }
}
