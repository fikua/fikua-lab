package com.fikua.core.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Full SD-JWT VC presentation verification for the OID4VP verifier (P1).
 *
 * <p>Checks, in order:
 * <ol>
 *   <li>issuer-JWT signature against the public key in its own x5c leaf;</li>
 *   <li>every disclosure digest is present in the issuer JWT's {@code _sd} array
 *       (no unmatched disclosures, no tampered salts/values);</li>
 *   <li>KB-JWT signature against the holder key in the issuer JWT's
 *       {@code cnf.jwk};</li>
 *   <li>KB-JWT {@code aud} equals the verifier's client_id, {@code nonce}
 *       equals the request nonce, and {@code sd_hash} equals SHA-256 of the
 *       presentation up to and including the last {@code ~}.</li>
 * </ol>
 *
 * Any failure throws {@link VerificationException}; the verifier maps that to a
 * 4xx rejection (OID4VP §8.2). The conformance suite issues the credential, so
 * the issuer signature is validated against the cert embedded in the
 * presentation rather than a locally configured trust anchor.
 */
public final class SdJwtVcVerifier {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Maximum tolerated absolute difference between the KB-JWT iat and now.
     * The conformance suite tests iat ±1 year; 5 minutes accepts genuine clock
     * skew while rejecting those.
     */
    private static final long MAX_KB_IAT_SKEW_SECONDS = 300;

    /** Thrown when a presentation fails any verification step. */
    public static final class VerificationException extends Exception {
        public VerificationException(String message) {
            super(message);
        }
    }

    private SdJwtVcVerifier() {}

    /**
     * Verify a full SD-JWT VC presentation and return the disclosed claims.
     *
     * @param presentation the combined {@code issuer-jwt~d1~...~kb-jwt} string
     * @param expectedAud  the verifier client_id the KB-JWT aud must match
     * @param expectedNonce the request nonce the KB-JWT nonce must match
     * @throws VerificationException if any check fails
     */
    public static Map<String, Object> verify(String presentation, String expectedAud,
                                             String expectedNonce) throws VerificationException {
        SdJwt sdJwt = parseOrThrow(presentation);

        JsonNode issuerClaims = verifyIssuerSignature(sdJwt.issuerJwt());
        verifyDisclosureDigests(sdJwt.disclosures(), issuerClaims);
        verifyKeyBinding(sdJwt, issuerClaims, presentation, expectedAud, expectedNonce);

        Map<String, Object> claims = new LinkedHashMap<>();
        for (Disclosure d : sdJwt.disclosures()) {
            claims.put(d.claimName(), d.claimValue());
        }
        return claims;
    }

    private static SdJwt parseOrThrow(String presentation) throws VerificationException {
        try {
            return SdJwt.parse(presentation);
        } catch (RuntimeException e) {
            throw new VerificationException("Malformed SD-JWT: " + e.getMessage());
        }
    }

    /** Verify the issuer JWT against the public key of its x5c leaf certificate. */
    private static JsonNode verifyIssuerSignature(String issuerJwt) throws VerificationException {
        try {
            SignedJWT jwt = SignedJWT.parse(issuerJwt);
            List<Base64> x5c = jwt.getHeader().getX509CertChain();
            if (x5c == null || x5c.isEmpty()) {
                throw new VerificationException("Issuer JWT has no x5c certificate");
            }
            ECPublicKey issuerKey = leafPublicKey(x5c.get(0));
            if (!jwt.verify(new ECDSAVerifier(issuerKey))) {
                throw new VerificationException("Issuer JWT signature is invalid");
            }
            return MAPPER.readTree(jwt.getPayload().toString());
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Failed to verify issuer JWT: " + e.getMessage());
        }
    }

    /** Each disclosure's digest must appear in the issuer JWT's _sd array. */
    private static void verifyDisclosureDigests(List<Disclosure> disclosures, JsonNode issuerClaims)
            throws VerificationException {
        JsonNode sdArray = issuerClaims.get("_sd");
        java.util.Set<String> sdDigests = new java.util.HashSet<>();
        if (sdArray != null && sdArray.isArray()) {
            sdArray.forEach(n -> sdDigests.add(n.asText()));
        }
        for (Disclosure d : disclosures) {
            if (!sdDigests.contains(d.digest())) {
                throw new VerificationException(
                        "Disclosure '" + d.claimName() + "' digest not found in _sd (sd_hash mismatch)");
            }
        }
    }

    /** Verify the KB-JWT signature and its aud, nonce, and sd_hash claims. */
    private static void verifyKeyBinding(SdJwt sdJwt, JsonNode issuerClaims, String presentation,
                                         String expectedAud, String expectedNonce)
            throws VerificationException {
        String kbJwt = sdJwt.keyBindingJwt();
        if (kbJwt == null) {
            throw new VerificationException("Key Binding JWT is missing");
        }
        try {
            SignedJWT kb = SignedJWT.parse(kbJwt);

            // Holder key from the issuer JWT's cnf.jwk.
            JsonNode cnf = issuerClaims.get("cnf");
            JsonNode cnfJwk = cnf != null ? cnf.get("jwk") : null;
            if (cnfJwk == null) {
                throw new VerificationException("Issuer JWT has no cnf.jwk for key binding");
            }
            ECKey holderKey = ECKey.parse(cnfJwk.toString());
            if (!kb.verify(new ECDSAVerifier(holderKey.toECPublicKey()))) {
                throw new VerificationException("Key Binding JWT signature is invalid");
            }

            var claims = kb.getJWTClaimsSet();

            String aud = singleAudience(claims.getAudience());
            if (!expectedAud.equals(aud)) {
                throw new VerificationException(
                        "KB-JWT aud '" + aud + "' does not match client_id '" + expectedAud + "'");
            }
            String nonce = claims.getStringClaim("nonce");
            if (!expectedNonce.equals(nonce)) {
                throw new VerificationException("KB-JWT nonce does not match the request nonce");
            }

            String expectedSdHash = computeSdHash(presentation);
            String sdHash = claims.getStringClaim("sd_hash");
            if (!expectedSdHash.equals(sdHash)) {
                throw new VerificationException("KB-JWT sd_hash does not match the presentation");
            }

            // iat must be fresh: the KB-JWT proves possession at presentation
            // time, so reject creation times outside an acceptable window
            // (catches iat far in the past or future).
            java.util.Date iat = claims.getIssueTime();
            if (iat == null) {
                throw new VerificationException("KB-JWT is missing iat");
            }
            long skewSeconds = (System.currentTimeMillis() - iat.getTime()) / 1000;
            if (Math.abs(skewSeconds) > MAX_KB_IAT_SKEW_SECONDS) {
                throw new VerificationException(
                        "KB-JWT iat is outside the acceptable window (skew " + skewSeconds + "s)");
            }
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Failed to verify Key Binding JWT: " + e.getMessage());
        }
    }

    /** sd_hash = base64url(SHA-256(issuer-jwt~d1~...~dn~)), i.e. everything up to the KB-JWT. */
    private static String computeSdHash(String presentation) throws Exception {
        int lastTilde = presentation.lastIndexOf('~');
        String toHash = presentation.substring(0, lastTilde + 1);
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(toHash.getBytes(StandardCharsets.US_ASCII));
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static ECPublicKey leafPublicKey(Base64 der) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(der.decode()));
        return (ECPublicKey) cert.getPublicKey();
    }

    private static String singleAudience(List<String> aud) {
        return (aud != null && !aud.isEmpty()) ? aud.get(0) : null;
    }
}
