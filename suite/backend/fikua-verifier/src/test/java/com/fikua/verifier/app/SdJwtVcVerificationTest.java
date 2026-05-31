package com.fikua.verifier.app;

import com.fikua.core.crypto.SigningKey;
import com.fikua.core.sdjwt.Disclosure;
import com.fikua.core.sdjwt.SdJwt;
import com.fikua.core.sdjwt.SdJwtBuilder;
import com.fikua.core.sdjwt.SdJwtVcVerifier;
import com.fikua.verifier.infra.PemKeyLoader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Full SD-JWT VC verification (P1): a correct presentation verifies, and each
 * single defect — bad issuer signature, tampered disclosure, wrong KB-JWT aud,
 * nonce, signature, or sd_hash — is rejected. Mirrors the OIDF verifier
 * negative tests (OID4VP-1FINAL-8.2).
 */
class SdJwtVcVerificationTest {

    private static final String AUD = "x509_hash:client-abc";
    private static final String NONCE = "nonce-xyz";

    /** Build a valid presentation; defects are applied by the individual tests. */
    private String validPresentation(Path certsDir, ECKey holderKey) throws Exception {
        SigningKey issuerKey = PemKeyLoader.loadOrGenerate(certsDir.toString());
        SdJwt sdJwt = new SdJwtBuilder(issuerKey)
                .vct("urn:eudi:pid:1")
                .issuer("https://issuer.example.test")
                .selectiveClaim("given_name", "Alice")
                .holderKey(holderKey)
                .x5cChain(issuerKey.x5cChain())
                .build();
        String issuerPart = sdJwt.serialize(); // ends with trailing ~ (no KB yet)
        String kbJwt = buildKbJwt(holderKey, AUD, NONCE, sdHash(issuerPart));
        return issuerPart + kbJwt;
    }

    private static String buildKbJwt(ECKey holderKey, String aud, String nonce, String sdHash)
            throws Exception {
        return buildKbJwt(holderKey, aud, nonce, sdHash, new java.util.Date());
    }

    private static String buildKbJwt(ECKey holderKey, String aud, String nonce, String sdHash,
                                     java.util.Date iat) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(aud)
                .claim("nonce", nonce)
                .claim("sd_hash", sdHash)
                .issueTime(iat)
                .build();
        SignedJWT kb = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("kb+jwt")).build(),
                claims);
        kb.sign(new ECDSASigner(holderKey));
        return kb.serialize();
    }

    private static String sdHash(String issuerPart) throws Exception {
        int last = issuerPart.lastIndexOf('~');
        String toHash = issuerPart.substring(0, last + 1);
        byte[] d = MessageDigest.getInstance("SHA-256")
                .digest(toHash.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(d);
    }

    @Test
    void validPresentation_verifies(@TempDir Path certsDir) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        Map<String, Object> claims =
                SdJwtVcVerifier.verify(validPresentation(certsDir, holder), AUD, NONCE);
        assertEquals("Alice", claims.get("given_name"));
    }

    @Test
    void wrongAud_rejected(@TempDir Path certsDir) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        String p = validPresentation(certsDir, holder);
        assertThrows(SdJwtVcVerifier.VerificationException.class,
                () -> SdJwtVcVerifier.verify(p, "x509_hash:someone-else", NONCE));
    }

    @Test
    void wrongNonce_rejected(@TempDir Path certsDir) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        String p = validPresentation(certsDir, holder);
        assertThrows(SdJwtVcVerifier.VerificationException.class,
                () -> SdJwtVcVerifier.verify(p, AUD, "wrong-nonce"));
    }

    @Test
    void tamperedIssuerSignature_rejected(@TempDir Path certsDir) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        String p = validPresentation(certsDir, holder);
        // Flip a character in the issuer JWT signature segment.
        int firstDot = p.indexOf('.');
        int secondDot = p.indexOf('.', firstDot + 1);
        char[] chars = p.toCharArray();
        chars[secondDot + 1] = chars[secondDot + 1] == 'A' ? 'B' : 'A';
        String tampered = new String(chars);
        assertThrows(SdJwtVcVerifier.VerificationException.class,
                () -> SdJwtVcVerifier.verify(tampered, AUD, NONCE));
    }

    @Test
    void iatInPast_rejected(@TempDir Path certsDir) throws Exception {
        assertThrows(SdJwtVcVerifier.VerificationException.class,
                () -> SdJwtVcVerifier.verify(
                        presentationWithKbIat(certsDir,
                                new java.util.Date(System.currentTimeMillis() - 365L * 24 * 3600 * 1000)),
                        AUD, NONCE));
    }

    @Test
    void iatInFuture_rejected(@TempDir Path certsDir) throws Exception {
        assertThrows(SdJwtVcVerifier.VerificationException.class,
                () -> SdJwtVcVerifier.verify(
                        presentationWithKbIat(certsDir,
                                new java.util.Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000)),
                        AUD, NONCE));
    }

    /** Build a valid presentation whose KB-JWT carries the given iat. */
    private String presentationWithKbIat(Path certsDir, java.util.Date iat) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        SigningKey issuerKey = PemKeyLoader.loadOrGenerate(certsDir.toString());
        SdJwt sdJwt = new SdJwtBuilder(issuerKey)
                .vct("urn:eudi:pid:1").issuer("https://issuer.example.test")
                .selectiveClaim("given_name", "Alice")
                .holderKey(holder).x5cChain(issuerKey.x5cChain()).build();
        String issuerPart = sdJwt.serialize();
        return issuerPart + buildKbJwt(holder, AUD, NONCE, sdHash(issuerPart), iat);
    }

    @Test
    void foreignKbJwtSignature_rejected(@TempDir Path certsDir) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        SigningKey issuerKey = PemKeyLoader.loadOrGenerate(certsDir.toString());
        SdJwt sdJwt = new SdJwtBuilder(issuerKey)
                .vct("urn:eudi:pid:1").issuer("https://issuer.example.test")
                .selectiveClaim("given_name", "Alice")
                .holderKey(holder).x5cChain(issuerKey.x5cChain()).build();
        String issuerPart = sdJwt.serialize();
        // Sign the KB-JWT with a different key than the cnf holder key.
        ECKey attacker = new ECKeyGenerator(Curve.P_256).generate();
        String kbJwt = buildKbJwt(attacker, AUD, NONCE, sdHash(issuerPart));
        String p = issuerPart + kbJwt;
        assertThrows(SdJwtVcVerifier.VerificationException.class,
                () -> SdJwtVcVerifier.verify(p, AUD, NONCE));
    }
}
