package com.fikua.issuer.infra;

import com.fikua.core.crypto.SigningKey;
import com.fikua.core.sdjwt.SdJwtBuilder;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for PemKeyLoader — HAIP 6.1.1 conformance.
 * Verifies that the issuer signing key always has an x5c certificate chain,
 * whether loaded from PEM files or generated as fallback.
 */
class PemKeyLoaderTest {

    @Test
    void loadOrGenerate_noPemFiles_returnsKeyWithX5c(@TempDir Path tempDir) {
        SigningKey key = PemKeyLoader.loadOrGenerate(tempDir.toString());

        List<Base64> x5c = key.x5cChain();
        assertNotNull(x5c, "x5c chain must not be null");
        assertFalse(x5c.isEmpty(), "x5c chain must not be empty — HAIP 6.1.1 requires x5c");
    }

    @Test
    void loadOrGenerate_noPemFiles_certIsNotSelfSigned(@TempDir Path tempDir) throws Exception {
        SigningKey key = PemKeyLoader.loadOrGenerate(tempDir.toString());

        // Decode the x5c certificate
        List<Base64> x5c = key.x5cChain();
        byte[] certBytes = x5c.getFirst().decode();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(certBytes));

        // HAIP 6.1.1: signing cert MUST NOT be self-signed
        // A self-signed cert has issuer DN == subject DN
        assertNotEquals(cert.getIssuerX500Principal(), cert.getSubjectX500Principal(),
                "Issuer cert must NOT be self-signed (HAIP 6.1.1)");
    }

    @Test
    void loadOrGenerate_noPemFiles_keyCanSign(@TempDir Path tempDir) {
        SigningKey key = PemKeyLoader.loadOrGenerate(tempDir.toString());

        assertNotNull(key.kid(), "kid must be present");
        assertNotNull(key.jwkSet(), "JWK Set must be present");

        // Verify the key can sign and the signature is valid
        String payload = "test-payload";
        var header = new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                .keyID(key.kid())
                .build();
        String signed = key.sign(header, new com.nimbusds.jose.Payload(payload));
        assertTrue(key.verify(signed), "Key must be able to verify its own signature");
    }

    @Test
    void loadOrGenerate_noPemFiles_sdJwtHasX5cHeader(@TempDir Path tempDir) throws Exception {
        SigningKey key = PemKeyLoader.loadOrGenerate(tempDir.toString());

        // Build an SD-JWT VC using this key (same path as IssuanceService)
        var sdJwt = new SdJwtBuilder(key)
                .vct("eu.europa.ec.eudi.pid.1")
                .issuer("https://issuer.lab.fikua.com")
                .x5cChain(key.x5cChain())
                .build();

        // Parse the JWT header and verify x5c is present
        String jwtPart = sdJwt.serialize().split("~")[0];
        SignedJWT jwt = SignedJWT.parse(jwtPart);
        List<com.nimbusds.jose.util.Base64> headerX5c = jwt.getHeader().getX509CertChain();

        assertNotNull(headerX5c, "SD-JWT VC header must contain x5c (HAIP 6.1.1)");
        assertFalse(headerX5c.isEmpty(), "SD-JWT VC header x5c must not be empty");
    }

    @Test
    void loadOrGenerate_withPemFiles_loadsFromFiles(@TempDir Path tempDir) throws IOException {
        // Copy test PEM files to temp directory
        Path devCerts = Path.of("../../dev-tools/issuer-cert");
        Path certSource = devCerts.resolve("issuer-cert.pem");
        Path keySource = devCerts.resolve("issuer-key.pem");

        // Skip if dev-tools PEM files don't exist (CI environment)
        if (!Files.exists(certSource) || !Files.exists(keySource)) {
            return;
        }

        Files.copy(certSource, tempDir.resolve("issuer-cert.pem"));
        Files.copy(keySource, tempDir.resolve("issuer-key.pem"));

        SigningKey key = PemKeyLoader.loadOrGenerate(tempDir.toString());

        assertNotNull(key.kid(), "kid must be present when loaded from PEM");
        assertFalse(key.x5cChain().isEmpty(), "x5c must be present when loaded from PEM");
    }
}
