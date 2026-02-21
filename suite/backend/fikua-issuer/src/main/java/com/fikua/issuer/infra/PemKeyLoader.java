package com.fikua.issuer.infra;

import com.fikua.core.crypto.EcKeyManager;
import com.fikua.core.crypto.SigningKey;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/**
 * Infrastructure utility to load signing keys from PEM files.
 * Falls back to generating a self-signed key+cert if no PEM files found.
 * HAIP 6.1.1 requires x5c in the SD-JWT VC header, so a certificate is always needed.
 */
public final class PemKeyLoader {

    private static final Logger log = LoggerFactory.getLogger(PemKeyLoader.class);

    private PemKeyLoader() {}

    /** Load issuer key from PEM files, or generate a self-signed key+cert. */
    public static SigningKey loadOrGenerate(String certsDir) {
        var certPath = Path.of(certsDir, "issuer-cert.pem");
        var keyPath = Path.of(certsDir, "issuer-key.pem");
        if (Files.exists(certPath) && Files.exists(keyPath)) {
            var cert = loadCertificate(certPath);
            var privKey = loadPrivateKey(keyPath);
            EcKeyManager key = EcKeyManager.fromPem(privKey, cert);
            log.info("Issuer key loaded from PEM, kid={}, subject={}", key.kid(), cert.getSubjectX500Principal());
            return key;
        }
        // HAIP 6.1.1: x5c is REQUIRED — generate self-signed cert for dev/test
        return generateWithSelfSignedCert(certsDir);
    }

    /** Generate EC P-256 key pair with a self-signed X.509 certificate. */
    private static SigningKey generateWithSelfSignedCert(String certsDir) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keyPair = kpg.generateKeyPair();

            // Self-signed cert valid for 1 year
            X500Name subject = new X500Name("CN=Fikua Lab Issuer (dev), O=Fikua, C=ES");
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
            X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
                    subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
            ).build(signer);

            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
            EcKeyManager key = EcKeyManager.fromPem(keyPair.getPrivate(), cert);
            log.info("Generated self-signed issuer key+cert, kid={} (no PEM at {})", key.kid(), certsDir);
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate self-signed issuer key", e);
        }
    }

    private static X509Certificate loadCertificate(Path pemPath) {
        try (InputStream is = Files.newInputStream(pemPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(is);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load certificate from " + pemPath, e);
        }
    }

    private static PrivateKey loadPrivateKey(Path pemPath) {
        try (PEMParser parser = new PEMParser(Files.newBufferedReader(pemPath))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            if (obj instanceof PrivateKeyInfo pki) {
                return converter.getPrivateKey(pki);
            }
            throw new RuntimeException("Unsupported PEM object: " + obj.getClass().getName());
        } catch (IOException e) {
            throw new RuntimeException("Failed to load private key from " + pemPath, e);
        }
    }
}
