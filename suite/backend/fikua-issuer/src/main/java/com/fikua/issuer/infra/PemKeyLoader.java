package com.fikua.issuer.infra;

import com.fikua.core.crypto.EcKeyManager;
import com.fikua.core.crypto.SigningKey;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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
 * Falls back to generating an ephemeral CA-signed certificate chain
 * when no PEM files are found (HAIP 6.1.1 requires x5c with non-self-signed cert).
 */
public final class PemKeyLoader {

    private static final Logger log = LoggerFactory.getLogger(PemKeyLoader.class);

    private PemKeyLoader() {}

    /**
     * Load issuer key from PEM files, or generate an ephemeral key with CA-signed cert.
     * HAIP 6.1.1: x5c MUST be present and the signing cert MUST NOT be self-signed.
     */
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
        return generateWithCaSignedCert(certsDir);
    }

    /**
     * Generate an ephemeral CA + issuer certificate chain.
     * The CA signs the issuer cert so it is NOT self-signed (HAIP 6.1.1).
     * Only the issuer cert goes into x5c — the root CA (trust anchor) is excluded per HAIP.
     */
    private static SigningKey generateWithCaSignedCert(String certsDir) {
        try {
            // 1. Generate CA key pair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair caKeyPair = kpg.generateKeyPair();

            // 2. Create self-signed CA certificate
            X500Name caSubject = new X500Name("CN=Fikua Lab CA (dev), O=Fikua, C=ES");
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
            BigInteger caSerial = BigInteger.valueOf(System.currentTimeMillis());

            ContentSigner caSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
            X509CertificateHolder caHolder = new JcaX509v3CertificateBuilder(
                    caSubject, caSerial, notBefore, notAfter, caSubject, caKeyPair.getPublic()
            ).build(caSigner);
            X509Certificate caCert = new JcaX509CertificateConverter().getCertificate(caHolder);

            // 3. Generate issuer key pair
            KeyPair issuerKeyPair = kpg.generateKeyPair();

            // 4. Create issuer certificate signed by CA (NOT self-signed)
            X500Name issuerSubject = new X500Name("CN=Fikua Lab Issuer (dev), O=Fikua, C=ES");
            BigInteger issuerSerial = BigInteger.valueOf(System.currentTimeMillis() + 1);

            ContentSigner issuerSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
            X509CertificateHolder issuerHolder = new JcaX509v3CertificateBuilder(
                    caSubject, issuerSerial, notBefore, notAfter, issuerSubject, issuerKeyPair.getPublic()
            ).build(issuerSigner);
            X509Certificate issuerCert = new JcaX509CertificateConverter().getCertificate(issuerHolder);

            // 5. Build EcKeyManager with issuer cert (CA excluded from x5c per HAIP)
            EcKeyManager key = EcKeyManager.fromPem(issuerKeyPair.getPrivate(), issuerCert);
            log.info("Generated ephemeral CA-signed issuer key+cert, kid={} (no PEM at {})", key.kid(), certsDir);
            return key;

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate CA-signed issuer key", e);
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
