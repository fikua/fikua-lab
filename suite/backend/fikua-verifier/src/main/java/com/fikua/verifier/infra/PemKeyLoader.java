package com.fikua.verifier.infra;

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
 * Infrastructure utility to load verifier signing keys from PEM files.
 * Falls back to generating an ephemeral CA-signed certificate chain
 * when no PEM files are found (HAIP requires x5c with non-self-signed cert).
 */
public final class PemKeyLoader {

    private static final Logger log = LoggerFactory.getLogger(PemKeyLoader.class);

    private PemKeyLoader() {}

    /**
     * Load verifier key from PEM files, or generate an ephemeral key with CA-signed cert.
     */
    public static SigningKey loadOrGenerate(String certsDir) {
        var certPath = Path.of(certsDir, "verifier-cert.pem");
        var keyPath = Path.of(certsDir, "verifier-key.pem");
        if (Files.exists(certPath) && Files.exists(keyPath)) {
            var cert = loadCertificate(certPath);
            var privKey = loadPrivateKey(keyPath);
            EcKeyManager key = EcKeyManager.fromPem(privKey, cert);
            log.info("Verifier key loaded from PEM, kid={}, subject={}", key.kid(), cert.getSubjectX500Principal());
            return key;
        }
        return generateWithCaSignedCert(certsDir);
    }

    private static SigningKey generateWithCaSignedCert(String certsDir) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair caKeyPair = kpg.generateKeyPair();

            X500Name caSubject = new X500Name("CN=Fikua Lab CA (dev), O=Fikua, C=ES");
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
            BigInteger caSerial = BigInteger.valueOf(System.currentTimeMillis());

            ContentSigner caSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
            X509CertificateHolder caHolder = new JcaX509v3CertificateBuilder(
                    caSubject, caSerial, notBefore, notAfter, caSubject, caKeyPair.getPublic()
            ).build(caSigner);
            new JcaX509CertificateConverter().getCertificate(caHolder);

            KeyPair verifierKeyPair = kpg.generateKeyPair();

            X500Name verifierSubject = new X500Name("CN=Fikua Lab Verifier (dev), O=Fikua, C=ES");
            BigInteger verifierSerial = BigInteger.valueOf(System.currentTimeMillis() + 1);

            ContentSigner verifierSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
            X509CertificateHolder verifierHolder = new JcaX509v3CertificateBuilder(
                    caSubject, verifierSerial, notBefore, notAfter, verifierSubject, verifierKeyPair.getPublic()
            ).build(verifierSigner);
            X509Certificate verifierCert = new JcaX509CertificateConverter().getCertificate(verifierHolder);

            EcKeyManager key = EcKeyManager.fromPem(verifierKeyPair.getPrivate(), verifierCert);
            log.info("Generated ephemeral CA-signed verifier key+cert, kid={} (no PEM at {})", key.kid(), certsDir);
            return key;

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate CA-signed verifier key", e);
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
