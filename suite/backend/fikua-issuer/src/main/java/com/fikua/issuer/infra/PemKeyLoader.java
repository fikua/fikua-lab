package com.fikua.issuer.infra;

import com.fikua.core.crypto.EcKeyManager;
import com.fikua.core.crypto.SigningKey;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Infrastructure utility to load signing keys from PEM files.
 * Falls back to generating a key without x5c if no PEM files found.
 *
 * HAIP 6.1.1 requires x5c in the SD-JWT VC header — ensure PEM files are
 * available in production. In the future, certificates may be loaded from
 * a QTSP or Vault instead of local PEM files.
 */
public final class PemKeyLoader {

    private static final Logger log = LoggerFactory.getLogger(PemKeyLoader.class);

    private PemKeyLoader() {}

    /** Load issuer key from PEM files, or generate an ephemeral key (without x5c). */
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
        EcKeyManager key = EcKeyManager.generate();
        log.warn("No PEM certificates found at {}. Using generated key (kid={}) WITHOUT x5c. "
                + "HAIP 6.1.1 requires x5c in SD-JWT VC header — provide issuer-cert.pem and issuer-key.pem for conformance.",
                certsDir, key.kid());
        return key;
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
