package com.fikua.trustlist;

import com.fikua.core.crypto.EcKeyManager;
import com.fikua.trustlist.infra.http.WalletProviderController;
import io.javalin.Javalin;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Wallet Provider service — Fikua Lab acting as an ARF Wallet Provider.
 *
 * Issues a Wallet Instance Attestation (WIA) signed by the Wallet Provider's
 * own key (with an x5c chain to the shared lab CA), so an Issuer can verify
 * the WIA was issued by a trusted Wallet Provider rather than self-signed by
 * the wallet. Also exposes a (mock) attestation status endpoint.
 *
 * The WP signing material is wallet-provider-cert.pem + wallet-provider-key.pem
 * in FIKUA_CERTS_DIR. If absent the WP endpoints are disabled (logged), since a
 * WP with no key cannot issue attestations.
 */
public class WalletProviderService {

    private static final Logger log = LoggerFactory.getLogger(WalletProviderService.class);

    public void start(Javalin app, String certsDir, String baseUrl) {
        EcKeyManager wpKey = loadKey(certsDir);
        if (wpKey == null) {
            log.warn("Wallet Provider: no wallet-provider-cert.pem/key.pem in {} — WP endpoints disabled", certsDir);
            return;
        }
        new WalletProviderController(wpKey, baseUrl).register(app);
        log.info("Wallet Provider service started, kid={}", wpKey.kid());
    }

    /** Load the WP signing key+cert from PEM, or null if not present. */
    private EcKeyManager loadKey(String certsDir) {
        try {
            Path certPath = Path.of(certsDir, "wallet-provider-cert.pem");
            Path keyPath = Path.of(certsDir, "wallet-provider-key.pem");
            if (!Files.exists(certPath) || !Files.exists(keyPath)) {
                return null;
            }
            X509Certificate cert;
            try (var is = Files.newInputStream(certPath)) {
                cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
            }
            PrivateKey privKey;
            try (PEMParser parser = new PEMParser(Files.newBufferedReader(keyPath))) {
                Object obj = parser.readObject();
                if (!(obj instanceof PrivateKeyInfo pki)) {
                    throw new IllegalStateException("Unsupported WP key PEM: " + obj);
                }
                privKey = new JcaPEMKeyConverter().getPrivateKey(pki);
            }
            return EcKeyManager.fromPem(privKey, cert);
        } catch (Exception e) {
            log.error("Failed to load Wallet Provider key from {}", certsDir, e);
            return null;
        }
    }
}
