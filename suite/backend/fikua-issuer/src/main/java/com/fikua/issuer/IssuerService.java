package com.fikua.issuer;

import com.fikua.core.crypto.SigningKey;
import com.fikua.core.oauth2.ClientAttestationValidator;
import com.fikua.core.oauth2.DPoPValidator;
import com.fikua.issuer.app.IssuanceService;
import com.fikua.issuer.app.port.EmailService;
import com.fikua.issuer.app.port.IssuanceStore;
import com.fikua.issuer.app.port.ProfileStore;
import com.fikua.issuer.app.port.SessionStore;
import com.fikua.issuer.infra.InMemorySessionStore;
import com.fikua.issuer.infra.JdbcIssuanceStore;
import com.fikua.issuer.infra.JdbcProfileStore;
import com.fikua.issuer.infra.PemKeyLoader;
import com.fikua.issuer.infra.http.IssuerController;
import io.javalin.Javalin;

import javax.sql.DataSource;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Issuer service entry point.
 * Wires infrastructure adapters, creates application service, registers HTTP routes.
 */
public class IssuerService {

    private IssuanceService issuanceService;

    /** Start the issuer service, registering routes on the given Javalin app. */
    public void start(Javalin app, DataSource dataSource, String baseUrl, String certsDir,
                      String identifyBaseUrl, EmailService emailService, String walletBaseUrl) {
        // Load signing key
        SigningKey key = PemKeyLoader.loadOrGenerate(certsDir);

        // Create infrastructure adapters
        SessionStore sessions = new InMemorySessionStore();
        IssuanceStore issuances = new JdbcIssuanceStore(dataSource);
        ProfileStore profiles = new JdbcProfileStore(dataSource);

        // M9: DPoP JTI replay protection with bounded size (evicts oldest entries)
        Set<String> jtiSet = ConcurrentHashMap.newKeySet();
        DPoPValidator dpop = new DPoPValidator(jti -> {
            // Evict oldest entries when set grows too large (DPoP proofs expire after 5 min)
            if (jtiSet.size() > 10_000) {
                var iter = jtiSet.iterator();
                for (int i = 0; i < 1_000 && iter.hasNext(); i++) {
                    iter.next();
                    iter.remove();
                }
            }
            return jtiSet.add(jti);
        });

        // Pin WIA validation to the trusted Wallet Provider anchor(s): the
        // shared lab root CA (root-ca.crt) that the WP leaf chains to. If absent,
        // the validator falls back to accepting self-consistent WIAs.
        ClientAttestationValidator attestationValidator =
                new ClientAttestationValidator(loadWalletProviderAnchors(certsDir));

        // Create application service
        issuanceService = new IssuanceService(key, sessions, issuances, profiles, dpop, baseUrl,
                identifyBaseUrl, emailService, walletBaseUrl, attestationValidator);

        // Register HTTP controller
        new IssuerController(issuanceService, baseUrl).register(app);
    }

    /** Get the issuance service (for orchestrator-level operations like reset). */
    public IssuanceService issuanceService() {
        return issuanceService;
    }

    /**
     * Load the Wallet Provider trust anchor(s) used to pin WIA validation.
     * Reads root-ca.crt from the certs dir (the shared lab CA the WP leaf
     * chains to). Returns an empty list if absent — validation then falls back
     * to accepting self-consistent WIAs (back-compat / no pinning).
     */
    private static java.util.List<java.security.cert.X509Certificate> loadWalletProviderAnchors(String certsDir) {
        var path = java.nio.file.Path.of(certsDir, "root-ca.crt");
        if (!java.nio.file.Files.exists(path)) {
            return java.util.List.of();
        }
        try (var is = java.nio.file.Files.newInputStream(path)) {
            var cf = java.security.cert.CertificateFactory.getInstance("X.509");
            return java.util.List.of((java.security.cert.X509Certificate) cf.generateCertificate(is));
        } catch (Exception e) {
            return java.util.List.of();
        }
    }
}
