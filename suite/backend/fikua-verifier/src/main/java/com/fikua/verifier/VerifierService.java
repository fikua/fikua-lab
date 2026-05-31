package com.fikua.verifier;

import com.fikua.core.crypto.ResponseEncryptionKey;
import com.fikua.core.crypto.SigningKey;
import com.fikua.verifier.app.VerificationService;
import com.fikua.verifier.app.port.ProfileStore;
import com.fikua.verifier.app.port.SessionStore;
import com.fikua.verifier.infra.InMemorySessionStore;
import com.fikua.verifier.infra.JdbcProfileStore;
import com.fikua.verifier.infra.PemKeyLoader;
import com.fikua.verifier.infra.http.VerifierController;
import io.javalin.Javalin;

import javax.sql.DataSource;

/**
 * Verifier service entry point.
 * Wires infrastructure adapters, creates application service, registers HTTP routes.
 */
public class VerifierService {

    private VerificationService verificationService;

    /** Start the verifier service, registering routes on the given Javalin app. */
    public void start(Javalin app, DataSource dataSource, String baseUrl, String certsDir) {
        // Load verifier signing key
        SigningKey key = PemKeyLoader.loadOrGenerate(certsDir);

        // Response-encryption key (ECDH-ES) for direct_post.jwt / HAIP §5.
        // One verifier-wide key, published in every request's client_metadata.
        ResponseEncryptionKey encryptionKey = ResponseEncryptionKey.generate();

        // Create infrastructure adapters
        SessionStore sessions = new InMemorySessionStore();
        ProfileStore profiles = new JdbcProfileStore(dataSource);

        // Create application service
        verificationService = new VerificationService(key, encryptionKey, sessions, profiles, baseUrl);

        // Register HTTP controller
        new VerifierController(verificationService, baseUrl).register(app);
    }

    /** Get the verification service (for orchestrator-level operations like reset). */
    public VerificationService verificationService() {
        return verificationService;
    }
}
